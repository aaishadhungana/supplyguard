import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

import app.models
from app.ai.gemini import AiUnavailable
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import get_db
from app.intel.service import Finding
from app.main import app
from app.middleware.rate_limit import store as rate_limit_store
from tests.helpers import auth_headers

TEST_DATABASE = "supplyguard_test"


class FakeIntel:
    def __init__(self) -> None:
        self.error: Exception | None = None
        self.advisories: dict[str, list] = {}

    def __call__(self, refs):
        if self.error is not None:
            raise self.error
        findings = [Finding(ref, item) for ref in refs for item in self.advisories.get(ref.name, [])]
        return findings, []


@pytest.fixture(scope="session")
def engine():
    base_url = get_settings().database_url
    admin = create_engine(base_url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        exists = connection.scalar(
            text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": TEST_DATABASE}
        )
        if not exists:
            connection.execute(text(f'CREATE DATABASE "{TEST_DATABASE}"'))
    admin.dispose()

    test_engine = create_engine(base_url.set(database=TEST_DATABASE))
    Base.metadata.drop_all(test_engine)
    Base.metadata.create_all(test_engine)
    yield test_engine
    test_engine.dispose()


@pytest.fixture()
def session_factory(engine):
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture(autouse=True)
def intel(monkeypatch):
    fake = FakeIntel()
    monkeypatch.setattr("app.services.pipeline.collect_findings", fake)
    return fake


@pytest.fixture(autouse=True)
def ai_disabled(monkeypatch):
    def disabled(system_prompt, user_prompt, schema):
        raise AiUnavailable("AI disabled in tests")

    monkeypatch.setattr("app.ai.analyst.generate_json", disabled)


@pytest.fixture()
def client(engine, session_factory, monkeypatch):
    with engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())
    rate_limit_store.reset()

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr("app.services.pipeline.SessionLocal", session_factory)
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def headers(client):
    return auth_headers(client)


@pytest.fixture()
def project(client, headers):
    response = client.post("/api/projects", json={"name": "Demo App"}, headers=headers)
    return response.json()