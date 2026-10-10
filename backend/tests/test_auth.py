from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt

from app.core.config import get_settings
from app.models.user import User
from tests.helpers import PASSWORD, auth_headers


def test_register_returns_user_without_password(client):
    response = client.post("/api/auth/register", json={"email": "a@example.com", "password": PASSWORD})
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "a@example.com"
    assert "password" not in body and "hashed_password" not in body


def test_duplicate_email_is_rejected_case_insensitively(client):
    client.post("/api/auth/register", json={"email": "a@example.com", "password": PASSWORD})
    response = client.post("/api/auth/register", json={"email": "A@Example.com", "password": PASSWORD})
    assert response.status_code == 409


def test_short_password_is_rejected(client):
    response = client.post("/api/auth/register", json={"email": "a@example.com", "password": "short"})
    assert response.status_code == 422


def test_passwords_are_stored_as_argon2_hashes(client, session_factory):
    client.post("/api/auth/register", json={"email": "a@example.com", "password": PASSWORD})
    with session_factory() as db:
        stored = db.query(User).one().hashed_password
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


def test_login_errors_do_not_reveal_whether_the_account_exists(client):
    client.post("/api/auth/register", json={"email": "a@example.com", "password": PASSWORD})
    wrong_password = client.post("/api/auth/login", json={"email": "a@example.com", "password": "wrong-password-1"})
    unknown_user = client.post("/api/auth/login", json={"email": "x@example.com", "password": "wrong-password-1"})
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


def test_protected_routes_require_a_token(client):
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/projects").status_code == 401


def test_me_returns_current_user(client, headers):
    assert client.get("/api/auth/me", headers=headers).json()["email"] == "user@example.com"


def test_tampered_token_is_rejected(client, headers):
    token = headers["Authorization"].split(" ", 1)[1]
    broken = token[:-5] + ("AAAAA" if token[-5:] != "AAAAA" else "BBBBB")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {broken}"}).status_code == 401


def _token(user_id: str, secret: str, expires_in: timedelta) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": user_id, "iat": now, "exp": now + expires_in}, secret, algorithm="HS256")


def test_expired_token_is_rejected(client, headers):
    user_id = client.get("/api/auth/me", headers=headers).json()["id"]
    expired = _token(user_id, get_settings().jwt_secret_key, timedelta(minutes=-1))
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_token_signed_with_another_key_is_rejected(client, headers):
    user_id = client.get("/api/auth/me", headers=headers).json()["id"]
    forged = _token(user_id, "x" * 40, timedelta(minutes=5))
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_token_for_unknown_user_is_rejected(client):
    token = _token(str(uuid4()), get_settings().jwt_secret_key, timedelta(minutes=5))
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401