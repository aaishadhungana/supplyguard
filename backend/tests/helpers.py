import json

from app.intel.normalize import NormalizedAdvisory

PASSWORD = "a-long-test-password"


def auth_headers(client, email: str = "user@example.com") -> dict[str, str]:
    client.post("/api/auth/register", json={"email": email, "password": PASSWORD})
    response = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def make_advisory(
    osv_id: str = "GHSA-test-0001",
    score: float = 7.0,
    severity: str = "high",
    exploited: bool = False,
    fixed: list[str] | None = None,
    summary: str = "Test advisory",
) -> NormalizedAdvisory:
    return NormalizedAdvisory(
        osv_id=osv_id,
        aliases=["CVE-2099-0001"],
        summary=summary,
        severity=severity,
        cvss_score=score,
        cvss_vector=None,
        known_exploited=exploited,
        fixed_versions=["9.9.9"] if fixed is None else fixed,
        published=None,
    )


def upload(client, headers, project_id: str, filename: str, content: str | bytes):
    data = content.encode() if isinstance(content, str) else content
    return client.post(
        f"/api/projects/{project_id}/scans",
        headers=headers,
        files={"file": (filename, data, "application/octet-stream")},
    )


def npm_lock(production=("lodash",), development=("mocha",)) -> str:
    packages = {
        "": {
            "name": "demo",
            "dependencies": {name: "*" for name in production},
            "devDependencies": {name: "*" for name in development},
        }
    }
    for name in production:
        packages[f"node_modules/{name}"] = {"version": "1.0.0"}
    for name in development:
        packages[f"node_modules/{name}"] = {"version": "1.0.0", "dev": True}
    return json.dumps({"lockfileVersion": 3, "packages": packages})