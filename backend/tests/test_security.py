from tests.helpers import upload


def test_security_headers_and_request_id(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["database"] == "up"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert len(response.headers["x-request-id"]) == 12


def test_login_is_rate_limited(client):
    payload = {"email": "nobody@example.com", "password": "wrong-password-123"}
    responses = [client.post("/api/auth/login", json=payload) for _ in range(11)]
    assert [item.status_code for item in responses[:10]] == [401] * 10
    assert responses[10].status_code == 429
    assert int(responses[10].headers["retry-after"]) >= 1


def test_file_over_five_megabytes_is_rejected(client, headers, project):
    response = upload(client, headers, project["id"], "requirements.txt", b"a" * (5 * 1024 * 1024 + 1024))
    assert response.status_code == 413


def test_request_body_over_limit_is_rejected_before_processing(client, headers, project):
    response = upload(client, headers, project["id"], "requirements.txt", b"a" * (7 * 1024 * 1024))
    assert response.status_code == 413