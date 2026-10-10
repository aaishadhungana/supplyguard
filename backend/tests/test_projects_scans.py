from tests.helpers import auth_headers, upload


def test_project_defaults_and_duplicate_names(client, headers):
    created = client.post("/api/projects", json={"name": "Shop"}, headers=headers)
    assert created.status_code == 201
    assert created.json()["internet_facing"] is False
    assert created.json()["criticality"] == "medium"
    assert client.post("/api/projects", json={"name": "Shop"}, headers=headers).status_code == 409


def test_users_cannot_see_each_others_projects(client, headers, project):
    other = auth_headers(client, "other@example.com")
    assert client.get(f"/api/projects/{project['id']}", headers=other).status_code == 404
    assert client.get("/api/projects", headers=other).json() == []
    assert client.get(f"/api/projects/{project['id']}/scans", headers=other).status_code == 404
    assert upload(client, other, project["id"], "requirements.txt", "django==3.2.0").status_code == 404


def test_context_update_and_validation(client, headers, project):
    url = f"/api/projects/{project['id']}/context"
    updated = client.patch(url, json={"internet_facing": True, "criticality": "high"}, headers=headers)
    assert updated.status_code == 200
    assert updated.json()["internet_facing"] is True and updated.json()["criticality"] == "high"
    assert client.patch(url, json={"criticality": "extreme"}, headers=headers).status_code == 422


def test_unsupported_filename_is_rejected(client, headers, project):
    response = upload(client, headers, project["id"], "setup.py", "print('hi')")
    assert response.status_code == 400


def test_non_utf8_file_is_rejected(client, headers, project):
    response = upload(client, headers, project["id"], "requirements.txt", b"\xff\xfedjango==3.2.0")
    assert response.status_code == 400


def test_scan_numbers_increase_per_project(client, headers, project):
    first = upload(client, headers, project["id"], "requirements.txt", "django==3.2.0")
    second = upload(client, headers, project["id"], "requirements.txt", "django==3.2.0")
    assert first.status_code == second.status_code == 202
    assert [first.json()["number"], second.json()["number"]] == [1, 2]