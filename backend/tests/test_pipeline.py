import json

from app.intel.errors import IntelligenceUnavailable
from tests.helpers import auth_headers, make_advisory, npm_lock, upload

BASE = "/api/projects/{project}/scans/{scan}"


def run_scan(client, headers, project, filename, content):
    response = upload(client, headers, project["id"], filename, content)
    assert response.status_code == 202
    return response.json()["id"]


def url(project, scan, suffix=""):
    return BASE.format(project=project["id"], scan=scan) + suffix


def findings(client, headers, project, scan):
    return client.get(url(project, scan, "/vulnerabilities"), headers=headers).json()


def test_scan_completes_with_scored_findings(client, headers, project, intel):
    intel.advisories["django"] = [make_advisory(fixed=["3.2.5"])]
    scan = run_scan(client, headers, project, "requirements.txt", "django==3.2.0\nrequests==2.19.0\n")

    assert client.get(url(project, scan), headers=headers).json()["status"] == "completed"
    [finding] = findings(client, headers, project, scan)
    assert finding["package_name"] == "django"
    assert finding["priority_rank"] == 1
    assert finding["component_role"] == "web_framework"
    assert finding["risk_score"] == 48.5
    assert finding["risk_level"] == "medium"
    assert [node["label"] for node in finding["attack_path"]["nodes"]] == ["Application", "django@3.2.0"]
    assert finding["attack_path"]["through_entry_point"] is True
    assert "3.2.5" in finding["remediation_hint"]
    assert {item["factor"] for item in finding["risk_breakdown"]} >= {"severity", "exploit", "scope"}

    summary = client.get(url(project, scan, "/summary"), headers=headers).json()
    assert summary["total_dependencies"] == 2
    assert summary["vulnerable_dependencies"] == 1
    assert summary["vulnerabilities_by_risk_level"]["medium"] == 1


def test_development_dependencies_score_lower(client, headers, project, intel):
    intel.advisories["lodash"] = [make_advisory("GHSA-prod", score=7.0)]
    intel.advisories["mocha"] = [make_advisory("GHSA-dev", score=7.0)]
    scan = run_scan(client, headers, project, "package-lock.json", npm_lock())
    scores = {item["package_name"]: item["risk_score"] for item in findings(client, headers, project, scan)}
    assert scores == {"lodash": 40.5, "mocha": 16.2}


def test_project_context_raises_scores_on_later_scans(client, headers, project, intel):
    intel.advisories["lodash"] = [make_advisory(score=7.0)]
    before = run_scan(client, headers, project, "package-lock.json", npm_lock(development=()))
    client.patch(
        f"/api/projects/{project['id']}/context",
        json={"internet_facing": True, "criticality": "high"},
        headers=headers,
    )
    after = run_scan(client, headers, project, "package-lock.json", npm_lock(development=()))
    assert findings(client, headers, project, before)[0]["risk_score"] == 40.5
    assert findings(client, headers, project, after)[0]["risk_score"] == 53.5


def test_known_exploited_findings_rank_first(client, headers, project, intel):
    intel.advisories["lodash"] = [make_advisory("GHSA-a", score=9.8)]
    intel.advisories["express"] = [make_advisory("GHSA-b", score=5.0, exploited=True)]
    scan = run_scan(client, headers, project, "package-lock.json", npm_lock(("lodash", "express"), ()))
    ranked = findings(client, headers, project, scan)
    assert [item["priority_rank"] for item in ranked] == [1, 2]
    assert ranked[0]["risk_score"] >= ranked[1]["risk_score"]


def test_intelligence_outage_fails_the_scan_instead_of_reporting_clean(client, headers, project, intel):
    intel.error = IntelligenceUnavailable("OSV request failed (HTTP 503)")
    scan = run_scan(client, headers, project, "requirements.txt", "django==3.2.0")
    body = client.get(url(project, scan), headers=headers).json()
    assert body["status"] == "failed"
    assert "OSV" in body["error_message"]
    assert client.get(url(project, scan, "/sbom"), headers=headers).status_code == 409


def test_malformed_manifest_fails_with_a_message(client, headers, project):
    scan = run_scan(client, headers, project, "package-lock.json", "{not json")
    body = client.get(url(project, scan), headers=headers).json()
    assert body["status"] == "failed"
    assert "valid JSON" in body["error_message"]


def test_sbom_is_cyclonedx_with_vulnerabilities(client, headers, project, intel):
    intel.advisories["django"] = [make_advisory("GHSA-sbom")]
    scan = run_scan(client, headers, project, "requirements.txt", "django==3.2.0")
    sbom = client.get(url(project, scan, "/sbom"), headers=headers).json()
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    assert sbom["components"][0]["purl"] == "pkg:pypi/django@3.2.0"
    assert sbom["vulnerabilities"][0]["id"] == "GHSA-sbom"
    assert sbom["vulnerabilities"][0]["affects"][0]["ref"] == "pkg:pypi/django@3.2.0"


def test_report_is_markdown_and_labels_ai_text(client, headers, project, intel):
    intel.advisories["django"] = [make_advisory("GHSA-report")]
    scan = run_scan(client, headers, project, "requirements.txt", "django==3.2.0")
    response = client.get(url(project, scan, "/report"), headers=headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert "attachment" in response.headers["content-disposition"]
    assert "# SupplyGuard Security Report" in response.text
    assert "GHSA-report" in response.text
    assert "Method and limitations" in response.text


def test_finding_detail_is_owner_only(client, headers, project, intel):
    intel.advisories["django"] = [make_advisory()]
    scan = run_scan(client, headers, project, "requirements.txt", "django==3.2.0")
    finding_id = findings(client, headers, project, scan)[0]["id"]
    detail = url(project, scan, f"/findings/{finding_id}")
    assert client.get(detail, headers=headers).status_code == 200
    assert client.get(detail, headers=auth_headers(client, "other@example.com")).status_code == 404


def test_comparison_reports_resolved_findings(client, headers, project, intel):
    intel.advisories["django"] = [make_advisory("GHSA-gone", score=9.0)]
    before = run_scan(client, headers, project, "requirements.txt", "django==3.2.0")
    intel.advisories.clear()
    after = run_scan(client, headers, project, "requirements.txt", "django==4.2.0")

    compare = f"/api/projects/{project['id']}/compare"
    result = client.get(f"{compare}?base={before}&target={after}", headers=headers).json()
    assert result["resolved_count"] == 1 and result["introduced_count"] == 0
    assert result["resolved"][0]["osv_id"] == "GHSA-gone"
    assert result["risk_score_change"] < 0
    assert result["context_changed"] is False
    assert result["changed_packages"][0]["name"] == "django"
    assert client.get(f"{compare}?base={before}&target={before}", headers=headers).status_code == 400


def test_history_lists_scans_with_counts(client, headers, project, intel):
    intel.advisories["django"] = [make_advisory()]
    run_scan(client, headers, project, "requirements.txt", "django==3.2.0")
    history = client.get(f"/api/projects/{project['id']}/history", headers=headers).json()
    assert history[0]["number"] == 1
    assert history[0]["total_vulnerabilities"] == 1
    assert history[0]["vulnerabilities_by_risk_level"]["medium"] == 1