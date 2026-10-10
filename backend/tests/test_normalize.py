from app.analysis.types import PackageRef
from app.intel.normalize import normalize_advisory

RECORD = {
    "id": "GHSA-test-1234",
    "aliases": ["CVE-2021-23337"],
    "summary": "Command injection in lodash",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
        },
        {
            "package": {"ecosystem": "npm", "name": "unrelated"},
            "ranges": [{"type": "SEMVER", "events": [{"fixed": "9.9.9"}]}],
        },
    ],
    "published": "2021-02-15T12:00:00Z",
}
LODASH = PackageRef("npm", "lodash", "4.17.15")


def test_normalizes_score_severity_aliases_and_fixes():
    advisory = normalize_advisory(RECORD, LODASH, frozenset())
    assert advisory.cvss_score == 7.2
    assert advisory.severity == "high"
    assert advisory.aliases == ["CVE-2021-23337"]
    assert advisory.fixed_versions == ["4.17.21"]
    assert advisory.published is not None and advisory.published.tzinfo is not None


def test_known_exploited_is_true_false_or_unknown():
    assert normalize_advisory(RECORD, LODASH, frozenset({"CVE-2021-23337"})).known_exploited is True
    assert normalize_advisory(RECORD, LODASH, frozenset({"CVE-1999-0001"})).known_exploited is False
    assert normalize_advisory(RECORD, LODASH, None).known_exploited is None


def test_falls_back_to_database_severity_without_cvss_vector():
    record = {"id": "PYSEC-1", "database_specific": {"severity": "MODERATE"}, "details": "First line\nSecond line"}
    advisory = normalize_advisory(record, LODASH, None)
    assert advisory.cvss_score is None
    assert advisory.severity == "medium"
    assert advisory.summary == "First line"


def test_pypi_package_names_are_compared_in_normalized_form():
    record = {
        "id": "PYSEC-2",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "Django"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "3.2.5"}]}],
            }
        ],
    }
    advisory = normalize_advisory(record, PackageRef("PyPI", "django", "3.2.0"), None)
    assert advisory.fixed_versions == ["3.2.5"]