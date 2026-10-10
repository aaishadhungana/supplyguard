import pytest

from app.intel.cvss import cvss3_base_score, severity_from_score


@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_known_vectors(vector, expected):
    assert cvss3_base_score(vector) == expected


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "garbage",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N",
    ],
)
def test_invalid_vectors_return_none(vector):
    assert cvss3_base_score(vector) is None


@pytest.mark.parametrize(
    "score,expected",
    [(None, "unknown"), (0.0, "unknown"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"),
     (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10.0, "critical")],
)
def test_severity_bands(score, expected):
    assert severity_from_score(score) == expected