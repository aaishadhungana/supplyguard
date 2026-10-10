import pytest

from app.risk.engine import RiskContext, RiskInput, compute_risk, overall_score, risk_level


def make_input(**overrides) -> RiskInput:
    values = dict(
        cvss_score=7.0,
        severity="high",
        known_exploited=False,
        is_direct=True,
        scope="production",
        role=None,
        has_attack_path=False,
        path_through_entry_point=False,
        context=RiskContext(internet_facing=False, criticality="medium"),
    )
    values.update(overrides)
    return RiskInput(**values)


def factor(result, name):
    return next(item for item in result.breakdown if item["factor"] == name)


def test_baseline_score():
    result = compute_risk(make_input())
    assert result.score == 38.5
    assert result.level == "medium"


def test_known_exploited_adds_twenty_points():
    result = compute_risk(make_input(known_exploited=True))
    assert result.score == 58.5
    assert result.level == "high"


def test_internet_exposure_adds_ten_points():
    context = RiskContext(internet_facing=True, criticality="medium")
    assert compute_risk(make_input(context=context)).score == 48.5


def test_development_scope_reduces_score():
    result = compute_risk(make_input(scope="development"))
    assert result.score == 15.4
    assert result.level == "low"
    assert factor(result, "scope")["multiplier"] == 0.4


def test_maximum_score_is_capped_at_one_hundred():
    result = compute_risk(
        make_input(
            cvss_score=10.0,
            known_exploited=True,
            role="auth",
            has_attack_path=True,
            path_through_entry_point=True,
            context=RiskContext(internet_facing=True, criticality="critical"),
        )
    )
    assert result.score == 100.0
    assert result.level == "critical"


def test_missing_cvss_uses_assumed_score_from_severity():
    result = compute_risk(make_input(cvss_score=None, severity="high"))
    assert factor(result, "severity")["points"] == 36.0
    assert "assumed" in factor(result, "severity")["detail"]


def test_unknown_exploit_status_adds_nothing_and_says_so():
    result = compute_risk(make_input(known_exploited=None))
    assert factor(result, "exploit")["points"] == 0.0
    assert "unknown" in factor(result, "exploit")["detail"].lower()


def test_score_is_deterministic():
    data = make_input(known_exploited=True, role="crypto", has_attack_path=True)
    assert compute_risk(data) == compute_risk(data)


def test_breakdown_adds_up_to_score():
    result = compute_risk(make_input(known_exploited=True, role="database", has_attack_path=True))
    raw = sum(item["points"] for item in result.breakdown if "points" in item)
    assert result.score == round(raw, 1)


@pytest.mark.parametrize(
    "score,expected",
    [(75, "critical"), (74.9, "high"), (55, "high"), (54.9, "medium"), (35, "medium"), (34.9, "low"), (0, "low")],
)
def test_risk_levels(score, expected):
    assert risk_level(score) == expected


def test_overall_score():
    assert overall_score([]) == 0.0
    assert overall_score([80.0]) == 80.0
    assert overall_score([80.0, 40.0, 20.0]) == 70.0