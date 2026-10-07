from dataclasses import dataclass
from statistics import mean

CVSS_WEIGHT = 4.5
EXPLOIT_POINTS = 20.0
EXPOSURE_POINTS = 10.0
ENTRY_POINT_PATH_POINTS = 5.0
PATH_POINTS = 2.0
DIRECT_POINTS = 3.0
DEV_SCOPE_FACTOR = 0.4

CRITICALITY_POINTS = {"low": 0.0, "medium": 4.0, "high": 7.0, "critical": 10.0}
ROLE_POINTS = {"auth": 7.0, "crypto": 7.0, "web_framework": 5.0, "database": 5.0, "serialization": 5.0}
FALLBACK_CVSS = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5, "unknown": 5.0}
LEVEL_THRESHOLDS = ((75.0, "critical"), (55.0, "high"), (35.0, "medium"))


@dataclass(frozen=True)
class RiskContext:
    internet_facing: bool
    criticality: str


@dataclass(frozen=True)
class RiskInput:
    cvss_score: float | None
    severity: str
    known_exploited: bool | None
    is_direct: bool
    scope: str
    role: str | None
    has_attack_path: bool
    path_through_entry_point: bool
    context: RiskContext


@dataclass(frozen=True)
class RiskResult:
    score: float
    level: str
    breakdown: list[dict]


def risk_level(score: float) -> str:
    for threshold, level in LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "low"


def _factor(name: str, points: float, maximum: float, detail: str) -> dict:
    return {"factor": name, "points": round(points, 2), "max_points": maximum, "detail": detail}


def compute_risk(data: RiskInput) -> RiskResult:
    if data.cvss_score is not None:
        cvss = min(max(data.cvss_score, 0.0), 10.0)
        severity_detail = f"CVSS v3 base score {cvss}"
    else:
        cvss = FALLBACK_CVSS.get(data.severity, FALLBACK_CVSS["unknown"])
        severity_detail = f"No CVSS v3 vector; severity '{data.severity}' mapped to an assumed score of {cvss}"

    if data.known_exploited is True:
        exploit_points, exploit_detail = EXPLOIT_POINTS, "Listed in the CISA Known Exploited Vulnerabilities catalog"
    elif data.known_exploited is False:
        exploit_points, exploit_detail = 0.0, "Not listed in the CISA Known Exploited Vulnerabilities catalog"
    else:
        exploit_points, exploit_detail = 0.0, "Exploit status unknown (KEV catalog unavailable)"

    if data.context.internet_facing:
        exposure_points, exposure_detail = EXPOSURE_POINTS, "Application is marked internet-facing"
    else:
        exposure_points, exposure_detail = 0.0, "Application is not marked internet-facing"

    if data.role:
        role_points = ROLE_POINTS.get(data.role, 0.0)
        role_detail = f"Package role '{data.role}' (inferred from the package name)"
    else:
        role_points, role_detail = 0.0, "No sensitive role inferred from the package name"

    if data.path_through_entry_point:
        path_points, path_detail = ENTRY_POINT_PATH_POINTS, "Dependency chain passes through a web framework entry point"
    elif data.has_attack_path:
        path_points, path_detail = PATH_POINTS, "Dependency chain from the application to the package is established"
    else:
        path_points, path_detail = 0.0, "No dependency chain from the application was found"

    if data.is_direct:
        direct_points, direct_detail = DIRECT_POINTS, "Direct dependency of the application"
    else:
        direct_points, direct_detail = 0.0, "Transitive dependency"

    criticality = CRITICALITY_POINTS.get(data.context.criticality, CRITICALITY_POINTS["medium"])

    factors = [
        _factor("severity", cvss * CVSS_WEIGHT, 45.0, severity_detail),
        _factor("exploit", exploit_points, EXPLOIT_POINTS, exploit_detail),
        _factor("exposure", exposure_points, EXPOSURE_POINTS, exposure_detail),
        _factor("component_role", role_points, 7.0, role_detail),
        _factor("attack_path", path_points, ENTRY_POINT_PATH_POINTS, path_detail),
        _factor("dependency_type", direct_points, DIRECT_POINTS, direct_detail),
        _factor("application_criticality", criticality, 10.0, f"Application criticality: {data.context.criticality}"),
    ]
    raw_total = sum(factor["points"] for factor in factors)

    if data.scope == "development":
        multiplier, scope_detail = DEV_SCOPE_FACTOR, "Development-only dependency; total reduced"
    else:
        multiplier, scope_detail = 1.0, "Production dependency; no reduction"
    factors.append({"factor": "scope", "multiplier": multiplier, "detail": scope_detail})

    score = round(min(100.0, raw_total * multiplier), 1)
    return RiskResult(score=score, level=risk_level(score), breakdown=factors)


def overall_score(scores: list[float]) -> float:
    if not scores:
        return 0.0
    ordered = sorted(scores, reverse=True)
    return round(0.7 * ordered[0] + 0.3 * mean(ordered[:5]), 1)