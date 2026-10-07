import math

_ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
_PRIVILEGES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PRIVILEGES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_USER_INTERACTION = {"N": 0.85, "R": 0.62}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    parts = vector.split("/")
    if not parts or not parts[0].startswith("CVSS:3"):
        return None
    metrics = dict(part.split(":", 1) for part in parts[1:] if ":" in part)
    try:
        scope_changed = metrics["S"] == "C"
        privileges = (_PRIVILEGES_CHANGED if scope_changed else _PRIVILEGES_UNCHANGED)[metrics["PR"]]
        exploitability = (
            8.22
            * _ATTACK_VECTOR[metrics["AV"]]
            * _ATTACK_COMPLEXITY[metrics["AC"]]
            * privileges
            * _USER_INTERACTION[metrics["UI"]]
        )
        iss = 1 - (
            (1 - _IMPACT[metrics["C"]]) * (1 - _IMPACT[metrics["I"]]) * (1 - _IMPACT[metrics["A"]])
        )
    except KeyError:
        return None

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0

    total = impact + exploitability
    if scope_changed:
        total *= 1.08
    return _roundup(min(total, 10.0))


def severity_from_score(score: float | None) -> str:
    if score is None or score <= 0:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"