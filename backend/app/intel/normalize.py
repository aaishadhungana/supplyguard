import re
from dataclasses import dataclass, field
from datetime import datetime

from app.analysis.types import PackageRef
from app.intel.cvss import cvss3_base_score, severity_from_score

_DATABASE_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


@dataclass
class NormalizedAdvisory:
    osv_id: str
    aliases: list[str]
    summary: str
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    known_exploited: bool | None
    fixed_versions: list[str] = field(default_factory=list)
    published: datetime | None = None


def _canonical(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name


def _fixed_versions(record: dict, ref: PackageRef) -> list[str]:
    fixed: list[str] = []
    target = _canonical(ref.ecosystem, ref.name)
    for affected in record.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem") != ref.ecosystem:
            continue
        if _canonical(ref.ecosystem, package.get("name", "")) != target:
            continue
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                version = event.get("fixed")
                if version and version not in fixed:
                    fixed.append(version)
    return fixed


def _cvss(record: dict) -> tuple[float | None, str | None]:
    for entry in record.get("severity", []):
        if entry.get("type") != "CVSS_V3":
            continue
        vector = entry.get("score", "")
        score = cvss3_base_score(vector)
        if score is not None:
            return score, vector
    return None, None


def _summary(record: dict) -> str:
    summary = record.get("summary")
    if not summary:
        details = (record.get("details") or "").strip()
        summary = details.splitlines()[0][:300] if details else "No description provided"
    return summary[:1000]


def _published(record: dict) -> datetime | None:
    value = record.get("published")
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_advisory(
    record: dict,
    ref: PackageRef,
    known_exploited: frozenset[str] | None,
) -> NormalizedAdvisory:
    osv_id = record["id"]
    aliases = [alias for alias in record.get("aliases", []) if isinstance(alias, str)]
    score, vector = _cvss(record)
    severity = severity_from_score(score)
    if severity == "unknown":
        database_specific = record.get("database_specific")
        label = database_specific.get("severity", "") if isinstance(database_specific, dict) else ""
        severity = _DATABASE_SEVERITY.get(str(label).upper(), "unknown")

    exploited = None
    if known_exploited is not None:
        exploited = any(identifier in known_exploited for identifier in [osv_id, *aliases])

    return NormalizedAdvisory(
        osv_id=osv_id,
        aliases=aliases,
        summary=_summary(record),
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        known_exploited=exploited,
        fixed_versions=_fixed_versions(record, ref),
        published=_published(record),
    )