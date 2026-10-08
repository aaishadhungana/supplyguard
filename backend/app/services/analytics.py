from collections import defaultdict
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.dependency import Dependency
from app.models.project import Project
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.analytics import (
    ComparisonResult,
    ComparisonSide,
    FindingRef,
    PackageChange,
    ScanHistoryItem,
)
from app.services.summary import RISK_LEVELS, scan_statistics

LIST_LIMIT = 100


def build_history(db: Session, project: Project, limit: int) -> list[ScanHistoryItem]:
    scans = list(
        db.scalars(
            select(Scan).where(Scan.project_id == project.id).order_by(Scan.number.desc()).limit(limit)
        )
    )
    counts: dict[UUID, dict[str, int]] = defaultdict(dict)
    if scans:
        rows = db.execute(
            select(Vulnerability.scan_id, Vulnerability.risk_level, func.count())
            .where(Vulnerability.scan_id.in_([scan.id for scan in scans]))
            .group_by(Vulnerability.scan_id, Vulnerability.risk_level)
        ).all()
        for scan_id, level, count in rows:
            counts[scan_id][level] = count

    items = []
    for scan in scans:
        by_level = {level: counts[scan.id].get(level, 0) for level in RISK_LEVELS}
        items.append(
            ScanHistoryItem(
                scan_id=scan.id,
                number=scan.number,
                status=scan.status,
                source_filename=scan.source_filename,
                created_at=scan.created_at,
                completed_at=scan.completed_at,
                overall_risk_score=scan.risk_score,
                total_vulnerabilities=sum(by_level.values()),
                vulnerabilities_by_risk_level=by_level,
                context=scan.context,
                ai_status=scan.ai_status,
            )
        )
    return items


def _side(db: Session, scan: Scan) -> ComparisonSide:
    return ComparisonSide(
        scan_id=scan.id,
        number=scan.number,
        created_at=scan.created_at,
        overall_risk_score=scan.risk_score,
        context=scan.context,
        **scan_statistics(db, scan),
    )


def _findings(db: Session, scan: Scan) -> dict[tuple[str, str, str], FindingRef]:
    rows = db.execute(
        select(Vulnerability, Dependency)
        .join(Dependency, Vulnerability.dependency_id == Dependency.id)
        .where(Vulnerability.scan_id == scan.id)
        .order_by(Vulnerability.priority_rank.asc().nulls_last())
    ).all()
    found: dict[tuple[str, str, str], FindingRef] = {}
    for vulnerability, dependency in rows:
        key = (dependency.ecosystem, dependency.name, vulnerability.osv_id)
        found.setdefault(
            key,
            FindingRef(
                vulnerability_id=vulnerability.id,
                osv_id=vulnerability.osv_id,
                package_name=dependency.name,
                package_version=dependency.version,
                ecosystem=dependency.ecosystem,
                scope=dependency.scope,
                risk_score=vulnerability.risk_score,
                risk_level=vulnerability.risk_level,
            ),
        )
    return found


def _versions(db: Session, scan: Scan) -> dict[tuple[str, str], set[str]]:
    versions: dict[tuple[str, str], set[str]] = defaultdict(set)
    rows = db.execute(
        select(Dependency.ecosystem, Dependency.name, Dependency.version).where(Dependency.scan_id == scan.id)
    )
    for ecosystem, name, version in rows:
        versions[(ecosystem, name)].add(version)
    return versions


def build_comparison(db: Session, base: Scan, target: Scan) -> ComparisonResult:
    base_side = _side(db, base)
    target_side = _side(db, target)
    base_findings = _findings(db, base)
    target_findings = _findings(db, target)

    resolved_keys = base_findings.keys() - target_findings.keys()
    introduced_keys = target_findings.keys() - base_findings.keys()
    persisting = base_findings.keys() & target_findings.keys()

    def by_risk(items: list[FindingRef]) -> list[FindingRef]:
        return sorted(items, key=lambda item: -(item.risk_score or 0.0))

    resolved = by_risk([base_findings[key] for key in resolved_keys])
    introduced = by_risk([target_findings[key] for key in introduced_keys])

    base_versions = _versions(db, base)
    target_versions = _versions(db, target)
    changes = [
        PackageChange(
            name=key[1],
            ecosystem=key[0],
            from_versions=sorted(base_versions[key]),
            to_versions=sorted(target_versions[key]),
        )
        for key in sorted(base_versions.keys() & target_versions.keys())
        if base_versions[key] != target_versions[key]
    ]

    change = None
    if base_side.overall_risk_score is not None and target_side.overall_risk_score is not None:
        change = round(target_side.overall_risk_score - base_side.overall_risk_score, 1)

    return ComparisonResult(
        base=base_side,
        target=target_side,
        risk_score_change=change,
        context_changed=base_side.context != target_side.context,
        resolved_count=len(resolved),
        introduced_count=len(introduced),
        persisting_count=len(persisting),
        resolved=resolved[:LIST_LIMIT],
        introduced=introduced[:LIST_LIMIT],
        changed_packages=changes[:LIST_LIMIT],
    )