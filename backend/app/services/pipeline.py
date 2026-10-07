import logging
from uuid import UUID

from sqlalchemy.orm import Session

from app.analysis.registry import parse_manifest
from app.analysis.types import ManifestError, PackageRef, ParsedManifest
from app.db.session import SessionLocal
from app.intel.errors import IntelligenceUnavailable
from app.intel.service import collect_findings
from app.models.dependency import Dependency, DependencyEdge
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability
from app.risk.engine import RiskContext, overall_score
from app.risk.service import ScoredFinding, score_findings
from app.services.ai import run_ai_analysis
from app.services.scans import transition_scan

logger = logging.getLogger(__name__)


def store_inventory(db: Session, scan: Scan, manifest: ParsedManifest) -> dict[PackageRef, UUID]:
    rows = {
        component.ref: Dependency(
            scan_id=scan.id,
            ecosystem=component.ref.ecosystem,
            name=component.ref.name,
            version=component.ref.version,
            purl=component.ref.purl,
            is_direct=component.is_direct,
            scope=component.scope,
        )
        for component in manifest.components
    }
    db.add_all(rows.values())
    db.flush()
    ids = {ref: row.id for ref, row in rows.items()}

    for component in manifest.components:
        if component.is_direct:
            db.add(DependencyEdge(scan_id=scan.id, parent_id=None, child_id=ids[component.ref]))
    for parent, child in manifest.edges:
        db.add(DependencyEdge(scan_id=scan.id, parent_id=ids[parent], child_id=ids[child]))
    db.commit()
    return ids


def store_findings(
    db: Session,
    scan: Scan,
    ids: dict[PackageRef, UUID],
    scored: list[ScoredFinding],
) -> None:
    for item in scored:
        advisory = item.finding.advisory
        db.add(
            Vulnerability(
                scan_id=scan.id,
                dependency_id=ids[item.finding.ref],
                osv_id=advisory.osv_id,
                aliases=advisory.aliases,
                summary=advisory.summary,
                severity=advisory.severity,
                cvss_score=advisory.cvss_score,
                cvss_vector=advisory.cvss_vector,
                known_exploited=advisory.known_exploited,
                fixed_versions=advisory.fixed_versions,
                published=advisory.published,
                risk_score=item.risk.score,
                risk_level=item.risk.level,
                priority_rank=item.rank,
                component_role=item.role,
                risk_breakdown=item.risk.breakdown,
                attack_path=item.path,
            )
        )
    db.flush()


def run_scan(scan_id: UUID, filename: str, content: str) -> None:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        try:
            transition_scan(db, scan, ScanStatus.RUNNING)
            manifest = parse_manifest(filename, content)
            ids = store_inventory(db, scan, manifest)
            findings, intel_warnings = collect_findings(list(ids))

            context = RiskContext(
                internet_facing=scan.project.internet_facing,
                criticality=scan.project.criticality,
            )
            scored = score_findings(manifest, findings, context)
            store_findings(db, scan, ids, scored)

            scan.context = {
                "internet_facing": context.internet_facing,
                "criticality": context.criticality,
            }
            scan.risk_score = overall_score([item.risk.score for item in scored])
            scan.warnings = [*manifest.warnings, *intel_warnings]
            db.commit()

            run_ai_analysis(db, scan)
            transition_scan(db, scan, ScanStatus.COMPLETED)
        except (ManifestError, IntelligenceUnavailable) as exc:
            db.rollback()
            transition_scan(db, scan, ScanStatus.FAILED, str(exc))
        except Exception:
            logger.exception("Scan %s failed unexpectedly", scan_id)
            db.rollback()
            transition_scan(db, scan, ScanStatus.FAILED, "Unexpected error during analysis")