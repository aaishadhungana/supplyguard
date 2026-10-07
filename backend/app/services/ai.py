import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.analyst import analyze
from app.ai.gemini import AiUnavailable
from app.core.config import get_settings
from app.models.dependency import Dependency
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.services.summary import scan_statistics

logger = logging.getLogger(__name__)


def generate_analysis(db: Session, scan: Scan) -> None:
    settings = get_settings()
    rows = db.execute(
        select(Vulnerability, Dependency)
        .join(Dependency, Vulnerability.dependency_id == Dependency.id)
        .where(Vulnerability.scan_id == scan.id, Vulnerability.priority_rank.is_not(None))
        .order_by(Vulnerability.priority_rank)
        .limit(settings.gemini_max_findings)
    ).all()

    if not rows:
        scan.ai_status = "skipped"
        scan.ai_message = "No vulnerabilities to analyze"
        scan.ai_summary = None
        db.commit()
        return

    try:
        summary, analyses = analyze(
            [(vulnerability, dependency) for vulnerability, dependency in rows],
            scan_statistics(db, scan),
            scan.context or {},
            scan.risk_score or 0.0,
        )
    except AiUnavailable as exc:
        scan.ai_status = "unavailable"
        scan.ai_message = str(exc)[:300]
        scan.ai_summary = None
        db.commit()
        return

    metadata = {
        "model": settings.gemini_model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    for vulnerability, _ in rows:
        analysis = analyses.get(vulnerability.priority_rank)
        vulnerability.ai_analysis = {**metadata, **analysis} if analysis else None
    scan.ai_summary = {**metadata, **summary}
    scan.ai_status = "generated"
    scan.ai_message = None
    db.commit()


def run_ai_analysis(db: Session, scan: Scan) -> None:
    try:
        generate_analysis(db, scan)
    except Exception:
        logger.exception("AI analysis failed for scan %s", scan.id)
        db.rollback()
        scan.ai_status = "unavailable"
        scan.ai_message = "Unexpected error during AI analysis"
        db.commit()