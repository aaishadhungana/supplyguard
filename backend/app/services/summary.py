from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.dependency import Dependency
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability

RISK_LEVELS = ("critical", "high", "medium", "low")


def scan_statistics(db: Session, scan: Scan) -> dict:
    counts = dict(
        db.execute(
            select(Vulnerability.risk_level, func.count())
            .where(Vulnerability.scan_id == scan.id)
            .group_by(Vulnerability.risk_level)
        ).all()
    )
    total_dependencies = db.scalar(
        select(func.count()).select_from(Dependency).where(Dependency.scan_id == scan.id)
    )
    vulnerable_dependencies = db.scalar(
        select(func.count(func.distinct(Vulnerability.dependency_id))).where(Vulnerability.scan_id == scan.id)
    )
    return {
        "total_dependencies": total_dependencies or 0,
        "vulnerable_dependencies": vulnerable_dependencies or 0,
        "total_vulnerabilities": sum(counts.values()),
        "vulnerabilities_by_risk_level": {level: counts.get(level, 0) for level in RISK_LEVELS},
    }


def build_summary(db: Session, scan: Scan) -> dict:
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "overall_risk_score": scan.risk_score,
        **scan_statistics(db, scan),
        "context": scan.context,
        "ai_status": scan.ai_status,
        "ai_message": scan.ai_message,
        "ai_summary": scan.ai_summary,
    }