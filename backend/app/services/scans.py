from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.scan import Scan, ScanStatus

ALLOWED_TRANSITIONS: dict[ScanStatus, set[ScanStatus]] = {
    ScanStatus.PENDING: {ScanStatus.RUNNING, ScanStatus.FAILED},
    ScanStatus.RUNNING: {ScanStatus.COMPLETED, ScanStatus.FAILED},
    ScanStatus.COMPLETED: set(),
    ScanStatus.FAILED: set(),
}


class InvalidScanTransition(Exception):
    pass


def create_scan(db: Session, project: Project, source_filename: str | None = None) -> Scan:
    db.execute(select(Project.id).where(Project.id == project.id).with_for_update())
    next_number = db.scalar(
        select(func.coalesce(func.max(Scan.number), 0) + 1).where(Scan.project_id == project.id)
    )
    scan = Scan(project_id=project.id, number=next_number, source_filename=source_filename)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def transition_scan(
    db: Session,
    scan: Scan,
    new_status: ScanStatus,
    error_message: str | None = None,
) -> Scan:
    current = ScanStatus(scan.status)
    if new_status not in ALLOWED_TRANSITIONS[current]:
        raise InvalidScanTransition(f"{current.value} -> {new_status.value}")

    now = datetime.now(timezone.utc)
    if new_status == ScanStatus.RUNNING:
        scan.started_at = now
    if new_status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        scan.completed_at = now
    if new_status == ScanStatus.FAILED:
        scan.error_message = (error_message or "Scan failed")[:1000]

    scan.status = new_status.value
    db.commit()
    db.refresh(scan)
    return scan