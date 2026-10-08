from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_owned_project
from app.api.scans import _to_read as vulnerability_to_read
from app.api.scans import get_owned_scan
from app.db.session import get_db
from app.models.dependency import Dependency
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability
from app.schemas.analytics import ComparisonResult, ScanHistoryItem
from app.schemas.results import VulnerabilityRead
from app.services.analytics import build_comparison, build_history
from app.services.report import build_report

router = APIRouter(prefix="/projects/{project_id}", tags=["insights"])


@router.get("/history", response_model=list[ScanHistoryItem])
def scan_history(
    limit: int = Query(30, ge=1, le=100),
    project: Project = Depends(get_owned_project),
    db: Session = Depends(get_db),
) -> list[ScanHistoryItem]:
    return build_history(db, project, limit)


@router.get("/compare", response_model=ComparisonResult)
def compare_scans(
    base: UUID = Query(...),
    target: UUID = Query(...),
    project: Project = Depends(get_owned_project),
    db: Session = Depends(get_db),
) -> ComparisonResult:
    if base == target:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose two different scans")
    scans = {
        scan.id: scan
        for scan in db.scalars(
            select(Scan).where(Scan.project_id == project.id, Scan.id.in_([base, target]))
        )
    }
    if base not in scans or target not in scans:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if any(scan.status != ScanStatus.COMPLETED.value for scan in scans.values()):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Both scans must be completed")
    return build_comparison(db, scans[base], scans[target])


@router.get("/scans/{scan_id}/findings/{finding_id}", response_model=VulnerabilityRead)
def finding_detail(
    finding_id: UUID,
    scan: Scan = Depends(get_owned_scan),
    db: Session = Depends(get_db),
) -> VulnerabilityRead:
    row = db.execute(
        select(Vulnerability, Dependency)
        .join(Dependency, Vulnerability.dependency_id == Dependency.id)
        .where(Vulnerability.id == finding_id, Vulnerability.scan_id == scan.id)
    ).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return vulnerability_to_read(row[0], row[1])


@router.get("/scans/{scan_id}/report")
def download_report(scan: Scan = Depends(get_owned_scan), db: Session = Depends(get_db)) -> Response:
    if scan.status != ScanStatus.COMPLETED.value:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan is not completed")
    return Response(
        content=build_report(db, scan),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="supplyguard-report-scan-{scan.number}.md"'},
    )