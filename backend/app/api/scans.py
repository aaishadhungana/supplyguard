from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_owned_project
from app.db.session import get_db
from app.models.project import Project
from app.models.scan import Scan
from app.schemas.scan import ScanRead
from app.services.scans import create_scan

router = APIRouter(prefix="/projects/{project_id}/scans", tags=["scans"])


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def start_scan(
    project: Project = Depends(get_owned_project),
    db: Session = Depends(get_db),
) -> Scan:
    return create_scan(db, project)


@router.get("", response_model=list[ScanRead])
def list_scans(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    project: Project = Depends(get_owned_project),
    db: Session = Depends(get_db),
) -> list[Scan]:
    statement = (
        select(Scan)
        .where(Scan.project_id == project.id)
        .order_by(Scan.number.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(db.scalars(statement))


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(
    scan_id: UUID,
    project: Project = Depends(get_owned_project),
    db: Session = Depends(get_db),
) -> Scan:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.project_id == project.id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan