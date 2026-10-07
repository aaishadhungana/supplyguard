import re
from uuid import UUID

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.registry import SUPPORTED_MANIFESTS
from app.api.deps import get_owned_project
from app.db.session import get_db
from app.models.dependency import Dependency, DependencyEdge
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability
from app.schemas.results import (
    DependencyGraph,
    DependencyRead,
    GraphEdge,
    GraphNode,
    VulnerabilityRead,
)
from app.schemas.scan import ScanRead
from app.services.pipeline import run_scan
from app.services.sbom import build_cyclonedx
from app.services.scans import create_scan

MAX_MANIFEST_BYTES = 5 * 1024 * 1024

router = APIRouter(prefix="/projects/{project_id}/scans", tags=["scans"])


def get_owned_scan(
    scan_id: UUID,
    project: Project = Depends(get_owned_project),
    db: Session = Depends(get_db),
) -> Scan:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.project_id == project.id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.post("", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
def start_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    project: Project = Depends(get_owned_project),
    db: Session = Depends(get_db),
) -> Scan:
    filename = re.split(r"[\\/]", file.filename or "")[-1]
    if filename not in SUPPORTED_MANIFESTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file. Upload one of: {', '.join(sorted(SUPPORTED_MANIFESTS))}",
        )
    raw = file.file.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File exceeds the 5 MB limit")
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be UTF-8 text (PowerShell's > redirect writes UTF-16; re-save as UTF-8)",
        )
    scan = create_scan(db, project, filename)
    background_tasks.add_task(run_scan, scan.id, filename, content)
    return scan


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
def get_scan(scan: Scan = Depends(get_owned_scan)) -> Scan:
    return scan


@router.get("/{scan_id}/dependencies", response_model=list[DependencyRead])
def list_dependencies(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    scan: Scan = Depends(get_owned_scan),
    db: Session = Depends(get_db),
) -> list[DependencyRead]:
    vulnerability_count = func.count(Vulnerability.id)
    rows = db.execute(
        select(Dependency, vulnerability_count)
        .outerjoin(Vulnerability, Vulnerability.dependency_id == Dependency.id)
        .where(Dependency.scan_id == scan.id)
        .group_by(Dependency.id)
        .order_by(vulnerability_count.desc(), Dependency.name, Dependency.version)
        .limit(limit)
        .offset(offset)
    ).all()
    return [
        DependencyRead.model_validate(dependency).model_copy(update={"vulnerability_count": count})
        for dependency, count in rows
    ]


@router.get("/{scan_id}/vulnerabilities", response_model=list[VulnerabilityRead])
def list_vulnerabilities(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    scan: Scan = Depends(get_owned_scan),
    db: Session = Depends(get_db),
) -> list[VulnerabilityRead]:
    rows = db.execute(
        select(Vulnerability, Dependency)
        .join(Dependency, Vulnerability.dependency_id == Dependency.id)
        .where(Vulnerability.scan_id == scan.id)
        .order_by(Vulnerability.cvss_score.desc().nulls_last(), Vulnerability.osv_id)
        .limit(limit)
        .offset(offset)
    ).all()
    return [
        VulnerabilityRead(
            id=vulnerability.id,
            osv_id=vulnerability.osv_id,
            aliases=vulnerability.aliases,
            summary=vulnerability.summary,
            severity=vulnerability.severity,
            cvss_score=vulnerability.cvss_score,
            cvss_vector=vulnerability.cvss_vector,
            known_exploited=vulnerability.known_exploited,
            fixed_versions=vulnerability.fixed_versions,
            published=vulnerability.published,
            url=f"https://osv.dev/vulnerability/{vulnerability.osv_id}",
            dependency_id=dependency.id,
            package_name=dependency.name,
            package_version=dependency.version,
            ecosystem=dependency.ecosystem,
            is_direct=dependency.is_direct,
            scope=dependency.scope,
        )
        for vulnerability, dependency in rows
    ]


@router.get("/{scan_id}/graph", response_model=DependencyGraph)
def get_graph(scan: Scan = Depends(get_owned_scan), db: Session = Depends(get_db)) -> DependencyGraph:
    dependencies = db.scalars(
        select(Dependency).where(Dependency.scan_id == scan.id).order_by(Dependency.name, Dependency.version)
    ).all()
    vulnerable_ids = set(
        db.scalars(select(Vulnerability.dependency_id).where(Vulnerability.scan_id == scan.id).distinct())
    )
    edges = db.scalars(select(DependencyEdge).where(DependencyEdge.scan_id == scan.id)).all()
    return DependencyGraph(
        application=scan.project.name,
        nodes=[
            GraphNode(
                id=str(dependency.id),
                name=dependency.name,
                version=dependency.version,
                ecosystem=dependency.ecosystem,
                is_direct=dependency.is_direct,
                scope=dependency.scope,
                vulnerable=dependency.id in vulnerable_ids,
            )
            for dependency in dependencies
        ],
        edges=[
            GraphEdge(
                source="application" if edge.parent_id is None else str(edge.parent_id),
                target=str(edge.child_id),
            )
            for edge in edges
        ],
    )


@router.get("/{scan_id}/sbom", response_model=None)
def get_sbom(scan: Scan = Depends(get_owned_scan), db: Session = Depends(get_db)) -> dict:
    if scan.status != ScanStatus.COMPLETED.value:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan is not completed")
    dependencies = list(db.scalars(select(Dependency).where(Dependency.scan_id == scan.id)))
    edges = list(db.scalars(select(DependencyEdge).where(DependencyEdge.scan_id == scan.id)))
    vulnerabilities = list(db.scalars(select(Vulnerability).where(Vulnerability.scan_id == scan.id)))
    return build_cyclonedx(scan.project, scan, dependencies, edges, vulnerabilities)