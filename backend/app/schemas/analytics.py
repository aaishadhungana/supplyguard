from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel


class ScanHistoryItem(BaseModel):
    scan_id: UUID
    number: int
    status: str
    source_filename: str | None
    created_at: datetime
    completed_at: datetime | None
    overall_risk_score: float | None
    total_vulnerabilities: int
    vulnerabilities_by_risk_level: dict[str, int]
    context: dict[str, Any] | None
    ai_status: str | None


class ComparisonSide(BaseModel):
    scan_id: UUID
    number: int
    created_at: datetime
    overall_risk_score: float | None
    total_dependencies: int
    vulnerable_dependencies: int
    total_vulnerabilities: int
    vulnerabilities_by_risk_level: dict[str, int]
    context: dict[str, Any] | None


class FindingRef(BaseModel):
    vulnerability_id: UUID
    osv_id: str
    package_name: str
    package_version: str
    ecosystem: str
    scope: str
    risk_score: float | None
    risk_level: str | None


class PackageChange(BaseModel):
    name: str
    ecosystem: str
    from_versions: list[str]
    to_versions: list[str]


class ComparisonResult(BaseModel):
    base: ComparisonSide
    target: ComparisonSide
    risk_score_change: float | None
    context_changed: bool
    resolved_count: int
    introduced_count: int
    persisting_count: int
    resolved: list[FindingRef]
    introduced: list[FindingRef]
    changed_packages: list[PackageChange]