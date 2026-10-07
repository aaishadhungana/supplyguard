from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class DependencyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    ecosystem: str
    name: str
    version: str
    purl: str
    is_direct: bool
    scope: str
    vulnerability_count: int = 0
    risk_score: float | None = None


class VulnerabilityRead(BaseModel):
    id: UUID
    osv_id: str
    aliases: list[str]
    summary: str
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    known_exploited: bool | None
    fixed_versions: list[str]
    published: datetime | None
    url: str
    dependency_id: UUID
    package_name: str
    package_version: str
    ecosystem: str
    is_direct: bool
    scope: str
    risk_score: float | None
    risk_level: str | None
    priority_rank: int | None
    component_role: str | None
    risk_breakdown: list[dict[str, Any]] | None
    attack_path: dict[str, Any] | None
    ai_analysis: dict[str, Any] | None
    remediation_hint: str


class GraphNode(BaseModel):
    id: str
    name: str
    version: str
    ecosystem: str
    is_direct: bool
    scope: str
    vulnerable: bool


class GraphEdge(BaseModel):
    source: str
    target: str


class DependencyGraph(BaseModel):
    application: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class ScanSummary(BaseModel):
    scan_id: UUID
    status: str
    overall_risk_score: float | None
    total_dependencies: int
    vulnerable_dependencies: int
    total_vulnerabilities: int
    vulnerabilities_by_risk_level: dict[str, int]
    context: dict[str, Any] | None
    ai_status: str | None
    ai_message: str | None
    ai_summary: dict[str, Any] | None