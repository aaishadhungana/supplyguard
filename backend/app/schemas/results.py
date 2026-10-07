from datetime import datetime
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