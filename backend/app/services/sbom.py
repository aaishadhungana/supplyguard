from collections import defaultdict
from datetime import datetime, timezone

from app.core.config import get_settings
from app.models.dependency import Dependency, DependencyEdge
from app.models.project import Project
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability


def _component(dependency: Dependency) -> dict:
    return {
        "type": "library",
        "bom-ref": dependency.purl,
        "name": dependency.name,
        "version": dependency.version,
        "purl": dependency.purl,
        "scope": "required" if dependency.scope == "production" else "optional",
        "properties": [
            {"name": "supplyguard:ecosystem", "value": dependency.ecosystem},
            {"name": "supplyguard:relationship", "value": "direct" if dependency.is_direct else "transitive"},
            {"name": "supplyguard:scope", "value": dependency.scope},
        ],
    }


def _vulnerability_entry(osv_id: str, items: list[Vulnerability], purls: dict) -> dict:
    first = items[0]
    entry: dict = {
        "id": osv_id,
        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{osv_id}"},
        "description": first.summary,
        "affects": [{"ref": purls[item.dependency_id]} for item in items],
    }
    if first.severity != "unknown":
        rating: dict = {"source": {"name": "OSV"}, "severity": first.severity}
        if first.cvss_score is not None:
            rating["score"] = first.cvss_score
            rating["method"] = "CVSSv31" if (first.cvss_vector or "").startswith("CVSS:3.1") else "CVSSv3"
            rating["vector"] = first.cvss_vector
        entry["ratings"] = [rating]
    if first.known_exploited is not None:
        entry["properties"] = [
            {"name": "supplyguard:known_exploited", "value": str(first.known_exploited).lower()}
        ]
    return entry


def build_cyclonedx(
    project: Project,
    scan: Scan,
    dependencies: list[Dependency],
    edges: list[DependencyEdge],
    vulnerabilities: list[Vulnerability],
) -> dict:
    settings = get_settings()
    purls = {dependency.id: dependency.purl for dependency in dependencies}
    root_ref = f"application:{project.id}"

    children: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        parent_ref = root_ref if edge.parent_id is None else purls[edge.parent_id]
        children[parent_ref].add(purls[edge.child_id])

    grouped: dict[str, list[Vulnerability]] = defaultdict(list)
    for vulnerability in vulnerabilities:
        grouped[vulnerability.osv_id].append(vulnerability)

    timestamp = (scan.completed_at or datetime.now(timezone.utc)).isoformat()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{scan.id}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {"type": "application", "name": "SupplyGuard", "version": settings.app_version}
                ]
            },
            "component": {"type": "application", "bom-ref": root_ref, "name": project.name},
        },
        "components": [_component(dependency) for dependency in dependencies],
        "dependencies": [
            {"ref": root_ref, "dependsOn": sorted(children[root_ref])},
            *[
                {"ref": dependency.purl, "dependsOn": sorted(children[dependency.purl])}
                for dependency in dependencies
            ],
        ],
        "vulnerabilities": [
            _vulnerability_entry(osv_id, items, purls) for osv_id, items in sorted(grouped.items())
        ],
    }