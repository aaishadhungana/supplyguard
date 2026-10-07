from dataclasses import dataclass

import httpx

from app.analysis.types import PackageRef
from app.intel.kev import get_known_exploited_cves
from app.intel.normalize import NormalizedAdvisory, normalize_advisory
from app.intel.osv import fetch_records, fetch_vulnerability_ids


@dataclass
class Finding:
    ref: PackageRef
    advisory: NormalizedAdvisory


def collect_findings(refs: list[PackageRef]) -> tuple[list[Finding], list[str]]:
    warnings: list[str] = []
    transport = httpx.HTTPTransport(retries=2)
    with httpx.Client(
        transport=transport,
        timeout=20,
        headers={"User-Agent": "SupplyGuard/0.3"},
    ) as client:
        ids_by_ref = fetch_vulnerability_ids(client, refs)
        unique_ids = sorted({vuln_id for ids in ids_by_ref.values() for vuln_id in ids})
        records = fetch_records(client, unique_ids)
        known_exploited = get_known_exploited_cves(client)

    if known_exploited is None:
        warnings.append("CISA KEV catalog was unavailable; exploit status is unknown for this scan")

    findings = [
        Finding(ref, normalize_advisory(records[vuln_id], ref, known_exploited))
        for ref, ids in ids_by_ref.items()
        for vuln_id in ids
    ]
    return findings, warnings