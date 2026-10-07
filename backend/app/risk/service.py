from dataclasses import dataclass

from app.analysis.types import ParsedManifest
from app.intel.service import Finding
from app.risk.attack_paths import describe_path, shortest_paths
from app.risk.engine import RiskContext, RiskInput, RiskResult, compute_risk
from app.risk.roles import role_for


@dataclass
class ScoredFinding:
    finding: Finding
    risk: RiskResult
    path: dict | None
    role: str | None
    rank: int = 0


def score_findings(
    manifest: ParsedManifest,
    findings: list[Finding],
    context: RiskContext,
) -> list[ScoredFinding]:
    components = {component.ref: component for component in manifest.components}
    chains = shortest_paths(manifest, {finding.ref for finding in findings})

    scored: list[ScoredFinding] = []
    for finding in findings:
        component = components[finding.ref]
        advisory = finding.advisory
        chain = chains.get(finding.ref)
        path = describe_path(chain, components, context.internet_facing) if chain else None
        role = role_for(finding.ref)
        risk = compute_risk(
            RiskInput(
                cvss_score=advisory.cvss_score,
                severity=advisory.severity,
                known_exploited=advisory.known_exploited,
                is_direct=component.is_direct,
                scope=component.scope,
                role=role,
                has_attack_path=path is not None,
                path_through_entry_point=bool(path and path["through_entry_point"]),
                context=context,
            )
        )
        scored.append(ScoredFinding(finding=finding, risk=risk, path=path, role=role))

    scored.sort(
        key=lambda item: (
            -item.risk.score,
            -(item.finding.advisory.cvss_score or 0.0),
            item.finding.advisory.osv_id,
            item.finding.ref.name,
        )
    )
    for rank, item in enumerate(scored, start=1):
        item.rank = rank
    return scored