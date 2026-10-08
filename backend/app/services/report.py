import html

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.dependency import Dependency
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.risk.remediation import remediation_hint
from app.services.summary import RISK_LEVELS, scan_statistics

TOP_FINDINGS = 10

LIMITATIONS = [
    "Findings come from OSV.dev advisories matched to exact package versions in the uploaded file.",
    "Risk scores are calculated by SupplyGuard's deterministic model (see docs/risk-model.md); AI never changes them.",
    "Attack paths are dependency chains from the lockfile. Runtime reachability of the vulnerable code was not analyzed.",
    "Package roles (authentication, web framework, and so on) are inferred from package names.",
    "requirements.txt scans cover pinned direct requirements only; transitive dependencies are not resolved.",
    "AI-generated text can be wrong. Verify it against the advisory before acting.",
]


def _plain(value: object) -> str:
    return " ".join(html.escape(str(value or ""), quote=False).split())


def _exploited(value: bool | None) -> str:
    return {True: "yes (CISA KEV)", False: "no", None: "unknown"}[value]


def _factor_line(breakdown: list[dict] | None) -> str:
    parts = [
        f"{item['factor']} {item['points']}/{item['max_points']}"
        for item in breakdown or []
        if "points" in item
    ]
    scope = next((item for item in breakdown or [] if item["factor"] == "scope"), None)
    if scope:
        parts.append(f"scope x{scope['multiplier']}")
    return ", ".join(parts)


def build_report(db: Session, scan: Scan) -> str:
    project = scan.project
    stats = scan_statistics(db, scan)
    context = scan.context or {}
    levels = stats["vulnerabilities_by_risk_level"]
    score = scan.risk_score if scan.risk_score is not None else "n/a"

    lines = [
        "# SupplyGuard Security Report",
        "",
        f"- **Project:** {_plain(project.name)}",
        f"- **Scan:** #{scan.number} ({_plain(scan.source_filename)})",
        f"- **Completed:** {scan.completed_at.isoformat() if scan.completed_at else 'n/a'}",
        f"- **Application context:** internet-facing: {'yes' if context.get('internet_facing') else 'no'}, "
        f"criticality: {_plain(context.get('criticality', 'n/a'))}",
        "",
        "## Summary",
        "",
        f"Overall risk score: **{score} / 100**",
        "",
        "| Risk level | Findings |",
        "|---|---|",
        *[f"| {level.capitalize()} | {levels[level]} |" for level in RISK_LEVELS],
        "",
        f"Dependencies: {stats['total_dependencies']} total, "
        f"{stats['vulnerable_dependencies']} with known vulnerabilities.",
        "",
    ]

    if scan.ai_summary:
        lines += [
            f"### AI-generated summary (model: {_plain(scan.ai_summary.get('model'))}; verify before acting)",
            "",
            _plain(scan.ai_summary.get("executive_summary")),
            "",
            *[f"- {_plain(item)}" for item in scan.ai_summary.get("top_priorities", [])],
            "",
        ]

    lines += [f"## Top {TOP_FINDINGS} prioritized findings", ""]
    rows = db.execute(
        select(Vulnerability, Dependency)
        .join(Dependency, Vulnerability.dependency_id == Dependency.id)
        .where(Vulnerability.scan_id == scan.id, Vulnerability.priority_rank.is_not(None))
        .order_by(Vulnerability.priority_rank)
        .limit(TOP_FINDINGS)
    ).all()
    if not rows:
        lines += ["No known vulnerabilities were found for the dependencies in this scan.", ""]

    for vulnerability, dependency in rows:
        aliases = ", ".join(_plain(alias) for alias in vulnerability.aliases[:3])
        title = f"{_plain(dependency.name)}@{_plain(dependency.version)} - {_plain(vulnerability.osv_id)}"
        lines += [
            f"### {vulnerability.priority_rank}. {title}",
            "",
            f"- **Risk:** {vulnerability.risk_score} ({vulnerability.risk_level})",
            f"- **Advisory:** {_plain(vulnerability.summary)}" + (f" ({aliases})" if aliases else ""),
            f"- **Severity:** {vulnerability.severity}, CVSS {vulnerability.cvss_score or 'n/a'}, "
            f"known exploited: {_exploited(vulnerability.known_exploited)}",
            f"- **Dependency:** {'direct' if dependency.is_direct else 'transitive'}, {dependency.scope}",
        ]
        if vulnerability.attack_path:
            chain = " -> ".join(_plain(node["label"]) for node in vulnerability.attack_path["nodes"])
            lines.append(f"- **Attack path:** {chain}")
        lines += [
            f"- **Score factors:** {_factor_line(vulnerability.risk_breakdown)}",
            f"- **Recommended action:** "
            f"{remediation_hint(dependency.name, dependency.is_direct, vulnerability.fixed_versions)}",
        ]
        analysis = vulnerability.ai_analysis
        if analysis:
            lines += [
                "",
                "AI-generated analysis (verify before acting):",
                f"- Why it matters: {_plain(analysis.get('why_it_matters'))}",
                f"- Potential impact: {_plain(analysis.get('potential_impact'))}",
                f"- Remediation: {_plain(analysis.get('remediation'))}",
            ]
        lines.append("")

    lines += ["## Method and limitations", "", *[f"- {item}" for item in LIMITATIONS], ""]
    return "\n".join(lines)