"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { ExternalLink } from "lucide-react";
import { getFinding, type AiAnalysis } from "@/lib/api";
import { useLoad } from "@/lib/hooks";
import AttackPath from "@/components/AttackPath";
import { Card, ErrorNotice, Loading, Notice, RiskBadge, formatDate } from "@/components/ui";

const AI_SECTIONS: { key: keyof AiAnalysis; label: string }[] = [
  { key: "why_it_matters", label: "Why it matters" },
  { key: "potential_impact", label: "Potential impact" },
  { key: "priority_reasoning", label: "Why it has this priority" },
  { key: "attack_path_explanation", label: "Attack path" },
  { key: "remediation", label: "Remediation" },
];

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs uppercase text-slate-500">{label}</dt>
      <dd className="mt-1 text-sm text-slate-200">{children}</dd>
    </div>
  );
}

export default function FindingPage() {
  const { projectId, scanId, findingId } = useParams<{
    projectId: string;
    scanId: string;
    findingId: string;
  }>();
  const finding = useLoad(() => getFinding(projectId, scanId, findingId), [projectId, scanId, findingId]);

  if (finding.loading) return <Loading />;
  if (finding.error) return <ErrorNotice message={finding.error} />;
  if (!finding.data) return null;
  const item = finding.data;
  const factors = item.risk_breakdown ?? [];
  const rawTotal = factors.reduce((sum, factor) => sum + (factor.points ?? 0), 0);

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <Link
          href={`/projects/${projectId}/scans/${scanId}`}
          className="text-sm text-slate-400 hover:text-slate-200"
        >
          Back to scan
        </Link>
        <h1 className="mt-1 text-2xl font-semibold">
          {item.package_name}@{item.package_version}
        </h1>
        <p className="mt-1 text-sm text-slate-400">{item.summary}</p>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <span className="text-3xl font-semibold">{item.risk_score ?? "-"}</span>
          <RiskBadge level={item.risk_level} />
          {item.priority_rank && <span className="text-sm text-slate-500">Priority #{item.priority_rank}</span>}
        </div>
      </div>

      <Card title="Security evidence">
        <dl className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          <Fact label="Advisory">
            {item.osv_id}
            {item.aliases.length > 0 && <div className="text-xs text-slate-400">{item.aliases.join(", ")}</div>}
          </Fact>
          <Fact label="Severity">
            <span className="capitalize">{item.severity}</span>
            {item.cvss_score !== null && ` · CVSS ${item.cvss_score}`}
            {item.cvss_vector && <div className="break-all text-xs text-slate-500">{item.cvss_vector}</div>}
          </Fact>
          <Fact label="Known exploited (CISA KEV)">
            {item.known_exploited === null ? "Unknown" : item.known_exploited ? "Yes" : "No"}
          </Fact>
          <Fact label="Dependency">
            {item.is_direct ? "Direct" : "Transitive"} · {item.scope} · {item.ecosystem}
          </Fact>
          <Fact label="Inferred package role">{item.component_role?.replace("_", " ") ?? "None"}</Fact>
          <Fact label="Published">{formatDate(item.published)}</Fact>
          <Fact label="Fixed versions">{item.fixed_versions.join(", ") || "None listed"}</Fact>
          <Fact label="Source">
            <a
              href={item.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-emerald-400 hover:underline"
            >
              OSV.dev <ExternalLink className="h-3 w-3" />
            </a>
          </Fact>
        </dl>
      </Card>

      <Card title="How the risk score was calculated">
        <div className="space-y-3">
          {factors.map((factor) =>
            factor.points !== undefined && factor.max_points ? (
              <div key={factor.factor}>
                <div className="flex justify-between text-sm">
                  <span className="capitalize">{factor.factor.replace("_", " ")}</span>
                  <span className="text-slate-300">
                    {factor.points} / {factor.max_points}
                  </span>
                </div>
                <div className="mt-1 h-1.5 rounded-full bg-slate-800">
                  <div
                    className="h-1.5 rounded-full bg-emerald-500"
                    style={{ width: `${Math.min(100, (factor.points / factor.max_points) * 100)}%` }}
                  />
                </div>
                <div className="mt-1 text-xs text-slate-500">{factor.detail}</div>
              </div>
            ) : (
              <div key={factor.factor} className="flex justify-between border-t border-slate-800 pt-3 text-sm">
                <span>
                  Scope multiplier
                  <div className="text-xs text-slate-500">{factor.detail}</div>
                </span>
                <span className="text-slate-300">x{factor.multiplier}</span>
              </div>
            ),
          )}
          <div className="flex justify-between border-t border-slate-800 pt-3 text-sm font-medium">
            <span>Raw total {rawTotal.toFixed(1)}, final score</span>
            <span>{item.risk_score}</span>
          </div>
        </div>
      </Card>

      <Card title="Attack path">
        {item.attack_path ? (
          <AttackPath path={item.attack_path} />
        ) : (
          <p className="text-sm text-slate-400">No dependency chain from the application was found.</p>
        )}
      </Card>

      <Card title="Recommended remediation">
        <p className="text-sm text-slate-200">{item.remediation_hint}</p>
        <p className="mt-2 text-xs text-slate-500">Derived from the fixed versions listed by OSV.</p>
      </Card>

      <Card title="AI analysis">
        {item.ai_analysis ? (
          <div className="space-y-4">
            {AI_SECTIONS.map((section) => (
              <div key={section.key}>
                <h3 className="text-xs uppercase text-slate-500">{section.label}</h3>
                <p className="mt-1 whitespace-pre-wrap text-sm text-slate-300">{item.ai_analysis?.[section.key]}</p>
              </div>
            ))}
            <p className="text-xs text-slate-500">
              AI-generated by {item.ai_analysis.model}. It explains the calculated score but does not change
              it. Verify against the advisory before acting.
            </p>
          </div>
        ) : (
          <Notice>
            No AI analysis for this finding. Gemini analyzes the highest-ranked findings of each scan, and
            may be unavailable. The evidence and score above are unaffected.
          </Notice>
        )}
      </Card>
    </div>
  );
}