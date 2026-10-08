"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowRight } from "lucide-react";
import { compareScans, getHistory, type Comparison, type FindingRef } from "@/lib/api";
import { useLoad } from "@/lib/hooks";
import { Card, ErrorNotice, Loading, Notice, RISK_LEVELS, RiskBadge, TEXT } from "@/components/ui";

function Delta({ before, after }: { before: number; after: number }) {
  const diff = Math.round((after - before) * 10) / 10;
  if (diff === 0) return <span className="text-slate-500">no change</span>;
  const good = diff < 0;
  return (
    <span className={good ? "text-emerald-400" : "text-red-400"}>
      {diff > 0 ? "+" : ""}
      {diff}
    </span>
  );
}

function FindingList({ title, items, total }: { title: string; items: FindingRef[]; total: number }) {
  return (
    <Card title={`${title} (${total})`}>
      {items.length === 0 && <p className="text-sm text-slate-400">None.</p>}
      <ul className="divide-y divide-slate-800">
        {items.map((item) => (
          <li key={item.vulnerability_id} className="flex items-center justify-between gap-3 py-2 text-sm">
            <div className="min-w-0">
              <span className="font-medium">
                {item.package_name}@{item.package_version}
              </span>
              <div className="truncate text-xs text-slate-500">{item.osv_id}</div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {item.risk_score}
              <RiskBadge level={item.risk_level} />
            </div>
          </li>
        ))}
      </ul>
      {total > items.length && <p className="mt-2 text-xs text-slate-500">Showing the first {items.length}.</p>}
    </Card>
  );
}

export default function ComparePage() {
  const { projectId } = useParams<{ projectId: string }>();
  const history = useLoad(() => getHistory(projectId), [projectId]);
  const completed = (history.data ?? []).filter((item) => item.status === "completed");
  const [base, setBase] = useState("");
  const [target, setTarget] = useState("");

  useEffect(() => {
    if (completed.length >= 2 && !base && !target) {
      setTarget(completed[0].scan_id);
      setBase(completed[1].scan_id);
    }
  }, [completed.length]);

  const comparison = useLoad<Comparison | null>(
    () => (base && target && base !== target ? compareScans(projectId, base, target) : Promise.resolve(null)),
    [projectId, base, target],
  );

  const options = completed.map((item) => (
    <option key={item.scan_id} value={item.scan_id}>
      Scan #{item.number} ({item.source_filename}, risk {item.overall_risk_score ?? "n/a"})
    </option>
  ));
  const result = comparison.data;

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <Link href={`/projects/${projectId}`} className="text-sm text-slate-400 hover:text-slate-200">
          Back to project
        </Link>
        <h1 className="mt-1 text-2xl font-semibold">Compare scans</h1>
        <p className="mt-1 text-sm text-slate-400">
          Pick a scan from before remediation and one from after.
        </p>
      </div>

      {history.loading && <Loading />}
      {history.error && <ErrorNotice message={history.error} />}
      {history.data && completed.length < 2 && <Notice>You need at least two completed scans to compare.</Notice>}

      {completed.length >= 2 && (
        <div className="flex flex-wrap items-center gap-3">
          <select
            value={base}
            onChange={(event) => setBase(event.target.value)}
            className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
          >
            <option value="">Before</option>
            {options}
          </select>
          <ArrowRight className="h-4 w-4 text-slate-500" />
          <select
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
          >
            <option value="">After</option>
            {options}
          </select>
        </div>
      )}

      {base && base === target && <Notice tone="warn">Choose two different scans.</Notice>}
      {comparison.error && <ErrorNotice message={comparison.error} />}

      {result && (
        <>
          {result.context_changed && (
            <Notice tone="warn">
              These scans used different application context (exposure or criticality), so part of the score
              change comes from the context, not from the dependencies.
            </Notice>
          )}

          <div className="grid gap-4 sm:grid-cols-3">
            <Card title={`Before: scan #${result.base.number}`}>
              <div className="text-3xl font-semibold">{result.base.overall_risk_score ?? "n/a"}</div>
              <div className="mt-1 text-xs text-slate-500">overall risk</div>
            </Card>
            <Card title="Change">
              <div className="text-3xl font-semibold">
                {result.risk_score_change === null ? (
                  "n/a"
                ) : (
                  <Delta before={result.base.overall_risk_score ?? 0} after={result.target.overall_risk_score ?? 0} />
                )}
              </div>
              <div className="mt-1 text-xs text-slate-500">
                {result.resolved_count} resolved, {result.introduced_count} new, {result.persisting_count} remaining
              </div>
            </Card>
            <Card title={`After: scan #${result.target.number}`}>
              <div className="text-3xl font-semibold">{result.target.overall_risk_score ?? "n/a"}</div>
              <div className="mt-1 text-xs text-slate-500">overall risk</div>
            </Card>
          </div>

          <Card title="Findings by risk level">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase text-slate-500">
                <tr>
                  <th className="pb-2">Level</th>
                  <th className="pb-2">Before</th>
                  <th className="pb-2">After</th>
                  <th className="pb-2">Change</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {RISK_LEVELS.map((level) => {
                  const before = result.base.vulnerabilities_by_risk_level[level] ?? 0;
                  const after = result.target.vulnerabilities_by_risk_level[level] ?? 0;
                  return (
                    <tr key={level}>
                      <td className={`py-2 capitalize ${TEXT[level]}`}>{level}</td>
                      <td className="py-2">{before}</td>
                      <td className="py-2">{after}</td>
                      <td className="py-2">
                        <Delta before={before} after={after} />
                      </td>
                    </tr>
                  );
                })}
                <tr>
                  <td className="py-2 text-slate-300">Vulnerable dependencies</td>
                  <td className="py-2">{result.base.vulnerable_dependencies}</td>
                  <td className="py-2">{result.target.vulnerable_dependencies}</td>
                  <td className="py-2">
                    <Delta
                      before={result.base.vulnerable_dependencies}
                      after={result.target.vulnerable_dependencies}
                    />
                  </td>
                </tr>
              </tbody>
            </table>
          </Card>

          <div className="grid gap-6 lg:grid-cols-2">
            <FindingList title="Resolved" items={result.resolved} total={result.resolved_count} />
            <FindingList title="New" items={result.introduced} total={result.introduced_count} />
          </div>

          <Card title={`Package changes (${result.changed_packages.length})`}>
            {result.changed_packages.length === 0 && (
              <p className="text-sm text-slate-400">No package versions changed.</p>
            )}
            <ul className="divide-y divide-slate-800 text-sm">
              {result.changed_packages.map((change) => (
                <li key={`${change.ecosystem}-${change.name}`} className="flex justify-between gap-3 py-2">
                  <span className="font-medium">{change.name}</span>
                  <span className="text-slate-400">
                    {change.from_versions.join(", ")} <ArrowRight className="inline h-3 w-3" />{" "}
                    {change.to_versions.join(", ")}
                  </span>
                </li>
              ))}
            </ul>
          </Card>
        </>
      )}
    </div>
  );
}