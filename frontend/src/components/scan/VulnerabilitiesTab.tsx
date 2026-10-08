import { useState } from "react";
import Link from "next/link";
import type { Finding, RiskLevel } from "@/lib/api";
import { RISK_LEVELS, RiskBadge } from "@/components/ui";

function exploited(value: boolean | null) {
  if (value === true) return <span className="text-red-400">Yes</span>;
  if (value === false) return <span className="text-slate-400">No</span>;
  return <span className="text-slate-500">Unknown</span>;
}

export default function VulnerabilitiesTab({
  projectId,
  scanId,
  findings,
}: {
  projectId: string;
  scanId: string;
  findings: Finding[];
}) {
  const [level, setLevel] = useState<RiskLevel | "all">("all");
  const [query, setQuery] = useState("");

  const rows = findings.filter(
    (finding) =>
      (level === "all" || finding.risk_level === level) &&
      `${finding.package_name} ${finding.osv_id} ${finding.aliases.join(" ")}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        {(["all", ...RISK_LEVELS] as const).map((option) => (
          <button
            key={option}
            onClick={() => setLevel(option)}
            className={`rounded-md border px-3 py-1.5 text-sm capitalize ${
              level === option
                ? "border-emerald-500 bg-emerald-500/10 text-emerald-300"
                : "border-slate-700 text-slate-300 hover:bg-slate-800"
            }`}
          >
            {option}
          </button>
        ))}
        <input
          placeholder="Search package or advisory"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          className="w-64 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-emerald-500"
        />
        <span className="text-sm text-slate-500">{rows.length} shown</span>
      </div>
      <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-800 text-xs uppercase text-slate-500">
            <tr>
              <th className="px-4 py-3">#</th>
              <th className="px-4 py-3">Advisory</th>
              <th className="px-4 py-3">Package</th>
              <th className="px-4 py-3">CVSS</th>
              <th className="px-4 py-3">Exploited</th>
              <th className="px-4 py-3">Risk</th>
              <th className="px-4 py-3">Fix</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {rows.map((finding) => (
              <tr key={finding.id}>
                <td className="px-4 py-2 text-slate-500">{finding.priority_rank ?? "-"}</td>
                <td className="px-4 py-2">
                  <Link
                    href={`/projects/${projectId}/scans/${scanId}/findings/${finding.id}`}
                    className="font-medium text-emerald-400 hover:underline"
                  >
                    {finding.aliases.find((alias) => alias.startsWith("CVE-")) ?? finding.osv_id}
                  </Link>
                  <div className="max-w-xs truncate text-xs text-slate-500">{finding.summary}</div>
                </td>
                <td className="px-4 py-2">
                  {finding.package_name}
                  <div className="text-xs text-slate-500">
                    {finding.package_version} · {finding.is_direct ? "direct" : "transitive"} · {finding.scope}
                  </div>
                </td>
                <td className="px-4 py-2">{finding.cvss_score ?? "-"}</td>
                <td className="px-4 py-2">{exploited(finding.known_exploited)}</td>
                <td className="px-4 py-2">
                  <div className="flex items-center gap-2">
                    {finding.risk_score ?? "-"}
                    <RiskBadge level={finding.risk_level} />
                  </div>
                </td>
                <td className="px-4 py-2 text-xs text-slate-400">
                  {finding.fixed_versions.slice(0, 2).join(", ") || "-"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {findings.length >= 1000 && <p className="text-xs text-slate-500">Showing the first 1000 findings.</p>}
    </div>
  );
}