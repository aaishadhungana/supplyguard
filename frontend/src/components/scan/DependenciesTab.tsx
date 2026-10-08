import { useState } from "react";
import { listDependencies } from "@/lib/api";
import { useLoad } from "@/lib/hooks";
import { ErrorNotice, Loading } from "@/components/ui";

export default function DependenciesTab({ projectId, scanId }: { projectId: string; scanId: string }) {
  const dependencies = useLoad(() => listDependencies(projectId, scanId), [projectId, scanId]);
  const [query, setQuery] = useState("");
  const [vulnerableOnly, setVulnerableOnly] = useState(false);

  if (dependencies.loading) return <Loading />;
  if (dependencies.error) return <ErrorNotice message={dependencies.error} />;

  const rows = (dependencies.data ?? []).filter(
    (item) =>
      item.name.toLowerCase().includes(query.toLowerCase()) &&
      (!vulnerableOnly || item.vulnerability_count > 0),
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-4">
        <input
          placeholder="Search packages"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          className="w-64 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-emerald-500"
        />
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={vulnerableOnly}
            onChange={(event) => setVulnerableOnly(event.target.checked)}
          />
          Vulnerable only
        </label>
        <span className="text-sm text-slate-500">{rows.length} shown</span>
      </div>
      <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-800 text-xs uppercase text-slate-500">
            <tr>
              <th className="px-4 py-3">Package</th>
              <th className="px-4 py-3">Version</th>
              <th className="px-4 py-3">Ecosystem</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Scope</th>
              <th className="px-4 py-3">Vulns</th>
              <th className="px-4 py-3">Top risk</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {rows.map((item) => (
              <tr key={item.id}>
                <td className="px-4 py-2 font-medium">{item.name}</td>
                <td className="px-4 py-2 text-slate-400">{item.version}</td>
                <td className="px-4 py-2 text-slate-400">{item.ecosystem}</td>
                <td className="px-4 py-2">{item.is_direct ? "direct" : "transitive"}</td>
                <td className="px-4 py-2 text-slate-400">{item.scope}</td>
                <td className="px-4 py-2">{item.vulnerability_count}</td>
                <td className="px-4 py-2">{item.risk_score ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {(dependencies.data?.length ?? 0) >= 1000 && (
        <p className="text-xs text-slate-500">Showing the first 1000 dependencies.</p>
      )}
    </div>
  );
}