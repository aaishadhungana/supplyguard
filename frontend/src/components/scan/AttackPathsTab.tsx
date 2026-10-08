import Link from "next/link";
import type { Finding } from "@/lib/api";
import AttackPath from "@/components/AttackPath";
import { Card, Notice, RiskBadge } from "@/components/ui";

export default function AttackPathsTab({
  projectId,
  scanId,
  findings,
}: {
  projectId: string;
  scanId: string;
  findings: Finding[];
}) {
  const withPaths = findings.filter((finding) => finding.attack_path).slice(0, 15);

  return (
    <div className="space-y-4">
      <Notice>
        Paths show how the application reaches each vulnerable package through the dependency graph. They
        are taken from the lockfile; whether the vulnerable code is actually reachable was not analyzed.
        Package roles are inferred from names.
      </Notice>
      {withPaths.length === 0 && <p className="text-sm text-slate-400">No attack paths to show.</p>}
      {withPaths.map((finding) => (
        <Card key={finding.id}>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
            <Link
              href={`/projects/${projectId}/scans/${scanId}/findings/${finding.id}`}
              className="text-sm font-medium hover:underline"
            >
              #{finding.priority_rank} {finding.package_name}@{finding.package_version}{" "}
              <span className="text-slate-500">{finding.osv_id}</span>
            </Link>
            <div className="flex items-center gap-2 text-sm">
              {finding.risk_score}
              <RiskBadge level={finding.risk_level} />
            </div>
          </div>
          {finding.attack_path && <AttackPath path={finding.attack_path} />}
        </Card>
      ))}
    </div>
  );
}