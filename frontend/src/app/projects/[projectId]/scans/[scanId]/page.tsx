"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Download, GitCompare } from "lucide-react";
import { downloadReport, getScan, getSummary, listFindings, rerunAi, type Finding } from "@/lib/api";
import { useLoad, usePoll } from "@/lib/hooks";
import { ErrorNotice, Loading, Notice, StatusPill, formatDate } from "@/components/ui";
import AttackPathsTab from "@/components/scan/AttackPathsTab";
import DependenciesTab from "@/components/scan/DependenciesTab";
import OverviewTab from "@/components/scan/OverviewTab";
import VulnerabilitiesTab from "@/components/scan/VulnerabilitiesTab";

type Tab = "overview" | "dependencies" | "vulnerabilities" | "paths";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "dependencies", label: "Dependencies" },
  { id: "vulnerabilities", label: "Vulnerabilities" },
  { id: "paths", label: "Attack paths" },
];

export default function ScanPage() {
  const { projectId, scanId } = useParams<{ projectId: string; scanId: string }>();
  const [tab, setTab] = useState<Tab>("overview");
  const [rerunning, setRerunning] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const scan = useLoad(() => getScan(projectId, scanId), [projectId, scanId]);
  const summary = useLoad(() => getSummary(projectId, scanId), [projectId, scanId]);

  const status = scan.data?.status;
  const inFlight = !status || status === "pending" || status === "running";
  const done = status === "completed";

  usePoll(
    () => {
      void scan.reload();
      void summary.reload();
    },
    inFlight,
  );

  const findings = useLoad<Finding[]>(
    () => (done ? listFindings(projectId, scanId) : Promise.resolve([])),
    [projectId, scanId, done],
  );

  useEffect(() => {
    if (done) void summary.reload();
  }, [done]);

  async function onRerunAi() {
    setRerunning(true);
    try {
      await rerunAi(projectId, scanId);
      await Promise.all([summary.reload(), findings.reload(), scan.reload()]);
    } finally {
      setRerunning(false);
    }
  }

  async function onDownload() {
    if (!scan.data) return;
    setDownloadError(null);
    try {
      const blob = await downloadReport(projectId, scanId);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `supplyguard-report-scan-${scan.data.number}.md`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setDownloadError(err instanceof Error ? err.message : "Download failed");
    }
  }

  if (scan.loading && !scan.data) return <Loading />;
  if (scan.error && !scan.data) return <ErrorNotice message={scan.error} />;
  if (!scan.data) return null;

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <Link href={`/projects/${projectId}`} className="text-sm text-slate-400 hover:text-slate-200">
            Back to project
          </Link>
          <h1 className="mt-1 flex items-center gap-3 text-2xl font-semibold">
            Scan #{scan.data.number}
            <StatusPill status={scan.data.status} />
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            {scan.data.source_filename} · {formatDate(scan.data.created_at)}
          </p>
        </div>
        {done && (
          <div className="flex gap-3">
            <Link
              href={`/projects/${projectId}/compare`}
              className="flex items-center gap-2 rounded-md border border-slate-700 px-3 py-2 text-sm hover:bg-slate-800"
            >
              <GitCompare className="h-4 w-4" />
              Compare
            </Link>
            <button
              onClick={onDownload}
              className="flex items-center gap-2 rounded-md bg-emerald-600 px-3 py-2 text-sm font-medium hover:bg-emerald-500"
            >
              <Download className="h-4 w-4" />
              Report
            </button>
          </div>
        )}
      </div>

      {downloadError && <ErrorNotice message={downloadError} />}
      {inFlight && <Notice>Scan in progress. This page updates automatically.</Notice>}
      {scan.data.status === "failed" && (
        <Notice tone="error">Scan failed: {scan.data.error_message ?? "unknown error"}</Notice>
      )}

      {done && summary.data && (
        <>
          <div className="flex gap-1 border-b border-slate-800">
            {TABS.map((item) => (
              <button
                key={item.id}
                onClick={() => setTab(item.id)}
                className={`border-b-2 px-4 py-2 text-sm ${
                  tab === item.id
                    ? "border-emerald-500 text-slate-100"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>
          {findings.error && <ErrorNotice message={findings.error} />}
          {tab === "overview" && (
            <OverviewTab
              projectId={projectId}
              scan={scan.data}
              summary={summary.data}
              findings={findings.data ?? []}
              onRerunAi={onRerunAi}
              rerunning={rerunning}
            />
          )}
          {tab === "dependencies" && <DependenciesTab projectId={projectId} scanId={scanId} />}
          {tab === "vulnerabilities" && (
            <VulnerabilitiesTab projectId={projectId} scanId={scanId} findings={findings.data ?? []} />
          )}
          {tab === "paths" && (
            <AttackPathsTab projectId={projectId} scanId={scanId} findings={findings.data ?? []} />
          )}
        </>
      )}
    </div>
  );
}