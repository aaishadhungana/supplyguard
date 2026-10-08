"use client";

import { useEffect, useState, type ChangeEvent } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { GitCompare, Upload } from "lucide-react";
import { getHistory, getProject, startScan, updateContext } from "@/lib/api";
import { useLoad, usePoll } from "@/lib/hooks";
import {
  Card,
  ErrorNotice,
  Loading,
  Notice,
  RISK_LEVELS,
  StatusPill,
  TEXT,
  formatDate,
} from "@/components/ui";

export default function ProjectPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const router = useRouter();
  const project = useLoad(() => getProject(projectId), [projectId]);
  const history = useLoad(() => getHistory(projectId), [projectId]);

  const [internetFacing, setInternetFacing] = useState(false);
  const [criticality, setCriticality] = useState("medium");
  const [contextMessage, setContextMessage] = useState<string | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);

  useEffect(() => {
    if (project.data) {
      setInternetFacing(project.data.internet_facing);
      setCriticality(project.data.criticality);
    }
  }, [project.data]);

  const inFlight = (history.data ?? []).some(
    (item) => item.status === "pending" || item.status === "running",
  );
  usePoll(() => void history.reload(), inFlight);

  async function saveContext() {
    setContextMessage(null);
    try {
      await updateContext(projectId, { internet_facing: internetFacing, criticality });
      setContextMessage("Saved. New scans will use this context.");
    } catch (err) {
      setContextMessage(err instanceof Error ? err.message : "Could not save");
    }
  }

  async function onUpload() {
    if (!file) return;
    setUploading(true);
    setUploadError(null);
    try {
      const scan = await startScan(projectId, file);
      router.push(`/projects/${projectId}/scans/${scan.id}`);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : "Upload failed");
      setUploading(false);
    }
  }

  const completedCount = (history.data ?? []).filter((item) => item.status === "completed").length;

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <Link href="/" className="text-sm text-slate-400 hover:text-slate-200">
          Projects
        </Link>
        <h1 className="mt-1 text-2xl font-semibold">{project.data?.name ?? "Project"}</h1>
      </div>
      {project.error && <ErrorNotice message={project.error} />}

      <div className="grid gap-6 md:grid-cols-2">
        <Card title="New scan">
          <p className="text-sm text-slate-400">
            Upload a <code>package-lock.json</code> (lockfile v2 or v3) or a pinned{" "}
            <code>requirements.txt</code>.
          </p>
          <input
            type="file"
            accept=".json,.txt"
            onChange={(event: ChangeEvent<HTMLInputElement>) => setFile(event.target.files?.[0] ?? null)}
            className="mt-4 block w-full text-sm text-slate-300 file:mr-3 file:rounded-md file:border-0 file:bg-slate-700 file:px-3 file:py-2 file:text-slate-100"
          />
          <button
            onClick={onUpload}
            disabled={!file || uploading}
            className="mt-4 flex items-center gap-2 rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium hover:bg-emerald-500 disabled:opacity-50"
          >
            <Upload className="h-4 w-4" />
            {uploading ? "Uploading" : "Start scan"}
          </button>
          {uploadError && (
            <div className="mt-4">
              <ErrorNotice message={uploadError} />
            </div>
          )}
        </Card>

        <Card title="Application context">
          <p className="text-sm text-slate-400">
            Risk scores weigh exposure and criticality. Each scan keeps the context it ran with.
          </p>
          <div className="mt-4 flex flex-wrap items-center gap-4">
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                checked={internetFacing}
                onChange={(event) => setInternetFacing(event.target.checked)}
              />
              Internet-facing
            </label>
            <select
              value={criticality}
              onChange={(event) => setCriticality(event.target.value)}
              className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
            >
              <option value="low">Low criticality</option>
              <option value="medium">Medium criticality</option>
              <option value="high">High criticality</option>
              <option value="critical">Critical</option>
            </select>
            <button
              onClick={saveContext}
              className="rounded-md bg-slate-700 px-4 py-2 text-sm hover:bg-slate-600"
            >
              Save
            </button>
          </div>
          {contextMessage && <p className="mt-3 text-sm text-slate-400">{contextMessage}</p>}
        </Card>
      </div>

      <Card
        title="Scan history"
        action={
          completedCount >= 2 ? (
            <Link
              href={`/projects/${projectId}/compare`}
              className="flex items-center gap-2 text-sm text-emerald-400 hover:underline"
            >
              <GitCompare className="h-4 w-4" />
              Compare scans
            </Link>
          ) : undefined
        }
      >
        {history.loading && <Loading />}
        {history.error && <ErrorNotice message={history.error} />}
        {history.data && history.data.length === 0 && <Notice>No scans yet. Upload a file to start.</Notice>}
        {history.data && history.data.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr>
                  <th className="pb-2 pr-4">Scan</th>
                  <th className="pb-2 pr-4">File</th>
                  <th className="pb-2 pr-4">Status</th>
                  <th className="pb-2 pr-4">Risk</th>
                  <th className="pb-2 pr-4">Findings</th>
                  <th className="pb-2 pr-4">Started</th>
                  <th className="pb-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {history.data.map((item) => (
                  <tr key={item.scan_id}>
                    <td className="py-2 pr-4 font-medium">#{item.number}</td>
                    <td className="py-2 pr-4 text-slate-400">{item.source_filename ?? "-"}</td>
                    <td className="py-2 pr-4">
                      <StatusPill status={item.status} />
                    </td>
                    <td className="py-2 pr-4">{item.overall_risk_score ?? "-"}</td>
                    <td className="py-2 pr-4">
                      <span className="flex gap-3 text-xs">
                        {RISK_LEVELS.map((level) => (
                          <span key={level} className={TEXT[level]}>
                            {item.vulnerabilities_by_risk_level[level] ?? 0}
                          </span>
                        ))}
                      </span>
                    </td>
                    <td className="py-2 pr-4 text-slate-400">{formatDate(item.created_at)}</td>
                    <td className="py-2 text-right">
                      <Link
                        href={`/projects/${projectId}/scans/${item.scan_id}`}
                        className="text-emerald-400 hover:underline"
                      >
                        Open
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="mt-3 text-xs text-slate-500">
              Findings columns: <span className={TEXT.critical}>critical</span>,{" "}
              <span className={TEXT.high}>high</span>, <span className={TEXT.medium}>medium</span>,{" "}
              <span className={TEXT.low}>low</span>.
            </p>
          </div>
        )}
      </Card>
    </div>
  );
}