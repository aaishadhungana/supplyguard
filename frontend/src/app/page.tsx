"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { Globe, Plus } from "lucide-react";
import { createProject, listProjects } from "@/lib/api";
import { useLoad } from "@/lib/hooks";
import { Card, ErrorNotice, Loading, formatDate } from "@/components/ui";

export default function ProjectsPage() {
  const projects = useLoad(listProjects, []);
  const [name, setName] = useState("");
  const [internetFacing, setInternetFacing] = useState(false);
  const [criticality, setCriticality] = useState("medium");
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setFormError(null);
    try {
      await createProject({ name, internet_facing: internetFacing, criticality });
      setName("");
      await projects.reload();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Could not create project");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Projects</h1>
        <p className="mt-1 text-sm text-slate-400">Each project holds a history of scans.</p>
      </div>

      <Card title="New project">
        <form onSubmit={onSubmit} className="flex flex-wrap items-end gap-4">
          <label className="text-sm">
            <span className="text-slate-400">Name</span>
            <input
              required
              maxLength={120}
              value={name}
              onChange={(event) => setName(event.target.value)}
              className="mt-1 block w-64 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 outline-none focus:border-emerald-500"
            />
          </label>
          <label className="text-sm">
            <span className="text-slate-400">Criticality</span>
            <select
              value={criticality}
              onChange={(event) => setCriticality(event.target.value)}
              className="mt-1 block rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </label>
          <label className="flex items-center gap-2 pb-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={internetFacing}
              onChange={(event) => setInternetFacing(event.target.checked)}
            />
            Internet-facing
          </label>
          <button
            type="submit"
            disabled={saving}
            className="flex items-center gap-2 rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium hover:bg-emerald-500 disabled:opacity-50"
          >
            <Plus className="h-4 w-4" />
            Create
          </button>
        </form>
        {formError && (
          <div className="mt-4">
            <ErrorNotice message={formError} />
          </div>
        )}
      </Card>

      {projects.loading && <Loading />}
      {projects.error && <ErrorNotice message={projects.error} />}
      {projects.data && projects.data.length === 0 && (
        <p className="text-sm text-slate-400">No projects yet. Create one above to get started.</p>
      )}
      <div className="grid gap-4 sm:grid-cols-2">
        {projects.data?.map((project) => (
          <Link
            key={project.id}
            href={`/projects/${project.id}`}
            className="rounded-lg border border-slate-800 bg-slate-900 p-5 hover:border-emerald-500/50"
          >
            <div className="font-medium">{project.name}</div>
            <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-slate-400">
              <span className="capitalize">Criticality: {project.criticality}</span>
              {project.internet_facing && (
                <span className="flex items-center gap-1">
                  <Globe className="h-3 w-3" />
                  Internet-facing
                </span>
              )}
              <span>Created {formatDate(project.created_at)}</span>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}