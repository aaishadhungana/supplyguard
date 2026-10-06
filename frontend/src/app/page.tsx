"use client";

import { useEffect, useState } from "react";
import { Database, Server, Tag } from "lucide-react";
import { fetchHealth, type Health } from "@/lib/api";

export default function OverviewPage() {
  const [health, setHealth] = useState<Health | null>(null);
  const [unreachable, setUnreachable] = useState(false);

  useEffect(() => {
    fetchHealth().then(setHealth).catch(() => setUnreachable(true));
  }, []);

  const cards = [
    {
      label: "API",
      value: unreachable ? "unreachable" : health ? health.status : "checking",
      icon: Server,
    },
    {
      label: "Database",
      value: unreachable ? "unknown" : health ? health.database : "checking",
      icon: Database,
    },
    {
      label: "Version",
      value: health ? health.version : "-",
      icon: Tag,
    },
  ];

  return (
    <div>
      <h1 className="text-2xl font-semibold">Overview</h1>
      <p className="mt-1 text-sm text-slate-400">Platform status</p>
      <div className="mt-6 grid gap-4 sm:grid-cols-3">
        {cards.map(({ label, value, icon: Icon }) => (
          <div key={label} className="rounded-lg border border-slate-800 bg-slate-900 p-5">
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <Icon className="h-4 w-4" />
              {label}
            </div>
            <div className="mt-2 text-xl font-medium">{value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}