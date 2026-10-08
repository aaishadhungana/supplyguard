import type { ReactNode } from "react";
import { Loader2 } from "lucide-react";
import type { RiskLevel } from "@/lib/api";

export const RISK_LEVELS: RiskLevel[] = ["critical", "high", "medium", "low"];

const BADGE: Record<string, string> = {
  critical: "border-red-500/30 bg-red-500/15 text-red-300",
  high: "border-orange-500/30 bg-orange-500/15 text-orange-300",
  medium: "border-yellow-500/30 bg-yellow-500/15 text-yellow-300",
  low: "border-sky-500/30 bg-sky-500/15 text-sky-300",
};

export const BAR: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-sky-500",
};

export const TEXT: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-sky-400",
};

export function levelFromScore(score: number): RiskLevel {
  if (score >= 75) return "critical";
  if (score >= 55) return "high";
  if (score >= 35) return "medium";
  return "low";
}

export function formatDate(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : "-";
}

export function RiskBadge({ level }: { level: string | null }) {
  const style = level ? BADGE[level] : undefined;
  return (
    <span
      className={`inline-flex rounded border px-2 py-0.5 text-xs font-medium capitalize ${
        style ?? "border-slate-700 bg-slate-800 text-slate-400"
      }`}
    >
      {level ?? "n/a"}
    </span>
  );
}

export function Card({
  title,
  action,
  children,
  className = "",
}: {
  title?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-lg border border-slate-800 bg-slate-900 ${className}`}>
      {(title || action) && (
        <header className="flex items-center justify-between border-b border-slate-800 px-5 py-3">
          <h2 className="text-sm font-medium text-slate-200">{title}</h2>
          {action}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-5">
      <div className="text-sm text-slate-400">{label}</div>
      <div className="mt-2 text-2xl font-semibold">{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export function StatusPill({ status }: { status: string }) {
  const active = status === "pending" || status === "running";
  const style =
    status === "completed"
      ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-300"
      : status === "failed"
        ? "border-red-500/30 bg-red-500/15 text-red-300"
        : "border-slate-600 bg-slate-800 text-slate-300";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs capitalize ${style}`}>
      {active && <Loader2 className="h-3 w-3 animate-spin" />}
      {status}
    </span>
  );
}

export function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const total = RISK_LEVELS.reduce((sum, level) => sum + (counts[level] ?? 0), 0);
  return (
    <div>
      <div className="flex h-3 overflow-hidden rounded-full bg-slate-800">
        {total > 0 &&
          RISK_LEVELS.map((level) =>
            (counts[level] ?? 0) > 0 ? (
              <div
                key={level}
                className={BAR[level]}
                style={{ width: `${((counts[level] ?? 0) / total) * 100}%` }}
              />
            ) : null,
          )}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-sm">
        {RISK_LEVELS.map((level) => (
          <span key={level} className="flex items-center gap-2 text-slate-300">
            <span className={`h-2 w-2 rounded-full ${BAR[level]}`} />
            <span className="capitalize">{level}</span>
            <span className="font-medium text-slate-100">{counts[level] ?? 0}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

export function Notice({
  tone = "info",
  children,
}: {
  tone?: "info" | "warn" | "error";
  children: ReactNode;
}) {
  const style =
    tone === "error"
      ? "border-red-500/30 bg-red-500/10 text-red-200"
      : tone === "warn"
        ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-200"
        : "border-slate-700 bg-slate-800/60 text-slate-300";
  return <div className={`rounded-md border px-4 py-3 text-sm ${style}`}>{children}</div>;
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-slate-400">
      <Loader2 className="h-4 w-4 animate-spin" />
      {label}
    </div>
  );
}

export function ErrorNotice({ message }: { message: string }) {
  return <Notice tone="error">{message}</Notice>;
}