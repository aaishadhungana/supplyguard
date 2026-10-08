import { ChevronRight } from "lucide-react";
import type { AttackPathData, AttackPathNode } from "@/lib/api";

function nodeStyle(node: AttackPathNode): string {
  if (node.vulnerable) return "border-red-500/50 bg-red-500/10";
  if (node.type === "application") return "border-emerald-500/40 bg-emerald-500/10";
  return "border-slate-700 bg-slate-800";
}

function subtitle(node: AttackPathNode, exposure: string): string {
  if (node.type === "application") return exposure;
  const parts: string[] = [node.type];
  if (node.role) parts.push(`${node.role.replace("_", " ")} (inferred)`);
  if (node.vulnerable) parts.push("vulnerable");
  return parts.join(" · ");
}

export default function AttackPath({ path }: { path: AttackPathData }) {
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        {path.nodes.map((node, index) => (
          <div key={index} className="flex items-center gap-2">
            {index > 0 && <ChevronRight className="h-4 w-4 text-slate-600" />}
            <div className={`rounded-md border px-3 py-2 text-xs ${nodeStyle(node)}`}>
              <div className="font-medium">{node.label}</div>
              <div className="mt-0.5 text-[11px] text-slate-400">{subtitle(node, path.exposure)}</div>
            </div>
          </div>
        ))}
      </div>
      <p className="mt-3 text-xs text-slate-500">{path.basis}</p>
    </div>
  );
}