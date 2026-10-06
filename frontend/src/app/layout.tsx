import type { Metadata } from "next";
import type { ReactNode } from "react";
import { LayoutDashboard, ShieldCheck } from "lucide-react";
import "./globals.css";

export const metadata: Metadata = {
  title: "SupplyGuard",
  description: "Software supply-chain security and risk analysis",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-slate-950 text-slate-100 antialiased">
        <div className="flex min-h-screen">
          <aside className="hidden w-60 shrink-0 border-r border-slate-800 bg-slate-900/50 p-5 md:block">
            <div className="flex items-center gap-2 text-lg font-semibold">
              <ShieldCheck className="h-6 w-6 text-emerald-400" />
              SupplyGuard
            </div>
            <nav className="mt-8">
              <a
                href="/"
                className="flex items-center gap-2 rounded-md bg-slate-800 px-3 py-2 text-sm"
              >
                <LayoutDashboard className="h-4 w-4" />
                Overview
              </a>
            </nav>
          </aside>
          <main className="flex-1 p-8">{children}</main>
        </div>
      </body>
    </html>
  );
}