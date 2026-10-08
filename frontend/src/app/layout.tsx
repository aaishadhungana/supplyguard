import type { Metadata } from "next";
import type { ReactNode } from "react";
import AuthShell from "@/components/AuthShell";
import "./globals.css";

export const metadata: Metadata = {
  title: "SupplyGuard",
  description: "Software supply-chain security and risk analysis",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-slate-950 text-slate-100 antialiased">
        <AuthShell>{children}</AuthShell>
      </body>
    </html>
  );
}