"use client";

import { useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { FolderGit2, LogOut, ShieldCheck } from "lucide-react";
import { clearToken, getToken } from "@/lib/auth";

const PUBLIC_PATHS = ["/login", "/register"];

export default function AuthShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const isPublic = PUBLIC_PATHS.includes(pathname);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const token = getToken();
    if (!token && !isPublic) {
      router.replace("/login");
      return;
    }
    if (token && isPublic) {
      router.replace("/");
      return;
    }
    setReady(true);
  }, [pathname, isPublic, router]);

  function signOut() {
    clearToken();
    router.replace("/login");
  }

  if (!ready) return null;

  if (isPublic) {
    return <main className="mx-auto flex min-h-screen max-w-md items-center px-6">{children}</main>;
  }

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-slate-800 bg-slate-900/50 p-5 md:flex">
        <div className="flex items-center gap-2 text-lg font-semibold">
          <ShieldCheck className="h-6 w-6 text-emerald-400" />
          SupplyGuard
        </div>
        <nav className="mt-8 flex-1">
          <Link
            href="/"
            className="flex items-center gap-2 rounded-md bg-slate-800 px-3 py-2 text-sm"
          >
            <FolderGit2 className="h-4 w-4" />
            Projects
          </Link>
        </nav>
        <button
          onClick={signOut}
          className="flex items-center gap-2 rounded-md px-3 py-2 text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-100"
        >
          <LogOut className="h-4 w-4" />
          Sign out
        </button>
      </aside>
      <main className="min-w-0 flex-1 p-6 md:p-8">{children}</main>
    </div>
  );
}