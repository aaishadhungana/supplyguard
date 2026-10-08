"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { login, register } from "@/lib/api";
import { setToken } from "@/lib/auth";
import { Notice } from "@/components/ui";

export default function AuthForm({ mode }: { mode: "login" | "register" }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const isRegister = mode === "register";

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (isRegister) await register(email, password);
      const { access_token } = await login(email, password);
      setToken(access_token);
      router.replace("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
      setBusy(false);
    }
  }

  return (
    <div className="w-full">
      <div className="mb-6 flex items-center gap-2 text-xl font-semibold">
        <ShieldCheck className="h-7 w-7 text-emerald-400" />
        SupplyGuard
      </div>
      <form onSubmit={onSubmit} className="space-y-4 rounded-lg border border-slate-800 bg-slate-900 p-6">
        <h1 className="text-lg font-medium">{isRegister ? "Create an account" : "Sign in"}</h1>
        {error && <Notice tone="error">{error}</Notice>}
        <label className="block text-sm">
          <span className="text-slate-400">Email</span>
          <input
            type="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 outline-none focus:border-emerald-500"
          />
        </label>
        <label className="block text-sm">
          <span className="text-slate-400">Password</span>
          <input
            type="password"
            required
            minLength={isRegister ? 12 : 1}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 outline-none focus:border-emerald-500"
          />
          {isRegister && <span className="mt-1 block text-xs text-slate-500">At least 12 characters</span>}
        </label>
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium hover:bg-emerald-500 disabled:opacity-50"
        >
          {busy ? "Please wait" : isRegister ? "Create account" : "Sign in"}
        </button>
        <p className="text-center text-sm text-slate-400">
          {isRegister ? (
            <>
              Already have an account?{" "}
              <Link href="/login" className="text-emerald-400 hover:underline">
                Sign in
              </Link>
            </>
          ) : (
            <>
              New here?{" "}
              <Link href="/register" className="text-emerald-400 hover:underline">
                Create an account
              </Link>
            </>
          )}
        </p>
      </form>
    </div>
  );
}