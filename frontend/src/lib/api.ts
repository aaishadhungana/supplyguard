const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type Health = {
  status: string;
  database: string;
  version: string;
  environment: string;
};

export async function fetchHealth(): Promise<Health> {
  const response = await fetch(`${API_URL}/api/health`, { cache: "no-store" });
  return response.json();
}