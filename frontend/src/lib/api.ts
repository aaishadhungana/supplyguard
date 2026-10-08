import { clearToken, getToken } from "./auth";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type RiskLevel = "critical" | "high" | "medium" | "low";
export type ScanStatus = "pending" | "running" | "completed" | "failed";

export type Project = {
  id: string;
  name: string;
  description: string | null;
  internet_facing: boolean;
  criticality: string;
  created_at: string;
};

export type Scan = {
  id: string;
  project_id: string;
  number: number;
  status: ScanStatus;
  source_filename: string | null;
  warnings: string[];
  risk_score: number | null;
  ai_status: string | null;
  ai_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
};

export type AiSummary = {
  model: string;
  generated_at: string;
  executive_summary: string;
  top_priorities: string[];
};

export type ScanContext = { internet_facing: boolean; criticality: string };

export type Summary = {
  scan_id: string;
  status: string;
  overall_risk_score: number | null;
  total_dependencies: number;
  vulnerable_dependencies: number;
  total_vulnerabilities: number;
  vulnerabilities_by_risk_level: Record<string, number>;
  context: ScanContext | null;
  ai_status: string | null;
  ai_message: string | null;
  ai_summary: AiSummary | null;
};

export type Dependency = {
  id: string;
  ecosystem: string;
  name: string;
  version: string;
  purl: string;
  is_direct: boolean;
  scope: string;
  vulnerability_count: number;
  risk_score: number | null;
};

export type AttackPathNode = {
  label: string;
  type: "application" | "direct" | "transitive";
  role: string | null;
  vulnerable: boolean;
};

export type AttackPathData = {
  established: boolean;
  exposure: string;
  length: number;
  through_entry_point: boolean;
  nodes: AttackPathNode[];
  basis: string;
};

export type RiskFactor = {
  factor: string;
  points?: number;
  max_points?: number;
  multiplier?: number;
  detail: string;
};

export type AiAnalysis = {
  model: string;
  generated_at: string;
  why_it_matters: string;
  potential_impact: string;
  priority_reasoning: string;
  attack_path_explanation: string;
  remediation: string;
};

export type Finding = {
  id: string;
  osv_id: string;
  aliases: string[];
  summary: string;
  severity: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  known_exploited: boolean | null;
  fixed_versions: string[];
  published: string | null;
  url: string;
  dependency_id: string;
  package_name: string;
  package_version: string;
  ecosystem: string;
  is_direct: boolean;
  scope: string;
  risk_score: number | null;
  risk_level: string | null;
  priority_rank: number | null;
  component_role: string | null;
  risk_breakdown: RiskFactor[] | null;
  attack_path: AttackPathData | null;
  ai_analysis: AiAnalysis | null;
  remediation_hint: string;
};

export type HistoryItem = {
  scan_id: string;
  number: number;
  status: ScanStatus;
  source_filename: string | null;
  created_at: string;
  completed_at: string | null;
  overall_risk_score: number | null;
  total_vulnerabilities: number;
  vulnerabilities_by_risk_level: Record<string, number>;
  context: ScanContext | null;
  ai_status: string | null;
};

export type ComparisonSide = {
  scan_id: string;
  number: number;
  created_at: string;
  overall_risk_score: number | null;
  total_dependencies: number;
  vulnerable_dependencies: number;
  total_vulnerabilities: number;
  vulnerabilities_by_risk_level: Record<string, number>;
  context: ScanContext | null;
};

export type FindingRef = {
  vulnerability_id: string;
  osv_id: string;
  package_name: string;
  package_version: string;
  ecosystem: string;
  scope: string;
  risk_score: number | null;
  risk_level: string | null;
};

export type PackageChange = {
  name: string;
  ecosystem: string;
  from_versions: string[];
  to_versions: string[];
};

export type Comparison = {
  base: ComparisonSide;
  target: ComparisonSide;
  risk_score_change: number | null;
  context_changed: boolean;
  resolved_count: number;
  introduced_count: number;
  persisting_count: number;
  resolved: FindingRef[];
  introduced: FindingRef[];
  changed_packages: PackageChange[];
};

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function describe(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0] as { msg?: string };
    return first.msg ?? "Invalid request";
  }
  return "Request failed";
}

async function send(path: string, options: RequestInit = {}): Promise<Response> {
  const headers = new Headers(options.headers);
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (options.body && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  let response: Response;
  try {
    response = await fetch(`${API_URL}/api${path}`, { ...options, headers, cache: "no-store" });
  } catch {
    throw new ApiError(0, "Cannot reach the SupplyGuard API");
  }

  if (response.status === 401 && token) {
    clearToken();
    window.location.href = "/login";
  }
  if (!response.ok) {
    let detail: unknown = null;
    try {
      detail = (await response.json()).detail;
    } catch {
      detail = null;
    }
    throw new ApiError(response.status, describe(detail));
  }
  return response;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await send(path, options);
  return (await response.json()) as T;
}

export const register = (email: string, password: string) =>
  request<{ id: string; email: string }>("/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });

export const login = (email: string, password: string) =>
  request<{ access_token: string }>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });

export const listProjects = () => request<Project[]>("/projects");

export const createProject = (body: { name: string; internet_facing: boolean; criticality: string }) =>
  request<Project>("/projects", { method: "POST", body: JSON.stringify(body) });

export const getProject = (projectId: string) => request<Project>(`/projects/${projectId}`);

export const updateContext = (projectId: string, body: { internet_facing: boolean; criticality: string }) =>
  request<Project>(`/projects/${projectId}/context`, { method: "PATCH", body: JSON.stringify(body) });

export const getHistory = (projectId: string) => request<HistoryItem[]>(`/projects/${projectId}/history`);

export function startScan(projectId: string, file: File) {
  const form = new FormData();
  form.append("file", file);
  return request<Scan>(`/projects/${projectId}/scans`, { method: "POST", body: form });
}

export const getScan = (projectId: string, scanId: string) =>
  request<Scan>(`/projects/${projectId}/scans/${scanId}`);

export const getSummary = (projectId: string, scanId: string) =>
  request<Summary>(`/projects/${projectId}/scans/${scanId}/summary`);

export const rerunAi = (projectId: string, scanId: string) =>
  request<Summary>(`/projects/${projectId}/scans/${scanId}/ai-analysis`, { method: "POST" });

export const listDependencies = (projectId: string, scanId: string) =>
  request<Dependency[]>(`/projects/${projectId}/scans/${scanId}/dependencies?limit=1000`);

export const listFindings = (projectId: string, scanId: string) =>
  request<Finding[]>(`/projects/${projectId}/scans/${scanId}/vulnerabilities?limit=1000`);

export const getFinding = (projectId: string, scanId: string, findingId: string) =>
  request<Finding>(`/projects/${projectId}/scans/${scanId}/findings/${findingId}`);

export const compareScans = (projectId: string, base: string, target: string) =>
  request<Comparison>(`/projects/${projectId}/compare?base=${base}&target=${target}`);

export async function downloadReport(projectId: string, scanId: string): Promise<Blob> {
  const response = await send(`/projects/${projectId}/scans/${scanId}/report`);
  return response.blob();
}