import type {
  AttackMatrix,
  AttackTechniqueDetail,
  BehaviourReport,
  ClassificationResult,
  RelationsReport,
  Report,
  ServiceStatus,
} from "./types";

/** An error carrying the status and message the API returned. */
export class ApiError extends Error {
  readonly status: number;
  readonly provider: string | null;

  constructor(message: string, status: number, provider: string | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.provider = provider;
  }

  /** Whether this failure is an exhausted provider rate limit. */
  get isQuota(): boolean {
    return this.status === 429;
  }

  /** Whether the indicator is simply unknown to the provider. */
  get isNotFound(): boolean {
    return this.status === 404;
  }

  /** Whether the service is missing a credential it needs. */
  get isUnconfigured(): boolean {
    return this.status === 503;
  }
}

async function request<T>(path: string, params?: Record<string, string>): Promise<T> {
  const query = params ? `?${new URLSearchParams(params)}` : "";
  let response: Response;

  try {
    response = await fetch(`/api${path}${query}`, { credentials: "same-origin" });
  } catch {
    throw new ApiError("Cannot reach the IoC Hunter API. Is the backend running?", 0);
  }

  if (response.ok) {
    return (await response.json()) as T;
  }

  let detail = `Request failed with status ${response.status}.`;
  let provider: string | null = null;
  try {
    const body = await response.json();
    if (typeof body.detail === "string") detail = body.detail;
    if (typeof body.provider === "string") provider = body.provider;
  } catch {
    /* the body was not JSON; the default message stands */
  }

  throw new ApiError(detail, response.status, provider);
}

/** Report how the service interprets `indicator`, without querying any provider. */
export function classify(indicator: string): Promise<ClassificationResult> {
  return request<ClassificationResult>("/classify", { indicator });
}

/** Fetch the threat intelligence report for `indicator`. */
export function lookup(indicator: string): Promise<Report> {
  return request<Report>("/lookup", { indicator });
}

/** Fetch sandbox behaviour and ATT&CK coverage for the file `indicator`. */
export function behaviour(indicator: string): Promise<BehaviourReport> {
  return request<BehaviourReport>("/behaviour", { indicator });
}

/** Fetch indicators connected to `indicator`. */
export function relations(indicator: string): Promise<RelationsReport> {
  return request<RelationsReport>("/relations", { indicator });
}

/** Fetch this session's recorded lookups, most recent first. */
export function history(): Promise<Report[]> {
  return request<Report[]>("/history");
}

/** Fetch service version and provider availability. */
export function status(): Promise<ServiceStatus> {
  return request<ServiceStatus>("/health");
}

/** Discard this session's recorded lookups. */
export async function clearHistory(): Promise<void> {
  await fetch("/api/history", { method: "DELETE", credentials: "same-origin" });
}

/** The URL that downloads this session's lookups as CSV. */
export const exportUrl = "/api/history/export.csv";

/** Fetch the ATT&CK matrix, optionally narrowed by text and platform. */
export function attackMatrix(query = "", platform = ""): Promise<AttackMatrix> {
  const params: Record<string, string> = {};
  if (query) params.q = query;
  if (platform) params.platform = platform;
  return request<AttackMatrix>("/attack/matrix", params);
}

/** Fetch one ATT&CK technique with its sub-techniques and parent. */
export function attackTechnique(id: string): Promise<AttackTechniqueDetail> {
  return request<AttackTechniqueDetail>(`/attack/techniques/${encodeURIComponent(id)}`);
}

/** The URL that downloads the whole ATT&CK catalogue as CSV. */
export const attackExportUrl = "/api/attack/export.csv";
