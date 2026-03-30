import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

/** Origin hosting the FastAPI app (e.g. http://localhost:8000) — for /health and root routes. */
export function getApiOrigin(): string {
  return API_BASE_URL.replace(/\/api\/v1\/?$/, "") || "http://localhost:8000";
}

export const healthService = {
  check: () =>
    axios.get(`${getApiOrigin()}/health`, { timeout: 8000 }),
};

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Request interceptor — do not send Bearer on login/forgot-password (avoids confusing proxies; stale JWT irrelevant)
api.interceptors.request.use((config) => {
  const path = `${config.baseURL ?? ""}${config.url ?? ""}`;
  const rel = config.url ?? "";
  const skipAuth =
    rel.includes("/auth/login") ||
    rel.includes("/auth/forgot-password") ||
    path.includes("/auth/login") ||
    path.includes("/auth/forgot-password");
  if (!skipAuth) {
    const token = sessionStorage.getItem("auth_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

// Response interceptor — 401 on protected routes sends user to login; skip for failed sign-in
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      const url = String(error.config?.url ?? "");
      if (!url.includes("/auth/login")) {
        sessionStorage.removeItem("auth_token");
        sessionStorage.removeItem("user");
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

// ── Auth ─────────────────────────────────────────────────────────

export const authService = {
  /** Primary: tries the PostgreSQL v2 auth endpoint; falls back to demo login */
  login: (email: string, password: string) => {
    // The v2 auth router expects { email, password }
    // The scanner demo router at /auth/login accepts { username/email, password }
    return api.post("/auth/login", { email, username: email, password });
  },
  forgotPassword: (email: string) =>
    api.post("/auth/forgot-password", { email }),
};

// ── Users ────────────────────────────────────────────────────────

export const userService = {
  getMe: () => api.get("/users/me"),
};

// ── Dashboard ─────────────────────────────────────────────────────

export const dashboardService = {
  getSummary: () => api.get("/dashboard/summary"),
  /** Phase 4: org policy vs latest scan TLS (indicative) */
  getPolicyAlignment: () => api.get("/dashboard/policy-alignment"),
  /** Phase 5: open migration tasks + pending waivers (counts) */
  getMigrationSnapshot: () => api.get("/dashboard/migration-snapshot"),
  /** Phase 6: stakeholder rollup (KPIs, policy, migration, domains) */
  getExecutiveBrief: () => api.get("/dashboard/executive-brief"),
};

// ── Assets ───────────────────────────────────────────────────────

export const assetService = {
  getAll:        (params?: Record<string, unknown>) => api.get("/assets", { params }),
  getStats:      () => api.get("/assets/stats"),
  getDistribution: () => api.get("/assets/distribution"),
  getInventory:  () => api.get("/discovery/assets"),
  /** Phase 2: deduplicated hosts across recent completed scans */
  getInventorySummary: (limitScans?: number) =>
    api.get("/inventory/summary", { params: limitScans != null ? { limit_scans: limitScans } : {} }),
  putMetadata: (body: {
    host: string;
    owner?: string | null;
    environment?: string | null;
    criticality?: string | null;
  }) => api.put("/assets/metadata", body),
  bulkMetadata: (items: { host: string; owner?: string; environment?: string; criticality?: string }[]) =>
    api.post("/assets/metadata/bulk", items),
  /** Register external assets (CMDB/cloud/K8s/Git-style); optional merge into scans */
  importRegisteredAssets: (body: Record<string, unknown>) => api.post("/inventory/sources/import", body),
  listRegisteredAssets: (params?: { domain?: string; source?: string; limit?: number }) =>
    api.get("/inventory/registered", { params }),
  /** CycloneDX/SPDX-style JSON blob per host */
  ingestSbom: (body: Record<string, unknown>) => api.post("/inventory/sbom", body),
};

// ── Discovery ─────────────────────────────────────────────────────

export const discoveryService = {
  getNetworkGraph:  (domain?: string) => api.get("/discovery/network-graph", { params: { domain } }),
  getAssets:        () => api.get("/discovery/assets"),
};

// ── CBOM ──────────────────────────────────────────────────────────

export const cbomService = {
  getSummary: (domain?: string) => api.get("/cbom/summary", { params: domain ? { domain } : {} }),
  getCharts:  (domain?: string) => api.get("/cbom/charts", { params: domain ? { domain } : {} }),
};

// ── PQC ───────────────────────────────────────────────────────────

export const pqcService = {
  getPosture:              () => api.get("/pqc/posture"),
  getVulnerableAlgorithms: () => api.get("/pqc/vulnerable-algorithms"),
  getRiskCategories:       () => api.get("/pqc/risk-categories"),
  getCompliance:           () => api.get("/pqc/compliance"),
  getPerAppCbom:           (domain?: string) => api.get("/cbom/per-app", { params: { domain } }),
};

// ── Cyber Rating ──────────────────────────────────────────────────

export const cyberRatingService = {
  getRating:     () => api.get("/cyber-rating"),
  getRiskFactors:() => api.get("/cyber-rating/risk-factors"),
  /** Phase 3: heuristic what-if on 0–100 engine score (latest completed scan) */
  simulateQuantumScore: (body: {
    domain?: string | null;
    assume_tls_13_all?: boolean;
    assume_pqc_hybrid_kem?: boolean;
  }) => api.post("/quantum-score/simulate", body),
};

// ── Migration tasks & waivers (Phase 5) ─────────────────────────

export const migrationService = {
  listTasks: (params?: { domain?: string; status_filter?: string }) =>
    api.get("/migration/tasks", { params }),
  createTask: (body: Record<string, unknown>) => api.post("/migration/tasks", body),
  patchTask: (taskId: string, body: Record<string, unknown>) =>
    api.patch(`/migration/tasks/${taskId}`, body),
  deleteTask: (taskId: string) => api.delete(`/migration/tasks/${taskId}`),
  seedFromBacklog: (body?: { domain?: string; limit?: number }) =>
    api.post("/migration/tasks/seed-from-backlog", body ?? {}),
  listWaivers: (statusFilter?: string) =>
    api.get("/migration/waivers", {
      params: statusFilter ? { status_filter: statusFilter } : {},
    }),
  createWaiver: (body: Record<string, unknown>) => api.post("/migration/waivers", body),
  patchWaiver: (waiverId: string, body: Record<string, unknown>) =>
    api.patch(`/migration/waivers/${waiverId}`, body),
  deleteWaiver: (waiverId: string) => api.delete(`/migration/waivers/${waiverId}`),
};

// ── Admin (Phase 4) ─────────────────────────────────────────────

export const adminService = {
  getPolicy: () => api.get("/admin/policy"),
  putPolicy: (body: Record<string, unknown>) => api.put("/admin/policy", body),
  getIntegrations: () => api.get("/admin/integrations"),
  putIntegrations: (body: Record<string, unknown>) => api.put("/admin/integrations", body),
  getExportHistory: (limit?: number) =>
    api.get("/admin/exports/history", { params: limit != null ? { limit } : {} }),
  logExport: (body: { export_type: string; domain?: string | null }) =>
    api.post("/admin/exports/log", body),
  /** Phase 7: Mongo ping, scan queue, limits, recent failures (admin-only) */
  getOpsSnapshot: () => api.get("/dashboard/ops-snapshot"),
};

// ── Reports & threat-model (exports, bundles, roadmap) ──────────

export const reportingService = {
  getDomains:     () => api.get("/reporting/domains"),
  exportBundle: (domain?: string) =>
    api.get("/reports/export-bundle", { params: domain ? { domain } : {} }),
  getThreatModelSummary: (domain?: string) =>
    api.get("/threat-model/summary", { params: domain ? { domain } : {} }),
  getMigrationRoadmap: (domain?: string) =>
    api.get("/migration/roadmap", { params: domain ? { domain } : {} }),
  /** Static NIST PQC publication URLs (FIPS 203/204/205, SP 800-208) */
  getNistCatalog: () => api.get("/threat-model/nist-catalog"),
};

/** Risk → target solution matrix from latest scan (TLS posture + PQC recommendations) */
export const roadmapService = {
  getSecurityRoadmap: (domain: string) =>
    api.get(`/security-roadmap/${encodeURIComponent(domain.trim().toLowerCase())}`),
  /** Fallback: roadmap derived from latest completed scan (no domain input). */
  getSecurityRoadmapLatest: () => api.get("/security-roadmap/latest"),
};

// ── DNS / Name Server ─────────────────────────────────────────────

export const dnsService = {
  getNameServerRecords: () => api.get("/dns/nameserver-records"),
};

// ── Crypto ────────────────────────────────────────────────────────

export const cryptoService = {
  getCryptoSecurityData: () => api.get("/crypto/security"),
};

// ── Scanner ───────────────────────────────────────────────────────

export type ScanControllerPayload = {
  max_subdomains?: number;
  execution_time_limit_seconds?: number;
};

export const scanService = {
  startScan: (domain: string, controller?: ScanControllerPayload) =>
    api.post("/scan", { domain, ...controller }),
  /** Phase 2: multiple domains (comma-free list); max domains enforced server-side */
  startBatchScan: (
    domains: string[],
    opts?: {
      include_subdomains?: boolean;
      ports?: string;
    } & ScanControllerPayload,
  ) =>
    api.post("/scan/batch", {
      domains,
      include_subdomains: opts?.include_subdomains ?? true,
      ports: opts?.ports,
      ...(opts?.max_subdomains != null ? { max_subdomains: opts.max_subdomains } : {}),
      ...(opts?.execution_time_limit_seconds != null
        ? { execution_time_limit_seconds: opts.execution_time_limit_seconds }
        : {}),
    }),
  getScanHistory: (domain: string, limit?: number, statusFilter?: string) =>
    api.get("/scans/history", {
      params: {
        domain,
        ...(limit != null ? { limit } : {}),
        ...(statusFilter ? { status_filter: statusFilter } : {}),
      },
    }),
  /** Phase 2: single query for portfolio run list (replaces per-domain N+1) */
  getRecentScans: (limit?: number, statusFilter?: string) =>
    api.get("/scans/recent", {
      params: {
        ...(limit != null ? { limit } : {}),
        ...(statusFilter ? { status_filter: statusFilter } : {}),
      },
    }),
  getScanDiff: (domain: string, fromScanId: string, toScanId: string) =>
    api.get("/scans/diff", { params: { domain, from_scan_id: fromScanId, to_scan_id: toScanId } }),
  getResults:      (domain: string) => api.get(`/results/${domain}`),
  getCBOM:         (domain: string) => api.get(`/cbom/${domain}`),
  getQuantumScore: (domain: string) => api.get(`/quantum-score/${domain}`),
};

export default api;
