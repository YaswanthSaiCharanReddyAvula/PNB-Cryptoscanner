import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Request interceptor to attach auth token
api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem("auth_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor for 401 logout
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      sessionStorage.removeItem("auth_token");
      sessionStorage.removeItem("user");
      window.location.href = "/login";
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
};

// ── Assets ───────────────────────────────────────────────────────

export const assetService = {
  getAll:        (params?: Record<string, unknown>) => api.get("/assets", { params }),
  getStats:      () => api.get("/assets/stats"),
  getDistribution: () => api.get("/assets/distribution"),
  getInventory:  () => api.get("/discovery/assets"),
};

// ── Discovery ─────────────────────────────────────────────────────

export const discoveryService = {
  getNetworkGraph:  (domain?: string) => api.get("/discovery/network-graph", { params: { domain } }),
  getAssets:        () => api.get("/discovery/assets"),
};

// ── CBOM ──────────────────────────────────────────────────────────

export const cbomService = {
  getSummary: () => api.get("/cbom/summary"),
  getCharts:  () => api.get("/cbom/charts"),
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
};

// ── Reporting ─────────────────────────────────────────────────────

export const reportingService = {
  getDomains:     () => api.get("/reporting/domains"),
  generateReport: (type: string, params: { format: string; scheduled_at?: string; filters?: any }) => {
    // Use the /reporting/generate endpoint for all types
    const body = { ...params, reportType: type };
    const config = type !== "scheduler" ? { responseType: "blob" as const } : {};
    return api.post("/reporting/generate", body, config);
  },
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

export const scanService = {
  startScan:       (domain: string) => api.post("/scan", { domain }),
  getResults:      (domain: string) => api.get(`/results/${domain}`),
  getCBOM:         (domain: string) => api.get(`/cbom/${domain}`),
  getQuantumScore: (domain: string) => api.get(`/quantum-score/${domain}`),
};

export default api;
