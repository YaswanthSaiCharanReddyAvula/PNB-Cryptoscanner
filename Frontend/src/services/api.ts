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

// Response interceptor for error handling
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

// Auth
export const authService = {
  login: (email: string, password: string) =>
    api.post("/auth/login", { email, password }),
  forgotPassword: (email: string) =>
    api.post("/auth/forgot-password", { email }),
};

// Users
export const userService = {
  getMe: () => api.get("/users/me"),
};

// Dashboard
export const dashboardService = {
  getSummary: () => api.get("/dashboard/summary"),
};

// Assets
export const assetService = {
  getAll: (params?: Record<string, unknown>) => api.get("/assets", { params }),
  getInventory: () => api.get("/asset-inventory"),
};

// Discovery
export const discoveryService = {
  getNetworkGraph: () => api.get("/asset-discovery"),
};

// CBOM
export const cbomService = {
  getSummary: () => api.get("/cbom/summary"),
  getCharts: () => api.get("/cbom/charts"),
};

// PQC
export const pqcService = {
  getPosture: () => api.get("/pqc/posture"),
};

// Cyber Rating
export const cyberRatingService = {
  getRating: () => api.get("/cyber-rating"),
};

// Reporting
export const reportingService = {
  generateReport: (type: string, params: { format: string; scheduled_at?: string; filters?: any }) => {
    // Scheduler endpoint returns JSON, others return a file blob
    const config = type !== "scheduler" ? { responseType: "blob" as const } : {};
    return api.post(`/report/${type}`, params, config);
  }
};

// DNS / Name Server
export const dnsService = {
  getNameServerRecords: () => api.get("/nameservers"),
};

// Crypto
export const cryptoService = {
  getCryptoSecurityData: () => api.get("/crypto"),
};

// Scanner
export const scanService = {
  startScan: (domain: string) => api.post("/scan", { domain, ports: [80, 443] }),
  getResults: (domain: string) => api.get(`/results/${domain}`),
  getCBOM: (domain: string) => api.get(`/cbom/${domain}`),
  getQuantumScore: (domain: string) => api.get(`/quantum-score/${domain}`),
};

export default api;
