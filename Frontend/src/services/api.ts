import axios from "axios";

const API_BASE_URL = "http://localhost:8000/api";

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
  login: (username: string, password: string) =>
    api.post("/auth/login", { username, password }),
  logout: () => api.post("/auth/logout"),
  forgotPassword: (email: string) =>
    api.post("/auth/forgot-password", { email }),
};

// Assets
export const assetService = {
  getAll: (params?: Record<string, unknown>) => api.get("/assets", { params }),
  getById: (id: string) => api.get(`/assets/${id}`),
  getStats: () => api.get("/assets/stats"),
  getDistribution: () => api.get("/assets/distribution"),
};

// Discovery
export const discoveryService = {
  getDiscoveredAssets: (params?: Record<string, unknown>) =>
    api.get("/discovery/assets", { params }),
  getNetworkGraph: () => api.get("/discovery/network-graph"),
};

// CBOM
export const cbomService = {
  getStats: () => api.get("/cbom/stats"),
  getKeyLengthDistribution: () => api.get("/cbom/key-length-distribution"),
  getCertificateAuthorities: () => api.get("/cbom/certificate-authorities"),
  getProtocolDistribution: () => api.get("/cbom/protocol-distribution"),
};

// PQC
export const pqcService = {
  getRiskCategories: () => api.get("/pqc/risk-categories"),
  getVulnerableAlgorithms: () => api.get("/pqc/vulnerable-algorithms"),
  getMigrationScore: () => api.get("/pqc/migration-score"),
  getComplianceData: () => api.get("/pqc/compliance"),
};

// Cyber Rating
export const cyberRatingService = {
  getRating: () => api.get("/cyber-rating"),
  getRiskBreakdown: () => api.get("/cyber-rating/risk-breakdown"),
  getRiskFactors: () => api.get("/cyber-rating/risk-factors"),
};

// Reporting
export const reportingService = {
  getDomains: () => api.get("/reporting/domains"),
  generateReport: (params: {
    domain: string;
    reportType: string;
    format: string;
  }) => api.post("/reporting/generate", params, { responseType: "blob" }),
};

// DNS / Name Server
export const dnsService = {
  getNameServerRecords: () => api.get("/dns/nameserver-records"),
};

// Crypto
export const cryptoService = {
  getCryptoSecurityData: () => api.get("/crypto/security"),
};

export default api;
