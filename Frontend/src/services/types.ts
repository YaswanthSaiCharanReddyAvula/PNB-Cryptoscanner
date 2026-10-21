export interface DashboardSummary {
  total_assets: number;
  public_web_apps: number;
  apis: number;
  servers: number;
  expiring_certificates: number;
  high_risk_assets: number;
}

export interface PolicyAlignment {
  has_scan: boolean;
  scan_domain?: string | null;
  policy: {
    min_tls_version: string;
    require_forward_secrecy: boolean;
    pqc_readiness_target?: string;
  };
  alignment: {
    tls_endpoints?: number;
    below_min_tls?: number;
    unknown_tls_version?: number;
    forward_secrecy_heuristic_flags?: number;
  };
  note?: string;
}

export interface MigrationSnapshot {
  open_tasks: number;
  pending_waivers: number;
}

export interface ExecutiveBrief {
  generated_at: string;
  disclaimer: string;
  kpis: DashboardSummary;
  portfolio: {
    unique_hosts_observed: number;
    completed_scans_in_window: number;
  };
  migration: MigrationSnapshot;
  policy: {
    min_tls_version: string;
    require_forward_secrecy: boolean;
    pqc_readiness_target?: string;
  };
  domains: Array<{
    domain: string;
    risk_level: string;
    score: number;
    completed_at: string;
  }>;
}

export interface AuthUser {
  id?: string;
  username?: string;
  full_name?: string;
  email: string;
  role: string;
  is_active?: boolean;
}

export interface VerifyOtpResponse {
  access_token: string;
  token_type: string;
  role?: string;
  user: AuthUser;
}

export type LoginResponse =
  | { requires_otp: true; email: string; message: string }
  | VerifyOtpResponse;


export interface AiRoadmapPlanBody {
  domain: string;
  constraints?: {
    horizon_days?: number;
    notes?: string;
  };
}

export interface AiRoadmapPlanResponse {
  plan: string;
  note?: string;
}
