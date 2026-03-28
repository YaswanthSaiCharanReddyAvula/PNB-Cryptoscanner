/** Reference: tier compliance matrix (TLS / posture) — shared by Security Roadmap and Cyber Rating. */

export type TierComplianceRow = {
  id: "elite" | "standard" | "legacy" | "critical";
  /** Order in reference table (Elite first, as in UI mock). */
  tableOrder: number;
  /** Left-to-right on the migration path (Critical → Elite). */
  roadmapIndex: number;
  tier: string;
  level: string;
  compliance: string;
  action: string;
  color: string;
};

export const TIER_COMPLIANCE_ROWS: TierComplianceRow[] = [
  {
    id: "elite",
    tableOrder: 0,
    roadmapIndex: 3,
    tier: "Tier-1 Elite",
    level: "High",
    compliance:
      "TLS 1.2/1.3 only; AES-GCM / ChaCha20; ECDHE key exchange; Cert ≥ 2048-bit; HSTS enabled.",
    action: "Maintain configuration; periodic monitoring",
    color: "#16a34a",
  },
  {
    id: "standard",
    tableOrder: 1,
    roadmapIndex: 2,
    tier: "Tier-2 Standard",
    level: "Moderate",
    compliance: "TLS 1.2 + legacy allowed; Key > 2048-bit; Minor cipher weaknesses.",
    action: "Improve gradually; disable legacy protocols",
    color: "#2563eb",
  },
  {
    id: "legacy",
    tableOrder: 2,
    roadmapIndex: 1,
    tier: "Tier-3 Legacy",
    level: "Low",
    compliance: "TLS 1.0/1.1 enabled; Weak ciphers (CBC, 3DES); Possible self-signed certs.",
    action: "Remediation required; upgrade TLS stack",
    color: "#f97316",
  },
  {
    id: "critical",
    tableOrder: 3,
    roadmapIndex: 0,
    tier: "Critical",
    level: "Critical",
    compliance: "SSL v2/v3 enabled; Key < 1024-bit; No HSTS.",
    action: "Immediate action; block or isolate service",
    color: "#dc2626",
  },
];

export function tierRowsForTable(): TierComplianceRow[] {
  return [...TIER_COMPLIANCE_ROWS].sort((a, b) => a.tableOrder - b.tableOrder);
}

export function tierRowsForRoadmapPath(): TierComplianceRow[] {
  return [...TIER_COMPLIANCE_ROWS].sort((a, b) => a.roadmapIndex - b.roadmapIndex);
}

/** Indicative “you are here” on the 4-step path (0 = Critical … 3 = Elite). */
export function inferTierRoadmapStep(data: {
  quantum_score?: number | null;
  items?: { priority?: string; risk?: string; solution?: string; risk_detail?: string }[];
} | null): number {
  if (!data) return 2;
  const items = data.items ?? [];
  const blob = items
    .map((i) => `${i.risk ?? ""} ${i.solution ?? ""} ${i.risk_detail ?? ""}`)
    .join(" ")
    .toLowerCase();
  if (/ssl\s*v?[23]\b|sslv3|key\s*<\s*1024|1023-bit|no hsts/.test(blob)) return 0;
  if (/tls\s*1\.0|tls\s*1\.1|tlsv1\.0|tlsv1\.1|weak cipher|3des|\bcbc\b|self-signed/.test(blob)) return 1;
  const sev = items.filter((i) =>
    ["critical", "high"].includes((i.priority || "").toLowerCase()),
  ).length;
  if (sev >= 3) return 0;
  if (sev >= 1) return 1;
  const q = data.quantum_score;
  if (typeof q === "number") {
    if (q >= 75) return 3;
    if (q >= 55) return 2;
    if (q >= 35) return 1;
    return 0;
  }
  if (items.length === 0) return 3;
  return 2;
}
