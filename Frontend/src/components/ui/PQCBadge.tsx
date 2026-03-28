import React from "react";
import { ShieldCheck, CheckCircle, AlertTriangle, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from "@/components/ui/tooltip";

export type PQCStatus = "quantum-safe" | "pqc-ready" | "vulnerable" | "hndl-risk" | "unknown";

interface PQCBadgeProps {
  status: PQCStatus;
  className?: string;
}

const statusConfig: Record<
  PQCStatus,
  { label: string; icon: React.ElementType; colorClass: string; tooltip: string; animate: boolean }
> = {
  "quantum-safe": {
    label: "Fully Quantum Safe",
    icon: ShieldCheck,
    colorClass: "bg-emerald-500/15 text-emerald-700 border-emerald-500/30",
    tooltip: "Uses NIST-standardized Post-Quantum Algorithms (e.g. Kyber, Dilithium, ML-KEM).",
    animate: true,
  },
  "pqc-ready": {
    label: "PQC Ready",
    icon: CheckCircle,
    colorClass: "bg-sky-500/15 text-sky-700 border-sky-500/30",
    tooltip: "Excellent classical security (e.g. TLS 1.3 with AES-256). Pre-quantum readiness.",
    animate: true,
  },
  "vulnerable": {
    label: "Quantum Vulnerable",
    icon: AlertTriangle,
    colorClass: "bg-red-500/15 text-red-700 border-red-500/30",
    tooltip: "Relies on algorithms vulerable to quantum computers (e.g. RSA, ECDH, ECC).",
    animate: false,
  },
  "hndl-risk": {
    label: "HNDL Risk",
    icon: ShieldAlert,
    colorClass: "bg-rose-800/15 text-rose-900 border-rose-800/30",
    tooltip: "Harvest Now, Decrypt Later risk. Weak algorithms (e.g. TLS 1.2 or below with RSA).",
    animate: false,
  },
  "unknown": {
    label: "Unknown Status",
    icon: AlertTriangle,
    colorClass: "bg-secondary text-muted-foreground border-border",
    tooltip: "Not enough information to determine PQC readiness.",
    animate: false,
  },
};

export const PQCBadge: React.FC<PQCBadgeProps> = ({ status, className = "" }) => {
  const config = statusConfig[status] || statusConfig["unknown"];
  const Icon = config.icon;

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <div className={`relative inline-flex ${config.animate && status === "quantum-safe" ? "group" : ""}`}>
            {config.animate && (
              <div 
                className={`absolute inset-0 rounded-full animate-ping opacity-20 ${
                  status === "quantum-safe" ? "bg-emerald-500" : "bg-sky-500"
                }`} 
                style={{ animationDuration: '3s' }}
              />
            )}
            <Badge 
              variant="outline" 
              className={`flex items-center gap-1.5 px-2.5 py-1 text-xs whitespace-nowrap relative z-10 font-medium ${config.colorClass} ${className}`}
            >
              <Icon className="w-3.5 h-3.5" />
              {config.label}
            </Badge>
          </div>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-[200px] text-center bg-card border-border text-xs">
          <p>{config.tooltip}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
};

export function determinePQCStatus(
  tlsVersion: string | null | undefined, 
  cipherSuite: string | null | undefined, 
  keyLength: string | null | undefined
): PQCStatus {
  const tls = (tlsVersion || "").toLowerCase();
  const cipher = (cipherSuite || "").toLowerCase();

  // 1. Fully Quantum Safe
  if (
    cipher.includes("kyber") || 
    cipher.includes("dilithium") || 
    cipher.includes("falcon") || 
    cipher.includes("sphincs") || 
    cipher.includes("ml-kem") || 
    cipher.includes("ml-dsa")
  ) {
    return "quantum-safe";
  }

  // 4. HNDL Risk if TLS <= 1.2 + RSA/DHE
  if ((tls.includes("1.0") || tls.includes("1.1") || tls.includes("1.2") || tls.includes("ssl")) && (cipher.includes("rsa") || cipher.includes("dh"))) {
    return "hndl-risk";
  }

  // 3. Quantum Vulnerable (RSA, ECDSA, ECDH, ECC, DH)
  if (cipher.includes("rsa") || cipher.includes("ecdsa") || cipher.includes("ecc") || cipher.includes("ecdh") || cipher.includes("dh")) {
    return "vulnerable";
  }

  // 2. PQC Ready (TLS 1.3 + AES 256 only)
  if (tls.includes("1.3") && cipher.includes("aes") && cipher.includes("256") && !cipher.includes("rsa") && !cipher.includes("ec")) {
    return "pqc-ready";
  }

  // Fallbacks if not enough info or exact match didn't fire
  if (tls.includes("1.3")) return "pqc-ready";
  if (cipher) return "vulnerable"; // Any older classical cipher not explicitly caught

  return "unknown";
}

/**
 * Harvest-relevant exposure aligned with the PQC engine: quantum-vulnerable / HNDL-class
 * statuses, plus legacy weak crypto when not explicitly PQC-safe.
 */
export function hndlRiskFromCrypto(
  tlsVersion: string | null | undefined,
  cipherSuite: string | null | undefined,
  keyLength: string | null | undefined,
): boolean {
  const tls = tlsVersion || "";
  const cipher = cipherSuite || "";
  const klStr =
    keyLength && String(keyLength) !== "None" && String(keyLength).toLowerCase() !== "unknown"
      ? String(keyLength)
      : undefined;
  const isWeak = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "TLS 1.0", "TLS 1.1"].some(
    (p) => cipher.includes(p) || tls.includes(p),
  );
  const isPQCSafe = ["Kyber", "Dilithium", "FALCON", "SPHINCS", "ML-KEM", "ML-DSA"].some((p) =>
    cipher.toLowerCase().includes(p.toLowerCase()),
  );
  const pqcStatus = determinePQCStatus(tls, cipher, klStr);
  return (
    pqcStatus === "hndl-risk" ||
    pqcStatus === "vulnerable" ||
    (!isPQCSafe && isWeak)
  );
}
