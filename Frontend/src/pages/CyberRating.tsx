import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Search, Lock, Loader2, ChevronDown, ChevronUp,
  CheckCircle2, ArrowUpCircle, CircleDot, AlertCircle,
} from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { cyberRatingService } from "@/services/api";
import { toast } from "sonner";
import { useScan } from "@/hooks/useScan";
import { ScanProgressBar } from "@/components/dashboard/ScanProgressBar";

const GOLD  = "#FBBC09";
const RED   = "#A20E37";
const GREEN = "#22c55e";
const TIER_THRESHOLDS = { elite: 700, standard: 400 };

function getTier(score: number): { label: string; color: string; bg: string } {
  if (score > TIER_THRESHOLDS.elite)  return { label: "Elite-PQC", color: GREEN, bg: "rgba(34,197,94,0.12)" };
  if (score >= TIER_THRESHOLDS.standard) return { label: "Standard", color: GOLD, bg: "rgba(251,188,9,0.12)" };
  return { label: "Legacy", color: RED, bg: "rgba(162,14,55,0.12)" };
}

function scaleScore(raw100: number) {
  return Math.round(Math.max(0, Math.min(1000, raw100 * 10)));
}

function computeScoreFromScan(v1: any): number {
  const tls = Array.isArray(v1?.tls_results) ? v1.tls_results : [];
  const hasLegacy = tls.some((t: any) => /1\.0|1\.1|ssl/i.test(String(t?.tls_version || "")));
  const raw = typeof v1?.quantum_score?.score === "number" ? v1.quantum_score.score : 75;
  return scaleScore(Math.max(0, Math.min(100, raw - (hasLegacy ? 20 : 0))));
}

// Reference tables — NOT scan data, kept as-is
const TIER_REFERENCE = [
  { status: "Elite-PQC",                          icon: <CheckCircle2 size={16} color={GREEN} />, rating: "> 700",       color: GREEN },
  { status: "Standard",                           icon: <ArrowUpCircle size={16} color={GOLD} />, rating: "400 till 700", color: GOLD  },
  { status: "Legacy",                             icon: <CircleDot    size={16} color={RED}  />, rating: "< 400",        color: RED   },
  { status: "Maximum Score after normalisation*", icon: null,                                     rating: "1000",         color: "#94a3b8" },
];

const TIER_CRITERIA = [
  { tier: "Tier-1 Elite",    level: "High",     compliance: "TLS 1.2/1.3 only · AES-GCM / ChaCha20 · ECDHE key exchange · Cert ≥ 2048-bit · HSTS enabled",          action: "Maintain Configuration; periodic monitoring",    actionColor: GREEN },
  { tier: "Tier-2 Standard", level: "Moderate", compliance: "TLS 1.2 + legacy allowed · Key > 2048-bit · Minor cipher weaknesses",                                    action: "Improve gradually; disable legacy protocols",     actionColor: GOLD  },
  { tier: "Tier-3 Legacy",   level: "Low",      compliance: "TLS 1.0/1.1 enabled · Weak ciphers (CBC, 3DES) · Possible self-signed certs",                            action: "Remediation required; upgrade TLS stack",        actionColor: "#f97316" },
  { tier: "Critical",        level: "Critical", compliance: "SSL v2/v3 enabled · Key < 1024-bit · No HSTS",                                                           action: "Immediate action; block or isolate service",      actionColor: RED   },
];

export default function CyberRating() {
  const [domain,        setDomain]        = useState("");
  const [scannedDomain, setScannedDomain] = useState("");
  const [score1000,     setScore1000]     = useState<number | null>(null);
  const [urlScores,     setUrlScores]     = useState<any[]>([]);
  const [tierOpen,      setTierOpen]      = useState(false);

  const { user } = useAuth();
  const isEmployee = user?.role === "Employee";
  const { isScanning, stageIndex, results, error, startScan } = useScan();

  const tier      = score1000 !== null ? getTier(score1000) : getTier(0);
  const CIRC      = 534;
  const dashArray = score1000 !== null ? (score1000 / 1000) * CIRC : 0;

  const fetchScore = async (v1FallbackPayload: any = null) => {
    try {
      const res = await cyberRatingService.getRating();
      if (res.data?.score) {
        setScore1000(scaleScore(res.data.score));
        if (res.data.per_url_scores?.length) setUrlScores(res.data.per_url_scores);
      }
    } catch { /* keep null */ }
    if (v1FallbackPayload) setScore1000(computeScoreFromScan(v1FallbackPayload));
  };

  useEffect(() => { fetchScore(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  useEffect(() => {
    if (results?.status === "completed" && !isScanning) {
      toast.success(`Analysis completed for ${scannedDomain}!`);
      const computed = computeScoreFromScan(results);
      setScore1000(computed);
      if (Array.isArray(results.tls_results) && results.tls_results.length) {
        setUrlScores(results.tls_results.slice(0, 8).map((t: any) => ({
          url:   t.host || t.target || scannedDomain,
          score: computeScoreFromScan({ tls_results: [t], quantum_score: results.quantum_score }),
        })));
      }
    } else if (error) { toast.error(error); }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [results, isScanning, error]);

  const handleScan = async () => {
    if (domain.trim() && !isScanning) { setScannedDomain(domain.trim()); await startScan(domain.trim()); }
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
        <h1 className="text-2xl font-bold text-foreground">Cyber Rating</h1>
        <p className="text-sm text-muted-foreground">Overall PQC-readiness score — maximum 1000 after normalisation</p>
      </motion.div>

      <div className="rounded-xl border border-border bg-card p-5">
        <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-3">Scan Domain</h3>
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Enter domain (e.g., pnbindia.com)" value={domain}
              onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleScan()}
              className="pl-10 bg-secondary border-border" disabled={isScanning} />
          </div>
          <Button onClick={handleScan} disabled={isEmployee || !domain || isScanning} className="px-6 font-semibold" style={{ backgroundColor: GOLD, color: "#111" }}>
            {isEmployee ? <Lock className="mr-2 h-4 w-4" /> : isScanning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            Analyze
          </Button>
        </div>
        {!isScanning && scannedDomain && stageIndex >= 5 && (
          <p className="text-xs text-muted-foreground mt-2">Showing results for: <span className="font-medium" style={{ color: GOLD }}>{scannedDomain}</span></p>
        )}
      </div>

      <ScanProgressBar isScanning={isScanning} stageIndex={stageIndex} targetDomain={scannedDomain} />

      {/* Score Card */}
      <motion.div initial={{ opacity: 0, scale: 0.97 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.4 }}
        className="rounded-xl border border-border bg-card p-8 flex flex-col lg:flex-row items-center gap-8">
        {score1000 === null ? (
          <div className="flex flex-col items-center justify-center h-56 w-full">
            <p className="text-muted-foreground text-sm text-center">No rating data yet. Scan a domain to generate a score.</p>
          </div>
        ) : (
          <>
            <div className="relative flex-shrink-0">
              <svg viewBox="0 0 200 200" className="w-52 h-52">
                <circle cx="100" cy="100" r="85" fill="none" stroke="hsl(220,14%,20%)" strokeWidth="14" />
                <circle cx="100" cy="100" r="85" fill="none" stroke={tier.color} strokeWidth="14"
                  strokeDasharray={`${dashArray} ${CIRC}`} strokeLinecap="round" transform="rotate(-90 100 100)"
                  style={{ transition: "stroke-dasharray 1.2s ease-out, stroke 0.8s ease" }} />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-5xl font-extrabold leading-none" style={{ color: tier.color, transition: "color 0.8s ease" }}>{score1000}</span>
                <span className="text-sm text-muted-foreground mt-1">/ 1000</span>
              </div>
            </div>
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-3xl font-bold text-foreground">{score1000} <span className="text-muted-foreground font-normal text-xl">/ 1000</span></span>
                <span className="px-3 py-1 rounded-full text-sm font-semibold" style={{ color: tier.color, backgroundColor: tier.bg, border: `1px solid ${tier.color}40` }}>{tier.label}</span>
              </div>
              <p className="text-muted-foreground text-sm max-w-md">
                Indicates a <span className="font-semibold" style={{ color: tier.color }}>{score1000 > 700 ? "stronger" : score1000 >= 400 ? "moderate" : "weaker"}</span> security posture.{" "}
                {score1000 <= 700 && "Review risk factors and upgrade your TLS stack to improve."}
              </p>
              <div className="flex gap-2 flex-wrap mt-1">
                <span className="text-xs px-2 py-0.5 rounded" style={{ background: "rgba(34,197,94,0.12)", color: GREEN, border: "1px solid rgba(34,197,94,0.25)" }}>Elite-PQC &gt; 700</span>
                <span className="text-xs px-2 py-0.5 rounded" style={{ background: "rgba(251,188,9,0.12)", color: GOLD,  border: "1px solid rgba(251,188,9,0.25)"  }}>Standard 400–700</span>
                <span className="text-xs px-2 py-0.5 rounded" style={{ background: "rgba(162,14,55,0.12)", color: RED,   border: "1px solid rgba(162,14,55,0.25)"  }}>Legacy &lt; 400</span>
              </div>
            </div>
          </>
        )}
      </motion.div>

      {/* Tier Reference Table */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-6 py-4 border-b border-border"><h2 className="text-sm font-semibold uppercase tracking-wide text-foreground">PQC Tier Reference</h2></div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-secondary/50">
                {["Status","Icon","PQC Rating For Enterprise"].map(h => <th key={h} className="text-left px-6 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {TIER_REFERENCE.map((row, i) => (
                <tr key={i} className="border-b border-border/50 hover:bg-secondary/30 transition-colors">
                  <td className="px-6 py-3 font-medium" style={{ color: row.color }}>{row.status}</td>
                  <td className="px-6 py-3">{row.icon ?? <span className="text-muted-foreground">—</span>}</td>
                  <td className="px-6 py-3 font-mono text-foreground">{row.rating}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </motion.div>

      {/* Per-URL Score Table */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-6 py-4 border-b border-border">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-foreground">Per-URL PQC Score</h2>
          <p className="text-xs text-muted-foreground mt-0.5">Individual endpoint scores contributing to the overall rating</p>
        </div>
        {urlScores.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-6 px-4">No URL scores yet — scan a domain to see per-URL ratings.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-secondary/50">
                  {["URL","PQC Score","Tier"].map(h => <th key={h} className="text-left px-6 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {urlScores.map((row, i) => {
                  const t = getTier(row.score);
                  return (
                    <tr key={i} className="border-b border-border/50 hover:bg-secondary/30 transition-colors">
                      <td className="px-6 py-3 font-mono text-foreground text-xs">{row.url}</td>
                      <td className="px-6 py-3">
                        <div className="flex items-center gap-3">
                          <div className="w-24 h-1.5 rounded-full bg-secondary overflow-hidden">
                            <div className="h-full rounded-full transition-all duration-700" style={{ width: `${row.score / 10}%`, backgroundColor: t.color }} />
                          </div>
                          <span className="font-semibold text-xs" style={{ color: t.color }}>{row.score}</span>
                        </div>
                      </td>
                      <td className="px-6 py-3">
                        <span className="text-[10px] px-2 py-0.5 rounded font-semibold" style={{ color: t.color, backgroundColor: t.bg, border: `1px solid ${t.color}40` }}>{t.label}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>

      {/* Tier Criteria Accordion */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="rounded-xl border border-border bg-card overflow-hidden">
        <button className="w-full flex items-center justify-between px-6 py-4 border-b border-border hover:bg-secondary/30 transition-colors" onClick={() => setTierOpen(o => !o)}>
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-foreground text-left">Tier Compliance Criteria</h2>
            <p className="text-xs text-muted-foreground mt-0.5 text-left">Security requirements and remediation priorities per tier</p>
          </div>
          {tierOpen ? <ChevronUp className="h-4 w-4 text-muted-foreground flex-shrink-0" /> : <ChevronDown className="h-4 w-4 text-muted-foreground flex-shrink-0" />}
        </button>
        <AnimatePresence initial={false}>
          {tierOpen && (
            <motion.div key="criteria" initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.25 }} className="overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-secondary/50">
                      {["Tier","Security Level","Compliance Criteria","Priority / Action"].map(h => <th key={h} className="text-left px-6 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {TIER_CRITERIA.map((row, i) => (
                      <tr key={i} className="border-b border-border/50 hover:bg-secondary/30 transition-colors align-top">
                        <td className="px-6 py-4 font-semibold text-foreground whitespace-nowrap">{row.tier}</td>
                        <td className="px-6 py-4">
                          <span className="text-[10px] px-2 py-0.5 rounded font-semibold" style={{ color: row.actionColor, backgroundColor: `${row.actionColor}18`, border: `1px solid ${row.actionColor}35` }}>{row.level}</span>
                        </td>
                        <td className="px-6 py-4 text-muted-foreground text-xs leading-relaxed max-w-xs">{row.compliance}</td>
                        <td className="px-6 py-4 text-xs font-medium" style={{ color: row.actionColor }}>{row.action}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {score1000 !== null && score1000 < 400 && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="rounded-xl border p-4 flex gap-3 items-start" style={{ borderColor: `${RED}50`, backgroundColor: `${RED}10` }}>
          <AlertCircle size={18} style={{ color: RED }} className="flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-semibold" style={{ color: RED }}>Legacy Tier — Immediate Action Required</p>
            <p className="text-xs text-muted-foreground mt-0.5">Your score is below 400. TLS 1.0 / 1.1 or weak ciphers may be active. Upgrade your TLS stack and apply PQC recommendations immediately.</p>
          </div>
        </motion.div>
      )}
    </div>
  );
}
