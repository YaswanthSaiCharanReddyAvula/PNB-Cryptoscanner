import { useState, useEffect, useCallback, useMemo } from "react";
import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import {
  Loader2, ChevronDown, ChevronUp,
  CheckCircle2, ArrowUpCircle, CircleDot, AlertCircle, RefreshCw,
} from "lucide-react";
import { cyberRatingService } from "@/services/api";
import { toast } from "sonner";
import { tierRowsForTable } from "@/lib/tierComplianceCriteria";

const BRAND = "#2563eb";
const RED = "#dc2626";
const GREEN = "#16a34a";
const TIER_THRESHOLDS = { elite: 700, standard: 400 };

function getTier(score: number): { label: string; color: string; bg: string } {
  if (score > TIER_THRESHOLDS.elite)  return { label: "Elite-PQC", color: GREEN, bg: "rgba(34,197,94,0.12)" };
  if (score >= TIER_THRESHOLDS.standard) return { label: "Standard", color: BRAND, bg: "rgba(37,99,235,0.12)" };
  return { label: "Legacy", color: RED, bg: "rgba(220,38,38,0.12)" };
}

/** When backend omits `explain`, still show the panel with score-based context. */
function fallbackExplain(score1000: number): {
  evidence: Record<string, number>;
  drivers: string[];
  note: string;
} {
  const t = getTier(score1000);
  return {
    evidence: {
      tls_total: 0,
      tls_1_3: 0,
      legacy_tls: 0,
      weak_cipher_indicators: 0,
      hndl_risk_inferred: 0,
    },
    drivers: [
      `Score ${score1000}/1000 maps to tier "${t.label}" (Standard is 400–700; Elite-PQC is above 700).`,
      "TLS evidence chips could not be loaded (older API or network). Use Refresh from latest scan after updating the backend.",
    ],
    note: "When GET /cyber-rating includes an explain object, this section shows TLS row counts from your last completed scan.",
  };
}

// Reference tables — NOT scan data, kept as-is
const TIER_REFERENCE = [
  { status: "Elite-PQC",                          icon: <CheckCircle2 size={16} color={GREEN} />, rating: "> 700",       color: GREEN },
  { status: "Standard",                           icon: <ArrowUpCircle size={16} color={BRAND} />, rating: "400 till 700", color: BRAND  },
  { status: "Legacy",                             icon: <CircleDot    size={16} color={RED}  />, rating: "< 400",        color: RED   },
  { status: "Maximum Score after normalisation*", icon: null,                                     rating: "1000",         color: "#94a3b8" },
];

type RatingHistoryRow = {
  scan_id?: string;
  domain?: string;
  score?: number;
  tier?: string;
  completed_at?: string;
  started_at?: string;
};

function formatDateTime(value?: string): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

export default function CyberRating() {
  const [score1000,     setScore1000]     = useState<number | null>(null);
  const [urlScores,     setUrlScores]     = useState<any[]>([]);
  const [explain,        setExplain]       = useState<any | null>(null);
  const [latestDomain, setLatestDomain] = useState<string | null>(null);
  const [history, setHistory] = useState<RatingHistoryRow[]>([]);
  const [explainOpen,   setExplainOpen]   = useState(true);
  const [tierOpen,      setTierOpen]      = useState(false);
  const [simTls,         setSimTls]         = useState(false);
  const [simPqc,         setSimPqc]         = useState(false);
  const [simBusy,        setSimBusy]        = useState(false);
  const [simResult, setSimResult] = useState<{
    baseline_score_100: number;
    projected_score_100: number;
    delta: number;
    note?: string;
    assumptions?: { assume_tls_13_all?: boolean; assume_pqc_hybrid_kem?: boolean };
    nist_pqc_references?: Record<string, { label: string; url: string }>;
  } | null>(null);

  const [ratingBusy, setRatingBusy] = useState(false);
  const [historyBusy, setHistoryBusy] = useState(false);

  const tier      = score1000 !== null ? getTier(score1000) : getTier(0);
  const CIRC      = 534;
  const dashArray = score1000 !== null ? (score1000 / 1000) * CIRC : 0;

  /** Merge API explain with client fallback so the panel always appears when a score exists. */
  const explainData = useMemo(
    () => (score1000 !== null ? explain ?? fallbackExplain(score1000) : null),
    [score1000, explain]
  );

  const fetchScore = useCallback(async () => {
    try {
      const res = await cyberRatingService.getRating();
      const d = res.data;
      // Backend returns score on 0–1000 scale and tier "N/A" when no scan exists.
      if (d?.tier === "N/A" || d == null) {
        setScore1000(null);
        setUrlScores([]);
        setExplain(null);
        setLatestDomain(null);
      } else if (typeof d.score === "number") {
        setScore1000(Math.round(Math.max(0, Math.min(1000, d.score))));
        if (Array.isArray(d.per_url_scores) && d.per_url_scores.length) setUrlScores(d.per_url_scores);
        setExplain(d.explain ?? null);
        setLatestDomain(typeof d.domain === "string" ? d.domain : null);
      }
    } catch {
      setScore1000(null);
      setExplain(null);
      setLatestDomain(null);
    }
  }, []);

  const fetchRatingHistory = useCallback(async () => {
    try {
      const res = await cyberRatingService.getRatingHistory({ limit: 200 });
      const rows = Array.isArray(res.data?.history) ? (res.data.history as RatingHistoryRow[]) : [];
      setHistory(rows);
    } catch {
      setHistory([]);
    }
  }, []);

  useEffect(() => {
    fetchScore();
    fetchRatingHistory();
  }, [fetchScore, fetchRatingHistory]);

  const refreshRating = async () => {
    setRatingBusy(true);
    setHistoryBusy(true);
    try {
      await Promise.all([fetchScore(), fetchRatingHistory()]);
    } finally {
      setRatingBusy(false);
      setHistoryBusy(false);
    }
  };

  const runScoreSimulation = async () => {
    setSimBusy(true);
    try {
      const res = await cyberRatingService.simulateQuantumScore({
        assume_tls_13_all: simTls,
        assume_pqc_hybrid_kem: simPqc,
      });
      const d = res.data as {
        baseline_score_100?: number;
        projected_score_100?: number;
        delta?: number;
        note?: string;
        assumptions?: { assume_tls_13_all?: boolean; assume_pqc_hybrid_kem?: boolean };
        nist_pqc_references?: Record<string, { label: string; url: string }>;
      };
      setSimResult({
        baseline_score_100: Number(d.baseline_score_100 ?? 0),
        projected_score_100: Number(d.projected_score_100 ?? 0),
        delta: Number(d.delta ?? 0),
        note: d.note,
        assumptions: d.assumptions,
        nist_pqc_references: d.nist_pqc_references,
      });
    } catch {
      toast.error("No completed scan to simulate, or the API is unreachable.");
      setSimResult(null);
    } finally {
      setSimBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Cyber Rating</h1>
          <p className="text-sm text-muted-foreground max-w-2xl">
            Enterprise-style score (0–1000) from the latest completed scan, plus historical scores for every scanned domain. Start or refresh scans from{" "}
            <Link to="/" className="font-medium text-primary hover:underline">Overview</Link>
            . This is a composite rating, not proof of deployed NIST PQC algorithms.
          </p>
          {latestDomain && (
            <p className="mt-1 text-xs text-muted-foreground">
              Latest score source: <span className="font-mono text-foreground">{latestDomain}</span>
            </p>
          )}
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="shrink-0 gap-2 border-primary/40"
          onClick={refreshRating}
          disabled={ratingBusy}
        >
          {ratingBusy || historyBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
          Refresh latest + history
        </Button>
      </motion.div>

      {/* Score Card */}
      <motion.div initial={{ opacity: 0, scale: 0.97 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.4 }}
        className="rounded-xl border border-border bg-card p-8 flex flex-col lg:flex-row items-center gap-8">
        {score1000 === null ? (
          <div className="flex flex-col items-center justify-center h-56 w-full">
            <p className="text-muted-foreground text-sm text-center px-4">
              No rating data yet. Run a scan from{" "}
              <Link to="/" className="font-medium text-primary hover:underline">Overview</Link>
              , then refresh here.
            </p>
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
                <span className="text-xs px-2 py-0.5 rounded" style={{ background: "rgba(37,99,235,0.12)", color: BRAND,  border: "1px solid rgba(37,99,235,0.28)"  }}>Standard 400–700</span>
                <span className="text-xs px-2 py-0.5 rounded" style={{ background: "rgba(220,38,38,0.12)", color: RED,   border: "1px solid rgba(220,38,38,0.28)"  }}>Legacy &lt; 400</span>
              </div>
            </div>
          </>
        )}
      </motion.div>

      {/* Explainability panel — tier badge uses composite score; chips summarize TLS rows from the same scan */}
      {score1000 !== null && explainData && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.06 }}
          className="rounded-xl border border-border bg-card p-6"
        >
          <button
            type="button"
            className="w-full flex items-center justify-between gap-3 text-left"
            onClick={() => setExplainOpen((v) => !v)}
            aria-expanded={explainOpen}
          >
            <div>
              <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide">
                Why this tier
              </h3>
              <p className="text-xs text-muted-foreground mt-0.5">
                Tier follows the 0–1000 score; bullets summarize TLS evidence from the latest completed scan (heuristic, not certification).
              </p>
            </div>
            <div className="text-muted-foreground shrink-0">{explainOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}</div>
          </button>

          <AnimatePresence initial={false}>
            {explainOpen && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.25 }}
                className="mt-4 overflow-hidden"
              >
                <div className="flex flex-wrap gap-2 mb-3">
                  <span className="text-xs px-2 py-0.5 rounded border border-primary/20 bg-primary/5 text-primary font-semibold">
                    TLS 1.3: {explainData.evidence?.tls_1_3 ?? 0}/{explainData.evidence?.tls_total ?? 0}
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded border border-amber-500/20 bg-amber-500/5 text-amber-700 font-semibold">
                    Legacy TLS: {explainData.evidence?.legacy_tls ?? 0}
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded border border-rose-500/20 bg-rose-500/5 text-rose-700 font-semibold">
                    Weak ciphers: {explainData.evidence?.weak_cipher_indicators ?? 0}
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded border border-rose-500/20 bg-rose-500/5 text-rose-700 font-semibold">
                    HNDL risk: {explainData.evidence?.hndl_risk_inferred ?? 0}
                  </span>
                </div>

                {Array.isArray(explainData.drivers) && explainData.drivers.length > 0 ? (
                  <div className="space-y-1">
                    {explainData.drivers.map((d: string, i: number) => (
                      <p key={i} className="text-sm text-foreground/90">
                        • {d}
                      </p>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No evidence drivers found.</p>
                )}

                {explainData.note && (
                  <p className="text-xs text-muted-foreground mt-3 leading-relaxed">{explainData.note}</p>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      )}

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.06 }}
        className="rounded-xl border border-border bg-card p-6"
      >
        <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-1">
          What-if quantum score
        </h3>
        <p className="text-xs text-muted-foreground mb-4">
          Heuristic projection on the scanner&apos;s 0–100 quantum score (display ×10 aligns with the 0–1000 gauge above). Indicative only.
        </p>
        <div className="flex flex-col lg:flex-row lg:items-center gap-4 mb-4">
          <div className="flex items-center gap-2">
            <Checkbox id="sim-tls" checked={simTls} onCheckedChange={(v) => setSimTls(v === true)} />
            <Label htmlFor="sim-tls" className="text-sm font-normal cursor-pointer">
              Assume TLS 1.3 on all endpoints
            </Label>
          </div>
          <div className="flex items-center gap-2">
            <Checkbox id="sim-pqc" checked={simPqc} onCheckedChange={(v) => setSimPqc(v === true)} />
            <Label htmlFor="sim-pqc" className="text-sm font-normal cursor-pointer">
              Assume PQC / hybrid KEM everywhere
            </Label>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="lg:ml-auto border-primary/50 text-primary hover:bg-primary/10"
            onClick={runScoreSimulation}
            disabled={simBusy}
          >
            {simBusy ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
            Run simulation
          </Button>
        </div>
        {simResult && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
            <div className="rounded-lg bg-secondary/40 px-3 py-2">
              <p className="text-[10px] uppercase text-muted-foreground">Baseline (0–100)</p>
              <p className="text-lg font-bold text-foreground">{simResult.baseline_score_100}</p>
              <p className="text-[10px] text-muted-foreground">≈ {Math.round(simResult.baseline_score_100 * 10)} / 1000</p>
            </div>
            <div className="rounded-lg bg-secondary/40 px-3 py-2">
              <p className="text-[10px] uppercase text-muted-foreground">Projected (0–100)</p>
              <p className="text-lg font-bold text-primary">{simResult.projected_score_100}</p>
              <p className="text-[10px] text-muted-foreground">≈ {Math.round(simResult.projected_score_100 * 10)} / 1000</p>
            </div>
            <div className="rounded-lg bg-secondary/40 px-3 py-2">
              <p className="text-[10px] uppercase text-muted-foreground">Delta</p>
              <p className="text-lg font-bold text-foreground">
                {simResult.delta >= 0 ? "+" : ""}
                {simResult.delta}
              </p>
            </div>
          </div>
        )}
        {simResult?.assumptions && (
          <p className="text-[11px] text-muted-foreground mt-3">
            {(() => {
              const p: string[] = [];
              if (simResult.assumptions?.assume_tls_13_all) p.push("TLS 1.3 everywhere");
              if (simResult.assumptions?.assume_pqc_hybrid_kem) p.push("PQC/hybrid KEM");
              return p.length
                ? `Applied: ${p.join(" · ")}`
                : "Applied: no uplift toggles (baseline only).";
            })()}
          </p>
        )}
        {simResult?.note && (
          <p className="text-[11px] text-muted-foreground mt-2 leading-relaxed">{simResult.note}</p>
        )}
        {simResult?.nist_pqc_references && (
          <div className="mt-4 rounded-lg border border-border/80 bg-secondary/20 p-3">
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Related NIST publications (reference)
            </p>
            <ul className="space-y-1.5">
              {Object.entries(simResult.nist_pqc_references).map(([k, ref]) => (
                <li key={k}>
                  <a
                    href={ref.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-primary hover:underline"
                  >
                    {ref.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
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
          <p className="text-sm text-muted-foreground text-center py-6 px-4">
            No URL scores yet — complete a scan from{" "}
            <Link to="/" className="font-medium text-primary hover:underline">Overview</Link>
            , then refresh.
          </p>
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

      {/* Rating History Table */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.14 }} className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="px-6 py-4 border-b border-border">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-foreground">Cyber Rating History (All Domains)</h2>
          <p className="text-xs text-muted-foreground mt-0.5">Every completed scan score grouped in one historical feed.</p>
        </div>
        {history.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-6 px-4">
            No historical ratings yet — complete at least one scan from{" "}
            <Link to="/" className="font-medium text-primary hover:underline">Overview</Link>.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-secondary/50">
                  {["Completed","Domain","Score","Tier","Scan ID"].map(h => <th key={h} className="text-left px-6 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {history.map((row, i) => {
                  const s = Math.max(0, Math.min(1000, Number(row.score ?? 0)));
                  const t = getTier(s);
                  return (
                    <tr key={`${row.scan_id ?? "scan"}-${i}`} className="border-b border-border/50 hover:bg-secondary/30 transition-colors">
                      <td className="px-6 py-3 text-xs text-muted-foreground">{formatDateTime(row.completed_at ?? row.started_at)}</td>
                      <td className="px-6 py-3 font-mono text-xs text-foreground">{row.domain ?? "unknown"}</td>
                      <td className="px-6 py-3 font-semibold" style={{ color: t.color }}>{s}</td>
                      <td className="px-6 py-3">
                        <span className="text-[10px] px-2 py-0.5 rounded font-semibold" style={{ color: t.color, backgroundColor: t.bg, border: `1px solid ${t.color}40` }}>
                          {row.tier || t.label}
                        </span>
                      </td>
                      <td className="px-6 py-3 font-mono text-[11px] text-muted-foreground">{row.scan_id ?? "—"}</td>
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
            <motion.div key="criteria" initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.25 }} className="overflow-hidden border-t border-border/60">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-secondary/50">
                      {["Tier","Security Level","Compliance Criteria","Priority / Action"].map(h => <th key={h} className="text-left px-6 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {tierRowsForTable().map((row) => (
                      <tr key={row.id} className="border-b border-border/50 hover:bg-secondary/30 transition-colors align-top">
                        <td className="px-6 py-4 font-semibold text-foreground whitespace-nowrap">{row.tier}</td>
                        <td className="px-6 py-4">
                          <span
                            className="text-[10px] px-2 py-0.5 rounded font-semibold"
                            style={{
                              color: row.color,
                              backgroundColor: `${row.color}18`,
                              border: `1px solid ${row.color}35`,
                            }}
                          >
                            {row.level}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-muted-foreground text-xs leading-relaxed max-w-xs">{row.compliance}</td>
                        <td className="px-6 py-4 text-xs font-medium" style={{ color: row.color }}>{row.action}</td>
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
