import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, Check, CheckCircle, XCircle, Lock } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
  Label,
} from "recharts";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { pqcService } from "@/services/api";
import { useDomain } from "@/contexts/DomainContext";

/** Enterprise blue (primary) — matches Intelligence Dossier mockups */
const BRAND = "#2563eb";
const RED = "#dc2626";
const GREEN = "#16a34a";
const NAVY = "#0b1220";

const chartTooltipLight = {
  contentStyle: {
    background: "rgba(255,255,255,0.96)",
    border: "1px solid rgb(226 232 240)",
    borderRadius: "12px",
    fontSize: "12px",
    color: "rgb(15 23 42)",
    boxShadow: "0 12px 40px -12px rgb(15 23 42 / 0.18)",
  },
  cursor: { fill: "rgb(59 130 246 / 0.06)" },
  labelStyle: { color: "rgb(71 85 105)", fontWeight: 600 },
};

const HEAT_STYLES = [
  {
    label: "Safe or No Risk",
    swatch: "bg-gradient-to-br from-emerald-400 to-teal-600 shadow-sm ring-1 ring-emerald-200/60",
    className:
      "bg-gradient-to-br from-emerald-400 via-emerald-500 to-teal-600 shadow-[0_8px_24px_-6px_rgba(16,185,129,0.55)] ring-1 ring-white/40",
  },
  {
    label: "Medium Risk",
    swatch: "bg-gradient-to-br from-amber-400 to-orange-600 shadow-sm ring-1 ring-orange-200/60",
    className:
      "bg-gradient-to-br from-amber-400 via-orange-500 to-orange-600 shadow-[0_8px_24px_-6px_rgba(249,115,22,0.5)] ring-1 ring-white/35",
  },
  {
    label: "High Risk",
    swatch: "bg-gradient-to-br from-rose-500 to-red-700 shadow-sm ring-1 ring-red-200/50",
    className:
      "bg-gradient-to-br from-rose-500 via-red-600 to-red-800 shadow-[0_8px_24px_-6px_rgba(220,38,38,0.55)] ring-1 ring-white/30",
  },
];
// Static heatmap — represents scoring system (not scan data)
const HEATMAP = [
  [2, 2, 1],
  [2, 1, 0],
  [1, 0, 0],
];

function PieCenterLabel({ viewBox, dominantName, dominantPct }: { viewBox?: { cx?: number; cy?: number }; dominantName: string; dominantPct: number }) {
  const cx = viewBox?.cx ?? 0;
  const cy = viewBox?.cy ?? 0;
  return (
    <text x={cx} y={cy} textAnchor="middle" dominantBaseline="middle" className="pointer-events-none select-none">
      <tspan x={cx} dy="-0.15em" className="fill-slate-500 text-[10px] font-semibold uppercase tracking-wider">
        Share
      </tspan>
      <tspan x={cx} dy="1.35em" className="fill-slate-800 text-lg font-bold tabular-nums">
        {dominantPct}%
      </tspan>
      <tspan x={cx} dy="1.15em" className="fill-slate-500 text-[9px] font-medium">
        {dominantName.length > 14 ? `${dominantName.slice(0, 12)}…` : dominantName}
      </tspan>
    </text>
  );
}

function scoreTier(s: number) {
  if (s > 700) return { label: "Elite-PQC", color: GREEN };
  if (s >= 400) return { label: "Standard",  color: BRAND };
  return              { label: "Legacy",     color: RED  };
}

const BarLabel = (props: any) => {
  const { x, y, width, value } = props;
  if (value == null || value === 0) return null;
  return (
    <text
      x={x + width / 2}
      y={y - 8}
      textAnchor="middle"
      fill="#fff"
      fontSize={12}
      fontWeight={700}
      style={{ textShadow: "0 1px 3px rgb(0 0 0 / 0.45)" }}
    >
      {value}
    </text>
  );
};

export default function PQCPosture() {
  const { selectedDomain } = useDomain();
  const [posture,       setPosture]       = useState<any>(null);
  const [algorithms,    setAlgorithms]    = useState<any[]>([]);
  const [loading,       setLoading]       = useState(true);
  const [selectedAsset, setSelectedAsset] = useState<any | null>(null);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      pqcService.getPosture(selectedDomain ?? undefined).catch(() => ({ data: null })),
      pqcService.getVulnerableAlgorithms(selectedDomain ?? undefined).catch(() => ({ data: [] })),
    ]).then(([postureRes, algoRes]) => {
      setPosture(postureRes.data);
      setAlgorithms(Array.isArray(algoRes.data) ? algoRes.data : []);
      setLoading(false);
    });
  }, [selectedDomain]);

  // Computed from real API data
  const classificationData = posture ? [
    { name: "Elite",    count: posture.elite_count    || 0, color: GREEN },
    { name: "Standard", count: posture.standard_count || 0, color: BRAND  },
    { name: "Critical", count: posture.critical_apps  || 0, color: RED   },
  ] : [];

  const pieData = posture ? [
    { name: "Elite-PQC Ready", value: posture.elite_pqc_pct   || 0, color: GREEN },
    { name: "Standard",        value: posture.standard_pct    || 0, color: BRAND  },
    { name: "Legacy",          value: posture.legacy_pct      || 0, color: "#f97316" },
    { name: "Critical",        value: posture.critical_pct    || 0, color: RED   },
  ] : [];

  const dominantSlice =
    pieData.length > 0
      ? pieData.reduce((a, b) => (Number(b.value) > Number(a.value) ? b : a), pieData[0])
      : { name: "—", value: 0 };

  const barFill: Record<string, string> = {
    Elite: "url(#gradeElite)",
    Standard: "url(#gradeStandard)",
    Critical: "url(#gradeCritical)",
  };

  const assetPqcData    = posture?.asset_pqc_status || [];
  const recommendations = posture?.recommendations   || [];

  const statsText = posture ? [
    { label: "Elite-PQC Ready", value: `${posture.elite_pqc_pct || 0}%`, color: GREEN },
    { label: "Standard",        value: `${posture.standard_pct  || 0}%`, color: BRAND  },
    { label: "Legacy",          value: `${posture.legacy_pct    || 0}%`, color: "#f97316" },
    { label: "Critical Apps",   value: `${posture.critical_apps || 0}`,  color: RED   },
    ...(typeof posture.pqc_kem_endpoints === "number"
      ? [{ label: "PQ/hybrid signals", value: String(posture.pqc_kem_endpoints), color: GREEN }]
      : []),
    ...(typeof posture.tls_modern_endpoints === "number"
      ? [{ label: "TLS modern (1.3)", value: String(posture.tls_modern_endpoints), color: NAVY }]
      : []),
  ] : [];

  if (loading) {
    return (
      <div className="space-y-5">
        <div className="space-y-2">
          {[1,2,3].map(i => <Skeleton key={i} className="h-10 w-full" />)}
        </div>
      </div>
    );
  }

  if (!posture) {
    return (
      <div className="text-center py-16 text-muted-foreground">
        <Lock className="h-12 w-12 mx-auto mb-4 opacity-30" />
        <p className="text-lg font-medium">No PQC posture data yet</p>
        <p className="text-sm max-w-md mx-auto">
          Run a scan from the dashboard. Posture is derived from the latest completed scan (TLS and inventory).
        </p>
        <Button asChild variant="outline" className="mt-6 border-primary/40 text-primary">
          <Link to="/">Open dashboard</Link>
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="rounded-xl overflow-hidden" style={{ backgroundColor: NAVY, border: `1px solid ${BRAND}33` }}>
        <div className="px-6 py-3 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <h1 className="text-lg font-bold text-white tracking-wide">PQC Compliance Dashboard</h1>
            <p className="text-xs text-blue-300 mt-0.5">Post-Quantum Cryptography Readiness Assessment</p>
            <p className="text-[11px] text-white/55 mt-2 max-w-2xl leading-relaxed">
              &quot;Elite&quot; includes TLS 1.3-class endpoints; &quot;PQC / hybrid signal&quot; means Kyber-like strings in
              cipher/KEX names from the scanner — verify in your environment. Asset values below are posture heuristics and
              are not the same metric as the Cyber Rating page&apos;s composite 0-1000 score.
            </p>
          </div>
          {statsText.length > 0 && (
            <div className="flex flex-wrap items-center gap-0 text-xs divide-x divide-white/10 rounded-lg overflow-hidden border border-white/10">
              {statsText.map((s) => (
                <div key={s.label} className="px-4 py-2 flex flex-col items-center gap-0.5" style={{ backgroundColor: `${s.color}14` }}>
                  <span className="font-bold text-sm" style={{ color: s.color }}>{s.value}</span>
                  <span className="text-white/60 text-[10px]">{s.label}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </motion.div>

      {posture?.quantum_readiness != null && typeof posture.quantum_readiness.score === "number" && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-xl border border-slate-200/90 bg-white p-5 shadow-sm ring-1 ring-slate-100"
        >
          <h3 className="text-[11px] font-bold uppercase tracking-[0.14em] text-slate-600">Quantum readiness (engine)</h3>
          <p className="text-xs text-muted-foreground mt-1 max-w-3xl leading-relaxed">
            From the latest scan&apos;s CBOM + catalog. Confidence reflects TLS scan certainty; drivers list the weakest categories.
          </p>
          <div className="mt-4 flex flex-wrap gap-6">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Score</p>
              <p className="text-2xl font-bold tabular-nums" style={{ color: NAVY }}>
                {Math.round(Number(posture.quantum_readiness.score))}
                <span className="text-sm font-medium text-muted-foreground">/100</span>
              </p>
            </div>
            {typeof posture.quantum_readiness.confidence === "number" && (
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Confidence</p>
                <p className="text-lg font-semibold tabular-nums">
                  {Math.round(Number(posture.quantum_readiness.confidence) * 100)}%
                </p>
              </div>
            )}
            {posture.quantum_readiness.catalog_version ? (
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Catalog</p>
                <p className="text-sm font-mono text-slate-800">{String(posture.quantum_readiness.catalog_version)}</p>
              </div>
            ) : null}
            {posture.quantum_readiness.risk_level ? (
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Risk</p>
                <p className="text-sm font-medium capitalize">{String(posture.quantum_readiness.risk_level)}</p>
              </div>
            ) : null}
          </div>
          {Array.isArray(posture.quantum_readiness.drivers) && posture.quantum_readiness.drivers.length > 0 && (
            <div className="mt-4 border-t border-slate-100 pt-3">
              <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground mb-2">Top drivers</p>
              <ul className="space-y-1 text-sm text-slate-700">
                {posture.quantum_readiness.drivers.map((d: string, i: number) => (
                  <li key={i}>• {d}</li>
                ))}
              </ul>
            </div>
          )}
        </motion.div>
      )}

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">

        {/* Pie chart */}
        <div className="rounded-2xl border border-slate-200/90 bg-gradient-to-b from-white to-slate-50/80 p-5 shadow-sm ring-1 ring-slate-100">
          <h3 className="mb-4 text-[11px] font-bold uppercase tracking-[0.14em] text-slate-600">Application Status</h3>
          {pieData.every((d) => d.value === 0) ? (
            <div className="flex h-[240px] items-center justify-center text-sm text-muted-foreground">No status data yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <defs>
                  <linearGradient id="pieElite" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stopColor="#22c55e" />
                    <stop offset="100%" stopColor="#4ade80" />
                  </linearGradient>
                  <linearGradient id="pieStandard" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stopColor="#1d4ed8" />
                    <stop offset="100%" stopColor="#93c5fd" />
                  </linearGradient>
                  <linearGradient id="pieLegacy" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stopColor="#ea580c" />
                    <stop offset="100%" stopColor="#fb923c" />
                  </linearGradient>
                  <linearGradient id="pieCritical" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stopColor="#b91c1c" />
                    <stop offset="100%" stopColor="#f87171" />
                  </linearGradient>
                </defs>
                <Pie
                  data={pieData}
                  cx="42%"
                  cy="50%"
                  innerRadius={56}
                  outerRadius={88}
                  paddingAngle={2}
                  cornerRadius={8}
                  dataKey="value"
                  stroke="#fff"
                  strokeWidth={3}
                  animationDuration={900}
                  animationEasing="ease-out"
                >
                  {pieData.map((entry, i) => {
                    const gid =
                      entry.name === "Elite-PQC Ready"
                        ? "pieElite"
                        : entry.name === "Standard"
                          ? "pieStandard"
                          : entry.name === "Legacy"
                            ? "pieLegacy"
                            : "pieCritical";
                    return <Cell key={i} fill={`url(#${gid})`} />;
                  })}
                  <Label
                    position="center"
                    content={(props: { viewBox?: { cx?: number; cy?: number } }) => (
                      <PieCenterLabel
                        viewBox={props.viewBox}
                        dominantName={dominantSlice.name}
                        dominantPct={Math.round(Number(dominantSlice.value))}
                      />
                    )}
                  />
                </Pie>
                <Tooltip
                  {...chartTooltipLight}
                  formatter={(v: number) => [`${v}%`, "Share"]}
                />
                <Legend
                  layout="vertical"
                  align="right"
                  verticalAlign="middle"
                  iconType="circle"
                  iconSize={10}
                  wrapperStyle={{ paddingLeft: 8 }}
                  formatter={(value) => (
                    <span className="text-[11px] font-medium text-slate-600">{value}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Heatmap (static — represents risk model, not scan data) */}
        <div className="rounded-2xl border border-slate-200/90 bg-gradient-to-b from-white via-slate-50/50 to-slate-100/40 p-5 shadow-sm ring-1 ring-slate-100">
          <h3 className="mb-4 text-[11px] font-bold uppercase tracking-[0.14em] text-slate-600">Risk Overview</h3>
          <div className="mt-1 flex flex-col h-full gap-5">
            {posture?.quantum_readiness?.breakdown ? (
              <div className="flex-1 flex items-center justify-center">
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 w-full max-w-[320px]">
                  {Object.entries(posture.quantum_readiness.breakdown).map(([key, score], idx) => {
                    if (score == null) return null;
                    const numScore = Number(score);
                    // Determine risk level based on score (Lower score = higher risk)
                    const level = numScore > 80 ? 0 : numScore > 40 ? 1 : 2;
                    const style = HEAT_STYLES[level];
                    const title = key.replace(/_/g, " ");
                    
                    return (
                      <motion.div
                        key={key}
                        initial={{ opacity: 0, scale: 0.9, y: 6 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        transition={{ delay: idx * 0.05, type: "spring", stiffness: 300, damping: 20 }}
                        whileHover={{ scale: 1.05, y: -2 }}
                        className={`flex flex-col items-center justify-center p-3 rounded-2xl text-white aspect-square ${style.className}`}
                        title={`${title}: ${numScore}/100`}
                      >
                        {level === 2 ? (
                          <span className="text-2xl font-black tracking-tight drop-shadow-md mb-1.5">H</span>
                        ) : level === 1 ? (
                          <span className="text-2xl font-black tracking-tight drop-shadow-md mb-1.5">M</span>
                        ) : (
                          <Check className="h-7 w-7 stroke-[3] drop-shadow-md mb-1.5" aria-hidden />
                        )}
                        <span className="text-[10px] font-bold uppercase tracking-wider text-white/95 truncate w-full text-center px-1 drop-shadow-sm">
                          {title}
                        </span>
                      </motion.div>
                    );
                  })}
                </div>
              </div>
            ) : (
              <div className="flex-1 flex items-center justify-center text-sm text-muted-foreground">
                No risk breakdown data available
              </div>
            )}
            <div className="flex flex-wrap justify-center gap-x-5 gap-y-2 mt-auto pt-4 border-t border-slate-100">
              {HEAT_STYLES.map((h) => (
                <div key={h.label} className="flex items-center gap-2 text-[11px] font-medium text-slate-600">
                  <span className={`h-3 w-3 shrink-0 rounded-md ${h.swatch}`} aria-hidden />
                  {h.label}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Asset PQC Support Table + Detail Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
        <div className="lg:col-span-3 rounded-xl border border-border bg-card overflow-hidden">
          <div className="px-5 py-4 border-b border-border flex items-center justify-between">
            <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide">Asset PQC Support</h3>
            <span className="text-xs text-muted-foreground">{assetPqcData.filter((a: any) => !a.pqc_supported).length} assets need attention</span>
          </div>
          {assetPqcData.length === 0 ? (
            <div className="px-5 py-8 text-center text-muted-foreground text-sm">
              No asset PQC data yet — run a scan from{" "}
              <Link to="/" className="font-medium text-primary hover:underline">Overview</Link>
              .
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr style={{ backgroundColor: BRAND }}>
                  <th className="px-4 py-3 text-left text-xs font-bold uppercase text-white">Assets Name</th>
                  <th className="px-4 py-3 text-center text-xs font-bold uppercase text-white">PQC Support</th>
                </tr>
              </thead>
              <tbody>
                {assetPqcData.map((asset: any, i: number) => (
                  <tr key={i} onClick={() => setSelectedAsset(asset)}
                    className="border-b border-border/40 cursor-pointer hover:bg-secondary/40 transition-colors"
                    style={{ backgroundColor: selectedAsset?.asset_name === asset.asset_name ? `${BRAND}22` : i % 2 === 0 ? "rgba(37,99,235,0.06)" : "transparent" }}>
                    <td className="px-4 py-3 font-mono text-xs text-foreground">{asset.asset_name}</td>
                    <td className="px-4 py-3 text-center">
                      {asset.pqc_supported
                        ? <CheckCircle size={18} color={GREEN} className="inline" />
                        : <XCircle    size={18} color={RED}   className="inline" />}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Detail panel */}
        <div className="lg:col-span-2 rounded-xl border border-border bg-card overflow-hidden">
          {selectedAsset ? (
            <motion.div key={selectedAsset.asset_name} initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} className="h-full">
              <div className="px-5 py-4 border-b border-border" style={{ backgroundColor: `${NAVY}cc` }}>
                <h3 className="text-sm font-bold text-white">App Details</h3>
                <p className="text-[10px] text-blue-300 mt-0.5 font-mono truncate">{selectedAsset.asset_name}</p>
              </div>
              <div className="p-5 space-y-3">
                {[
                  { label: "TLS Version", value: selectedAsset.tls_version  || "—" },
                  { label: "Risk",        value: selectedAsset.risk          || "—" },
                  { label: "Status",      value: selectedAsset.status        || "—" },
                ].map((row) => (
                  <div key={row.label} className="flex justify-between items-center py-2 border-b border-border/40">
                    <span className="text-xs text-muted-foreground font-medium">{row.label}</span>
                    <span className="text-xs text-foreground font-semibold">{row.value}</span>
                  </div>
                ))}
                {selectedAsset.score !== undefined && (
                  <div className="flex justify-between items-center py-2 border-b border-border/40">
                    <span className="text-xs text-muted-foreground font-medium">Posture indicator</span>
                    <span className="text-sm font-bold" style={{ color: scoreTier(selectedAsset.score).color }}>
                      {selectedAsset.score}<span className="text-[10px] text-muted-foreground font-normal"> / 1000</span>
                    </span>
                  </div>
                )}
                <p className="text-[10px] text-muted-foreground">
                  This per-asset indicator is derived from TLS posture buckets (critical/standard/modern/PQ signal). Cyber Rating uses a separate
                  enterprise composite score, so values may differ.
                </p>
                <div className="mt-2 rounded-lg p-3 flex items-center gap-3"
                  style={{ backgroundColor: selectedAsset.pqc_supported ? `${GREEN}12` : `${RED}12`, border: `1px solid ${selectedAsset.pqc_supported ? GREEN : RED}30` }}>
                  {selectedAsset.pqc_supported ? <CheckCircle size={20} color={GREEN} /> : <XCircle size={20} color={RED} />}
                  <span className="text-xs font-semibold" style={{ color: selectedAsset.pqc_supported ? GREEN : RED }}>
                    {selectedAsset.pqc_supported ? "PQC Supported — Asset is quantum-ready" : "PQC Not Supported — Remediation required"}
                  </span>
                </div>
              </div>
            </motion.div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center p-8 text-center gap-3 min-h-[200px]">
              <div className="w-12 h-12 rounded-full bg-secondary flex items-center justify-center">
                <CheckCircle size={22} color={BRAND} />
              </div>
              <p className="text-sm text-muted-foreground">Click an asset row to view its details</p>
            </div>
          )}
        </div>
      </div>

      {/* Recommendations + NIST Banner */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4 flex items-center gap-2">
            <AlertTriangle size={15} color={BRAND} /> Improvement Recommendations
          </h3>
          {recommendations.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No recommendations yet — run a scan from{" "}
              <Link to="/" className="font-medium text-primary hover:underline">Overview</Link>
              .
            </p>
          ) : (
            <div className="space-y-2">
              {recommendations.map((rec: string, i: number) => (
                <div key={i} className="flex items-start gap-3 p-3 rounded-lg" style={{ backgroundColor: "rgba(251,188,9,0.06)", border: "1px solid rgba(251,188,9,0.15)" }}>
                  <span style={{ color: BRAND }} className="text-base mt-0.5 flex-shrink-0">{i === 0 ? "⚠" : "→"}</span>
                  <span className="text-sm text-foreground">{rec}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="rounded-xl p-5 flex flex-col justify-between" style={{ backgroundColor: NAVY, border: `1px solid ${BRAND}33` }}>
          <div>
            <h3 className="text-sm font-semibold text-white uppercase tracking-wide mb-3">NIST PQC Standards Reference</h3>
            <div className="space-y-2">
              {[
                { id: "FIPS 203", name: "ML-KEM / Kyber",     desc: "Key Encapsulation Mechanism" },
                { id: "FIPS 204", name: "ML-DSA / Dilithium", desc: "Digital Signature Algorithm" },
                { id: "FIPS 205", name: "SLH-DSA / SPHINCS+", desc: "Stateless Hash-Based Signature" },
              ].map((std) => (
                <div key={std.id} className="flex items-start gap-3 p-2.5 rounded-lg" style={{ backgroundColor: "rgba(255,255,255,0.05)" }}>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded flex-shrink-0 mt-0.5" style={{ backgroundColor: BRAND, color: "#f8fafc" }}>{std.id}</span>
                  <div>
                    <p className="text-xs font-semibold text-white">{std.name}</p>
                    <p className="text-[10px] text-blue-300">{std.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <a href="https://csrc.nist.gov/projects/post-quantum-cryptography" target="_blank" rel="noopener noreferrer" className="mt-4 text-xs font-medium hover:underline" style={{ color: BRAND }}>
            View NIST Standards →
          </a>
        </div>
      </div>
    </div>
  );
}
