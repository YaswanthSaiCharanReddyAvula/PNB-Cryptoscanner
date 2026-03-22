import { useState } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, CheckCircle, XCircle } from "lucide-react";
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
} from "recharts";

// ── Theme ────────────────────────────────────────────────────────────────────
const GOLD  = "#FBBC09";
const RED   = "#A20E37";
const GREEN = "#22c55e";
const NAVY  = "#0d1b2a";

// ── Static mock data ──────────────────────────────────────────────────────────

const CLASSIFICATION_DATA = [
  { name: "Elite",    count: 37, color: GREEN },
  { name: "Critical", count: 2,  color: RED   },
  { name: "Std",      count: 4,  color: "#7c3aed" },
];

const PIE_DATA = [
  { name: "Elite-PQC Ready", value: 45, color: GREEN },
  { name: "Standard",        value: 30, color: GOLD  },
  { name: "Legacy",          value: 15, color: "#f97316" },
  { name: "Critical",        value: 10, color: RED   },
];

// 3×3 heat-map cells: 0=safe 1=medium 2=high
const HEATMAP = [
  [2, 2, 1],
  [2, 1, 0],
  [1, 0, 0],
];
const HEAT_COLOR = ["#22c55e", "#f97316", "#A20E37"];
const HEAT_LABEL = ["Safe or No Risk", "Medium Risk", "High Risk"];

const ASSET_PQC_DATA = [
  { name: "Digigrihavatika.pnbuat.bank.in (103.109.225.128)", pqc: true,  tls: "TLS 1.3", score: 820, owner: "Team 2", exposure: "Internet" },
  { name: "wcw.pnb.bank.in (103.109.225.201)",                pqc: true,  tls: "TLS 1.2", score: 620, owner: "Team 3", exposure: "Internet" },
  { name: "Wbbgb.pnbuk.bank.in (103.109.224.249)",            pqc: false, tls: "RSA / ECC", score: 480, owner: "Team 1", exposure: "Internet" },
  { name: "corpbanking.pnbindia.in (103.109.225.10)",         pqc: true,  tls: "TLS 1.3", score: 760, owner: "Team 4", exposure: "Intranet" },
  { name: "mobileapi.pnb.bank.in (103.109.224.80)",           pqc: false, tls: "TLS 1.1", score: 320, owner: "Team 1", exposure: "Internet" },
  { name: "vpn.pnbindia.in (203.94.232.18)",                  pqc: false, tls: "RSA / ECC", score: 440, owner: "Team 5", exposure: "Intranet" },
];

const RECOMMENDATIONS = [
  "Upgrade to TLS 1.3 with PQC",
  "Implement Kyber for Key Exchange",
  "Update Cryptographic Libraries",
  "Develop PQC Migration Plan",
];

const tooltipStyle = {
  contentStyle: {
    background: "hsl(220, 18%, 13%)",
    border: "1px solid hsl(220, 14%, 20%)",
    borderRadius: "8px",
    fontSize: "12px",
    color: "hsl(210, 20%, 92%)",
  },
};

function scoreTier(s: number) {
  if (s > 700) return { label: "Elite-PQC", color: GREEN };
  if (s >= 400) return { label: "Standard",  color: GOLD };
  return              { label: "Legacy",     color: RED  };
}

// ── Custom bar label ──────────────────────────────────────────────────────────
const BarLabel = (props: any) => {
  const { x, y, width, value } = props;
  return (
    <text x={x + width / 2} y={y - 6} textAnchor="middle" fill="white" fontSize={12} fontWeight={700}>
      {value}
    </text>
  );
};

// ── Main Component ─────────────────────────────────────────────────────────────
export default function PQCPosture() {
  const [selectedAsset, setSelectedAsset] = useState<typeof ASSET_PQC_DATA[0] | null>(null);

  return (
    <div className="space-y-5">

      {/* ── 1. Top Header Bar ───────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        className="rounded-xl overflow-hidden"
        style={{ backgroundColor: NAVY, border: `1px solid ${GOLD}22` }}
      >
        <div className="px-6 py-3 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <h1 className="text-lg font-bold text-white tracking-wide">PQC Compliance Dashboard</h1>
            <p className="text-xs text-blue-300 mt-0.5">Post-Quantum Cryptography Readiness Assessment — PNB</p>
          </div>

          {/* Stats pills */}
          <div className="flex flex-wrap items-center gap-0 text-xs divide-x divide-white/10 rounded-lg overflow-hidden border border-white/10">
            {[
              { label: "Elite-PQC Ready", value: "45%", color: GREEN },
              { label: "Standard",        value: "30%", color: GOLD  },
              { label: "Legacy",          value: "15%", color: "#f97316" },
              { label: "Critical Apps",   value: "8",   color: RED   },
            ].map((s) => (
              <div key={s.label} className="px-4 py-2 flex flex-col items-center gap-0.5" style={{ backgroundColor: `${s.color}14` }}>
                <span className="font-bold text-sm" style={{ color: s.color }}>{s.value}</span>
                <span className="text-white/60 text-[10px]">{s.label}</span>
              </div>
            ))}
          </div>
        </div>
      </motion.div>

      {/* ── 2. Three Column Layout ──────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

        {/* LEFT — Bar Chart */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">
            Assets by Classification Grade
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={CLASSIFICATION_DATA} margin={{ top: 20, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(220, 14%, 20%)" />
              <XAxis dataKey="name" tick={{ fill: "hsl(215, 15%, 60%)", fontSize: 12 }} />
              <YAxis tick={{ fill: "hsl(215, 15%, 60%)", fontSize: 11 }} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="count" radius={[6, 6, 0, 0]} label={<BarLabel />}>
                {CLASSIFICATION_DATA.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* CENTER — Pie Chart */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">
            Application Status
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={PIE_DATA}
                cx="40%"
                cy="50%"
                innerRadius={50}
                outerRadius={85}
                dataKey="value"
                strokeWidth={2}
                stroke="hsl(220, 22%, 10%)"
              >
                {PIE_DATA.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                {...tooltipStyle}
                formatter={(v: number) => [`${v}%`, ""]}
              />
              <Legend
                layout="vertical"
                align="right"
                verticalAlign="middle"
                iconType="circle"
                iconSize={9}
                formatter={(value) => (
                  <span style={{ color: "hsl(215, 15%, 70%)", fontSize: 11 }}>{value}</span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* RIGHT — Heat Map */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">
            Risk Overview
          </h3>
          <div className="flex flex-col items-center gap-3 mt-2">
            <div className="grid grid-cols-3 gap-2">
              {HEATMAP.map((row, ri) =>
                row.map((level, ci) => (
                  <div
                    key={`${ri}-${ci}`}
                    className="w-16 h-16 rounded-lg flex items-center justify-center text-white text-xs font-bold shadow-md"
                    style={{
                      backgroundColor: HEAT_COLOR[level],
                      opacity: 0.85 + level * 0.1,
                    }}
                    title={HEAT_LABEL[level]}
                  >
                    {level === 2 ? "H" : level === 1 ? "M" : "✓"}
                  </div>
                ))
              )}
            </div>
            {/* Legend */}
            <div className="flex gap-4 mt-2 flex-wrap justify-center">
              {HEAT_LABEL.map((label, i) => (
                <div key={label} className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <div className="w-3 h-3 rounded" style={{ backgroundColor: HEAT_COLOR[i] }} />
                  {label}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── 3. Asset PQC Support Table + Detail Panel ───────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
        {/* Table */}
        <div className="lg:col-span-3 rounded-xl border border-border bg-card overflow-hidden">
          <div className="px-5 py-4 border-b border-border flex items-center justify-between">
            <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide">Asset PQC Support</h3>
            <span className="text-xs text-muted-foreground">{ASSET_PQC_DATA.filter(a => !a.pqc).length} assets need attention</span>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr style={{ backgroundColor: GOLD }}>
                <th className="px-4 py-3 text-left text-xs font-bold uppercase" style={{ color: "#111" }}>Assets Name</th>
                <th className="px-4 py-3 text-center text-xs font-bold uppercase" style={{ color: "#111" }}>PQC Support</th>
              </tr>
            </thead>
            <tbody>
              {ASSET_PQC_DATA.map((asset, i) => (
                <tr
                  key={i}
                  onClick={() => setSelectedAsset(asset)}
                  className="border-b border-border/40 cursor-pointer hover:bg-secondary/40 transition-colors"
                  style={{
                    backgroundColor:
                      selectedAsset?.name === asset.name
                        ? `${GOLD}15`
                        : i % 2 === 0
                        ? "rgba(162,14,55,0.04)"
                        : "transparent",
                  }}
                >
                  <td className="px-4 py-3 font-mono text-xs text-foreground">{asset.name}</td>
                  <td className="px-4 py-3 text-center">
                    {asset.pqc ? (
                      <CheckCircle size={18} color={GREEN} className="inline" />
                    ) : (
                      <XCircle size={18} color={RED} className="inline" />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Detail Panel */}
        <div className="lg:col-span-2 rounded-xl border border-border bg-card overflow-hidden">
          {selectedAsset ? (
            <motion.div
              key={selectedAsset.name}
              initial={{ opacity: 0, x: 12 }}
              animate={{ opacity: 1, x: 0 }}
              className="h-full"
            >
              <div
                className="px-5 py-4 border-b border-border"
                style={{ backgroundColor: `${NAVY}cc` }}
              >
                <h3 className="text-sm font-bold text-white">App Details</h3>
                <p className="text-[10px] text-blue-300 mt-0.5 font-mono truncate">{selectedAsset.name}</p>
              </div>
              <div className="p-5 space-y-3">
                {[
                  { label: "Owner",    value: selectedAsset.owner },
                  { label: "Exposure", value: selectedAsset.exposure },
                  { label: "TLS",      value: selectedAsset.tls },
                ].map((row) => (
                  <div key={row.label} className="flex justify-between items-center py-2 border-b border-border/40">
                    <span className="text-xs text-muted-foreground font-medium">{row.label}</span>
                    <span className="text-xs text-foreground font-semibold">{row.value}</span>
                  </div>
                ))}

                {/* Score */}
                <div className="flex justify-between items-center py-2 border-b border-border/40">
                  <span className="text-xs text-muted-foreground font-medium">Score</span>
                  <span
                    className="text-sm font-bold"
                    style={{ color: scoreTier(selectedAsset.score).color }}
                  >
                    {selectedAsset.score}
                    <span className="text-[10px] text-muted-foreground font-normal"> / 1000</span>
                  </span>
                </div>

                {/* Status */}
                <div className="flex justify-between items-center py-2">
                  <span className="text-xs text-muted-foreground font-medium">Status</span>
                  <span
                    className="text-[11px] px-2.5 py-1 rounded-full font-semibold"
                    style={{
                      color: scoreTier(selectedAsset.score).color,
                      backgroundColor: `${scoreTier(selectedAsset.score).color}18`,
                      border: `1px solid ${scoreTier(selectedAsset.score).color}40`,
                    }}
                  >
                    {scoreTier(selectedAsset.score).label}
                  </span>
                </div>

                {/* PQC indicator */}
                <div
                  className="mt-2 rounded-lg p-3 flex items-center gap-3"
                  style={{
                    backgroundColor: selectedAsset.pqc ? `${GREEN}12` : `${RED}12`,
                    border: `1px solid ${selectedAsset.pqc ? GREEN : RED}30`,
                  }}
                >
                  {selectedAsset.pqc ? (
                    <CheckCircle size={20} color={GREEN} />
                  ) : (
                    <XCircle size={20} color={RED} />
                  )}
                  <span
                    className="text-xs font-semibold"
                    style={{ color: selectedAsset.pqc ? GREEN : RED }}
                  >
                    {selectedAsset.pqc
                      ? "PQC Supported — Asset is quantum-ready"
                      : "PQC Not Supported — Remediation required"}
                  </span>
                </div>
              </div>
            </motion.div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center p-8 text-center gap-3 min-h-[200px]">
              <div className="w-12 h-12 rounded-full bg-secondary flex items-center justify-center">
                <CheckCircle size={22} color={GOLD} />
              </div>
              <p className="text-sm text-muted-foreground">
                Click an asset row to view its details
              </p>
            </div>
          )}
        </div>
      </div>

      {/* ── 4 & 5. Bottom Row: Recommendations + NIST Banner ────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Improvement Recommendations */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4 flex items-center gap-2">
            <AlertTriangle size={15} color={GOLD} />
            Improvement Recommendations
          </h3>
          <div className="space-y-2">
            {RECOMMENDATIONS.map((rec, i) => (
              <div
                key={i}
                className="flex items-start gap-3 p-3 rounded-lg"
                style={{
                  backgroundColor: "rgba(251,188,9,0.06)",
                  border: "1px solid rgba(251,188,9,0.15)",
                }}
              >
                <span style={{ color: GOLD }} className="text-base mt-0.5 flex-shrink-0">
                  {i === 0 ? "⚠" : "→"}
                </span>
                <span className="text-sm text-foreground">{rec}</span>
              </div>
            ))}
          </div>
        </div>

        {/* NIST Standards info */}
        <div
          className="rounded-xl p-5 flex flex-col justify-between"
          style={{ backgroundColor: NAVY, border: `1px solid ${GOLD}20` }}
        >
          <div>
            <h3 className="text-sm font-semibold text-white uppercase tracking-wide mb-3">
              NIST PQC Standards Reference
            </h3>
            <div className="space-y-2">
              {[
                { id: "FIPS 203", name: "ML-KEM / Kyber",      desc: "Key Encapsulation Mechanism" },
                { id: "FIPS 204", name: "ML-DSA / Dilithium",  desc: "Digital Signature Algorithm" },
                { id: "FIPS 205", name: "SLH-DSA / SPHINCS+",  desc: "Stateless Hash-Based Signature" },
              ].map((std) => (
                <div
                  key={std.id}
                  className="flex items-start gap-3 p-2.5 rounded-lg"
                  style={{ backgroundColor: "rgba(255,255,255,0.05)" }}
                >
                  <span
                    className="text-[10px] font-bold px-2 py-0.5 rounded flex-shrink-0 mt-0.5"
                    style={{ backgroundColor: GOLD, color: "#111" }}
                  >
                    {std.id}
                  </span>
                  <div>
                    <p className="text-xs font-semibold text-white">{std.name}</p>
                    <p className="text-[10px] text-blue-300">{std.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <a
            href="https://csrc.nist.gov/projects/post-quantum-cryptography"
            target="_blank"
            rel="noopener noreferrer"
            className="mt-4 text-xs font-medium hover:underline"
            style={{ color: GOLD }}
          >
            View NIST Standards →
          </a>
        </div>
      </div>

    </div>
  );
}
