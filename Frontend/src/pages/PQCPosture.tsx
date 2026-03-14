import { motion } from "framer-motion";
import { StatCard } from "@/components/dashboard/StatCard";
import { DataTable } from "@/components/dashboard/DataTable";
import { Badge } from "@/components/ui/badge";
import { ShieldAlert, AlertTriangle, TrendingUp, CheckCircle } from "lucide-react";
import {
  RadialBarChart, RadialBar, ResponsiveContainer, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
} from "recharts";

const migrationScore = 62;

const riskCategories = [
  { name: "Key Exchange", score: 75, fill: "hsl(152, 60%, 45%)" },
  { name: "Symmetric Enc", score: 88, fill: "hsl(45, 96%, 51%)" },
  { name: "Hash Functions", score: 92, fill: "hsl(210, 80%, 55%)" },
  { name: "Digital Signatures", score: 45, fill: "hsl(342, 88%, 35%)" },
  { name: "Random Number Gen", score: 70, fill: "hsl(280, 60%, 55%)" },
];

const vulnerableAlgorithms = [
  { algorithm: "RSA-2048", category: "Key Exchange", risk: "High", status: "Vulnerable", recommendation: "Migrate to CRYSTALS-Kyber" },
  { algorithm: "ECDSA P-256", category: "Digital Signatures", risk: "High", status: "Vulnerable", recommendation: "Migrate to CRYSTALS-Dilithium" },
  { algorithm: "DH-2048", category: "Key Exchange", risk: "Critical", status: "Vulnerable", recommendation: "Migrate to CRYSTALS-Kyber" },
  { algorithm: "RSA-4096", category: "Digital Signatures", risk: "Medium", status: "Monitor", recommendation: "Plan migration to FALCON" },
  { algorithm: "ECDH P-384", category: "Key Exchange", risk: "Medium", status: "Monitor", recommendation: "Evaluate hybrid approach" },
  { algorithm: "SHA-256", category: "Hash Functions", risk: "Low", status: "Safe", recommendation: "No action needed" },
  { algorithm: "AES-256", category: "Symmetric", risk: "Low", status: "Safe", recommendation: "Quantum resistant" },
];

const complianceData = [
  { name: "Inventory", done: 85 },
  { name: "Risk Assessment", done: 72 },
  { name: "Migration Plan", done: 45 },
  { name: "Testing", done: 30 },
  { name: "Deployment", done: 10 },
];

const riskBadge = (risk: string) => {
  const colors: Record<string, string> = {
    Critical: "bg-accent/20 text-accent border-accent/30",
    High: "bg-accent/15 text-accent border-accent/20",
    Medium: "bg-warning/15 text-warning border-warning/20",
    Low: "bg-success/15 text-success border-success/20",
  };
  return <Badge variant="outline" className={`text-[10px] ${colors[risk] || ""}`}>{risk}</Badge>;
};

const statusBadge = (status: string) => {
  const colors: Record<string, string> = {
    Vulnerable: "bg-accent/20 text-accent border-accent/30",
    Monitor: "bg-warning/15 text-warning border-warning/20",
    Safe: "bg-success/15 text-success border-success/20",
  };
  return <Badge variant="outline" className={`text-[10px] ${colors[status] || ""}`}>{status}</Badge>;
};

const tooltipStyle = {
  contentStyle: { background: "hsl(220, 18%, 13%)", border: "1px solid hsl(220, 14%, 20%)", borderRadius: "8px", fontSize: "12px", color: "hsl(210, 20%, 92%)" },
};

export default function PQCPosture() {
  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <h1 className="text-2xl font-bold text-foreground">Post-Quantum Cryptography Posture</h1>
        <p className="text-sm text-muted-foreground">Quantum readiness assessment and migration tracking</p>
      </motion.div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Migration Score" value={`${migrationScore}%`} icon={TrendingUp} variant="gold" />
        <StatCard title="Vulnerable Algorithms" value="5" icon={ShieldAlert} variant="red" />
        <StatCard title="Needs Monitoring" value="2" icon={AlertTriangle} variant="info" />
        <StatCard title="Quantum Safe" value="2" icon={CheckCircle} variant="success" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Migration Readiness */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">Migration Readiness Score</h3>
          <div className="flex items-center justify-center">
            <div className="relative">
              <svg viewBox="0 0 200 200" className="w-48 h-48">
                <circle cx="100" cy="100" r="85" fill="none" stroke="hsl(220, 14%, 20%)" strokeWidth="12" />
                <circle
                  cx="100" cy="100" r="85" fill="none"
                  stroke="hsl(45, 96%, 51%)"
                  strokeWidth="12"
                  strokeDasharray={`${migrationScore * 5.34} 534`}
                  strokeLinecap="round"
                  transform="rotate(-90 100 100)"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl font-bold text-primary">{migrationScore}%</span>
                <span className="text-xs text-muted-foreground">Ready</span>
              </div>
            </div>
          </div>
        </div>

        {/* Compliance Progress */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">PQC Compliance Progress</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={complianceData}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(220, 14%, 20%)" />
              <XAxis dataKey="name" tick={{ fill: "hsl(215, 15%, 55%)", fontSize: 10 }} />
              <YAxis tick={{ fill: "hsl(215, 15%, 55%)", fontSize: 10 }} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="done" fill="hsl(45, 96%, 51%)" radius={[4, 4, 0, 0]} name="Completion %" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Risk Categories */}
      <div className="rounded-xl border border-border bg-card p-5">
        <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">PQC Risk Categories</h3>
        <div className="grid grid-cols-1 sm:grid-cols-5 gap-4">
          {riskCategories.map((cat) => (
            <div key={cat.name} className="text-center p-4 rounded-lg bg-secondary/50">
              <div className="relative inline-flex items-center justify-center w-16 h-16 mb-2">
                <svg viewBox="0 0 100 100" className="w-16 h-16">
                  <circle cx="50" cy="50" r="42" fill="none" stroke="hsl(220, 14%, 20%)" strokeWidth="6" />
                  <circle cx="50" cy="50" r="42" fill="none" stroke={cat.fill} strokeWidth="6" strokeDasharray={`${cat.score * 2.64} 264`} strokeLinecap="round" transform="rotate(-90 50 50)" />
                </svg>
                <span className="absolute text-sm font-bold text-foreground">{cat.score}</span>
              </div>
              <p className="text-xs text-muted-foreground">{cat.name}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Vulnerable Algorithms */}
      <DataTable
        title="Vulnerable Algorithms"
        searchable
        data={vulnerableAlgorithms}
        columns={[
          { key: "algorithm", header: "Algorithm", render: (r) => <span className="font-mono text-primary">{r.algorithm as string}</span> },
          { key: "category", header: "Category" },
          { key: "risk", header: "Risk", render: (r) => riskBadge(r.risk as string) },
          { key: "status", header: "Status", render: (r) => statusBadge(r.status as string) },
          { key: "recommendation", header: "Recommendation" },
        ]}
      />
    </div>
  );
}
