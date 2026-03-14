import { motion } from "framer-motion";
import { StatCard } from "@/components/dashboard/StatCard";
import { Globe, Search, ShieldCheck, AlertTriangle, ShieldAlert } from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from "recharts";

const stats = [
  { title: "Total Applications", value: "534", icon: Globe, variant: "gold" as const },
  { title: "Sites Surveyed", value: "1,203", icon: Search, variant: "info" as const },
  { title: "Active Certificates", value: "892", icon: ShieldCheck, variant: "success" as const },
  { title: "Weak Cryptography", value: "47", icon: AlertTriangle, variant: "red" as const },
  { title: "Certificate Issues", value: "18", icon: ShieldAlert, variant: "red" as const },
];

const keyLengthData = [
  { name: "1024-bit", count: 12 },
  { name: "2048-bit", count: 456 },
  { name: "3072-bit", count: 89 },
  { name: "4096-bit", count: 234 },
  { name: "EC-256", count: 67 },
  { name: "EC-384", count: 34 },
];

const caData = [
  { name: "DigiCert", value: 340 },
  { name: "Let's Encrypt", value: 280 },
  { name: "Comodo", value: 120 },
  { name: "GlobalSign", value: 90 },
  { name: "Entrust", value: 62 },
];

const protocolData = [
  { name: "TLS 1.3", value: 580 },
  { name: "TLS 1.2", value: 250 },
  { name: "TLS 1.1", value: 42 },
  { name: "TLS 1.0", value: 20 },
];

const COLORS = ["hsl(45, 96%, 51%)", "hsl(342, 88%, 35%)", "hsl(152, 60%, 45%)", "hsl(210, 80%, 55%)", "hsl(280, 60%, 55%)"];

const tooltipStyle = {
  contentStyle: {
    background: "hsl(220, 18%, 13%)",
    border: "1px solid hsl(220, 14%, 20%)",
    borderRadius: "8px",
    fontSize: "12px",
    color: "hsl(210, 20%, 92%)",
  },
};

export default function CBOM() {
  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <h1 className="text-2xl font-bold text-foreground">CBOM</h1>
        <p className="text-sm text-muted-foreground">Cryptographic Bill of Materials</p>
      </motion.div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {stats.map((s, i) => (
          <motion.div key={s.title} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
            <StatCard {...s} />
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {/* Key Length */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">Key Length Distribution</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={keyLengthData}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(220, 14%, 20%)" />
              <XAxis dataKey="name" tick={{ fill: "hsl(215, 15%, 55%)", fontSize: 10 }} />
              <YAxis tick={{ fill: "hsl(215, 15%, 55%)", fontSize: 10 }} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="count" fill="hsl(45, 96%, 51%)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top CAs */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">Top Certificate Authorities</h3>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie data={caData} cx="50%" cy="50%" outerRadius={90} dataKey="value" label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`} labelLine={false}>
                {caData.map((_, i) => (
                  <Cell key={i} fill={COLORS[i]} />
                ))}
              </Pie>
              <Tooltip {...tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Protocols */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">Encryption Protocol Distribution</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={protocolData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(220, 14%, 20%)" />
              <XAxis type="number" tick={{ fill: "hsl(215, 15%, 55%)", fontSize: 10 }} />
              <YAxis type="category" dataKey="name" tick={{ fill: "hsl(215, 15%, 55%)", fontSize: 10 }} width={60} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="value" fill="hsl(342, 88%, 35%)" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
