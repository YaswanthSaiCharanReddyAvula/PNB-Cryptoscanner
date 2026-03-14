import { useState } from "react";
import { motion } from "framer-motion";
import { DataTable } from "@/components/dashboard/DataTable";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Search } from "lucide-react";
import {
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  ResponsiveContainer, Tooltip,
} from "recharts";

const overallScore = 73;

const radarData = [
  { subject: "Network", score: 82 },
  { subject: "Application", score: 68 },
  { subject: "Endpoint", score: 75 },
  { subject: "Cloud", score: 70 },
  { subject: "Data", score: 85 },
  { subject: "Identity", score: 60 },
];

const riskFactors = [
  { factor: "SSL/TLS Configuration", score: 85, impact: "High", status: "Good" },
  { factor: "Encryption Standards", score: 70, impact: "Critical", status: "Fair" },
  { factor: "Patch Management", score: 65, impact: "High", status: "Fair" },
  { factor: "Access Controls", score: 55, impact: "Critical", status: "Poor" },
  { factor: "Network Segmentation", score: 80, impact: "Medium", status: "Good" },
  { factor: "Incident Response", score: 72, impact: "High", status: "Fair" },
  { factor: "Data Protection", score: 88, impact: "Critical", status: "Good" },
  { factor: "Vulnerability Management", score: 60, impact: "High", status: "Fair" },
];

const getScoreColor = (score: number) => {
  if (score >= 80) return "text-success";
  if (score >= 60) return "text-warning";
  return "text-accent";
};

const getScoreLabel = (score: number) => {
  if (score >= 80) return "Good";
  if (score >= 60) return "Fair";
  return "Poor";
};

const statusBadge = (status: string) => {
  const c: Record<string, string> = {
    Good: "bg-success/15 text-success border-success/20",
    Fair: "bg-warning/15 text-warning border-warning/20",
    Poor: "bg-accent/15 text-accent border-accent/20",
  };
  return <Badge variant="outline" className={`text-[10px] ${c[status] || ""}`}>{status}</Badge>;
};

const tooltipStyle = {
  contentStyle: { background: "hsl(220, 18%, 13%)", border: "1px solid hsl(220, 14%, 20%)", borderRadius: "8px", fontSize: "12px", color: "hsl(210, 20%, 92%)" },
};

export default function CyberRating() {
  const [domain, setDomain] = useState("");
  const [scannedDomain, setScannedDomain] = useState("");

  const handleScan = () => {
    if (domain.trim()) {
      setScannedDomain(domain.trim());
    }
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <h1 className="text-2xl font-bold text-foreground">Cyber Rating</h1>
        <p className="text-sm text-muted-foreground">Overall security posture assessment</p>
      </motion.div>

      {/* Domain Input */}
      <div className="rounded-xl border border-border bg-card p-5">
        <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-3">Scan Domain</h3>
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Enter domain (e.g., securebank.com)"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              className="pl-10 bg-secondary border-border"
            />
          </div>
          <Button onClick={handleScan} className="bg-primary text-primary-foreground hover:bg-primary/90 px-6">
            Analyze
          </Button>
        </div>
        {scannedDomain && (
          <p className="text-xs text-muted-foreground mt-2">
            Showing results for: <span className="text-primary font-medium">{scannedDomain}</span>
          </p>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Score */}
        <div className="rounded-xl border border-border bg-card p-8 flex flex-col items-center justify-center">
          <div className="relative">
            <svg viewBox="0 0 200 200" className="w-56 h-56">
              <circle cx="100" cy="100" r="85" fill="none" stroke="hsl(220, 14%, 20%)" strokeWidth="14" />
              <circle
                cx="100" cy="100" r="85" fill="none"
                stroke={overallScore >= 80 ? "hsl(152, 60%, 45%)" : overallScore >= 60 ? "hsl(45, 96%, 51%)" : "hsl(342, 88%, 35%)"}
                strokeWidth="14"
                strokeDasharray={`${overallScore * 5.34} 534`}
                strokeLinecap="round"
                transform="rotate(-90 100 100)"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className={`text-5xl font-bold ${getScoreColor(overallScore)}`}>{overallScore}</span>
              <span className="text-sm text-muted-foreground">out of 100</span>
              <span className={`text-xs font-semibold mt-1 ${getScoreColor(overallScore)}`}>
                {getScoreLabel(overallScore)}
              </span>
            </div>
          </div>
          <p className="text-sm text-muted-foreground mt-4 text-center max-w-xs">
            Your organization's security posture is <strong className="text-foreground">fair</strong>. Focus on improving access controls and vulnerability management.
          </p>
        </div>

        {/* Radar */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">Risk Breakdown</h3>
          <ResponsiveContainer width="100%" height={320}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="hsl(220, 14%, 20%)" />
              <PolarAngleAxis dataKey="subject" tick={{ fill: "hsl(215, 15%, 55%)", fontSize: 11 }} />
              <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: "hsl(215, 15%, 55%)", fontSize: 9 }} />
              <Radar name="Score" dataKey="score" stroke="hsl(45, 96%, 51%)" fill="hsl(45, 96%, 51%)" fillOpacity={0.2} strokeWidth={2} />
              <Tooltip {...tooltipStyle} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Risk Factors */}
      <DataTable
        title="Risk Factors"
        data={riskFactors}
        columns={[
          { key: "factor", header: "Factor" },
          { key: "score", header: "Score", render: (r) => <span className={`font-bold ${getScoreColor(r.score as number)}`}>{r.score as number}/100</span> },
          { key: "impact", header: "Impact", render: (r) => {
            const c: Record<string, string> = { Critical: "text-accent", High: "text-warning", Medium: "text-info" };
            return <span className={`text-xs font-medium ${c[r.impact as string] || ""}`}>{r.impact as string}</span>;
          }},
          { key: "status", header: "Status", render: (r) => statusBadge(r.status as string) },
        ]}
      />
    </div>
  );
}
