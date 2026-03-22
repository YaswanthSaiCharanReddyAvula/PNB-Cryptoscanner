import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { DataTable } from "@/components/dashboard/DataTable";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Search, Lock, Loader2 } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { cyberRatingService } from "@/services/api";
import { toast } from "sonner";
import { useScan } from "@/hooks/useScan";
import { ScanProgressBar } from "@/components/dashboard/ScanProgressBar";

const getScoreColor = (score: number) => {
  if (score >= 80) return "text-success";
  if (score >= 60) return "text-warning";
  return "text-accent";
};

const statusBadge = (severity: string) => {
  if (!severity) return null;
  const c: Record<string, string> = {
    Critical: "bg-accent/15 text-accent border-accent/20",
    High: "bg-warning/15 text-warning border-warning/20",
    Medium: "bg-info/15 text-info border-info/20",
    Low: "bg-success/15 text-success border-success/20",
  };
  return <Badge variant="outline" className={`text-[10px] ${c[severity] || ""}`}>{severity}</Badge>;
};

export default function CyberRating() {
  const [domain, setDomain] = useState("");
  const [scannedDomain, setScannedDomain] = useState("");

  const [overallScore, setOverallScore] = useState(0);
  const [grade, setGrade] = useState("Unknown");
  const [riskFactors, setRiskFactors] = useState<any[]>([]);
  
  const { user } = useAuth();
  const isEmployee = user?.role === "Employee";

  const { isScanning, stageIndex, results, error, startScan } = useScan();

  const fetchScore = async (v1FallbackPayload: any = null) => {
    try {
      const res = await cyberRatingService.getRating();
      const data = res.data;
      setOverallScore(data.score || 0);
      setGrade(data.grade || "Unknown");
      setRiskFactors(data.risk_factors || []);
    } catch {
      // Handle gracefully if backend has no persisted data initially
    }

    if (overallScore === 0 || grade === "Unknown") {
      if (v1FallbackPayload) {
        applyV1Fallback(v1FallbackPayload);
      }
    }
  };

  const applyV1Fallback = (v1: any) => {
    const tls = Array.isArray(v1.tls_results) ? v1.tls_results : [];
    const hasLegacyProto = tls.some((t: any) =>
      String(t?.tls_version || "").toLowerCase().includes("1.0") ||
      String(t?.tls_version || "").toLowerCase().includes("1.1") ||
      String(t?.tls_version || "").toLowerCase().includes("ssl")
    );
    const qScore = v1?.quantum_score?.score;
    const base = typeof qScore === "number" ? qScore : 50;
    const computed = Math.max(0, Math.min(100, Math.round(base - (hasLegacyProto ? 20 : 0))));

    setOverallScore(computed);
    setGrade(computed >= 80 ? "Elite-PQC" : computed >= 60 ? "Standard" : "Legacy");
    setRiskFactors([
      ...(hasLegacyProto ? [{ factor: "Legacy protocols enabled", severity: "High", detail: "TLS 1.0/1.1 or SSL detected in scan results" }] : []),
      ...(Array.isArray(v1.recommendations) && v1.recommendations.length
        ? [{ factor: "PQC migration recommendations", severity: "Medium", detail: "Recommendations generated from cryptographic inventory" }]
        : []),
    ]);
  };

  useEffect(() => {
    fetchScore();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (results && results.status === "completed" && !isScanning) {
      toast.success(`Analysis completed for ${scannedDomain}!`);
      fetchScore(results);
    } else if (error) {
      toast.error(error);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [results, isScanning, error]);

  const handleScan = async () => {
    if (domain.trim() && !isScanning) {
      const targetDomain = domain.trim();
      setScannedDomain(targetDomain);
      await startScan(targetDomain);
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
              disabled={isScanning}
            />
          </div>
          <Button onClick={handleScan} disabled={isEmployee || !domain || isScanning} className="bg-primary text-primary-foreground hover:bg-primary/90 px-6">
            {isEmployee ? <Lock className="mr-2 h-4 w-4" /> : isScanning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null} 
            Analyze
          </Button>
        </div>
        {!isScanning && scannedDomain && stageIndex >= 5 && (
          <p className="text-xs text-muted-foreground mt-2">
            Showing results for: <span className="text-primary font-medium">{scannedDomain}</span>
          </p>
        )}
      </div>

      <ScanProgressBar isScanning={isScanning} stageIndex={stageIndex} targetDomain={scannedDomain} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Score */}
        <div className="rounded-xl border border-border bg-card p-8 flex flex-col items-center justify-center lg:col-span-2">
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
                style={{ transition: "stroke-dasharray 1s ease-out, stroke 1s ease" }}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className={`text-5xl font-bold ${getScoreColor(overallScore)} transition-colors duration-1000`}>{overallScore}</span>
              <span className="text-sm text-muted-foreground">out of 100</span>
              <span className={`text-xs font-semibold mt-1 ${getScoreColor(overallScore)} transition-colors duration-1000`}>
                {grade}
              </span>
            </div>
          </div>
          <p className="text-sm text-muted-foreground mt-4 text-center max-w-xs">
            Your organization's security grade is <strong className="text-foreground">{grade}</strong>. Review the risk factors below to improve your score.
          </p>
        </div>
      </div>

      {/* Risk Factors */}
      <DataTable
        title="Risk Factors"
        data={riskFactors}
        columns={[
          { key: "factor", header: "Factor" },
          { key: "severity", header: "Severity", render: (r) => statusBadge(r.severity as string) },
          { key: "detail", header: "Detail" },
        ]}
      />
    </div>
  );
}
