import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { StatCard } from "@/components/dashboard/StatCard";
import { DataTable } from "@/components/dashboard/DataTable";
import { Badge } from "@/components/ui/badge";
import { ShieldAlert, AlertTriangle, TrendingUp, CheckCircle } from "lucide-react";
import { pqcService } from "@/services/api";
import { PQCBadge, determinePQCStatus, PQCStatus } from "@/components/ui/PQCBadge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Info } from "lucide-react";
import { PQCCertificateModal } from "@/components/dashboard/PQCCertificateModal";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";

const riskBadge = (risk: string) => {
  if (!risk) return null;
  const colors: Record<string, string> = {
    Critical: "bg-accent/20 text-accent border-accent/30",
    High: "bg-accent/15 text-accent border-accent/20",
    Medium: "bg-warning/15 text-warning border-warning/20",
    Low: "bg-success/15 text-success border-success/20",
  };
  return <Badge variant="outline" className={`text-[10px] ${colors[risk] || ""}`}>{risk}</Badge>;
};

export default function PQCPosture() {
  const [migrationScore, setMigrationScore] = useState(0);
  const [pqcReady, setPqcReady] = useState(0);
  const [vulnerableAlgorithms, setVulnerableAlgorithms] = useState<any[]>([]);
  const [overallStatus, setOverallStatus] = useState<PQCStatus>("unknown");

  useEffect(() => {
    pqcService.getPosture()
      .then(res => {
        const data = res.data;
        setMigrationScore(Math.round(data.migration_score || 0));
        setPqcReady(data.pqc_ready_assets || 0);
        
        if (data.vulnerable_algorithms) {
          setVulnerableAlgorithms(data.vulnerable_algorithms.map((v: any) => ({
            algorithm: v.name,
            occurrences: v.count,
            risk: v.risk || "Medium",
            pqcStatus: determinePQCStatus("", v.name, ""),
          })));
        }

        const score = Math.round(data.migration_score || 0);
        if (score === 100) setOverallStatus("quantum-safe");
        else if (score >= 70) setOverallStatus("pqc-ready");
        else if (score >= 40) setOverallStatus("vulnerable");
        else setOverallStatus("hndl-risk");

      })
      .catch(err => console.error("Could not fetch PQC posture", err));
  }, []);

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <Alert className="bg-primary/5 border-primary/20 mb-2">
          <Info className="h-4 w-4 text-primary" />
          <AlertTitle className="text-primary font-semibold">NIST PQC Standards</AlertTitle>
          <AlertDescription className="text-muted-foreground text-xs mt-1 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <span>
              This assessment evaluates compliance with NIST Post-Quantum Cryptography Standards: 
              <strong className="text-foreground mx-1">FIPS 203</strong> (ML-KEM/Kyber),
              <strong className="text-foreground mx-1">FIPS 204</strong> (ML-DSA/Dilithium),
              <strong className="text-foreground mx-1">FIPS 205</strong> (SLH-DSA/SPHINCS+).
            </span>
            <a href="https://csrc.nist.gov/projects/post-quantum-cryptography" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline whitespace-nowrap font-medium">
              View NIST Standards &rarr;
            </a>
          </AlertDescription>
        </Alert>
      </motion.div>

      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Post-Quantum Cryptography Posture</h1>
          <p className="text-sm text-muted-foreground">Quantum readiness assessment and migration tracking</p>
        </div>
        <div className="flex items-center gap-3">
          <PQCCertificateModal />
          <PQCBadge status={overallStatus} className="px-4 py-2 text-sm" />
        </div>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
        <Accordion type="single" collapsible className="w-full bg-[#A20E37]/10 border border-[#A20E37]/30 rounded-lg px-4 shadow-sm">
          <AccordionItem value="hndl-info" className="border-b-0">
            <AccordionTrigger className="text-[#A20E37] hover:no-underline font-semibold py-4">
              <div className="flex items-center gap-2 text-left">
                <AlertTriangle className="h-5 w-5 shrink-0" />
                <span>Harvest Now, Decrypt Later (HNDL) Threat Advisory</span>
                <Badge variant="outline" className="ml-2 bg-[#A20E37]/20 text-[#A20E37] border-[#A20E37]/30 hidden sm:flex">
                  {vulnerableAlgorithms.reduce((acc, v) => acc + v.occurrences, 0)} Vulnerabilities Detected
                </Badge>
              </div>
            </AccordionTrigger>
            <AccordionContent className="text-foreground/90 space-y-4 pb-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-3">
                  <p className="leading-relaxed text-sm">
                    <strong>What is HNDL?</strong> In a "Harvest Now, Decrypt Later" attack, adversaries passively store your encrypted network traffic today. While they cannot break the encryption now, they intend to decrypt it once powerful quantum computers become available. Any asset using legacy asymmetric cryptography for key exchange (like RSA, ECDH, or ECDSA) is currently at risk.
                  </p>
                  <p className="leading-relaxed text-sm">
                    <strong>The Threat Timeline:</strong> Cryptanalytically Relevant Quantum Computers (CRQCs) capable of breaking current encryption are estimated to be feasible between <strong>2030 and 2035</strong>. Highly sensitive data with long-term retention requirements must be protected immediately.
                  </p>
                </div>
                <div className="p-4 rounded-xl bg-secondary/50 border border-border flex flex-col justify-center">
                  <h4 className="font-semibold text-[#A20E37] mb-2 flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4" /> Immediate Action Required
                  </h4>
                  <p className="text-sm mb-4">
                    You currently have <strong className="text-foreground">{vulnerableAlgorithms.reduce((acc, v) => acc + v.occurrences, 0)}</strong> detected instances of legacy algorithms. Migrate your key exchange mechanisms from RSA/ECC to NIST-standardized Post-Quantum Cryptography such as <strong>ML-KEM (Kyber)</strong> now to secure data against future decryption.
                  </p>
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </motion.div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Migration Score" value={`${migrationScore}%`} icon={TrendingUp} variant="gold" />
        <StatCard title="Vulnerable Algorithms" value={vulnerableAlgorithms.length.toString()} icon={ShieldAlert} variant="red" />
        <StatCard title="Needs Monitoring" value="0" icon={AlertTriangle} variant="info" />
        <StatCard title="PQC Ready Assets" value={pqcReady.toString()} icon={CheckCircle} variant="success" />
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
      </div>

      {/* Vulnerable Algorithms */}
      <DataTable
        title="Vulnerable Algorithms"
        searchable
        data={vulnerableAlgorithms}
        columns={[
          { key: "algorithm", header: "Algorithm", render: (r) => <span className="font-mono text-primary">{r.algorithm as string}</span> },
          { key: "occurrences", header: "Occurrences Found" },
          { key: "risk", header: "Risk", render: (r) => riskBadge(r.risk as string) },
          { key: "pqcStatus", header: "PQC Status", render: (r) => <PQCBadge status={r.pqcStatus as PQCStatus} /> },
        ]}
      />
    </div>
  );
}
