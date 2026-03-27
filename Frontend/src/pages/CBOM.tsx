import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { StatCard } from "@/components/dashboard/StatCard";
import { DataTable } from "@/components/dashboard/DataTable";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Globe, Search, ShieldCheck, AlertTriangle, ShieldAlert, Download, RefreshCw } from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from "recharts";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { cbomService, cryptoService, pqcService, reportingService } from "@/services/api";
import { PQCBadge, determinePQCStatus, PQCStatus } from "@/components/ui/PQCBadge";
import { CheckCircle } from "lucide-react";

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

// ── Helpers to classify crypto records ──────────────────────────────────────
function mapCryptoToCbomAsset(r: any) {
  const tls    = r.tls_version   || "";
  const cipher = r.cipher_suite  || "";
  const kl     = r.key_length    || 0;

  const isWeak     = ["RC4","DES","3DES","MD5","NULL","EXPORT","TLS 1.0","TLS 1.1"]
                       .some(p => cipher.includes(p) || tls.includes(p));
  const isPQCSafe  = ["Kyber","Dilithium","FALCON","SPHINCS","ML-KEM","ML-DSA"]
                       .some(p => cipher.toLowerCase().includes(p.toLowerCase()));
  const pqcStatus  = isPQCSafe ? "quantum-safe"
                   : isWeak    ? "vulnerable"
                   : tls === "TLS 1.3" ? "pqc-ready" : "vulnerable";
  const hndlRisk   = ["RSA","ECDH","ECDSA","DH"].some(p => cipher.includes(p));

  let rec = "No action needed";
  if (cipher.includes("RSA") || cipher.includes("DH"))
    rec = "Migrate key exchange to CRYSTALS-Kyber";
  else if (tls === "TLS 1.0" || tls === "TLS 1.1")
    rec = "Urgent: Upgrade to TLS 1.3";
  else if (tls === "TLS 1.2")
    rec = "Plan migration to TLS 1.3 + PQC";

  return {
    assetName:           r.asset || "Unknown",
    url:                 r.asset || "",
    assetType:           "Server",
    tlsVersion:          tls,
    keyExchange:         cipher.split("_")[1] || cipher,
    cipherSuite:         cipher,
    ca:                  r.certificate_authority || "Unknown",
    keyLength:           kl && kl !== "None" ? `${kl}`.includes("-bit") ? kl : `${kl}-bit` : "Unknown",
    certExpiry:          "—",
    pqcStatus,
    hndlRisk,
    recommendedMigration: rec,
    // Per-app CBOM fields
    algorithmOid:        "—",
    keyState:            "Active",
    keyCreationDate:     "—",
    sigAlgorithm:        cipher,
    weak:                isWeak,
    application:         r.asset || "Unknown",
  };
}

export default function CBOM() {
  const [summary,       setSummary]       = useState<any>(null);
  const [keyLengthData, setKeyLengthData] = useState<any[]>([]);
  const [caData,        setCaData]        = useState<any[]>([]);
  const [protocolData,  setProtocolData]  = useState<any[]>([]);
  const [pqcStats,      setPqcStats]      = useState({ safe: 0, ready: 0, vuln: 0, hndl: 0 });
  const [pqcFilter,     setPqcFilter]     = useState("All");

  // Live data replacing mock arrays
  const [cbomAssets,  setCbomAssets]  = useState<any[]>([]);
  const [cipherUsage, setCipherUsage] = useState<any[]>([]);
  const [perAppCbom,  setPerAppCbom]  = useState<any[]>([]);
  const [loading,     setLoading]     = useState(true);

  useEffect(() => {
    let cancelled = false;

    cbomService
      .getSummary()
      .then((summaryRes) => {
        if (cancelled) return;
        const summaryData = summaryRes.data;
        setSummary(summaryData);
        const domain = summaryData?.domain as string | undefined;

        return Promise.all([
          cbomService.getCharts(domain),
          pqcService.getPerAppCbom(domain),
          cryptoService.getCryptoSecurityData(),
        ]).then(([chartsRes, perAppRes, cryptoRes]) => {
          if (cancelled) return;
          const displayDomain = domain ?? "";

          const data = chartsRes.data;
          if (data.key_length_distribution) {
            setKeyLengthData(data.key_length_distribution.map((k: any) => ({
              name: `${k.key_length}-bit`,
              count: k.count
            })));
          }
          if (data.top_certificate_authorities) {
            setCaData(data.top_certificate_authorities.map((c: any) => ({
              name: c.certificate_authority,
              value: c.count
            })));
          }
          if (data.encryption_protocols) {
            setProtocolData(data.encryption_protocols.map((p: any) => ({
              name: p.tls_version,
              value: p.count
            })));
          }
          const cu = Array.isArray(data.cipher_usage) ? data.cipher_usage : [];
          setCipherUsage(cu);

          const components = Array.isArray(perAppRes.data) ? perAppRes.data : [];
          const mapped = components.map((c: any) => ({
            application:         displayDomain || "—",
            keyLength:           c.key_size ? `${c.key_size}-bit` : "N/A",
            cipherSuite:         c.name,
            ca:                  "—",
            algorithmOid:        c.details?.includes("OID") ? c.details.split("OID:")[1] : "—",
            keyState:            "Active",
            keyCreationDate:     "—",
            sigAlgorithm:        c.category === "cipher" ? c.name : "—",
            weak:                c.risk_level === "critical" || c.risk_level === "high",
            pqcStatus:           c.quantum_status,
            assetName:           c.name,
            url:                 displayDomain || "—",
            assetType:           c.category,
            threatVector:        c.threat_vector ? String(c.threat_vector) : "",
            nistPrimary:         c.nist_primary_recommendation || "",
            nistSummary:         c.nist_summary || "",
            nistRefs:            Array.isArray(c.nist_reference_urls) ? c.nist_reference_urls : [],
          }));
          setPerAppCbom(mapped);

          const records = Array.isArray(cryptoRes.data) ? cryptoRes.data : [];
          let safe = 0, ready = 0, vuln = 0, hndl = 0;
          const cryptoMapped = records.map((r: any) => {
            const status = determinePQCStatus(r.tls_version, r.cipher_suite, r.key_length?.toString());
            if (status === "quantum-safe") safe++;
            else if (status === "pqc-ready") ready++;
            else if (status === "vulnerable") vuln++;
            else if (status === "hndl-risk") hndl++;
            return mapCryptoToCbomAsset(r);
          });
          setPqcStats({ safe, ready, vuln, hndl });
          setCbomAssets(cryptoMapped);
          setLoading(false);
        });
      })
      .catch((err) => {
        console.error("Could not load CBOM page data", err);
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const CIPHER_MAX = cipherUsage.length
    ? Math.max(...cipherUsage.map((c: any) => c.count))
    : 1;

  const stats = [
    { title: "Total Applications", value: summary ? summary.total_applications.toString() : "...", icon: Globe, variant: "gold" as const },
    { title: "Sites Surveyed",     value: summary ? summary.sites_surveyed.toString()      : "...", icon: Search, variant: "info" as const },
    { title: "Active Certificates",value: summary ? summary.active_certificates.toString() : "...", icon: ShieldCheck, variant: "success" as const },
    { title: "Weak Cryptography",  value: summary ? summary.weak_cryptography.toString()   : "...", icon: AlertTriangle, variant: "red" as const },
    { title: "Certificate Issues", value: summary ? summary.certificate_issues.toString()  : "...", icon: ShieldAlert, variant: "red" as const },
  ];

  const filteredAssets = cbomAssets.filter(a => {
    if (pqcFilter === "All") return true;
    if (pqcFilter === "Quantum Safe" && a.pqcStatus === "quantum-safe") return true;
    if (pqcFilter === "Vulnerable"   && a.pqcStatus === "vulnerable")   return true;
    if (pqcFilter === "PQC Ready"    && a.pqcStatus === "pqc-ready")    return true;
    return false;
  });

  const handleExportJSON = () => {
    const report = {
      generated_at: new Date().toISOString(),
      total_assets: cbomAssets.length,
      assets: cbomAssets.map(a => ({
        name: a.assetName, url: a.url, tls_version: a.tlsVersion,
        cipher_suite: a.cipherSuite, key_exchange: a.keyExchange,
        certificate_authority: a.ca, key_length: a.keyLength,
        cert_expiry: a.certExpiry, pqc_status: a.pqcStatus,
        hndl_risk: a.hndlRisk, recommended_migration: a.recommendedMigration,
      })),
      summary: {
        quantum_safe: cbomAssets.filter(a => a.pqcStatus === "quantum-safe").length,
        pqc_ready:    cbomAssets.filter(a => a.pqcStatus === "pqc-ready").length,
        vulnerable:   cbomAssets.filter(a => a.pqcStatus === "vulnerable").length,
        hndl_risk:    cbomAssets.filter(a => a.hndlRisk).length,
      }
    };
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const el = document.createElement("a");
    el.setAttribute("href", dataStr);
    el.setAttribute("download", "cbom_report.json");
    document.body.appendChild(el); el.click(); el.remove();
  };

  const handleExportCSV = () => {
    const headers = [
      "Asset Name","URL","Asset Type","TLS Version","Key Exchange",
      "Cipher Suite","Certificate Authority","Key Length","Cert Expiry",
      "PQC Status","HNDL Risk","Recommended Migration"
    ];
    const rows = cbomAssets.map(a => [
      a.assetName, a.url, a.assetType, a.tlsVersion, a.keyExchange,
      a.cipherSuite, a.ca, a.keyLength, a.certExpiry, a.pqcStatus,
      a.hndlRisk ? "Yes" : "No", a.recommendedMigration,
    ].map(str => `"${String(str).replace(/"/g, '""')}"`).join(","));
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows].join("\n");
    const el = document.createElement("a");
    el.setAttribute("href", encodeURI(csvContent));
    el.setAttribute("download", "cbom_report.csv");
    document.body.appendChild(el); el.click(); el.remove();
  };

  const handleExportPDF = () => window.print();

  const handleExportServerBundle = async () => {
    try {
      const domain = summary?.domain as string | undefined;
      const res = await reportingService.exportBundle(domain);
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `scan_bundle_${(domain || "latest").replace(/[^\w.-]+/g, "_")}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.success("Scan bundle downloaded");
    } catch {
      toast.error("No completed scan to export, or the API is unreachable.");
    }
  };

  // Empty state
  const emptyState = !loading && cbomAssets.length === 0;

  return (
    <div className="space-y-6 printable-cbom">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 no-print">
        <div>
          <h1 className="text-2xl font-bold text-foreground">CBOM</h1>
          <p className="text-sm text-muted-foreground">Cryptographic Bill of Materials</p>
        </div>
      </motion.div>

      {/* Summary Top Card */}
      <div className="rounded-xl border border-border bg-card p-6 flex flex-col sm:flex-row justify-between items-start sm:items-center no-print">
        <div>
          <h2 className="text-lg font-bold text-foreground">CBOM Inventory Report</h2>
          <div className="text-sm text-muted-foreground mt-2 space-y-1">
            <p><strong>CBOM Report for:</strong> {summary?.domain || "..."}</p>
            <p><strong>CBOM Generated:</strong> {summary?.generated_at ? new Date(summary.generated_at).toLocaleString() : "..."}</p>
            <p><strong>NIST Compliance:</strong> FIPS 140-3 / NIST SP 800-208</p>
          </div>
        </div>
        <Button onClick={() => window.location.reload()} variant="outline" className="mt-4 sm:mt-0 gap-2 border-[#FBBC09]/50 text-[#FBBC09] hover:bg-[#FBBC09]/10 hover:text-[#FBBC09]">
          <RefreshCw className="w-4 h-4" /> Regenerate
        </Button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 no-print">
        {stats.map((s, i) => (
          <motion.div key={s.title} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
            <StatCard {...s} />
          </motion.div>
        ))}
      </div>

      {/* Loading skeletons */}
      {loading && (
        <div className="space-y-2">
          {[1,2,3].map(i => <Skeleton key={i} className="h-10 w-full" />)}
        </div>
      )}

      {/* Empty state */}
      {emptyState && (
        <div className="text-center py-16 text-muted-foreground">
          <ShieldCheck className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="text-lg font-medium">No CBOM data yet</p>
          <p className="text-sm max-w-md mx-auto">Complete a scan from the dashboard to populate CBOM charts and inventory.</p>
          <Button asChild variant="outline" className="mt-6 border-[#FBBC09]/40 text-[#FBBC09]">
            <Link to="/">Open dashboard</Link>
          </Button>
        </div>
      )}

      {!loading && (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6 no-print">
            {/* PQC Status overview */}
            <div className="rounded-xl border border-border bg-card p-5 lg:col-span-2 xl:col-span-3">
              <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">PQC Asset Readiness Overview</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="flex flex-col items-center justify-center p-4 rounded-lg bg-[#FBBC09]/10 border border-[#FBBC09]/20">
                  <ShieldCheck className="w-6 h-6 text-[#FBBC09] mb-2" />
                  <span className="text-2xl font-bold text-[#FBBC09]">{pqcStats.safe}</span>
                  <span className="text-xs text-muted-foreground uppercase mt-1">Quantum Safe</span>
                </div>
                <div className="flex flex-col items-center justify-center p-4 rounded-lg bg-[#0ea5e9]/10 border border-[#0ea5e9]/20">
                  <CheckCircle className="w-6 h-6 text-[#0ea5e9] mb-2" />
                  <span className="text-2xl font-bold text-[#0ea5e9]">{pqcStats.ready}</span>
                  <span className="text-xs text-muted-foreground uppercase mt-1">PQC Ready</span>
                </div>
                <div className="flex flex-col items-center justify-center p-4 rounded-lg bg-[#ef4444]/10 border border-[#ef4444]/20">
                  <AlertTriangle className="w-6 h-6 text-[#ef4444] mb-2" />
                  <span className="text-2xl font-bold text-[#ef4444]">{pqcStats.vuln}</span>
                  <span className="text-xs text-muted-foreground uppercase mt-1">Vulnerable</span>
                </div>
                <div className="flex flex-col items-center justify-center p-4 rounded-lg bg-[#A20E37]/10 border border-[#A20E37]/20">
                  <ShieldAlert className="w-6 h-6 text-[#A20E37] mb-2" />
                  <span className="text-2xl font-bold text-[#A20E37]">{pqcStats.hndl}</span>
                  <span className="text-xs text-muted-foreground uppercase mt-1">HNDL Risk</span>
                </div>
              </div>
            </div>

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
                      <Cell key={`cell-${i}`} fill={COLORS[i % COLORS.length]} />
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

          {/* Cipher Usage */}
          <div className="rounded-xl border border-border bg-card p-5 no-print">
            <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">Cipher Usage</h3>
            {cipherUsage.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">No cipher data yet — scan a domain to see cipher usage.</p>
            ) : (
              <div className="space-y-3">
                {cipherUsage.map((cipher: any) => {
                  const pct = Math.round((cipher.count / CIPHER_MAX) * 100);
                  const barColor = cipher.weak ? "#A20E37" : "#FBBC09";
                  return (
                    <div
                      key={cipher.name}
                      className={`flex items-center gap-3 px-3 py-2 rounded-lg ${cipher.weak ? "bg-[#A20E37]/10 border border-[#A20E37]/20" : ""}`}
                    >
                      <span
                        className="text-xs font-mono flex-1 min-w-0 truncate"
                        style={{ color: cipher.weak ? "#A20E37" : "hsl(var(--foreground))" }}
                        title={cipher.name}
                      >
                        {cipher.name}
                        {cipher.weak && (
                          <span className="ml-2 text-[10px] font-sans font-semibold px-1.5 py-0.5 rounded bg-[#A20E37]/20 text-[#A20E37]">WEAK</span>
                        )}
                      </span>
                      <div className="w-40 h-3 rounded-full bg-secondary overflow-hidden flex-shrink-0">
                        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: barColor }} />
                      </div>
                      <span className="text-xs font-bold w-6 text-right flex-shrink-0" style={{ color: barColor }}>{cipher.count}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Export Controls & Inventory Table */}
          <div className="rounded-xl border border-border bg-card p-6">
            <div className="hidden print:block mb-8 text-black">
              <div className="flex justify-between items-end border-b-2 border-black pb-4 mb-4">
                <div>
                  <h1 className="text-3xl font-bold">PNB × QSCAS</h1>
                  <h2 className="text-xl mt-1 text-gray-700">Cryptographic Bill of Materials (CBOM)</h2>
                </div>
                <div className="text-right text-sm text-gray-600">
                  <p>Generated: {new Date().toLocaleDateString()}</p>
                </div>
              </div>
            </div>

            <div className="flex flex-col xl:flex-row justify-between xl:items-center gap-4 mb-6 no-print">
              <div>
                <h3 className="text-lg font-bold text-foreground">Cryptographic Bill of Materials — Asset Inventory</h3>
                <p className="text-sm text-muted-foreground mt-1">Detailed inventory of cryptographic assets and vulnerabilities.</p>
              </div>
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
                <select
                  className="h-10 px-3 py-2 bg-secondary border border-border rounded-md text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
                  value={pqcFilter}
                  onChange={e => setPqcFilter(e.target.value)}
                >
                  <option value="All">All Assets</option>
                  <option value="Quantum Safe">Quantum Safe Only</option>
                  <option value="PQC Ready">PQC Ready Only</option>
                  <option value="Vulnerable">Vulnerable Only</option>
                </select>
                <div className="flex flex-wrap gap-2">
                  <Button onClick={handleExportServerBundle} variant="outline" className="gap-2 border-primary/40" title="Raw JSON from latest completed scan (server)">
                    <Download className="w-4 h-4" /> Server bundle
                  </Button>
                  <Button onClick={handleExportJSON} variant="outline" className="gap-2"><Download className="w-4 h-4" /> Export JSON</Button>
                  <Button onClick={handleExportCSV}  variant="outline" className="gap-2"><Download className="w-4 h-4" /> Export CSV</Button>
                  <Button onClick={handleExportPDF}  className="gap-2 bg-primary"><Download className="w-4 h-4" /> Export PDF</Button>
                </div>
              </div>
            </div>

            <DataTable
              searchable
              pageSize={10}
              data={filteredAssets}
              columns={[
                { key: "assetName",            header: "Asset Name" },
                { key: "url",                  header: "URL / Endpoint" },
                { key: "assetType",            header: "Asset Type" },
                { key: "tlsVersion",           header: "TLS Version" },
                { key: "keyExchange",          header: "Key Exchange" },
                { key: "cipherSuite",          header: "Cipher Suite" },
                { key: "ca",                   header: "Cert Authority" },
                { key: "keyLength",            header: "Key Length" },
                { key: "certExpiry",           header: "Cert Expiry" },
                { key: "pqcStatus",            header: "PQC Status",  render: (r) => <PQCBadge status={r.pqcStatus as PQCStatus} /> },
                { key: "hndlRisk",             header: "HNDL Risk",   render: (r) => r.hndlRisk ? <Badge className="bg-[#A20E37]/15 text-[#A20E37] border-[#A20E37]/20 uppercase text-[10px]">Yes</Badge> : <Badge className="bg-success/15 text-success border-success/20 uppercase text-[10px]">No</Badge> },
                { key: "recommendedMigration", header: "Recommended Migration" },
              ]}
            />
          </div>

          {/* Per-Application CBOM Table */}
          <div className="rounded-xl border border-border bg-card overflow-hidden no-print">
            <div className="px-6 py-4 border-b border-border">
              <h3 className="text-sm font-bold text-foreground uppercase tracking-wide">Per-Application CBOM</h3>
              <p className="text-xs text-muted-foreground mt-0.5">
                CERT-IN fields plus Phase 3 threat/NIST mapping (indicative — not certification advice).
              </p>
            </div>
            {perAppCbom.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground text-sm">
                No per-application CBOM data — scan a domain to populate this table.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr style={{ backgroundColor: "#FBBC09" }}>
                      {[
                        "Application",
                        "Key Length",
                        "Cipher Suite",
                        "Certificate Authority",
                        "Algorithm OID",
                        "Key State",
                        "Key Creation Date",
                        "Signature Algorithm",
                        "Threat",
                        "NIST (indicative)",
                        "Guidance",
                        "Refs",
                      ].map((h) => (
                        <th key={h} className="px-4 py-3 text-left font-bold uppercase tracking-wide whitespace-nowrap" style={{ color: "#111" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {perAppCbom.map((row, i) => (
                      <tr
                        key={i}
                        className="border-b border-border/40 hover:opacity-90 transition-opacity"
                        style={{
                          backgroundColor: row.weak
                            ? "rgba(162,14,55,0.10)"
                            : i % 2 === 0 ? "rgba(251,188,9,0.04)" : "transparent",
                        }}
                      >
                        <td className="px-4 py-2.5 font-mono text-foreground">{row.application}</td>
                        <td className="px-4 py-2.5 font-mono" style={{ color: row.keyLength === "1024-bit" ? "#A20E37" : "inherit" }}>{row.keyLength}</td>
                        <td className="px-4 py-2.5 font-mono max-w-[180px] truncate" style={{ color: row.weak ? "#A20E37" : "inherit" }} title={row.cipherSuite}>{row.cipherSuite}</td>
                        <td className="px-4 py-2.5">{row.ca}</td>
                        <td className="px-4 py-2.5 font-mono text-muted-foreground">{row.algorithmOid}</td>
                        <td className="px-4 py-2.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            row.keyState === "Active" ? "bg-green-500/15 text-green-400"
                            : row.keyState === "Revoked" ? "bg-[#A20E37]/15 text-[#A20E37]"
                            : "bg-yellow-500/15 text-yellow-400"
                          }`}>{row.keyState}</span>
                        </td>
                        <td className="px-4 py-2.5 text-muted-foreground">{row.keyCreationDate}</td>
                        <td className="px-4 py-2.5 font-mono text-muted-foreground">{row.sigAlgorithm}</td>
                        <td className="px-4 py-2.5 text-[11px] uppercase text-muted-foreground">
                          {row.threatVector || "—"}
                        </td>
                        <td className="px-4 py-2.5 text-[11px] text-foreground max-w-[140px]" title={row.nistPrimary}>
                          {row.nistPrimary || "—"}
                        </td>
                        <td className="px-4 py-2.5 text-[11px] text-muted-foreground max-w-[200px] leading-snug" title={row.nistSummary}>
                          {row.nistSummary ? `${row.nistSummary.slice(0, 120)}${row.nistSummary.length > 120 ? "…" : ""}` : "—"}
                        </td>
                        <td className="px-4 py-2.5 align-top">
                          {row.nistRefs?.length ? (
                            <div className="flex flex-col gap-1">
                              {row.nistRefs.map((ref: { label?: string; url?: string }, j: number) => (
                                ref.url ? (
                                  <a
                                    key={j}
                                    href={ref.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-[10px] text-primary underline underline-offset-2 truncate max-w-[160px]"
                                    title={ref.label}
                                  >
                                    {ref.label || ref.url}
                                  </a>
                                ) : null
                              ))}
                            </div>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
