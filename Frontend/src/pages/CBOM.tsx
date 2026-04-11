import { useState, useEffect, type ReactNode } from "react";
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
  LabelList,
} from "recharts";
import { Link } from "react-router-dom";
import { DossierPageHeader } from "@/components/layout/DossierPageHeader";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { cbomService, cryptoService, pqcService, reportingService } from "@/services/api";
import { PQCBadge, determinePQCStatus, hndlRiskFromCrypto, PQCStatus } from "@/components/ui/PQCBadge";
import { CheckCircle } from "lucide-react";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

const COLORS = ["hsl(221, 83%, 53%)", "hsl(199, 89%, 48%)", "hsl(262, 83%, 58%)", "hsl(330, 81%, 56%)", "hsl(43, 96%, 52%)"];

/** Pie / multi-series palette — enterprise blue–violet range */
const PIE_SLICE_COLORS = [
  "hsl(221, 83%, 53%)",
  "hsl(199, 89%, 48%)",
  "hsl(262, 72%, 58%)",
  "hsl(291, 64%, 52%)",
  "hsl(330, 75%, 58%)",
  "hsl(43, 96%, 52%)",
];

/** Distinct fills per negotiated TLS bucket (horizontal bar chart) */
const PROTOCOL_BAR_FILL: Record<string, string> = {
  "TLSv1.3": "hsl(152, 55%, 38%)",
  "TLSv1.2": "hsl(210, 78%, 48%)",
  "TLSv1.1": "hsl(38, 92%, 50%)",
  "TLSv1.0": "hsl(25, 90%, 45%)",
  Unknown: "hsl(215, 15%, 45%)",
};

function protocolBarColor(name: string, index: number): string {
  return PROTOCOL_BAR_FILL[name] ?? COLORS[index % COLORS.length];
}

/** Light-card friendly tooltips (charts sit on pale panels) */
const chartTooltipContent = {
  contentStyle: {
    background: "rgba(255, 255, 255, 0.96)",
    border: "1px solid rgb(226 232 240)",
    borderRadius: "12px",
    fontSize: "12px",
    color: "rgb(15 23 42)",
    boxShadow: "0 10px 40px -12px rgb(15 23 42 / 0.18)",
  },
  labelStyle: { color: "rgb(71 85 105)", fontWeight: 600 },
  cursor: { fill: "rgb(59 130 246 / 0.06)" },
};

const CHART_GRID = {
  stroke: "hsl(214, 32%, 91%)",
  strokeDasharray: "4 6" as const,
};

const CHART_AXIS_TICK = { fill: "hsl(215, 16%, 42%)", fontSize: 11, fontWeight: 500 };

/** Legacy dark tooltip — kept for any non-chart use */
const tooltipStyle = {
  contentStyle: {
    background: "hsl(220, 18%, 13%)",
    border: "1px solid hsl(220, 14%, 20%)",
    borderRadius: "8px",
    fontSize: "12px",
    color: "hsl(210, 20%, 92%)",
  },
};

function CbomChartCard({
  title,
  subtitle,
  children,
  className,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-2xl border border-slate-200/90 bg-gradient-to-br from-white via-slate-50/50 to-white p-5 shadow-sm ring-1 ring-slate-200/40",
        "dark:border-border dark:from-card dark:via-card dark:to-muted/15 dark:ring-border/40",
        className,
      )}
    >
      <div className="mb-4 flex flex-col gap-1">
        <h3 className="text-[11px] font-bold uppercase tracking-[0.14em] text-slate-500 dark:text-muted-foreground">
          {title}
        </h3>
        {subtitle ? (
          <p className="text-xs leading-relaxed text-muted-foreground">{subtitle}</p>
        ) : null}
      </div>
      <div className="rounded-xl border border-slate-100/90 bg-slate-50/70 p-3 shadow-inner dark:border-border/60 dark:bg-muted/20">
        {children}
      </div>
    </div>
  );
}

// ── Helpers to classify crypto records ──────────────────────────────────────
function mapCryptoToCbomAsset(r: any) {
  const tlsRaw    = r.tls_version   || "";
  const cipherRaw = r.cipher_suite  || "";
  const tls = String(tlsRaw);
  const cipher = String(cipherRaw);
  const kl     = r.key_length    || 0;
  const klStr  = kl && kl !== "None" ? String(kl) : undefined;

  const isWeak     = ["RC4","DES","3DES","MD5","NULL","EXPORT","TLS 1.0","TLS 1.1"]
                       .some(p => cipher.includes(p) || tls.includes(p));
  const pqcStatus  = determinePQCStatus(tls, cipher, klStr);
  const hndlRisk   = hndlRiskFromCrypto(tls, cipher, klStr);

  const tlsLc = tls.toLowerCase();
  const cipherLc = cipher.toLowerCase();
  const isTls13 = tlsLc.includes("1.3");
  const isLegacyTls = tlsLc.includes("1.0") || tlsLc.includes("1.1") || tlsLc.includes("ssl");
  const isTls12 = tlsLc.includes("1.2");
  const hasRsaOrDhSignals =
    cipherLc.includes(" rsa") ||
    cipherLc.includes("_rsa") ||
    cipherLc.includes("rsa_") ||
    cipherLc.includes(" dh") ||
    cipherLc.includes("_dh") ||
    cipherLc.includes("dhe") ||
    cipherLc.includes("ecdh") ||
    cipherLc.includes("ecdsa") ||
    cipherLc.includes("ecc");

  let rec = "No action needed";
  if (pqcStatus === "quantum-safe") {
    rec = "Maintain configuration; periodic monitoring";
  } else if (isWeak || isLegacyTls) {
    rec = "Immediate: disable weak protocols/ciphers; upgrade to TLS 1.3";
  } else if (hndlRisk) {
    rec = "Prioritize HNDL risk: move to TLS 1.3 everywhere; pilot hybrid PQC (ML‑KEM) where supported";
  } else if (!isTls13 && (isTls12 || hasRsaOrDhSignals || pqcStatus === "vulnerable")) {
    rec = "Plan migration: TLS 1.3 baseline + PQC-ready crypto; remove RSA/DH legacy where present";
  } else if (!isTls13) {
    rec = "Upgrade to TLS 1.3 baseline; validate forward secrecy and modern cipher suites";
  }

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
            setKeyLengthData(
              (Array.isArray(data.key_length_distribution) ? data.key_length_distribution : []).map((k: any) => {
                const raw = k?.key_length ?? k?.name ?? k?.key_size;
                const n = raw == null ? "" : String(raw);
                return {
                  name: n ? `${n}-bit` : "Unknown",
                  count: Number(k?.count ?? k?.value ?? 0),
                };
              }),
            );
          }
          if (data.top_certificate_authorities) {
            setCaData(
              (Array.isArray(data.top_certificate_authorities) ? data.top_certificate_authorities : []).map((c: any) => ({
                name: String(c?.certificate_authority ?? c?.name ?? "Unknown"),
                value: Number(c?.count ?? c?.value ?? 0),
              })),
            );
          }
          if (data.encryption_protocols) {
            setProtocolData(
              (Array.isArray(data.encryption_protocols) ? data.encryption_protocols : []).map((p: any) => ({
                name: String(p?.tls_version ?? p?.name ?? "Unknown"),
                value: Number(p?.count ?? p?.value ?? 0),
              })),
            );
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

  const handleExportPDF = () => {
    // Data-based PDF export (not "Print to PDF" screenshot).
    // We generate a CBOM table using jsPDF so the exported PDF is content-first.
    const doc = new jsPDF({ orientation: "landscape", unit: "pt", format: "a4" });

    const domain = summary?.domain || "";
    const generatedAt = summary?.generated_at ? new Date(summary.generated_at) : new Date();

    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.text("PNB × QSCAS", 40, 50);

    doc.setFontSize(12);
    doc.setFont("helvetica", "normal");
    doc.text("Cryptographic Bill of Materials (CBOM)", 40, 70);
    doc.setFontSize(10);
    doc.text(`CBOM Report for: ${domain || "—"}`, 40, 86);
    doc.text(`Generated: ${generatedAt.toLocaleString()}`, 40, 102);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(10);
    doc.text("PQC Readiness Summary", 40, 120);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);

    // Use the same boolean used for the table HNDL column (`hndlRisk`) so header matches exported content.
    const exportAssets = filteredAssets;
    const hndlCount = exportAssets.filter((a: any) => Boolean(a?.hndlRisk)).length;

    doc.text(
      `Quantum Safe: ${exportAssets.filter((a: any) => a?.pqcStatus === "quantum-safe").length
      }   |   PQC Ready: ${exportAssets.filter((a: any) => a?.pqcStatus === "pqc-ready").length
      }   |   Vulnerable: ${exportAssets.filter((a: any) => a?.pqcStatus === "vulnerable").length
      }   |   HNDL Risk: ${hndlCount}`,
      40,
      134
    );

    const rows = exportAssets.map((a: any) => [
      a.assetName ?? "—",
      a.url ?? "—",
      a.assetType ?? "—",
      a.tlsVersion ?? "—",
      a.keyExchange ?? "—",
      a.cipherSuite ?? "—",
      a.ca ?? "—",
      a.keyLength ?? "—",
      a.certExpiry ?? "—",
      a.pqcStatus ?? "—",
      a.hndlRisk ? "Yes" : "No",
      a.recommendedMigration ?? "—",
    ]);

    autoTable(doc, {
      startY: 160,
      head: [
        [
          "Asset Name",
          "URL / Endpoint",
          "Asset Type",
          "TLS Version",
          "Key Exchange",
          "Cipher Suite",
          "Cert Authority",
          "Key Length",
          "Cert Expiry",
          "PQC Status",
          "HNDL Risk",
          "Recommended Migration",
        ],
      ],
      body: rows,
      styles: { fontSize: 7, cellPadding: 3, overflow: "linebreak" },
      headStyles: { fillColor: [221, 231, 255], textColor: [0, 0, 0], fontStyle: "bold" },
      theme: "grid",
      columnStyles: {
        1: { cellWidth: 120 },
        10: { cellWidth: 55 },
        11: { cellWidth: 170 },
      },
    });

    // Footnote
    const pageCount = doc.getNumberOfPages();
    doc.setFontSize(8);
    doc.setTextColor(80);
    doc.text(
      "Note: Migration recommendations are indicative and based on scan evidence.",
      40,
      820
    );

    doc.save(`cbom_report_${(domain || "latest").replace(/[^\w.-]+/g, "_")}.pdf`);
  };

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
    <div className="space-y-8 printable-cbom">
      <div className="no-print">
        <DossierPageHeader
          eyebrow="Cryptographic inventory"
          title="Crypto Bill of Materials"
          description="TLS, certificates, and algorithm inventory derived from the latest completed scan."
        />
      </div>

      {/* Summary Top Card */}
      <div className="dossier-card flex flex-col items-start justify-between gap-4 p-6 sm:flex-row sm:items-center no-print">
        <div>
          <h2 className="text-lg font-bold text-foreground">CBOM Inventory Report</h2>
          <div className="text-sm text-muted-foreground mt-2 space-y-1">
            <p><strong>CBOM Report for:</strong> {summary?.domain || "..."}</p>
            <p><strong>CBOM Generated:</strong> {summary?.generated_at ? new Date(summary.generated_at).toLocaleString() : "..."}</p>
            <p><strong>NIST Compliance:</strong> FIPS 140-3 / NIST SP 800-208</p>
          </div>
        </div>
        <Button onClick={() => window.location.reload()} variant="outline" className="mt-4 gap-2 border-primary/50 text-primary hover:bg-primary/10 hover:text-primary sm:mt-0">
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
          <Button asChild variant="outline" className="mt-6 border-primary/40 text-primary">
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
                <div className="flex flex-col items-center justify-center rounded-lg border border-primary/20 bg-primary/10 p-4">
                  <ShieldCheck className="mb-2 h-6 w-6 text-primary" />
                  <span className="text-2xl font-bold text-primary">{pqcStats.safe}</span>
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
                <div className="flex flex-col items-center justify-center rounded-lg border border-destructive/20 bg-destructive/10 p-4">
                  <ShieldAlert className="mb-2 h-6 w-6 text-destructive" />
                  <span className="text-2xl font-bold text-destructive">{pqcStats.hndl}</span>
                  <span className="text-xs text-muted-foreground uppercase mt-1">HNDL Risk</span>
                </div>
              </div>
            </div>

            {/* Key Length */}
            <CbomChartCard title="Key Length Distribution">
              <ResponsiveContainer width="100%" height={268}>
                <BarChart
                  data={keyLengthData}
                  margin={{ top: 16, right: 12, left: 4, bottom: 8 }}
                  barCategoryGap="20%"
                >
                  <defs>
                    <linearGradient id="cbomKeyLen" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#38bdf8" />
                      <stop offset="55%" stopColor="#3b82f6" />
                      <stop offset="100%" stopColor="#1d4ed8" />
                    </linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} stroke={CHART_GRID.stroke} strokeDasharray={CHART_GRID.strokeDasharray} />
                  <XAxis
                    dataKey="name"
                    tick={CHART_AXIS_TICK}
                    tickLine={false}
                    axisLine={{ stroke: "hsl(214, 32%, 88%)" }}
                  />
                  <YAxis tick={CHART_AXIS_TICK} tickLine={false} axisLine={false} allowDecimals={false} width={36} />
                  <Tooltip {...chartTooltipContent} />
                  <Bar dataKey="count" fill="url(#cbomKeyLen)" radius={[10, 10, 0, 0]} maxBarSize={52} />
                </BarChart>
              </ResponsiveContainer>
            </CbomChartCard>

            {/* Top CAs */}
            <CbomChartCard title="Top Certificate Authorities">
              <ResponsiveContainer width="100%" height={268}>
                <PieChart>
                  <Pie
                    data={caData}
                    cx="50%"
                    cy="50%"
                    innerRadius={56}
                    outerRadius={94}
                    paddingAngle={caData.length > 1 ? 2 : 0}
                    dataKey="value"
                    stroke="hsl(210, 40%, 99%)"
                    strokeWidth={2}
                    label={({ name, percent }) => {
                      const s = String(name);
                      const short = s.length > 18 ? `${s.slice(0, 16)}…` : s;
                      return `${short} ${(percent * 100).toFixed(0)}%`;
                    }}
                    labelLine={{ stroke: "hsl(215, 16%, 72%)", strokeWidth: 1 }}
                  >
                    {caData.map((_, i) => (
                      <Cell key={`cell-${i}`} fill={PIE_SLICE_COLORS[i % PIE_SLICE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip {...chartTooltipContent} />
                </PieChart>
              </ResponsiveContainer>
            </CbomChartCard>

            {/* Protocols — negotiated TLS per endpoint */}
            <CbomChartCard
              title="Encryption Protocol Distribution"
              subtitle='Endpoints counted by negotiated TLS version (not every supported protocol on each host).'
            >
              <ResponsiveContainer width="100%" height={268}>
                <BarChart
                  data={protocolData}
                  layout="vertical"
                  margin={{ top: 8, right: 28, left: 8, bottom: 8 }}
                  barCategoryGap="16%"
                >
                  <CartesianGrid
                    horizontal={false}
                    stroke={CHART_GRID.stroke}
                    strokeDasharray={CHART_GRID.strokeDasharray}
                  />
                  <XAxis
                    type="number"
                    allowDecimals={false}
                    tick={CHART_AXIS_TICK}
                    tickLine={false}
                    domain={[0, "dataMax"]}
                    tickFormatter={(v) => (Number.isInteger(v) ? String(v) : "")}
                    axisLine={{ stroke: "hsl(214, 32%, 88%)" }}
                  />
                  <YAxis
                    type="category"
                    dataKey="name"
                    tick={CHART_AXIS_TICK}
                    tickLine={false}
                    axisLine={false}
                    width={76}
                  />
                  <Tooltip
                    {...chartTooltipContent}
                    formatter={(value: number) => {
                      const n = Number(value);
                      const total = protocolData.reduce(
                        (sum, row) => sum + Number(row.value ?? row.count ?? 0),
                        0,
                      );
                      const pct = total > 0 ? Math.round((n / total) * 100) : 0;
                      return [`${n} endpoint${n === 1 ? "" : "s"} (${pct}%)`, "Endpoints"];
                    }}
                  />
                  <Bar dataKey="value" radius={[0, 10, 10, 0]} barSize={22} maxBarSize={28}>
                    {protocolData.map((entry, index) => (
                      <Cell key={`cell-${entry.name}-${index}`} fill={protocolBarColor(String(entry.name), index)} />
                    ))}
                    <LabelList
                      dataKey="value"
                      position="right"
                      fill="hsl(215, 16%, 38%)"
                      fontSize={12}
                      fontWeight={600}
                      formatter={(v: number) => (v > 0 ? v : "")}
                    />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </CbomChartCard>
          </div>

          {/* Cipher Usage */}
          <div className="rounded-xl border border-border bg-card p-5 no-print">
            <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">Cipher Usage</h3>
            {cipherUsage.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">
                No cipher data yet — run a scan from{" "}
                <Link to="/" className="font-medium text-primary hover:underline">Overview</Link>
                .
              </p>
            ) : (
              <div className="space-y-3">
                {cipherUsage.map((cipher: any) => {
                  const pct = Math.round((cipher.count / CIPHER_MAX) * 100);
                  const barColor = cipher.weak ? "#dc2626" : "#2563eb";
                  return (
                    <div
                      key={cipher.name}
                      className={`flex items-center gap-3 rounded-lg px-3 py-2 ${cipher.weak ? "border border-destructive/20 bg-destructive/10" : ""}`}
                    >
                      <span
                        className="text-xs font-mono flex-1 min-w-0 truncate"
                        style={{ color: cipher.weak ? "#dc2626" : "hsl(var(--foreground))" }}
                        title={cipher.name}
                      >
                        {cipher.name}
                        {cipher.weak && (
                          <span className="ml-2 rounded bg-destructive/20 px-1.5 py-0.5 font-sans text-[10px] font-semibold text-destructive">WEAK</span>
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
                { key: "hndlRisk",             header: "HNDL Risk",   render: (r) => r.hndlRisk ? <Badge className="border-destructive/20 bg-destructive/15 text-[10px] uppercase text-destructive">Yes</Badge> : <Badge className="border-success/20 bg-success/15 text-[10px] uppercase text-success">No</Badge> },
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
                No per-application CBOM data — run a scan from{" "}
                <Link to="/" className="font-medium text-primary hover:underline">Overview</Link>
                .
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="bg-primary text-primary-foreground">
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
                        <th key={h} className="whitespace-nowrap px-4 py-3 text-left font-bold uppercase tracking-wide text-primary-foreground">{h}</th>
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
                            ? "hsl(0 72% 51% / 0.08)"
                            : i % 2 === 0 ? "hsl(221 83% 53% / 0.06)" : "transparent",
                        }}
                      >
                        <td className="px-4 py-2.5 font-mono text-foreground">{row.application}</td>
                        <td className={`px-4 py-2.5 font-mono ${row.keyLength === "1024-bit" ? "text-destructive" : ""}`}>{row.keyLength}</td>
                        <td className={`px-4 py-2.5 font-mono max-w-[180px] truncate ${row.weak ? "text-destructive" : ""}`} title={row.cipherSuite}>{row.cipherSuite}</td>
                        <td className="px-4 py-2.5">{row.ca}</td>
                        <td className="px-4 py-2.5 font-mono text-muted-foreground">{row.algorithmOid}</td>
                        <td className="px-4 py-2.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            row.keyState === "Active" ? "bg-green-500/15 text-green-400"
                            : row.keyState === "Revoked" ? "bg-destructive/15 text-destructive"
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
