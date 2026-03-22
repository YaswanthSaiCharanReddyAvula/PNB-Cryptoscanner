import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { StatCard } from "@/components/dashboard/StatCard";
import { DataTable } from "@/components/dashboard/DataTable";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Globe, Search, ShieldCheck, AlertTriangle, ShieldAlert, Download, RefreshCw } from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from "recharts";
import { cbomService, cryptoService } from "@/services/api";
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

const MOCK_CBOM_ASSETS = [
  {
    assetName: "API Gateway",
    url: "api.securebank.com",
    assetType: "API",
    tlsVersion: "TLS 1.3",
    keyExchange: "ML-KEM (Kyber768)",
    cipherSuite: "TLS_AES_256_GCM_SHA384",
    ca: "DigiCert Global Root G3",
    keyLength: "768-bit",
    certExpiry: "2026-10-15",
    pqcStatus: "quantum-safe",
    hndlRisk: false,
    recommendedMigration: "None"
  },
  {
    assetName: "Customer Portal",
    url: "app.securebank.com",
    assetType: "Web App",
    tlsVersion: "TLS 1.2",
    keyExchange: "ECDHE-RSA",
    cipherSuite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    ca: "Let's Encrypt Authority X3",
    keyLength: "2048-bit",
    certExpiry: "2024-05-20",
    pqcStatus: "vulnerable",
    hndlRisk: true,
    recommendedMigration: "Migrate to ML-KEM via hybrid key exchange"
  },
  {
    assetName: "Auth Service",
    url: "auth.securebank.com",
    assetType: "API",
    tlsVersion: "TLS 1.3",
    keyExchange: "X25519",
    cipherSuite: "TLS_CHACHA20_POLY1305_SHA256",
    ca: "Amazon",
    keyLength: "256-bit",
    certExpiry: "2025-01-10",
    pqcStatus: "pqc-ready",
    hndlRisk: true,
    recommendedMigration: "Upgrade X25519 to X25519Kyber768Draft00"
  },
  {
    assetName: "Legacy Database",
    url: "db-internal.securebank.net",
    assetType: "Server",
    tlsVersion: "TLS 1.0",
    keyExchange: "RSA",
    cipherSuite: "TLS_RSA_WITH_AES_128_CBC_SHA",
    ca: "Internal Corp CA",
    keyLength: "1024-bit",
    certExpiry: "2023-11-01",
    pqcStatus: "vulnerable",
    hndlRisk: true,
    recommendedMigration: "Urgent: Disable TLS 1.0, upgrade to TLS 1.3 + ML-KEM"
  },
  {
    assetName: "Payment Gateway",
    url: "pay.securebank.com",
    assetType: "API",
    tlsVersion: "TLS 1.3",
    keyExchange: "FALCON-512",
    cipherSuite: "TLS_AES_256_GCM_SHA384",
    ca: "GlobalSign PQC Root",
    keyLength: "512-bit",
    certExpiry: "2026-12-01",
    pqcStatus: "quantum-safe",
    hndlRisk: false,
    recommendedMigration: "None"
  },
  {
    assetName: "Corporate VPN",
    url: "vpn.securebank.com",
    assetType: "Server",
    tlsVersion: "TLS 1.2",
    keyExchange: "DHE-RSA",
    cipherSuite: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    ca: "Sectigo RSA Domain Validation Secure Server CA",
    keyLength: "4096-bit",
    certExpiry: "2025-08-30",
    pqcStatus: "vulnerable",
    hndlRisk: true,
    recommendedMigration: "Migrate to Hybrid PQC VPN protocols"
  },
  {
    assetName: "Mobile App API",
    url: "mobile.securebank.com",
    assetType: "API",
    tlsVersion: "TLS 1.3",
    keyExchange: "ECDHE-ECDSA",
    cipherSuite: "TLS_AES_128_GCM_SHA256",
    ca: "Let's Encrypt Authority X3",
    keyLength: "256-bit",
    certExpiry: "2024-12-15",
    pqcStatus: "vulnerable",
    hndlRisk: true,
    recommendedMigration: "Transition auth keys to ML-DSA/Dilithium"
  },
  {
    assetName: "Marketing Site",
    url: "www.securebank.com",
    assetType: "Web App",
    tlsVersion: "TLS 1.3",
    keyExchange: "X25519",
    cipherSuite: "TLS_AES_256_GCM_SHA384",
    ca: "Cloudflare Inc ECC CA-3",
    keyLength: "256-bit",
    certExpiry: "2025-06-22",
    pqcStatus: "pqc-ready",
    hndlRisk: false,
    recommendedMigration: "Monitor standard maturity; prep ML-KEM"
  }
];

// ── Cipher Usage mock data ────────────────────────────────────────────────
const CIPHER_USAGE = [
  { name: "ECDHE-RSA-AES256-GCM-SHA384",    count: 29, weak: false },
  { name: "ECDHE-ECDSA-AES256-GCM-SHA384",  count: 23, weak: false },
  { name: "AES256-GCM-SHA384",               count: 19, weak: false },
  { name: "AES128-GCM-SHA256",               count: 15, weak: false },
  { name: "TLS_RSA_WITH_DES_CBC_SHA",        count: 9,  weak: true  },
  { name: "RC4-SHA",                         count: 4,  weak: true  },
];
const CIPHER_MAX = Math.max(...CIPHER_USAGE.map((c) => c.count));

// ── Per-application CBOM mock ─────────────────────────────────────────────
const PER_APP_CBOM = [
  {
    application: "portal.company.com",
    keyLength: "2048-Bit",
    cipher: "ECDHE-RSA-AES256-GCM-SHA384",
    ca: "DigiCert",
    algorithmOid: "1.2.840.113549.1.1.11",
    keyState: "Active",
    keyCreationDate: "2024-01-10",
    sigAlgorithm: "SHA256withRSA",
    weak: false,
  },
  {
    application: "portal.company.com",
    keyLength: "1024-Bit",
    cipher: "TLS_RSA_WITH_256C@SHA384",
    ca: "COMODO",
    algorithmOid: "1.2.840.113549.1.1.5",
    keyState: "Expired",
    keyCreationDate: "2021-06-15",
    sigAlgorithm: "SHA1withRSA",
    weak: true,
  },
  {
    application: "vpn.company.com",
    keyLength: "4096-Bit",
    cipher: "ECDHE-RSA-AES256-GCM-SHA384",
    ca: "COMODO",
    algorithmOid: "1.2.840.10045.4.3.3",
    keyState: "Active",
    keyCreationDate: "2024-09-01",
    sigAlgorithm: "SHA384withECDSA",
    weak: false,
  },
  {
    application: "purn.company.com",
    keyLength: "4096-Bit",
    cipher: "TLS_RSA_AES256_GCM_SHA384",
    ca: "loopDot",
    algorithmOid: "1.2.840.113549.1.1.12",
    keyState: "Revoked",
    keyCreationDate: "2022-11-20",
    sigAlgorithm: "SHA512withRSA",
    weak: true,
  },
];


export default function CBOM() {
  const [summary, setSummary] = useState<any>(null);
  const [keyLengthData, setKeyLengthData] = useState<any[]>([]);
  const [caData, setCaData] = useState<any[]>([]);
  const [protocolData, setProtocolData] = useState<any[]>([]);
  const [pqcStats, setPqcStats] = useState({ safe: 0, ready: 0, vuln: 0, hndl: 0 });
  const [pqcFilter, setPqcFilter] = useState("All");

  useEffect(() => {
    // Fetch Summary
    cbomService.getSummary()
      .then(res => setSummary(res.data))
      .catch(err => console.error("Could not fetch CBOM summary", err));

    // Fetch Charts
    cbomService.getCharts()
      .then(res => {
        const data = res.data;
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
      })
      .catch(err => console.error("Could not fetch CBOM charts", err));

    // Fetch PQC tallies
    cryptoService.getCryptoSecurityData()
      .then(res => {
        let safe = 0, ready = 0, vuln = 0, hndl = 0;
        res.data.forEach((c: any) => {
          const status = determinePQCStatus(c.tls_version, c.cipher_suite, c.key_length?.toString());
          if (status === "quantum-safe") safe++;
          else if (status === "pqc-ready") ready++;
          else if (status === "vulnerable") vuln++;
          else if (status === "hndl-risk") hndl++;
        });
        setPqcStats({ safe, ready, vuln, hndl });
      })
      .catch(err => console.error("Could not fetch crypto data for PQC stats", err));
  }, []);

  const stats = [
    { title: "Total Applications", value: summary ? summary.total_applications.toString() : "...", icon: Globe, variant: "gold" as const },
    { title: "Sites Surveyed", value: summary ? summary.sites_surveyed.toString() : "...", icon: Search, variant: "info" as const },
    { title: "Active Certificates", value: summary ? summary.active_certificates.toString() : "...", icon: ShieldCheck, variant: "success" as const },
    { title: "Weak Cryptography", value: summary ? summary.weak_cryptography.toString() : "...", icon: AlertTriangle, variant: "red" as const },
    { title: "Certificate Issues", value: summary ? summary.certificate_issues.toString() : "...", icon: ShieldAlert, variant: "red" as const },
  ];

  const filteredAssets = MOCK_CBOM_ASSETS.filter(a => {
    if (pqcFilter === "All") return true;
    if (pqcFilter === "Quantum Safe" && a.pqcStatus === "quantum-safe") return true;
    if (pqcFilter === "Vulnerable" && a.pqcStatus === "vulnerable") return true;
    if (pqcFilter === "PQC Ready" && a.pqcStatus === "pqc-ready") return true;
    return false;
  });

  const handleExportJSON = () => {
    const report = {
      generated_at: new Date().toISOString(),
      domain: "securebank.com",
      total_assets: MOCK_CBOM_ASSETS.length,
      assets: MOCK_CBOM_ASSETS.map(a => ({
        name: a.assetName,
        url: a.url,
        tls_version: a.tlsVersion,
        cipher_suite: a.cipherSuite,
        key_exchange: a.keyExchange,
        certificate_authority: a.ca,
        key_length: a.keyLength,
        cert_expiry: a.certExpiry,
        pqc_status: a.pqcStatus,
        hndl_risk: a.hndlRisk,
        recommended_migration: a.recommendedMigration
      })),
      summary: {
        quantum_safe: MOCK_CBOM_ASSETS.filter(a => a.pqcStatus === "quantum-safe").length,
        pqc_ready: MOCK_CBOM_ASSETS.filter(a => a.pqcStatus === "pqc-ready").length,
        vulnerable: MOCK_CBOM_ASSETS.filter(a => a.pqcStatus === "vulnerable").length,
        hndl_risk: MOCK_CBOM_ASSETS.filter(a => a.hndlRisk).length
      }
    };
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const el = document.createElement("a");
    el.setAttribute("href", dataStr);
    el.setAttribute("download", "cbom_report.json");
    document.body.appendChild(el);
    el.click();
    el.remove();
  };
  
  const handleExportCSV = () => {
    const headers = [
      "Asset Name", "URL", "Asset Type", "TLS Version", "Key Exchange",
      "Cipher Suite", "Certificate Authority", "Key Length", "Cert Expiry",
      "PQC Status", "HNDL Risk", "Recommended Migration"
    ];
    const rows = MOCK_CBOM_ASSETS.map(a => [
      a.assetName, a.url, a.assetType, a.tlsVersion, a.keyExchange,
      a.cipherSuite, a.ca, a.keyLength, a.certExpiry, a.pqcStatus,
      a.hndlRisk ? "Yes" : "No", a.recommendedMigration
    ].map(str => `"${String(str).replace(/"/g, '""')}"`).join(","));
    
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows].join("\n");
    const encodedUri = encodeURI(csvContent);
    const el = document.createElement("a");
    el.setAttribute("href", encodedUri);
    el.setAttribute("download", "cbom_report.csv");
    document.body.appendChild(el);
    el.click();
    el.remove();
  };

  const handleExportPDF = () => {
    window.print();
  };

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
            <p><strong>CBOM Generated:</strong> {new Date().toLocaleString()}</p>
            <p><strong>Domain scanned:</strong> securebank.com</p>
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

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6 no-print">
        {/* PQC Status */}
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

      {/* ── Cipher Usage ────────────────────────────────────────────── */}
      <div className="rounded-xl border border-border bg-card p-5 no-print">
        <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">Cipher Usage</h3>
        <div className="space-y-3">
          {CIPHER_USAGE.map((cipher) => {
            const pct = Math.round((cipher.count / CIPHER_MAX) * 100);
            const barColor = cipher.weak ? "#A20E37" : "#FBBC09";
            return (
              <div
                key={cipher.name}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg ${
                  cipher.weak ? "bg-[#A20E37]/10 border border-[#A20E37]/20" : ""
                }`}
              >
                <span
                  className="text-xs font-mono flex-1 min-w-0 truncate"
                  style={{ color: cipher.weak ? "#A20E37" : "hsl(var(--foreground))" }}
                  title={cipher.name}
                >
                  {cipher.name}
                  {cipher.weak && (
                    <span className="ml-2 text-[10px] font-sans font-semibold px-1.5 py-0.5 rounded bg-[#A20E37]/20 text-[#A20E37]">
                      WEAK
                    </span>
                  )}
                </span>
                <div className="w-40 h-3 rounded-full bg-secondary overflow-hidden flex-shrink-0">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${pct}%`, backgroundColor: barColor }}
                  />
                </div>
                <span
                  className="text-xs font-bold w-6 text-right flex-shrink-0"
                  style={{ color: barColor }}
                >
                  {cipher.count}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Export Controls & Inventory Table */}
      <div className="rounded-xl border border-border bg-card p-6">
        
        {/* Print Header */}
        <div className="hidden print:block mb-8 text-black">
          <div className="flex justify-between items-end border-b-2 border-black pb-4 mb-4">
            <div>
              <h1 className="text-3xl font-bold">PNB × QSCAS</h1>
              <h2 className="text-xl mt-1 text-gray-700">Cryptographic Bill of Materials (CBOM)</h2>
            </div>
            <div className="text-right text-sm text-gray-600">
              <p>Generated: {new Date().toLocaleDateString()}</p>
              <p>Domain: securebank.com</p>
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

            <div className="flex gap-2">
              <Button onClick={handleExportJSON} variant="outline" className="gap-2">
                <Download className="w-4 h-4" /> Export JSON
              </Button>
              <Button onClick={handleExportCSV} variant="outline" className="gap-2">
                <Download className="w-4 h-4" /> Export CSV
              </Button>
              <Button onClick={handleExportPDF} className="gap-2 bg-primary">
                <Download className="w-4 h-4" /> Export PDF
              </Button>
            </div>
          </div>
        </div>

        <DataTable
          searchable
          pageSize={10}
          data={filteredAssets}
          columns={[
            { key: "assetName", header: "Asset Name" },
            { key: "url", header: "URL / Endpoint" },
            { key: "assetType", header: "Asset Type" },
            { key: "tlsVersion", header: "TLS Version" },
            { key: "keyExchange", header: "Key Exchange" },
            { key: "cipherSuite", header: "Cipher Suite" },
            { key: "ca", header: "Cert Authority" },
            { key: "keyLength", header: "Key Length" },
            { key: "certExpiry", header: "Cert Expiry" },
            { 
              key: "pqcStatus", 
              header: "PQC Status", 
              render: (r) => <PQCBadge status={r.pqcStatus as PQCStatus} /> 
            },
            { 
              key: "hndlRisk", 
              header: "HNDL Risk", 
              render: (r) => r.hndlRisk ? <Badge className="bg-[#A20E37]/15 text-[#A20E37] border-[#A20E37]/20 uppercase text-[10px]">Yes</Badge> : <Badge className="bg-success/15 text-success border-success/20 uppercase text-[10px]">No</Badge> 
            },
            { key: "recommendedMigration", header: "Recommended Migration" },
          ]}
        />
      </div>

      {/* ── Per-Application CBOM Table (CERT-IN Compliance) ────────── */}
      <div className="rounded-xl border border-border bg-card overflow-hidden no-print">
        <div className="px-6 py-4 border-b border-border">
          <h3 className="text-sm font-bold text-foreground uppercase tracking-wide">Per-Application CBOM</h3>
          <p className="text-xs text-muted-foreground mt-0.5">CERT-IN compliance fields — Algorithm OID, Key State, Key Creation Date, Signature Algorithm</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr style={{ backgroundColor: "#FBBC09" }}>
                {["Application","Key Length","Cipher Suite","Certificate Authority","Algorithm OID","Key State","Key Creation Date","Signature Algorithm"].map((h) => (
                  <th key={h} className="px-4 py-3 text-left font-bold uppercase tracking-wide" style={{ color: "#111" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {PER_APP_CBOM.map((row, i) => (
                <tr
                  key={i}
                  className="border-b border-border/40 hover:opacity-90 transition-opacity"
                  style={{
                    backgroundColor: row.weak
                      ? "rgba(162,14,55,0.10)"
                      : i % 2 === 0
                      ? "rgba(251,188,9,0.04)"
                      : "transparent",
                  }}
                >
                  <td className="px-4 py-2.5 font-mono text-foreground">{row.application}</td>
                  <td className="px-4 py-2.5 font-mono" style={{ color: row.keyLength === "1024-Bit" ? "#A20E37" : "inherit" }}>{row.keyLength}</td>
                  <td className="px-4 py-2.5 font-mono max-w-[180px] truncate" style={{ color: row.weak ? "#A20E37" : "inherit" }} title={row.cipher}>{row.cipher}</td>
                  <td className="px-4 py-2.5">{row.ca}</td>
                  <td className="px-4 py-2.5 font-mono text-muted-foreground">{row.algorithmOid}</td>
                  <td className="px-4 py-2.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                      row.keyState === "Active"
                        ? "bg-green-500/15 text-green-400"
                        : row.keyState === "Revoked"
                        ? "bg-[#A20E37]/15 text-[#A20E37]"
                        : "bg-yellow-500/15 text-yellow-400"
                    }`}>{row.keyState}</span>
                  </td>
                  <td className="px-4 py-2.5 text-muted-foreground">{row.keyCreationDate}</td>
                  <td className="px-4 py-2.5 font-mono text-muted-foreground">{row.sigAlgorithm}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
