import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Server,
  Globe,
  Code,
  HardDrive,
  AlertTriangle,
  ShieldAlert,
  Search,
  Loader2,
} from "lucide-react";
import { StatCard } from "@/components/dashboard/StatCard";
import { DataTable } from "@/components/dashboard/DataTable";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  dashboardService,
  assetService,
  dnsService,
  cryptoService,
} from "@/services/api";
import { toast } from "sonner";
import { useWebSocket } from "@/hooks/useWebSocket";
import { LiveScanConsole } from "@/components/dashboard/LiveScanConsole";
import { PQCBadge, determinePQCStatus, PQCStatus } from "@/components/ui/PQCBadge";
import { HNDLAlert } from "@/components/ui/HNDLAlert";
import { useScan } from "@/hooks/useScan";
import { ScanProgressBar } from "@/components/dashboard/ScanProgressBar";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

const CHART_COLORS = [
  "hsl(45, 96%, 51%)",
  "hsl(342, 88%, 35%)",
  "hsl(152, 60%, 45%)",
  "hsl(210, 80%, 55%)",
  "hsl(280, 60%, 55%)",
];

const TOOLTIP_STYLE = {
  contentStyle: {
    background: "hsl(220, 18%, 13%)",
    border: "1px solid hsl(220, 14%, 20%)",
    borderRadius: "8px",
    fontSize: "12px",
    color: "hsl(210, 20%, 92%)",
  },
};



const riskBadge = (risk: string) => {
  if (!risk) return null;
  const colors: Record<string, string> = {
    Critical: "bg-accent/20 text-accent border-accent/30",
    High: "bg-accent/15 text-accent border-accent/20",
    Medium: "bg-warning/15 text-warning border-warning/20",
    Low: "bg-success/15 text-success border-success/20",
  };
  return (
    <Badge variant="outline" className={`text-[10px] ${colors[risk] || ""}`}>
      {risk}
    </Badge>
  );
};

const certBadge = (status: string) => {
  if (!status) return null;
  const colors: Record<string, string> = {
    Valid: "bg-success/15 text-success border-success/20",
    Expiring: "bg-warning/15 text-warning border-warning/20",
    Expired: "bg-accent/15 text-accent border-accent/20",
  };
  return (
    <Badge variant="outline" className={`text-[10px] ${colors[status] || ""}`}>
      {status}
    </Badge>
  );
};

function inferAssetTypeFromPorts(ports: number[]) {
  const p = new Set(ports || []);
  if (p.has(443) || p.has(8443) || p.has(80) || p.has(8080)) return "Web App";
  if (p.has(22) || p.has(3389)) return "Server";
  return "Other";
}

const isHNDLVulnerable = (keyLength?: string, cipherSuite?: string) => {
  const kl = (keyLength || "").toUpperCase();
  const cs = (cipherSuite || "").toUpperCase();
  return kl.includes("RSA") || cs.includes("ECDH") || cs.includes("ECDSA");
};

export default function Dashboard() {
  const [domain, setDomain] = useState("");
  const [scannedDomain, setScannedDomain] = useState("");
  
  const [summary, setSummary] = useState<any>(null);
  const [distributionData, setDistributionData] = useState<any[]>([]);
  const [assetInventoryData, setAssetInventoryData] = useState<any[]>([]);
  const [nameServerData, setNameServerData] = useState<any[]>([]);
  const [cryptoSecurityData, setCryptoSecurityData] = useState<any[]>([]);
  
  const [hndlCount, setHndlCount] = useState(0);
  const [totalAssetsCount, setTotalAssetsCount] = useState(0);
  
  // Chart and Feed States
  const [certExpiryData, setCertExpiryData] = useState<any[]>([]);
  const [ipVersionData, setIpVersionData] = useState<any[]>([]);
  const [assetRiskData, setAssetRiskData] = useState<any[]>([]);
  const [activityFeed, setActivityFeed] = useState<any[]>([]);
  const [geoPins, setGeoPins] = useState<any[]>([]);

  const { isScanning, stageIndex, results, error, startScan } = useScan();

  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [isConsoleOpen, setIsConsoleOpen] = useState(false);
  const { messages, clearMessages } = useWebSocket(activeScanId);

  useEffect(() => {
    if (messages.length > 0) {
      const lastMsg = messages[messages.length - 1];
      
      if (lastMsg.type === 'metrics' && lastMsg.data) {
        setSummary((prev: any) => ({ ...prev, ...lastMsg.data }));
      }

      if (lastMsg.type === 'data' && lastMsg.assets) {
        const v1Assets = lastMsg.assets;
        setAssetInventoryData(
          v1Assets.slice(0, 5).map((a: any) => ({
            name: a.subdomain,
            url: a.subdomain,
            ipv4: a.ip,
            ipv6: "N/A",
            type: inferAssetTypeFromPorts(a.open_ports),
            owner: "N/A",
            risk: "",
            certStatus: "",
            keyLength: "",
            lastScan: "",
          }))
        );
      }
    }
  }, [messages]);

  useEffect(() => {
    refreshDashboardData();
  }, []);

  useEffect(() => {
    if (results && results.status === "completed" && !isScanning) {
      toast.success(`Scan completed successfully for ${scannedDomain}!`);
      refreshDashboardData(results);
    } else if (error) {
      toast.error(error);
    }
  }, [results, isScanning, error]);

  const refreshDashboardData = async (v1FallbackPayload: any = null) => {
    try {
      const [sumRes, assetRes, dnsRes, cryptoRes, distRes] = await Promise.all([
        dashboardService.getSummary().catch(() => ({ data: null })),
        assetService.getAll({ page_size: 100 }).catch(() => ({ data: { items: [] } })),
        dnsService.getNameServerRecords().catch(() => ({ data: [] })),
        cryptoService.getCryptoSecurityData().catch(() => ({ data: [] })),
        assetService.getDistribution().catch(() => ({ data: [] }))
      ]);

      if (sumRes.data) setSummary(sumRes.data);
      if (dnsRes.data) setNameServerData(dnsRes.data);
      if (distRes.data) setDistributionData(distRes.data);
      
      const assets = assetRes.data?.items || [];
      const formattedInventory = assets.slice(0, 5).map((a: any) => ({
        name: a.asset_name,
        url: a.url,
        ipv4: a.ipv4,
        ipv6: a.ipv6,
        type: a.type || "Unknown",
        owner: a.owner || "",
        risk: a.risk || "",
        certStatus: a.certificate_status || "",
        keyLength: a.key_length && a.key_length !== "None" ? `${a.key_length}`.includes("-bit") ? a.key_length : `${a.key_length}-bit` : "",
        lastScan: a.last_scan ? new Date(a.last_scan).toLocaleDateString() : "",
        pqcStatus: determinePQCStatus(a.tls_version, a.cipher_suite, a.key_length?.toString()),
        hndlRisk: isHNDLVulnerable(a.key_length?.toString(), a.cipher_suite),
      }));
      setAssetInventoryData(formattedInventory);

      let hCount = 0;
      assets.forEach((a: any) => {
        if (isHNDLVulnerable(a.key_length?.toString(), a.cipher_suite)) {
          hCount++;
        }
      });
      setHndlCount(hCount);
      setTotalAssetsCount(assets.length);
      
      // IP Version Distribution
      const ipv4Count = assets.filter((a: any) => a.ipv4 && !a.ipv6).length;
      const ipv6Count = assets.filter((a: any) => a.ipv6).length;
      const ipData = [];
      if (ipv4Count > 0) ipData.push({ name: "IPv4", value: Math.round((ipv4Count / assets.length) * 100), color: "hsl(210, 80%, 55%)" });
      if (ipv6Count > 0) ipData.push({ name: "IPv6", value: Math.round((ipv6Count / assets.length) * 100), color: "hsl(280, 60%, 55%)" });
      setIpVersionData(ipData);

      // Asset Risk Distribution
      const riskCounts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
      assets.forEach((a: any) => {
        const r = a.risk || "Low";
        if (riskCounts[r] !== undefined) riskCounts[r]++;
      });
      const riskColors: Record<string, string> = { Critical: "hsl(342, 88%, 35%)", High: "hsl(45, 96%, 51%)", Medium: "hsl(210, 80%, 55%)", Low: "hsl(152, 60%, 45%)" };
      setAssetRiskData(Object.keys(riskCounts).map(k => ({ name: k, count: riskCounts[k], color: riskColors[k] })));

      // Cert Expiry (Mock derived from status for now)
      const expiryCounts: Record<string, number> = { "Expired": 0, "Soon": 0, "Valid": 0 };
      assets.forEach((a: any) => {
        if (a.certificate_status === "expired") expiryCounts["Expired"]++;
        else if (a.certificate_status === "expiring_soon") expiryCounts["Soon"]++;
        else expiryCounts["Valid"]++;
      });
      setCertExpiryData([
        { name: "30 Days", count: expiryCounts["Soon"], color: "hsl(45, 96%, 51%)" },
        { name: "90 Days", count: expiryCounts["Valid"], color: "hsl(210, 80%, 55%)" },
        { name: "Expired", count: expiryCounts["Expired"], color: "hsl(342, 88%, 35%)" },
      ]);
      
      if (cryptoRes.data) {
        const cryptoRecords = cryptoRes.data.map((c: any) => ({
          asset: c.asset,
          keyLength: c.key_length && c.key_length !== "None" ? `${c.key_length}`.includes("-bit") ? c.key_length : `${c.key_length}-bit` : "Unknown",
          cipherSuite: c.cipher_suite || "Unknown",
          tlsVersion: c.tls_version || "",
          ca: c.certificate_authority || "",
          pqcStatus: determinePQCStatus(c.tls_version, c.cipher_suite, c.key_length?.toString()),
        }));
        setCryptoSecurityData(cryptoRecords.slice(0, 5));
      }

      if (!assets.length && v1FallbackPayload) {
        applyV1Fallback(v1FallbackPayload);
      }
    } catch (err) {
      console.error("Could not refresh dashboard data", err);
    }
  };

  const applyV1Fallback = (v1: any) => {
    const v1Assets = Array.isArray(v1.assets) ? v1.assets : [];
    const v1Tls = Array.isArray(v1.tls_results) ? v1.tls_results : [];

    const expiring = v1Tls.filter((t: any) => {
      const days = t?.certificate?.days_until_expiry;
      return typeof days === "number" && days <= 30 && days >= 0;
    }).length;
    const highRisk = Array.isArray(v1.cbom)
      ? v1.cbom.filter((c: any) => ["critical", "high"].includes(String(c?.risk_level))).length
      : 0;

    setSummary((prev: any) => prev ?? {
      total_assets: v1Assets.length,
      public_web_apps: v1Assets.filter((a: any) => inferAssetTypeFromPorts(a.open_ports) === "Web App").length,
      apis: 0,
      servers: v1Assets.filter((a: any) => inferAssetTypeFromPorts(a.open_ports) === "Server").length,
      expiring_certificates: expiring,
      high_risk_assets: highRisk,
    });

    setAssetInventoryData(
      v1Assets.slice(0, 5).map((a: any) => {
        const tls = v1Tls.find((t: any) => t.host === a.subdomain) || {};
        return {
          name: a.subdomain,
          url: a.subdomain,
          ipv4: a.ip,
          ipv6: "N/A",
          type: inferAssetTypeFromPorts(a.open_ports),
          owner: "N/A",
          risk: (v1?.quantum_score?.risk_level || "").toString(),
          certStatus: "",
          keyLength: "",
          lastScan: v1.completed_at ? new Date(v1.completed_at).toLocaleDateString() : "",
          pqcStatus: determinePQCStatus(tls.tls_version, tls.cipher_suite, tls.certificate?.public_key_size?.toString()),
          hndlRisk: isHNDLVulnerable(tls.certificate?.public_key_size?.toString(), tls.cipher_suite),
        };
      })
    );
    
    let hCount3 = 0;
    v1Assets.forEach((a: any) => {
      const tls = v1Tls.find((t: any) => t.host === a.subdomain) || {};
      if (isHNDLVulnerable(tls.certificate?.public_key_size?.toString(), tls.cipher_suite)) hCount3++;
    });
    setHndlCount(hCount3);
    setTotalAssetsCount(v1Assets.length);

    const distCount: Record<string, number> = {};
    v1Assets.forEach((a: any) => {
      const t = inferAssetTypeFromPorts(a.open_ports);
      distCount[t] = (distCount[t] || 0) + 1;
    });
    const distArray = Object.keys(distCount).map((k) => ({ name: k, value: distCount[k] }));
    setDistributionData(distArray.length > 0 ? distArray : [{ name: "No Data", value: 1 }]);

    setCryptoSecurityData(
      v1Tls.slice(0, 5).map((t: any) => ({
        asset: `${t.host}:${t.port}`,
        keyLength: t?.certificate?.public_key_size ? `${t.certificate.public_key_size}-bit` : "Unknown",
        cipherSuite: t.cipher_suite || "Unknown",
        tlsVersion: t.tls_version || "Unknown",
        ca: t?.certificate?.issuer || "Unknown",
        pqcStatus: determinePQCStatus(t.tls_version, t.cipher_suite, t.certificate?.public_key_size?.toString()),
      }))
    );
  };

  const stats = [
    { title: "Total Assets", value: summary ? summary.total_assets.toString() : "...", icon: Server, variant: "gold" as const },
    { title: "Web Applications", value: summary ? summary.public_web_apps.toString() : "...", icon: Globe, variant: "default" as const },
    { title: "APIs", value: summary ? summary.apis.toString() : "...", icon: Code, variant: "info" as const },
    { title: "Servers", value: summary ? summary.servers.toString() : "...", icon: HardDrive, variant: "default" as const },
    { title: "Expiring Certs", value: summary ? summary.expiring_certificates.toString() : "...", icon: AlertTriangle, variant: "red" as const },
    { title: "High Risk Assets", value: summary ? summary.high_risk_assets.toString() : "...", icon: ShieldAlert, variant: "red" as const },
    { title: "HNDL Vulnerable", value: hndlCount.toString(), icon: AlertTriangle, variant: "red" as const },
  ];

  const handleScan = async () => {
    if (domain.trim() && !isScanning) {
      const targetDomain = domain.trim();
      setScannedDomain(targetDomain);
      clearMessages();
      setIsConsoleOpen(true);
      
      // Need to simulate a scan ID if no web socket returns one immediately
      setActiveScanId("pending..."); 
      
      await startScan(targetDomain);
    }
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <h1 className="text-2xl font-bold text-foreground">Dashboard</h1>
        <p className="text-sm text-muted-foreground">Security overview and asset monitoring</p>
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
          <Button onClick={handleScan} disabled={isScanning} className="bg-primary text-primary-foreground hover:bg-primary/90 px-6">
            {isScanning && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            Scan
          </Button>
        </div>
        {!isScanning && scannedDomain && stageIndex >= 5 && (
          <p className="text-xs text-muted-foreground mt-2">
            Scan results available for: <span className="text-primary font-medium">{scannedDomain}</span>.
          </p>
        )}
      </div>

      <ScanProgressBar isScanning={isScanning} stageIndex={stageIndex} targetDomain={scannedDomain} />
      
      {hndlCount > 0 && (
        <HNDLAlert 
          description={
            <span>
              <strong>{hndlCount} out of {totalAssetsCount}</strong> scanned assets are currently vulnerable to Harvest Now, Decrypt Later (HNDL) attacks. They use legacy asymmetric cryptography (RSA/ECC) for key exchange. Adversaries may be harvesting encrypted traffic today for future quantum decryption.
            </span>
          } 
        />
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-7 gap-4">
        {stats.map((s, i) => (
          <motion.div key={s.title} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
            <StatCard {...s} />
          </motion.div>
        ))}
      </div>

      {/* No scan yet banner */}
      {summary && summary.total_assets === 0 && (
        <div className="rounded-xl border border-primary/30 bg-primary/5 p-4 flex items-center gap-3">
          <Search className="h-5 w-5 text-primary flex-shrink-0" />
          <div>
            <p className="text-sm font-semibold text-foreground">No scan data yet</p>
            <p className="text-xs text-muted-foreground">Enter a domain above and click Scan to discover assets and populate this dashboard.</p>
          </div>
        </div>
      )}

      {/* Charts Row — 4 cols */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">
        {/* Chart 1 — Assets Distribution (existing donut) */}
        <div className="rounded-xl border border-border bg-card p-5 relative">
          {isScanning && (
            <div className="absolute inset-0 bg-card/80 backdrop-blur-sm z-20 rounded-xl flex items-center justify-center">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          )}
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-3">Assets Distribution</h3>
          {distributionData.length === 0 ? (
            <div className="flex items-center justify-center h-[220px]">
              <p className="text-sm text-muted-foreground text-center">Scan a domain to see asset distribution</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={distributionData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value">
                  {distributionData.map((_, i) => (
                    <Cell key={`cell-${i}`} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip {...TOOLTIP_STYLE} />
                <Legend wrapperStyle={{ fontSize: "10px", color: "hsl(215, 15%, 55%)" }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-3">IP Version Breakdown</h3>
          {ipVersionData.length === 0 ? (
            <div className="flex items-center justify-center h-[220px]">
              <p className="text-sm text-muted-foreground text-center">Scan a domain to see IP breakdown</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={ipVersionData}
                  cx="50%" cy="50%"
                  innerRadius={55} outerRadius={80}
                  dataKey="value"
                  strokeWidth={2}
                  stroke="hsl(220,22%,10%)"
                  label={({ cx, cy, value, name }) => (
                    <>
                      <text x={cx} y={cy - 6} textAnchor="middle" fill="white" fontSize={22} fontWeight={700}>{value}%</text>
                      <text x={cx} y={cy + 14} textAnchor="middle" fill="hsl(215,15%,55%)" fontSize={10}>{name}</text>
                    </>
                  )}
                  labelLine={false}
                >
                  {ipVersionData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Tooltip {...TOOLTIP_STYLE} formatter={(v: number) => [`${v}%`]} />
                <Legend wrapperStyle={{ fontSize: "10px", color: "hsl(215,15%,55%)" }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-3">Cert Expiry Timeline</h3>
          {certExpiryData.every(d => d.count === 0) ? (
            <div className="flex items-center justify-center h-[220px]">
              <p className="text-sm text-muted-foreground text-center">Scan a domain to see expiry timeline</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={certExpiryData} layout="vertical" margin={{ top: 0, right: 24, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(220,14%,20%)" horizontal={false} />
                <XAxis type="number" tick={{ fill: "hsl(215,15%,55%)", fontSize: 10 }} />
                <YAxis type="category" dataKey="name" tick={{ fill: "hsl(215,15%,55%)", fontSize: 10 }} width={72} />
                <Tooltip {...TOOLTIP_STYLE} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {certExpiryData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-3">Asset Risk Distribution</h3>
          {assetRiskData.every(d => d.count === 0) ? (
            <div className="flex items-center justify-center h-[220px]">
              <p className="text-sm text-muted-foreground text-center">Scan a domain to see risk levels</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={assetRiskData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(220,14%,20%)" />
                <XAxis dataKey="name" tick={{ fill: "hsl(215,15%,55%)", fontSize: 10 }} />
                <YAxis tick={{ fill: "hsl(215,15%,55%)", fontSize: 10 }} />
                <Tooltip {...TOOLTIP_STYLE} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {assetRiskData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Asset Inventory Table */}
      <div className="relative">
        {isScanning && (
          <div className="absolute inset-0 bg-card/80 backdrop-blur-sm z-20 rounded-xl flex flex-col gap-4 p-8">
            <Skeleton className="h-10 w-full" /><Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" /><Skeleton className="h-10 w-full" />
          </div>
        )}
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          {/* Custom header with Add Asset + Scan All */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-border flex-wrap gap-3">
            <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide">Assets Inventory</h3>
            <div className="flex items-center gap-2">
              <button
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg border transition-colors"
                style={{ borderColor: "#FBBC09", color: "#FBBC09" }}
              >
                + Add Asset ▾
              </button>
              <button
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold rounded-lg transition-colors"
                style={{ backgroundColor: "#FBBC09", color: "#111" }}
                onClick={handleScan}
                disabled={isScanning}
              >
                ⟳ Scan All
              </button>
            </div>
          </div>
          <DataTable
            searchable
            data={assetInventoryData}
            columns={[
              { key: "name", header: "Asset Name" },
              { key: "url", header: "URL" },
              { key: "ipv4", header: "IPv4" },
              { key: "type", header: "Type" },
              { key: "owner", header: "Owner" },
              { key: "risk", header: "Risk", render: (r) => riskBadge(r.risk as string) },
              { key: "hndlRisk", header: "HNDL Risk", render: (r) => r.hndlRisk ? <Badge className="bg-[#A20E37]/15 text-[#A20E37] border-[#A20E37]/20 uppercase text-[10px]">Yes</Badge> : <Badge className="bg-success/15 text-success border-success/20 uppercase text-[10px]">No</Badge> },
              { key: "certStatus", header: "Cert Status", render: (r) => certBadge(r.certStatus as string) },
              { key: "pqcStatus", header: "PQC Status", render: (r) => <PQCBadge status={r.pqcStatus as PQCStatus} /> },
            ]}
          />
        </div>
      </div>

      {/* Name Server + Crypto */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 relative">
        {isScanning && (
          <div className="absolute inset-0 bg-card/80 backdrop-blur-sm z-20 rounded-xl flex items-center justify-center gap-4 p-8">
            <Loader2 className="w-10 h-10 animate-spin text-primary" />
          </div>
        )}
        <DataTable
          title="Name Server Records"
          data={nameServerData}
          columns={[
            { key: "hostname", header: "Hostname" },
            { key: "type", header: "Type" },
            { key: "ip_address", header: "IP Address" },
            { key: "ttl", header: "TTL" },
          ]}
        />
        <DataTable
          title="Crypto & Security Overview"
          data={cryptoSecurityData}
          columns={[
            { key: "asset", header: "Asset" },
            { key: "keyLength", header: "Key Length" },
            { key: "cipherSuite", header: "Cipher Suite" },
            { key: "tlsVersion", header: "TLS Version" },
            { key: "ca", header: "Certificate Authority" },
            { key: "pqcStatus", header: "PQC Status", render: (r) => <PQCBadge status={r.pqcStatus as PQCStatus} /> },
          ]}
        />
      </div>

      {/* Activity Feed + Geo Map */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <div className="xl:col-span-1 rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">Recent Scans &amp; Activity</h3>
          {activityFeed.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-[200px] text-center">
              <p className="text-xs text-muted-foreground">No recent activity found.<br/>Activity will appear here after your first scan.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {activityFeed.map((item, i) => (
                <div
                  key={i}
                  className="flex items-start gap-3 p-3 rounded-lg"
                  style={{ backgroundColor: `${item.color}10`, border: `1px solid ${item.color}25` }}
                >
                  <span className="text-lg leading-none flex-shrink-0" style={{ color: item.color }}>{item.icon}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-foreground font-medium truncate">{item.msg}</p>
                    <p className="text-[10px] text-muted-foreground mt-0.5">{item.time}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="xl:col-span-2 rounded-xl border border-border bg-card p-5 overflow-hidden">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">Geographic Asset Distribution</h3>
          <div className="relative w-full rounded-lg overflow-hidden" style={{ height: 200, backgroundColor: "hsl(220,22%,10%)" }}>
            {/* Simple SVG world outline */}
            <svg viewBox="0 0 800 400" className="absolute inset-0 w-full h-full opacity-20">
              <polygon points="80,80 200,70 220,160 160,200 80,180" fill="hsl(220,14%,40%)" />
              <polygon points="160,210 210,200 230,300 180,340 130,300" fill="hsl(220,14%,40%)" />
              <polygon points="340,70 430,65 440,140 370,150 330,120" fill="hsl(220,14%,40%)" />
              <polygon points="350,155 430,145 450,280 390,320 330,280 330,200" fill="hsl(220,14%,40%)" />
              <polygon points="440,60 680,55 700,200 600,230 460,200 430,130" fill="hsl(220,14%,40%)" />
              <polygon points="600,250 700,245 710,310 640,330 590,300" fill="hsl(220,14%,40%)" />
            </svg>

            {/* City pins */}
            {geoPins.length === 0 ? (
              <div className="absolute inset-0 flex items-center justify-center">
                <p className="text-xs text-muted-foreground">Scan assets to see geographic distribution</p>
              </div>
            ) : (
              geoPins.map((pin) => (
                <div
                  key={pin.city}
                  className="absolute flex flex-col items-center"
                  style={{ left: pin.x, top: pin.y, transform: "translate(-50%,-100%)" }}
                >
                  <div
                    className="w-3 h-3 rounded-full border-2 border-white shadow-lg"
                    style={{ backgroundColor: "#FBBC09" }}
                  />
                  <div
                    className="mt-1 px-1.5 py-0.5 rounded text-[9px] font-bold whitespace-nowrap"
                    style={{ backgroundColor: "#FBBC09", color: "#111" }}
                  >
                    {pin.city}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <LiveScanConsole
        isOpen={isConsoleOpen}
        onClose={() => setIsConsoleOpen(false)}
        messages={messages}
        scanId={activeScanId}
      />
    </div>
  );
}
