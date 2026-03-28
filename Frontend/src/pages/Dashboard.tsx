import { useState, useEffect, type ReactNode } from "react";
import { Link } from "react-router-dom";
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
  Layers,
  ScrollText,
  ListTodo,
} from "lucide-react";
import { StatCard } from "@/components/dashboard/StatCard";
import { DataTable } from "@/components/dashboard/DataTable";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import {
  dashboardService,
  assetService,
  dnsService,
  cryptoService,
  scanService,
  type ScanControllerPayload,
} from "@/services/api";
import { ThreatModelPanel } from "@/components/dashboard/ThreatModelPanel";
import { toast } from "sonner";
import { useWebSocket } from "@/hooks/useWebSocket";
import { LiveScanConsole } from "@/components/dashboard/LiveScanConsole";
import { PQCBadge, determinePQCStatus, hndlRiskFromCrypto, PQCStatus } from "@/components/ui/PQCBadge";
import { HNDLAlert } from "@/components/ui/HNDLAlert";
import { useScan } from "@/hooks/useScan";
import { ScanProgressBar } from "@/components/dashboard/ScanProgressBar";
import { DossierPageHeader } from "@/components/layout/DossierPageHeader";
import { setLastScannedDomain } from "@/lib/lastScanDomain";
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

/** Gradient pairs for donuts / bars — enterprise blue + semantic accents */
const DIST_GRADIENT_STOPS: { from: string; to: string }[] = [
  { from: "#38bdf8", to: "#2563eb" },
  { from: "#c084fc", to: "#7c3aed" },
  { from: "#4ade80", to: "#16a34a" },
  { from: "#fbbf24", to: "#d97706" },
  { from: "#94a3b8", to: "#475569" },
];

const CHART_TOOLTIP = {
  contentStyle: {
    background: "rgba(255,255,255,0.96)",
    border: "1px solid rgb(226 232 240)",
    borderRadius: "12px",
    fontSize: "12px",
    color: "rgb(15 23 42)",
    boxShadow: "0 10px 40px -12px rgb(15 23 42 / 0.2)",
  },
  cursor: { fill: "rgb(59 130 246 / 0.06)" },
  labelStyle: { color: "rgb(71 85 105)", fontWeight: 600 },
};

const CHART_AXIS_TICK = { fill: "rgb(100 116 139)", fontSize: 11, fontWeight: 500 };
const CHART_GRID = { stroke: "rgb(226 232 240)", strokeDasharray: "4 6" };

/** Aligned with backend `Settings.MAX_BATCH_DOMAINS` */
const MAX_BATCH_DOMAINS = 25;

/** Defaults when Controller is enabled (match `MAX_SUBDOMAINS` / `TOOL_TIMEOUT` in backend config). */
const DEFAULT_CTRL_MAX_SUBS = 50;
const DEFAULT_CTRL_EXEC_SEC = 30;

function ChartCard({
  title,
  children,
  scanning,
}: {
  title: string;
  children: ReactNode;
  scanning?: boolean;
}) {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-slate-200/90 bg-gradient-to-b from-white via-slate-50/40 to-white p-5 shadow-sm">
      {scanning && (
        <div className="absolute inset-0 z-20 flex items-center justify-center rounded-2xl bg-white/75 backdrop-blur-sm">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      )}
      <h3 className="mb-1 text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500">{title}</h3>
      {children}
    </div>
  );
}



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

/** Mirrors Backend `classify_asset_ports` → display labels for WS / v1 fallback rows */
function inferAssetTypeFromPorts(ports: number[]) {
  const p = new Set(ports || []);
  if (p.has(443) || p.has(8443) || p.has(80) || p.has(8080)) return "Web App";
  if (p.has(22) || p.has(3389) || p.has(21) || p.has(3306) || p.has(5432)) return "Server";
  return "API";
}

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

  const { isScanning, stageIndex, results, error, startScan, scanId } = useScan();

  const [initialLoadDone, setInitialLoadDone] = useState(false);
  const [isConsoleOpen, setIsConsoleOpen] = useState(false);
  const { messages, clearMessages, status: wsStatus } = useWebSocket(scanId);

  const [batchRaw, setBatchRaw] = useState("");
  const [batchBusy, setBatchBusy] = useState(false);

  const [controllerEnabled, setControllerEnabled] = useState(false);
  const [controllerMaxSubs, setControllerMaxSubs] = useState(String(DEFAULT_CTRL_MAX_SUBS));
  const [controllerExecSec, setControllerExecSec] = useState(String(DEFAULT_CTRL_EXEC_SEC));

  const [policyAlignment, setPolicyAlignment] = useState<{
    has_scan?: boolean;
    scan_domain?: string;
    policy?: { min_tls_version?: string; require_forward_secrecy?: boolean };
    alignment?: {
      tls_endpoints?: number;
      below_min_tls?: number;
      unknown_tls_version?: number;
      forward_secrecy_heuristic_flags?: number;
    };
    note?: string;
  } | null>(null);

  const [migrationSnapshot, setMigrationSnapshot] = useState<{
    open_tasks?: number;
    pending_waivers?: number;
  } | null>(null);

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
      const [sumRes, assetRes, dnsRes, cryptoRes, distRes, polRes, migRes] = await Promise.all([
        dashboardService.getSummary().catch(() => ({ data: null })),
        assetService.getAll({ page_size: 100 }).catch(() => ({ data: { items: [] } })),
        dnsService.getNameServerRecords().catch(() => ({ data: [] })),
        cryptoService.getCryptoSecurityData().catch(() => ({ data: [] })),
        assetService.getDistribution().catch(() => ({ data: [] })),
        dashboardService.getPolicyAlignment().catch(() => ({ data: null })),
        dashboardService.getMigrationSnapshot().catch(() => ({ data: null })),
      ]);

      if (sumRes.data) setSummary(sumRes.data);
      setPolicyAlignment(polRes.data ?? null);
      setMigrationSnapshot(migRes.data ?? null);
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
        hndlRisk: hndlRiskFromCrypto(a.tls_version, a.cipher_suite, a.key_length?.toString()),
      }));
      setAssetInventoryData(formattedInventory);

      let hCount = 0;
      assets.forEach((a: any) => {
        if (hndlRiskFromCrypto(a.tls_version, a.cipher_suite, a.key_length?.toString())) {
          hCount++;
        }
      });
      setHndlCount(hCount);
      setTotalAssetsCount(assets.length);
      
      // IP Version Distribution
      const ipv4Count = assets.filter((a: any) => a.ipv4 && !a.ipv6).length;
      const ipv6Count = assets.filter((a: any) => a.ipv6).length;
      const ipData = [];
      if (ipv4Count > 0)
        ipData.push({
          name: "IPv4",
          value: Math.round((ipv4Count / assets.length) * 100),
          grad: "ipv4",
        });
      if (ipv6Count > 0)
        ipData.push({
          name: "IPv6",
          value: Math.round((ipv6Count / assets.length) * 100),
          grad: "ipv6",
        });
      setIpVersionData(ipData);

      // Asset Risk Distribution
      const riskCounts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
      assets.forEach((a: any) => {
        const r = a.risk || "Low";
        if (riskCounts[r] !== undefined) riskCounts[r]++;
      });
      setAssetRiskData(
        Object.keys(riskCounts).map((k) => ({
          name: k,
          count: riskCounts[k],
          key: k,
        }))
      );

      // Cert Expiry (Mock derived from status for now)
      const expiryCounts: Record<string, number> = { "Expired": 0, "Soon": 0, "Valid": 0 };
      assets.forEach((a: any) => {
        if (a.certificate_status === "expired") expiryCounts["Expired"]++;
        else if (a.certificate_status === "expiring_soon") expiryCounts["Soon"]++;
        else expiryCounts["Valid"]++;
      });
      setCertExpiryData([
        { name: "30 Days", count: expiryCounts["Soon"], key: "soon" },
        { name: "90 Days", count: expiryCounts["Valid"], key: "valid" },
        { name: "Expired", count: expiryCounts["Expired"], key: "expired" },
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
      toast.error("Could not load dashboard data. Check the API URL and that the backend is running.");
    } finally {
      setInitialLoadDone(true);
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
          hndlRisk: hndlRiskFromCrypto(
            tls.tls_version,
            tls.cipher_suite,
            tls.certificate?.public_key_size?.toString(),
          ),
        };
      })
    );
    
    let hCount3 = 0;
    v1Assets.forEach((a: any) => {
      const tls = v1Tls.find((t: any) => t.host === a.subdomain) || {};
      if (
        hndlRiskFromCrypto(
          tls.tls_version,
          tls.cipher_suite,
          tls.certificate?.public_key_size?.toString(),
        )
      )
        hCount3++;
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
      let scanOpts: ScanControllerPayload | undefined;
      if (controllerEnabled) {
        const ms = parseInt(controllerMaxSubs, 10);
        const ex = parseInt(controllerExecSec, 10);
        if (
          !(
            Number.isFinite(ms) &&
            ms >= 1 &&
            ms <= 500 &&
            Number.isFinite(ex) &&
            ex >= 10 &&
            ex <= 900
          )
        ) {
          toast.error("Controller: subdomain limit 1–500, execution limit 10–900 seconds.");
          return;
        }
        scanOpts = { max_subdomains: ms, execution_time_limit_seconds: ex };
      }
      setScannedDomain(targetDomain);
      setLastScannedDomain(targetDomain);
      clearMessages();
      setIsConsoleOpen(true);

      await startScan(targetDomain, scanOpts);
    }
  };

  const parseBatchDomains = (raw: string) => {
    const parts = raw
      .split(/[\n,;\t]+/)
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    const seen = new Set<string>();
    const out: string[] = [];
    for (const p of parts) {
      if (!seen.has(p)) {
        seen.add(p);
        out.push(p);
      }
    }
    return out;
  };

  const handleBatchScan = async () => {
    const list = parseBatchDomains(batchRaw);
    if (list.length === 0) {
      toast.error("Add at least one domain (one per line or comma-separated).");
      return;
    }
    if (list.length > MAX_BATCH_DOMAINS) {
      toast.error(`Portfolio batch is limited to ${MAX_BATCH_DOMAINS} domains per request.`);
      return;
    }
    setBatchBusy(true);
    try {
      const res = await scanService.startBatchScan(list);
      const data = res.data as {
        batch_id?: string;
        queued?: number;
      };
      const n = data.queued ?? list.length;
      const bid = data.batch_id;
      toast.success(
        `Queued ${n} scan(s)${bid ? ` · batch ${bid.slice(0, 8)}…` : ""}. Track jobs under Inventory Runs.`,
      );
      setBatchRaw("");
    } catch (err: unknown) {
      const ax = err as { response?: { data?: { detail?: string } } };
      toast.error(ax.response?.data?.detail || "Batch scan failed.");
    } finally {
      setBatchBusy(false);
    }
  };

  return (
    <div className="space-y-8">
      <DossierPageHeader
        eyebrow="Executive intelligence summary"
        title="Overview"
        description="Enterprise-wide cryptographic resilience, live scan orchestration, and fleet posture at a glance."
      />

      {/* Domain Input */}
      <div className="dossier-card p-5">
        <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-3">Scan Domain</h3>
        <div className="flex flex-col gap-4">
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
          <div className="flex flex-col gap-3 rounded-xl border border-border/60 bg-secondary/30 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3">
              <Switch
                id="scan-controller"
                checked={controllerEnabled}
                onCheckedChange={setControllerEnabled}
                disabled={isScanning}
                aria-label="Controller"
              />
              <div>
                <Label htmlFor="scan-controller" className="cursor-pointer text-sm font-semibold text-foreground">
                  Controller
                </Label>
                <p className="text-xs text-muted-foreground">
                  Off: server defaults. On: cap subdomains and per-tool execution time.
                </p>
              </div>
            </div>
            {controllerEnabled && (
              <div className="grid w-full gap-3 sm:max-w-md sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="ctrl-max-subs" className="text-xs text-muted-foreground">
                    Subdomain scan limit
                  </Label>
                  <Input
                    id="ctrl-max-subs"
                    type="number"
                    min={1}
                    max={500}
                    value={controllerMaxSubs}
                    onChange={(e) => setControllerMaxSubs(e.target.value)}
                    disabled={isScanning}
                    className="bg-background border-border"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="ctrl-exec-sec" className="text-xs text-muted-foreground">
                    Execution time limit (seconds)
                  </Label>
                  <Input
                    id="ctrl-exec-sec"
                    type="number"
                    min={10}
                    max={900}
                    value={controllerExecSec}
                    onChange={(e) => setControllerExecSec(e.target.value)}
                    disabled={isScanning}
                    className="bg-background border-border"
                  />
                </div>
              </div>
            )}
          </div>
        </div>
        {!isScanning && scannedDomain && stageIndex >= 5 && (
          <p className="text-xs text-muted-foreground mt-2">
            Scan results available for: <span className="text-primary font-medium">{scannedDomain}</span>.{" "}
            <Link to="/security-roadmap" className="font-medium text-primary hover:underline">
              View security roadmap
            </Link>
            .
          </p>
        )}
      </div>

      <div className="dossier-card p-5">
        <div className="mb-3 flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold uppercase tracking-wide text-foreground">
              Portfolio batch scan
            </h3>
          </div>
          <Link
            to="/inventory-runs"
            className="text-xs font-medium text-blue-600 hover:text-blue-700"
          >
            Inventory Runs →
          </Link>
        </div>
        <p className="mb-3 text-xs text-muted-foreground">
          Queue up to {MAX_BATCH_DOMAINS} root domains in one request. Jobs share a global concurrency
          limit on the server (Phase 2).
        </p>
        <Textarea
          placeholder={"example.com\nbank.example.org"}
          value={batchRaw}
          onChange={(e) => setBatchRaw(e.target.value)}
          disabled={batchBusy}
          rows={4}
          className="resize-y bg-secondary/50 font-mono text-sm border-border"
        />
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <Button
            type="button"
            variant="secondary"
            onClick={handleBatchScan}
            disabled={batchBusy}
            className="border border-slate-200 bg-white hover:bg-slate-50"
          >
            {batchBusy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Queue batch
          </Button>
          <span className="text-[11px] text-muted-foreground">
            Parsed: {parseBatchDomains(batchRaw).length} domain(s)
          </span>
        </div>
      </div>

      <ScanProgressBar
        isScanning={isScanning}
        stageIndex={stageIndex}
        targetDomain={scannedDomain}
        pipelineStageLabel={
          isScanning && results && typeof (results as { current_stage?: string }).current_stage === "string"
            ? (results as { current_stage: string }).current_stage
            : null
        }
      />
      
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

      {policyAlignment?.has_scan &&
        policyAlignment.alignment &&
        (policyAlignment.alignment.tls_endpoints ?? 0) > 0 && (
          <div
            className={`flex flex-col gap-2 rounded-xl border p-4 sm:flex-row sm:items-center sm:justify-between ${
              (policyAlignment.alignment.below_min_tls ?? 0) > 0 ||
              (policyAlignment.alignment.forward_secrecy_heuristic_flags ?? 0) > 0
                ? "border-amber-300/90 bg-amber-50/95 text-amber-950"
                : "border-emerald-200/90 bg-emerald-50/80 text-emerald-950"
            }`}
          >
            <div className="flex gap-3">
              <ScrollText className="mt-0.5 h-5 w-5 shrink-0 opacity-80" aria-hidden />
              <div>
                <p className="text-sm font-semibold">Policy vs latest scan</p>
                <p className="mt-1 text-xs leading-relaxed opacity-90">
                  Target: TLS ≥ {policyAlignment.policy?.min_tls_version ?? "—"}
                  {policyAlignment.policy?.require_forward_secrecy ? " · forward secrecy on" : ""}
                  {" · "}
                  <span className="font-mono">{policyAlignment.scan_domain}</span> —{" "}
                  {policyAlignment.alignment.tls_endpoints} TLS endpoint(s):{" "}
                  <strong>{policyAlignment.alignment.below_min_tls ?? 0}</strong> below min version,{" "}
                  <strong>{policyAlignment.alignment.unknown_tls_version ?? 0}</strong> unknown version,{" "}
                  <strong>{policyAlignment.alignment.forward_secrecy_heuristic_flags ?? 0}</strong> FS heuristic
                  flags. Indicative only.
                </p>
              </div>
            </div>
            <Link
              to="/policy"
              className="shrink-0 text-xs font-semibold underline underline-offset-2 sm:ml-4"
            >
              Edit policy →
            </Link>
          </div>
        )}

      {migrationSnapshot &&
        ((migrationSnapshot.open_tasks ?? 0) > 0 || (migrationSnapshot.pending_waivers ?? 0) > 0) && (
          <div className="flex flex-col gap-2 rounded-xl border border-slate-200 bg-slate-50/90 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex gap-3">
              <ListTodo className="mt-0.5 h-5 w-5 shrink-0 text-slate-600" aria-hidden />
              <div>
                <p className="text-sm font-semibold text-slate-900">Migration queue</p>
                <p className="mt-0.5 text-xs text-slate-600">
                  <strong>{migrationSnapshot.open_tasks ?? 0}</strong> open / in-progress task(s)
                  {" · "}
                  <strong>{migrationSnapshot.pending_waivers ?? 0}</strong> waiver(s) awaiting review
                </p>
              </div>
            </div>
            <Link
              to="/migration"
              className="shrink-0 text-xs font-semibold text-slate-800 underline underline-offset-2"
            >
              Open migration planner →
            </Link>
          </div>
        )}

      {/* No scan yet banner */}
      {initialLoadDone &&
        !isScanning &&
        totalAssetsCount === 0 &&
        (!summary || (summary.total_assets ?? 0) === 0) && (
        <div className="rounded-xl border border-primary/30 bg-primary/5 p-4 flex items-center gap-3">
          <Search className="h-5 w-5 text-primary flex-shrink-0" />
          <div>
            <p className="text-sm font-semibold text-foreground">No scan data yet</p>
            <p className="text-xs text-muted-foreground">
              Enter a domain above and run Scan to discover assets. CBOM, PQC posture, and cyber rating use the same completed scan.
            </p>
          </div>
        </div>
      )}

      {/* Charts Row — 4 cols */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 xl:grid-cols-4">
        <ChartCard title="Assets Distribution" scanning={isScanning}>
          {distributionData.length === 0 ? (
            <div className="flex h-[248px] items-center justify-center">
              <p className="text-center text-sm text-muted-foreground">Scan a domain to see asset distribution</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={248}>
              <PieChart>
                <defs>
                  {distributionData.map((_, i) => {
                    const { from, to } = DIST_GRADIENT_STOPS[i % DIST_GRADIENT_STOPS.length];
                    return (
                      <linearGradient key={i} id={`dist-grad-${i}`} x1="0" y1="0" x2="1" y2="1">
                        <stop offset="0%" stopColor={from} />
                        <stop offset="100%" stopColor={to} />
                      </linearGradient>
                    );
                  })}
                </defs>
                <Pie
                  data={distributionData}
                  cx="50%"
                  cy="46%"
                  innerRadius="42%"
                  outerRadius="72%"
                  paddingAngle={2.5}
                  cornerRadius={8}
                  dataKey="value"
                  stroke="#fff"
                  strokeWidth={2}
                >
                  {distributionData.map((_, i) => (
                    <Cell key={`cell-${i}`} fill={`url(#dist-grad-${i})`} />
                  ))}
                </Pie>
                <Tooltip {...CHART_TOOLTIP} formatter={(v: number) => [v, "Assets"]} />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  iconType="circle"
                  iconSize={8}
                  formatter={(value) => <span className="text-[11px] font-medium text-slate-600">{value}</span>}
                  wrapperStyle={{ paddingTop: 8 }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard title="IP Version Breakdown">
          {ipVersionData.length === 0 ? (
            <div className="flex h-[248px] items-center justify-center">
              <p className="text-center text-sm text-muted-foreground">Scan a domain to see IP breakdown</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={248}>
              <PieChart>
                <defs>
                  <linearGradient id="ip-grad-v4" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stopColor="#60a5fa" />
                    <stop offset="100%" stopColor="#1d4ed8" />
                  </linearGradient>
                  <linearGradient id="ip-grad-v6" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stopColor="#c084fc" />
                    <stop offset="100%" stopColor="#6d28d9" />
                  </linearGradient>
                </defs>
                <Pie
                  data={ipVersionData}
                  cx="50%"
                  cy="46%"
                  innerRadius="44%"
                  outerRadius="72%"
                  paddingAngle={ipVersionData.length > 1 ? 3 : 0}
                  cornerRadius={8}
                  dataKey="value"
                  stroke="#fff"
                  strokeWidth={2}
                  label={({ cx, cy, value, name }) => (
                    <>
                      <text
                        x={cx}
                        y={cy! - 5}
                        textAnchor="middle"
                        fill="rgb(15 23 42)"
                        fontSize={20}
                        fontWeight={700}
                      >
                        {value}%
                      </text>
                      <text
                        x={cx}
                        y={cy! + 14}
                        textAnchor="middle"
                        fill="rgb(100 116 139)"
                        fontSize={11}
                        fontWeight={500}
                      >
                        {name}
                      </text>
                    </>
                  )}
                  labelLine={false}
                >
                  {ipVersionData.map((entry, i) => (
                    <Cell key={i} fill={`url(#ip-grad-${entry.grad === "ipv6" ? "v6" : "v4"})`} />
                  ))}
                </Pie>
                <Tooltip {...CHART_TOOLTIP} formatter={(v: number) => [`${v}%`, "Share"]} />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  iconType="circle"
                  iconSize={8}
                  formatter={(value) => <span className="text-[11px] font-medium text-slate-600">{value}</span>}
                  wrapperStyle={{ paddingTop: 8 }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard title="Cert Expiry Timeline">
          {certExpiryData.every((d) => d.count === 0) ? (
            <div className="flex h-[248px] items-center justify-center">
              <p className="text-center text-sm text-muted-foreground">Scan a domain to see expiry timeline</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={248}>
              <BarChart
                data={certExpiryData}
                layout="vertical"
                margin={{ top: 4, right: 16, left: 4, bottom: 4 }}
                barCategoryGap={18}
              >
                <defs>
                  <linearGradient id="cert-grad-soon" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#fcd34d" />
                    <stop offset="100%" stopColor="#ea580c" />
                  </linearGradient>
                  <linearGradient id="cert-grad-valid" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#7dd3fc" />
                    <stop offset="100%" stopColor="#2563eb" />
                  </linearGradient>
                  <linearGradient id="cert-grad-expired" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#fb7185" />
                    <stop offset="100%" stopColor="#be123c" />
                  </linearGradient>
                </defs>
                <CartesianGrid {...CHART_GRID} horizontal={false} vertical />
                <XAxis
                  type="number"
                  tick={CHART_AXIS_TICK}
                  tickLine={false}
                  axisLine={{ stroke: "rgb(203 213 225)" }}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  tick={CHART_AXIS_TICK}
                  width={76}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip {...CHART_TOOLTIP} formatter={(v: number) => [v, "Certificates"]} />
                <Bar dataKey="count" radius={[0, 10, 10, 0]} barSize={20} animationDuration={600}>
                  {certExpiryData.map((entry) => (
                    <Cell key={entry.key} fill={`url(#cert-grad-${entry.key})`} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard title="Asset Risk Distribution">
          {assetRiskData.every((d) => d.count === 0) ? (
            <div className="flex h-[248px] items-center justify-center">
              <p className="text-center text-sm text-muted-foreground">Scan a domain to see risk levels</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={248}>
              <BarChart
                data={assetRiskData}
                margin={{ top: 12, right: 8, left: -8, bottom: 4 }}
                barCategoryGap="22%"
              >
                <defs>
                  <linearGradient id="risk-grad-Critical" x1="0" y1="1" x2="0" y2="0">
                    <stop offset="0%" stopColor="#fecaca" />
                    <stop offset="100%" stopColor="#dc2626" />
                  </linearGradient>
                  <linearGradient id="risk-grad-High" x1="0" y1="1" x2="0" y2="0">
                    <stop offset="0%" stopColor="#fed7aa" />
                    <stop offset="100%" stopColor="#ea580c" />
                  </linearGradient>
                  <linearGradient id="risk-grad-Medium" x1="0" y1="1" x2="0" y2="0">
                    <stop offset="0%" stopColor="#fde68a" />
                    <stop offset="100%" stopColor="#ca8a04" />
                  </linearGradient>
                  <linearGradient id="risk-grad-Low" x1="0" y1="1" x2="0" y2="0">
                    <stop offset="0%" stopColor="#bbf7d0" />
                    <stop offset="100%" stopColor="#16a34a" />
                  </linearGradient>
                </defs>
                <CartesianGrid {...CHART_GRID} vertical={false} />
                <XAxis
                  dataKey="name"
                  tick={CHART_AXIS_TICK}
                  tickLine={false}
                  axisLine={{ stroke: "rgb(203 213 225)" }}
                />
                <YAxis tick={CHART_AXIS_TICK} tickLine={false} axisLine={false} width={36} allowDecimals={false} />
                <Tooltip {...CHART_TOOLTIP} formatter={(v: number) => [v, "Assets"]} />
                <Bar dataKey="count" radius={[10, 10, 0, 0]} maxBarSize={48} animationDuration={600}>
                  {assetRiskData.map((entry) => (
                    <Cell key={entry.key} fill={`url(#risk-grad-${entry.key})`} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>
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
                type="button"
                className="flex items-center gap-1.5 rounded-lg border border-primary px-3 py-1.5 text-xs font-semibold text-primary transition-colors hover:bg-primary/10"
              >
                + Add Asset ▾
              </button>
              <button
                type="button"
                className="flex items-center gap-1.5 rounded-lg bg-primary px-3 py-1.5 text-xs font-bold text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
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
              { key: "hndlRisk", header: "HNDL Risk", render: (r) => r.hndlRisk ? <Badge className="border-destructive/20 bg-destructive/15 text-[10px] uppercase text-destructive">Yes</Badge> : <Badge className="border-success/20 bg-success/15 text-[10px] uppercase text-success">No</Badge> },
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

      <ThreatModelPanel />

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
                    className="h-3 w-3 rounded-full border-2 border-white bg-primary shadow-lg"
                  />
                  <div
                    className="mt-1 whitespace-nowrap rounded bg-primary px-1.5 py-0.5 text-[9px] font-bold text-primary-foreground"
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
        scanId={scanId}
        wsStatus={wsStatus}
      />
    </div>
  );
}
