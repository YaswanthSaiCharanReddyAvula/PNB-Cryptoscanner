import { useState, useEffect, useRef, useMemo, type ReactNode } from "react";
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
  Activity,
  Inbox,
  Check,
  X,
  Clock,
  CircleDot,
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
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
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
import { useDomain } from "@/contexts/DomainContext";
import { cn } from "@/lib/utils";
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

/** Recent activity — full-width rows, strong left border + readable tint */
const ACTIVITY_STATUS_ROW: Record<string, string> = {
  completed:
    "border-l-emerald-600 bg-emerald-50/95 hover:bg-emerald-50 dark:border-l-emerald-500 dark:bg-emerald-950/35 dark:hover:bg-emerald-950/45",
  failed:
    "border-l-rose-600 bg-rose-50/95 hover:bg-rose-50 dark:border-l-rose-500 dark:bg-rose-950/35 dark:hover:bg-rose-950/45",
  running:
    "border-l-sky-600 bg-sky-50/95 hover:bg-sky-50 dark:border-l-sky-500 dark:bg-sky-950/35 dark:hover:bg-sky-950/45",
  pending:
    "border-l-amber-600 bg-amber-50/95 hover:bg-amber-50 dark:border-l-amber-500 dark:bg-amber-950/35 dark:hover:bg-amber-950/45",
};

function ActivityStatusGlyph({ status }: { status: string }) {
  const box =
    "flex h-11 w-11 shrink-0 items-center justify-center rounded-xl shadow-sm ring-2 ring-black/[0.04] dark:ring-white/10";
  switch (status) {
    case "completed":
      return (
        <div className={cn(box, "bg-emerald-600 text-white dark:bg-emerald-500")}>
          <Check className="h-5 w-5" strokeWidth={2.75} aria-hidden />
        </div>
      );
    case "failed":
      return (
        <div className={cn(box, "bg-rose-600 text-white dark:bg-rose-500")}>
          <X className="h-5 w-5" strokeWidth={2.75} aria-hidden />
        </div>
      );
    case "running":
      return (
        <div className={cn(box, "bg-sky-600 text-white dark:bg-sky-500")}>
          <Loader2 className="h-5 w-5 animate-spin" aria-hidden />
        </div>
      );
    case "pending":
      return (
        <div className={cn(box, "bg-amber-600 text-white dark:bg-amber-500")}>
          <Clock className="h-5 w-5" strokeWidth={2.25} aria-hidden />
        </div>
      );
    default:
      return (
        <div className={cn(box, "bg-slate-500 text-white")}>
          <CircleDot className="h-5 w-5" strokeWidth={2} aria-hidden />
        </div>
      );
  }
}

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

/** Inline domain search bar with autocomplete dropdown */
function DomainSearchBar() {
  const { selectedDomain, setSelectedDomain, availableDomains, loading } = useDomain();
  const [query, setQuery] = useState(selectedDomain ?? "");
  const [open, setOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(() => {
    const q = (query || "").trim().toLowerCase();
    if (!q) return availableDomains;
    return availableDomains.filter((d) => d.toLowerCase().includes(q));
  }, [query, availableDomains]);

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(e.target as Node) &&
        inputRef.current &&
        !inputRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const selectDomain = (d: string) => {
    setQuery(d);
    setSelectedDomain(d);
    setOpen(false);
    toast.success(`Showing results for ${d}`);
  };

  return (
    <div className="relative">
      <div className="flex gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            ref={inputRef}
            placeholder={loading ? "Loading domains…" : "Search scanned domains…"}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setOpen(true);
            }}
            onFocus={() => setOpen(true)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && filtered.length > 0) {
                selectDomain(filtered[0]);
              }
            }}
            className="pl-10 h-11 bg-secondary border-border"
          />
        </div>
        {selectedDomain && (
          <Button
            variant="outline"
            onClick={() => {
              setQuery("");
              setSelectedDomain(null);
            }}
            className="h-11 text-xs"
          >
            Clear
          </Button>
        )}
      </div>

      {/* Autocomplete dropdown */}
      {open && filtered.length > 0 && (
        <div
          ref={dropdownRef}
          className="absolute left-0 right-0 z-50 mt-1.5 max-h-56 overflow-y-auto rounded-xl border border-border bg-card shadow-xl"
        >
          {filtered.map((d) => (
            <button
              key={d}
              onClick={() => selectDomain(d)}
              className={cn(
                "flex w-full items-center gap-2 px-4 py-2.5 text-sm text-left transition-colors hover:bg-primary/10",
                d === selectedDomain && "bg-primary/5 font-semibold text-primary",
              )}
            >
              <Globe className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
              <span className="truncate">{d}</span>
              {d === selectedDomain && (
                <Badge variant="outline" className="ml-auto text-[9px] border-primary/30 text-primary">
                  Active
                </Badge>
              )}
            </button>
          ))}
        </div>
      )}

      {open && filtered.length === 0 && query.trim() && (
        <div className="absolute left-0 right-0 z-50 mt-1.5 rounded-xl border border-border bg-card p-4 text-center text-sm text-muted-foreground shadow-xl">
          No scanned domains match "<strong>{query}</strong>".{" "}
          <Link to="/scan" className="text-primary hover:underline font-medium">
            Run a new scan →
          </Link>
        </div>
      )}

      {selectedDomain && (
        <p className="mt-2 text-xs text-muted-foreground flex items-center gap-2">
          Viewing results for: <span className="text-primary font-semibold">{selectedDomain}</span>
          {" · "}
          <Link to={`/scan-results/${encodeURIComponent(selectedDomain)}`} className="font-medium text-primary hover:underline">
            Full results →
          </Link>
        </p>
      )}
    </div>
  );
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

  const {
    isScanning,
    stageIndex,
    results,
    error,
    startScan,
    cancelScan,
    scanId,
    targetDomain: activeScanDomain,
  } = useScan();

  const displayScanDomain = scannedDomain || activeScanDomain || "";

  const [initialLoadDone, setInitialLoadDone] = useState(false);
  const [isConsoleOpen, setIsConsoleOpen] = useState(false);
  const { messages, clearMessages, status: wsStatus } = useWebSocket(scanId);

  const [batchRaw, setBatchRaw] = useState("");
  const [batchBusy, setBatchBusy] = useState(false);

  const [controllerEnabled, setControllerEnabled] = useState(false);
  const [controllerMaxSubs, setControllerMaxSubs] = useState(String(DEFAULT_CTRL_MAX_SUBS));
  const [controllerExecSec, setControllerExecSec] = useState(String(DEFAULT_CTRL_EXEC_SEC));

  // Manual asset registration (Portfolio inventory)
  const [addAssetOpen, setAddAssetOpen] = useState(false);
  const [addHost, setAddHost] = useState("");
  const [addParentDomain, setAddParentDomain] = useState("");
  const [addOwner, setAddOwner] = useState("");
  const [addEnvironment, setAddEnvironment] = useState("");
  const [addCriticality, setAddCriticality] = useState("");
  const [addNotes, setAddNotes] = useState("");
  const [addSaving, setAddSaving] = useState(false);

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
    if (results && (results as any).status === "completed" && !isScanning) {
      toast.success(`Scan completed for ${displayScanDomain}!`, {
        action: {
          label: "View Results",
          onClick: () => window.location.href = `/scan-results/${encodeURIComponent(displayScanDomain)}`,
        },
        duration: 8000,
      });
      refreshDashboardData(results);
    } else if (error && typeof error === "string") {
      toast.error(error);
    }
  }, [results, isScanning, error, displayScanDomain]);

  const refreshDashboardData = async (v1FallbackPayload: any = null) => {
    try {
      const [sumRes, assetRes, dnsRes, cryptoRes, distRes, polRes, migRes, recentRes] = await Promise.all([
        dashboardService.getSummary().catch(() => ({ data: null })),
        assetService.getAll({ page_size: 100 }).catch(() => ({ data: { items: [] } })),
        dnsService.getNameServerRecords().catch(() => ({ data: [] })),
        cryptoService.getCryptoSecurityData().catch(() => ({ data: [] })),
        assetService.getDistribution().catch(() => ({ data: [] })),
        dashboardService.getPolicyAlignment().catch(() => ({ data: null })),
        dashboardService.getMigrationSnapshot().catch(() => ({ data: null })),
        scanService
          .getRecentScans(8)
          .catch(() => ({ data: { scans: [] } })),
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

      // ── Recent scans activity (overview) ─────────────────────────────────
      const scans = Array.isArray(recentRes?.data?.scans) ? recentRes.data.scans : [];
      const activity = scans.slice(0, 6).map((s: any) => {
        const st = String(s?.status || "").toLowerCase();
        const completedOrStarted = s?.completed_at || s?.started_at;
        const when = completedOrStarted ? new Date(completedOrStarted).toLocaleString() : "—";

        const statusLabel =
          st === "completed" ? "Completed" :
          st === "failed" ? "Failed" :
          st === "running" ? "Running" :
          st === "pending" ? "Queued" :
          (st ? st.charAt(0).toUpperCase() + st.slice(1) : "Unknown");

        return {
          status: st || "unknown",
          msg: `${statusLabel}: ${s?.domain || "—"}`,
          time: when,
        };
      });
      setActivityFeed(activity);

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

  const submitAddAsset = async () => {
    const host = addHost.trim().toLowerCase();
    if (!host) {
      toast.error("Host is required (e.g. api.bank.in)");
      return;
    }
    setAddSaving(true);
    try {
      await assetService.importRegisteredAssets({
        source: "manual",
        parent_domain: addParentDomain.trim().toLowerCase() || undefined,
        items: [
          {
            host,
            owner: addOwner.trim() || undefined,
            environment: addEnvironment.trim() || undefined,
            criticality: addCriticality.trim() || undefined,
            notes: addNotes.trim() || undefined,
          },
        ],
      });
      toast.success("Asset added to inventory");
      setAddAssetOpen(false);
      setAddHost("");
      setAddParentDomain("");
      setAddOwner("");
      setAddEnvironment("");
      setAddCriticality("");
      setAddNotes("");
      await refreshDashboardData();
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || "Failed to add asset");
    } finally {
      setAddSaving(false);
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

      {/* Domain Search Bar */}
      <div className="dossier-card relative overflow-hidden p-5">
        <div className="absolute -z-10 -right-20 -top-20 h-80 w-80 rounded-full bg-primary/5 blur-3xl" />
        <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-3 flex items-center gap-2">
          <Search className="h-4 w-4 text-primary" />
          Select Domain
        </h3>
        <DomainSearchBar />
      </div>
      
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
                onClick={() => setAddAssetOpen(true)}
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

      {/* Add Asset (manual registration) */}
      <Sheet open={addAssetOpen} onOpenChange={setAddAssetOpen}>
        <SheetContent a11yTitle="Add asset" className="w-full sm:max-w-lg">
          <SheetHeader>
            <SheetTitle className="text-left">Add asset</SheetTitle>
          </SheetHeader>
          <div className="mt-5 space-y-4">
            <div className="space-y-1.5">
              <Label>Host *</Label>
              <Input
                value={addHost}
                onChange={(e) => setAddHost(e.target.value)}
                placeholder="api.bank.in"
                className="bg-secondary"
                maxLength={253}
              />
              <p className="text-[11px] text-muted-foreground">
                This registers the host in Portfolio inventory (source: manual). Include it in future scans by enabling “merge registered inventory”.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>Parent domain (optional)</Label>
                <Input
                  value={addParentDomain}
                  onChange={(e) => setAddParentDomain(e.target.value)}
                  placeholder="bank.in"
                  className="bg-secondary"
                  maxLength={253}
                />
              </div>
              <div className="space-y-1.5">
                <Label>Owner (optional)</Label>
                <Input
                  value={addOwner}
                  onChange={(e) => setAddOwner(e.target.value)}
                  placeholder="Payments team"
                  className="bg-secondary"
                />
              </div>
              <div className="space-y-1.5">
                <Label>Environment (optional)</Label>
                <Input
                  value={addEnvironment}
                  onChange={(e) => setAddEnvironment(e.target.value)}
                  placeholder="prod / stage"
                  className="bg-secondary"
                />
              </div>
              <div className="space-y-1.5">
                <Label>Criticality (optional)</Label>
                <Input
                  value={addCriticality}
                  onChange={(e) => setAddCriticality(e.target.value)}
                  placeholder="critical / high / medium / low"
                  className="bg-secondary"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label>Notes (optional)</Label>
              <Textarea
                value={addNotes}
                onChange={(e) => setAddNotes(e.target.value)}
                placeholder="Why this asset matters, onboarding details, etc."
                className="bg-secondary"
                rows={3}
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-1">
              <Button
                type="button"
                variant="secondary"
                onClick={() => setAddAssetOpen(false)}
                disabled={addSaving}
              >
                Cancel
              </Button>
              <Button type="button" onClick={submitAddAsset} disabled={addSaving}>
                {addSaving ? "Saving…" : "Save asset"}
              </Button>
            </div>
          </div>
        </SheetContent>
      </Sheet>

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

      {/* Recent scans activity — full width, strong status tint */}
      <div className="w-full overflow-hidden rounded-2xl border border-border bg-card shadow-sm">
        <div className="flex flex-wrap items-center gap-3 border-b border-border bg-muted/30 px-4 py-4 sm:px-6">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
            <Activity className="h-5 w-5" strokeWidth={2.25} />
          </div>
          <div className="min-w-0 flex-1">
            <h3 className="text-base font-semibold tracking-tight text-foreground">Recent scans &amp; activity</h3>
            <p className="mt-0.5 text-sm text-muted-foreground">Latest jobs from your scan queue</p>
          </div>
        </div>

        <div className="px-4 py-4 sm:px-6 sm:py-5">
          {activityFeed.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border bg-muted/20 py-12 text-center sm:py-14">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
                <Inbox className="h-5 w-5" strokeWidth={1.75} />
              </div>
              <div className="max-w-md space-y-1 px-2">
                <p className="text-sm font-medium text-foreground">No activity yet</p>
                <p className="text-sm leading-relaxed text-muted-foreground">
                  Completed and in-progress scans will show here after you run a scan from this overview.
                </p>
              </div>
            </div>
          ) : (
            <ul className="flex w-full flex-col gap-3">
              {activityFeed.map((item: { status?: string; msg: string; time: string }, i: number) => {
                const st = item.status && ACTIVITY_STATUS_ROW[item.status] ? item.status : "unknown";
                const rowClass =
                  st === "unknown"
                    ? "border-l-slate-500 bg-muted/50 hover:bg-muted/70 dark:border-l-slate-400"
                    : ACTIVITY_STATUS_ROW[st];

                return (
                  <motion.li
                    key={i}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.15, delay: Math.min(i * 0.03, 0.18) }}
                    className={cn(
                      "flex w-full min-w-0 items-center gap-4 rounded-xl border border-border/80 border-l-4 py-4 pl-4 pr-4 shadow-sm transition-colors sm:gap-5 sm:py-4 sm:pl-5 sm:pr-5",
                      rowClass,
                    )}
                  >
                    <ActivityStatusGlyph status={st} />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-semibold leading-snug text-foreground sm:text-[15px]">{item.msg}</p>
                      <time
                        className="mt-1 block text-xs tabular-nums text-muted-foreground sm:text-sm"
                        dateTime={item.time}
                      >
                        {item.time}
                      </time>
                    </div>
                  </motion.li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
