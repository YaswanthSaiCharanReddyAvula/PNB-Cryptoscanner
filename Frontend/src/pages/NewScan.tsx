import { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  Zap,
  Search,
  Loader2,
  Layers,
  Server,
  Globe,
  Code,
  HardDrive,
  Terminal,
  CheckCircle2,
  Info,
  ShieldCheck,
  AlertTriangle,
  Clock,
} from "lucide-react";
import { StatCard } from "@/components/dashboard/StatCard";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { DossierPageHeader } from "@/components/layout/DossierPageHeader";
import { ScanProgressBar } from "@/components/dashboard/ScanProgressBar";
import { useScan } from "@/hooks/useScan";
import { useWebSocket, type WSMessage } from "@/hooks/useWebSocket";
import { scanService, type ScanControllerPayload } from "@/services/api";
import { useDomain } from "@/contexts/DomainContext";
import { setLastScannedDomain } from "@/lib/lastScanDomain";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

const DEFAULT_CTRL_MAX_SUBS = 50;
const DEFAULT_CTRL_EXEC_SEC = 120;
const MAX_BATCH_DOMAINS = 25;

export default function NewScan() {
  const [domain, setDomain] = useState("");
  const { refreshDomains, setSelectedDomain } = useDomain();

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

  const { messages, clearMessages, status: wsStatus } = useWebSocket(scanId);

  const [controllerEnabled, setControllerEnabled] = useState(false);
  const [controllerMaxSubs, setControllerMaxSubs] = useState(String(DEFAULT_CTRL_MAX_SUBS));
  const [controllerExecSec, setControllerExecSec] = useState(String(DEFAULT_CTRL_EXEC_SEC));

  const [batchRaw, setBatchRaw] = useState("");
  const [batchBusy, setBatchBusy] = useState(false);

  // Intermediate metrics from WebSocket
  const [liveMetrics, setLiveMetrics] = useState<Record<string, unknown> | null>(null);

  const consoleEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages]);

  // Extract latest metrics from WS messages
  useEffect(() => {
    const metricsMessages = messages.filter((m) => m.type === "metrics" && m.data);
    if (metricsMessages.length > 0) {
      setLiveMetrics(metricsMessages[metricsMessages.length - 1].data as Record<string, unknown>);
    }
  }, [messages]);

  // When scan completes, refresh the domain list and set the scanned domain as selected
  useEffect(() => {
    if (!isScanning && stageIndex >= 5 && activeScanDomain) {
      refreshDomains();
      setSelectedDomain(activeScanDomain);
    }
  }, [isScanning, stageIndex, activeScanDomain, refreshDomains, setSelectedDomain]);

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
      setLastScannedDomain(targetDomain);
      setLiveMetrics(null);
      clearMessages();
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
      const data = res.data as { batch_id?: string; queued?: number };
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

  const intermediateStats = liveMetrics
    ? [
        { title: "Total Assets", value: String(liveMetrics.total_assets ?? "—"), icon: Server, variant: "gold" as const },
        { title: "Web Applications", value: String(liveMetrics.public_web_apps ?? "—"), icon: Globe, variant: "default" as const },
        { title: "APIs", value: String(liveMetrics.apis ?? "—"), icon: Code, variant: "info" as const },
        { title: "Servers", value: String(liveMetrics.servers ?? "—"), icon: HardDrive, variant: "default" as const },
      ]
    : [];

  const scanComplete = !isScanning && stageIndex >= 5;

  return (
    <div className="space-y-6">
      <DossierPageHeader
        eyebrow="Quantum cryptographic assessment"
        title="New Scan"
        description="Launch a domain scan to discover assets, analyze TLS configurations, and evaluate quantum readiness."
      />

      {/* ── Scan Domain Input ──────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        className="relative overflow-hidden rounded-2xl border border-primary/20 bg-card p-6 shadow-lg"
      >
        <div className="absolute -z-10 -right-20 -top-20 h-80 w-80 rounded-full bg-primary/5 blur-3xl" />

        <h3 className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-foreground mb-4">
          <Zap className="h-4 w-4 text-primary" />
          Scan Target
        </h3>

        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Enter domain (e.g., securebank.com)"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              className="pl-10 h-12 text-base bg-secondary border-border"
              disabled={isScanning}
            />
          </div>
          <Button
            onClick={handleScan}
            disabled={isScanning || !domain.trim()}
            className="h-12 px-8 bg-primary text-primary-foreground hover:bg-primary/90 text-base font-semibold shadow-md"
          >
            {isScanning && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            <Zap className="w-4 h-4 mr-2" />
            Scan
          </Button>
        </div>

        {/* Controller */}
        <div className="mt-4 flex flex-col gap-3 rounded-xl border border-border/60 bg-secondary/30 p-4 sm:flex-row sm:items-center sm:justify-between">
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

        {error && (
          <p className="mt-3 text-sm text-destructive flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" /> {error}
          </p>
        )}

        {scanComplete && activeScanDomain && (
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="mt-3 text-sm text-muted-foreground flex items-center gap-2"
          >
            <CheckCircle2 className="h-4 w-4 text-emerald-500" />
            Scan completed for <strong className="text-primary">{activeScanDomain}</strong>.{" "}
            <Link
              to={`/scan-results/${encodeURIComponent(activeScanDomain)}`}
              className="font-semibold text-primary hover:underline"
            >
              View full results →
            </Link>
          </motion.p>
        )}
      </motion.div>

      {/* ── Progress Bar ──────────────────────────────────── */}
      <ScanProgressBar
        isScanning={isScanning}
        stageIndex={stageIndex}
        targetDomain={activeScanDomain}
        pipelineStageLabel={
          isScanning && results && typeof (results as { current_stage?: string }).current_stage === "string"
            ? (results as { current_stage: string }).current_stage
            : null
        }
      />

      {/* ── Intermediate Results (live stats from WS) ──── */}
      <AnimatePresence>
        {(isScanning || scanComplete) && intermediateStats.length > 0 && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
          >
            <div className="mb-3 flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-bold uppercase tracking-wider text-foreground">
                {scanComplete ? "Scan Results Summary" : "Intermediate Discovery"}
              </h3>
              {isScanning && (
                <Badge variant="outline" className="text-[10px] animate-pulse border-primary/30 text-primary">
                  LIVE
                </Badge>
              )}
            </div>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {intermediateStats.map((s, i) => (
                <motion.div
                  key={s.title}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.06 }}
                >
                  <StatCard {...s} />
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Live Console (inline) ─────────────────────────── */}
      <AnimatePresence>
        {(isScanning || messages.length > 0) && (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 12 }}
            className="rounded-2xl border border-border bg-card shadow-lg overflow-hidden"
          >
            {/* Console Header */}
            <div className="p-4 border-b border-border bg-muted/30 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-primary" />
                <span className="text-sm font-semibold text-foreground tracking-tight">Live Scan Console</span>
                <Badge
                  variant="outline"
                  className="max-w-[140px] truncate text-[10px] font-mono opacity-80"
                  title={scanId ? `${scanId} · ${wsStatus}` : wsStatus}
                >
                  {!scanId
                    ? wsStatus === "connecting" ? "connecting…" : "idle"
                    : `${scanId.slice(0, 8)}…`}
                </Badge>
                <div className="flex items-center gap-1.5 ml-2">
                  <div
                    className={cn(
                      "h-2 w-2 rounded-full",
                      wsStatus === "open"
                        ? "animate-pulse bg-emerald-500"
                        : wsStatus === "connecting"
                          ? "animate-pulse bg-amber-500"
                          : "bg-zinc-400",
                    )}
                  />
                  <span className="text-[10px] text-muted-foreground">
                    {wsStatus === "open" ? "Connected" : wsStatus === "connecting" ? "Connecting…" : "Idle"}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {cancelScan && scanId && isScanning && (
                  <button
                    onClick={cancelScan}
                    className="text-xs px-3 py-1.5 rounded-md bg-destructive/10 text-destructive hover:bg-destructive hover:text-destructive-foreground transition-colors font-medium"
                  >
                    Cancel Scan
                  </button>
                )}
                <span className="text-[10px] text-muted-foreground">{messages.length} entries</span>
              </div>
            </div>

            {/* Console Body */}
            <ScrollArea className="h-[340px] p-4 bg-slate-950/95 font-mono text-[11px] leading-relaxed">
              <div className="space-y-1">
                <div className="text-zinc-500 mb-2">Initialize secure connection to scan pipeline...</div>

                {messages.length === 0 && (
                  <div className="flex items-center gap-2 text-zinc-400">
                    <Loader2 className="h-3 w-3 animate-spin" />
                    <span>Waiting for tool output...</span>
                  </div>
                )}

                {messages.map((msg, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="text-zinc-600 shrink-0">
                      [{new Date().toLocaleTimeString([], { hour12: false })}]
                    </span>

                    {msg.type === "status" && (
                      <span className="text-sky-400 font-bold">
                        {msg.status === "completed" ? (
                          <CheckCircle2 className="inline h-3 w-3 mr-1 text-emerald-400" />
                        ) : (
                          <Info className="inline h-3 w-3 mr-1" />
                        )}
                        {msg.message}
                      </span>
                    )}

                    {msg.type === "log" && (
                      <span className="text-zinc-300">
                        <span className="text-cyan-500/80 mr-1.5">➔</span>
                        {msg.message}
                      </span>
                    )}

                    {msg.type === "data" && (
                      <span className="text-amber-300 font-medium bg-amber-500/10 px-1 rounded">
                        {msg.message}
                      </span>
                    )}

                    {msg.type === "metrics" && msg.data && (
                      <span className="text-emerald-400">
                        <span className="mr-1.5 text-emerald-500/80">◆</span>
                        Metrics: {JSON.stringify(msg.data)}
                      </span>
                    )}
                  </div>
                ))}

                {messages.some((m) => m.status === "completed") && (
                  <div className="pt-2 text-emerald-400/80 font-bold border-t border-zinc-800 mt-2">
                    ✓ Pipeline verification complete. Dashboard updated.
                  </div>
                )}

                <div ref={consoleEndRef} />
              </div>
            </ScrollArea>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Portfolio Batch Scan ──────────────────────────── */}
      <div className="dossier-card p-5">
        <div className="mb-3 flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold uppercase tracking-wide text-foreground">
              Portfolio batch scan
            </h3>
          </div>
          <Link to="/inventory-runs" className="text-xs font-medium text-blue-600 hover:text-blue-700">
            Inventory Runs →
          </Link>
        </div>
        <p className="mb-3 text-xs text-muted-foreground">
          Queue up to {MAX_BATCH_DOMAINS} root domains in one request. Jobs share a global concurrency limit on the server.
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
    </div>
  );
}
