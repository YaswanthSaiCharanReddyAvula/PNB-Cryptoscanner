import { useCallback, useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Loader2, AlertCircle, RefreshCw, ChevronDown, ChevronUp, Check, MapPin } from "lucide-react";
import { DossierPageHeader } from "@/components/layout/DossierPageHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { roadmapService, scanService } from "@/services/api";
import { getLastScannedDomain } from "@/lib/lastScanDomain";
import {
  inferTierRoadmapStep,
  tierRowsForRoadmapPath,
  tierRowsForTable,
} from "@/lib/tierComplianceCriteria";
import { toast } from "sonner";

type RoadmapItem = {
  id: string;
  source?: string;
  risk: string;
  risk_detail?: string;
  category?: string;
  priority?: string;
  solution: string;
  actions?: string;
  confidence?: string;
};

type RoadmapResponse = {
  domain?: string;
  scan_id?: string;
  scan_status?: string;
  completed_at?: string;
  quantum_risk_level?: string;
  quantum_score?: number;
  items?: RoadmapItem[];
  disclaimer?: string;
};

type RecentScanRow = {
  scan_id: string;
  domain: string;
  status: string;
  completed_at?: string;
  started_at?: string;
};

function priorityBadge(priority: string | undefined) {
  const pr = (priority || "medium").toLowerCase();
  const map: Record<string, string> = {
    critical: "bg-red-600/15 text-red-700 border-red-500/30",
    high: "bg-orange-500/15 text-orange-800 border-orange-500/25",
    medium: "bg-amber-500/12 text-amber-900 border-amber-500/25",
    low: "bg-slate-500/10 text-slate-700 border-slate-400/25",
    safe: "bg-emerald-500/12 text-emerald-800 border-emerald-500/25",
  };
  return (
    <Badge variant="outline" className={`text-[10px] font-semibold uppercase tracking-wide ${map[pr] || map.medium}`}>
      {pr}
    </Badge>
  );
}

const pathSteps = tierRowsForRoadmapPath();

function confidenceBadge(conf: string | undefined) {
  const c = (conf || "medium").toLowerCase();
  const map: Record<string, string> = {
    high: "bg-emerald-500/12 text-emerald-900 border-emerald-500/25",
    medium: "bg-sky-500/10 text-sky-800 border-sky-500/25",
    low: "bg-rose-500/12 text-rose-800 border-rose-500/25",
  };
  return (
    <Badge variant="outline" className={`text-[10px] font-semibold uppercase tracking-wide ${map[c] || map.medium}`}>
      {c}
    </Badge>
  );
}

export default function SecurityRoadmap() {
  const location = useLocation();
  const [activeDomain, setActiveDomain] = useState<string | null>(null);
  const [data, setData] = useState<RoadmapResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [noSession, setNoSession] = useState(false);
  const [tierTableOpen, setTierTableOpen] = useState(true);
  const [recentCompleted, setRecentCompleted] = useState<RecentScanRow[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");

  const load = useCallback(async (domain: string) => {
    const d = domain.trim().toLowerCase();
    if (!d) {
      setNoSession(true);
      setData(null);
      setActiveDomain(null);
      setLoading(false);
      return;
    }
    setNoSession(false);
    setLoading(true);
    setData(null);
    setActiveDomain(d);
    try {
      const res = await roadmapService.getSecurityRoadmap(d);
      setData(res.data as RoadmapResponse);
    } catch (err: unknown) {
      const ax = err as { response?: { status?: number; data?: { detail?: string } } };
      if (ax.response?.status === 404) {
        toast.error(
          ax.response?.data?.detail ||
            "No scan data yet for this domain. Finish a scan on Overview, then refresh.",
        );
      } else {
        toast.error(ax.response?.data?.detail || "Failed to load security roadmap.");
      }
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadLatest = useCallback(async () => {
    setNoSession(false);
    setLoading(true);
    setData(null);
    setActiveDomain(null);
    try {
      const res = await roadmapService.getSecurityRoadmapLatest();
      setData(res.data as RoadmapResponse);
      setActiveDomain(
        (res.data as RoadmapResponse)?.domain ? String((res.data as RoadmapResponse).domain) : null,
      );
    } catch (err: unknown) {
      const ax = err as { response?: { status?: number; data?: { detail?: string } } };
      if (ax.response?.status === 404) {
        setNoSession(true);
      } else {
        toast.error(ax.response?.data?.detail || "Failed to load security roadmap.");
        setNoSession(true);
      }
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadByScanId = useCallback(async (scanId: string) => {
    const sid = (scanId || "").trim();
    if (!sid) return;
    setNoSession(false);
    setLoading(true);
    setData(null);
    try {
      const res = await roadmapService.getSecurityRoadmapByScanId(sid);
      setData(res.data as RoadmapResponse);
      setActiveDomain(
        (res.data as RoadmapResponse)?.domain ? String((res.data as RoadmapResponse).domain) : null,
      );
    } catch (err: unknown) {
      const ax = err as { response?: { status?: number; data?: { detail?: string } } };
      toast.error(ax.response?.data?.detail || "Failed to load historical roadmap.");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshRecentCompleted = useCallback(async () => {
    try {
      const res = await scanService.getRecentScans(40, "completed");
      const rows = Array.isArray(res.data?.scans) ? (res.data.scans as any[]) : [];
      const mapped = rows
        .filter((r) => r?.scan_id && r?.domain)
        .map((r) => ({
          scan_id: String(r.scan_id),
          domain: String(r.domain),
          status: String(r.status || "completed"),
          completed_at: r.completed_at ? String(r.completed_at) : undefined,
          started_at: r.started_at ? String(r.started_at) : undefined,
        })) as RecentScanRow[];
      setRecentCompleted(mapped);
    } catch {
      // non-blocking
      setRecentCompleted([]);
    }
  }, []);

  useEffect(() => {
    const d = getLastScannedDomain();
    if (d) load(d);
    else loadLatest();
    void refreshRecentCompleted();
  }, [location.key, load]);

  const items = data?.items ?? [];
  const currentStep = data ? inferTierRoadmapStep(data) : null;

  return (
    <div className="space-y-8">
      <DossierPageHeader
        eyebrow="Quantum-safe migration"
        title="Security roadmap"
        description="TLS tier journey from risk to target state, plus scan-derived actions. The domain comes from your last Overview scan—there is no separate domain field here."
      />

      <div className="dossier-card p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide">Active domain</h3>
            {activeDomain && !noSession ? (
              <p className="mt-1 font-mono text-sm text-foreground">{activeDomain}</p>
            ) : (
              <p className="mt-1 text-sm text-muted-foreground">None set — run a scan from Overview first.</p>
            )}
          </div>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                Past scans
              </span>
              <select
                value={selectedScanId}
                onChange={(e) => {
                  const sid = e.target.value;
                  setSelectedScanId(sid);
                  if (sid) void loadByScanId(sid);
                }}
                className="h-9 rounded-md border border-border bg-secondary px-2 text-xs"
                title="Load roadmap from a previous completed scan"
              >
                <option value="">Latest (auto)</option>
                {recentCompleted.map((s) => {
                  const when = s.completed_at || s.started_at || "";
                  const label = `${s.domain}${when ? ` · ${new Date(when).toLocaleString()}` : ""}`;
                  return (
                    <option key={s.scan_id} value={s.scan_id}>
                      {label}
                    </option>
                  );
                })}
              </select>
            </div>

            <Button
              type="button"
              variant="outline"
              size="sm"
              className="shrink-0 gap-2 border-primary/40"
              disabled={loading}
              onClick={() => {
                if (selectedScanId) void loadByScanId(selectedScanId);
                else {
                  const d = getLastScannedDomain();
                  if (d) void load(d);
                  else void loadLatest();
                }
                void refreshRecentCompleted();
              }}
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
              Refresh roadmap
            </Button>
          </div>
        </div>
        <p className="mt-3 text-xs text-muted-foreground">
          Start or change the domain on{" "}
          <Link to="/" className="font-medium text-primary hover:underline">
            Overview
          </Link>{" "}
          (Scan). Each scan updates the domain used here.
        </p>
      </div>

      {noSession && !loading && (
        <div className="rounded-xl border border-border bg-card px-6 py-12 text-center text-sm text-muted-foreground">
          <p className="mb-4">No completed scan results found yet.</p>
          <Link to="/" className="font-medium text-primary hover:underline">
            Go to Overview and run Scan
          </Link>
        </div>
      )}

      {!noSession && (
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
          className="relative overflow-hidden rounded-2xl border border-border bg-gradient-to-br from-slate-50/90 via-card to-blue-50/40 shadow-sm dark:from-slate-950 dark:via-card dark:to-primary/[0.07]"
        >
          <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-primary/[0.06] blur-3xl" />
          <div className="pointer-events-none absolute -bottom-16 -left-16 h-48 w-48 rounded-full bg-emerald-500/[0.05] blur-3xl" />

          <div className="relative px-5 py-6 sm:px-8 sm:py-8">
            <div className="mb-6 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h2 className="text-xs font-bold uppercase tracking-[0.2em] text-muted-foreground">Migration path</h2>
                <p className="mt-1 text-lg font-semibold text-foreground sm:text-xl">Tier compliance journey</p>
                <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
                  Move from critical exposure toward Tier-1 Elite. The highlighted step is an{" "}
                  <span className="font-medium text-foreground">indicative</span> position from your latest scan
                  signals—not a certification.
                </p>
              </div>
              {currentStep !== null && data && (
                <div className="flex items-center gap-2 rounded-full border border-primary/25 bg-primary/5 px-3 py-1.5 text-xs text-foreground">
                  <MapPin className="h-3.5 w-3.5 shrink-0 text-primary" />
                  <span>
                    Est. posture: <span className="font-semibold">{pathSteps[currentStep]?.tier}</span>
                  </span>
                </div>
              )}
              {currentStep === null && (
                <p className="text-xs text-muted-foreground">
                  {loading ? "Loading scan signals…" : "Complete a scan to estimate your position on the path."}
                </p>
              )}
            </div>

            {/* Desktop / tablet: horizontal track */}
            <div className="hidden md:block">
              <div className="relative px-2 pb-2 pt-6">
                <div
                  className="absolute left-[8%] right-[8%] top-[2.25rem] h-1 rounded-full bg-gradient-to-r from-red-200 via-blue-200 to-emerald-200 dark:from-red-950/80 dark:via-blue-950/50 dark:to-emerald-950/80"
                  aria-hidden
                />
                <div className="relative flex justify-between gap-2">
                  {pathSteps.map((step, idx) => {
                    const done = currentStep !== null && idx < currentStep;
                    const here = currentStep !== null && idx === currentStep;
                    const future = currentStep === null || idx > currentStep;
                    return (
                      <motion.div
                        key={step.id}
                        initial={{ opacity: 0, y: 16 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.06 * idx, duration: 0.35 }}
                        className="flex w-[22%] min-w-0 flex-col items-center text-center"
                      >
                        <div
                          className={`relative z-10 flex h-14 w-14 items-center justify-center rounded-2xl border-2 text-sm font-bold shadow-sm transition-all duration-300 ${
                            here
                              ? "scale-110 border-primary bg-primary text-primary-foreground shadow-lg shadow-primary/25 ring-4 ring-primary/20"
                              : done
                                ? "border-emerald-500/50 bg-emerald-500 text-white"
                                : future
                                  ? "border-border bg-card/90 text-muted-foreground"
                                  : ""
                          }`}
                          style={
                            here
                              ? undefined
                              : done
                                ? undefined
                                : future
                                  ? { borderColor: `${step.color}35` }
                                  : undefined
                          }
                        >
                          {done ? <Check className="h-6 w-6" strokeWidth={2.5} /> : idx + 1}
                        </div>
                        <p className="mt-3 text-[11px] font-bold uppercase tracking-wide text-muted-foreground">
                          Step {idx + 1}
                        </p>
                        <p className="mt-0.5 line-clamp-2 text-sm font-semibold leading-snug text-foreground">
                          {step.tier}
                        </p>
                        <span
                          className="mt-2 inline-flex rounded-full px-2 py-0.5 text-[10px] font-semibold"
                          style={{
                            color: step.color,
                            backgroundColor: `${step.color}14`,
                            border: `1px solid ${step.color}30`,
                          }}
                        >
                          {step.level}
                        </span>
                        <p className="mt-2 line-clamp-3 text-left text-[11px] leading-relaxed text-muted-foreground">
                          {step.action}
                        </p>
                      </motion.div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Mobile: vertical timeline */}
            <div className="space-y-0 md:hidden">
              {pathSteps.map((step, idx) => {
                const done = currentStep !== null && idx < currentStep;
                const here = currentStep !== null && idx === currentStep;
                const isLast = idx === pathSteps.length - 1;
                return (
                  <div key={step.id} className="relative flex gap-4">
                    <div className="flex flex-col items-center">
                      <div
                        className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border-2 text-sm font-bold ${
                          here
                            ? "border-primary bg-primary text-primary-foreground shadow-md ring-4 ring-primary/15"
                            : done
                              ? "border-emerald-500 bg-emerald-500 text-white"
                              : "border-border bg-card text-muted-foreground"
                        }`}
                      >
                        {done ? <Check className="h-5 w-5" /> : idx + 1}
                      </div>
                      {!isLast && (
                        <div
                          className="my-1 min-h-[2rem] w-0.5 flex-1 rounded-full bg-gradient-to-b from-red-200 via-blue-200 to-emerald-200 dark:from-red-950/70 dark:via-blue-950/50 dark:to-emerald-950/70"
                          aria-hidden
                        />
                      )}
                    </div>
                    <div className={`pb-8 ${isLast ? "pb-2" : ""}`}>
                      <p className="text-xs font-bold uppercase tracking-wide text-muted-foreground">Step {idx + 1}</p>
                      <p className="text-sm font-semibold text-foreground">{step.tier}</p>
                      <span
                        className="mt-1 inline-flex rounded-full px-2 py-0.5 text-[10px] font-semibold"
                        style={{
                          color: step.color,
                          backgroundColor: `${step.color}14`,
                          border: `1px solid ${step.color}30`,
                        }}
                      >
                        {step.level}
                      </span>
                      <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{step.compliance}</p>
                      <p className="mt-1 text-xs font-medium" style={{ color: step.color }}>
                        {step.action}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </motion.section>
      )}

      {!noSession && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="overflow-hidden rounded-xl border border-border bg-card shadow-sm"
        >
          <button
            type="button"
            className="flex w-full items-center justify-between gap-3 border-b border-border px-5 py-4 text-left transition-colors hover:bg-secondary/40 sm:px-6"
            onClick={() => setTierTableOpen((o) => !o)}
          >
            <div>
              <h2 className="text-sm font-semibold uppercase tracking-wide text-foreground">Tier compliance criteria</h2>
              <p className="mt-0.5 text-xs text-muted-foreground">Security requirements and remediation priorities per tier</p>
            </div>
            {tierTableOpen ? (
              <ChevronUp className="h-4 w-4 shrink-0 text-muted-foreground" />
            ) : (
              <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
            )}
          </button>
          <AnimatePresence initial={false}>
            {tierTableOpen && (
              <motion.div
                key="tier-criteria"
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.25 }}
                className="overflow-hidden"
              >
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[640px] text-sm">
                    <thead>
                      <tr className="border-b border-border bg-secondary/50">
                        {["Tier", "Security level", "Compliance criteria", "Priority / action"].map((h) => (
                          <th
                            key={h}
                            className="px-5 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground sm:px-6"
                          >
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {tierRowsForTable().map((row) => (
                        <tr key={row.id} className="border-b border-border/60 align-top transition-colors hover:bg-secondary/25 last:border-0">
                          <td className="whitespace-nowrap px-5 py-4 font-semibold text-foreground sm:px-6">{row.tier}</td>
                          <td className="px-5 py-4 sm:px-6">
                            <span
                              className="inline-flex rounded-full px-2.5 py-0.5 text-[10px] font-semibold"
                              style={{
                                color: row.color,
                                backgroundColor: `${row.color}16`,
                                border: `1px solid ${row.color}38`,
                              }}
                            >
                              {row.level}
                            </span>
                          </td>
                          <td className="max-w-md px-5 py-4 text-xs leading-relaxed text-muted-foreground sm:px-6">
                            {row.compliance}
                          </td>
                          <td className="px-5 py-4 text-xs font-medium sm:px-6" style={{ color: row.color }}>
                            {row.action}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      )}

      {loading && (
        <div className="flex items-center justify-center gap-2 py-16 text-muted-foreground">
          <Loader2 className="h-6 w-6 animate-spin" />
          <span>Loading roadmap…</span>
        </div>
      )}

      {!loading && activeDomain && !data && !noSession && (
        <div className="rounded-xl border border-border bg-card px-6 py-10 text-center text-sm text-muted-foreground">
          <p className="mb-2">No roadmap data loaded for this domain yet.</p>
          <p>
            If a scan is still running on{" "}
            <Link to="/" className="font-medium text-primary hover:underline">
              Overview
            </Link>
            , wait until it completes, then use <span className="font-medium text-foreground">Refresh roadmap</span>.
          </p>
        </div>
      )}

      {!loading && data && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
            <span>
              Scan: <span className="font-mono text-foreground">{data.domain}</span>
            </span>
            {data.quantum_score != null && (
              <span>
                Quantum score:{" "}
                <span className="font-semibold text-foreground">{Number(data.quantum_score).toFixed(1)}</span>
                {data.quantum_risk_level ? <span className="ml-1">({data.quantum_risk_level})</span> : null}
              </span>
            )}
            {data.scan_id && <span className="font-mono text-xs">id {data.scan_id.slice(0, 8)}…</span>}
          </div>

          {data.disclaimer && (
            <div className="flex gap-2 rounded-xl border border-amber-500/25 bg-amber-500/5 px-4 py-3 text-xs text-amber-950 dark:text-amber-100/90">
              <AlertCircle className="h-4 w-4 shrink-0 text-amber-600" />
              <p>{data.disclaimer}</p>
            </div>
          )}

          <div className="overflow-hidden rounded-xl border border-border bg-card shadow-sm">
            <div className="border-b border-border bg-secondary/30 px-5 py-3 sm:px-6">
              <h3 className="text-sm font-semibold uppercase tracking-wide text-foreground">Scan-derived remediation</h3>
              <p className="mt-0.5 text-xs text-muted-foreground">Findings from your latest run mapped to concrete next steps</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-sm">
                <thead>
                  <tr className="border-b border-border bg-secondary/50 text-left">
                    <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                      Priority
                    </th>
                    <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                      Risk / finding
                    </th>
                    <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                      Category
                    </th>
                    <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                      Target solution
                    </th>
                    <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {items.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-12 text-center text-muted-foreground">
                        No roadmap rows for this scan yet. If the scan is still running, wait for it to finish, then
                        use Refresh.
                      </td>
                    </tr>
                  ) : (
                    items.map((row) => (
                      <tr
                        key={row.id}
                        className="border-b border-border/80 align-top last:border-0 hover:bg-secondary/20"
                      >
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="flex flex-wrap items-center gap-2">
                            {priorityBadge(row.priority)}
                            {row.confidence ? confidenceBadge(row.confidence) : null}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <p className="font-medium text-foreground">{row.risk}</p>
                          {row.risk_detail ? (
                            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{row.risk_detail}</p>
                          ) : null}
                          {row.source ? (
                            <p className="mt-1 text-[10px] uppercase tracking-wide text-muted-foreground/80">
                              Source: {row.source.replace(/_/g, " ")}
                            </p>
                          ) : null}
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground capitalize">{row.category || "—"}</td>
                        <td className="px-4 py-3 text-sm text-foreground">{row.solution}</td>
                        <td className="px-4 py-3 text-xs leading-relaxed text-muted-foreground">{row.actions || "—"}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
