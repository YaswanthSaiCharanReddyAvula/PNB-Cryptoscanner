import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Settings,
  FileDown,
  Link2,
  Shield,
  Loader2,
  Lock,
  RefreshCw,
  Activity,
  CalendarClock,
  Mail,
} from "lucide-react";
import { toast } from "sonner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { useAuth } from "@/contexts/AuthContext";
import { adminService, reportingService } from "@/services/api";
import { DossierPageHeader } from "@/components/layout/DossierPageHeader";
import { AdminNotificationInbox } from "@/components/notifications/AdminNotificationInbox";


export default function Admin() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { user } = useAuth();
  const isAdmin = user?.role === "Admin";
  const isEmployee = user?.role === "Employee";

  const [loading, setLoading] = useState(true);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [savingInt, setSavingInt] = useState(false);

  const [minTls, setMinTls] = useState("1.2");
  const [requireFs, setRequireFs] = useState(true);
  const [pqcTarget, setPqcTarget] = useState("");
  const [policyNotes, setPolicyNotes] = useState("");

  const [notifyScan, setNotifyScan] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState("");
  const [slackUrl, setSlackUrl] = useState("");
  const [jiraUrl, setJiraUrl] = useState("");
  const [intPreview, setIntPreview] = useState<{
    outbound_webhook_preview?: string | null;
    slack_webhook_preview?: string | null;
    jira_webhook_preview?: string | null;
  } | null>(null);

  const [exportEvents, setExportEvents] = useState<
    { event_id?: string; export_type?: string; domain?: string; actor?: string; created_at?: string }[]
  >([]);

  const [schedules, setSchedules] = useState<Record<string, unknown>[]>([]);
  const [mailLog, setMailLog] = useState<Record<string, unknown>[]>([]);
  const [artifacts, setArtifacts] = useState<Record<string, unknown>[]>([]);
  const [reportsBusy, setReportsBusy] = useState(false);
  const [newDomain, setNewDomain] = useState("");
  const [newCadence, setNewCadence] = useState("daily");
  const [newHour, setNewHour] = useState(6);
  const [newMinute, setNewMinute] = useState(0);
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [downloadEnabled, setDownloadEnabled] = useState(true);
  const [emailTo, setEmailTo] = useState("");

  type OpsSnapshot = {
    generated_at?: string;
    app?: { name?: string; version?: string };
    database?: { ok?: boolean; error?: string | null };
    scans?: {
      running?: number;
      pending?: number;
      completed_last_24h?: number;
      failed_last_7d?: number;
    };
    limits?: Record<string, number>;
    recent_failures?: {
      scan_id?: string;
      domain?: string;
      error?: string;
      completed_at?: string;
    }[];
  };
  const [opsSnapshot, setOpsSnapshot] = useState<OpsSnapshot | null>(null);
  const [opsLoading, setOpsLoading] = useState(false);

  const adminTabs = useMemo(() => ["policy", "exports", "scheduled", "integrations", "operations", "inbox"], []);
  const employeeTabs = useMemo(() => ["policy", "exports", "integrations"], []);
  const allowedTabs = isAdmin ? adminTabs : employeeTabs;
  const tabParam = searchParams.get("tab") || "policy";
  const activeTab = allowedTabs.includes(tabParam) ? tabParam : "policy";

  const loadAll = async () => {
    setLoading(true);
    try {
      const [p, i, h] = await Promise.all([
        adminService.getPolicy(),
        adminService.getIntegrations(),
        adminService.getExportHistory(40),
      ]);
      const pol = p.data;
      if (pol) {
        setMinTls(pol.min_tls_version || "1.2");
        setRequireFs(!!pol.require_forward_secrecy);
        setPqcTarget(pol.pqc_readiness_target || "");
        setPolicyNotes(pol.policy_notes || "");
      }
      const int = i.data;
      if (int) {
        setNotifyScan(!!int.notify_on_scan_complete);
        setIntPreview({
          outbound_webhook_preview: int.outbound_webhook_preview,
          slack_webhook_preview: int.slack_webhook_preview,
          jira_webhook_preview: int.jira_webhook_preview,
        });
      }
      setExportEvents(Array.isArray(h.data?.events) ? h.data.events : []);
    } catch {
      toast.error("Could not load admin settings (check API and auth).");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  const loadReports = async () => {
    if (!isAdmin) return;
    setReportsBusy(true);
    try {
      const [s, m, a] = await Promise.all([
        adminService.listReportSchedules(),
        adminService.getMailLog(80),
        adminService.listReportArtifacts(40),
      ]);
      setSchedules(Array.isArray(s.data?.schedules) ? s.data.schedules : []);
      setMailLog(Array.isArray(m.data?.events) ? m.data.events : []);
      setArtifacts(Array.isArray(a.data?.artifacts) ? a.data.artifacts : []);
    } catch {
      toast.error("Could not load scheduled reports");
    } finally {
      setReportsBusy(false);
    }
  };

  const loadOps = async () => {
    if (!isAdmin) return;
    setOpsLoading(true);
    try {
      const r = await adminService.getOpsSnapshot();
      setOpsSnapshot(r.data as OpsSnapshot);
    } catch {
      toast.error("Could not load operations snapshot (admin only).");
      setOpsSnapshot(null);
    } finally {
      setOpsLoading(false);
    }
  };

  const savePolicy = async () => {
    if (!isAdmin) return;
    setSavingPolicy(true);
    try {
      await adminService.putPolicy({
        min_tls_version: minTls,
        require_forward_secrecy: requireFs,
        pqc_readiness_target: pqcTarget || "",
        policy_notes: policyNotes || "",
      });
      toast.success("Policy saved");
      await loadAll();
    } catch {
      toast.error("Failed to save policy");
    } finally {
      setSavingPolicy(false);
    }
  };

  const saveIntegrations = async () => {
    if (!isAdmin) return;
    setSavingInt(true);
    try {
      const body: Record<string, unknown> = { notify_on_scan_complete: notifyScan };
      if (webhookUrl.trim()) body.outbound_webhook_url = webhookUrl.trim();
      if (slackUrl.trim()) body.slack_webhook_url = slackUrl.trim();
      if (jiraUrl.trim()) body.jira_webhook_url = jiraUrl.trim();
      const res = await adminService.putIntegrations(body);
      setWebhookUrl("");
      setSlackUrl("");
      setJiraUrl("");
      if (res.data) {
        setIntPreview({
          outbound_webhook_preview: res.data.outbound_webhook_preview,
          slack_webhook_preview: res.data.slack_webhook_preview,
          jira_webhook_preview: res.data.jira_webhook_preview,
        });
        setNotifyScan(!!res.data.notify_on_scan_complete);
      }
      toast.success("Integrations saved");
      await loadAll();
    } catch {
      toast.error("Failed to save integrations (admin only)");
    } finally {
      setSavingInt(false);
    }
  };

  const clearOutbound = async () => {
    if (!isAdmin) return;
    setSavingInt(true);
    try {
      await adminService.putIntegrations({
        outbound_webhook_url: "",
        notify_on_scan_complete: notifyScan,
      });
      toast.success("Outbound webhook cleared");
      await loadAll();
    } catch {
      toast.error("Could not clear webhook");
    } finally {
      setSavingInt(false);
    }
  };

  const downloadBundle = async () => {
    try {
      const res = await reportingService.exportBundle();
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `scan_bundle_${String(res.data?.domain || "latest").replace(/[^\w.-]+/g, "_")}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.success("Bundle downloaded");
      await loadAll();
    } catch {
      toast.error("No completed scan or API error");
    }
  };

  const downloadRoadmap = async () => {
    try {
      const res = await reportingService.getMigrationRoadmap();
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `migration_roadmap_${String(res.data?.domain || "latest").replace(/[^\w.-]+/g, "_")}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.success("Roadmap downloaded");
      try {
        const d = String(res.data?.domain || "").trim();
        await adminService.logExport({
          export_type: "migration_roadmap_json",
          domain: d || undefined,
        });
      } catch {
        /* audit log is best-effort */
      }
      await loadAll();
    } catch {
      toast.error("Could not download roadmap");
    }
  };

  const downloadThreat = async () => {
    try {
      const res = await reportingService.getThreatModelSummary();
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "threat_model_summary.json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.success("Threat summary downloaded");
      try {
        const d = String(res.data?.domain || "").trim();
        await adminService.logExport({
          export_type: "threat_model_summary_json",
          domain: d || undefined,
        });
      } catch {
        /* best-effort */
      }
      await loadAll();
    } catch {
      toast.error("Could not download threat summary");
    }
  };

  return (
    <div className="space-y-8">
      <DossierPageHeader
        eyebrow="Console"
        title="Admin & Reporting Exports"
        description="Org policy, intelligence exports, and outbound integrations (webhooks)."
      />

      {isEmployee && (
        <p className="text-xs text-muted-foreground flex items-center gap-2 rounded-lg border border-border bg-secondary/30 px-3 py-2">
          <Lock className="h-3.5 w-3.5" />
          Employee role: view-only. Policy and integration changes require an Admin account.
        </p>
      )}

      {loading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground py-12">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading admin data…
        </div>
      ) : (
        <Tabs
          value={activeTab}
          className="w-full"
          onValueChange={(v) => {
            setSearchParams({ tab: v }, { replace: true });
            if (v === "operations" && isAdmin) void loadOps();
            if (v === "scheduled" && isAdmin) void loadReports();
          }}
        >
          <TabsList
            className={
              isAdmin
                ? "grid h-auto w-full max-w-6xl grid-cols-2 gap-1 sm:grid-cols-3 lg:grid-cols-6"
                : "grid w-full max-w-lg grid-cols-3"
            }
          >
            <TabsTrigger value="policy" className="gap-1.5">
              <Shield className="h-3.5 w-3.5" />
              Policy
            </TabsTrigger>
            <TabsTrigger value="exports" className="gap-1.5">
              <FileDown className="h-3.5 w-3.5" />
              Exports
            </TabsTrigger>
            {isAdmin && (
              <TabsTrigger value="scheduled" className="gap-1.5">
                <CalendarClock className="h-3.5 w-3.5" />
                Scheduled
              </TabsTrigger>
            )}
            <TabsTrigger value="integrations" className="gap-1.5">
              <Link2 className="h-3.5 w-3.5" />
              Integrations
            </TabsTrigger>
            {isAdmin && (
              <TabsTrigger value="operations" className="gap-1.5">
                <Activity className="h-3.5 w-3.5" />
                Operations
              </TabsTrigger>
            )}
            {isAdmin && (
              <TabsTrigger value="inbox" className="gap-1.5">
                <Mail className="h-3.5 w-3.5" />
                Inbox
              </TabsTrigger>
            )}
          </TabsList>

          <TabsContent value="policy" className="mt-6 space-y-5">
            <div className="rounded-xl border border-border bg-card p-6 space-y-4 max-w-2xl">
              <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                Organizational crypto policy
              </h3>
              <p className="text-xs text-muted-foreground">
                Targets for audits and migration planning — not enforced automatically by the scanner.
              </p>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label>Minimum TLS version</Label>
                  <select
                    value={minTls}
                    onChange={(e) => setMinTls(e.target.value)}
                    disabled={!isAdmin}
                    className="w-full h-10 px-3 rounded-md border border-border bg-secondary text-sm"
                  >
                    <option value="1.2">TLS 1.2</option>
                    <option value="1.3">TLS 1.3</option>
                  </select>
                </div>
                <div className="flex items-end gap-2 pb-2">
                  <Checkbox
                    id="fs"
                    checked={requireFs}
                    onCheckedChange={(v) => setRequireFs(v === true)}
                    disabled={!isAdmin}
                  />
                  <Label htmlFor="fs" className="font-normal cursor-pointer">
                    Require forward secrecy (target)
                  </Label>
                </div>
              </div>
              <div className="space-y-2">
                <Label>PQC readiness target (e.g. fiscal year / quarter)</Label>
                <Input
                  value={pqcTarget}
                  onChange={(e) => setPqcTarget(e.target.value)}
                  disabled={!isAdmin}
                  placeholder="e.g. FY28 Q2"
                  className="bg-secondary"
                />
              </div>
              <div className="space-y-2">
                <Label>Notes</Label>
                <textarea
                  value={policyNotes}
                  onChange={(e) => setPolicyNotes(e.target.value)}
                  disabled={!isAdmin}
                  rows={4}
                  className="w-full px-3 py-2 rounded-md border border-border bg-secondary text-sm resize-y min-h-[100px]"
                  placeholder="Internal standards, exceptions process, etc."
                />
              </div>
              <Button
                type="button"
                onClick={savePolicy}
                disabled={!isAdmin || savingPolicy}
                className="bg-primary font-semibold text-primary-foreground hover:bg-primary/90"
              >
                {savingPolicy ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                Save policy
              </Button>
            </div>
          </TabsContent>

          <TabsContent value="exports" className="mt-6 space-y-5">
            <div className="rounded-xl border border-border bg-card p-6 space-y-4 max-w-3xl">
              <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                Export center
              </h3>
              <p className="text-xs text-muted-foreground">
                On-demand JSON exports. Bundle downloads are recorded in the audit log below.
              </p>
              <div className="flex flex-wrap gap-2">
                <Button type="button" variant="outline" onClick={downloadBundle} className="gap-2 border-primary/40">
                  <FileDown className="h-4 w-4" />
                  Full scan bundle
                </Button>
                <Button type="button" variant="outline" onClick={downloadRoadmap} className="gap-2">
                  <FileDown className="h-4 w-4" />
                  Migration roadmap
                </Button>
                <Button type="button" variant="outline" onClick={downloadThreat} className="gap-2">
                  <FileDown className="h-4 w-4" />
                  Threat model summary
                </Button>
                <Button type="button" variant="ghost" size="sm" onClick={() => loadAll()} className="gap-1 text-muted-foreground">
                  <RefreshCw className="h-3.5 w-3.5" />
                  Refresh history
                </Button>
              </div>
            </div>
            <div className="rounded-xl border border-border bg-card overflow-hidden max-w-3xl">
              <div className="px-4 py-3 border-b border-border text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Export audit log
              </div>
              {exportEvents.length === 0 ? (
                <p className="text-sm text-muted-foreground p-6">No exports recorded yet.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border bg-secondary/40">
                        <th className="text-left px-4 py-2 font-medium text-muted-foreground">Type</th>
                        <th className="text-left px-4 py-2 font-medium text-muted-foreground">Domain</th>
                        <th className="text-left px-4 py-2 font-medium text-muted-foreground">Actor</th>
                        <th className="text-left px-4 py-2 font-medium text-muted-foreground">Time (UTC)</th>
                      </tr>
                    </thead>
                    <tbody>
                      {exportEvents.map((ev, i) => (
                        <tr key={ev.event_id || i} className="border-b border-border/50">
                          <td className="px-4 py-2 font-mono text-xs">{ev.export_type || "—"}</td>
                          <td className="px-4 py-2 font-mono text-xs">{ev.domain || "—"}</td>
                          <td className="px-4 py-2 text-xs text-muted-foreground">{ev.actor || "—"}</td>
                          <td className="px-4 py-2 text-xs text-muted-foreground">
                            {ev.created_at ? new Date(ev.created_at).toISOString() : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </TabsContent>

          {isAdmin && (
            <TabsContent value="scheduled" className="mt-6 space-y-5">
              <div className="rounded-xl border border-border bg-card p-6 space-y-4 max-w-3xl">
                <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                  Scheduled scan bundle reports
                </h3>
                <p className="text-xs text-muted-foreground">
                  JSON export bundles (same as /reports/export-bundle). Configure SMTP in backend .env for email delivery.
                </p>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label className="text-xs">Domain (optional)</Label>
                    <Input
                      value={newDomain}
                      onChange={(e) => setNewDomain(e.target.value)}
                      placeholder="example.com — empty = latest completed scan"
                      className="font-mono text-xs bg-secondary"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Cadence</Label>
                    <select
                      value={newCadence}
                      onChange={(e) => setNewCadence(e.target.value)}
                      className="w-full h-10 px-3 rounded-md border border-border bg-secondary text-sm"
                    >
                      <option value="daily">Daily</option>
                      <option value="weekly">Weekly</option>
                      <option value="monthly">Monthly</option>
                    </select>
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Hour (UTC)</Label>
                    <Input
                      type="number"
                      min={0}
                      max={23}
                      value={newHour}
                      onChange={(e) => setNewHour(Number(e.target.value))}
                      className="bg-secondary"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Minute (UTC)</Label>
                    <Input
                      type="number"
                      min={0}
                      max={59}
                      value={newMinute}
                      onChange={(e) => setNewMinute(Number(e.target.value))}
                      className="bg-secondary"
                    />
                  </div>
                </div>
                <div className="flex flex-wrap gap-4">
                  <div className="flex items-center gap-2">
                    <Checkbox
                      id="dl"
                      checked={downloadEnabled}
                      onCheckedChange={(v) => setDownloadEnabled(v === true)}
                    />
                    <Label htmlFor="dl" className="font-normal cursor-pointer text-sm">
                      Save generated JSON for download
                    </Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <Checkbox
                      id="em"
                      checked={emailEnabled}
                      onCheckedChange={(v) => setEmailEnabled(v === true)}
                    />
                    <Label htmlFor="em" className="font-normal cursor-pointer text-sm">
                      Email JSON attachment
                    </Label>
                  </div>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Email recipients (comma-separated)</Label>
                  <Input
                    value={emailTo}
                    onChange={(e) => setEmailTo(e.target.value)}
                    placeholder="a@bank.com, b@bank.com"
                    disabled={!emailEnabled}
                    className="font-mono text-xs bg-secondary"
                  />
                </div>
                <Button
                  type="button"
                  className="bg-primary text-primary-foreground"
                  disabled={reportsBusy || (!emailEnabled && !downloadEnabled)}
                  onClick={async () => {
                    const to = emailTo
                      .split(/[,;\s]+/)
                      .map((s) => s.trim())
                      .filter(Boolean);
                    if (emailEnabled && to.length === 0) {
                      toast.error("Add at least one email or disable email delivery.");
                      return;
                    }
                    try {
                      await adminService.createReportSchedule({
                        domain: newDomain.trim() || null,
                        cadence: newCadence,
                        hour_utc: newHour,
                        minute_utc: newMinute,
                        enabled: true,
                        delivery: {
                          email_enabled: emailEnabled,
                          download_enabled: downloadEnabled,
                          email_to: to,
                        },
                      });
                      toast.success("Schedule created");
                      setNewDomain("");
                      setEmailTo("");
                      await loadReports();
                    } catch {
                      toast.error("Could not create schedule");
                    }
                  }}
                >
                  Add schedule
                </Button>
              </div>

              <div className="rounded-xl border border-border bg-card overflow-hidden max-w-4xl">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-3">
                  <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                    Active schedules
                  </span>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="gap-1 text-muted-foreground"
                    onClick={() => void loadReports()}
                    disabled={reportsBusy}
                  >
                    {reportsBusy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                    Refresh
                  </Button>
                </div>
                {schedules.length === 0 ? (
                  <p className="text-sm text-muted-foreground p-6">No schedules yet.</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-border bg-secondary/40">
                          <th className="text-left px-4 py-2 font-medium text-muted-foreground">Domain</th>
                          <th className="text-left px-4 py-2 font-medium text-muted-foreground">Cadence</th>
                          <th className="text-left px-4 py-2 font-medium text-muted-foreground">Next run (UTC)</th>
                          <th className="text-left px-4 py-2 font-medium text-muted-foreground">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {schedules.map((s) => {
                          const sid = String(s.schedule_id ?? "");
                          return (
                            <tr key={sid} className="border-b border-border/50">
                              <td className="px-4 py-2 font-mono text-xs">{String(s.domain ?? "—")}</td>
                              <td className="px-4 py-2 text-xs">
                                {String(s.cadence)} @ {String(s.hour_utc ?? 0)}:
                                {String(Number(s.minute_utc ?? 0)).padStart(2, "0")}
                              </td>
                              <td className="px-4 py-2 text-xs text-muted-foreground">
                                {s.next_run_at ? new Date(String(s.next_run_at)).toISOString().slice(0, 19).replace("T", " ") : "—"}
                              </td>
                              <td className="px-4 py-2 flex flex-wrap gap-1">
                                <Button
                                  type="button"
                                  size="sm"
                                  variant="outline"
                                  className="h-7 text-xs"
                                  onClick={async () => {
                                    try {
                                      await adminService.runReportScheduleNow(sid);
                                      toast.success("Run queued");
                                      await loadReports();
                                    } catch {
                                      toast.error("Run failed");
                                    }
                                  }}
                                >
                                  Run now
                                </Button>
                                <Button
                                  type="button"
                                  size="sm"
                                  variant="ghost"
                                  className="h-7 text-xs text-destructive"
                                  onClick={async () => {
                                    try {
                                      await adminService.deleteReportSchedule(sid);
                                      toast.success("Deleted");
                                      await loadReports();
                                    } catch {
                                      toast.error("Delete failed");
                                    }
                                  }}
                                >
                                  Delete
                                </Button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div className="rounded-xl border border-border bg-card overflow-hidden max-w-4xl">
                <div className="border-b border-border px-4 py-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Mail log (SMTP)
                </div>
                {mailLog.length === 0 ? (
                  <p className="text-sm text-muted-foreground p-6">No mail events yet.</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-border bg-secondary/40">
                          <th className="text-left px-4 py-2 font-medium text-muted-foreground">Status</th>
                          <th className="text-left px-4 py-2 font-medium text-muted-foreground">To</th>
                          <th className="text-left px-4 py-2 font-medium text-muted-foreground">Subject</th>
                          <th className="text-left px-4 py-2 font-medium text-muted-foreground">Time (UTC)</th>
                          <th className="text-left px-4 py-2 font-medium text-muted-foreground">Error</th>
                        </tr>
                      </thead>
                      <tbody>
                        {mailLog.map((m, i) => (
                          <tr key={String(m.log_id ?? i)} className="border-b border-border/50 align-top">
                            <td className="px-4 py-2 text-xs">{String(m.status ?? "—")}</td>
                            <td className="px-4 py-2 text-xs font-mono max-w-[200px] break-all">
                              {Array.isArray(m.to) ? (m.to as string[]).join(", ") : "—"}
                            </td>
                            <td className="px-4 py-2 text-xs">{String(m.subject ?? "—")}</td>
                            <td className="px-4 py-2 text-xs text-muted-foreground">
                              {m.created_at ? new Date(String(m.created_at)).toISOString().slice(0, 19).replace("T", " ") : "—"}
                            </td>
                            <td className="px-4 py-2 text-xs text-destructive max-w-xs break-words">
                              {String(m.error || "")}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div className="rounded-xl border border-border bg-card overflow-hidden max-w-4xl">
                <div className="border-b border-border px-4 py-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Generated files (download)
                </div>
                {artifacts.length === 0 ? (
                  <p className="text-sm text-muted-foreground p-6">No generated files yet.</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-border bg-secondary/40">
                          <th className="text-left px-4 py-2 font-medium text-muted-foreground">Domain</th>
                          <th className="text-left px-4 py-2 font-medium text-muted-foreground">File</th>
                          <th className="text-left px-4 py-2 font-medium text-muted-foreground">Created</th>
                          <th className="text-left px-4 py-2 font-medium text-muted-foreground">Download</th>
                        </tr>
                      </thead>
                      <tbody>
                        {artifacts.map((a) => {
                          const aid = String(a.artifact_id ?? "");
                          return (
                            <tr key={aid} className="border-b border-border/50">
                              <td className="px-4 py-2 font-mono text-xs">{String(a.domain ?? "—")}</td>
                              <td className="px-4 py-2 font-mono text-xs">{String(a.filename ?? "—")}</td>
                              <td className="px-4 py-2 text-xs text-muted-foreground">
                                {a.created_at ? new Date(String(a.created_at)).toISOString().slice(0, 19).replace("T", " ") : "—"}
                              </td>
                              <td className="px-4 py-2">
                                <Button
                                  type="button"
                                  size="sm"
                                  variant="outline"
                                  className="h-7 text-xs"
                                  onClick={async () => {
                                    try {
                                      const res = await adminService.downloadReportArtifactBlob(aid);
                                      const blob = res.data as Blob;
                                      const url = URL.createObjectURL(blob);
                                      const el = document.createElement("a");
                                      el.href = url;
                                      el.download = String(a.filename || "report.json");
                                      document.body.appendChild(el);
                                      el.click();
                                      el.remove();
                                      URL.revokeObjectURL(url);
                                      toast.success("Download started");
                                    } catch {
                                      toast.error("Download failed");
                                    }
                                  }}
                                >
                                  Download
                                </Button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </TabsContent>
          )}

          {isAdmin && (
            <TabsContent value="operations" className="mt-6 space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-xs text-muted-foreground max-w-xl">
                  Phase 7 — datastore ping, scan queue pressure, configured caps, and recent pipeline failures.
                </p>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="gap-1.5"
                  onClick={() => void loadOps()}
                  disabled={opsLoading}
                >
                  {opsLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                  Refresh
                </Button>
              </div>
              {opsLoading && !opsSnapshot ? (
                <div className="flex items-center gap-2 py-12 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" /> Loading ops snapshot…
                </div>
              ) : opsSnapshot ? (
                <div className="space-y-5">
                  <p className="text-[11px] text-muted-foreground">
                    Generated <span className="font-mono">{opsSnapshot.generated_at ?? "—"}</span> UTC ·{" "}
                    {opsSnapshot.app?.name} v{opsSnapshot.app?.version}
                  </p>
                  <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                    <div className="rounded-xl border border-border bg-card p-4">
                      <p className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">MongoDB</p>
                      <p className="mt-2 text-lg font-semibold">
                        {opsSnapshot.database?.ok ? (
                          <span className="text-emerald-600">Reachable</span>
                        ) : (
                          <span className="text-destructive">Error</span>
                        )}
                      </p>
                      {opsSnapshot.database?.error && (
                        <p className="mt-2 font-mono text-xs text-destructive break-all">{opsSnapshot.database.error}</p>
                      )}
                    </div>
                    {[
                      ["Running", opsSnapshot.scans?.running],
                      ["Pending", opsSnapshot.scans?.pending],
                      ["Completed (24h)", opsSnapshot.scans?.completed_last_24h],
                      ["Failed (7d)", opsSnapshot.scans?.failed_last_7d],
                    ].map(([label, n]) => (
                      <div key={String(label)} className="rounded-xl border border-border bg-card p-4">
                        <p className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">{label}</p>
                        <p className="mt-2 text-2xl font-bold tabular-nums">{n ?? 0}</p>
                      </div>
                    ))}
                  </div>
                  <div className="rounded-xl border border-border bg-card p-4 max-w-2xl">
                    <p className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Scanner limits</p>
                    <ul className="mt-3 grid gap-1 text-sm sm:grid-cols-2">
                      {opsSnapshot.limits &&
                        Object.entries(opsSnapshot.limits).map(([k, v]) => (
                          <li key={k} className="flex justify-between gap-4 border-b border-border/40 py-1 font-mono text-xs">
                            <span className="text-muted-foreground">{k}</span>
                            <span>{v}</span>
                          </li>
                        ))}
                    </ul>
                  </div>
                  <div className="rounded-xl border border-border bg-card overflow-hidden max-w-4xl">
                    <div className="border-b border-border bg-secondary/40 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                      Recent failed scans
                    </div>
                    {!opsSnapshot.recent_failures?.length ? (
                      <p className="p-6 text-sm text-muted-foreground">No failed scans on record.</p>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b border-border bg-secondary/30">
                              <th className="px-4 py-2 text-left font-medium text-muted-foreground">Domain</th>
                              <th className="px-4 py-2 text-left font-medium text-muted-foreground">Scan ID</th>
                              <th className="px-4 py-2 text-left font-medium text-muted-foreground">Error</th>
                              <th className="px-4 py-2 text-left font-medium text-muted-foreground">Completed</th>
                            </tr>
                          </thead>
                          <tbody>
                            {opsSnapshot.recent_failures.map((f, i) => (
                              <tr key={f.scan_id || i} className="border-b border-border/50 align-top">
                                <td className="px-4 py-2 font-mono text-xs">{f.domain || "—"}</td>
                                <td className="px-4 py-2 font-mono text-xs">{f.scan_id || "—"}</td>
                                <td className="px-4 py-2 text-xs text-muted-foreground max-w-md whitespace-pre-wrap break-words">
                                  {f.error || "—"}
                                </td>
                                <td className="px-4 py-2 text-xs text-muted-foreground whitespace-nowrap">
                                  {f.completed_at
                                    ? new Date(f.completed_at).toISOString().slice(0, 19).replace("T", " ")
                                    : "—"}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground py-8">
                  Snapshot not loaded — click Refresh, or re-open this tab.
                </p>
              )}
            </TabsContent>
          )}

          <TabsContent value="integrations" className="mt-6 space-y-5">
            <div className="rounded-xl border border-border bg-card p-6 space-y-4 max-w-2xl">
              <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                Outbound integrations
              </h3>
              <p className="text-xs text-muted-foreground">
                Optional webhooks. The primary URL receives a JSON payload when a scan completes (if enabled).
              </p>
              {intPreview && (
                <div className="text-[11px] text-muted-foreground space-y-1 rounded-md bg-secondary/40 px-3 py-2">
                  {intPreview.outbound_webhook_preview && (
                    <p>
                      Outbound (saved): <span className="font-mono text-foreground">{intPreview.outbound_webhook_preview}</span>
                    </p>
                  )}
                  {intPreview.slack_webhook_preview && (
                    <p>
                      Slack (saved): <span className="font-mono text-foreground">{intPreview.slack_webhook_preview}</span>
                    </p>
                  )}
                  {intPreview.jira_webhook_preview && (
                    <p>
                      Jira (saved): <span className="font-mono text-foreground">{intPreview.jira_webhook_preview}</span>
                    </p>
                  )}
                </div>
              )}
              <div className="flex items-center gap-2">
                <Checkbox
                  id="notify"
                  checked={notifyScan}
                  onCheckedChange={(v) => setNotifyScan(v === true)}
                  disabled={!isAdmin}
                />
                <Label htmlFor="notify" className="font-normal cursor-pointer">
                  POST to outbound URL when a scan completes
                </Label>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <Label>Outbound webhook URL</Label>
                  {isAdmin && intPreview?.outbound_webhook_preview && (
                    <button
                      type="button"
                      onClick={clearOutbound}
                      className="text-[11px] text-muted-foreground underline underline-offset-2 hover:text-foreground"
                    >
                      Clear saved URL
                    </button>
                  )}
                </div>
                <Input
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  disabled={!isAdmin}
                  placeholder="https://example.com/hooks/quantumshield"
                  className="font-mono text-xs bg-secondary"
                />
              </div>
              <div className="space-y-2">
                <Label>Slack incoming webhook (optional)</Label>
                <Input
                  value={slackUrl}
                  onChange={(e) => setSlackUrl(e.target.value)}
                  disabled={!isAdmin}
                  placeholder="https://hooks.slack.com/services/..."
                  className="font-mono text-xs bg-secondary"
                />
              </div>
              <div className="space-y-2">
                <Label>Jira / automation URL (optional)</Label>
                <Input
                  value={jiraUrl}
                  onChange={(e) => setJiraUrl(e.target.value)}
                  disabled={!isAdmin}
                  placeholder="https://your-org.atlassian.net/..."
                  className="font-mono text-xs bg-secondary"
                />
              </div>
              <p className="text-[11px] text-muted-foreground">
                When &quot;POST on scan complete&quot; is on: generic JSON goes to the outbound URL (if set), the same
                payload to Jira/automation URL (if set), and a short summary to Slack (if set).
              </p>
              <Button
                type="button"
                onClick={saveIntegrations}
                disabled={!isAdmin || savingInt}
                className="bg-primary font-semibold text-primary-foreground hover:bg-primary/90"
              >
                {savingInt ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                Save integrations
              </Button>
            </div>
          </TabsContent>

          {isAdmin && (
            <TabsContent value="inbox" className="mt-6 space-y-5">
              <div className="rounded-xl border border-border bg-card p-6 space-y-4 max-w-4xl">
                <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                  Employee messages
                </h3>
                <p className="text-xs text-muted-foreground">
                  In-app notifications sent by employee accounts. Mark as read after triage.
                </p>
                <AdminNotificationInbox />
              </div>
            </TabsContent>
          )}
        </Tabs>
      )}
    </div>
  );
}
