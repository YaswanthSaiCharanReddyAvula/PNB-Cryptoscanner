import { useEffect, useState } from "react";
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


export default function Admin() {
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
          defaultValue="policy"
          className="w-full"
          onValueChange={(v) => {
            if (v === "operations" && isAdmin) void loadOps();
          }}
        >
          <TabsList
            className={
              isAdmin
                ? "grid h-auto w-full max-w-4xl grid-cols-2 gap-1 sm:grid-cols-4"
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
        </Tabs>
      )}
    </div>
  );
}
