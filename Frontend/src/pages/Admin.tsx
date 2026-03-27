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
} from "lucide-react";
import { toast } from "sonner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { useAuth } from "@/contexts/AuthContext";
import { adminService, reportingService } from "@/services/api";

const GOLD = "#FBBC09";

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
    { event_id?: string; export_type?: string; domain?: string; created_at?: string }[]
  >([]);

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
    } catch {
      toast.error("Could not download threat summary");
    }
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-center gap-3">
          <div
            className="flex h-10 w-10 items-center justify-center rounded-lg border border-border"
            style={{ backgroundColor: `${GOLD}18` }}
          >
            <Settings className="h-5 w-5" style={{ color: GOLD }} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">Admin & reporting</h1>
            <p className="text-sm text-muted-foreground">
              Phase 4 — org policy, export center, and outbound integrations.
            </p>
          </div>
        </div>
      </motion.div>

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
        <Tabs defaultValue="policy" className="w-full">
          <TabsList className="grid w-full max-w-lg grid-cols-3">
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
                className="font-semibold"
                style={{ backgroundColor: GOLD, color: "#111" }}
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
                <Button type="button" variant="outline" onClick={downloadBundle} className="gap-2 border-[#FBBC09]/40">
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
                        <th className="text-left px-4 py-2 font-medium text-muted-foreground">Time (UTC)</th>
                      </tr>
                    </thead>
                    <tbody>
                      {exportEvents.map((ev, i) => (
                        <tr key={ev.event_id || i} className="border-b border-border/50">
                          <td className="px-4 py-2 font-mono text-xs">{ev.export_type || "—"}</td>
                          <td className="px-4 py-2 font-mono text-xs">{ev.domain || "—"}</td>
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
                Slack and Jira URLs are stored for your records; only the outbound URL receives automated scan-complete
                notifications today.
              </p>
              <Button
                type="button"
                onClick={saveIntegrations}
                disabled={!isAdmin || savingInt}
                className="font-semibold"
                style={{ backgroundColor: GOLD, color: "#111" }}
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
