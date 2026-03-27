import { useCallback, useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  ClipboardList,
  Loader2,
  Plus,
  Trash2,
  Sprout,
  ShieldAlert,
  Lock,
} from "lucide-react";
import { toast } from "sonner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/contexts/AuthContext";
import { migrationService } from "@/services/api";

const GOLD = "#FBBC09";

type TaskRow = {
  task_id: string;
  title: string;
  description?: string;
  domain?: string;
  host?: string;
  wave?: number;
  priority?: string;
  status?: string;
  owner?: string;
  due_date?: string;
};

type WaiverRow = {
  waiver_id: string;
  requestor: string;
  reason: string;
  expiry?: string;
  impacted_assets?: string[];
  status?: string;
};

export default function Migration() {
  const { user } = useAuth();
  const isAdmin = user?.role === "Admin";

  const [tab, setTab] = useState("tasks");
  const [loading, setLoading] = useState(true);
  const [tasks, setTasks] = useState<TaskRow[]>([]);
  const [waivers, setWaivers] = useState<WaiverRow[]>([]);
  const [seeding, setSeeding] = useState(false);

  const [newTitle, setNewTitle] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newDomain, setNewDomain] = useState("");
  const [newHost, setNewHost] = useState("");

  const [wReq, setWReq] = useState("");
  const [wReason, setWReason] = useState("");
  const [wAssets, setWAssets] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [t, w] = await Promise.all([
        migrationService.listTasks(),
        migrationService.listWaivers(),
      ]);
      setTasks(Array.isArray(t.data?.tasks) ? t.data.tasks : []);
      setWaivers(Array.isArray(w.data?.waivers) ? w.data.waivers : []);
    } catch {
      toast.error("Could not load migration data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const addTask = async () => {
    if (!newTitle.trim()) {
      toast.error("Title is required");
      return;
    }
    try {
      await migrationService.createTask({
        title: newTitle.trim(),
        description: newDesc.trim() || undefined,
        domain: newDomain.trim() || undefined,
        host: newHost.trim() || undefined,
        wave: 1,
        priority: "medium",
        status: "open",
      });
      toast.success("Task created");
      setNewTitle("");
      setNewDesc("");
      setNewDomain("");
      setNewHost("");
      await load();
    } catch {
      toast.error("Failed to create task");
    }
  };

  const updateTaskStatus = async (taskId: string, status: string) => {
    try {
      await migrationService.patchTask(taskId, { status });
      await load();
    } catch {
      toast.error("Update failed");
    }
  };

  const removeTask = async (taskId: string) => {
    if (!isAdmin) return;
    try {
      await migrationService.deleteTask(taskId);
      toast.success("Task removed");
      await load();
    } catch {
      toast.error("Delete failed (admin only)");
    }
  };

  const runSeed = async () => {
    if (!isAdmin) return;
    setSeeding(true);
    try {
      const res = await migrationService.seedFromBacklog({ limit: 15 });
      toast.success(`Seeded ${res.data?.seeded ?? 0} task(s) from backlog`);
      await load();
    } catch {
      toast.error("Seed failed — need a completed scan (admin only)");
    } finally {
      setSeeding(false);
    }
  };

  const addWaiver = async () => {
    if (!wReq.trim() || !wReason.trim()) {
      toast.error("Requestor and reason are required");
      return;
    }
    try {
      const assets = wAssets
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      await migrationService.createWaiver({
        requestor: wReq.trim(),
        reason: wReason.trim(),
        impacted_assets: assets,
        status: "pending",
      });
      toast.success("Waiver submitted");
      setWReq("");
      setWReason("");
      setWAssets("");
      await load();
    } catch {
      toast.error("Failed to submit waiver");
    }
  };

  const setWaiverStatus = async (waiverId: string, status: string) => {
    try {
      await migrationService.patchWaiver(waiverId, { status });
      toast.success(`Waiver ${status}`);
      await load();
    } catch {
      toast.error("Update failed (approve/reject: admin only)");
    }
  };

  const removeWaiver = async (waiverId: string) => {
    if (!isAdmin) return;
    try {
      await migrationService.deleteWaiver(waiverId);
      toast.success("Waiver removed");
      await load();
    } catch {
      toast.error("Delete failed (admin only)");
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
            <ClipboardList className="h-5 w-5" style={{ color: GOLD }} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">Migration</h1>
            <p className="text-sm text-muted-foreground">
              Phase 5 — remediation tasks and crypto waivers (exceptions).
            </p>
          </div>
        </div>
      </motion.div>

      {loading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground py-12">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading…
        </div>
      ) : (
        <Tabs value={tab} onValueChange={setTab} className="w-full">
          <TabsList className="grid w-full max-w-md grid-cols-2">
            <TabsTrigger value="tasks">Tasks</TabsTrigger>
            <TabsTrigger value="waivers" className="gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5" />
              Waivers
            </TabsTrigger>
          </TabsList>

          <TabsContent value="tasks" className="mt-6 space-y-6">
            <div className="flex flex-wrap items-center gap-2">
              {isAdmin && (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={runSeed}
                  disabled={seeding}
                  className="gap-2 border-[#FBBC09]/40"
                >
                  {seeding ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sprout className="h-4 w-4" />}
                  Seed from scan backlog
                </Button>
              )}
              {!isAdmin && (
                <p className="text-xs text-muted-foreground flex items-center gap-1">
                  <Lock className="h-3 w-3" /> Backlog seeding is admin-only.
                </p>
              )}
            </div>

            <div className="rounded-xl border border-border bg-card p-5 max-w-3xl space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">New task</h3>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="sm:col-span-2 space-y-1">
                  <Label>Title</Label>
                  <Input value={newTitle} onChange={(e) => setNewTitle(e.target.value)} className="bg-secondary" />
                </div>
                <div className="space-y-1">
                  <Label>Domain (optional)</Label>
                  <Input value={newDomain} onChange={(e) => setNewDomain(e.target.value)} className="bg-secondary" placeholder="example.com" />
                </div>
                <div className="space-y-1">
                  <Label>Host (optional)</Label>
                  <Input value={newHost} onChange={(e) => setNewHost(e.target.value)} className="bg-secondary" placeholder="api.example.com" />
                </div>
                <div className="sm:col-span-2 space-y-1">
                  <Label>Description</Label>
                  <textarea
                    value={newDesc}
                    onChange={(e) => setNewDesc(e.target.value)}
                    rows={2}
                    className="w-full px-3 py-2 rounded-md border border-border bg-secondary text-sm"
                  />
                </div>
              </div>
              <Button type="button" onClick={addTask} style={{ backgroundColor: GOLD, color: "#111" }} className="font-semibold gap-2">
                <Plus className="h-4 w-4" />
                Add task
              </Button>
            </div>

            <div className="rounded-xl border border-border bg-card overflow-hidden">
              <div className="px-4 py-3 border-b border-border text-xs font-semibold uppercase text-muted-foreground">
                Task backlog ({tasks.length})
              </div>
              {tasks.length === 0 ? (
                <p className="text-sm text-muted-foreground p-6">No tasks yet — add one or seed from a completed scan.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border bg-secondary/40 text-left text-xs text-muted-foreground">
                        <th className="px-3 py-2">Title</th>
                        <th className="px-3 py-2">Host</th>
                        <th className="px-3 py-2">Priority</th>
                        <th className="px-3 py-2">Status</th>
                        <th className="px-3 py-2 w-32" />
                      </tr>
                    </thead>
                    <tbody>
                      {tasks.map((t) => (
                        <tr key={t.task_id} className="border-b border-border/50">
                          <td className="px-3 py-2 font-medium max-w-[220px] truncate" title={t.title}>{t.title}</td>
                          <td className="px-3 py-2 font-mono text-xs text-muted-foreground">{t.host || "—"}</td>
                          <td className="px-3 py-2 text-xs capitalize">{t.priority || "—"}</td>
                          <td className="px-3 py-2">
                            <select
                              value={t.status || "open"}
                              onChange={(e) => updateTaskStatus(t.task_id, e.target.value)}
                              className="h-8 px-2 rounded border border-border bg-secondary text-xs"
                            >
                              {["open", "in_progress", "done", "cancelled"].map((s) => (
                                <option key={s} value={s}>{s.replace("_", " ")}</option>
                              ))}
                            </select>
                          </td>
                          <td className="px-3 py-2">
                            {isAdmin && (
                              <button
                                type="button"
                                onClick={() => removeTask(t.task_id)}
                                className="text-muted-foreground hover:text-destructive p-1"
                                title="Delete"
                              >
                                <Trash2 className="h-4 w-4" />
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="waivers" className="mt-6 space-y-6">
            <div className="rounded-xl border border-border bg-card p-5 max-w-3xl space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Request waiver</h3>
              <div className="space-y-2">
                <Label>Requestor</Label>
                <Input value={wReq} onChange={(e) => setWReq(e.target.value)} className="bg-secondary" placeholder="Name / team" />
              </div>
              <div className="space-y-2">
                <Label>Reason</Label>
                <textarea
                  value={wReason}
                  onChange={(e) => setWReason(e.target.value)}
                  rows={3}
                  className="w-full px-3 py-2 rounded-md border border-border bg-secondary text-sm"
                  placeholder="Business justification for temporary exception…"
                />
              </div>
              <div className="space-y-2">
                <Label>Impacted assets (comma or newline separated)</Label>
                <textarea
                  value={wAssets}
                  onChange={(e) => setWAssets(e.target.value)}
                  rows={2}
                  className="w-full px-3 py-2 rounded-md border border-border bg-secondary text-sm font-mono text-xs"
                  placeholder="host1.bank.in&#10;legacy-app.bank.in"
                />
              </div>
              <Button type="button" onClick={addWaiver} style={{ backgroundColor: GOLD, color: "#111" }} className="font-semibold gap-2">
                <Plus className="h-4 w-4" />
                Submit waiver
              </Button>
            </div>

            <div className="rounded-xl border border-border bg-card overflow-hidden">
              <div className="px-4 py-3 border-b border-border text-xs font-semibold uppercase text-muted-foreground">
                Waiver queue ({waivers.length})
              </div>
              {waivers.length === 0 ? (
                <p className="text-sm text-muted-foreground p-6">No waivers submitted.</p>
              ) : (
                <div className="divide-y divide-border/60">
                  {waivers.map((w) => (
                    <div key={w.waiver_id} className="p-4 space-y-2">
                      <div className="flex flex-wrap justify-between gap-2">
                        <span className="text-sm font-semibold">{w.requestor}</span>
                        <span className="text-[10px] uppercase px-2 py-0.5 rounded bg-secondary text-muted-foreground">{w.status}</span>
                      </div>
                      <p className="text-sm text-muted-foreground leading-relaxed">{w.reason}</p>
                      {w.impacted_assets && w.impacted_assets.length > 0 && (
                        <p className="text-xs font-mono text-muted-foreground">
                          Assets: {w.impacted_assets.join(", ")}
                        </p>
                      )}
                      <div className="flex flex-wrap gap-2 pt-1">
                        {isAdmin && w.status === "pending" && (
                          <>
                            <Button size="sm" variant="outline" className="h-8 text-xs" onClick={() => setWaiverStatus(w.waiver_id, "approved")}>
                              Approve
                            </Button>
                            <Button size="sm" variant="outline" className="h-8 text-xs" onClick={() => setWaiverStatus(w.waiver_id, "rejected")}>
                              Reject
                            </Button>
                          </>
                        )}
                        {isAdmin && (
                          <button
                            type="button"
                            onClick={() => removeWaiver(w.waiver_id)}
                            className="text-muted-foreground hover:text-destructive p-1 ml-auto"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}
