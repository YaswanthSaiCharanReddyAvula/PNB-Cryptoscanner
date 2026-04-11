import { useCallback, useEffect, useState } from "react";
import { Check, Loader2, Mail } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { adminService } from "@/services/api";

export type AdminNotificationRow = {
  notification_id?: string;
  from_email?: string;
  from_name?: string;
  subject?: string;
  body?: string;
  category?: string;
  created_at?: string;
  read_at?: string | null;
  read_by?: string | null;
};

export function AdminNotificationInbox() {
  const [rows, setRows] = useState<AdminNotificationRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await adminService.listNotifications({ limit: 80, skip: 0, unread_only: false });
      const list = res.data?.notifications;
      setRows(Array.isArray(list) ? list : []);
    } catch {
      toast.error("Could not load notifications.");
      setRows([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const markRead = async (id: string) => {
    setBusyId(id);
    try {
      await adminService.markNotificationRead(id);
      window.dispatchEvent(new Event("qs-notifications-updated"));
      await load();
    } catch {
      toast.error("Could not mark as read.");
    } finally {
      setBusyId(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground py-8">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading inbox…
      </div>
    );
  }

  if (!rows.length) {
    return (
      <div className="rounded-xl border border-dashed border-border bg-card/50 p-8 text-center text-sm text-muted-foreground">
        <Mail className="h-8 w-8 mx-auto mb-2 opacity-50" />
        No messages from employees yet.
      </div>
    );
  }

  return (
    <div className="space-y-3 max-w-4xl">
      {rows.map((n) => {
        const id = String(n.notification_id || "");
        const unread = !n.read_at;
        return (
          <div
            key={id}
            className={`rounded-xl border p-4 text-sm ${
              unread ? "border-primary/40 bg-primary/5" : "border-border bg-card"
            }`}
          >
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <p className="font-semibold text-foreground">{n.subject || "(no subject)"}</p>
                <p className="text-xs text-muted-foreground mt-1">
                  From {n.from_name || n.from_email || "unknown"}{" "}
                  {n.from_email ? <span className="font-mono">&lt;{n.from_email}&gt;</span> : null}
                  {n.category ? (
                    <span className="ml-2 rounded bg-secondary px-1.5 py-0.5 text-[10px] uppercase">
                      {n.category}
                    </span>
                  ) : null}
                </p>
              </div>
              <div className="flex flex-col items-end gap-1">
                <span className="text-[11px] text-muted-foreground">
                  {n.created_at ? new Date(n.created_at).toLocaleString() : ""}
                </span>
                {unread ? (
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="h-8 gap-1"
                    disabled={busyId === id}
                    onClick={() => void markRead(id)}
                  >
                    {busyId === id ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Check className="h-3.5 w-3.5" />
                    )}
                    Mark read
                  </Button>
                ) : (
                  <span className="text-[11px] text-muted-foreground">
                    Read{n.read_by ? ` by ${n.read_by}` : ""}
                  </span>
                )}
              </div>
            </div>
            <pre className="mt-3 whitespace-pre-wrap font-sans text-foreground/90 text-[13px] leading-relaxed border-t border-border/60 pt-3">
              {n.body || ""}
            </pre>
          </div>
        );
      })}
    </div>
  );
}
