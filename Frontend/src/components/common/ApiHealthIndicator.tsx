import { useEffect, useState } from "react";
import { getApiOrigin, healthService } from "@/services/api";

type Status = "checking" | "ok" | "down";

export function ApiHealthIndicator() {
  const [status, setStatus] = useState<Status>("checking");

  useEffect(() => {
    let cancelled = false;
    const tick = () => {
      healthService
        .check()
        .then((res) => {
          if (cancelled) return;
          setStatus(res.data?.status === "healthy" ? "ok" : "down");
        })
        .catch(() => {
          if (!cancelled) setStatus("down");
        });
    };
    tick();
    const id = window.setInterval(tick, 60_000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  const label =
    status === "checking"
      ? "API: checking…"
      : status === "ok"
        ? "API: connected"
        : "API: unreachable";

  const color =
    status === "checking"
      ? "bg-muted-foreground/50"
      : status === "ok"
        ? "bg-emerald-500"
        : "bg-destructive";

  return (
    <div
      className="hidden lg:flex items-center gap-1.5 px-2 py-1 rounded-md border border-border/60 bg-secondary/40"
      title={`${label} (${getApiOrigin()})`}
    >
      <span className={`h-2 w-2 rounded-full shrink-0 ${color}`} aria-hidden />
      <span className="text-[10px] text-muted-foreground max-w-[120px] truncate">{label}</span>
    </div>
  );
}
