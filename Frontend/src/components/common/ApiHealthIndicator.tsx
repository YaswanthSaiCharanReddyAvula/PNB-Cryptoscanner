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
      className="hidden items-center gap-1.5 rounded-md border border-slate-200 bg-slate-100/80 px-2 py-1 lg:flex"
      title={`${label} (${getApiOrigin()})`}
    >
      <span className={`h-2 w-2 shrink-0 rounded-full ${color}`} aria-hidden />
      <span className="max-w-[120px] truncate text-[10px] text-slate-600">{label}</span>
    </div>
  );
}
