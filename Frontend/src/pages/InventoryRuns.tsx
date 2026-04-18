import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useDomain } from "@/contexts/DomainContext";
import { Loader2, Rocket, ExternalLink } from "lucide-react";
import { DossierPageHeader } from "@/components/layout/DossierPageHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { scanService } from "@/services/api";
import { toast } from "sonner";

type Row = {
  domain: string;
  status?: string;
  error?: string;
  completed_at?: string;
  started_at?: string;
  scan_id?: string;
  batch_id?: string | null;
  quantum_score?: number | null;
  risk_level?: string | null;
};

function normalizeScanStatus(status: unknown, error: unknown): string {
  let v = String(status ?? "")
    .trim()
    .toLowerCase();
  if (v.includes(".")) {
    v = v.split(".").pop() || v;
  }
  const err = error != null ? String(error).trim() : "";
  if (err && (v === "running" || v === "pending")) {
    return "failed";
  }
  return v || "unknown";
}

type StatusFilter = "all" | "completed" | "running" | "failed";
type SortMode =
  | "domain_asc"
  | "domain_desc"
  | "started_desc"
  | "started_asc"
  | "completed_desc"
  | "completed_asc";

export default function InventoryRuns() {
  const { selectedDomain } = useDomain();
  const [rows, setRows] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [sortMode, setSortMode] = useState<SortMode>("domain_asc");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const res = await scanService.getRecentScans(120);
        const payload = res.data as { scans?: Row[] };
        const scans = Array.isArray(payload?.scans) ? payload.scans : [];
        const normalized: Row[] = scans.map((s: any) => ({
          domain: String(s.domain || ""),
          status: normalizeScanStatus(s.status, s.error),
          error: s.error != null ? String(s.error) : undefined,
          completed_at: s.completed_at,
          started_at: s.started_at,
          scan_id: s.scan_id,
          batch_id: s.batch_id ?? null,
          quantum_score: typeof s.quantum_score === "object" && s.quantum_score !== null
            ? (s.quantum_score.score ?? null)
            : (s.quantum_score ?? null),
          risk_level: s.risk_level
            ?? (typeof s.quantum_score === "object" && s.quantum_score !== null ? s.quantum_score.risk_level : null)
            ?? null,
        }));
        if (!cancelled) setRows(normalized);
      } catch {
        toast.error("Could not load inventory runs.");
        if (!cancelled) setRows([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const uniqueDomains = useMemo(() => {
    const s = new Set<string>();
    for (const r of rows) {
      const d = (r.domain || "").trim().toLowerCase();
      if (d) s.add(d);
    }
    return Array.from(s).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
  }, [rows]);

  const filteredSorted = useMemo(() => {
    const q = selectedDomain?.trim().toLowerCase() || "";
    let list = rows.filter((r) => {
      if (q && !(r.domain || "").toLowerCase().includes(q)) return false;
      if (statusFilter === "all") return true;
      const st = (r.status || "").toLowerCase();
      if (statusFilter === "running") return st === "running" || st === "pending";
      if (statusFilter === "completed") return st === "completed";
      if (statusFilter === "failed") return st === "failed";
      return true;
    });

    const tStarted = (r: Row) => {
      const v = r.started_at;
      return v ? new Date(v).getTime() : 0;
    };
    const tCompleted = (r: Row) => {
      const v = r.completed_at;
      return v ? new Date(v).getTime() : 0;
    };

    list = [...list].sort((a, b) => {
      const cmpDom = (a.domain || "").localeCompare(b.domain || "", undefined, { sensitivity: "base" });
      switch (sortMode) {
        case "domain_asc":
          return cmpDom;
        case "domain_desc":
          return -cmpDom;
        case "started_desc":
          return tStarted(b) - tStarted(a);
        case "started_asc":
          return tStarted(a) - tStarted(b);
        case "completed_desc":
          return tCompleted(b) - tCompleted(a);
        case "completed_asc":
          return tCompleted(a) - tCompleted(b);
        default:
          return 0;
      }
    });
    return list;
  }, [rows, selectedDomain, statusFilter, sortMode]);

  const statusBadge = (r: Row) => {
    const v = (r.status || "").toLowerCase();
    if (v === "completed")
      return (
        <Badge className="border-0 bg-emerald-50 text-emerald-800 hover:bg-emerald-50">
          Completed
        </Badge>
      );
    if (v === "running" || v === "pending")
      return (
        <Badge className="border-0 bg-blue-50 text-blue-800 hover:bg-blue-50">
          {v === "pending" ? "Pending" : "Running"}
        </Badge>
      );
    if (v === "failed")
      return (
        <Badge
          variant="destructive"
          title={r.error ? r.error : undefined}
          className={r.error ? "cursor-help" : undefined}
        >
          Failed
        </Badge>
      );
    return (
      <Badge variant="secondary" className="text-slate-600">
        {r.status || "—"}
      </Badge>
    );
  };

  return (
    <div className="space-y-8">
      <DossierPageHeader
        eyebrow="Intelligence dossier / inventory history"
        title="Inventory Runs"
        description="Scan execution queue across your estate — single portfolio feed from Phase 2 /scans/recent."
        actions={
          <Button asChild className="rounded-lg bg-slate-900 text-white hover:bg-slate-800">
            <Link to="/" className="gap-2">
              <Rocket className="h-4 w-4" />
              Run inventory
            </Link>
          </Button>
        }
      />

      <div className="dossier-card overflow-hidden">
        <div className="flex flex-col gap-4 border-b border-slate-100 px-4 py-4 sm:flex-row sm:flex-wrap sm:items-end sm:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Recent runs
            </p>
            <p className="mt-1 text-xs text-slate-500">
              Filter by domain and status; sort by domain name or scan times.
            </p>
          </div>
          <span className="text-xs text-slate-500">
            Showing {filteredSorted.length} of {rows.length} job{rows.length === 1 ? "" : "s"}
          </span>
        </div>

        {!loading && rows.length > 0 && (
          <div className="flex flex-col gap-4 border-b border-slate-100 px-4 py-4">
            <div className="grid gap-4 sm:grid-cols-2 sm:max-w-xl">
              <div className="space-y-1.5">
                <Label className="text-xs text-slate-600">Status</Label>
                <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as StatusFilter)}>
                  <SelectTrigger className="h-9">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All statuses</SelectItem>
                    <SelectItem value="completed">Completed</SelectItem>
                    <SelectItem value="running">Running / pending</SelectItem>
                    <SelectItem value="failed">Failed</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs text-slate-600">Sort by</Label>
                <Select value={sortMode} onValueChange={(v) => setSortMode(v as SortMode)}>
                  <SelectTrigger className="h-9">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="domain_asc">Domain A → Z</SelectItem>
                    <SelectItem value="domain_desc">Domain Z → A</SelectItem>
                    <SelectItem value="started_desc">Started (newest first)</SelectItem>
                    <SelectItem value="started_asc">Started (oldest first)</SelectItem>
                    <SelectItem value="completed_desc">Completed (newest first)</SelectItem>
                    <SelectItem value="completed_asc">Completed (oldest first)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-20 text-slate-500">
            <Loader2 className="mr-2 h-5 w-5 animate-spin" />
            Loading runs…
          </div>
        ) : rows.length === 0 ? (
          <p className="px-4 py-12 text-center text-sm text-slate-500">
            No scans yet. Start a single or batch scan from Overview.
          </p>
        ) : filteredSorted.length === 0 ? (
          <p className="px-4 py-12 text-center text-sm text-slate-500">
            No runs match your filters. Clear the domain filter or widen status.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="bg-slate-50/80 hover:bg-slate-50/80">
                <TableHead className="text-xs font-semibold uppercase text-slate-600">Domain</TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">Status</TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">Risk</TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">Started</TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">Completed</TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">Scan ID</TableHead>
                <TableHead className="text-right text-xs font-semibold uppercase text-slate-600">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredSorted.map((r) => (
                <TableRow key={`${r.scan_id || r.domain}-${r.started_at}`} className="border-slate-100">
                  <TableCell className="font-medium text-slate-900 font-mono">{r.domain || "—"}</TableCell>
                  <TableCell>{statusBadge(r)}</TableCell>
                  <TableCell>
                    {r.risk_level ? (
                      <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${
                        r.risk_level === "critical" ? "bg-red-50 text-red-700 border-red-200" :
                        r.risk_level === "high" ? "bg-orange-50 text-orange-700 border-orange-200" :
                        r.risk_level === "medium" ? "bg-yellow-50 text-yellow-700 border-yellow-200" :
                        "bg-green-50 text-green-700 border-green-200"
                      }`}>{r.risk_level}{r.quantum_score != null ? ` · ${Number(r.quantum_score).toFixed(0)}` : ""}</span>
                    ) : <span className="text-slate-300">—</span>}
                  </TableCell>
                  <TableCell className="text-slate-600 text-xs">
                    {r.started_at ? new Date(r.started_at).toLocaleString() : "—"}
                  </TableCell>
                  <TableCell className="text-slate-600 text-xs">
                    {r.completed_at ? new Date(r.completed_at).toLocaleString() : "—"}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-slate-400">
                    {r.scan_id ? `${r.scan_id.slice(0, 12)}…` : "—"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" asChild className="text-blue-600">
                      <Link to={`/scan-results/${encodeURIComponent(r.domain)}`}>
                        Results
                        <ExternalLink className="ml-1 h-3 w-3" />
                      </Link>
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  );
}
