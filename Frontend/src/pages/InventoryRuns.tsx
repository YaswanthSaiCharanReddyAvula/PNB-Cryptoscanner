import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Loader2, Rocket, ExternalLink } from "lucide-react";
import { DossierPageHeader } from "@/components/layout/DossierPageHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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
  completed_at?: string;
  started_at?: string;
  scan_id?: string;
  batch_id?: string | null;
};

export default function InventoryRuns() {
  const [rows, setRows] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const res = await scanService.getRecentScans(120);
        const payload = res.data as { scans?: Row[] };
        const scans = Array.isArray(payload?.scans) ? payload.scans : [];
        const normalized: Row[] = scans.map((s) => ({
          domain: String(s.domain || ""),
          status: s.status,
          completed_at: s.completed_at,
          started_at: s.started_at,
          scan_id: s.scan_id,
          batch_id: s.batch_id ?? null,
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

  const statusBadge = (s?: string) => {
    const v = (s || "").toLowerCase();
    if (v === "completed")
      return (
        <Badge className="border-0 bg-emerald-50 text-emerald-800 hover:bg-emerald-50">
          Completed
        </Badge>
      );
    if (v === "running" || v === "pending")
      return (
        <Badge className="border-0 bg-blue-50 text-blue-800 hover:bg-blue-50">Running</Badge>
      );
    if (v === "failed")
      return <Badge variant="destructive">Failed</Badge>;
    return (
      <Badge variant="secondary" className="text-slate-600">
        {s || "—"}
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
        <div className="flex items-center justify-between border-b border-slate-100 px-4 py-3">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            Recent runs
          </p>
          <span className="text-xs text-slate-500">{rows.length} jobs</span>
        </div>
        {loading ? (
          <div className="flex items-center justify-center py-20 text-slate-500">
            <Loader2 className="mr-2 h-5 w-5 animate-spin" />
            Loading runs…
          </div>
        ) : rows.length === 0 ? (
          <p className="px-4 py-12 text-center text-sm text-slate-500">
            No scans yet. Start a single or batch scan from Overview.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="bg-slate-50/80 hover:bg-slate-50/80">
                <TableHead className="text-xs font-semibold uppercase text-slate-600">
                  Domain
                </TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">
                  Status
                </TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">
                  Started
                </TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">
                  Completed
                </TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">
                  Batch
                </TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">
                  Scan ID
                </TableHead>
                <TableHead className="text-right text-xs font-semibold uppercase text-slate-600">
                  Actions
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r) => (
                <TableRow key={`${r.scan_id || r.domain}-${r.started_at}`} className="border-slate-100">
                  <TableCell className="font-medium text-slate-900">{r.domain || "—"}</TableCell>
                  <TableCell>{statusBadge(r.status)}</TableCell>
                  <TableCell className="text-slate-600">
                    {r.started_at ? new Date(r.started_at).toLocaleString() : "—"}
                  </TableCell>
                  <TableCell className="text-slate-600">
                    {r.completed_at ? new Date(r.completed_at).toLocaleString() : "—"}
                  </TableCell>
                  <TableCell className="font-mono text-[10px] text-slate-500">
                    {r.batch_id ? `${r.batch_id.slice(0, 8)}…` : "—"}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-slate-500">
                    {r.scan_id || "—"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" asChild className="text-blue-600">
                      <Link to={`/?domain=${encodeURIComponent(r.domain)}`}>
                        Open
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
