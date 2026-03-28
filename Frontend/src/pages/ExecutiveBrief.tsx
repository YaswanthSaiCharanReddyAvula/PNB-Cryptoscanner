import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { FileDown, Loader2, Printer, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { DossierPageHeader } from "@/components/layout/DossierPageHeader";
import { dashboardService, adminService } from "@/services/api";

type Alignment = {
  tls_endpoints?: number;
  below_min_tls?: number;
  unknown_tls_version?: number;
  forward_secrecy_heuristic_flags?: number;
  policy_min_tls_version?: string;
  require_forward_secrecy?: boolean;
  note?: string;
} | null;

type DomainRow = {
  domain?: string;
  risk_level?: string;
  score?: number;
  completed_at?: string;
};

type ExecutiveBriefPayload = {
  generated_at?: string;
  disclaimer?: string;
  kpis?: Record<string, number>;
  portfolio?: { unique_hosts_observed?: number; completed_scans_in_window?: number };
  migration?: { open_tasks?: number; pending_waivers?: number };
  policy?: {
    has_scan?: boolean;
    scan_domain?: string | null;
    targets?: Record<string, unknown>;
    alignment?: Alignment;
  };
  domains?: DomainRow[];
};

function formatWhen(v: unknown): string {
  if (v == null) return "—";
  if (typeof v === "string") return v.slice(0, 19).replace("T", " ");
  if (typeof v === "object" && v !== null && "toISOString" in v) {
    try {
      return (v as Date).toISOString().slice(0, 19).replace("T", " ");
    } catch {
      return "—";
    }
  }
  return String(v);
}

export default function ExecutiveBrief() {
  const [data, setData] = useState<ExecutiveBriefPayload | null>(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const res = await dashboardService.getExecutiveBrief();
      setData(res.data as ExecutiveBriefPayload);
    } catch {
      toast.error("Could not load executive brief.");
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handlePrint = async () => {
    try {
      await adminService.logExport({
        export_type: "executive_brief_print",
        domain: data?.policy?.scan_domain ?? null,
      });
    } catch {
      /* audit is best-effort */
    }
    window.print();
  };

  const downloadJson = async () => {
    if (!data) return;
    try {
      await adminService.logExport({
        export_type: "executive_brief_json",
        domain: data.policy?.scan_domain ?? null,
      });
    } catch {
      /* best-effort */
    }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `quantumshield-executive-brief-${data.generated_at?.slice(0, 10) ?? "snapshot"}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Brief downloaded.");
  };

  const kpis = data?.kpis ?? {};
  const alignment = data?.policy?.alignment;

  return (
    <div className="printable-cbom printable-executive-brief space-y-8 pb-16">
      <DossierPageHeader
        eyebrow="Phase 6 · Stakeholder reporting"
        title="Executive brief"
        description="Single portfolio snapshot for leadership — same heuristics as the main dashboard; not a compliance attestation."
        actions={
          <div className="no-print flex flex-wrap items-center gap-2">
            <Button type="button" variant="outline" size="sm" className="gap-2" onClick={() => load()} disabled={loading}>
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
              Refresh
            </Button>
            <Button type="button" variant="outline" size="sm" className="gap-2" onClick={downloadJson} disabled={!data}>
              <FileDown className="h-4 w-4" />
              JSON
            </Button>
            <Button type="button" size="sm" className="gap-2" onClick={handlePrint} disabled={!data}>
              <Printer className="h-4 w-4" />
              Print
            </Button>
          </div>
        }
      />

      {loading && !data && (
        <div className="dossier-card flex items-center justify-center gap-2 p-12 text-sm text-slate-500">
          <Loader2 className="h-5 w-5 animate-spin" />
          Loading brief…
        </div>
      )}

      {data && (
        <>
          <p className="rounded-lg border border-amber-200/80 bg-amber-50/90 px-4 py-3 text-sm text-amber-950">
            {data.disclaimer}
          </p>

          <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500">
            <span>
              Generated <strong className="text-slate-700">{data.generated_at ?? "—"}</strong> UTC
            </span>
            <span className="no-print">·</span>
            <Link to="/" className="no-print text-primary underline-offset-4 hover:underline">
              Back to overview
            </Link>
          </div>

          <section className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-[0.14em] text-slate-500">Portfolio KPIs</h2>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {[
                ["Total asset rows (window)", kpis.total_assets],
                ["Web-facing", kpis.public_web_apps],
                ["Servers", kpis.servers],
                ["API / other", kpis.apis],
                ["Certs expiring ≤30d", kpis.expiring_certificates],
                ["High-risk scans (window)", kpis.high_risk_assets],
              ].map(([label, val]) => (
                <div key={String(label)} className="dossier-card rounded-xl p-4">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</p>
                  <p className="mt-1 text-2xl font-bold tabular-nums text-slate-900">{val ?? 0}</p>
                </div>
              ))}
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="dossier-card rounded-xl p-4">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Unique hosts (deduped)
                </p>
                <p className="mt-1 text-2xl font-bold tabular-nums text-slate-900">
                  {data.portfolio?.unique_hosts_observed ?? 0}
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  Across last {data.portfolio?.completed_scans_in_window ?? 0} completed scan(s) in window.
                </p>
              </div>
              <div className="dossier-card rounded-xl p-4">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Migration queue</p>
                <p className="mt-2 flex flex-wrap gap-2 text-sm text-slate-700">
                  <Badge variant="outline" className="font-mono">
                    {data.migration?.open_tasks ?? 0} open / in-progress tasks
                  </Badge>
                  <Badge variant="outline" className="font-mono">
                    {data.migration?.pending_waivers ?? 0} pending waivers
                  </Badge>
                </p>
                <Link
                  to="/migration"
                  className="no-print mt-3 inline-block text-xs font-medium text-primary underline-offset-4 hover:underline"
                >
                  Open migration →
                </Link>
              </div>
            </div>
          </section>

          <section className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-[0.14em] text-slate-500">Policy vs latest scan</h2>
            <div className="dossier-card overflow-hidden rounded-xl">
              <div className="border-b border-slate-100 bg-slate-50/80 px-4 py-3 text-sm">
                {data.policy?.has_scan ? (
                  <span>
                    Compared against latest completed scan:{" "}
                    <strong className="text-slate-900">{data.policy.scan_domain}</strong>
                  </span>
                ) : (
                  <span className="text-slate-600">No completed scan available for comparison.</span>
                )}
              </div>
              <div className="grid gap-4 p-4 sm:grid-cols-2">
                <div className="text-sm text-slate-600">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Org targets</p>
                  <ul className="mt-2 space-y-1">
                    <li>Min TLS: {String(data.policy?.targets?.min_tls_version ?? "—")}</li>
                    <li>Forward secrecy: {data.policy?.targets?.require_forward_secrecy ? "Yes" : "No"}</li>
                    <li className="line-clamp-2">
                      PQC target: {String(data.policy?.targets?.pqc_readiness_target || "—")}
                    </li>
                  </ul>
                  <Link
                    to="/policy"
                    className="no-print mt-3 inline-block text-xs font-medium text-primary underline-offset-4 hover:underline"
                  >
                    Policy &amp; standards →
                  </Link>
                </div>
                <div className="text-sm text-slate-600">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Indicative alignment</p>
                  {alignment ? (
                    <ul className="mt-2 space-y-1">
                      <li>TLS endpoints: {alignment.tls_endpoints ?? 0}</li>
                      <li>Below min TLS: {alignment.below_min_tls ?? 0}</li>
                      <li>Unknown TLS version: {alignment.unknown_tls_version ?? 0}</li>
                      <li>FS heuristic flags: {alignment.forward_secrecy_heuristic_flags ?? 0}</li>
                    </ul>
                  ) : (
                    <p className="mt-2 text-slate-500">—</p>
                  )}
                  {alignment?.note && (
                    <p className="mt-3 border-l-2 border-slate-200 pl-3 text-xs text-slate-500">{alignment.note}</p>
                  )}
                </div>
              </div>
            </div>
          </section>

          <section className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-[0.14em] text-slate-500">Domains at a glance</h2>
            <div className="dossier-card overflow-x-auto rounded-xl">
              <table className="w-full min-w-[480px] border-collapse text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50/90 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                    <th className="px-4 py-3">Domain</th>
                    <th className="px-4 py-3">Risk</th>
                    <th className="px-4 py-3">Score</th>
                    <th className="px-4 py-3">Last completed</th>
                  </tr>
                </thead>
                <tbody>
                  {(data.domains ?? []).length === 0 ? (
                    <tr>
                      <td colSpan={4} className="px-4 py-8 text-center text-slate-500">
                        No completed scans yet.
                      </td>
                    </tr>
                  ) : (
                    (data.domains ?? []).map((row) => (
                      <tr key={row.domain ?? "?"} className="border-b border-slate-100">
                        <td className="px-4 py-2.5 font-medium text-slate-900">{row.domain}</td>
                        <td className="px-4 py-2.5 capitalize">{row.risk_level ?? "—"}</td>
                        <td className="px-4 py-2.5 tabular-nums">{row.score ?? "—"}</td>
                        <td className="px-4 py-2.5 text-slate-600">{formatWhen(row.completed_at)}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
