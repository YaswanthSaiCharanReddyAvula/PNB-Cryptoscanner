import { useEffect, useState } from "react";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
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
import { Link } from "react-router-dom";
import { cryptoService, pqcService, reportingService } from "@/services/api";
import { Loader2, ListPlus, ExternalLink } from "lucide-react";
import { toast } from "sonner";

type NistRef = { label: string; url: string };

type Finding = {
  id: string;
  title: string;
  asset: string;
  algorithm: string;
  threat: string;
  nist: string;
  risk: string;
  detail?: string;
  nistSummary?: string;
  nistRefs?: NistRef[];
  source: "tls" | "cbom";
};

function riskBadge(level: string) {
  const u = level.toUpperCase();
  if (u.includes("CRITICAL"))
    return <Badge className="border-0 bg-red-50 text-red-800">{level}</Badge>;
  if (u.includes("HIGH"))
    return <Badge className="border-0 bg-orange-50 text-orange-800">{level}</Badge>;
  if (u.includes("MEDIUM"))
    return <Badge className="border-0 bg-amber-50 text-amber-900">{level}</Badge>;
  if (u.includes("SAFE") || u.includes("LOW"))
    return <Badge className="border-0 bg-emerald-50 text-emerald-900">{level}</Badge>;
  return <Badge variant="secondary">{level}</Badge>;
}

function threatBadge(id: string) {
  const u = id.toLowerCase();
  const map: Record<string, string> = {
    shor: "bg-violet-50 text-violet-900 border-violet-200",
    grover: "bg-sky-50 text-sky-900 border-sky-200",
    hndl: "bg-amber-50 text-amber-950 border-amber-200",
  };
  return (
    <Badge variant="outline" className={`text-[10px] font-medium uppercase ${map[u] || "border-slate-200"}`}>
      {u}
    </Badge>
  );
}

function tlsThreatLens(tls: string, cipher: string): string {
  const c = (cipher || "").toUpperCase();
  const t = (tls || "").toUpperCase();
  if (/RSA|ECDSA|ECDH|ECC|DH|FFDHE/.test(c) || /RSA|ECDSA|ECDH/.test(t)) return "shor";
  if (/1\.0|1\.1|SSL/.test(t)) return "hndl";
  return "grover";
}

function tlsNistHint(lens: string, weakTls: boolean): string {
  if (weakTls) return "TLS 1.3 + FS (SP 800-208)";
  if (lens === "shor") return "ML-KEM / hybrid KEM (FIPS 203)";
  return "AES-256 / SHA-256+ (Grover margin)";
}

export default function CryptoFindings() {
  const [rows, setRows] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [pick, setPick] = useState<Finding | null>(null);
  const [threatCtx, setThreatCtx] = useState<{
    vectors: { id: string; name: string; affects: string }[];
    from_scan: {
      tls_endpoints: number;
      legacy_protocol_endpoints: number;
      rsa_cipher_or_kx_mentions: number;
      pqc_hybrid_string_signals: number;
    };
  } | null>(null);
  const [nistCatalog, setNistCatalog] = useState<Record<string, NistRef>>({});

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const [cryptoRes, cbomRes, tmRes, catRes] = await Promise.all([
          cryptoService.getCryptoSecurityData(),
          pqcService.getPerAppCbom(),
          reportingService.getThreatModelSummary().catch(() => ({ data: null })),
          reportingService.getNistCatalog().catch(() => ({ data: null })),
        ]);
        if (cancelled) return;

        const tm = tmRes.data as typeof threatCtx;
        if (tm?.vectors && tm?.from_scan) setThreatCtx(tm);

        const catPayload = (catRes.data as { references?: Record<string, NistRef> })?.references;
        const catalog: Record<string, NistRef> =
          catPayload && typeof catPayload === "object" ? catPayload : {};
        if (Object.keys(catalog).length) setNistCatalog(catalog);

        const cryptoRows: unknown[] = Array.isArray(cryptoRes.data) ? cryptoRes.data : [];
        const perApp: Record<string, unknown>[] = Array.isArray(cbomRes.data) ? cbomRes.data : [];

        const out: Finding[] = [];

        cryptoRows.forEach((raw, i) => {
          const r = raw as Record<string, unknown>;
          const tls = String(r.tls_version || "");
          const cipher = String(r.cipher_suite || "");
          const weakTls = /1\.0|1\.1|ssl/i.test(tls);
          const risk = weakTls ? "CRITICAL" : r.pqcStatus === "not-ready" ? "HIGH" : "MEDIUM";
          const lens = tlsThreatLens(tls, cipher);
          out.push({
            id: `tls-${i}`,
            title: weakTls ? "Legacy TLS version" : "TLS cryptographic posture",
            asset: String(r.asset || "—"),
            algorithm: cipher || tls || "—",
            threat: lens,
            nist: tlsNistHint(lens, weakTls),
            risk,
            detail: JSON.stringify(r, null, 2),
            nistSummary: weakTls
              ? "Upgrade to TLS 1.3 with forward secrecy; reduce harvest-now-decrypt-later exposure per org policy."
              : "Review key exchange for hybrid / PQC readiness against Shor-class threats on long-lived records.",
            nistRefs:
              catalog.SP_800_208 || catalog.FIPS_203
                ? ([catalog.SP_800_208, catalog.FIPS_203].filter(Boolean) as NistRef[])
                : undefined,
            source: "tls",
          });
        });

        perApp.slice(0, 60).forEach((c, i) => {
          const name = String(c.name || c.component || "Component");
          const rl = String(c.risk_level || c.risk || "medium");
          const risk =
            rl === "critical"
              ? "CRITICAL"
              : rl === "high"
                ? "HIGH"
                : rl === "safe"
                  ? "SAFE"
                  : "MEDIUM";
          const tv = String(c.threat_vector || c.primary_quantum_threat || "shor").toLowerCase();
          const refsRaw = c.nist_reference_urls;
          const nistRefs = Array.isArray(refsRaw)
            ? (refsRaw as NistRef[]).filter((x) => x && x.url)
            : undefined;
          out.push({
            id: `cbom-${i}`,
            title: name,
            asset: String(c.application || c.asset || "—"),
            algorithm: name,
            threat: tv.includes("grover") ? "grover" : tv.includes("hndl") ? "hndl" : "shor",
            nist: String(c.nist_primary_recommendation || "See NIST PQC publications"),
            risk,
            detail: JSON.stringify(c, null, 2),
            nistSummary: String(c.nist_summary || ""),
            nistRefs,
            source: "cbom",
          });
        });

        setRows(out);
      } catch {
        toast.error("Could not load crypto findings.");
        if (!cancelled) setRows([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-8">
      <DossierPageHeader
        eyebrow="Phase 3 / threat & NIST mapping"
        title="Crypto Findings"
        description="TLS signals plus CBOM components enriched with quantum threat vectors and indicative NIST PQC guidance — not a compliance determination."
        actions={
          <Button variant="outline" className="rounded-lg border-slate-300" disabled>
            <ListPlus className="mr-2 h-4 w-4" />
            Bulk create tasks
          </Button>
        }
      />

      {threatCtx && (
        <div className="dossier-card p-5">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-600">
              Threat model context (latest completed scan)
            </h3>
            <Link
              to="/cbom"
              className="text-xs font-medium text-blue-600 hover:text-blue-700"
            >
              CBOM detail →
            </Link>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 text-sm">
            <div className="rounded-lg border border-slate-100 bg-slate-50/80 px-3 py-2">
              <p className="text-[10px] uppercase text-slate-500">TLS endpoints</p>
              <p className="text-lg font-semibold text-slate-900">{threatCtx.from_scan.tls_endpoints}</p>
            </div>
            <div className="rounded-lg border border-slate-100 bg-slate-50/80 px-3 py-2">
              <p className="text-[10px] uppercase text-slate-500">Legacy TLS (1.0/1.1)</p>
              <p className="text-lg font-semibold text-amber-800">
                {threatCtx.from_scan.legacy_protocol_endpoints}
              </p>
            </div>
            <div className="rounded-lg border border-slate-100 bg-slate-50/80 px-3 py-2">
              <p className="text-[10px] uppercase text-slate-500">RSA in cipher/KX</p>
              <p className="text-lg font-semibold text-slate-900">
                {threatCtx.from_scan.rsa_cipher_or_kx_mentions}
              </p>
            </div>
            <div className="rounded-lg border border-slate-100 bg-slate-50/80 px-3 py-2">
              <p className="text-[10px] uppercase text-slate-500">Hybrid / PQC signals</p>
              <p className="text-lg font-semibold text-emerald-800">
                {threatCtx.from_scan.pqc_hybrid_string_signals}
              </p>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            {threatCtx.vectors.map((v) => (
              <span
                key={v.id}
                className="inline-flex max-w-full flex-col rounded-md border border-slate-200 bg-white px-2 py-1.5 text-left"
                title={v.affects}
              >
                <span className="text-[10px] font-semibold uppercase text-slate-500">{v.id}</span>
                <span className="text-xs text-slate-800">{v.name}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="dossier-card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20 text-slate-500">
            <Loader2 className="mr-2 h-5 w-5 animate-spin" />
            Loading findings…
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="bg-slate-50/80 hover:bg-slate-50/80">
                <TableHead className="text-xs font-semibold uppercase text-slate-600">
                  Finding
                </TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">
                  Asset
                </TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">
                  Threat
                </TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">
                  NIST focus
                </TableHead>
                <TableHead className="text-xs font-semibold uppercase text-slate-600">
                  Risk
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r) => (
                <TableRow
                  key={r.id}
                  className="cursor-pointer border-slate-100 hover:bg-slate-50/50"
                  onClick={() => setPick(r)}
                >
                  <TableCell className="max-w-[200px]">
                    <p className="font-medium text-slate-900">{r.title}</p>
                    <p className="truncate text-[10px] text-slate-500">{r.algorithm}</p>
                  </TableCell>
                  <TableCell className="text-slate-700">{r.asset}</TableCell>
                  <TableCell>{threatBadge(r.threat)}</TableCell>
                  <TableCell className="max-w-[200px] text-xs text-slate-600" title={r.nist}>
                    {r.nist}
                  </TableCell>
                  <TableCell>{riskBadge(r.risk)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      {Object.keys(nistCatalog).length > 0 && (
        <div className="rounded-xl border border-slate-200 bg-slate-50/50 p-4">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-600">
            NIST PQC references (static catalog)
          </p>
          <ul className="flex flex-col gap-1.5 sm:flex-row sm:flex-wrap">
            {Object.entries(nistCatalog).map(([k, ref]) => (
              <li key={k}>
                <a
                  href={ref.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-xs font-medium text-blue-600 hover:underline"
                >
                  {ref.label.slice(0, 48)}
                  {ref.label.length > 48 ? "…" : ""}
                  <ExternalLink className="h-3 w-3 shrink-0 opacity-70" />
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}

      <Sheet open={!!pick} onOpenChange={() => setPick(null)}>
        <SheetContent className="w-full border-l border-slate-200 bg-slate-900 text-slate-100 sm:max-w-lg">
          <SheetHeader>
            <SheetTitle className="text-left text-slate-100">Finding detail</SheetTitle>
          </SheetHeader>
          {pick && (
            <div className="mt-6 space-y-4">
              <div>
                <p className="text-xs uppercase tracking-wider text-slate-500">Title</p>
                <p className="text-lg font-semibold">{pick.title}</p>
              </div>
              <div className="flex flex-wrap gap-2">
                {riskBadge(pick.risk)}
                {threatBadge(pick.threat)}
                <Badge variant="secondary" className="bg-white/10 text-slate-200">
                  {pick.source === "cbom" ? "CBOM (enriched)" : "TLS inventory"}
                </Badge>
              </div>
              {pick.nistSummary ? (
                <div className="rounded-lg border border-white/10 bg-black/40 p-3">
                  <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    NIST-oriented summary
                  </p>
                  <p className="text-sm leading-relaxed text-slate-200">{pick.nistSummary}</p>
                </div>
              ) : null}
              {pick.nistRefs && pick.nistRefs.length > 0 ? (
                <div className="rounded-lg border border-white/10 bg-black/40 p-3">
                  <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    References
                  </p>
                  <ul className="space-y-2">
                    {pick.nistRefs.map((ref, idx) => (
                      <li key={idx}>
                        <a
                          href={ref.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sm text-blue-300 hover:underline"
                        >
                          {ref.label}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
              <div className="rounded-lg border border-white/10 bg-black/40 p-3">
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Evidence
                </p>
                <pre className="max-h-64 overflow-auto text-[11px] leading-relaxed text-slate-300">
                  {pick.detail || "No raw payload."}
                </pre>
              </div>
              <div className="flex gap-2 pt-2">
                <Button className="flex-1 bg-white text-slate-900 hover:bg-slate-200" asChild>
                  <Link to="/migration">Add to migration plan</Link>
                </Button>
                <Button variant="secondary" className="flex-1 bg-white/10 text-white" asChild>
                  <Link to="/migration">Request waiver</Link>
                </Button>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
