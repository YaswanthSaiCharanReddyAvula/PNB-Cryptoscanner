import { useEffect, useState } from "react";
import { reportingService } from "@/services/api";
import { Skeleton } from "@/components/ui/skeleton";

type ThreatPayload = {
  vectors: { id: string; name: string; affects: string; note: string }[];
  from_scan: {
    tls_endpoints: number;
    legacy_protocol_endpoints: number;
    rsa_cipher_or_kx_mentions: number;
    pqc_hybrid_string_signals?: number;
  };
};

type RoadmapWave = {
  wave: number;
  name: string;
  focus: string;
  estimated_assets: number;
  nist_alignment?: string;
  priority_score?: number;
};

type BacklogItem = {
  host: string;
  priority_score?: number;
  threat_vector?: string;
  nist_primary_recommendation?: string;
  reason?: string;
  tls_version?: string;
};

type RoadmapPayload = {
  domain: string | null;
  waves: RoadmapWave[];
  backlog?: BacklogItem[];
  nist_pqc_references?: Record<string, { label: string; url: string }>;
};

export function ThreatModelPanel() {
  const [threat, setThreat] = useState<ThreatPayload | null>(null);
  const [roadmap, setRoadmap] = useState<RoadmapPayload | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      reportingService.getThreatModelSummary().catch(() => ({ data: null })),
      reportingService.getMigrationRoadmap().catch(() => ({ data: null })),
    ]).then(([t, r]) => {
      if (cancelled) return;
      setThreat(t.data || null);
      setRoadmap(r.data || null);
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
      <div className="rounded-xl border border-border bg-card p-5">
        <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-1">
          Quantum threat model
        </h3>
        <p className="text-xs text-muted-foreground mb-4">
          How classical cryptography relates to quantum-era risk (indicative; not a formal threat model).
        </p>
        <div className="space-y-3">
          {(threat?.vectors || []).map((v) => (
            <div
              key={v.id}
              className="rounded-lg border border-border/80 bg-secondary/30 p-3 text-sm"
            >
              <p className="font-semibold text-foreground">{v.name}</p>
              <p className="text-[11px] text-muted-foreground mt-0.5">Targets: {v.affects}</p>
              <p className="text-xs text-foreground/90 mt-1.5 leading-snug">{v.note}</p>
            </div>
          ))}
        </div>
        {threat?.from_scan && (
          <div className="mt-4 pt-4 border-t border-border text-xs text-muted-foreground space-y-1">
            <p>
              <span className="text-foreground font-medium">From latest scan:</span>{" "}
              {threat.from_scan.tls_endpoints} TLS endpoints ·{" "}
              {threat.from_scan.legacy_protocol_endpoints} legacy protocol ·{" "}
              {threat.from_scan.rsa_cipher_or_kx_mentions} RSA-related mentions
              {typeof threat.from_scan.pqc_hybrid_string_signals === "number" && (
                <>
                  {" "}
                  · {threat.from_scan.pqc_hybrid_string_signals} PQ/hybrid KEM name signal(s)
                </>
              )}
            </p>
          </div>
        )}
        {roadmap?.nist_pqc_references && Object.keys(roadmap.nist_pqc_references).length > 0 && (
          <div className="mt-4 pt-4 border-t border-border">
            <h4 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground mb-2">
              NIST PQC references
            </h4>
            <ul className="space-y-1.5">
              {Object.entries(roadmap.nist_pqc_references).map(([k, v]) => (
                <li key={k}>
                  <a
                    href={v.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-primary hover:underline leading-snug"
                  >
                    {v.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <div className="rounded-xl border border-border bg-card p-5">
        <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-1">
          Migration roadmap (derived)
        </h3>
        <p className="text-xs text-muted-foreground mb-4">
          Phased view from scan signals — for planning, not automated orchestration.
        </p>
        {!roadmap?.waves?.length ? (
          <p className="text-sm text-muted-foreground">Complete a scan to see suggested waves.</p>
        ) : (
          <ol className="space-y-3">
            {roadmap.waves.map((w) => (
              <li
                key={w.wave}
                className="flex gap-3 rounded-lg border border-border/80 bg-secondary/20 p-3"
              >
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/15 text-xs font-bold text-primary">
                  {w.wave}
                </span>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-foreground">{w.name}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{w.focus}</p>
                  {w.nist_alignment && (
                    <p className="text-[10px] text-muted-foreground mt-1 leading-snug">
                      NIST alignment: {w.nist_alignment}
                    </p>
                  )}
                  <p className="text-[11px] text-muted-foreground mt-1">
                    ~{w.estimated_assets} asset(s) (estimate)
                  </p>
                </div>
              </li>
            ))}
          </ol>
        )}
        {!!roadmap?.backlog?.length && (
          <div className="mt-4 pt-4 border-t border-border">
            <h4 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground mb-2">
              Prioritized backlog
            </h4>
            <ul className="space-y-2 max-h-52 overflow-y-auto pr-1">
              {roadmap.backlog.slice(0, 8).map((b) => (
                <li
                  key={b.host}
                  className="rounded-md border border-border/70 bg-secondary/15 px-2.5 py-2 text-xs"
                >
                  <p className="font-mono font-semibold text-foreground truncate" title={b.host}>
                    {b.host}
                  </p>
                  <p className="text-[10px] text-muted-foreground mt-0.5">
                    Priority {typeof b.priority_score === "number" ? b.priority_score.toFixed(1) : "—"}
                    {b.threat_vector ? ` · ${b.threat_vector}` : ""}
                  </p>
                  {b.nist_primary_recommendation && (
                    <p className="text-[11px] text-muted-foreground mt-1 leading-snug">{b.nist_primary_recommendation}</p>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
