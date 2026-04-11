import { useState, useEffect, useMemo } from "react";
import { DataTable } from "@/components/dashboard/DataTable";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { assetService } from "@/services/api";
import { DossierPageHeader } from "@/components/layout/DossierPageHeader";

function getExposure(ip: string) {
  if (!ip || ip === "N/A" || ip === "Unknown") return "Unknown";
  if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.")) return "Internal";
  if (ip.startsWith("172.")) {
    const secondOctet = parseInt(ip.split(".")[1], 10);
    if (secondOctet >= 16 && secondOctet <= 31) return "Internal";
  }
  return "Public";
}

type PortfolioRow = {
  host: string;
  parentDomain: string;
  risk: string;
  owner: string;
  lastScan: string;
  surface: string;
  hosting: string;
  buckets: string;
};

export default function AssetInventory() {
  const [filterExposure, setFilterExposure] = useState("Public Only");
  const [discoveredAssets, setDiscoveredAssets] = useState<any[]>([]);
  const [portfolioRows, setPortfolioRows] = useState<PortfolioRow[]>([]);
  const [portfolioRootFilter, setPortfolioRootFilter] = useState<string>("");
  const [portfolioHostFilter, setPortfolioHostFilter] = useState<string>("__all_subdomains__");
  const [portfolioSurfaceFilter, setPortfolioSurfaceFilter] = useState<string>("__all__");
  const [portfolioMeta, setPortfolioMeta] = useState({ host_count: 0, scans_considered: 0 });
  const [stats, setStats] = useState({
    total: 0,
    publicCount: 0,
    subnets: 0,
    ports: 0,
    locations: 0,
  });

  useEffect(() => {
    assetService
      .getInventorySummary(80)
      .then((res) => {
        const d = res.data as {
          hosts?: Record<string, unknown>[];
          host_count?: number;
          scans_considered?: number;
        };
        const hosts = Array.isArray(d.hosts) ? d.hosts : [];
        setPortfolioMeta({
          host_count: d.host_count ?? hosts.length,
          scans_considered: d.scans_considered ?? 0,
        });
        setPortfolioRows(
          hosts.map((h) => ({
            host: String(h.host ?? "—"),
            parentDomain: String(h.parent_domain ?? "—"),
            risk: String(h.quantum_risk_level ?? "—"),
            owner: String(h.owner ?? "—"),
            lastScan: h.last_completed_at
              ? new Date(String(h.last_completed_at)).toLocaleString()
              : "—",
            surface: String(h.surface ?? "—"),
            hosting: String(h.hosting_hint ?? "—"),
            buckets: Array.isArray(h.buckets) ? h.buckets.slice(0, 8).join(", ") : "—",
          })),
        );
      })
      .catch(() => setPortfolioRows([]));
  }, []);

  const portfolioRootDomains = useMemo(() => {
    const s = new Set<string>();
    for (const r of portfolioRows) {
      const p = (r.parentDomain || "").trim();
      if (p && p !== "—") s.add(p);
    }
    return Array.from(s).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
  }, [portfolioRows]);

  useEffect(() => {
    if (portfolioRootDomains.length === 0) {
      setPortfolioRootFilter("");
      return;
    }
    if (!portfolioRootFilter || !portfolioRootDomains.includes(portfolioRootFilter)) {
      setPortfolioRootFilter(portfolioRootDomains[0]);
      setPortfolioHostFilter("__all_subdomains__");
    }
  }, [portfolioRootDomains, portfolioRootFilter]);

  const portfolioFilteredSorted = useMemo(() => {
    let list = portfolioRows;
    if (portfolioRootFilter) {
      list = list.filter((r) => r.parentDomain === portfolioRootFilter);
    }
    if (portfolioHostFilter !== "__all_subdomains__") {
      list = list.filter((r) => r.host === portfolioHostFilter);
    }
    if (portfolioSurfaceFilter !== "__all__") {
      list = list.filter(
        (r) => (r.surface || "").toLowerCase() === portfolioSurfaceFilter.toLowerCase(),
      );
    }
    return [...list].sort((a, b) => {
      const byParent = a.parentDomain.localeCompare(b.parentDomain, undefined, { sensitivity: "base" });
      if (byParent !== 0) return byParent;
      return a.host.localeCompare(b.host, undefined, { sensitivity: "base" });
    });
  }, [portfolioRows, portfolioRootFilter, portfolioHostFilter, portfolioSurfaceFilter]);

  const subdomainsForSelectedRoot = useMemo(() => {
    if (!portfolioRootFilter) return [];
    return portfolioRows
      .filter((r) => r.parentDomain === portfolioRootFilter)
      .map((r) => r.host)
      .filter((h) => h && h !== "—")
      .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
  }, [portfolioRows, portfolioRootFilter]);

  useEffect(() => {
    assetService.getInventory()
      .then(res => {
        const assets = res.data;
        const formatted = assets.map((a: any) => {
          const ip = a.ip_address || "N/A";
          return {
            detectionDate: a.detection_date ? new Date(a.detection_date).toLocaleDateString() : "N/A",
            hostLabel: a.asset || a.name || "—",
            ipAddress: ip,
            ports: a.ports || "N/A",
            surface: a.surface || "—",
            hosting: a.hosting_hint || "—",
            subnets: a.subnets || "N/A",
            asn: a.asn || "N/A",
            netName: a.net_name || "N/A",
            location: a.location || "N/A",
            company: a.company || "N/A",
            exposure: getExposure(ip),
          };
        });
        
        setDiscoveredAssets(formatted);

        // Compute dynamic stats
        const uniqueSubnets = new Set(assets.map((a: any) => a.subnets).filter(Boolean)).size;
        const uniqueLocations = new Set(assets.map((a: any) => a.location).filter(Boolean)).size;
        
        // Simple port splitting (if comma separated)
        const allPorts = new Set();
        assets.forEach((a: any) => {
          if (a.ports) {
            a.ports.split(",").forEach((p: string) => allPorts.add(p.trim()));
          }
        });

        setStats({
          total: assets.length,
          publicCount: formatted.filter((a: any) => a.exposure === "Public").length,
          subnets: uniqueSubnets,
          ports: allPorts.size,
          locations: uniqueLocations,
        });

      })
      .catch(err => console.error("Could not fetch asset inventory", err));
  }, []);

  return (
    <div className="space-y-8">
      <DossierPageHeader
        eyebrow="Intelligence dossier / inventory"
        title="Inventory Assets"
        description="Discovery feed from the graph service plus Phase 2 deduplicated hosts from recent completed scans and org metadata."
      />

      <div className="grid grid-cols-1 sm:grid-cols-5 gap-4">
        {[
          { label: "Total Discovered", value: stats.total.toString(), color: "text-primary" },
          { label: "Public-Facing Assets", value: stats.publicCount.toString(), color: "text-success" },
          { label: "Unique Subnets", value: stats.subnets.toString(), color: "text-info" },
          { label: "Active Ports", value: stats.ports.toString(), color: "text-[#0ea5e9]" },
          { label: "Locations", value: stats.locations.toString(), color: "text-warning" },
        ].map((s) => (
          <div key={s.label} className="rounded-xl border border-border bg-card p-4">
            <p className="text-xs text-muted-foreground uppercase tracking-wider">{s.label}</p>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      <p className="text-xs text-muted-foreground">
        Portfolio view: {portfolioMeta.host_count} unique host(s) from up to{" "}
        {portfolioMeta.scans_considered} recent completed scan(s) (
        <code className="rounded bg-muted px-1 py-0.5 text-[10px]">GET /inventory/summary</code>
        ). Pick a scanned domain, then narrow by discovered subdomain.
      </p>
      {portfolioRows.length > 0 && (
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:gap-4">
          <div className="space-y-1.5">
            <Label className="text-xs text-muted-foreground">Scanned root domain</Label>
            <Select
              value={portfolioRootFilter}
              onValueChange={(v) => {
                setPortfolioRootFilter(v);
                setPortfolioHostFilter("__all_subdomains__");
              }}
            >
              <SelectTrigger className="h-9 w-full max-w-xs">
                <SelectValue placeholder="Select domain" />
              </SelectTrigger>
              <SelectContent>
                {portfolioRootDomains.map((d) => (
                  <SelectItem key={d} value={d}>
                    {d}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs text-muted-foreground">Found subdomain</Label>
            <Select value={portfolioHostFilter} onValueChange={setPortfolioHostFilter}>
              <SelectTrigger className="h-9 w-full max-w-xs">
                <SelectValue placeholder="All discovered subdomains" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__all_subdomains__">All discovered subdomains</SelectItem>
                {subdomainsForSelectedRoot.map((h) => (
                  <SelectItem key={h} value={h}>
                    {h}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs text-muted-foreground">Surface (classified)</Label>
            <Select value={portfolioSurfaceFilter} onValueChange={setPortfolioSurfaceFilter}>
              <SelectTrigger className="h-9 w-full max-w-xs">
                <SelectValue placeholder="All surfaces" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__all__">All surfaces</SelectItem>
                {["web", "api", "mail", "vpn", "rdp", "unknown"].map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <p className="text-xs text-muted-foreground pb-2">
            Showing {portfolioFilteredSorted.length} host(s)
            {portfolioRootFilter ? ` under ${portfolioRootFilter}` : ""}.
          </p>
        </div>
      )}
      <DataTable
        title={
          portfolioRootFilter
            ? `Scanned domain: ${portfolioRootFilter}`
            : "Portfolio hosts (deduplicated)"
        }
        searchable
        searchKeys={["host", "parentDomain", "owner", "risk", "surface", "hosting", "buckets"]}
        pageSize={10}
        data={portfolioFilteredSorted}
        columns={[
          { key: "host", header: "Host", render: (r) => <span className="font-mono text-sm text-primary">{r.host as string}</span> },
          { key: "surface", header: "Surface" },
          { key: "hosting", header: "Hosting" },
          {
            key: "buckets",
            header: "Buckets",
            render: (r) => (
              <span className="max-w-[240px] truncate text-xs text-muted-foreground" title={r.buckets as string}>
                {r.buckets as string}
              </span>
            ),
          },
          { key: "risk", header: "Quantum risk" },
          { key: "owner", header: "Owner" },
          { key: "lastScan", header: "Last completed" },
        ]}
      />

      <div className="flex items-center gap-3">
        <span className="text-sm font-semibold text-foreground tracking-wide uppercase">Show:</span>
        {["All Assets", "Public Only", "Internal Only"].map(f => (
          <Button
            key={f}
            variant={filterExposure === f ? "default" : "outline"}
            size="sm"
            onClick={() => setFilterExposure(f)}
            className={filterExposure === f ? "bg-primary text-primary-foreground font-semibold" : "bg-card border-border"}
          >
            {f}
          </Button>
        ))}
      </div>

      <DataTable
        title="Discovered Assets"
        searchable
        searchKeys={["hostLabel", "ipAddress", "netName", "location", "asn", "surface", "hosting"]}
        pageSize={12}
        data={discoveredAssets.filter(a => {
          if (filterExposure === "Public Only") return a.exposure === "Public";
          if (filterExposure === "Internal Only") return a.exposure === "Internal";
          return true;
        })}
        columns={[
          { key: "detectionDate", header: "Detection Date" },
          {
            key: "hostLabel",
            header: "Host",
            render: (r) => <span className="font-mono text-xs text-primary">{r.hostLabel as string}</span>,
          },
          { key: "ipAddress", header: "IP Address", render: (r) => <span className="font-mono text-primary">{r.ipAddress as string}</span> },
          { key: "surface", header: "Surface" },
          { key: "hosting", header: "Hosting" },
          { 
            key: "exposure", 
            header: "Exposure", 
            render: (r) => {
              const map: any = { 
                "Public": "bg-success/20 text-success border-success/30", 
                "Internal": "bg-secondary text-muted-foreground border-border", 
                "Unknown": "bg-warning/20 text-warning border-warning/30" 
              };
              return <Badge variant="outline" className={`text-[10px] ${map[r.exposure as string]}`}>{r.exposure as string}</Badge>;
            }
          },
          { key: "ports", header: "Ports", render: (r) => <Badge variant="outline" className="text-[10px] font-mono">{r.ports as string}</Badge> },
          { key: "subnets", header: "Subnets" },
          { key: "asn", header: "ASN" },
          { key: "netName", header: "Net Name" },
          { key: "location", header: "Location" },
          { key: "company", header: "Company" },
        ]}
      />
    </div>
  );
}
