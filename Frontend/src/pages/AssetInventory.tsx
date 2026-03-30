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
};

export default function AssetInventory() {
  const [filterExposure, setFilterExposure] = useState("Public Only");
  const [discoveredAssets, setDiscoveredAssets] = useState<any[]>([]);
  const [portfolioRows, setPortfolioRows] = useState<PortfolioRow[]>([]);
  const [portfolioRootFilter, setPortfolioRootFilter] = useState<string>("__all__");
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

  const portfolioFilteredSorted = useMemo(() => {
    let list = portfolioRows;
    if (portfolioRootFilter !== "__all__") {
      list = list.filter((r) => r.parentDomain === portfolioRootFilter);
    }
    return [...list].sort((a, b) => {
      const byParent = a.parentDomain.localeCompare(b.parentDomain, undefined, { sensitivity: "base" });
      if (byParent !== 0) return byParent;
      return a.host.localeCompare(b.host, undefined, { sensitivity: "base" });
    });
  }, [portfolioRows, portfolioRootFilter]);

  useEffect(() => {
    assetService.getInventory()
      .then(res => {
        const assets = res.data;
        const formatted = assets.map((a: any) => {
          const ip = a.ip_address || "N/A";
          return {
            detectionDate: a.detection_date ? new Date(a.detection_date).toLocaleDateString() : "N/A",
            ipAddress: ip,
            ports: a.ports || "N/A",
            subnets: a.subnets || "N/A",
            asn: a.asn || "N/A",
            netName: a.net_name || "N/A",
            location: a.location || "N/A",
            company: a.company || "N/A",
            exposure: getExposure(ip)
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
        ). Filter by root domain; rows are sorted by root domain, then hostname.
      </p>
      {portfolioRows.length > 0 && (
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:gap-4">
          <div className="space-y-1.5">
            <Label className="text-xs text-muted-foreground">Scanned root domain</Label>
            <Select value={portfolioRootFilter} onValueChange={setPortfolioRootFilter}>
              <SelectTrigger className="h-9 w-full max-w-xs">
                <SelectValue placeholder="All roots" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__all__">All scanned domains</SelectItem>
                {portfolioRootDomains.map((d) => (
                  <SelectItem key={d} value={d}>
                    {d}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <p className="text-xs text-muted-foreground pb-2">
            Showing {portfolioFilteredSorted.length} host(s)
            {portfolioRootFilter !== "__all__" ? ` under ${portfolioRootFilter}` : ""}.
          </p>
        </div>
      )}
      <DataTable
        title="Portfolio hosts (deduplicated)"
        searchable
        searchKeys={["host", "parentDomain", "owner", "risk"]}
        pageSize={10}
        data={portfolioFilteredSorted}
        columns={[
          { key: "host", header: "Host", render: (r) => <span className="font-mono text-sm text-primary">{r.host as string}</span> },
          { key: "parentDomain", header: "Root domain" },
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
        searchKeys={["ipAddress", "netName", "location", "asn"]}
        pageSize={12}
        data={discoveredAssets.filter(a => {
          if (filterExposure === "Public Only") return a.exposure === "Public";
          if (filterExposure === "Internal Only") return a.exposure === "Internal";
          return true;
        })}
        columns={[
          { key: "detectionDate", header: "Detection Date" },
          { key: "ipAddress", header: "IP Address", render: (r) => <span className="font-mono text-primary">{r.ipAddress as string}</span> },
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
