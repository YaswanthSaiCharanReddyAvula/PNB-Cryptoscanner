import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { DataTable } from "@/components/dashboard/DataTable";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { assetService } from "@/services/api";

function getExposure(ip: string) {
  if (!ip || ip === "N/A" || ip === "Unknown") return "Unknown";
  if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.")) return "Internal";
  if (ip.startsWith("172.")) {
    const secondOctet = parseInt(ip.split(".")[1], 10);
    if (secondOctet >= 16 && secondOctet <= 31) return "Internal";
  }
  return "Public";
}

export default function AssetInventory() {
  const [filterExposure, setFilterExposure] = useState("Public Only");
  const [discoveredAssets, setDiscoveredAssets] = useState<any[]>([]);
  const [stats, setStats] = useState({
    total: 0,
    publicCount: 0,
    subnets: 0,
    ports: 0,
    locations: 0,
  });

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
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <h1 className="text-2xl font-bold text-foreground">Asset Inventory</h1>
        <p className="text-sm text-muted-foreground">Discovered asset records and network mapping</p>
      </motion.div>

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
