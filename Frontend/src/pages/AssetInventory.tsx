import { motion } from "framer-motion";
import { DataTable } from "@/components/dashboard/DataTable";
import { Badge } from "@/components/ui/badge";

const discoveredAssets = Array.from({ length: 50 }, (_, i) => ({
  detectionDate: `2026-03-${String(12 - (i % 10)).padStart(2, "0")}`,
  ipAddress: `10.0.${Math.floor(i / 10)}.${(i % 254) + 1}`,
  ports: [80, 443, 8080, 22, 3306, 5432][i % 6] + (i % 3 === 0 ? ", 443" : ""),
  subnets: `10.0.${Math.floor(i / 10)}.0/24`,
  asn: `AS${10000 + i}`,
  netName: ["BANK-NET", "CORP-NET", "DMZ-NET", "CLOUD-NET"][i % 4],
  location: ["New York", "London", "Singapore", "Frankfurt", "Tokyo"][i % 5],
  company: "SecureBank Corp",
}));

export default function AssetInventory() {
  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <h1 className="text-2xl font-bold text-foreground">Asset Inventory</h1>
        <p className="text-sm text-muted-foreground">Discovered asset records and network mapping</p>
      </motion.div>

      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        {[
          { label: "Total Discovered", value: "50", color: "text-primary" },
          { label: "Unique Subnets", value: "5", color: "text-info" },
          { label: "Active Ports", value: "6", color: "text-success" },
          { label: "Locations", value: "5", color: "text-warning" },
        ].map((s) => (
          <div key={s.label} className="rounded-xl border border-border bg-card p-4">
            <p className="text-xs text-muted-foreground uppercase tracking-wider">{s.label}</p>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      <DataTable
        title="Discovered Assets"
        searchable
        searchKeys={["ipAddress", "netName", "location", "asn"]}
        pageSize={12}
        data={discoveredAssets}
        columns={[
          { key: "detectionDate", header: "Detection Date" },
          { key: "ipAddress", header: "IP Address", render: (r) => <span className="font-mono text-primary">{r.ipAddress as string}</span> },
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
