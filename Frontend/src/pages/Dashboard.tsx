import { useState } from "react";
import { motion } from "framer-motion";
import {
  Server,
  Globe,
  Code,
  HardDrive,
  AlertTriangle,
  ShieldAlert,
  Search,
} from "lucide-react";
import { StatCard } from "@/components/dashboard/StatCard";
import { DataTable } from "@/components/dashboard/DataTable";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from "recharts";

const stats = [
  { title: "Total Assets", value: "2,847", icon: Server, variant: "gold" as const },
  { title: "Web Applications", value: "342", icon: Globe, variant: "default" as const },
  { title: "APIs", value: "189", icon: Code, variant: "info" as const },
  { title: "Servers", value: "1,204", icon: HardDrive, variant: "default" as const },
  { title: "Expiring Certs", value: "23", icon: AlertTriangle, variant: "red" as const },
  { title: "High Risk Assets", value: "67", icon: ShieldAlert, variant: "red" as const },
];

const distributionData = [
  { name: "Web Apps", value: 342 },
  { name: "APIs", value: 189 },
  { name: "Servers", value: 1204 },
  { name: "Databases", value: 412 },
  { name: "IoT Devices", value: 700 },
];

const CHART_COLORS = [
  "hsl(45, 96%, 51%)",
  "hsl(342, 88%, 35%)",
  "hsl(152, 60%, 45%)",
  "hsl(210, 80%, 55%)",
  "hsl(280, 60%, 55%)",
];

const assetInventoryData = [
  { name: "Core Banking API", url: "api.bank.com", ipv4: "10.0.1.15", ipv6: "::1", type: "API", owner: "Platform Team", risk: "High", certStatus: "Valid", keyLength: "2048", lastScan: "2026-03-12" },
  { name: "Customer Portal", url: "portal.bank.com", ipv4: "10.0.2.20", ipv6: "fe80::1", type: "Web App", owner: "Digital Team", risk: "Medium", certStatus: "Expiring", keyLength: "4096", lastScan: "2026-03-11" },
  { name: "Payment Gateway", url: "pay.bank.com", ipv4: "10.0.3.10", ipv6: "::ffff:10.0.3.10", type: "API", owner: "Payments Team", risk: "Critical", certStatus: "Valid", keyLength: "2048", lastScan: "2026-03-10" },
  { name: "Auth Server", url: "auth.bank.com", ipv4: "10.0.1.5", ipv6: "fe80::2", type: "Server", owner: "Security Team", risk: "Low", certStatus: "Valid", keyLength: "4096", lastScan: "2026-03-12" },
  { name: "Data Warehouse", url: "dw.internal", ipv4: "10.0.5.100", ipv6: "—", type: "Database", owner: "Data Team", risk: "Medium", certStatus: "Valid", keyLength: "2048", lastScan: "2026-03-09" },
];

const nameServerData = [
  { hostname: "ns1.bank.com", type: "A", ipAddress: "203.0.113.1", ttl: "3600" },
  { hostname: "ns2.bank.com", type: "A", ipAddress: "203.0.113.2", ttl: "3600" },
  { hostname: "mail.bank.com", type: "MX", ipAddress: "203.0.113.10", ttl: "7200" },
  { hostname: "api.bank.com", type: "CNAME", ipAddress: "lb.bank.com", ttl: "300" },
];

const cryptoSecurityData = [
  { asset: "Core Banking API", keyLength: "2048-bit RSA", cipherSuite: "TLS_AES_256_GCM_SHA384", tlsVersion: "TLS 1.3", ca: "DigiCert" },
  { asset: "Customer Portal", keyLength: "4096-bit RSA", cipherSuite: "TLS_CHACHA20_POLY1305", tlsVersion: "TLS 1.3", ca: "Let's Encrypt" },
  { asset: "Payment Gateway", keyLength: "2048-bit RSA", cipherSuite: "TLS_AES_128_GCM_SHA256", tlsVersion: "TLS 1.2", ca: "Comodo" },
  { asset: "Auth Server", keyLength: "4096-bit RSA", cipherSuite: "TLS_AES_256_GCM_SHA384", tlsVersion: "TLS 1.3", ca: "DigiCert" },
];

const riskBadge = (risk: string) => {
  const colors: Record<string, string> = {
    Critical: "bg-accent/20 text-accent border-accent/30",
    High: "bg-accent/15 text-accent border-accent/20",
    Medium: "bg-warning/15 text-warning border-warning/20",
    Low: "bg-success/15 text-success border-success/20",
  };
  return (
    <Badge variant="outline" className={`text-[10px] ${colors[risk] || ""}`}>
      {risk}
    </Badge>
  );
};

const certBadge = (status: string) => {
  const colors: Record<string, string> = {
    Valid: "bg-success/15 text-success border-success/20",
    Expiring: "bg-warning/15 text-warning border-warning/20",
    Expired: "bg-accent/15 text-accent border-accent/20",
  };
  return (
    <Badge variant="outline" className={`text-[10px] ${colors[status] || ""}`}>
      {status}
    </Badge>
  );
};

export default function Dashboard() {
  const [domain, setDomain] = useState("");
  const [scannedDomain, setScannedDomain] = useState("");

  const handleScan = () => {
    if (domain.trim()) {
      setScannedDomain(domain.trim());
    }
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <h1 className="text-2xl font-bold text-foreground">Dashboard</h1>
        <p className="text-sm text-muted-foreground">Security overview and asset monitoring</p>
      </motion.div>

      {/* Domain Input */}
      <div className="rounded-xl border border-border bg-card p-5">
        <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-3">Scan Domain</h3>
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Enter domain (e.g., securebank.com)"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              className="pl-10 bg-secondary border-border"
            />
          </div>
          <Button onClick={handleScan} className="bg-primary text-primary-foreground hover:bg-primary/90 px-6">
            Scan
          </Button>
        </div>
        {scannedDomain && (
          <p className="text-xs text-muted-foreground mt-2">
            Showing results for: <span className="text-primary font-medium">{scannedDomain}</span>
          </p>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {stats.map((s, i) => (
          <motion.div key={s.title} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
            <StatCard {...s} />
          </motion.div>
        ))}
      </div>

      {/* Chart + Inventory */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Pie Chart */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-4">
            Assets Distribution
          </h3>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={distributionData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={100}
                paddingAngle={3}
                dataKey="value"
              >
                {distributionData.map((_, i) => (
                  <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "hsl(220, 18%, 13%)",
                  border: "1px solid hsl(220, 14%, 20%)",
                  borderRadius: "8px",
                  fontSize: "12px",
                  color: "hsl(210, 20%, 92%)",
                }}
              />
              <Legend
                wrapperStyle={{ fontSize: "11px", color: "hsl(215, 15%, 55%)" }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Asset Inventory */}
        <div className="xl:col-span-2">
          <DataTable
            title="Assets Inventory"
            searchable
            data={assetInventoryData}
            columns={[
              { key: "name", header: "Asset Name" },
              { key: "url", header: "URL" },
              { key: "ipv4", header: "IPv4" },
              { key: "ipv6", header: "IPv6" },
              { key: "type", header: "Type" },
              { key: "owner", header: "Owner" },
              { key: "risk", header: "Risk", render: (r) => riskBadge(r.risk as string) },
              { key: "certStatus", header: "Cert Status", render: (r) => certBadge(r.certStatus as string) },
              { key: "keyLength", header: "Key Length" },
              { key: "lastScan", header: "Last Scan" },
            ]}
          />
        </div>
      </div>

      {/* Name Server + Crypto */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <DataTable
          title="Name Server Records"
          data={nameServerData}
          columns={[
            { key: "hostname", header: "Hostname" },
            { key: "type", header: "Type" },
            { key: "ipAddress", header: "IP Address" },
            { key: "ttl", header: "TTL" },
          ]}
        />

        <DataTable
          title="Crypto & Security"
          data={cryptoSecurityData}
          columns={[
            { key: "asset", header: "Asset" },
            { key: "keyLength", header: "Key Length" },
            { key: "cipherSuite", header: "Cipher Suite" },
            { key: "tlsVersion", header: "TLS Version" },
            { key: "ca", header: "Certificate Authority" },
          ]}
        />
      </div>
    </div>
  );
}
