import { useState, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { discoveryService, assetService, cryptoService, dnsService } from "@/services/api";
import {
  Search,
  Network,
  ChevronUp,
  ChevronDown,
  ChevronsUpDown,
  X,
  CalendarIcon,
} from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";

// ── Theme constants ───────────────────────────────────────────────────────────
const BRAND = "#2563eb";
const ON_BRAND = "#f8fafc";

// ── Types ─────────────────────────────────────────────────────────────────────
type SubFilter = "New" | "False Positive" | "Confirmed" | "All";


// ── Column definitions ────────────────────────────────────────────────────────
type ColDef<T> = { key: keyof T; header: string; className?: string };

type DomainRow   = { detectionDate: string; domainName: string; registrationDate: string; registrar: string; company: string };
type SslRow      = { detectionDate: string; sha: string; validFrom: string; commonName: string; company: string; ca: string };
type IpRow       = { detectionDate: string; ip: string; ports: string; subnet: string; asn: string; netname: string; location: string; company: string };
type SoftwareRow = { detectionDate: string; product: string; version: string; type: string; port: string; host: string; company: string };

const DOMAIN_COLS: ColDef<DomainRow>[] = [
  { key: "detectionDate",    header: "Detection Date" },
  { key: "domainName",       header: "Domain Name", className: "font-mono text-xs" },
  { key: "registrationDate", header: "Registration Date" },
  { key: "registrar",        header: "Registrar" },
  { key: "company",          header: "Company Name" },
];
const SSL_COLS: ColDef<SslRow>[] = [
  { key: "detectionDate", header: "Detection Date" },
  { key: "sha",           header: "SSL SHA Fingerprint", className: "font-mono text-[10px] max-w-[140px] truncate" },
  { key: "validFrom",     header: "Valid From" },
  { key: "commonName",    header: "Common Name" },
  { key: "company",       header: "Company Name" },
  { key: "ca",            header: "Certificate Authority" },
];
const IP_COLS: ColDef<IpRow>[] = [
  { key: "detectionDate", header: "Detection Date" },
  { key: "ip",            header: "IP Address", className: "font-mono" },
  { key: "ports",         header: "Ports" },
  { key: "subnet",        header: "Subnet", className: "font-mono" },
  { key: "asn",           header: "ASN" },
  { key: "netname",       header: "Netname" },
  { key: "location",      header: "Location" },
  { key: "company",       header: "Company" },
];
const SW_COLS: ColDef<SoftwareRow>[] = [
  { key: "detectionDate", header: "Detection Date" },
  { key: "product",       header: "Product" },
  { key: "version",       header: "Version", className: "font-mono" },
  { key: "type",          header: "Type" },
  { key: "port",          header: "Port", className: "font-mono" },
  { key: "host",          header: "Host", className: "font-mono text-xs" },
  { key: "company",       header: "Company Name" },
];

// ── Generic Sortable Table ─────────────────────────────────────────────────────
function SortableTable<T extends Record<string, string>>({
  cols,
  data,
  search,
}: {
  cols: ColDef<T>[];
  data: T[];
  search: string;
}) {
  const [sortKey, setSortKey] = useState<keyof T | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 6;

  const filtered = useMemo(() => {
    if (!search.trim()) return data;
    const q = search.toLowerCase();
    return data.filter((row) =>
      Object.values(row).some((v) => String(v).toLowerCase().includes(q))
    );
  }, [data, search]);

  const sorted = useMemo(() => {
    if (!sortKey) return filtered;
    return [...filtered].sort((a, b) => {
      const av = String(a[sortKey]);
      const bv = String(b[sortKey]);
      return sortDir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
    });
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const pageData = sorted.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const handleSort = (key: keyof T) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
    setPage(1);
  };

  const SortIcon = ({ k }: { k: keyof T }) => {
    if (sortKey !== k) return <ChevronsUpDown size={12} className="opacity-40" />;
    return sortDir === "asc" ? <ChevronUp size={12} /> : <ChevronDown size={12} />;
  };

  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr style={{ backgroundColor: BRAND }}>
              {cols.map((col) => (
                <th
                  key={String(col.key)}
                  onClick={() => handleSort(col.key)}
                  className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wide cursor-pointer select-none whitespace-nowrap"
                  style={{ color: ON_BRAND }}
                >
                  <span className="flex items-center gap-1">
                    {col.header}
                    <SortIcon k={col.key} />
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {pageData.length === 0 ? (
              <tr>
                <td colSpan={cols.length} className="px-4 py-8 text-center text-muted-foreground text-sm">
                  No records found
                </td>
              </tr>
            ) : (
              pageData.map((row, i) => (
                <tr
                  key={i}
                  className="border-b border-border/40 hover:bg-secondary/40 transition-colors"
                  style={{
                    backgroundColor:
                      i % 2 === 0
                        ? "rgba(162,14,55,0.04)"   // light pink tint
                        : "transparent",
                  }}
                >
                  {cols.map((col) => (
                    <td
                      key={String(col.key)}
                      className={`px-4 py-2.5 text-foreground text-xs ${col.className ?? ""}`}
                    >
                      {String(row[col.key])}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between px-4 py-3 border-t border-border">
        <span className="text-xs text-muted-foreground">
          {sorted.length === 0
            ? "No records"
            : `${(page - 1) * PAGE_SIZE + 1}–${Math.min(page * PAGE_SIZE, sorted.length)} of ${sorted.length}`}
        </span>
        <div className="flex gap-1">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-3 py-1 text-xs rounded border border-border disabled:opacity-40 hover:bg-secondary transition-colors"
          >
            ← Prev
          </button>
          {Array.from({ length: totalPages }, (_, i) => i + 1)
            .filter((p) => p === 1 || p === totalPages || Math.abs(p - page) <= 1)
            .map((p, i, arr) => (
              <>
                {i > 0 && arr[i - 1] !== p - 1 && (
                  <span key={`ellipsis-${p}`} className="px-2 py-1 text-xs text-muted-foreground">…</span>
                )}
                <button
                  key={p}
                  onClick={() => setPage(p)}
                  className="px-3 py-1 text-xs rounded border transition-colors"
                  style={
                    page === p
                      ? { backgroundColor: BRAND, color: ON_BRAND, borderColor: BRAND, fontWeight: 700 }
                      : { borderColor: "hsl(var(--border))" }
                  }
                >
                  {p}
                </button>
              </>
            ))}
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="px-3 py-1 text-xs rounded border border-border disabled:opacity-40 hover:bg-secondary transition-colors"
          >
            Next →
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────

const TABS = ["Domains", "SSL", "IP Address/Subnets", "Software"] as const;
type Tab = typeof TABS[number];

const edgeStyle = { stroke: "hsl(220, 14%, 30%)", strokeWidth: 2 };

const getCompanyFromDomain = (domain: string) => {
  if (!domain || domain === "—") return "";
  const part = domain.split(".")[0];
  return part.charAt(0).toUpperCase() + part.slice(1);
};

export default function AssetDiscovery() {
  const [activeTab, setActiveTab] = useState<Tab>("Domains");
  const [subFilter, setSubFilter] = useState<SubFilter>("All");
  const [search, setSearch] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [showGraph, setShowGraph] = useState(false);

  // API-driven state
  const [domainData,   setDomainData]   = useState<any[]>([]);
  const [sslData,      setSslData]      = useState<any[]>([]);
  const [ipData,       setIpData]       = useState<any[]>([]);
  const [softwareData, setSoftwareData] = useState<any[]>([]);

  // Dynamic SUB_COUNTS derived from live data
  const SUB_COUNTS: Record<string, Record<SubFilter, number>> = {
    Domains:              { New: domainData.length, "False Positive": 0, Confirmed: domainData.length, All: domainData.length },
    SSL:                  { New: sslData.length,    "False Positive": 0, Confirmed: sslData.length,   All: sslData.length    },
    "IP Address/Subnets": { New: ipData.length,     "False Positive": 0, Confirmed: ipData.length,    All: ipData.length     },
    Software:             { New: softwareData.length, "False Positive": 0, Confirmed: softwareData.length, All: softwareData.length },
  };

  // Fetch API data on mount
  useEffect(() => {
    // Domains from asset inventory
    assetService.getInventory()
      .then(res => {
        const items = Array.isArray(res.data) ? res.data : (res.data?.items || []);
        setDomainData(items.map((a: any) => {
          const host = a.asset || a.name || a.subdomain || "";
          const seen = a.last_seen || a.detection_date || "";
          return {
            detectionDate:    typeof seen === "string" ? seen.split("T")[0] : "",
            domainName:       host,
            registrationDate: a.registration_date || "",
            registrar:        a.registrar || "",
            company:          a.company || getCompanyFromDomain(host),
          };
        }));
      })
      .catch(() => setDomainData([]));

    // SSL from crypto security data
    cryptoService.getCryptoSecurityData()
      .then(res => {
        const items = Array.isArray(res.data) ? res.data : (res.data?.items || []);
        setSslData(items.map((c: any) => ({
          detectionDate: "",
          sha:           c.certificate_sha256 || c.cert_sha || "",
          validFrom:     c.cert_valid_from    || "",
          commonName:    c.asset              || "",
          company:       c.company || getCompanyFromDomain(c.asset),
          ca:            c.certificate_authority || "",
        })));
      })
      .catch(() => setSslData([]));

    // IP data from asset-discovery
    assetService.getAll()
      .then(res => {
        const items = Array.isArray(res.data) ? res.data : (res.data?.items || []);
        setIpData(items
          .map((a: any) => ({
            detectionDate: a.last_scan || a.last_seen?.split("T")[0] || "",
            ip:            a.ipv4 || a.ip_address || "",
            ports:         Array.isArray(a.open_ports) ? a.open_ports.join(", ") : (a.ports || ""),
            subnet:        a.subnet || "",
            asn:           a.asn || "",
            netname:       a.netname || "",
            location:      a.location || a.country || "",
            company:       a.company || getCompanyFromDomain(a.ipv4 || a.ip_address),
          })));
      })
      .catch(() => setIpData([]));

    // Software from DNS / name-server records
    dnsService.getNameServerRecords()
      .then(res => {
        const items = Array.isArray(res.data) ? res.data : (res.data?.records || []);
        setSoftwareData(items.map((d: any) => ({
          detectionDate: "",
          product:       d.software || d.type || "",
          version:       d.version  || "",
          type:          d.record_type || "NS",
          port:          d.port || "",
          host:          d.host || d.name || "",
          company:       d.company || getCompanyFromDomain(d.host || d.name),
        })));
      })
      .catch(() => setSoftwareData([]));

    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ReactFlow state
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  useEffect(() => {
    if (!showGraph) return;
    discoveryService
      .getNetworkGraph(search)
      .then((res) => {
        const data = res.data;
        if (data.nodes && data.edges) {
          let gridIndex = 0;
          const formattedNodes: Node[] = data.nodes.map((n: any) => {
            const cols = 4;
            // Root node style
            if (n.id === "root") {
              return {
                id: n.id,
                position: { x: 400, y: 50 },
                data: { label: n.label },
                style: {
                  background: "hsl(260, 40%, 30%)",
                  color: "white",
                  border: "2px solid hsl(260, 50%, 50%)",
                  borderRadius: "12px",
                  fontSize: "14px",
                  fontWeight: "bold",
                  padding: "12px 20px",
                  zIndex: 10,
                },
              };
            }

            const gi = gridIndex++;

            const isHighRisk = n.risk === "high" || n.hndl_vulnerable || n.cert_expired;
            const isMediumRisk = n.risk === "medium" || n.cert_expiring;
            const isWeb = n.type === "web_app";
            
            let borderColor = "hsl(220, 14%, 25%)";
            let boxShadow = "none";
            let backgroundColor = "hsl(220, 18%, 18%)";
            
            if (isHighRisk) {
              borderColor = "hsl(0, 80%, 50%)";
              boxShadow = "0 0 12px hsla(0, 80%, 50%, 0.4)";
            } else if (isMediumRisk) {
              borderColor = "hsl(40, 80%, 50%)";
            }
            
            if (isWeb) {
              backgroundColor = "hsl(210, 30%, 25%)";
            }

            const statusEmoji = n.cert_expired ? " ❌" : n.cert_expiring ? " ⚠️" : n.hndl_vulnerable ? " ☢️" : "";

            return {
              id: n.id,
              position: { x: (gi % cols) * 250 + 100, y: Math.floor(gi / cols) * 150 + 200 },
              data: { label: `${n.label}${statusEmoji}` },
              style: {
                background: backgroundColor,
                color: "hsl(210, 20%, 92%)",
                border: `1px solid ${borderColor}`,
                borderRadius: "10px",
                fontSize: "11px",
                padding: "10px 16px",
                boxShadow: boxShadow,
                transition: "all 0.3s ease",
              },
            };
          });

          const formattedEdges: Edge[] = data.edges.map((e: any, i: number) => ({
            id: `edge-${i}`,
            source: e.source,
            target: e.target,
            style: edgeStyle,
            animated: true,
          }));
          setNodes(formattedNodes);
          setEdges(formattedEdges);
        }
      })
      .catch((err) => console.error("Could not fetch discovery graph", err));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showGraph, search]);


  // Apply date filter helper
  const applyDateFilter = <T extends { detectionDate: string }>(data: T[]): T[] => {
    return data.filter((row) => {
      if (startDate && row.detectionDate < startDate) return false;
      if (endDate   && row.detectionDate > endDate)   return false;
      return true;
    });
  };

  const currentData = useMemo(() => {
    if (activeTab === "Domains")           return applyDateFilter(domainData);
    if (activeTab === "SSL")               return applyDateFilter(sslData);
    if (activeTab === "IP Address/Subnets") return applyDateFilter(ipData);
    return applyDateFilter(softwareData);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, startDate, endDate, domainData, sslData, ipData, softwareData]);

  const totalDiscovered = domainData.length + sslData.length + ipData.length + softwareData.length;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
          <h1 className="text-2xl font-bold text-foreground">Asset Discovery</h1>
          <p className="text-sm text-muted-foreground">Discovered digital assets across your attack surface</p>
        </motion.div>
        <Button
          variant="outline"
          className="flex items-center gap-2 border-border text-sm"
          style={showGraph ? { borderColor: BRAND, color: BRAND } : {}}
          onClick={() => setShowGraph((v) => !v)}
        >
          <Network size={15} />
          {showGraph ? "Hide Network Graph" : "View Network Graph"}
        </Button>
      </div>

      {/* Network Graph Panel */}
      <AnimatePresence>
        {showGraph && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 420, opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="rounded-xl border border-border bg-card overflow-hidden"
          >
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              fitView
              proOptions={{ hideAttribution: true }}
            >
              <Background color="hsl(220, 14%, 18%)" gap={20} size={1} />
              <Controls style={{ background: "hsl(220, 18%, 13%)", border: "1px solid hsl(220, 14%, 20%)", borderRadius: "8px" }} />
              <MiniMap
                style={{ background: "hsl(220, 22%, 8%)", border: "1px solid hsl(220, 14%, 20%)", borderRadius: "8px" }}
                nodeColor="hsl(45, 96%, 51%)"
                maskColor="hsl(220, 20%, 10%, 0.8)"
              />
            </ReactFlow>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Search + Date Filter Panel */}
      <div className="rounded-xl border border-border bg-card p-5 space-y-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search domain, URL, contact, IoC or other…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10 bg-secondary border-border"
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              <X size={14} />
            </button>
          )}
        </div>

        <div className="flex items-center gap-4 flex-wrap">
          <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wide flex items-center gap-1">
            <CalendarIcon size={13} /> Time Period
          </span>
          <div className="flex items-center gap-2">
            <input
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              className="px-3 py-1.5 rounded-md border border-border bg-secondary text-foreground text-xs focus:outline-none focus:border-primary"
            />
            <span className="text-muted-foreground text-xs">–</span>
            <input
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              className="px-3 py-1.5 rounded-md border border-border bg-secondary text-foreground text-xs focus:outline-none focus:border-primary"
            />
            {(startDate || endDate) && (
              <button
                onClick={() => { setStartDate(""); setEndDate(""); }}
                className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
              >
                <X size={12} /> Clear
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Empty state */}
      {totalDiscovered === 0 && (
        <div className="text-center py-12 text-muted-foreground">
          <Network className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="text-lg font-medium">No assets discovered yet</p>
          <p className="text-sm">
            Run a scan from{" "}
            <Link to="/" className="font-medium text-primary hover:underline">Overview</Link>
            {" "}to populate this view.
          </p>
        </div>
      )}

      {/* Main Tab Card */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        {/* Tab Pills */}
        <div className="flex items-center gap-2 px-5 pt-5 flex-wrap">
          {TABS.map((tab) => {
            const count = SUB_COUNTS[tab]?.All ?? 0;
            const active = activeTab === tab;
            return (
              <button
                key={tab}
                onClick={() => { setActiveTab(tab); setSubFilter("All"); }}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-full text-xs font-semibold transition-all border"
                style={
                  active
                    ? { backgroundColor: BRAND, color: ON_BRAND, borderColor: BRAND }
                    : { borderColor: "hsl(var(--border))", color: "hsl(var(--muted-foreground))" }
                }
              >
                {tab}
                <span
                  className="text-[10px] px-1.5 py-0.5 rounded-full font-bold"
                  style={
                    active
                      ? { backgroundColor: "rgba(15,23,42,0.12)", color: "rgb(15,23,42)" }
                      : { backgroundColor: "hsl(var(--secondary))" }
                  }
                >
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Sub-filter pills */}
        <div className="flex items-center gap-2 px-5 pt-3 pb-4 border-b border-border flex-wrap">
          {(["New", "False Positive", "Confirmed", "All"] as SubFilter[]).map((sf) => {
            const n = SUB_COUNTS[activeTab]?.[sf] ?? 0;
            const active = subFilter === sf;
            return (
              <button
                key={sf}
                onClick={() => setSubFilter(sf)}
                className="flex items-center gap-1 px-3 py-1 rounded-full text-xs font-medium border transition-all"
                style={
                  active
                    ? { backgroundColor: "rgba(37,99,235,0.12)", color: BRAND, borderColor: `${BRAND}99` }
                    : { borderColor: "hsl(var(--border))", color: "hsl(var(--muted-foreground))" }
                }
              >
                {sf}
                <span className="text-[10px] bg-secondary px-1.5 rounded-full">{n}</span>
              </button>
            );
          })}
        </div>

        {/* Table content */}
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, x: 10 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -10 }}
            transition={{ duration: 0.18 }}
          >
            {activeTab === "Domains" && (
              <SortableTable cols={DOMAIN_COLS as any} data={currentData as any} search={search} />
            )}
            {activeTab === "SSL" && (
              <SortableTable cols={SSL_COLS as any} data={currentData as any} search={search} />
            )}
            {activeTab === "IP Address/Subnets" && (
              <SortableTable cols={IP_COLS as any} data={currentData as any} search={search} />
            )}
            {activeTab === "Software" && (
              <SortableTable cols={SW_COLS as any} data={currentData as any} search={search} />
            )}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}
