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
import { discoveryService } from "@/services/api";
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

// ── Theme constants ───────────────────────────────────────────────────────────
const GOLD = "#FBBC09";
const GOLD_DARK = "#111111";

// ── Types ─────────────────────────────────────────────────────────────────────
type SubFilter = "New" | "False Positive" | "Confirmed" | "All";

// ── Sample Data ───────────────────────────────────────────────────────────────

const DOMAIN_DATA = [
  { detectionDate: "2025-01-14", domainName: "pnb.bank.in", registrationDate: "2009-04-02", registrar: "National Internet Exchange of India", company: "PNB" },
  { detectionDate: "2025-01-12", domainName: "netbanking.pnbindia.in", registrationDate: "2011-07-15", registrar: "National Internet Exchange of India", company: "PNB" },
  { detectionDate: "2025-01-10", domainName: "corp.pnbindia.in", registrationDate: "2013-03-22", registrar: "National Internet Exchange of India", company: "PNB" },
  { detectionDate: "2025-01-08", domainName: "mobile.pnbindia.in", registrationDate: "2015-11-09", registrar: "National Internet Exchange of India", company: "PNB" },
  { detectionDate: "2025-01-06", domainName: "api.pnbindia.in", registrationDate: "2018-06-30", registrar: "National Internet Exchange of India", company: "PNB" },
  { detectionDate: "2024-12-30", domainName: "secure.pnbindia.in", registrationDate: "2020-01-17", registrar: "National Internet Exchange of India", company: "PNB" },
  { detectionDate: "2024-12-28", domainName: "loans.pnbindia.in", registrationDate: "2021-08-04", registrar: "National Internet Exchange of India", company: "PNB" },
];

const SSL_DATA = [
  { detectionDate: "2025-01-14", sha: "b7563b983bfd217d471f607c9bbc509034a6bcf1", validFrom: "2024-11-01", commonName: "Generic Cert for WF Ovrd", company: "PNB", ca: "Symantec" },
  { detectionDate: "2025-01-12", sha: "a3d24f1e9c78b02e5af890cde12b3f56781234a0", validFrom: "2024-10-15", commonName: "netbanking.pnbindia.in", company: "PNB", ca: "DigiCert" },
  { detectionDate: "2025-01-10", sha: "c8f1b23d5a91e047d3b768f5e2c490a1d5678abc", validFrom: "2024-09-20", commonName: "corp.pnbindia.in", company: "PNB", ca: "Entrust" },
  { detectionDate: "2025-01-08", sha: "e0a12f93cd561b3f8a20de54b7810c23a4096fed", validFrom: "2024-08-01", commonName: "api.pnbindia.in", company: "PNB", ca: "DigiCert" },
  { detectionDate: "2025-01-06", sha: "91b4d0e7a2cf38c1e5f62907d80b43a196e57821", validFrom: "2024-07-11", commonName: "secure.pnbindia.in", company: "PNB", ca: "Symantec" },
  { detectionDate: "2024-12-28", sha: "4f2a1c8d9b37e05c6f710d23a89b145c302ef780", validFrom: "2024-06-30", commonName: "mobile.pnbindia.in", company: "PNB", ca: "Entrust" },
];

const IP_DATA = [
  { detectionDate: "2025-01-14", ip: "103.107.224.10", ports: "80, 443", subnet: "103.107.224.0/22", asn: "AS9583", netname: "E2E-Networks-IN", location: "Nashik, India", company: "Punjab National Bank" },
  { detectionDate: "2025-01-12", ip: "103.107.225.45", ports: "443, 2087", subnet: "103.107.224.0/22", asn: "AS9583", netname: "MSFT", location: "Chennai, India", company: "Punjab National Bank" },
  { detectionDate: "2025-01-10", ip: "203.94.232.18", ports: "80, 587", subnet: "203.94.232.0/24", asn: "AS17813", netname: "Quantum-Link-Co", location: "Leh, India", company: "Punjab National Bank" },
  { detectionDate: "2025-01-08", ip: "103.107.226.77", ports: "443", subnet: "103.107.224.0/22", asn: "AS9583", netname: "E2E-Networks-IN", location: "Mumbai, India", company: "Punjab National Bank" },
  { detectionDate: "2025-01-06", ip: "45.112.160.35", ports: "80, 443, 8443", subnet: "45.112.160.0/22", asn: "AS134175", netname: "MSFT", location: "Delhi, India", company: "Punjab National Bank" },
  { detectionDate: "2024-12-30", ip: "103.107.227.12", ports: "80", subnet: "103.107.224.0/22", asn: "AS9583", netname: "Quantum-Link-Co", location: "Bangalore, India", company: "Punjab National Bank" },
  { detectionDate: "2024-12-28", ip: "202.131.160.90", ports: "443, 587", subnet: "202.131.160.0/24", asn: "AS4755", netname: "E2E-Networks-IN", location: "Hyderabad, India", company: "Punjab National Bank" },
];

const SOFTWARE_DATA = [
  { detectionDate: "2025-01-14", product: "http_server", version: "2.4.54", type: "WebServer", port: "80", host: "pnb.bank.in", company: "PNB" },
  { detectionDate: "2025-01-12", product: "Apache", version: "2.4.51", type: "WebServer", port: "443", host: "netbanking.pnbindia.in", company: "PNB" },
  { detectionDate: "2025-01-10", product: "IIS 10.0", version: "10.0", type: "WebServer", port: "80", host: "corp.pnbindia.in", company: "PNB" },
  { detectionDate: "2025-01-08", product: "Microsoft-IIS", version: "10.0.19041", type: "WebServer", port: "443", host: "api.pnbindia.in", company: "PNB" },
  { detectionDate: "2025-01-06", product: "OpenResty", version: "1.27.1.1", type: "WebServer", port: "2087", host: "mobile.pnbindia.in", company: "PNB" },
  { detectionDate: "2024-12-30", product: "nginx", version: "1.24.0", type: "WebServer", port: "587", host: "secure.pnbindia.in", company: "PNB" },
  { detectionDate: "2024-12-28", product: "Apache", version: "2.4.58", type: "WebServer", port: "80", host: "loans.pnbindia.in", company: "PNB" },
];

// Sub-filter counts (static demo)
const SUB_COUNTS: Record<string, Record<SubFilter, number>> = {
  Domains:           { New: 3, "False Positive": 2, Confirmed: 15, All: 20 },
  SSL:               { New: 5, "False Positive": 1, Confirmed: 9,  All: 15 },
  "IP Address/Subnets": { New: 8, "False Positive": 4, Confirmed: 22, All: 34 },
  Software:          { New: 12,"False Positive": 6, Confirmed: 34, All: 52 },
};

// ── Column definitions ────────────────────────────────────────────────────────
type ColDef<T> = { key: keyof T; header: string; className?: string };

const DOMAIN_COLS: ColDef<typeof DOMAIN_DATA[0]>[] = [
  { key: "detectionDate", header: "Detection Date" },
  { key: "domainName", header: "Domain Name", className: "font-mono text-xs" },
  { key: "registrationDate", header: "Registration Date" },
  { key: "registrar", header: "Registrar" },
  { key: "company", header: "Company Name" },
];
const SSL_COLS: ColDef<typeof SSL_DATA[0]>[] = [
  { key: "detectionDate", header: "Detection Date" },
  { key: "sha", header: "SSL SHA Fingerprint", className: "font-mono text-[10px] max-w-[140px] truncate" },
  { key: "validFrom", header: "Valid From" },
  { key: "commonName", header: "Common Name" },
  { key: "company", header: "Company Name" },
  { key: "ca", header: "Certificate Authority" },
];
const IP_COLS: ColDef<typeof IP_DATA[0]>[] = [
  { key: "detectionDate", header: "Detection Date" },
  { key: "ip", header: "IP Address", className: "font-mono" },
  { key: "ports", header: "Ports" },
  { key: "subnet", header: "Subnet", className: "font-mono" },
  { key: "asn", header: "ASN" },
  { key: "netname", header: "Netname" },
  { key: "location", header: "Location" },
  { key: "company", header: "Company" },
];
const SW_COLS: ColDef<typeof SOFTWARE_DATA[0]>[] = [
  { key: "detectionDate", header: "Detection Date" },
  { key: "product", header: "Product" },
  { key: "version", header: "Version", className: "font-mono" },
  { key: "type", header: "Type" },
  { key: "port", header: "Port", className: "font-mono" },
  { key: "host", header: "Host", className: "font-mono text-xs" },
  { key: "company", header: "Company Name" },
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
            <tr style={{ backgroundColor: GOLD }}>
              {cols.map((col) => (
                <th
                  key={String(col.key)}
                  onClick={() => handleSort(col.key)}
                  className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wide cursor-pointer select-none whitespace-nowrap"
                  style={{ color: GOLD_DARK }}
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
                      ? { backgroundColor: GOLD, color: GOLD_DARK, borderColor: GOLD, fontWeight: 700 }
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

export default function AssetDiscovery() {
  const [activeTab, setActiveTab] = useState<Tab>("Domains");
  const [subFilter, setSubFilter] = useState<SubFilter>("All");
  const [search, setSearch] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [showGraph, setShowGraph] = useState(false);

  // ReactFlow state
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  useEffect(() => {
    if (!showGraph) return;
    discoveryService
      .getNetworkGraph()
      .then((res) => {
        const data = res.data;
        if (data.nodes && data.edges) {
          const formattedNodes: Node[] = data.nodes.map((n: any, i: number) => {
            const cols = 4;
            return {
              id: n.id,
              position: { x: (i % cols) * 250 + 100, y: Math.floor(i / cols) * 150 + 100 },
              data: { label: n.label || n.id },
              style: {
                background: "hsl(220, 18%, 18%)",
                color: "hsl(210, 20%, 92%)",
                border: "1px solid hsl(220, 14%, 25%)",
                borderRadius: "10px",
                fontSize: "11px",
                padding: "10px 16px",
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
  }, [showGraph]);

  // Apply date filter helper
  const applyDateFilter = <T extends { detectionDate: string }>(data: T[]): T[] => {
    return data.filter((row) => {
      if (startDate && row.detectionDate < startDate) return false;
      if (endDate && row.detectionDate > endDate) return false;
      return true;
    });
  };

  const currentData = useMemo(() => {
    if (activeTab === "Domains") return applyDateFilter(DOMAIN_DATA);
    if (activeTab === "SSL") return applyDateFilter(SSL_DATA);
    if (activeTab === "IP Address/Subnets") return applyDateFilter(IP_DATA);
    return applyDateFilter(SOFTWARE_DATA);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, startDate, endDate]);

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
          style={showGraph ? { borderColor: GOLD, color: GOLD } : {}}
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
                    ? { backgroundColor: GOLD, color: GOLD_DARK, borderColor: GOLD }
                    : { borderColor: "hsl(var(--border))", color: "hsl(var(--muted-foreground))" }
                }
              >
                {tab}
                <span
                  className="text-[10px] px-1.5 py-0.5 rounded-full font-bold"
                  style={
                    active
                      ? { backgroundColor: GOLD_DARK + "30", color: GOLD_DARK }
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
                    ? { backgroundColor: "rgba(251,188,9,0.15)", color: GOLD, borderColor: `${GOLD}60` }
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
