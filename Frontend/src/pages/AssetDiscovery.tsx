import { useCallback } from "react";
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
import { motion } from "framer-motion";

const initialNodes: Node[] = [
  { id: "gw", position: { x: 400, y: 50 }, data: { label: "Internet Gateway" }, style: { background: "hsl(45, 96%, 51%)", color: "hsl(220, 20%, 10%)", border: "none", borderRadius: "12px", fontWeight: 600, fontSize: "12px", padding: "12px 20px" } },
  { id: "fw", position: { x: 400, y: 160 }, data: { label: "Firewall" }, style: { background: "hsl(342, 88%, 35%)", color: "#fff", border: "none", borderRadius: "12px", fontWeight: 600, fontSize: "12px", padding: "12px 20px" } },
  { id: "lb", position: { x: 400, y: 270 }, data: { label: "Load Balancer" }, style: { background: "hsl(210, 80%, 55%)", color: "#fff", border: "none", borderRadius: "12px", fontWeight: 600, fontSize: "12px", padding: "12px 20px" } },
  { id: "web1", position: { x: 150, y: 380 }, data: { label: "Web Server 1" }, style: { background: "hsl(220, 18%, 18%)", color: "hsl(210, 20%, 92%)", border: "1px solid hsl(220, 14%, 25%)", borderRadius: "10px", fontSize: "11px", padding: "10px 16px" } },
  { id: "web2", position: { x: 400, y: 380 }, data: { label: "Web Server 2" }, style: { background: "hsl(220, 18%, 18%)", color: "hsl(210, 20%, 92%)", border: "1px solid hsl(220, 14%, 25%)", borderRadius: "10px", fontSize: "11px", padding: "10px 16px" } },
  { id: "api1", position: { x: 650, y: 380 }, data: { label: "API Server" }, style: { background: "hsl(220, 18%, 18%)", color: "hsl(210, 20%, 92%)", border: "1px solid hsl(220, 14%, 25%)", borderRadius: "10px", fontSize: "11px", padding: "10px 16px" } },
  { id: "db1", position: { x: 250, y: 500 }, data: { label: "Primary DB" }, style: { background: "hsl(152, 60%, 20%)", color: "hsl(152, 60%, 80%)", border: "1px solid hsl(152, 40%, 30%)", borderRadius: "10px", fontSize: "11px", padding: "10px 16px" } },
  { id: "db2", position: { x: 550, y: 500 }, data: { label: "Replica DB" }, style: { background: "hsl(152, 60%, 20%)", color: "hsl(152, 60%, 80%)", border: "1px solid hsl(152, 40%, 30%)", borderRadius: "10px", fontSize: "11px", padding: "10px 16px" } },
  { id: "cache", position: { x: 400, y: 600 }, data: { label: "Redis Cache" }, style: { background: "hsl(280, 40%, 20%)", color: "hsl(280, 60%, 75%)", border: "1px solid hsl(280, 30%, 30%)", borderRadius: "10px", fontSize: "11px", padding: "10px 16px" } },
];

const edgeStyle = { stroke: "hsl(220, 14%, 30%)", strokeWidth: 2 };
const initialEdges: Edge[] = [
  { id: "e1", source: "gw", target: "fw", style: edgeStyle, animated: true },
  { id: "e2", source: "fw", target: "lb", style: edgeStyle, animated: true },
  { id: "e3", source: "lb", target: "web1", style: edgeStyle },
  { id: "e4", source: "lb", target: "web2", style: edgeStyle },
  { id: "e5", source: "lb", target: "api1", style: edgeStyle },
  { id: "e6", source: "web1", target: "db1", style: edgeStyle },
  { id: "e7", source: "web2", target: "db1", style: edgeStyle },
  { id: "e8", source: "api1", target: "db2", style: edgeStyle },
  { id: "e9", source: "db1", target: "cache", style: edgeStyle },
  { id: "e10", source: "db2", target: "cache", style: edgeStyle },
];

export default function AssetDiscovery() {
  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <h1 className="text-2xl font-bold text-foreground">Asset Discovery</h1>
        <p className="text-sm text-muted-foreground">Interactive network topology visualization</p>
      </motion.div>

      <div className="rounded-xl border border-border bg-card overflow-hidden" style={{ height: "calc(100vh - 200px)" }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
          proOptions={{ hideAttribution: true }}
        >
          <Background color="hsl(220, 14%, 18%)" gap={20} size={1} />
          <Controls
            style={{ background: "hsl(220, 18%, 13%)", border: "1px solid hsl(220, 14%, 20%)", borderRadius: "8px" }}
          />
          <MiniMap
            style={{ background: "hsl(220, 22%, 8%)", border: "1px solid hsl(220, 14%, 20%)", borderRadius: "8px" }}
            nodeColor="hsl(45, 96%, 51%)"
            maskColor="hsl(220, 20%, 10%, 0.8)"
          />
        </ReactFlow>
      </div>
    </div>
  );
}
