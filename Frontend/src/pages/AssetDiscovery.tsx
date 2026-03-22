import { useEffect } from "react";
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
import { discoveryService } from "@/services/api";

const edgeStyle = { stroke: "hsl(220, 14%, 30%)", strokeWidth: 2 };

export default function AssetDiscovery() {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  useEffect(() => {
    discoveryService.getNetworkGraph()
      .then(res => {
        const data = res.data;
        if (data.nodes && data.edges) {
          // Layout nodes in a simple grid for visualization
          const formattedNodes: Node[] = data.nodes.map((n: any, i: number) => {
            const cols = 4;
            const x = (i % cols) * 250 + 100;
            const y = Math.floor(i / cols) * 150 + 100;
            return {
              id: n.id,
              position: { x, y },
              data: { label: n.label || n.id },
              style: { 
                background: "hsl(220, 18%, 18%)", 
                color: "hsl(210, 20%, 92%)", 
                border: "1px solid hsl(220, 14%, 25%)", 
                borderRadius: "10px", 
                fontSize: "11px", 
                padding: "10px 16px" 
              }
            };
          });

          const formattedEdges: Edge[] = data.edges.map((e: any, i: number) => ({
            id: `edge-${i}`,
            source: e.source,
            target: e.target,
            style: edgeStyle,
            animated: true
          }));

          setNodes(formattedNodes);
          setEdges(formattedEdges);
        }
      })
      .catch(err => console.error("Could not fetch discovery graph", err));
  }, []);

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
