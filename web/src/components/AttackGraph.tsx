"use client";

import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

interface GraphProps {
  nodes: Array<{ data: Record<string, unknown> }>;
  edges: Array<{ data: Record<string, unknown> }>;
  highlightedNodeIds: string[];
}

const NODE_COLORS: Record<string, string> = {
  Principal: "#f59e0b",
  Compute: "#3b82f6",
  SecurityGroup: "#8b5cf6",
  RDSInstance: "#ef4444",
  DBRole: "#10b981",
  DBTable: "#ec4899",
};

export default function AttackGraph({ nodes, edges, highlightedNodeIds }: GraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!containerRef.current) return;
    const hlSet = new Set(highlightedNodeIds);

    const cy = cytoscape({
      container: containerRef.current,
      elements: [
        ...nodes.map((n) => ({
          data: {
            ...n.data,
            color: NODE_COLORS[String(n.data.node_type)] || "#64748b",
            highlighted: hlSet.has(String(n.data.id)) ? "yes" : "no",
          },
        })),
        ...edges.map((e) => ({ data: e.data })),
      ],
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            label: "data(label)",
            color: "#f8fafc",
            "font-size": "11px",
            "text-valign": "bottom",
            "text-margin-y": 6,
            width: 34,
            height: 34,
            "border-width": 2,
            "border-color": "#1e293b",
          },
        },
        {
          selector: 'node[highlighted = "yes"]',
          style: {
            "border-width": 4,
            "border-color": "#f43f5e",
            width: 44,
            height: 44,
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#475569",
            "target-arrow-color": "#475569",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(rel)",
            color: "#94a3b8",
            "font-size": "9px",
            "text-rotation": "autorotate",
          },
        },
      ],
      layout: { name: "breadthfirst", directed: true, padding: 24, spacingFactor: 1.3 },
    });

    return () => cy.destroy();
  }, [nodes, edges, highlightedNodeIds]);

  return (
    <div
      ref={containerRef}
      className="h-[420px] w-full rounded-xl border border-slate-800 bg-slate-950/80"
    />
  );
}
