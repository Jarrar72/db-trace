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
        ...edges.map((e) => {
          const isHl = hlSet.has(String(e.data.source)) && hlSet.has(String(e.data.target));
          return { data: { ...e.data, highlighted: isHl ? "yes" : "no" } };
        }),
      ],
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            label: "data(label)",
            color: "#e2e8f0",
            "font-size": "11px",
            "font-weight": "bold",
            "text-valign": "bottom",
            "text-margin-y": 8,
            "text-background-color": "#0b1120",
            "text-background-opacity": 0.85,
            "text-background-padding": "3px",
            width: 36,
            height: 36,
            "border-width": 2,
            "border-color": "#0f172a",
          },
        },
        {
          selector: 'node[highlighted = "yes"]',
          style: {
            "border-width": 4,
            "border-color": "#fb7185",
            width: 46,
            height: 46,
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#334155",
            "target-arrow-color": "#334155",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(rel)",
            color: "#94a3b8",
            "font-size": "9px",
            "text-rotation": "autorotate",
          },
        },
        {
          selector: 'edge[highlighted = "yes"]',
          style: {
            width: 3.5,
            "line-color": "#f43f5e",
            "target-arrow-color": "#f43f5e",
            "line-style": "dashed",
            color: "#fda4af",
          },
        },
      ],
      layout: { name: "breadthfirst", directed: true, padding: 30, spacingFactor: 1.45 },
    });

    return () => cy.destroy();
  }, [nodes, edges, highlightedNodeIds]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3 text-xs text-slate-300">
        {Object.entries(NODE_COLORS).map(([type, color]) => (
          <span key={type} className="inline-flex items-center gap-1.5 rounded-full bg-slate-900 px-2.5 py-1 border border-slate-800">
            <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />
            {type}
          </span>
        ))}
        <span className="ml-auto text-rose-400 font-medium">Red dashed = Active Attack Path</span>
      </div>
      <div
        ref={containerRef}
        className="h-[460px] w-full rounded-xl border border-slate-800 bg-[#070b14] shadow-inner"
      />
    </div>
  );
}
