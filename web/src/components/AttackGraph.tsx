"use client";

import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

interface GraphProps {
  nodes: Array<{ data: Record<string, unknown> }>;
  edges: Array<{ data: Record<string, unknown> }>;
  highlightedNodeIds: string[];
}

const NODE_COLORS: Record<string, string> = {
  Principal: "#d97706",
  Compute: "#2563eb",
  SecurityGroup: "#7c3aed",
  RDSInstance: "#dc2626",
  DBRole: "#059669",
  DBTable: "#db2777",
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
            color: NODE_COLORS[String(n.data.node_type)] || "#475569",
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
            color: "#0f172a",
            "font-size": "11px",
            "font-weight": "bold",
            "text-valign": "bottom",
            "text-margin-y": 8,
            "text-background-color": "#ffffff",
            "text-background-opacity": 0.92,
            "text-background-padding": "3px",
            "text-border-color": "#e2e8f0",
            "text-border-width": 1,
            "text-border-opacity": 1,
            width: 34,
            height: 34,
            "border-width": 2,
            "border-color": "#ffffff",
          },
        },
        {
          selector: 'node[highlighted = "yes"]',
          style: {
            "border-width": 4,
            "border-color": "#dc2626",
            width: 44,
            height: 44,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.8,
            "line-color": "#cbd5e1",
            "target-arrow-color": "#94a3b8",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(rel)",
            color: "#475569",
            "font-size": "9px",
            "text-rotation": "autorotate",
            "text-background-color": "#f8fafc",
            "text-background-opacity": 0.85,
            "text-background-padding": "2px",
          },
        },
        {
          selector: 'edge[highlighted = "yes"]',
          style: {
            width: 3,
            "line-color": "#dc2626",
            "target-arrow-color": "#dc2626",
            "line-style": "dashed",
            color: "#b91c1c",
            "font-weight": "bold",
          },
        },
      ],
      layout: { name: "breadthfirst", directed: true, padding: 32, spacingFactor: 1.45 },
    });

    return () => cy.destroy();
  }, [nodes, edges, highlightedNodeIds]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600">
        {Object.entries(NODE_COLORS).map(([type, color]) => (
          <span
            key={type}
            className="inline-flex items-center gap-1.5 rounded-md bg-slate-50 px-2.5 py-1 border border-slate-200 font-medium"
          >
            <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />
            {type}
          </span>
        ))}
        <span className="ml-auto text-xs font-medium text-red-600">
          Dashed red = Active attack path
        </span>
      </div>
      <div
        ref={containerRef}
        className="h-[440px] w-full rounded-lg border border-slate-200 bg-slate-50"
      />
    </div>
  );
}
