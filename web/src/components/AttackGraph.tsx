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

const TIER_X: Record<string, number> = {
  Principal: 80,
  Compute: 280,
  SecurityGroup: 480,
  RDSInstance: 680,
  DBRole: 880,
  DBTable: 1080,
};

export default function AttackGraph({ nodes, edges, highlightedNodeIds }: GraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!containerRef.current) return;
    const hlSet = new Set(highlightedNodeIds);

    // Group nodes by tier so each column stacks cleanly without overlap
    const tierCounts: Record<string, number> = {};
    const tierTotals: Record<string, number> = {};
    for (const n of nodes) {
      const t = String(n.data.node_type || "Principal");
      tierTotals[t] = (tierTotals[t] || 0) + 1;
    }

    const positionedNodes = nodes.map((n) => {
      const t = String(n.data.node_type || "Principal");
      const idx = tierCounts[t] || 0;
      tierCounts[t] = idx + 1;
      const total = tierTotals[t] || 1;
      const x = TIER_X[t] ?? 500;
      const y = (idx - (total - 1) / 2) * 105 + 220;
      return {
        data: {
          ...n.data,
          color: NODE_COLORS[t] || "#475569",
          highlighted: hlSet.has(String(n.data.id)) ? "yes" : "no",
        },
        position: { x, y },
      };
    });

    const cy = cytoscape({
      container: containerRef.current,
      elements: [
        ...positionedNodes,
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
            shape: "round-rectangle",
            label: "data(label)",
            color: "#0f172a",
            "font-size": "11px",
            "font-weight": "bold",
            "text-valign": "bottom",
            "text-margin-y": 7,
            "text-background-color": "#ffffff",
            "text-background-opacity": 0.95,
            "text-background-padding": "3px",
            "text-border-color": "#cbd5e1",
            "text-border-width": 1,
            "text-border-opacity": 1,
            width: 36,
            height: 36,
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
            width: 1.6,
            "line-color": "#cbd5e1",
            "target-arrow-color": "#94a3b8",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(rel)",
            color: "#64748b",
            "font-size": "9px",
            "text-rotation": "autorotate",
            "text-background-color": "#f8fafc",
            "text-background-opacity": 0.9,
            "text-background-padding": "2px",
          },
        },
        {
          selector: 'edge[highlighted = "yes"]',
          style: {
            width: 3.2,
            "line-color": "#dc2626",
            "target-arrow-color": "#dc2626",
            "line-style": "dashed",
            color: "#b91c1c",
            "font-weight": "bold",
          },
        },
      ],
      layout: { name: "preset", fit: true, padding: 36 },
    });

    return () => cy.destroy();
  }, [nodes, edges, highlightedNodeIds]);

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-6 gap-1 text-center text-[11px] font-semibold uppercase tracking-wider text-slate-500 bg-slate-100 rounded-md py-1.5 px-2">
        <span>1. Identity</span>
        <span>2. Compute</span>
        <span>3. Network / SG</span>
        <span>4. RDS / DB</span>
        <span>5. DB Role</span>
        <span>6. Target Table</span>
      </div>
      <div
        ref={containerRef}
        className="h-[420px] w-full rounded-lg border border-slate-200 bg-slate-50"
      />
      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600">
        {Object.entries(NODE_COLORS).map(([type, color]) => (
          <span
            key={type}
            className="inline-flex items-center gap-1.5 rounded-md bg-white px-2.5 py-1 border border-slate-200 font-medium"
          >
            <span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: color }} />
            {type}
          </span>
        ))}
        <span className="ml-auto text-xs font-medium text-red-600">
          Dashed red = Active attack path
        </span>
      </div>
    </div>
  );
}
