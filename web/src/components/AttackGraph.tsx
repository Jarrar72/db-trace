"use client";

import { useMemo } from "react";
import { Cpu, Database, Globe, KeyRound, Shield, Table2, User } from "lucide-react";

export interface GraphNode {
  data: {
    id: string;
    label?: string;
    node_type?: string;
    [key: string]: unknown;
  };
}

export interface GraphEdge {
  data: {
    id: string;
    source: string;
    target: string;
    rel?: string;
    [key: string]: unknown;
  };
}

interface AttackGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  highlightedNodeIds: string[];
  selectedNodeId: string | null;
  onSelectNode: (node: GraphNode) => void;
  isExploitable: boolean;
}

const TIERS = ["Principal", "Compute", "SecurityGroup", "RDSInstance", "DBRole", "DBTable"] as const;

const TIER_META: Record<
  string,
  { title: string; badgeBg: string; badgeText: string; iconBg: string; Icon: typeof User }
> = {
  Principal: {
    title: "1. Identity",
    badgeBg: "bg-amber-50 border-amber-200",
    badgeText: "text-amber-700",
    iconBg: "bg-amber-100 text-amber-700",
    Icon: User,
  },
  Compute: {
    title: "2. Compute",
    badgeBg: "bg-blue-50 border-blue-200",
    badgeText: "text-blue-700",
    iconBg: "bg-blue-100 text-blue-700",
    Icon: Cpu,
  },
  SecurityGroup: {
    title: "3. Network / SG",
    badgeBg: "bg-violet-50 border-violet-200",
    badgeText: "text-violet-700",
    iconBg: "bg-violet-100 text-violet-700",
    Icon: Shield,
  },
  RDSInstance: {
    title: "4. Database",
    badgeBg: "bg-red-50 border-red-200",
    badgeText: "text-red-700",
    iconBg: "bg-red-100 text-red-700",
    Icon: Database,
  },
  DBRole: {
    title: "5. DB Role",
    badgeBg: "bg-emerald-50 border-emerald-200",
    badgeText: "text-emerald-700",
    iconBg: "bg-emerald-100 text-emerald-700",
    Icon: KeyRound,
  },
  DBTable: {
    title: "6. Crown Jewel",
    badgeBg: "bg-pink-50 border-pink-200",
    badgeText: "text-pink-700",
    iconBg: "bg-pink-100 text-pink-700",
    Icon: Table2,
  },
};

const CANVAS_W = 1220;
const NODE_W = 164;
const NODE_H = 66;

export default function AttackGraph({
  nodes,
  edges,
  highlightedNodeIds,
  selectedNodeId,
  onSelectNode,
  isExploitable,
}: AttackGraphProps) {
  const hlSet = useMemo(() => new Set(highlightedNodeIds), [highlightedNodeIds]);

  const { positioned, svgEdges, canvasH } = useMemo(() => {
    const byTier: Record<string, GraphNode[]> = {};
    for (const t of TIERS) byTier[t] = [];
    for (const n of nodes) {
      const t = String(n.data.node_type || "Principal");
      (byTier[t] || byTier.Principal).push(n);
    }

    const maxPerTier = Math.max(1, ...TIERS.map((t) => byTier[t].length));
    const height = Math.max(360, maxPerTier * 96 + 70);
    const colSpacing = (CANVAS_W - 60) / TIERS.length;

    const posMap: Record<string, { x: number; y: number; node: GraphNode }> = {};
    TIERS.forEach((tier, colIdx) => {
      const list = byTier[tier];
      const totalH = list.length * 88;
      const startY = (height - totalH) / 2 + 12;
      list.forEach((n, rowIdx) => {
        posMap[n.data.id] = {
          x: 30 + colIdx * colSpacing + (colSpacing - NODE_W) / 2,
          y: startY + rowIdx * 88,
          node: n,
        };
      });
    });

    const edgeList = edges
      .map((e) => {
        const src = posMap[e.data.source];
        const dst = posMap[e.data.target];
        if (!src || !dst) return null;
        const active = hlSet.has(e.data.source) && hlSet.has(e.data.target);
        const x1 = src.x + NODE_W;
        const y1 = src.y + NODE_H / 2;
        const x2 = dst.x;
        const y2 = dst.y + NODE_H / 2;
        const dx = Math.max(40, Math.abs(x2 - x1) * 0.45);
        const d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
        const mx = (x1 + x2) / 2;
        const my = (y1 + y2) / 2;
        return { id: e.data.id, d, rel: String(e.data.rel || ""), active, mx, my };
      })
      .filter(Boolean) as Array<{ id: string; d: string; rel: string; active: boolean; mx: number; my: number }>;

    return { positioned: Object.values(posMap), svgEdges: edgeList, canvasH: height };
  }, [nodes, edges, hlSet]);

  return (
    <div className="space-y-3">
      {/* Tier Column Headers */}
      <div className="grid grid-cols-6 gap-2 px-2">
        {TIERS.map((t) => (
          <div key={t} className="text-center text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            {TIER_META[t].title}
          </div>
        ))}
      </div>

      {/* Interactive Dot-Grid Canvas */}
      <div className="overflow-x-auto rounded-xl border border-slate-200 dot-grid">
        <div className="relative mx-auto" style={{ width: CANVAS_W, height: canvasH }}>
          {/* SVG Animated Bezier Edges */}
          <svg className="absolute inset-0 pointer-events-none" width={CANVAS_W} height={canvasH}>
            <defs>
              <marker id="arrow-muted" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                <path d="M 0 1 L 8 5 L 0 9 z" fill="#94a3b8" />
              </marker>
              <marker id="arrow-active" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                <path d="M 0 1 L 8 5 L 0 9 z" fill={isExploitable ? "#dc2626" : "#059669"} />
              </marker>
            </defs>

            {svgEdges
              .filter((e) => !e.active)
              .map((e) => (
                <path
                  key={e.id}
                  d={e.d}
                  fill="none"
                  stroke="#cbd5e1"
                  strokeWidth={1.5}
                  markerEnd="url(#arrow-muted)"
                />
              ))}

            {svgEdges
              .filter((e) => e.active)
              .map((e) => (
                <g key={e.id}>
                  <path
                    d={e.d}
                    fill="none"
                    stroke={isExploitable ? "rgba(220,38,38,0.18)" : "rgba(5,150,105,0.18)"}
                    strokeWidth={7}
                  />
                  <path
                    d={e.d}
                    fill="none"
                    stroke={isExploitable ? "#dc2626" : "#059669"}
                    strokeWidth={2.4}
                    className="animate-attack-edge"
                    markerEnd="url(#arrow-active)"
                  />
                </g>
              ))}
          </svg>

          {/* Edge Labels for Active Path */}
          {svgEdges
            .filter((e) => e.active && e.rel)
            .map((e) => (
              <div
                key={`lbl-${e.id}`}
                style={{ left: e.mx, top: e.my }}
                className={`absolute -translate-x-1/2 -translate-y-1/2 rounded-full border px-2 py-0.5 text-[10px] font-semibold shadow-sm pointer-events-none ${
                  isExploitable
                    ? "bg-red-50 border-red-200 text-red-700"
                    : "bg-emerald-50 border-emerald-200 text-emerald-700"
                }`}
              >
                {e.rel}
              </div>
            ))}

          {/* Interactive Node Cards */}
          {positioned.map(({ x, y, node }) => {
            const type = String(node.data.node_type || "Principal");
            const meta = TIER_META[type] || TIER_META.Principal;
            const Icon = String(node.data.label || "").includes("internet") ? Globe : meta.Icon;
            const isHl = hlSet.has(node.data.id);
            const isSelected = selectedNodeId === node.data.id;

            return (
              <button
                key={node.data.id}
                type="button"
                onClick={() => onSelectNode(node)}
                style={{ left: x, top: y, width: NODE_W, height: NODE_H }}
                className={`absolute text-left rounded-xl bg-white px-3 py-2 transition-all duration-200 flex items-center gap-2.5 group ${
                  isSelected
                    ? "ring-2 ring-blue-600 border border-blue-600 shadow-md scale-[1.03] z-20"
                    : isHl
                    ? isExploitable
                      ? "border-2 border-red-500 shadow-md shadow-red-100 z-10 hover:scale-[1.02]"
                      : "border-2 border-emerald-500 shadow-md shadow-emerald-100 z-10 hover:scale-[1.02]"
                    : "border border-slate-200 opacity-65 hover:opacity-100 hover:border-slate-300 shadow-sm"
                }`}
              >
                <div className={`relative h-8 w-8 rounded-lg flex items-center justify-center shrink-0 ${meta.iconBg}`}>
                  <Icon className="h-4 w-4" />
                  {isHl && isExploitable && (
                    <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                      <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-600" />
                    </span>
                  )}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                    {type}
                  </div>
                  <div className="text-xs font-semibold text-slate-900 truncate" title={String(node.data.label || node.data.id)}>
                    {String(node.data.label || node.data.id)}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 px-1">
        <span>Click any node card to open its contextual inspector drawer &amp; inline remediation.</span>
        <span className={isExploitable ? "font-medium text-red-600" : "font-medium text-emerald-700"}>
          {isExploitable ? "Animated red flow = Active exploitable attack path" : "Animated green flow = Verified blocked path"}
        </span>
      </div>
    </div>
  );
}
