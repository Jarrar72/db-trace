"use client";

import { useMemo, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Edge,
  Handle,
  MarkerType,
  MiniMap,
  Node,
  NodeProps,
  Panel,
  Position,
  ReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Cpu,
  Database,
  Globe,
  KeyRound,
  Maximize2,
  Minimize2,
  Shield,
  Table2,
  User,
} from "lucide-react";

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
  simulationStep?: number;
  isSimulating?: boolean;
  heightClass?: string;
}

const TIERS = ["Principal", "Compute", "SecurityGroup", "RDSInstance", "DBRole", "DBTable"] as const;

const TIER_META: Record<
  string,
  {
    title: string;
    short: string;
    mitre: string;
    accentBorder: string;
    iconBg: string;
    minimapColor: string;
    Icon: typeof User;
  }
> = {
  Principal: {
    title: "1. Identity",
    short: "IAM / ENTRY",
    mitre: "T1078.004",
    accentBorder: "border-l-amber-500",
    iconBg: "bg-amber-50 text-amber-700 ring-1 ring-amber-200/70",
    minimapColor: "#f59e0b",
    Icon: User,
  },
  Compute: {
    title: "2. Compute",
    short: "EC2 / LAMBDA",
    mitre: "T1552.005",
    accentBorder: "border-l-blue-500",
    iconBg: "bg-blue-50 text-blue-700 ring-1 ring-blue-200/70",
    minimapColor: "#3b82f6",
    Icon: Cpu,
  },
  SecurityGroup: {
    title: "3. Network",
    short: "VPC / SG",
    mitre: "T1190",
    accentBorder: "border-l-violet-500",
    iconBg: "bg-violet-50 text-violet-700 ring-1 ring-violet-200/70",
    minimapColor: "#8b5cf6",
    Icon: Shield,
  },
  RDSInstance: {
    title: "4. Database",
    short: "AWS RDS",
    mitre: "T1530",
    accentBorder: "border-l-rose-500",
    iconBg: "bg-rose-50 text-rose-700 ring-1 ring-rose-200/70",
    minimapColor: "#f43f5e",
    Icon: Database,
  },
  DBRole: {
    title: "5. DB Role",
    short: "PG ROLE",
    mitre: "T1098",
    accentBorder: "border-l-emerald-500",
    iconBg: "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200/70",
    minimapColor: "#10b981",
    Icon: KeyRound,
  },
  DBTable: {
    title: "6. Crown Jewel",
    short: "PII TABLE",
    mitre: "T1530",
    accentBorder: "border-l-pink-600",
    iconBg: "bg-pink-50 text-pink-700 ring-1 ring-pink-200/70",
    minimapColor: "#db2777",
    Icon: Table2,
  },
};

type CustomNodeData = {
  label: string;
  nodeType: string;
  isHighlighted: boolean;
  isSelected: boolean;
  isExploitable: boolean;
  isCompromisedInSim: boolean;
  isActiveInSim: boolean;
  rawNode: GraphNode;
  onSelect: (n: GraphNode) => void;
};

function SecurityNode({ data }: NodeProps<Node<CustomNodeData>>) {
  const meta = TIER_META[data.nodeType] || TIER_META.Principal;
  const Icon = data.label.toLowerCase().includes("internet") ? Globe : meta.Icon;

  return (
    <div
      onClick={() => data.onSelect(data.rawNode)}
      className={`group relative w-[204px] cursor-pointer rounded-xl bg-white px-3.5 py-3 border border-l-4 transition-all duration-200 ${
        data.isSelected
          ? "border-indigo-500 border-l-indigo-600 ring-2 ring-indigo-500/25 shadow-lg scale-[1.03]"
          : data.isActiveInSim
          ? "border-amber-400 border-l-amber-500 shadow-lg animate-amber-ring scale-[1.04]"
          : data.isCompromisedInSim
          ? "border-red-400 border-l-red-600 bg-red-50/40 shadow-md"
          : data.isHighlighted
          ? data.isExploitable
            ? "border-red-300 border-l-red-600 shadow-md hover:shadow-lg hover:-translate-y-0.5"
            : "border-emerald-300 border-l-emerald-600 shadow-md hover:shadow-lg hover:-translate-y-0.5"
          : `border-slate-200/90 ${meta.accentBorder} opacity-70 hover:opacity-100 hover:shadow-md`
      }`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-2 !border-white !bg-slate-400"
      />

      <div className="flex items-center gap-3">
        <div
          className={`relative flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${
            data.isActiveInSim
              ? "bg-amber-100 text-amber-800 ring-1 ring-amber-300"
              : data.isCompromisedInSim
              ? "bg-red-100 text-red-700 ring-1 ring-red-300"
              : meta.iconBg
          }`}
        >
          <Icon className="h-4 w-4" />
          {data.isHighlighted && data.isExploitable && !data.isActiveInSim && (
            <span className="absolute -right-1 -top-1 flex h-2.5 w-2.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-red-600" />
            </span>
          )}
          {data.isActiveInSim && (
            <span className="absolute -right-1 -top-1 flex h-3 w-3">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-85" />
              <span className="relative inline-flex h-3 w-3 rounded-full bg-amber-500" />
            </span>
          )}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-1">
            <span className="text-[9.5px] font-bold uppercase tracking-wider text-slate-400">
              {meta.short}
            </span>
            {data.isCompromisedInSim && (
              <span className="rounded bg-red-600 px-1.5 py-0.5 text-[8px] font-bold uppercase tracking-wide text-white">
                Breached
              </span>
            )}
            {data.isActiveInSim && (
              <span className="rounded bg-amber-500 px-1.5 py-0.5 text-[8px] font-bold uppercase tracking-wide text-white animate-pulse">
                Active
              </span>
            )}
            {!data.isCompromisedInSim && !data.isActiveInSim && data.isHighlighted && (
              <span
                className={`rounded px-1.5 py-0.5 text-[8px] font-bold uppercase ${
                  data.isExploitable
                    ? "bg-red-50 text-red-700 ring-1 ring-red-200"
                    : "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200"
                }`}
              >
                {data.isExploitable ? "At Risk" : "Safe"}
              </span>
            )}
          </div>
          <div
            className="mt-0.5 truncate text-xs font-bold text-slate-900"
            title={data.label}
          >
            {data.label}
          </div>
          <div className="mt-0.5 font-mono text-[9.5px] text-slate-400">
            {meta.mitre}
          </div>
        </div>
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!h-2.5 !w-2.5 !border-2 !border-white !bg-slate-400"
      />
    </div>
  );
}

const nodeTypes = { securityNode: SecurityNode };

export default function AttackGraph({
  nodes,
  edges,
  highlightedNodeIds,
  selectedNodeId,
  onSelectNode,
  isExploitable,
  simulationStep = -1,
  isSimulating = false,
  heightClass = "h-[520px]",
}: AttackGraphProps) {
  const [expanded, setExpanded] = useState(false);
  const hlSet = useMemo(() => new Set(highlightedNodeIds), [highlightedNodeIds]);

  const { flowNodes, flowEdges } = useMemo(() => {
    const byTier: Record<string, GraphNode[]> = {};
    for (const t of TIERS) byTier[t] = [];
    for (const n of nodes) {
      const t = String(n.data.node_type || "Principal");
      (byTier[t] || byTier.Principal).push(n);
    }

    const tierIdxMap: Record<string, number> = {};
    const builtNodes: Node<CustomNodeData>[] = [];
    const colSpacing = 275;
    const rowSpacing = 108;

    TIERS.forEach((tier, colIdx) => {
      const list = byTier[tier];
      const totalH = (list.length - 1) * rowSpacing;
      const startY = 220 - totalH / 2;
      list.forEach((n, rowIdx) => {
        tierIdxMap[n.data.id] = colIdx;
        const isHl = hlSet.has(n.data.id);
        const isComp = isSimulating && simulationStep >= 0 && isHl && colIdx < simulationStep;
        const isAct = isSimulating && simulationStep >= 0 && isHl && colIdx === simulationStep;

        builtNodes.push({
          id: n.data.id,
          type: "securityNode",
          position: { x: 40 + colIdx * colSpacing, y: startY + rowIdx * rowSpacing },
          data: {
            label: String(n.data.label || n.data.id),
            nodeType: tier,
            isHighlighted: isHl,
            isSelected: selectedNodeId === n.data.id,
            isExploitable,
            isCompromisedInSim: isComp,
            isActiveInSim: isAct,
            rawNode: n,
            onSelect: onSelectNode,
          },
        });
      });
    });

    const builtEdges: Edge[] = edges.map((e) => {
      const srcIdx = tierIdxMap[e.data.source] ?? 0;
      const dstIdx = tierIdxMap[e.data.target] ?? 0;
      let active = hlSet.has(e.data.source) && hlSet.has(e.data.target);
      if (isSimulating && simulationStep >= 0) {
        active = active && Math.max(srcIdx, dstIdx) <= simulationStep;
      }
      const strokeColor = active
        ? isExploitable
          ? "#ef4444"
          : "#10b981"
        : "#cbd5e1";

      return {
        id: e.data.id,
        source: e.data.source,
        target: e.data.target,
        type: "smoothstep",
        animated: active,
        label: active && e.data.rel ? String(e.data.rel) : undefined,
        labelStyle: {
          fill: isExploitable ? "#b91c1c" : "#047857",
          fontWeight: 700,
          fontSize: 9.5,
          fontFamily: "var(--font-jetbrains-mono), monospace",
        },
        labelBgStyle: {
          fill: isExploitable ? "#fef2f2" : "#ecfdf5",
          stroke: isExploitable ? "#fecaca" : "#a7f3d0",
          strokeWidth: 1,
        },
        labelBgPadding: [6, 3] as [number, number],
        labelBgBorderRadius: 99,
        style: {
          stroke: strokeColor,
          strokeWidth: active ? 2.5 : 1.35,
          opacity: active ? 1 : 0.65,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: strokeColor,
          width: 16,
          height: 16,
        },
      };
    });

    return { flowNodes: builtNodes, flowEdges: builtEdges };
  }, [nodes, edges, hlSet, selectedNodeId, isExploitable, isSimulating, simulationStep, onSelectNode]);

  return (
    <div className={expanded ? "fixed inset-4 z-50 flex flex-col rounded-2xl bg-white p-4 shadow-2xl border border-slate-200" : "space-y-3"}>
      {/* 6-Stage MITRE Progress Header */}
      <div className="grid grid-cols-6 gap-2">
        {TIERS.map((t, idx) => {
          const meta = TIER_META[t];
          const isComp = isSimulating && simulationStep >= 0 && idx < simulationStep;
          const isAct = isSimulating && simulationStep >= 0 && idx === simulationStep;
          return (
            <div
              key={t}
              className={`rounded-lg border px-2.5 py-2 text-center transition-all duration-300 ${
                isAct
                  ? "border-amber-300 bg-amber-50 shadow-sm ring-1 ring-amber-400/50"
                  : isComp
                  ? "border-red-200 bg-red-50/80"
                  : "border-slate-200/80 bg-slate-50/70"
              }`}
            >
              <div className="text-[10.5px] font-bold uppercase tracking-wider text-slate-800">
                {meta.title}
              </div>
              <div className="mt-0.5 flex items-center justify-center gap-1.5">
                <span className="font-mono text-[9px] text-slate-400">{meta.mitre}</span>
                {isComp && (
                  <span className="rounded bg-red-600 px-1 py-0.2 text-[8px] font-bold uppercase text-white">
                    Breached
                  </span>
                )}
                {isAct && (
                  <span className="rounded bg-amber-500 px-1 py-0.2 text-[8px] font-bold uppercase text-white animate-pulse">
                    Active
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Interactive React Flow Canvas */}
      <div
        className={`relative w-full overflow-hidden rounded-xl border border-slate-200/90 bg-[#F8FAFC] ${
          expanded ? "flex-1" : heightClass
        }`}
      >
        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.16 }}
          minZoom={0.35}
          maxZoom={1.6}
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={18} size={1.2} color="#CBD5E1" />
          <Controls showInteractive={false} position="bottom-left" />
          <MiniMap
            position="bottom-right"
            pannable
            zoomable
            nodeColor={(n) => {
              const nt = String((n.data as CustomNodeData)?.nodeType || "Principal");
              return TIER_META[nt]?.minimapColor || "#64748b";
            }}
            maskColor="rgba(241, 245, 249, 0.72)"
          />

          {/* Top-Left Status Legend */}
          <Panel position="top-left">
            <div className="flex items-center gap-3 rounded-lg border border-slate-200/90 bg-white/95 px-3 py-1.5 text-[11px] font-medium text-slate-600 shadow-sm backdrop-blur">
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
                Exploitable Flow
              </span>
              <span className="text-slate-300">|</span>
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-emerald-500" />
                Verified Blocked
              </span>
              <span className="text-slate-300">|</span>
              <span className="text-slate-400">Drag nodes • Scroll to zoom • Click node to inspect</span>
            </div>
          </Panel>

          {/* Top-Right Fullscreen Button */}
          <Panel position="top-right">
            <button
              type="button"
              onClick={() => setExpanded((v) => !v)}
              className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white/95 px-2.5 py-1.5 text-[11px] font-semibold text-slate-700 shadow-sm hover:bg-slate-50 transition-colors"
            >
              {expanded ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
              <span>{expanded ? "Exit Fullscreen" : "Expand Graph"}</span>
            </button>
          </Panel>
        </ReactFlow>
      </div>
    </div>
  );
}
