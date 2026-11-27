"use client";

import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Database,
  KeyRound,
  Server,
  Shield,
  ShieldAlert,
  Table2,
  User,
  Wrench,
  X,
} from "lucide-react";
import type { GraphNode } from "@/components/AttackGraph";

interface InspectorDrawerProps {
  node: GraphNode | null;
  onClose: () => void;
  onJumpToRemediation: () => void;
  onAskCopilot: (q: string) => void;
}

const ICON_MAP: Record<string, typeof Server> = {
  Principal: User,
  Compute: Cpu,
  SecurityGroup: Shield,
  RDSInstance: Database,
  DBRole: KeyRound,
  DBTable: Table2,
};

export default function InspectorDrawer({
  node,
  onClose,
  onJumpToRemediation,
  onAskCopilot,
}: InspectorDrawerProps) {
  const [drawerTab, setDrawerTab] = useState<"overview" | "findings" | "remediation">("overview");

  const nodeType = String(node?.data?.node_type || "Resource");
  const label = String(node?.data?.label || node?.data?.id || "");
  const Icon = ICON_MAP[nodeType] || Server;

  const metaEntries = node
    ? Object.entries(node.data).filter(
        ([k, v]) => !["id", "label", "node_type"].includes(k) && v !== null && v !== undefined && v !== ""
      )
    : [];

  return (
    <AnimatePresence>
      {node && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 z-40 bg-slate-900/20 backdrop-blur-[2px]"
          />
          <motion.aside
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", stiffness: 360, damping: 34 }}
            className="fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-slate-200 bg-white shadow-2xl"
          >
            {/* Header */}
            <div className="flex items-start justify-between border-b border-slate-100 p-5">
              <div className="flex items-center gap-3 min-w-0">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-indigo-50 text-indigo-600 ring-1 ring-indigo-200/70">
                  <Icon className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                      {nodeType}
                    </span>
                    <span className="rounded-full bg-red-50 px-2 py-0.5 text-[9.5px] font-bold text-red-700 ring-1 ring-red-200">
                      In Attack Chain
                    </span>
                  </div>
                  <h3 className="truncate text-sm font-bold text-slate-900 mt-0.5">{label}</h3>
                </div>
              </div>
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Wiz-style Sub-Tabs */}
            <div className="flex border-b border-slate-100 px-5 pt-2 gap-5 text-xs font-semibold">
              {(["overview", "findings", "remediation"] as const).map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setDrawerTab(t)}
                  className={`pb-2.5 capitalize border-b-2 transition-colors ${
                    drawerTab === t
                      ? "border-indigo-600 text-indigo-600"
                      : "border-transparent text-slate-500 hover:text-slate-800"
                  }`}
                >
                  {t === "findings" ? "Risks & Findings" : t}
                </button>
              ))}
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto p-5 space-y-4 text-xs">
              {drawerTab === "overview" && (
                <>
                  <div className="rounded-xl border border-slate-200/90 bg-slate-50/70 p-3.5 space-y-1">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                      Canonical Resource Identifier
                    </div>
                    <div className="font-mono text-xs text-slate-800 break-all">{node.data.id}</div>
                  </div>

                  <div className="space-y-2">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                      Discovered Properties
                    </div>
                    {metaEntries.length > 0 ? (
                      <div className="divide-y divide-slate-100 rounded-xl border border-slate-200/80 bg-white">
                        {metaEntries.map(([k, v]) => (
                          <div key={k} className="flex items-center justify-between px-3.5 py-2.5 gap-3">
                            <span className="text-slate-500 capitalize">{k.replace(/_/g, " ")}</span>
                            <span className="font-mono font-semibold text-slate-900 text-right truncate max-w-[180px]">
                              {String(v)}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="rounded-xl border border-slate-200/80 bg-slate-50/50 p-3 text-slate-500">
                        Active cloud graph entity indexed by DB-TRACE collector.
                      </div>
                    )}
                  </div>
                </>
              )}

              {drawerTab === "findings" && (
                <div className="space-y-3">
                  {nodeType === "SecurityGroup" && (
                    <div className="rounded-xl border border-red-200 bg-red-50/70 p-4 space-y-1.5">
                      <div className="flex items-center gap-1.5 font-bold text-red-800">
                        <AlertTriangle className="h-4 w-4 text-red-600" />
                        <span>Unrestricted PostgreSQL Port 5432 Ingress</span>
                      </div>
                      <p className="text-red-900/80 leading-relaxed">
                        Allows direct TCP 5432 connectivity from external or compute tiers without strict CIDR isolation. Violates CIS AWS 4.1 &amp; NIST SC-7.
                      </p>
                    </div>
                  )}
                  {nodeType === "Compute" && (
                    <div className="rounded-xl border border-amber-200 bg-amber-50/70 p-4 space-y-1.5">
                      <div className="flex items-center gap-1.5 font-bold text-amber-900">
                        <ShieldAlert className="h-4 w-4 text-amber-600" />
                        <span>IMDSv1 Enabled — SSRF Credential Exposure</span>
                      </div>
                      <p className="text-amber-900/80 leading-relaxed">
                        Instance metadata endpoint does not require IMDSv2 session tokens, enabling lateral IAM credential theft (Capital One 2019 vector).
                      </p>
                    </div>
                  )}
                  {nodeType === "DBRole" && (
                    <div className="rounded-xl border border-purple-200 bg-purple-50/70 p-4 space-y-1.5">
                      <div className="flex items-center gap-1.5 font-bold text-purple-900">
                        <KeyRound className="h-4 w-4 text-purple-600" />
                        <span>Transitive Role Privilege Escalation</span>
                      </div>
                      <p className="text-purple-900/80 leading-relaxed">
                        Role inherits broad SELECT/SUPERUSER privileges across sensitive schemas via group membership closure.
                      </p>
                    </div>
                  )}
                  {!["SecurityGroup", "Compute", "DBRole"].includes(nodeType) && (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 space-y-1.5">
                      <div className="flex items-center gap-1.5 font-bold text-slate-800">
                        <CheckCircle2 className="h-4 w-4 text-indigo-600" />
                        <span>Contextual Attack-Chain Participation</span>
                      </div>
                      <p className="text-slate-600 leading-relaxed">
                        This resource participates in a multi-hop exploitable trajectory verified by the DB-TRACE GNN + XGBoost engine.
                      </p>
                    </div>
                  )}
                </div>
              )}

              {drawerTab === "remediation" && (
                <div className="space-y-3">
                  <div className="rounded-xl border border-emerald-200 bg-emerald-50/60 p-4 space-y-2">
                    <div className="flex items-center gap-1.5 font-bold text-emerald-900">
                      <Wrench className="h-4 w-4 text-emerald-600" />
                      <span>Verified Safe Remediation Available</span>
                    </div>
                    <p className="text-emerald-900/80 leading-relaxed">
                      DB-TRACE has synthesized a Terraform / SQL patch validated against 30 days of CloudTrail &amp; pgaudit logs with 0% legitimate breakage.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      onClose();
                      onJumpToRemediation();
                    }}
                    className="flex w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-indigo-700 transition-colors"
                  >
                    <span>Open Verified Patch &amp; Log Replay</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              )}
            </div>

            {/* Footer Actions */}
            <div className="border-t border-slate-100 p-4 flex items-center gap-2 bg-slate-50/60">
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onAskCopilot(`Explain the security risk of ${nodeType} '${label}' and how to remediate it.`);
                }}
                className="flex-1 rounded-xl border border-indigo-200 bg-indigo-50 py-2 text-xs font-bold text-indigo-700 hover:bg-indigo-100 transition-colors"
              >
                Ask AI Copilot
              </button>
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onJumpToRemediation();
                }}
                className="flex-1 rounded-xl bg-slate-900 py-2 text-xs font-bold text-white hover:bg-slate-800 transition-colors"
              >
                Remediate
              </button>
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}
