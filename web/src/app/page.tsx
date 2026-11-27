"use client";

import { useEffect, useState } from "react";
import { ShieldAlert, ShieldCheck, Activity, Sparkles } from "lucide-react";
import AttackGraph from "@/components/AttackGraph";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

interface EnvSummary {
  env_id: string;
  scenario_type: string;
  is_demo: boolean;
}

interface PathItem {
  path_id: string;
  entry_principal_id: string;
  compute_id: string | null;
  rds_id: string;
  db_role_id: string;
  db_table_id: string;
  label_exploitable: number;
  risk_score: number;
  failure_reason: string;
}

interface ShapFeat {
  feature: string;
  value: number;
  shap_value: number;
}

interface RemediationItem {
  fix_id: string;
  title: string;
  description: string;
  patch_snippet: string;
  paths_before: number;
  paths_after: number;
  paths_eliminated: number;
  legit_total: number;
  legit_broken: number;
  status: string;
  narration?: { summary: string };
}

export default function DashboardPage() {
  const [envs, setEnvs] = useState<EnvSummary[]>([]);
  const [selectedEnv, setSelectedEnv] = useState<string>("demo_capital_one");
  const [graph, setGraph] = useState<{ nodes: Array<{ data: Record<string, unknown> }>; edges: Array<{ data: Record<string, unknown> }> }>({ nodes: [], edges: [] });
  const [paths, setPaths] = useState<PathItem[]>([]);
  const [explanations, setExplanations] = useState<Record<string, { top_features: ShapFeat[] }>>({});
  const [selectedPathId, setSelectedPathId] = useState<string>("");
  const [remediations, setRemediations] = useState<RemediationItem[]>([]);
  const [evalMetrics, setEvalMetrics] = useState<Record<string, Record<string, number>>>({});

  useEffect(() => {
    fetch(`${API_BASE}/environments`)
      .then((r) => r.json())
      .then(setEnvs)
      .catch(() => {});
    fetch(`${API_BASE}/metrics`)
      .then((r) => r.json())
      .then((d) => setEvalMetrics(d?.evaluation?.models || {}))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedEnv) return;
    fetch(`${API_BASE}/environments/${selectedEnv}/graph`)
      .then((r) => r.json())
      .then((d) => setGraph({ nodes: d.nodes || [], edges: d.edges || [] }))
      .catch(() => {});
    fetch(`${API_BASE}/environments/${selectedEnv}/paths`)
      .then((r) => r.json())
      .then((d) => {
        const list: PathItem[] = d.paths || [];
        setPaths(list);
        setExplanations(d.explanations || {});
        if (list.length > 0) setSelectedPathId(list[0].path_id);
      })
      .catch(() => {});
    fetch(`${API_BASE}/environments/${selectedEnv}/remediate`)
      .then((r) => r.json())
      .then((d) => setRemediations(d.remediations || []))
      .catch(() => {});
  }, [selectedEnv]);

  const activePath = paths.find((p) => p.path_id === selectedPathId) || paths[0];
  const highlightedIds = activePath
    ? [
        activePath.entry_principal_id,
        activePath.compute_id || "",
        activePath.rds_id,
        activePath.db_role_id,
        activePath.db_table_id,
      ].filter(Boolean)
    : [];
  const activeShap = activePath ? explanations[activePath.path_id]?.top_features || [] : [];
  const exploitableCount = paths.filter((p) => p.label_exploitable === 1).length;

  return (
    <main className="mx-auto max-w-7xl space-y-6 p-6">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">DB-TRACE</h1>
          <p className="text-sm text-slate-400">
            AI-Driven Contextual Risk Detection (GNN + XGBoost + SHAP) &amp; Verified Remediation
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setSelectedEnv("demo_capital_one")}
            className="inline-flex items-center gap-2 rounded-lg bg-rose-600 px-3 py-2 text-sm font-medium text-white hover:bg-rose-500"
          >
            <Sparkles className="h-4 w-4" /> Capital One Replay
          </button>
          <select
            value={selectedEnv}
            onChange={(e) => setSelectedEnv(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200"
          >
            {envs.map((e) => (
              <option key={e.env_id} value={e.env_id}>
                {e.env_id} ({e.scenario_type})
              </option>
            ))}
          </select>
        </div>
      </header>

      <section className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center gap-2 text-sm text-slate-400">
            <Activity className="h-4 w-4 text-blue-400" /> Candidate Access Paths
          </div>
          <div className="mt-1 text-2xl font-bold text-white">{paths.length}</div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center gap-2 text-sm text-slate-400">
            <ShieldAlert className="h-4 w-4 text-rose-400" /> Exploitable Attack Paths
          </div>
          <div className="mt-1 text-2xl font-bold text-rose-400">{exploitableCount}</div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center gap-2 text-sm text-slate-400">
            <ShieldCheck className="h-4 w-4 text-emerald-400" /> Verified Safe Fixes
          </div>
          <div className="mt-1 text-2xl font-bold text-emerald-400">
            {remediations.filter((r) => r.status === "Verified Safe-to-Apply").length}
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-3">
          <h2 className="text-lg font-semibold text-white">Attack-Path Access Graph</h2>
          <AttackGraph nodes={graph.nodes} edges={graph.edges} highlightedNodeIds={highlightedIds} />
        </div>

        <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <h2 className="text-lg font-semibold text-white">SHAP Path Explanation</h2>
          <select
            value={selectedPathId}
            onChange={(e) => setSelectedPathId(e.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-200"
          >
            {paths.slice(0, 20).map((p) => (
              <option key={p.path_id} value={p.path_id}>
                {p.path_id} | score={p.risk_score} | {p.label_exploitable ? "EXPLOITABLE" : "safe"}
              </option>
            ))}
          </select>
          <div className="space-y-2 pt-2">
            {activeShap.map((s) => (
              <div key={s.feature} className="text-xs">
                <div className="flex justify-between text-slate-300">
                  <span>{s.feature} ({s.value})</span>
                  <span className={s.shap_value >= 0 ? "text-rose-400" : "text-emerald-400"}>
                    {s.shap_value >= 0 ? "+" : ""}{s.shap_value.toFixed(3)}
                  </span>
                </div>
                <div className="mt-1 h-1.5 w-full rounded bg-slate-800">
                  <div
                    className={`h-1.5 rounded ${s.shap_value >= 0 ? "bg-rose-500" : "bg-emerald-500"}`}
                    style={{ width: `${Math.min(100, Math.abs(s.shap_value) * 35)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-white">Verified Remediation Recommendations (Log Replay)</h2>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {remediations.map((rem) => (
            <div key={rem.fix_id} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <h3 className="font-semibold text-white">{rem.title}</h3>
                <span
                  className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                    rem.status.startsWith("Verified")
                      ? "bg-emerald-950 text-emerald-300 border border-emerald-700"
                      : rem.status.startsWith("Unsafe")
                      ? "bg-rose-950 text-rose-300 border border-rose-700"
                      : "bg-slate-800 text-slate-300"
                  }`}
                >
                  {rem.status}
                </span>
              </div>
              <p className="text-xs text-slate-400">{rem.narration?.summary || rem.description}</p>
              <div className="flex gap-4 text-xs text-slate-300">
                <span>Paths eliminated: <b>{rem.paths_eliminated}</b> ({rem.paths_before} → {rem.paths_after})</span>
                <span>Legit calls broken: <b>{rem.legit_broken}/{rem.legit_total}</b></span>
              </div>
              <pre className="overflow-x-auto rounded bg-slate-950 p-2 text-[11px] text-sky-300">
                {rem.patch_snippet}
              </pre>
            </div>
          ))}
        </div>
      </section>

      {Object.keys(evalMetrics).length > 0 && (
        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-white">Model Benchmark Comparison (Hold-Out Test Set)</h2>
          <div className="overflow-x-auto rounded-xl border border-slate-800">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900 text-slate-400">
                <tr>
                  <th className="p-3">Model</th>
                  <th className="p-3">Precision</th>
                  <th className="p-3">Recall</th>
                  <th className="p-3">F1</th>
                  <th className="p-3">PR-AUC</th>
                  <th className="p-3">Accuracy</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {Object.entries(evalMetrics).map(([name, m]) => (
                  <tr key={name} className={name.startsWith("B5") ? "bg-emerald-950/20 font-semibold" : ""}>
                    <td className="p-3 text-white">{name}</td>
                    <td className="p-3">{(m.precision * 100).toFixed(1)}%</td>
                    <td className="p-3">{(m.recall * 100).toFixed(1)}%</td>
                    <td className="p-3">{(m.f1 * 100).toFixed(1)}%</td>
                    <td className="p-3">{m.pr_auc?.toFixed(3)}</td>
                    <td className="p-3">{(m.accuracy * 100).toFixed(1)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </main>
  );
}
