"use client";

import { useEffect, useState } from "react";
import {
  AlertCircle,
  CheckCircle2,
  Cloud,
  Cpu,
  Database,
  GitBranch,
  Play,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  XCircle,
} from "lucide-react";
import AttackGraph from "@/components/AttackGraph";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

type TabId = "cloud" | "training" | "explorer" | "remediation";

interface EnvSummary {
  env_id: string;
  scenario_type: string;
  is_demo: boolean;
}

interface AttackStep {
  stage: string;
  resource: string;
  detail: string;
}

interface PathItem {
  path_id: string;
  entry_principal_id: string;
  entry_name?: string;
  compute_id: string | null;
  rds_id: string;
  db_role_id: string;
  db_role_name?: string;
  db_table_id: string;
  db_table_name?: string;
  label_exploitable: number;
  risk_score: number;
  failure_reason: string;
  attack_steps?: AttackStep[];
}

interface ShapFeat {
  feature: string;
  label?: string;
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

interface PipelineStage {
  stage: string;
  ms: number;
  detail: string;
}

interface NeonStatus {
  connected: boolean;
  host?: string;
  roles_discovered?: number;
  tables_discovered?: number;
  public_grant_tables?: string[];
  message?: string;
}

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState<TabId>("cloud");
  const [apiOnline, setApiOnline] = useState<boolean>(true);
  const [neonStatus, setNeonStatus] = useState<NeonStatus | null>(null);

  // Cloud connection inputs
  const [customPgUrl, setCustomPgUrl] = useState<string>("");
  const [awsRegion, setAwsRegion] = useState<string>("us-east-1");
  const [awsKey, setAwsKey] = useState<string>("");
  const [awsSecret, setAwsSecret] = useState<string>("");
  const [awsToken, setAwsToken] = useState<string>("");
  const [awsResult, setAwsResult] = useState<string>("");
  const [awsError, setAwsError] = useState<string>("");

  // Live scan & ML state
  const [liveStages, setLiveStages] = useState<PipelineStage[]>([]);
  const [busyMsg, setBusyMsg] = useState<string>("");
  const [notice, setNotice] = useState<string>("");
  const [datasetInfo, setDatasetInfo] = useState<{ manifest?: Record<string, unknown>; sample_rows?: Array<Record<string, unknown>> }>({});
  const [nEnvsInput, setNEnvsInput] = useState<number>(100);

  // Explorer / Remediation / Metrics state
  const [envs, setEnvs] = useState<EnvSummary[]>([]);
  const [selectedEnv, setSelectedEnv] = useState<string>("live_neon_cloud");
  const [graph, setGraph] = useState<{ nodes: Array<{ data: Record<string, unknown> }>; edges: Array<{ data: Record<string, unknown> }> }>({ nodes: [], edges: [] });
  const [paths, setPaths] = useState<PathItem[]>([]);
  const [explanations, setExplanations] = useState<Record<string, { top_features: ShapFeat[] }>>({});
  const [selectedPathId, setSelectedPathId] = useState<string>("");
  const [remediations, setRemediations] = useState<RemediationItem[]>([]);
  const [evalData, setEvalData] = useState<{ manifest?: Record<string, unknown>; evaluation?: Record<string, unknown> }>({});

  const refreshNeon = async () => {
    try {
      const r = await fetch(`${API_BASE}/live/neon/status`);
      if (!r.ok) throw new Error();
      setNeonStatus(await r.json());
      setApiOnline(true);
    } catch {
      setApiOnline(false);
    }
  };

  const refreshMetricsAndDataset = async () => {
    try {
      const [mRes, dRes] = await Promise.all([
        fetch(`${API_BASE}/metrics`).then((r) => (r.ok ? r.json() : {})),
        fetch(`${API_BASE}/ml/dataset`).then((r) => (r.ok ? r.json() : {})),
      ]);
      setEvalData(mRes);
      setDatasetInfo(dRes);
    } catch {
      // ignore
    }
  };

  const loadEnvironment = async (envId: string) => {
    try {
      const [gRes, pRes, rRes] = await Promise.all([
        fetch(`${API_BASE}/environments/${envId}/graph`).then((r) => r.json()),
        fetch(`${API_BASE}/environments/${envId}/paths`).then((r) => r.json()),
        fetch(`${API_BASE}/environments/${envId}/remediate`).then((r) => r.json()),
      ]);
      setGraph({ nodes: gRes.nodes || [], edges: gRes.edges || [] });
      const list: PathItem[] = pRes.paths || [];
      setPaths(list);
      setExplanations(pRes.explanations || {});
      setSelectedPathId(list[0]?.path_id || "");
      setRemediations(rRes.remediations || []);
      setApiOnline(true);
    } catch {
      setApiOnline(false);
    }
  };

  useEffect(() => {
    refreshNeon();
    refreshMetricsAndDataset();
    fetch(`${API_BASE}/environments`)
      .then((r) => r.json())
      .then((list: EnvSummary[]) => {
        setEnvs(list);
        const initial = list.some((e) => e.env_id === "live_neon_cloud") ? "live_neon_cloud" : "demo_capital_one";
        setSelectedEnv(initial);
      })
      .catch(() => setApiOnline(false));
  }, []);

  useEffect(() => {
    if (selectedEnv) loadEnvironment(selectedEnv);
  }, [selectedEnv]);

  const handleSeedNeon = async () => {
    setBusyMsg("Applying test misconfigurations to live Neon PostgreSQL...");
    setNotice("");
    try {
      const r = await fetch(`${API_BASE}/live/neon/seed`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ connection_url: customPgUrl || null }),
      });
      const data = await r.json();
      setNotice(`Seeded live Neon Cloud DB: ${(data.actions || []).join(" | ")}`);
      await refreshNeon();
    } finally {
      setBusyMsg("");
    }
  };

  const handleScanNeon = async () => {
    setBusyMsg("Running live 4-stage AI scan against Neon Cloud PostgreSQL...");
    setNotice("");
    try {
      const r = await fetch(`${API_BASE}/live/neon/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ connection_url: customPgUrl || null }),
      });
      const data = await r.json();
      setLiveStages(data.stages || []);
      setGraph(data.graph || { nodes: [], edges: [] });
      setPaths(data.paths || []);
      setExplanations(data.explanations || {});
      setSelectedPathId(data.paths?.[0]?.path_id || "");
      setRemediations(data.remediations || []);
      setSelectedEnv("live_neon_cloud");
      await refreshNeon();
      setNotice("Live Neon scan completed. Open Attack Path Explorer to inspect the discovered paths and SHAP drivers.");
    } finally {
      setBusyMsg("");
    }
  };

  const handleApplyNeonFix = async (tableName: string) => {
    setBusyMsg(`Executing REVOKE on live Neon table public.${tableName} and re-scanning...`);
    try {
      const r = await fetch(`${API_BASE}/live/neon/apply-fix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ table_name: tableName, connection_url: customPgUrl || null }),
      });
      const data = await r.json();
      setLiveStages(data.scan?.stages || []);
      setGraph(data.scan?.graph || { nodes: [], edges: [] });
      setPaths(data.scan?.paths || []);
      setExplanations(data.scan?.explanations || {});
      setSelectedPathId(data.scan?.paths?.[0]?.path_id || "");
      setRemediations(data.scan?.remediations || []);
      await refreshNeon();
      setNotice(`Applied live SQL remediation: ${data.fix?.sql}`);
    } finally {
      setBusyMsg("");
    }
  };

  const handleScanAws = async () => {
    setBusyMsg(`Connecting to AWS (${awsRegion}) via boto3 read-only APIs...`);
    setAwsError("");
    setAwsResult("");
    try {
      const r = await fetch(`${API_BASE}/cloud/aws/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          region: awsRegion,
          access_key_id: awsKey || null,
          secret_access_key: awsSecret || null,
          session_token: awsToken || null,
        }),
      });
      const data = await r.json();
      if (!r.ok) {
        setAwsError(data.detail || "AWS scan failed.");
        return;
      }
      setGraph(data.graph || { nodes: [], edges: [] });
      setPaths(data.paths || []);
      setExplanations(data.explanations || {});
      setSelectedPathId(data.paths?.[0]?.path_id || "");
      setRemediations(data.remediations || []);
      const inv = data.inventory;
      setAwsResult(
        `Scanned AWS ${inv.region} in ${inv.collect_ms} ms: ${inv.principals} IAM principals, ${inv.policies} policies, ${inv.security_groups} security groups, ${inv.rds_instances} RDS instances.`
      );
    } finally {
      setBusyMsg("");
    }
  };

  const handleGenerateDataset = async () => {
    setBusyMsg(`Generating ${nEnvsInput} synthetic cloud environments and labeling attack paths...`);
    setNotice("");
    try {
      const r = await fetch(`${API_BASE}/ml/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ n_envs: nEnvsInput, seed: 42 }),
      });
      const data = await r.json();
      setNotice(`Generated ${data.manifest?.n_paths} labeled paths across ${data.manifest?.n_environments} environments.`);
      await refreshMetricsAndDataset();
    } finally {
      setBusyMsg("");
    }
  };

  const handleTrainModel = async () => {
    setBusyMsg("Training PyG Heterogeneous GraphSAGE + XGBoost + SHAP (80/20 environment-grouped split)...");
    setNotice("");
    try {
      const r = await fetch(`${API_BASE}/ml/train`, { method: "POST" });
      if (r.ok) {
        setNotice("Model training completed and artifacts saved (gnn_weights.pt, model_bundle.pkl, eval_report.json).");
        await refreshMetricsAndDataset();
      }
    } finally {
      setBusyMsg("");
    }
  };

  const activePath = paths.find((p) => p.path_id === selectedPathId) || paths[0];
  const highlightedIds = activePath
    ? [activePath.entry_principal_id, activePath.compute_id || "", activePath.rds_id, activePath.db_role_id, activePath.db_table_id].filter(Boolean)
    : [];
  const activeShap = activePath ? explanations[activePath.path_id]?.top_features || [] : [];
  const exploitableCount = paths.filter((p) => p.label_exploitable === 1).length;
  const safeFixCount = remediations.filter((r) => r.status === "Verified Safe-to-Apply").length;
  const evalModels = (evalData.evaluation as { models?: Record<string, { precision: number; recall: number; f1: number; pr_auc: number; accuracy: number; confusion_matrix?: number[][] }> })?.models || {};
  const b5Cm = evalModels["B5_gnn_xgboost_hybrid"]?.confusion_matrix;
  const manifest = datasetInfo.manifest as { n_environments?: number; n_paths?: number; n_exploitable?: number; exploitable_ratio?: number } | undefined;

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900">
      {/* Sidebar */}
      <aside className="w-64 shrink-0 border-r border-slate-200 bg-white flex flex-col justify-between">
        <div className="p-5 space-y-6">
          <div className="flex items-center gap-3 pb-4 border-b border-slate-100">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600 text-sm font-bold text-white shadow-sm">
              DT
            </div>
            <div>
              <div className="text-sm font-bold tracking-tight text-slate-900">DB-TRACE</div>
              <div className="text-xs text-slate-500">Cloud DB Risk Platform</div>
            </div>
          </div>

          <nav className="space-y-1">
            {[
              { id: "cloud", label: "1. Cloud Connections", icon: Cloud },
              { id: "training", label: "2. Dataset & AI Training", icon: Cpu },
              { id: "explorer", label: "3. Attack Path Explorer", icon: GitBranch },
              { id: "remediation", label: "4. Verified Remediations", icon: Wrench },
            ].map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id as TabId)}
                  className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition ${
                    active
                      ? "bg-blue-50 text-blue-700 border border-blue-200"
                      : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                  }`}
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  {item.label}
                </button>
              );
            })}
          </nav>

          <div className="rounded-lg border border-slate-200 bg-slate-50 p-3.5 space-y-2.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Inspect Environment
            </div>
            <select
              value={selectedEnv}
              onChange={(e) => setSelectedEnv(e.target.value)}
              className="w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-800 focus:border-blue-500 focus:outline-none"
            >
              {envs.map((e) => (
                <option key={e.env_id} value={e.env_id}>
                  {e.is_demo ? e.scenario_type : `${e.env_id} — ${e.scenario_type}`}
                </option>
              ))}
            </select>
            <button
              onClick={() => {
                setSelectedEnv("demo_capital_one");
                setActiveTab("explorer");
              }}
              className="w-full rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100"
            >
              Load Capital One Case Study
            </button>
          </div>
        </div>

        <div className="border-t border-slate-200 p-4 space-y-2 text-xs bg-slate-50/70">
          <div className="flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${apiOnline ? "bg-emerald-500" : "bg-red-500"}`} />
            <span className="font-medium text-slate-700">{apiOnline ? "API Engine Online" : "API Offline (port 8000)"}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${neonStatus?.connected ? "bg-emerald-500" : "bg-amber-500"}`} />
            <span className="text-slate-500 truncate">
              {neonStatus?.connected ? "Neon Cloud PG Connected" : "Neon Cloud Disconnected"}
            </span>
          </div>
        </div>
      </aside>

      {/* Main Workspace */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar */}
        <header className="h-14 border-b border-slate-200 bg-white px-6 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <h1 className="text-sm font-semibold text-slate-900">
              {activeTab === "cloud" && "Cloud Connections & Real-Time Scanner"}
              {activeTab === "training" && "Dataset Management & Hybrid AI Training (GNN + XGBoost + SHAP)"}
              {activeTab === "explorer" && "Contextual Attack-Path Explorer & SHAP Attribution"}
              {activeTab === "remediation" && "Remediation Engine & Historical Log-Replay Verification"}
            </h1>
          </div>
          <div className="flex items-center gap-4 text-xs">
            <span className="text-slate-500">Active Target: <b className="text-slate-800">{selectedEnv}</b></span>
            <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 font-semibold ${exploitableCount > 0 ? "bg-red-50 text-red-700 border border-red-200" : "bg-emerald-50 text-emerald-700 border border-emerald-200"}`}>
              {exploitableCount} Exploitable Paths
            </span>
            <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 border border-emerald-200 px-2.5 py-0.5 font-semibold text-emerald-700">
              {safeFixCount} Verified Safe Fixes
            </span>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-6 max-w-7xl w-full mx-auto space-y-6">
          {busyMsg && (
            <div className="flex items-center gap-2.5 rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 text-sm font-medium text-blue-800">
              <RefreshCw className="h-4 w-4 animate-spin" />
              {busyMsg}
            </div>
          )}
          {notice && (
            <div className="flex items-center gap-2.5 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600" />
              {notice}
            </div>
          )}

          {/* TAB 1: CLOUD CONNECTIONS */}
          {activeTab === "cloud" && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Real AWS Connector */}
                <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                    <div className="flex items-center gap-2.5">
                      <Server className="h-5 w-5 text-blue-600" />
                      <div>
                        <h2 className="text-base font-semibold text-slate-900">Connect Real AWS Account</h2>
                        <p className="text-xs text-slate-500">Read-only boto3 collection (IAM, VPC, Security Groups, RDS)</p>
                      </div>
                    </div>
                    <span className="rounded-md bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-600">SecurityAudit</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">AWS Region</label>
                      <input
                        value={awsRegion}
                        onChange={(e) => setAwsRegion(e.target.value)}
                        className="w-full rounded-md border border-slate-300 px-3 py-2 text-slate-900 focus:border-blue-500 focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">Access Key ID (optional if SSO/profile)</label>
                      <input
                        value={awsKey}
                        onChange={(e) => setAwsKey(e.target.value)}
                        placeholder="AKIA... or leave empty for local AWS CLI"
                        className="w-full rounded-md border border-slate-300 px-3 py-2 text-slate-900 focus:border-blue-500 focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">Secret Access Key</label>
                      <input
                        type="password"
                        value={awsSecret}
                        onChange={(e) => setAwsSecret(e.target.value)}
                        placeholder="Optional if using local aws login"
                        className="w-full rounded-md border border-slate-300 px-3 py-2 text-slate-900 focus:border-blue-500 focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">Session Token (for STS/SSO)</label>
                      <input
                        type="password"
                        value={awsToken}
                        onChange={(e) => setAwsToken(e.target.value)}
                        placeholder="Optional temporary token"
                        className="w-full rounded-md border border-slate-300 px-3 py-2 text-slate-900 focus:border-blue-500 focus:outline-none"
                      />
                    </div>
                  </div>

                  <button
                    disabled={!!busyMsg}
                    onClick={handleScanAws}
                    className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
                  >
                    <Play className="h-4 w-4" /> Scan Real AWS Account
                  </button>

                  {awsError && (
                    <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 flex items-start gap-2">
                      <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                      <span>{awsError}</span>
                    </div>
                  )}
                  {awsResult && (
                    <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-800">
                      {awsResult}
                    </div>
                  )}
                </section>

                {/* Real Neon / PostgreSQL Connector */}
                <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                    <div className="flex items-center gap-2.5">
                      <Database className="h-5 w-5 text-emerald-600" />
                      <div>
                        <h2 className="text-base font-semibold text-slate-900">Live Cloud PostgreSQL (Neon / RDS)</h2>
                        <p className="text-xs text-slate-500">Inspects real pg_roles, memberships &amp; table grants</p>
                      </div>
                    </div>
                    <span className={`rounded-md px-2 py-0.5 text-[11px] font-semibold ${neonStatus?.connected ? "bg-emerald-50 text-emerald-700 border border-emerald-200" : "bg-amber-50 text-amber-700"}`}>
                      {neonStatus?.connected ? "Connected" : "Not Connected"}
                    </span>
                  </div>

                  {neonStatus?.connected && (
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3.5 text-xs space-y-1">
                      <div><span className="text-slate-500">Cloud Host:</span> <code className="text-slate-800">{neonStatus.host}</code></div>
                      <div><span className="text-slate-500">Inventory:</span> <b>{neonStatus.roles_discovered}</b> roles, <b>{neonStatus.tables_discovered}</b> tables</div>
                      <div>
                        <span className="text-slate-500">PUBLIC-Exposed Tables:</span>{" "}
                        <b className={(neonStatus.public_grant_tables?.length || 0) > 0 ? "text-red-600" : "text-emerald-700"}>
                          {(neonStatus.public_grant_tables?.length || 0) > 0 ? neonStatus.public_grant_tables?.join(", ") : "None (Secured)"}
                        </b>
                      </div>
                    </div>
                  )}

                  <div className="text-xs">
                    <label className="block font-medium text-slate-700 mb-1">Custom PostgreSQL / RDS / Azure URL (optional)</label>
                    <input
                      value={customPgUrl}
                      onChange={(e) => setCustomPgUrl(e.target.value)}
                      placeholder="Leave empty to use pre-connected Neon Cloud PostgreSQL 18"
                      className="w-full rounded-md border border-slate-300 px-3 py-2 text-slate-900 focus:border-blue-500 focus:outline-none"
                    />
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <button
                      disabled={!!busyMsg}
                      onClick={handleSeedNeon}
                      className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-xs font-semibold text-amber-800 hover:bg-amber-100 disabled:opacity-50"
                    >
                      1. Inject Misconfigurations
                    </button>
                    <button
                      disabled={!!busyMsg}
                      onClick={handleScanNeon}
                      className="rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
                    >
                      2. Run Real-Time AI Scan
                    </button>
                    <button
                      disabled={!!busyMsg}
                      onClick={() => handleApplyNeonFix("customers_pii")}
                      className="rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-xs font-semibold text-emerald-800 hover:bg-emerald-100 disabled:opacity-50"
                    >
                      3. Apply Verified SQL Fix &amp; Re-Scan
                    </button>
                  </div>
                </section>
              </div>

              {/* Pipeline Execution Stages */}
              {liveStages.length > 0 && (
                <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-3">
                  <h3 className="text-sm font-semibold text-slate-900">Real-Time Pipeline Execution Trace</h3>
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                    {liveStages.map((st) => (
                      <div key={st.stage} className="rounded-lg border border-slate-200 bg-slate-50 p-3.5 space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-semibold text-emerald-700">{st.stage}</span>
                          <span className="font-mono text-slate-500">{st.ms} ms</span>
                        </div>
                        <p className="text-xs text-slate-600 leading-relaxed">{st.detail}</p>
                      </div>
                    ))}
                  </div>
                </section>
              )}
            </div>
          )}

          {/* TAB 2: DATASET & AI TRAINING */}
          {activeTab === "training" && (
            <div className="space-y-6">
              <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-4">
                  <div>
                    <h2 className="text-base font-semibold text-slate-900">AI Model Training Pipeline (PyG GNN + XGBoost + SHAP)</h2>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Generate labeled multi-hop attack paths across synthetic AWS+PostgreSQL environments, then train and evaluate all 6 models using a leakage-safe 80/20 environment-grouped split.
                    </p>
                  </div>
                  <div className="flex items-center gap-2.5">
                    <label className="text-xs text-slate-600">Environments:</label>
                    <input
                      type="number"
                      min={20}
                      max={200}
                      value={nEnvsInput}
                      onChange={(e) => setNEnvsInput(Number(e.target.value))}
                      className="w-20 rounded-md border border-slate-300 px-2.5 py-1.5 text-xs text-slate-900"
                    />
                    <button
                      disabled={!!busyMsg}
                      onClick={handleGenerateDataset}
                      className="rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                    >
                      Generate Dataset
                    </button>
                    <button
                      disabled={!!busyMsg}
                      onClick={handleTrainModel}
                      className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
                    >
                      Train AI Model Now
                    </button>
                  </div>
                </div>

                {manifest && (
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-2">
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3.5">
                      <div className="text-xs text-slate-500">Environments</div>
                      <div className="text-xl font-bold text-slate-900 mt-0.5">{manifest.n_environments}</div>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3.5">
                      <div className="text-xs text-slate-500">Labeled Access Paths</div>
                      <div className="text-xl font-bold text-slate-900 mt-0.5">{manifest.n_paths}</div>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3.5">
                      <div className="text-xs text-slate-500">Exploitable Paths</div>
                      <div className="text-xl font-bold text-red-600 mt-0.5">{manifest.n_exploitable}</div>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3.5">
                      <div className="text-xs text-slate-500">Positive Class Ratio</div>
                      <div className="text-xl font-bold text-slate-900 mt-0.5">{((manifest.exploitable_ratio || 0) * 100).toFixed(1)}%</div>
                    </div>
                  </div>
                )}
              </section>

              {/* Model Comparison Table */}
              <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
                <h3 className="text-sm font-semibold text-slate-900">Hold-Out Test Set Benchmarks (20 Unseen Environments)</h3>
                <div className="overflow-x-auto rounded-lg border border-slate-200">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-50 text-slate-600 border-b border-slate-200">
                      <tr>
                        <th className="p-3 font-semibold">Model / Baseline</th>
                        <th className="p-3 font-semibold">Precision</th>
                        <th className="p-3 font-semibold">Recall</th>
                        <th className="p-3 font-semibold">F1-Score</th>
                        <th className="p-3 font-semibold">PR-AUC</th>
                        <th className="p-3 font-semibold">Accuracy</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {Object.entries(evalModels).map(([name, m]) => (
                        <tr key={name} className={name.startsWith("B5") ? "bg-blue-50/60 font-semibold" : "bg-white"}>
                          <td className="p-3 font-mono text-slate-900">{name}</td>
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

                {b5Cm && (
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 text-center text-xs">
                    <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3">
                      <div className="text-emerald-700 font-medium">True Negatives</div>
                      <div className="text-xl font-bold text-slate-900 mt-1">{b5Cm[0][0]}</div>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                      <div className="text-slate-600 font-medium">False Positives</div>
                      <div className="text-xl font-bold text-slate-900 mt-1">{b5Cm[0][1]}</div>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                      <div className="text-slate-600 font-medium">False Negatives</div>
                      <div className="text-xl font-bold text-slate-900 mt-1">{b5Cm[1][0]}</div>
                    </div>
                    <div className="rounded-lg border border-blue-200 bg-blue-50 p-3">
                      <div className="text-blue-700 font-medium">True Positives</div>
                      <div className="text-xl font-bold text-slate-900 mt-1">{b5Cm[1][1]}</div>
                    </div>
                  </div>
                )}
              </section>

              {/* Dataset Preview Table */}
              {(datasetInfo.sample_rows?.length || 0) > 0 && (
                <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-3">
                  <h3 className="text-sm font-semibold text-slate-900">Labeled Dataset Preview (data/paths.csv)</h3>
                  <div className="overflow-x-auto rounded-lg border border-slate-200">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-50 text-slate-600 border-b border-slate-200">
                        <tr>
                          <th className="p-2.5">Path ID</th>
                          <th className="p-2.5">Scenario</th>
                          <th className="p-2.5">Entry Principal</th>
                          <th className="p-2.5">DB Role</th>
                          <th className="p-2.5">Target Table</th>
                          <th className="p-2.5">Label</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {(datasetInfo.sample_rows || []).slice(0, 10).map((row, i) => (
                          <tr key={i}>
                            <td className="p-2.5 font-mono text-slate-700">{String(row.path_id)}</td>
                            <td className="p-2.5 text-slate-600">{String(row.scenario_type)}</td>
                            <td className="p-2.5 font-mono text-slate-600">{String(row.entry_principal_id)}</td>
                            <td className="p-2.5 font-mono text-slate-600">{String(row.db_role_id)}</td>
                            <td className="p-2.5 font-mono text-slate-600">{String(row.db_table_id)}</td>
                            <td className="p-2.5">
                              <span className={`rounded-full px-2 py-0.5 font-semibold ${Number(row.label_exploitable) === 1 ? "bg-red-50 text-red-700" : "bg-slate-100 text-slate-600"}`}>
                                {Number(row.label_exploitable) === 1 ? "Exploitable" : "Safe"}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}
            </div>
          )}

          {/* TAB 3: ATTACK PATH EXPLORER */}
          {activeTab === "explorer" && (
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
              <div className="xl:col-span-7 space-y-4">
                <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h2 className="text-sm font-semibold text-slate-900">Heterogeneous Access Graph</h2>
                    <select
                      value={selectedPathId}
                      onChange={(e) => setSelectedPathId(e.target.value)}
                      className="rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-800 max-w-sm"
                    >
                      {paths.slice(0, 30).map((p) => (
                        <option key={p.path_id} value={p.path_id}>
                          [{p.label_exploitable ? "EXPLOITABLE" : "SAFE"}] {(p.risk_score * 100).toFixed(0)}% — {p.db_role_name} → {p.db_table_name}
                        </option>
                      ))}
                    </select>
                  </div>
                  <AttackGraph nodes={graph.nodes} edges={graph.edges} highlightedNodeIds={highlightedIds} />
                </section>
              </div>

              <div className="xl:col-span-5 space-y-4">
                <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-3">
                  <div className="flex items-center justify-between">
                    <h2 className="text-sm font-semibold text-slate-900">Step-by-Step Attack Chain</h2>
                    {activePath && (
                      <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${activePath.label_exploitable ? "bg-red-50 text-red-700 border border-red-200" : "bg-emerald-50 text-emerald-700 border border-emerald-200"}`}>
                        AI Risk: {(activePath.risk_score * 100).toFixed(1)}%
                      </span>
                    )}
                  </div>
                  <div className="space-y-2.5">
                    {(activePath?.attack_steps || []).map((st) => (
                      <div key={st.stage} className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-semibold text-blue-700">{st.stage}</span>
                          <span className="font-mono text-slate-500">{st.resource}</span>
                        </div>
                        <p className="mt-1 text-xs text-slate-700">{st.detail}</p>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-3">
                  <h2 className="text-sm font-semibold text-slate-900">SHAP Explainability (Risk Drivers)</h2>
                  <div className="space-y-2.5">
                    {activeShap.map((s) => (
                      <div key={s.feature} className="space-y-1">
                        <div className="flex items-center justify-between text-xs gap-2">
                          <span className="text-slate-700">{s.label || s.feature}</span>
                          <span className={`font-mono font-semibold shrink-0 ${s.shap_value >= 0 ? "text-red-600" : "text-emerald-700"}`}>
                            {s.shap_value >= 0 ? "+" : ""}{s.shap_value.toFixed(3)}
                          </span>
                        </div>
                        <div className="h-2 w-full rounded-full bg-slate-100 overflow-hidden">
                          <div
                            className={`h-2 rounded-full ${s.shap_value >= 0 ? "bg-red-500" : "bg-emerald-500"}`}
                            style={{ width: `${Math.min(100, Math.abs(s.shap_value) * 35)}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </section>
              </div>
            </div>
          )}

          {/* TAB 4: VERIFIED REMEDIATIONS */}
          {activeTab === "remediation" && (
            <div className="space-y-4">
              <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                <h2 className="text-base font-semibold text-slate-900">Verified Remediation Simulator (30-Day Log Replay)</h2>
                <p className="text-xs text-slate-500 mt-1">
                  Proposed configuration fixes are simulated on a graph copy and replayed against historical CloudTrail &amp; PostgreSQL <code>pgaudit</code> logs. Any fix that would disrupt legitimate production traffic is flagged <b>Unsafe</b>.
                </p>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {remediations.map((rem) => {
                  const isSafe = rem.status.startsWith("Verified");
                  const isUnsafe = rem.status.startsWith("Unsafe");
                  return (
                    <div key={rem.fix_id} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-3">
                      <div className="flex items-start justify-between gap-2">
                        <h3 className="text-sm font-semibold text-slate-900">{rem.title}</h3>
                        <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold shrink-0 ${isSafe ? "bg-emerald-50 text-emerald-700 border border-emerald-200" : isUnsafe ? "bg-red-50 text-red-700 border border-red-200" : "bg-slate-100 text-slate-600"}`}>
                          {isSafe ? <ShieldCheck className="h-3.5 w-3.5" /> : isUnsafe ? <XCircle className="h-3.5 w-3.5" /> : <ShieldAlert className="h-3.5 w-3.5" />}
                          {rem.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 leading-relaxed">{rem.narration?.summary || rem.description}</p>
                      <div className="grid grid-cols-2 gap-3 rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs">
                        <div>
                          <div className="text-slate-500">Paths Eliminated</div>
                          <div className="text-base font-bold text-slate-900">{rem.paths_eliminated} <span className="text-xs font-normal text-slate-500">({rem.paths_before} → {rem.paths_after})</span></div>
                        </div>
                        <div>
                          <div className="text-slate-500">Legit Calls Broken</div>
                          <div className={`text-base font-bold ${rem.legit_broken > 0 ? "text-red-600" : "text-emerald-700"}`}>
                            {rem.legit_broken} / {rem.legit_total}
                          </div>
                        </div>
                      </div>
                      <pre className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-900 p-3 text-xs text-slate-100 font-mono">
                        {rem.patch_snippet}
                      </pre>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
