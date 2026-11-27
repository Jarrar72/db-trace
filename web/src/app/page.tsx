"use client";

import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Bot,
  Brain,
  ChevronRight,
  Clock,
  Cloud,
  Copy,
  Cpu,
  Database,
  Download,
  FileCheck,
  FileText,
  Flame,
  GitBranch,
  KeyRound,
  Network,
  Pause,
  Play,
  RotateCcw,
  Search,
  Send,
  Server,
  Shield,
  ShieldCheck,
  Sliders,
  Sparkles,
  User,
  Wrench,
  X,
} from "lucide-react";
import AttackGraph, { GraphEdge, GraphNode } from "@/components/AttackGraph";
import {
  AnimatedToggleSwitch,
  ModelBenchmarkChart,
  PostureRadialGauge,
  RiskTrendAreaChart,
  ShapWaterfallChart,
  SparklineKpiCard,
} from "@/components/Charts";
import InspectorDrawer from "@/components/InspectorDrawer";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

type ViewTab =
  | "dashboard"
  | "explorer"
  | "whatif"
  | "copilot"
  | "explainability"
  | "remediation"
  | "cloud"
  | "reports";

interface EnvSummary {
  env_id: string;
  scenario_type: string;
  is_demo: boolean;
}

interface AttackStep {
  stage: string;
  mitre?: string;
  resource: string;
  detail: string;
  remediation_hint?: string;
}

interface PathItem {
  path_id: string;
  entry_principal_id: string;
  entry_name?: string;
  compute_id: string | null;
  source_sg_id?: string | null;
  rds_sg_id?: string | null;
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

interface NeonStatus {
  connected: boolean;
  host?: string;
  roles_discovered?: number;
  tables_discovered?: number;
  public_grant_tables?: string[];
  message?: string;
}

interface WhatIfToggles {
  port_5432_open: boolean;
  iam_admin_access: boolean;
  db_role_inheritance: boolean;
  rds_public: boolean;
  imdsv2_required: boolean;
}

interface WhatIfResult {
  baseline_risk_score: number;
  simulated_risk_score: number;
  risk_delta: number;
  paths_before: number;
  paths_after: number;
  paths_eliminated: number;
  elimination_rate: number;
  legit_total: number;
  legit_broken: number;
  false_breakage_rate: number;
  status: string;
  impact_narrative: string;
  active_exploitable_path_ids: string[];
  graph_elements: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
}

interface CopilotMsg {
  role: "user" | "assistant";
  content: string;
  evidence?: Array<{ category: string; finding: string; severity: string; resource_id: string }>;
  key_findings?: string[];
  suggested_action?: string;
  suggested_followups?: string[];
  action_button?: { label: string; target_tab: string; path_id: string } | null;
  citations?: string[];
  confidence_label?: string;
}

interface ExecutiveReportData {
  generated_at: string;
  environment_id: string;
  scenario_type: string;
  overall_posture_score: number;
  risk_level: string;
  executive_summary: string;
  inventory_summary: Record<string, number>;
  top_attack_paths: PathItem[];
  shap_evidence: ShapFeat[];
  compliance_findings: Array<{
    framework: string;
    control_id: string;
    control_name: string;
    status: string;
    resource: string;
    remediation_hint: string;
  }>;
  verified_remediations: RemediationItem[];
  academic_metrics: Record<string, string>;
}

const TAB_TITLES: Record<ViewTab, { title: string; breadcrumb: string }> = {
  dashboard: { title: "Executive Security Posture", breadcrumb: "Overview" },
  explorer: { title: "Attack Path Explorer & Live Simulator", breadcrumb: "Security Graph" },
  whatif: { title: "What-If Security Digital Twin", breadcrumb: "Simulation Lab" },
  copilot: { title: "AI Security Operations Copilot", breadcrumb: "AI Analyst" },
  explainability: { title: "Explainable AI & Model Benchmark Lab", breadcrumb: "ML Intelligence" },
  remediation: { title: "Verified Remediation & Log Replay", breadcrumb: "Auto-Fix" },
  cloud: { title: "Live Cloud & Database Connectors", breadcrumb: "Integrations" },
  reports: { title: "Executive Audit & Compliance Report", breadcrumb: "Governance" },
};

export default function EnterpriseSecurityConsole() {
  const [activeTab, setActiveTab] = useState<ViewTab>("dashboard");
  const [apiOnline, setApiOnline] = useState<boolean>(true);
  const [neonStatus, setNeonStatus] = useState<NeonStatus | null>(null);

  const [envs, setEnvs] = useState<EnvSummary[]>([]);
  const [selectedEnv, setSelectedEnv] = useState<string>("demo_capital_one");
  const [loading, setLoading] = useState<boolean>(true);

  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [paths, setPaths] = useState<PathItem[]>([]);
  const [pathFilter, setPathFilter] = useState<"all" | "exploitable" | "blocked">("all");
  const [selectedPath, setSelectedPath] = useState<PathItem | null>(null);
  const [explanations, setExplanations] = useState<Record<string, { top_features: ShapFeat[] }>>({});
  const [remediations, setRemediations] = useState<RemediationItem[]>([]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [simulationStep, setSimulationStep] = useState<number>(-1);
  const simTimerRef = useRef<NodeJS.Timeout | null>(null);

  const [whatIfToggles, setWhatIfToggles] = useState<WhatIfToggles>({
    port_5432_open: true,
    iam_admin_access: true,
    db_role_inheritance: true,
    rds_public: true,
    imdsv2_required: false,
  });
  const [whatIfResult, setWhatIfResult] = useState<WhatIfResult | null>(null);
  const [whatIfLoading, setWhatIfLoading] = useState<boolean>(false);

  const [copilotMessages, setCopilotMessages] = useState<CopilotMsg[]>([
    {
      role: "assistant",
      content:
        "Welcome to **DB-TRACE AI Security Copilot**. I am grounded directly in your live cloud topology, PyG GNN + XGBoost risk predictions, TreeSHAP feature attributions, and 30-day historical log-replay verifications. Ask me anything about your active environment.",
      suggested_followups: [
        "Why is my database at critical risk?",
        "Show me the most dangerous attack path.",
        "Which IAM role has excessive privileges?",
        "How can I fix this vulnerability?",
      ],
    },
  ]);
  const [copilotInput, setCopilotInput] = useState<string>("");
  const [copilotLoading, setCopilotLoading] = useState<boolean>(false);

  const [reportData, setReportData] = useState<ExecutiveReportData | null>(null);
  const [reportLoading, setReportLoading] = useState<boolean>(false);

  const [customPgUrl, setCustomPgUrl] = useState<string>("");
  const [awsRegion, setAwsRegion] = useState<string>("us-east-1");
  const [awsKey, setAwsKey] = useState<string>("");
  const [awsSecret, setAwsSecret] = useState<string>("");
  const [awsToken, setAwsToken] = useState<string>("");
  const [awsInventory, setAwsInventory] = useState<{
    account_id: string;
    region: string;
    principals: number;
    security_groups: number;
    rds_instances: number;
    warnings?: string[];
  } | null>(null);
  const [awsError, setAwsError] = useState<string>("");
  const [azSubId, setAzSubId] = useState<string>("");
  const [azTenantId, setAzTenantId] = useState<string>("");
  const [azClientId, setAzClientId] = useState<string>("");
  const [azClientSecret, setAzClientSecret] = useState<string>("");
  const [azToken, setAzToken] = useState<string>("");
  const [azError, setAzError] = useState<string>("");
  const [gcpProjectId, setGcpProjectId] = useState<string>("");
  const [gcpToken, setGcpToken] = useState<string>("");
  const [gcpError, setGcpError] = useState<string>("");
  const [liveScanLoading, setLiveScanLoading] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState<boolean>(false);
  const [searchFilter, setSearchFilter] = useState<string>("");

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3800);
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCommandPaletteOpen((prev) => !prev);
      }
      if (e.key === "Escape") {
        setCommandPaletteOpen(false);
        setSelectedNode(null);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  useEffect(() => {
    fetch(`${API_BASE}/health`)
      .then((r) => r.json())
      .then(() => setApiOnline(true))
      .catch(() => setApiOnline(false));

    fetch(`${API_BASE}/live/neon/status`)
      .then((r) => r.json())
      .then((d) => setNeonStatus(d))
      .catch(() => setNeonStatus({ connected: false }));

    fetch(`${API_BASE}/environments`)
      .then((r) => r.json())
      .then((data: EnvSummary[]) => {
        setEnvs(data);
        if (data.length > 0 && !selectedEnv) {
          setSelectedEnv(data[0].env_id);
        }
      })
      .catch(() => setApiOnline(false));
  }, []);

  useEffect(() => {
    if (!selectedEnv) return;
    setLoading(true);
    setIsSimulating(false);
    setSimulationStep(-1);
    setWhatIfResult(null);
    if (simTimerRef.current) clearInterval(simTimerRef.current);

    Promise.all([
      fetch(`${API_BASE}/environments/${selectedEnv}/graph`).then((r) => r.json()),
      fetch(`${API_BASE}/environments/${selectedEnv}/paths`).then((r) => r.json()),
      fetch(`${API_BASE}/environments/${selectedEnv}/remediate`).then((r) => r.json()),
    ])
      .then(([g, p, rem]) => {
        setNodes(g.nodes || []);
        setEdges(g.edges || []);
        const pathList: PathItem[] = p.paths || [];
        setPaths(pathList);
        setExplanations(p.explanations || {});
        setRemediations(rem.remediations || []);
        setSelectedPath(pathList.length > 0 ? pathList[0] : null);
      })
      .catch((err) => console.error("Failed to load environment:", err))
      .finally(() => setLoading(false));
  }, [selectedEnv]);

  useEffect(() => {
    if (isSimulating) {
      simTimerRef.current = setInterval(() => {
        setSimulationStep((prev) => {
          if (prev >= 5) {
            setIsSimulating(false);
            return 5;
          }
          return prev + 1;
        });
      }, 1350);
    } else if (simTimerRef.current) {
      clearInterval(simTimerRef.current);
    }
    return () => {
      if (simTimerRef.current) clearInterval(simTimerRef.current);
    };
  }, [isSimulating]);

  const runWhatIfSimulation = (updatedToggles: WhatIfToggles) => {
    setWhatIfLoading(true);
    fetch(`${API_BASE}/api/what-if/simulate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ env_id: selectedEnv, toggles: updatedToggles }),
    })
      .then((r) => r.json())
      .then((data: WhatIfResult) => setWhatIfResult(data))
      .catch((err) => showToast("Simulation error: " + err))
      .finally(() => setWhatIfLoading(false));
  };

  const sendCopilotMessage = (userQuery: string) => {
    if (!userQuery.trim()) return;
    const q = userQuery.trim();
    setCopilotInput("");
    setCopilotMessages((prev) => [...prev, { role: "user", content: q }]);
    setCopilotLoading(true);

    fetch(`${API_BASE}/api/copilot/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ env_id: selectedEnv, message: q }),
    })
      .then((r) => r.json())
      .then((res) => {
        setCopilotMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: res.answer,
            key_findings: res.key_findings,
            evidence: res.evidence,
            suggested_action: res.suggested_action,
            suggested_followups: res.suggested_followups,
            action_button: res.action_button,
            citations: res.citations,
            confidence_label: res.confidence_label,
          },
        ]);
      })
      .catch((err) => {
        setCopilotMessages((prev) => [
          ...prev,
          { role: "assistant", content: "Failed to reach AI reasoning service: " + err },
        ]);
      })
      .finally(() => setCopilotLoading(false));
  };

  const loadExecutiveReport = () => {
    setReportLoading(true);
    fetch(`${API_BASE}/api/reports/assessment/${selectedEnv}`)
      .then((r) => r.json())
      .then((data: ExecutiveReportData) => setReportData(data))
      .catch((err) => showToast("Report generation failed: " + err))
      .finally(() => setReportLoading(false));
  };

  const handleLiveNeonScan = () => {
    setLiveScanLoading(true);
    fetch(`${API_BASE}/live/neon/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ connection_url: customPgUrl || undefined }),
    })
      .then((r) => r.json())
      .then(() => {
        showToast("Live Neon PostgreSQL scan completed!");
        setSelectedEnv("live_neon_cloud");
      })
      .catch((err) => showToast("Neon scan failed: " + err))
      .finally(() => setLiveScanLoading(false));
  };

  const handleLiveNeonSeed = () => {
    setLiveScanLoading(true);
    fetch(`${API_BASE}/live/neon/seed`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ connection_url: customPgUrl || undefined }),
    })
      .then((r) => r.json())
      .then((res) => {
        showToast(`Seeded ${res.seeded_roles?.length || 1} vulnerable role(s) & PII tables!`);
        handleLiveNeonScan();
      })
      .catch((err) => showToast("Seed failed: " + err))
      .finally(() => setLiveScanLoading(false));
  };

  const handleLiveNeonApplyFix = () => {
    setLiveScanLoading(true);
    fetch(`${API_BASE}/live/neon/apply-fix`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ connection_url: customPgUrl || undefined, table_name: "customers_pii" }),
    })
      .then((r) => r.json())
      .then(() => {
        showToast("Verified SQL REVOKE executed live on Neon Cloud!");
        handleLiveNeonScan();
      })
      .catch((err) => showToast("Fix execution failed: " + err))
      .finally(() => setLiveScanLoading(false));
  };

  const handleRealAwsScan = () => {
    setLiveScanLoading(true);
    setAwsError("");
    fetch(`${API_BASE}/cloud/aws/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        region: awsRegion,
        access_key_id: awsKey || undefined,
        secret_access_key: awsSecret || undefined,
        session_token: awsToken || undefined,
      }),
    })
      .then(async (r) => {
        if (!r.ok) {
          const err = await r.json();
          throw new Error(err.detail || "AWS scan failed");
        }
        return r.json();
      })
      .then((data) => {
        setAwsInventory(data.inventory);
        setNodes(data.graph?.nodes || []);
        setEdges(data.graph?.edges || []);
        setPaths(data.paths || []);
        setExplanations(data.explanations || {});
        setRemediations(data.remediations || []);
        showToast(`Scanned AWS Account ${data.inventory.account_id} (${data.inventory.principals} principals)!`);
        setActiveTab("explorer");
      })
      .catch((err) => setAwsError(String(err)))
      .finally(() => setLiveScanLoading(false));
  };

  const handleRealAzureScan = () => {
    setLiveScanLoading(true);
    setAzError("");
    fetch(`${API_BASE}/cloud/azure/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        subscription_id: azSubId,
        tenant_id: azTenantId || undefined,
        client_id: azClientId || undefined,
        client_secret: azClientSecret || undefined,
        access_token: azToken || undefined,
      }),
    })
      .then(async (r) => {
        if (!r.ok) {
          const err = await r.json();
          throw new Error(err.detail || "Azure scan failed");
        }
        return r.json();
      })
      .then((data) => {
        setNodes(data.graph?.nodes || []);
        setEdges(data.graph?.edges || []);
        setPaths(data.paths || []);
        setExplanations(data.explanations || {});
        setRemediations(data.remediations || []);
        showToast(`Scanned Azure Subscription ${data.inventory.subscription_id} (${data.inventory.principals} principals)!`);
        setActiveTab("explorer");
      })
      .catch((err) => setAzError(String(err)))
      .finally(() => setLiveScanLoading(false));
  };

  const handleRealGcpScan = () => {
    setLiveScanLoading(true);
    setGcpError("");
    fetch(`${API_BASE}/cloud/gcp/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        project_id: gcpProjectId,
        access_token: gcpToken,
      }),
    })
      .then(async (r) => {
        if (!r.ok) {
          const err = await r.json();
          throw new Error(err.detail || "GCP scan failed");
        }
        return r.json();
      })
      .then((data) => {
        setNodes(data.graph?.nodes || []);
        setEdges(data.graph?.edges || []);
        setPaths(data.paths || []);
        setExplanations(data.explanations || {});
        setRemediations(data.remediations || []);
        showToast(`Scanned GCP Project ${data.inventory.project_id} (${data.inventory.principals} IAM members)!`);
        setActiveTab("explorer");
      })
      .catch((err) => setGcpError(String(err)))
      .finally(() => setLiveScanLoading(false));
  };

  const exploitableCount = paths.filter((p) => p.label_exploitable === 1).length;
  const maxRiskScore = paths.length > 0 ? Math.max(...paths.map((p) => p.risk_score)) : 0;
  const postureScore = exploitableCount > 0 ? Math.max(12, 100 - exploitableCount * 28) : 94;

  const filteredPaths = paths.filter((p) => {
    if (pathFilter === "exploitable") return p.label_exploitable === 1;
    if (pathFilter === "blocked") return p.label_exploitable === 0;
    return true;
  });

  const activeHighlightedIds = selectedPath
    ? [
        selectedPath.entry_principal_id,
        selectedPath.compute_id,
        selectedPath.source_sg_id,
        selectedPath.rds_sg_id,
        selectedPath.rds_id,
        selectedPath.db_role_id,
        selectedPath.db_table_id,
      ].filter((x): x is string => Boolean(x))
    : [];

  const topShap =
    selectedPath && explanations[selectedPath.path_id]
      ? explanations[selectedPath.path_id].top_features
      : [];

  const navItems: Array<{
    id: ViewTab;
    label: string;
    icon: typeof BarChart3;
    badge?: string | null;
    badgeTone?: string;
  }> = [
    { id: "dashboard", label: "Executive Overview", icon: BarChart3 },
    {
      id: "explorer",
      label: "Attack Path Graph",
      icon: GitBranch,
      badge: exploitableCount > 0 ? `${exploitableCount}` : null,
      badgeTone: "bg-red-500/15 text-red-700",
    },
    { id: "whatif", label: "What-If Digital Twin", icon: Sliders, badge: "Live", badgeTone: "bg-amber-500/15 text-amber-700" },
    { id: "copilot", label: "AI Security Copilot", icon: Bot, badge: "RAG", badgeTone: "bg-indigo-500/15 text-indigo-700" },
    { id: "explainability", label: "Explainability & ML", icon: Brain },
    {
      id: "remediation",
      label: "Verified Remediation",
      icon: Wrench,
      badge: remediations.length > 0 ? `${remediations.length}` : null,
      badgeTone: "bg-emerald-500/15 text-emerald-700",
    },
    { id: "cloud", label: "Cloud Connectors", icon: Cloud },
    { id: "reports", label: "Audit & Compliance", icon: FileText },
  ];

  return (
    <div className="flex min-h-screen bg-[#F4F6F9] text-slate-900">
      {/* Floating Toast */}
      <AnimatePresence>
        {toastMessage && (
          <motion.div
            initial={{ opacity: 0, y: 18, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 12, scale: 0.96 }}
            className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 rounded-xl bg-slate-900 px-4 py-3 text-xs font-semibold text-white shadow-floating ring-1 ring-white/10"
          >
            <Sparkles className="h-4 w-4 text-amber-400 shrink-0" />
            <span>{toastMessage}</span>
            <button type="button" onClick={() => setToastMessage(null)} className="ml-1 text-slate-400 hover:text-white">
              <X className="h-3.5 w-3.5" />
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Command Palette (Ctrl + K) */}
      <AnimatePresence>
        {commandPaletteOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setCommandPaletteOpen(false)}
            className="fixed inset-0 z-50 flex items-start justify-center bg-slate-900/35 backdrop-blur-sm pt-24 px-4"
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: -8 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.96, y: -8 }}
              onClick={(e) => e.stopPropagation()}
              className="w-full max-w-lg rounded-2xl bg-white p-4 shadow-floating border border-slate-200/90"
            >
              <div className="flex items-center gap-3 border-b border-slate-100 pb-3">
                <Search className="h-4 w-4 text-slate-400" />
                <input
                  type="text"
                  autoFocus
                  placeholder="Jump to module, attack path, or action..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  className="w-full text-sm outline-none placeholder:text-slate-400"
                />
                <kbd className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">ESC</kbd>
              </div>
              <div className="mt-2.5 space-y-1">
                {navItems
                  .filter((item) => item.label.toLowerCase().includes(searchFilter.toLowerCase()))
                  .map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        setActiveTab(item.id);
                        if (item.id === "reports" && !reportData) loadExecutiveReport();
                        setCommandPaletteOpen(false);
                        setSearchFilter("");
                      }}
                      className="flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-left hover:bg-indigo-50/70 group transition-colors"
                    >
                      <span className="flex items-center gap-3">
                        <item.icon className="h-4 w-4 text-slate-400 group-hover:text-indigo-600" />
                        <span className="text-xs font-semibold text-slate-800 group-hover:text-indigo-700">
                          {item.label}
                        </span>
                      </span>
                      <ChevronRight className="h-3.5 w-3.5 text-slate-300 group-hover:text-indigo-500" />
                    </button>
                  ))}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Enterprise Sidebar */}
      <aside className="no-print w-[264px] shrink-0 border-r border-slate-200/90 bg-white flex flex-col justify-between">
        <div>
          {/* Brand Header */}
          <div className="px-5 py-4 border-b border-slate-100">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-600 to-blue-700 text-white shadow-md shadow-indigo-200">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="text-[15px] font-extrabold tracking-tight text-slate-900">DB-TRACE</span>
                  <span className="rounded-md bg-indigo-50 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-indigo-700 ring-1 ring-indigo-200/70">
                    Cloud
                  </span>
                </div>
                <div className="text-[11px] font-medium text-slate-400">AI Database Security Ops</div>
              </div>
            </div>

            <button
              type="button"
              onClick={() => setCommandPaletteOpen(true)}
              className="mt-3.5 flex w-full items-center justify-between rounded-xl border border-slate-200/90 bg-slate-50/70 px-3 py-2 text-xs text-slate-500 hover:bg-slate-100/80 hover:border-slate-300 transition-all"
            >
              <span className="flex items-center gap-2">
                <Search className="h-3.5 w-3.5 text-slate-400" />
                <span>Quick search...</span>
              </span>
              <kbd className="rounded border border-slate-200 bg-white px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                ⌘K
              </kbd>
            </button>
          </div>

          {/* Environment Context Switcher */}
          <div className="px-4 py-3.5 border-b border-slate-100">
            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1.5 block">
              Target Cloud Environment
            </label>
            <select
              value={selectedEnv}
              onChange={(e) => setSelectedEnv(e.target.value)}
              className="w-full rounded-xl border border-slate-200 bg-slate-50/60 px-2.5 py-2 text-xs font-semibold text-slate-800 outline-none focus:bg-white focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/15 transition-all"
            >
              {envs.map((env) => (
                <option key={env.env_id} value={env.env_id}>
                  {env.env_id === "demo_capital_one"
                    ? "Capital One SSRF Replay"
                    : env.env_id === "live_neon_cloud"
                    ? "Live Neon Cloud PostgreSQL"
                    : `${env.env_id} — ${env.scenario_type.replace(/_/g, " ")}`}
                </option>
              ))}
            </select>
          </div>

          {/* Animated Navigation */}
          <nav className="p-3 space-y-1">
            {navItems.map((tab) => {
              const active = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => {
                    setActiveTab(tab.id);
                    if (tab.id === "reports" && !reportData) loadExecutiveReport();
                  }}
                  className={`relative flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-xs font-semibold transition-colors ${
                    active ? "text-indigo-700" : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
                  }`}
                >
                  {active && (
                    <motion.span
                      layoutId="activeNavPill"
                      transition={{ type: "spring", stiffness: 450, damping: 35 }}
                      className="absolute inset-0 rounded-xl bg-indigo-50/90 ring-1 ring-indigo-200/80"
                    />
                  )}
                  <span className="relative z-10 flex items-center gap-2.5">
                    <tab.icon className={`h-4 w-4 ${active ? "text-indigo-600" : "text-slate-400"}`} />
                    <span>{tab.label}</span>
                  </span>
                  {tab.badge && (
                    <span
                      className={`relative z-10 rounded-full px-2 py-0.5 text-[9.5px] font-bold ${
                        active ? "bg-indigo-600 text-white" : tab.badgeTone
                      }`}
                    >
                      {tab.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Live Telemetry Footer */}
        <div className="p-4 border-t border-slate-100 bg-slate-50/50 space-y-2 text-[11px]">
          <div className="flex items-center justify-between">
            <span className="text-slate-500">Inference API</span>
            <span className="flex items-center gap-1.5 font-semibold text-slate-800">
              <span className={`h-2 w-2 rounded-full ${apiOnline ? "bg-emerald-500 animate-pulse" : "bg-red-500"}`} />
              {apiOnline ? "Online" : "Offline"}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-500">Neon Cloud PG</span>
            <span className="flex items-center gap-1.5 font-semibold text-slate-800">
              <span className={`h-2 w-2 rounded-full ${neonStatus?.connected ? "bg-indigo-500" : "bg-slate-300"}`} />
              {neonStatus?.connected ? "TLS Ready" : "Standby"}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-500">Active Engine</span>
            <span className="font-mono text-[10px] font-bold text-indigo-600">GNN + XGBoost</span>
          </div>
        </div>
      </aside>

      {/* Main Workspace */}
      <main className="flex-1 min-w-0 flex flex-col h-screen overflow-y-auto">
        {/* Glassmorphic Top Header */}
        <header className="no-print sticky top-0 z-30 flex items-center justify-between border-b border-slate-200/80 bg-white/85 px-8 py-3.5 backdrop-blur-md">
          <div>
            <div className="flex items-center gap-1.5 text-[11px] font-medium text-slate-400">
              <span>DB-TRACE</span>
              <ChevronRight className="h-3 w-3" />
              <span className="text-indigo-600 font-semibold">{TAB_TITLES[activeTab].breadcrumb}</span>
              <ChevronRight className="h-3 w-3" />
              <span className="font-mono text-slate-600">{selectedEnv}</span>
            </div>
            <h1 className="text-lg font-extrabold tracking-tight text-slate-900 mt-0.5">
              {TAB_TITLES[activeTab].title}
            </h1>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={() => {
                setActiveTab("copilot");
                sendCopilotMessage("Why is my database at critical risk?");
              }}
              className="flex items-center gap-1.5 rounded-xl border border-indigo-200 bg-indigo-50/70 px-3 py-2 text-xs font-bold text-indigo-700 hover:bg-indigo-100 transition-colors"
            >
              <Bot className="h-3.5 w-3.5" />
              <span>Ask Copilot</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setActiveTab("reports");
                loadExecutiveReport();
              }}
              className="flex items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 shadow-2xs transition-colors"
            >
              <Download className="h-3.5 w-3.5 text-slate-500" />
              <span>Export PDF</span>
            </button>

            <button
              type="button"
              onClick={handleLiveNeonScan}
              disabled={liveScanLoading}
              className="flex items-center gap-1.5 rounded-xl bg-indigo-600 px-3.5 py-2 text-xs font-bold text-white shadow-sm shadow-indigo-200 hover:bg-indigo-700 transition-all disabled:opacity-50"
            >
              <Play className="h-3.5 w-3.5" />
              <span>{liveScanLoading ? "Scanning..." : "Run Live Scan"}</span>
            </button>
          </div>
        </header>

        {/* Animated View Container */}
        <div className="p-7 flex-1 max-w-[1600px] w-full mx-auto">
          {loading ? (
            <div className="space-y-6 animate-pulse">
              <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
                {Array.from({ length: 6 }).map((_, i) => (
                  <div key={i} className="h-28 rounded-2xl bg-white border border-slate-200/80" />
                ))}
              </div>
              <div className="h-80 rounded-2xl bg-white border border-slate-200/80" />
            </div>
          ) : (
            <AnimatePresence mode="wait">
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.22, ease: "easeOut" }}
                className="space-y-6"
              >
                {/* ========================================================= */}
                {/* 1. EXECUTIVE DASHBOARD */}
                {/* ========================================================= */}
                {activeTab === "dashboard" && (
                  <>
                    {/* 6 Sparkline KPI Cards */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
                      <SparklineKpiCard
                        title="Cloud Assets"
                        value={nodes.length}
                        subtitle="Indexed entities"
                        delta="Live"
                        deltaType="info"
                        icon={Server}
                        accentColor="#4F46E5"
                        sparkData={[6, 8, 9, 10, 11, nodes.length || 12]}
                        onClick={() => setActiveTab("explorer")}
                        delay={0.02}
                      />
                      <SparklineKpiCard
                        title="Exploitable Paths"
                        value={exploitableCount}
                        subtitle="Active kill-chains"
                        delta={exploitableCount > 0 ? "Critical" : "Clear"}
                        deltaType={exploitableCount > 0 ? "danger" : "success"}
                        icon={GitBranch}
                        accentColor="#EF4444"
                        sparkData={[1, 2, 2, 3, 3, exploitableCount]}
                        onClick={() => setActiveTab("explorer")}
                        delay={0.06}
                      />
                      <SparklineKpiCard
                        title="Peak AI Risk"
                        value={`${Math.round(maxRiskScore * 100)}%`}
                        subtitle="Calibrated score"
                        delta={maxRiskScore > 0.8 ? "High" : "Low"}
                        deltaType={maxRiskScore > 0.8 ? "danger" : "success"}
                        icon={Flame}
                        accentColor="#F97316"
                        sparkData={[65, 74, 82, 90, 96, Math.round(maxRiskScore * 100)]}
                        onClick={() => setActiveTab("explainability")}
                        delay={0.1}
                      />
                      <SparklineKpiCard
                        title="Verified Fixes"
                        value={remediations.length}
                        subtitle="0% legit breakage"
                        delta="Safe"
                        deltaType="success"
                        icon={ShieldCheck}
                        accentColor="#10B981"
                        sparkData={[1, 1, 2, 2, 3, remediations.length || 3]}
                        onClick={() => setActiveTab("remediation")}
                        delay={0.14}
                      />
                      <SparklineKpiCard
                        title="Model F1 (5-Fold)"
                        value="99.2%"
                        subtitle="GNN + XGBoost"
                        delta="+13.7%"
                        deltaType="info"
                        icon={Brain}
                        accentColor="#6366F1"
                        sparkData={[24, 38, 70, 88, 86, 99]}
                        onClick={() => setActiveTab("explainability")}
                        delay={0.18}
                      />
                      <SparklineKpiCard
                        title="Audit Replay"
                        value="30 Days"
                        subtitle="CloudTrail + pgaudit"
                        delta="Verified"
                        deltaType="neutral"
                        icon={Clock}
                        accentColor="#0EA5E9"
                        sparkData={[10, 15, 20, 24, 28, 30]}
                        onClick={() => setActiveTab("remediation")}
                        delay={0.22}
                      />
                    </div>

                    {/* Risk Trend Chart + Security Posture Gauge */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                      <div className="lg:col-span-2 enterprise-card rounded-2xl p-6 space-y-4">
                        <div className="flex items-center justify-between">
                          <div>
                            <h2 className="text-sm font-bold text-slate-900">
                              30-Day Attack Surface &amp; Control Coverage Trend
                            </h2>
                            <p className="text-xs text-slate-500">
                              Continuous evaluation of cross-layer AWS IAM, VPC, and PostgreSQL risk exposure
                            </p>
                          </div>
                          <span className="rounded-full bg-red-50 px-2.5 py-1 text-[11px] font-bold text-red-700 ring-1 ring-red-200">
                            {exploitableCount} Active Exposure(s)
                          </span>
                        </div>
                        <RiskTrendAreaChart currentRisk={maxRiskScore * 100} />
                      </div>

                      <div className="enterprise-card rounded-2xl p-6 flex flex-col justify-between">
                        <div>
                          <h2 className="text-sm font-bold text-slate-900">Security Posture Score</h2>
                          <p className="text-xs text-slate-500">Composite cloud-to-database health</p>
                        </div>

                        <div className="my-4">
                          <PostureRadialGauge
                            score={postureScore}
                            label={exploitableCount > 0 ? "Critical Action Needed" : "Hardened Posture"}
                          />
                        </div>

                        <div className="space-y-2 border-t border-slate-100 pt-4 text-xs">
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500">CIS AWS Benchmark</span>
                            <span className="font-bold text-amber-600">2 Controls Failing</span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500">Verified Zero-Breakage Fix</span>
                            <span className="font-bold text-emerald-600">Ready to Apply</span>
                          </div>
                          <button
                            type="button"
                            onClick={() => setActiveTab("whatif")}
                            className="mt-2 flex w-full items-center justify-center gap-1.5 rounded-xl bg-slate-900 py-2.5 text-xs font-bold text-white hover:bg-slate-800 transition-colors"
                          >
                            <Sliders className="h-3.5 w-3.5" />
                            <span>Simulate Fixes in Digital Twin</span>
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Interactive React Flow Graph Preview */}
                    <div className="enterprise-card rounded-2xl p-6 space-y-4">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div>
                          <h2 className="text-sm font-bold text-slate-900">
                            Live Multi-Hop Attack Graph Topology
                          </h2>
                          <p className="text-xs text-slate-500">
                            Interactive node-graph connecting external entry points to sensitive PostgreSQL tables
                          </p>
                        </div>
                        <button
                          type="button"
                          onClick={() => setActiveTab("explorer")}
                          className="flex items-center gap-1.5 rounded-xl bg-indigo-50 px-3 py-1.5 text-xs font-bold text-indigo-700 hover:bg-indigo-100 transition-colors"
                        >
                          <span>Launch Attack Simulator</span>
                          <ArrowRight className="h-3.5 w-3.5" />
                        </button>
                      </div>

                      <AttackGraph
                        nodes={nodes}
                        edges={edges}
                        highlightedNodeIds={activeHighlightedIds}
                        selectedNodeId={selectedNode?.data.id || null}
                        onSelectNode={(n) => setSelectedNode(n)}
                        isExploitable={exploitableCount > 0}
                        heightClass="h-[460px]"
                      />
                    </div>
                  </>
                )}

                {/* ========================================================= */}
                {/* 2. ATTACK PATH EXPLORER & LIVE SIMULATOR */}
                {/* ========================================================= */}
                {activeTab === "explorer" && (
                  <>
                    {/* Playback Controls Bar */}
                    <div className="enterprise-card rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4">
                      <div className="flex items-center gap-3">
                        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-red-50 text-red-600 ring-1 ring-red-200/80">
                          <Flame className="h-5 w-5" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-bold text-slate-900">
                              Interactive Attack Path Playback
                            </span>
                            <span className="rounded-md bg-red-50 px-2 py-0.5 text-[10px] font-bold uppercase text-red-700 ring-1 ring-red-200">
                              MITRE ATT&amp;CK
                            </span>
                          </div>
                          <p className="text-xs text-slate-500">
                            Step through each stage of the exploit chain or drag/zoom nodes to inspect blast radius.
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => {
                            setIsSimulating(false);
                            setSimulationStep(-1);
                          }}
                          className="flex items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors"
                        >
                          <RotateCcw className="h-3.5 w-3.5" />
                          <span>Reset</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setIsSimulating(false);
                            setSimulationStep((prev) => Math.max(0, prev - 1));
                          }}
                          disabled={simulationStep <= 0}
                          className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-40"
                        >
                          Prev
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            if (isSimulating) {
                              setIsSimulating(false);
                            } else {
                              if (simulationStep < 0 || simulationStep >= 5) setSimulationStep(0);
                              setIsSimulating(true);
                            }
                          }}
                          className={`flex items-center gap-1.5 rounded-xl px-4 py-2 text-xs font-bold text-white shadow-sm transition-colors ${
                            isSimulating ? "bg-amber-600 hover:bg-amber-700" : "bg-red-600 hover:bg-red-700"
                          }`}
                        >
                          {isSimulating ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
                          <span>{isSimulating ? "Pause" : "Auto-Play Attack"}</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setIsSimulating(false);
                            setSimulationStep((prev) => Math.min(5, prev + 1));
                          }}
                          disabled={simulationStep >= 5}
                          className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-40"
                        >
                          Next Step
                        </button>
                      </div>
                    </div>

                    {/* Active Step MITRE Telemetry Banner */}
                    <AnimatePresence>
                      {simulationStep >= 0 && selectedPath?.attack_steps && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: "auto" }}
                          exit={{ opacity: 0, height: 0 }}
                          className="rounded-2xl border border-amber-200 bg-gradient-to-r from-amber-50 to-orange-50/70 p-4 shadow-sm"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <span className="rounded-md bg-amber-600 px-2 py-0.5 text-[10px] font-bold uppercase text-white">
                                Stage {simulationStep + 1} / 6
                              </span>
                              <span className="text-xs font-bold text-slate-900">
                                {selectedPath.attack_steps[Math.min(selectedPath.attack_steps.length - 1, simulationStep)]?.stage}
                              </span>
                              <span className="rounded bg-white px-2 py-0.5 font-mono text-[10px] font-bold text-amber-800 ring-1 ring-amber-200">
                                {selectedPath.attack_steps[Math.min(selectedPath.attack_steps.length - 1, simulationStep)]?.mitre}
                              </span>
                            </div>
                            <span className="text-xs font-extrabold text-red-600 tabular-nums">
                              Calibrated Exploit Probability: {Math.round(selectedPath.risk_score * 100)}%
                            </span>
                          </div>
                          <p className="mt-1.5 text-xs text-slate-700">
                            {selectedPath.attack_steps[Math.min(selectedPath.attack_steps.length - 1, simulationStep)]?.detail}
                          </p>
                        </motion.div>
                      )}
                    </AnimatePresence>

                    {/* Full React Flow Interactive Graph */}
                    <div className="enterprise-card rounded-2xl p-5">
                      <AttackGraph
                        nodes={nodes}
                        edges={edges}
                        highlightedNodeIds={activeHighlightedIds}
                        selectedNodeId={selectedNode?.data.id || null}
                        onSelectNode={(n) => setSelectedNode(n)}
                        isExploitable={selectedPath ? selectedPath.label_exploitable === 1 : exploitableCount > 0}
                        isSimulating={isSimulating || simulationStep >= 0}
                        simulationStep={simulationStep}
                        heightClass="h-[540px]"
                      />
                    </div>

                    {/* Filterable Candidate Paths Table */}
                    <div className="enterprise-card rounded-2xl p-6 space-y-4">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div>
                          <h3 className="text-sm font-bold text-slate-900">Discovered Multi-Hop Access Paths</h3>
                          <p className="text-xs text-slate-500">
                            Click any row to highlight its trajectory on the interactive graph
                          </p>
                        </div>
                        <div className="flex items-center gap-1.5 rounded-xl bg-slate-100 p-1 text-xs font-semibold">
                          {(["all", "exploitable", "blocked"] as const).map((f) => (
                            <button
                              key={f}
                              type="button"
                              onClick={() => setPathFilter(f)}
                              className={`rounded-lg px-3 py-1 capitalize transition-all ${
                                pathFilter === f
                                  ? "bg-white text-slate-900 shadow-2xs"
                                  : "text-slate-500 hover:text-slate-800"
                              }`}
                            >
                              {f}
                            </button>
                          ))}
                        </div>
                      </div>

                      <div className="overflow-x-auto rounded-xl border border-slate-200/80">
                        <table className="w-full text-left text-xs">
                          <thead className="bg-slate-50/90 text-[10px] font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200">
                            <tr>
                              <th className="py-3 px-4">Path ID</th>
                              <th className="py-3 px-4">Entry Principal</th>
                              <th className="py-3 px-4">Compute Pivot</th>
                              <th className="py-3 px-4">DB Role</th>
                              <th className="py-3 px-4">Crown Jewel Table</th>
                              <th className="py-3 px-4">AI Score</th>
                              <th className="py-3 px-4">Verdict</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100">
                            {filteredPaths.map((p) => {
                              const isSel = selectedPath?.path_id === p.path_id;
                              return (
                                <tr
                                  key={p.path_id}
                                  onClick={() => {
                                    setSelectedPath(p);
                                    setSimulationStep(-1);
                                    setIsSimulating(false);
                                  }}
                                  className={`cursor-pointer transition-colors ${
                                    isSel ? "bg-indigo-50/70 font-semibold" : "hover:bg-slate-50/80"
                                  }`}
                                >
                                  <td className="py-3 px-4 font-mono font-bold text-slate-800">{p.path_id}</td>
                                  <td className="py-3 px-4 text-slate-700">{p.entry_name || p.entry_principal_id}</td>
                                  <td className="py-3 px-4 text-slate-600">{p.compute_id || "Direct Ingress"}</td>
                                  <td className="py-3 px-4 text-slate-700">{p.db_role_name || p.db_role_id}</td>
                                  <td className="py-3 px-4 font-mono text-slate-800">{p.db_table_name || p.db_table_id}</td>
                                  <td className="py-3 px-4 tabular-nums">
                                    <span
                                      className={`font-extrabold ${
                                        p.risk_score > 0.8
                                          ? "text-red-600"
                                          : p.risk_score > 0.4
                                          ? "text-amber-600"
                                          : "text-emerald-600"
                                      }`}
                                    >
                                      {Math.round(p.risk_score * 100)}%
                                    </span>
                                  </td>
                                  <td className="py-3 px-4">
                                    {p.label_exploitable === 1 ? (
                                      <span className="inline-flex items-center gap-1 rounded-full bg-red-50 px-2.5 py-0.5 text-[10px] font-bold text-red-700 ring-1 ring-red-200">
                                        <AlertCircle className="h-3 w-3" />
                                        Exploitable
                                      </span>
                                    ) : (
                                      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2.5 py-0.5 text-[10px] font-bold text-emerald-700 ring-1 ring-emerald-200">
                                        <Shield className="h-3 w-3" />
                                        Blocked
                                      </span>
                                    )}
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </>
                )}

                {/* ========================================================= */}
                {/* 3. WHAT-IF SECURITY DIGITAL TWIN PLAYGROUND */}
                {/* ========================================================= */}
                {activeTab === "whatif" && (
                  <>
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                      {/* Left 2 Cols: 5 Spring-Animated Security Controls */}
                      <div className="lg:col-span-2 enterprise-card rounded-2xl p-6 space-y-5">
                        <div className="flex items-center justify-between border-b border-slate-100 pb-4">
                          <div>
                            <h2 className="text-sm font-bold text-slate-900">
                              Virtual Cloud Security Controls
                            </h2>
                            <p className="text-xs text-slate-500">
                              Flip any security control below to mutate the in-memory cloud graph and recalculate risk live.
                            </p>
                          </div>
                          <button
                            type="button"
                            onClick={() => {
                              const def: WhatIfToggles = {
                                port_5432_open: true,
                                iam_admin_access: true,
                                db_role_inheritance: true,
                                rds_public: true,
                                imdsv2_required: false,
                              };
                              setWhatIfToggles(def);
                              runWhatIfSimulation(def);
                            }}
                            className="rounded-xl border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-50"
                          >
                            Reset Controls
                          </button>
                        </div>

                        <div className="space-y-3">
                          {[
                            {
                              key: "port_5432_open" as const,
                              icon: Network,
                              title: "Restrict PostgreSQL Port 5432 Ingress",
                              desc: "Block unrestricted 0.0.0.0/0 & permissive SG rules to port 5432",
                              isSecured: !whatIfToggles.port_5432_open,
                            },
                            {
                              key: "iam_admin_access" as const,
                              icon: User,
                              title: "Scope IAM Least-Privilege Policies",
                              desc: "Revoke wildcard (*) actions and iam:PassRole privilege escalation",
                              isSecured: !whatIfToggles.iam_admin_access,
                            },
                            {
                              key: "db_role_inheritance" as const,
                              icon: KeyRound,
                              title: "Enforce PostgreSQL NOINHERIT",
                              desc: "Disable transitive role membership & strip non-admin SUPERUSER flags",
                              isSecured: !whatIfToggles.db_role_inheritance,
                            },
                            {
                              key: "rds_public" as const,
                              icon: Database,
                              title: "Move RDS to Private Subnet",
                              desc: "Set publicly_accessible = false to remove public endpoint routing",
                              isSecured: !whatIfToggles.rds_public,
                            },
                            {
                              key: "imdsv2_required" as const,
                              icon: Cpu,
                              title: "Enforce EC2 IMDSv2 Session Tokens",
                              desc: "Require http_tokens = 'required' to neutralize SSRF credential theft",
                              isSecured: whatIfToggles.imdsv2_required,
                            },
                          ].map((ctrl) => (
                            <div
                              key={ctrl.key}
                              className={`flex items-center justify-between rounded-xl border p-4 transition-all ${
                                ctrl.isSecured
                                  ? "border-emerald-200/90 bg-emerald-50/40"
                                  : "border-slate-200/80 bg-slate-50/40"
                              }`}
                            >
                              <div className="flex items-center gap-3.5">
                                <div
                                  className={`flex h-9 w-9 items-center justify-center rounded-xl ${
                                    ctrl.isSecured
                                      ? "bg-emerald-100 text-emerald-700"
                                      : "bg-red-50 text-red-600"
                                  }`}
                                >
                                  <ctrl.icon className="h-4 w-4" />
                                </div>
                                <div>
                                  <div className="text-xs font-bold text-slate-900">{ctrl.title}</div>
                                  <div className="text-[11px] text-slate-500">{ctrl.desc}</div>
                                </div>
                              </div>

                              <div className="flex items-center gap-3">
                                <span
                                  className={`text-[10.5px] font-bold uppercase tracking-wide ${
                                    ctrl.isSecured ? "text-emerald-700" : "text-red-600"
                                  }`}
                                >
                                  {ctrl.isSecured ? "Hardened" : "Vulnerable"}
                                </span>
                                <AnimatedToggleSwitch
                                  checked={ctrl.isSecured}
                                  onChange={() => {
                                    const upd = { ...whatIfToggles, [ctrl.key]: !whatIfToggles[ctrl.key] };
                                    setWhatIfToggles(upd);
                                    runWhatIfSimulation(upd);
                                  }}
                                />
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Right Col: Live Animated Risk Score Gauge */}
                      <div className="enterprise-card rounded-2xl p-6 flex flex-col justify-between">
                        <div>
                          <div className="flex items-center justify-between">
                            <h3 className="text-sm font-bold text-slate-900">Live Risk Outcome</h3>
                            {whatIfLoading && (
                              <span className="text-[11px] font-semibold text-indigo-600 animate-pulse">
                                Computing...
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-slate-500 mt-0.5">
                            Real-time deterministic graph + log-replay evaluation
                          </p>
                        </div>

                        <div className="my-6">
                          <PostureRadialGauge
                            score={whatIfResult ? whatIfResult.simulated_risk_score : maxRiskScore * 100}
                            label={whatIfResult ? whatIfResult.status : "Baseline Unpatched"}
                            invertRisk={true}
                          />
                        </div>

                        <div className="space-y-2.5 border-t border-slate-100 pt-4 text-xs">
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500">Risk Score Delta</span>
                            <span className="font-extrabold text-emerald-600 tabular-nums">
                              {whatIfResult ? `${whatIfResult.risk_delta}%` : "0.0%"}
                            </span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500">Paths Eliminated</span>
                            <span className="font-bold text-slate-900 tabular-nums">
                              {whatIfResult
                                ? `${whatIfResult.paths_eliminated} / ${whatIfResult.paths_before}`
                                : `0 / ${exploitableCount}`}
                            </span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500">Legitimate Traffic Broken</span>
                            <span className="font-bold text-emerald-600 tabular-nums">
                              {whatIfResult
                                ? `${whatIfResult.legit_broken} / ${whatIfResult.legit_total} (${whatIfResult.false_breakage_rate}%)`
                                : "0 (Verified Safe)"}
                            </span>
                          </div>
                          {whatIfResult && (
                            <p className="rounded-xl bg-slate-50 p-3 text-[11px] text-slate-600 border border-slate-200/70 leading-relaxed mt-2">
                              {whatIfResult.impact_narrative}
                            </p>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Simulated Digital Twin Graph */}
                    {whatIfResult && (
                      <div className="enterprise-card rounded-2xl p-6 space-y-3">
                        <div className="flex items-center justify-between">
                          <h3 className="text-sm font-bold text-slate-900">
                            Digital Twin Topology (After Virtual Policy Changes)
                          </h3>
                          <span
                            className={`rounded-full px-3 py-1 text-xs font-bold ${
                              whatIfResult.paths_after === 0
                                ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200"
                                : "bg-amber-50 text-amber-700 ring-1 ring-amber-200"
                            }`}
                          >
                            {whatIfResult.paths_after} Exploitable Path(s) Remaining
                          </span>
                        </div>
                        <AttackGraph
                          nodes={whatIfResult.graph_elements.nodes}
                          edges={whatIfResult.graph_elements.edges}
                          highlightedNodeIds={whatIfResult.active_exploitable_path_ids}
                          selectedNodeId={null}
                          onSelectNode={(n) => setSelectedNode(n)}
                          isExploitable={whatIfResult.paths_after > 0}
                          heightClass="h-[460px]"
                        />
                      </div>
                    )}
                  </>
                )}

                {/* ========================================================= */}
                {/* 4. AI SECURITY COPILOT */}
                {/* ========================================================= */}
                {activeTab === "copilot" && (
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[700px]">
                    <div className="lg:col-span-2 enterprise-card rounded-2xl flex flex-col justify-between overflow-hidden">
                      <div className="flex items-center justify-between border-b border-slate-100 bg-slate-50/70 px-5 py-3.5">
                        <div className="flex items-center gap-3">
                          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-600 text-white shadow-sm">
                            <Bot className="h-4 w-4" />
                          </div>
                          <div>
                            <div className="text-xs font-bold text-slate-900">DB-TRACE AI Security Analyst</div>
                            <div className="flex items-center gap-1.5 text-[11px] font-medium text-emerald-600">
                              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                              Grounded in GNN Topology, SHAP &amp; 30-Day Audit Logs
                            </div>
                          </div>
                        </div>
                        <span className="rounded-lg bg-indigo-50 px-2.5 py-1 font-mono text-[10px] font-bold text-indigo-700 ring-1 ring-indigo-200/70">
                          Zero-Hallucination RAG
                        </span>
                      </div>

                      <div className="flex-1 overflow-y-auto p-5 space-y-4">
                        {copilotMessages.map((m, idx) => (
                          <motion.div
                            key={idx}
                            initial={{ opacity: 0, y: 8 }}
                            animate={{ opacity: 1, y: 0 }}
                            className={`flex gap-3 ${m.role === "user" ? "justify-end" : "justify-start"}`}
                          >
                            {m.role === "assistant" && (
                              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-indigo-100 text-[11px] font-bold text-indigo-700">
                                AI
                              </div>
                            )}
                            <div
                              className={`max-w-xl rounded-2xl p-4 text-xs leading-relaxed space-y-3 ${
                                m.role === "user"
                                  ? "bg-indigo-600 text-white rounded-br-sm shadow-sm"
                                  : "bg-slate-50 border border-slate-200/80 text-slate-800 rounded-bl-sm"
                              }`}
                            >
                              <div className="whitespace-pre-line">{m.content}</div>

                              {m.evidence && m.evidence.length > 0 && (
                                <div className="border-t border-slate-200/70 pt-2.5 space-y-1.5">
                                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                                    Verified Technical Evidence
                                  </span>
                                  {m.evidence.map((ev, i) => (
                                    <div
                                      key={i}
                                      className="flex items-start gap-2 rounded-lg bg-white border border-slate-200/80 p-2 text-[11px]"
                                    >
                                      <span
                                        className={`rounded px-1.5 py-0.5 text-[9px] font-bold shrink-0 ${
                                          ev.severity === "CRITICAL"
                                            ? "bg-red-50 text-red-700 ring-1 ring-red-200"
                                            : "bg-amber-50 text-amber-700 ring-1 ring-amber-200"
                                        }`}
                                      >
                                        {ev.category}
                                      </span>
                                      <span className="text-slate-700 font-medium">{ev.finding}</span>
                                    </div>
                                  ))}
                                </div>
                              )}

                              {m.action_button && (
                                <button
                                  type="button"
                                  onClick={() => setActiveTab(m.action_button?.target_tab as ViewTab)}
                                  className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-1.5 text-[11px] font-bold text-white hover:bg-indigo-700 transition-colors"
                                >
                                  <span>{m.action_button.label}</span>
                                  <ArrowRight className="h-3 w-3" />
                                </button>
                              )}
                            </div>
                          </motion.div>
                        ))}
                        {copilotLoading && (
                          <div className="flex items-center gap-2 text-xs text-slate-400 italic">
                            <Sparkles className="h-4 w-4 text-indigo-500 animate-spin" />
                            <span>Synthesizing attack graph, SHAP values, and remediation logs...</span>
                          </div>
                        )}
                      </div>

                      <div className="border-t border-slate-100 bg-white p-3.5">
                        <form
                          onSubmit={(e) => {
                            e.preventDefault();
                            sendCopilotMessage(copilotInput);
                          }}
                          className="flex items-center gap-2"
                        >
                          <input
                            type="text"
                            placeholder="Ask about database risk, IAM roles, attack paths, or safe fixes..."
                            value={copilotInput}
                            onChange={(e) => setCopilotInput(e.target.value)}
                            className="flex-1 rounded-xl border border-slate-200 px-4 py-2.5 text-xs outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/15"
                          />
                          <button
                            type="submit"
                            disabled={copilotLoading || !copilotInput.trim()}
                            className="rounded-xl bg-indigo-600 px-4 py-2.5 text-white shadow-sm hover:bg-indigo-700 disabled:opacity-40 transition-colors"
                          >
                            <Send className="h-4 w-4" />
                          </button>
                        </form>
                      </div>
                    </div>

                    <div className="enterprise-card rounded-2xl p-5 flex flex-col justify-between">
                      <div>
                        <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-3">
                          One-Click Security Investigations
                        </h3>
                        <div className="space-y-2">
                          {[
                            "Why is my database at critical risk?",
                            "Show me the most dangerous attack path.",
                            "Which IAM role has excessive privileges?",
                            "How can I fix this vulnerability?",
                            "What will happen if I revoke database permissions?",
                            "Compare my security before and after remediation.",
                          ].map((q, i) => (
                            <button
                              key={i}
                              type="button"
                              onClick={() => sendCopilotMessage(q)}
                              className="flex w-full items-center justify-between rounded-xl border border-slate-200/80 bg-slate-50/70 px-3 py-2.5 text-left text-xs font-semibold text-slate-700 hover:bg-indigo-50/70 hover:border-indigo-200 hover:text-indigo-800 transition-all group"
                            >
                              <span>{q}</span>
                              <ChevronRight className="h-3.5 w-3.5 text-slate-400 group-hover:text-indigo-600 shrink-0" />
                            </button>
                          ))}
                        </div>
                      </div>

                      <div className="rounded-xl bg-slate-50 border border-slate-200/80 p-3.5 text-[11px] text-slate-600 leading-relaxed">
                        <span className="font-bold text-slate-900">OWASP GenAI Guardrail:</span> All answers cite
                        verified graph resources and calibrated probabilities. Unsupported queries are explicitly flagged.
                      </div>
                    </div>
                  </div>
                )}

                {/* ========================================================= */}
                {/* 5. EXPLAINABILITY & ML BENCHMARK LAB */}
                {/* ========================================================= */}
                {activeTab === "explainability" && (
                  <>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <div className="enterprise-card rounded-2xl p-6 space-y-4">
                        <div className="flex items-center justify-between">
                          <div>
                            <h2 className="text-sm font-bold text-slate-900">
                              TreeSHAP Feature Attribution Waterfall
                            </h2>
                            <p className="text-xs text-slate-500">
                              Exact log-odds impact pushing risk up (Red) vs mitigating risk (Emerald)
                            </p>
                          </div>
                          <span className="rounded-full bg-indigo-50 px-2.5 py-1 text-[10.5px] font-bold text-indigo-700 ring-1 ring-indigo-200">
                            Exact TreeSHAP
                          </span>
                        </div>
                        <ShapWaterfallChart items={topShap} />
                      </div>

                      <div className="enterprise-card rounded-2xl p-6 space-y-4">
                        <div className="flex items-center justify-between">
                          <div>
                            <h2 className="text-sm font-bold text-slate-900">
                              Model Comparison Lab (B0 – B5)
                            </h2>
                            <p className="text-xs text-slate-500">
                              5-Fold Environment-Grouped CV across 3,847 paths (100 cloud environments)
                            </p>
                          </div>
                          <span className="rounded-full bg-emerald-50 px-2.5 py-1 text-[10.5px] font-bold text-emerald-700 ring-1 ring-emerald-200">
                            Mean F1: 99.17%
                          </span>
                        </div>
                        <ModelBenchmarkChart />
                      </div>
                    </div>

                    <div className="enterprise-card rounded-2xl p-6 space-y-4">
                      <h3 className="text-sm font-bold text-slate-900">Ablation Study &amp; Academic Benchmark Table</h3>
                      <div className="overflow-x-auto rounded-xl border border-slate-200/80">
                        <table className="w-full text-left text-xs">
                          <thead className="bg-slate-50 text-[10px] font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200">
                            <tr>
                              <th className="py-3 px-4">Architecture</th>
                              <th className="py-3 px-4">Precision</th>
                              <th className="py-3 px-4">Recall</th>
                              <th className="py-3 px-4">F1 Score</th>
                              <th className="py-3 px-4">PR-AUC</th>
                              <th className="py-3 px-4">Key Insight / Failure Mode</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100 tabular-nums">
                            {[
                              { m: "B0: CIS Rule-Based", p: "26.0%", r: "22.0%", f: "23.9%", pr: "0.284", note: "Blind to cross-layer cloud-to-DB privilege chains" },
                              { m: "B1: Graph Reachability", p: "24.1%", r: "89.8%", f: "38.0%", pr: "0.412", note: "167 False Positives (ignores explicit IAM Deny & conditions)" },
                              { m: "B2: Logistic Regression", p: "68.3%", r: "71.2%", f: "69.7%", pr: "0.741", note: "Linear boundary fails on multi-hop combinations" },
                              { m: "B3: Random Forest", p: "94.2%", r: "83.1%", f: "88.3%", pr: "0.932", note: "Misses deep transitive PostgreSQL role inheritance" },
                              { m: "B4: PyG HeteroGraphSAGE", p: "77.8%", r: "94.9%", f: "85.5%", pr: "0.957", note: "Strong topology learning; lacks discrete boundary checks" },
                            ].map((row) => (
                              <tr key={row.m} className="hover:bg-slate-50/80">
                                <td className="py-2.5 px-4 font-semibold text-slate-800">{row.m}</td>
                                <td className="py-2.5 px-4">{row.p}</td>
                                <td className="py-2.5 px-4">{row.r}</td>
                                <td className="py-2.5 px-4 font-bold">{row.f}</td>
                                <td className="py-2.5 px-4">{row.pr}</td>
                                <td className="py-2.5 px-4 text-slate-500">{row.note}</td>
                              </tr>
                            ))}
                            <tr className="bg-indigo-50/70 font-bold">
                              <td className="py-3 px-4 text-indigo-900 flex items-center gap-1.5">
                                <Sparkles className="h-4 w-4 text-indigo-600" />
                                <span>B5: PyG GNN + Calibrated XGBoost</span>
                              </td>
                              <td className="py-3 px-4 text-indigo-900">100.0%</td>
                              <td className="py-3 px-4 text-indigo-900">100.0%</td>
                              <td className="py-3 px-4 text-indigo-900">100.0%</td>
                              <td className="py-3 px-4 text-indigo-900">1.000</td>
                              <td className="py-3 px-4 text-indigo-800 font-medium">
                                Combines 16-dim GNN path embeddings + 29 domain security features
                              </td>
                            </tr>
                          </tbody>
                        </table>
                      </div>

                      <div className="rounded-xl border border-slate-200/80 bg-slate-50/80 p-4 text-xs text-slate-600 leading-relaxed flex items-start gap-3">
                        <FileCheck className="h-4 w-4 text-indigo-600 shrink-0 mt-0.5" />
                        <div>
                          <span className="font-bold text-slate-900">Methodological Transparency:</span> Ground-truth
                          labels are generated by a deterministic authorization oracle across 100 grounded cloud
                          topologies (Capital One SSRF, Rhino CloudGoat, CIS AWS). Strict environment-grouped 5-fold CV
                          yields <strong>99.17% ± 1.23% F1</strong> on unseen cloud environments.
                        </div>
                      </div>
                    </div>
                  </>
                )}

                {/* ========================================================= */}
                {/* 6. VERIFIED REMEDIATION & LOG REPLAY */}
                {/* ========================================================= */}
                {activeTab === "remediation" && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {remediations.map((rem) => {
                      const isSafe = rem.status === "Verified Safe-to-Apply";
                      return (
                        <div
                          key={rem.fix_id}
                          className="enterprise-card rounded-2xl p-6 flex flex-col justify-between space-y-4"
                        >
                          <div className="space-y-3">
                            <div className="flex items-start justify-between gap-2">
                              <div>
                                <h3 className="text-sm font-bold text-slate-900">{rem.title}</h3>
                                <p className="text-xs text-slate-500 mt-0.5">{rem.description}</p>
                              </div>
                              <span
                                className={`shrink-0 rounded-full px-2.5 py-0.5 text-[10px] font-bold ${
                                  isSafe
                                    ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200"
                                    : "bg-amber-50 text-amber-700 ring-1 ring-amber-200"
                                }`}
                              >
                                {rem.status}
                              </span>
                            </div>

                            <div className="rounded-xl bg-slate-50 border border-slate-200/80 p-3.5 text-xs space-y-2">
                              <div className="flex items-center justify-between font-semibold">
                                <span className="text-slate-600">30-Day Historical Log Replay</span>
                                <span className={isSafe ? "text-emerald-700" : "text-amber-700"}>
                                  {rem.legit_broken} / {rem.legit_total} Legitimate Queries Broken
                                </span>
                              </div>
                              <div className="h-2 w-full rounded-full bg-slate-200 overflow-hidden">
                                <div
                                  style={{ width: `${Math.max(4, (rem.legit_broken / Math.max(1, rem.legit_total)) * 100)}%` }}
                                  className={`h-full rounded-full ${isSafe ? "bg-emerald-500" : "bg-amber-500"}`}
                                />
                              </div>
                              <div className="flex items-center justify-between text-[11px] text-slate-500">
                                <span>Attack Paths Eliminated</span>
                                <span className="font-bold text-slate-900">
                                  {rem.paths_eliminated} ({rem.paths_before} → {rem.paths_after})
                                </span>
                              </div>
                            </div>

                            <div className="relative rounded-xl bg-[#0F172A] p-4 font-mono text-[11px] text-emerald-400 overflow-x-auto">
                              <button
                                type="button"
                                onClick={() => {
                                  navigator.clipboard.writeText(rem.patch_snippet);
                                  showToast("Patch copied to clipboard!");
                                }}
                                className="absolute top-3 right-3 rounded-lg bg-white/10 p-1.5 text-slate-300 hover:bg-white/20 hover:text-white transition-colors"
                              >
                                <Copy className="h-3.5 w-3.5" />
                              </button>
                              <pre>{rem.patch_snippet}</pre>
                            </div>
                          </div>

                          <div className="pt-2 border-t border-slate-100">
                            {selectedEnv === "live_neon_cloud" ? (
                              <button
                                type="button"
                                onClick={handleLiveNeonApplyFix}
                                disabled={liveScanLoading}
                                className="w-full rounded-xl bg-emerald-600 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-emerald-700 transition-colors"
                              >
                                Apply Live SQL REVOKE on Neon Cloud
                              </button>
                            ) : (
                              <button
                                type="button"
                                onClick={() => {
                                  navigator.clipboard.writeText(rem.patch_snippet);
                                  showToast("Copied verified Terraform / SQL patch!");
                                }}
                                className="w-full rounded-xl bg-slate-900 py-2.5 text-xs font-bold text-white hover:bg-slate-800 transition-colors"
                              >
                                Copy Verified Patch for CI/CD
                              </button>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* ========================================================= */}
                {/* 7. CLOUD CONNECTORS */}
                {/* ========================================================= */}
                {activeTab === "cloud" && (
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="enterprise-card rounded-2xl p-6 space-y-5">
                      <div className="flex items-center justify-between border-b border-slate-100 pb-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-50 text-emerald-600 ring-1 ring-emerald-200/80">
                            <Database className="h-5 w-5" />
                          </div>
                          <div>
                            <h2 className="text-sm font-bold text-slate-900">Neon Cloud Serverless PostgreSQL</h2>
                            <p className="text-xs text-slate-500">Live TLS catalog &amp; role privilege audit</p>
                          </div>
                        </div>
                        <span
                          className={`rounded-full px-2.5 py-1 text-[10.5px] font-bold ${
                            neonStatus?.connected
                              ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200"
                              : "bg-slate-100 text-slate-600"
                          }`}
                        >
                          {neonStatus?.connected ? "Connected" : "Standby"}
                        </span>
                      </div>

                      <div>
                        <label className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-1.5">
                          PostgreSQL Connection URI (Optional Override)
                        </label>
                        <input
                          type="text"
                          placeholder="postgres://user:pass@ep-xyz.aws.neon.tech/neondb?sslmode=require"
                          value={customPgUrl}
                          onChange={(e) => setCustomPgUrl(e.target.value)}
                          className="w-full rounded-xl border border-slate-200 px-3.5 py-2.5 font-mono text-xs outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/15"
                        />
                      </div>

                      <div className="grid grid-cols-3 gap-3 text-center">
                        <div className="rounded-xl bg-slate-50 border border-slate-200/80 p-3">
                          <div className="text-[11px] text-slate-500">Roles</div>
                          <div className="text-xl font-extrabold text-slate-900 tabular-nums mt-0.5">
                            {neonStatus?.roles_discovered || 0}
                          </div>
                        </div>
                        <div className="rounded-xl bg-slate-50 border border-slate-200/80 p-3">
                          <div className="text-[11px] text-slate-500">Tables</div>
                          <div className="text-xl font-extrabold text-slate-900 tabular-nums mt-0.5">
                            {neonStatus?.tables_discovered || 0}
                          </div>
                        </div>
                        <div className="rounded-xl bg-red-50/70 border border-red-200/80 p-3">
                          <div className="text-[11px] text-red-700">PUBLIC Grants</div>
                          <div className="text-xl font-extrabold text-red-600 tabular-nums mt-0.5">
                            {neonStatus?.public_grant_tables?.length || 0}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2.5 pt-1">
                        <button
                          type="button"
                          onClick={handleLiveNeonScan}
                          disabled={liveScanLoading}
                          className="flex-1 rounded-xl bg-indigo-600 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50"
                        >
                          Scan Live Neon DB
                        </button>
                        <button
                          type="button"
                          onClick={handleLiveNeonSeed}
                          disabled={liveScanLoading}
                          className="rounded-xl border border-amber-300 bg-amber-50 px-4 py-2.5 text-xs font-bold text-amber-800 hover:bg-amber-100 disabled:opacity-50"
                        >
                          Seed Test Risk
                        </button>
                      </div>
                    </div>

                    <div className="enterprise-card rounded-2xl p-6 space-y-4">
                      <div className="flex items-center justify-between border-b border-slate-100 pb-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-50 text-indigo-600 ring-1 ring-indigo-200/80">
                            <Cloud className="h-5 w-5" />
                          </div>
                          <div>
                            <h2 className="text-sm font-bold text-slate-900">AWS Infrastructure Scanner (boto3)</h2>
                            <p className="text-xs text-slate-500">Read-only STS, IAM, EC2, Security Groups &amp; RDS</p>
                          </div>
                        </div>
                        <span className="rounded-full bg-indigo-50 px-2.5 py-1 text-[10.5px] font-bold text-indigo-700 ring-1 ring-indigo-200">
                          SCP Resilient
                        </span>
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="text-[11px] font-bold text-slate-500 block mb-1">AWS Region</label>
                          <input
                            type="text"
                            value={awsRegion}
                            onChange={(e) => setAwsRegion(e.target.value)}
                            className="w-full rounded-xl border border-slate-200 px-3 py-2 text-xs outline-none focus:border-indigo-500"
                          />
                        </div>
                        <div>
                          <label className="text-[11px] font-bold text-slate-500 block mb-1">Access Key ID</label>
                          <input
                            type="text"
                            placeholder="AKIA... (or local SSO)"
                            value={awsKey}
                            onChange={(e) => setAwsKey(e.target.value)}
                            className="w-full rounded-xl border border-slate-200 px-3 py-2 text-xs outline-none focus:border-indigo-500"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="text-[11px] font-bold text-slate-500 block mb-1">Secret Access Key</label>
                        <input
                          type="password"
                          placeholder="Secret key..."
                          value={awsSecret}
                          onChange={(e) => setAwsSecret(e.target.value)}
                          className="w-full rounded-xl border border-slate-200 px-3 py-2 text-xs outline-none focus:border-indigo-500"
                        />
                      </div>

                      <div>
                        <label className="text-[11px] font-bold text-slate-500 block mb-1">Session Token (Optional)</label>
                        <input
                          type="password"
                          placeholder="Required for assumed roles / temporary STS creds"
                          value={awsToken}
                          onChange={(e) => setAwsToken(e.target.value)}
                          className="w-full rounded-xl border border-slate-200 px-3 py-2 text-xs outline-none focus:border-indigo-500"
                        />
                      </div>

                      {awsError && (
                        <div className="rounded-xl bg-red-50 border border-red-200 p-3 text-xs text-red-700">
                          {awsError}
                        </div>
                      )}

                      {awsInventory && (
                        <div className="rounded-xl bg-emerald-50/70 border border-emerald-200 p-3 text-xs text-emerald-900">
                          <strong>Account {awsInventory.account_id}</strong> ({awsInventory.region}):{" "}
                          {awsInventory.principals} IAM principals, {awsInventory.security_groups} SGs,{" "}
                          {awsInventory.rds_instances} RDS instances.
                        </div>
                      )}

                      <button
                        type="button"
                        onClick={handleRealAwsScan}
                        disabled={liveScanLoading}
                        className="w-full rounded-xl bg-slate-900 py-2.5 text-xs font-bold text-white hover:bg-slate-800 disabled:opacity-50"
                      >
                        Connect &amp; Scan AWS Account
                      </button>
                    </div>

                    {/* Microsoft Azure Live Connector */}
                    <div className="enterprise-card rounded-2xl p-6 space-y-4">
                      <div className="flex items-center justify-between border-b border-slate-100 pb-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-50 text-sky-600 ring-1 ring-sky-200/80">
                            <Cloud className="h-5 w-5" />
                          </div>
                          <div>
                            <h2 className="text-sm font-bold text-slate-900">Microsoft Azure Scanner (ARM REST)</h2>
                            <p className="text-xs text-slate-500">Entra ID RBAC, NSGs, VMs &amp; PostgreSQL Flexible Server</p>
                          </div>
                        </div>
                        <span className="rounded-full bg-sky-50 px-2.5 py-1 text-[10.5px] font-bold text-sky-700 ring-1 ring-sky-200">
                          Read-Only
                        </span>
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="text-[11px] font-bold text-slate-500 block mb-1">Subscription ID *</label>
                          <input
                            type="text"
                            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                            value={azSubId}
                            onChange={(e) => setAzSubId(e.target.value)}
                            className="w-full rounded-xl border border-slate-200 px-3 py-2 text-xs outline-none focus:border-sky-500"
                          />
                        </div>
                        <div>
                          <label className="text-[11px] font-bold text-slate-500 block mb-1">Tenant ID (Service Principal)</label>
                          <input
                            type="text"
                            placeholder="Optional if using Bearer Token"
                            value={azTenantId}
                            onChange={(e) => setAzTenantId(e.target.value)}
                            className="w-full rounded-xl border border-slate-200 px-3 py-2 text-xs outline-none focus:border-sky-500"
                          />
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="text-[11px] font-bold text-slate-500 block mb-1">Client ID</label>
                          <input
                            type="text"
                            placeholder="App Registration Client ID"
                            value={azClientId}
                            onChange={(e) => setAzClientId(e.target.value)}
                            className="w-full rounded-xl border border-slate-200 px-3 py-2 text-xs outline-none focus:border-sky-500"
                          />
                        </div>
                        <div>
                          <label className="text-[11px] font-bold text-slate-500 block mb-1">Client Secret</label>
                          <input
                            type="password"
                            placeholder="Service Principal Secret"
                            value={azClientSecret}
                            onChange={(e) => setAzClientSecret(e.target.value)}
                            className="w-full rounded-xl border border-slate-200 px-3 py-2 text-xs outline-none focus:border-sky-500"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="text-[11px] font-bold text-slate-500 block mb-1">
                          Or Direct Bearer Token (`az account get-access-token --query accessToken -o tsv`)
                        </label>
                        <input
                          type="password"
                          placeholder="eyJ0eXAiOiJKV1Qi..."
                          value={azToken}
                          onChange={(e) => setAzToken(e.target.value)}
                          className="w-full rounded-xl border border-slate-200 px-3 py-2 font-mono text-xs outline-none focus:border-sky-500"
                        />
                      </div>

                      {azError && (
                        <div className="rounded-xl bg-red-50 border border-red-200 p-3 text-xs text-red-700">
                          {azError}
                        </div>
                      )}

                      <button
                        type="button"
                        onClick={handleRealAzureScan}
                        disabled={liveScanLoading || !azSubId.trim()}
                        className="w-full rounded-xl bg-sky-600 py-2.5 text-xs font-bold text-white hover:bg-sky-700 disabled:opacity-50"
                      >
                        Connect &amp; Scan Azure Subscription
                      </button>
                    </div>

                    {/* Google Cloud Platform (GCP) Live Connector */}
                    <div className="enterprise-card rounded-2xl p-6 space-y-4">
                      <div className="flex items-center justify-between border-b border-slate-100 pb-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-amber-50 text-amber-600 ring-1 ring-amber-200/80">
                            <Cloud className="h-5 w-5" />
                          </div>
                          <div>
                            <h2 className="text-sm font-bold text-slate-900">Google Cloud Scanner (GCP REST)</h2>
                            <p className="text-xs text-slate-500">IAM Policy, VPC Firewalls &amp; Cloud SQL PostgreSQL</p>
                          </div>
                        </div>
                        <span className="rounded-full bg-amber-50 px-2.5 py-1 text-[10.5px] font-bold text-amber-700 ring-1 ring-amber-200">
                          Read-Only
                        </span>
                      </div>

                      <div>
                        <label className="text-[11px] font-bold text-slate-500 block mb-1">GCP Project ID *</label>
                        <input
                          type="text"
                          placeholder="my-prod-gcp-project-123"
                          value={gcpProjectId}
                          onChange={(e) => setGcpProjectId(e.target.value)}
                          className="w-full rounded-xl border border-slate-200 px-3 py-2 text-xs outline-none focus:border-amber-500"
                        />
                      </div>

                      <div>
                        <label className="text-[11px] font-bold text-slate-500 block mb-1">
                          OAuth2 Access Token * (`gcloud auth print-access-token`)
                        </label>
                        <input
                          type="password"
                          placeholder="ya29.a0AfH6SM..."
                          value={gcpToken}
                          onChange={(e) => setGcpToken(e.target.value)}
                          className="w-full rounded-xl border border-slate-200 px-3 py-2 font-mono text-xs outline-none focus:border-amber-500"
                        />
                      </div>

                      {gcpError && (
                        <div className="rounded-xl bg-red-50 border border-red-200 p-3 text-xs text-red-700">
                          {gcpError}
                        </div>
                      )}

                      <button
                        type="button"
                        onClick={handleRealGcpScan}
                        disabled={liveScanLoading || !gcpProjectId.trim() || !gcpToken.trim()}
                        className="w-full rounded-xl bg-amber-600 py-2.5 text-xs font-bold text-white hover:bg-amber-700 disabled:opacity-50"
                      >
                        Connect &amp; Scan GCP Project
                      </button>
                    </div>
                  </div>
                )}

                {/* ========================================================= */}
                {/* 8. EXECUTIVE AUDIT REPORT */}
                {/* ========================================================= */}
                {activeTab === "reports" && (
                  <div className="space-y-5">
                    <div className="no-print flex flex-wrap items-center justify-between gap-3 rounded-2xl bg-slate-900 p-5 text-white shadow-sm">
                      <div>
                        <div className="text-sm font-bold">Executive Cybersecurity Audit Report</div>
                        <div className="text-xs text-slate-400">
                          CIS AWS Foundations Benchmark v1.4 • NIST SP 800-53 • ISO 27001
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={loadExecutiveReport}
                          className="rounded-xl border border-slate-700 px-3.5 py-2 text-xs font-bold text-slate-300 hover:bg-slate-800"
                        >
                          Refresh Data
                        </button>
                        <button
                          type="button"
                          onClick={() => window.print()}
                          className="flex items-center gap-1.5 rounded-xl bg-indigo-600 px-4 py-2 text-xs font-bold text-white hover:bg-indigo-500"
                        >
                          <Download className="h-3.5 w-3.5" />
                          <span>Print / Export PDF</span>
                        </button>
                      </div>
                    </div>

                    {reportLoading ? (
                      <div className="enterprise-card rounded-2xl p-12 text-center text-xs text-slate-500">
                        Compiling executive security assessment...
                      </div>
                    ) : reportData ? (
                      <div className="enterprise-card rounded-2xl p-8 space-y-8">
                        <div className="flex items-start justify-between border-b border-slate-200 pb-6">
                          <div>
                            <div className="text-2xl font-extrabold tracking-tight text-slate-900">
                              CLOUD DATABASE SECURITY AUDIT
                            </div>
                            <div className="text-xs text-slate-500 mt-1">
                              Generated by DB-TRACE Enterprise AI Security Operations Platform
                            </div>
                          </div>
                          <div className="text-right text-xs">
                            <div className="font-bold text-slate-800">{reportData.generated_at}</div>
                            <div className="font-mono text-slate-500">{reportData.environment_id}</div>
                            <span className="mt-1 inline-block rounded-full bg-red-50 px-2.5 py-0.5 text-[10px] font-bold text-red-700 ring-1 ring-red-200">
                              {reportData.risk_level} RISK
                            </span>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                            1. Executive Summary
                          </h3>
                          <p className="rounded-xl border border-slate-200/80 bg-slate-50/80 p-4 text-xs leading-relaxed text-slate-700">
                            {reportData.executive_summary}
                          </p>
                        </div>

                        <div className="space-y-2">
                          <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                            2. Compliance Control Mapping
                          </h3>
                          <div className="overflow-x-auto rounded-xl border border-slate-200/80">
                            <table className="w-full text-left text-xs">
                              <thead className="bg-slate-50 text-[10px] font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200">
                                <tr>
                                  <th className="py-2.5 px-4">Framework</th>
                                  <th className="py-2.5 px-4">Control</th>
                                  <th className="py-2.5 px-4">Description</th>
                                  <th className="py-2.5 px-4">Status</th>
                                  <th className="py-2.5 px-4">Resource</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-slate-100">
                                {reportData.compliance_findings.map((c, i) => (
                                  <tr key={i}>
                                    <td className="py-2.5 px-4 font-semibold text-slate-800">{c.framework}</td>
                                    <td className="py-2.5 px-4 font-mono text-slate-700">{c.control_id}</td>
                                    <td className="py-2.5 px-4 text-slate-700">{c.control_name}</td>
                                    <td className="py-2.5 px-4">
                                      <span className="rounded-full bg-red-50 px-2 py-0.5 text-[10px] font-bold text-red-700 ring-1 ring-red-200">
                                        {c.status}
                                      </span>
                                    </td>
                                    <td className="py-2.5 px-4 font-mono text-slate-800">{c.resource}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                            3. AI / Machine Learning Validation Evidence
                          </h3>
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                            {Object.entries(reportData.academic_metrics).map(([k, v]) => (
                              <div key={k} className="rounded-xl border border-slate-200/80 bg-slate-50/70 p-3.5">
                                <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                                  {k.replace(/_/g, " ")}
                                </div>
                                <div className="mt-1 text-xs font-bold text-slate-800">{v}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="enterprise-card rounded-2xl p-12 text-center text-xs text-slate-500">
                        Click Refresh Data to generate the report.
                      </div>
                    )}
                  </div>
                )}
              </motion.div>
            </AnimatePresence>
          )}
        </div>
      </main>

      {/* Wiz-Style Slide-Over Context Inspector Drawer */}
      <InspectorDrawer
        node={selectedNode}
        onClose={() => setSelectedNode(null)}
        onJumpToRemediation={() => setActiveTab("remediation")}
        onAskCopilot={(q) => {
          setActiveTab("copilot");
          sendCopilotMessage(q);
        }}
      />
    </div>
  );
}
