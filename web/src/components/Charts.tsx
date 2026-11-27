"use client";

import { motion } from "framer-motion";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { LucideIcon } from "lucide-react";

/* ============================================================================
 * 1. Animated KPI Card with Recharts Sparkline
 * ==========================================================================*/
interface SparklineKpiCardProps {
  title: string;
  value: string | number;
  subtitle: string;
  delta?: string;
  deltaType?: "danger" | "success" | "neutral" | "info";
  icon: LucideIcon;
  accentColor: string;
  sparkData: number[];
  onClick?: () => void;
  delay?: number;
}

export function SparklineKpiCard({
  title,
  value,
  subtitle,
  delta,
  deltaType = "neutral",
  icon: Icon,
  accentColor,
  sparkData,
  onClick,
  delay = 0,
}: SparklineKpiCardProps) {
  const chartData = sparkData.map((v, idx) => ({ idx, v }));
  const deltaStyle =
    deltaType === "danger"
      ? "bg-red-50 text-red-700 ring-1 ring-red-200/80"
      : deltaType === "success"
      ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200/80"
      : deltaType === "info"
      ? "bg-indigo-50 text-indigo-700 ring-1 ring-indigo-200/80"
      : "bg-slate-100 text-slate-600";

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay, ease: "easeOut" }}
      onClick={onClick}
      className={`enterprise-card rounded-2xl p-4 flex flex-col justify-between ${
        onClick ? "cursor-pointer" : ""
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
          {title}
        </span>
        <div
          className="flex h-7 w-7 items-center justify-center rounded-lg"
          style={{ backgroundColor: `${accentColor}15`, color: accentColor }}
        >
          <Icon className="h-3.5 w-3.5" />
        </div>
      </div>

      <div className="mt-2 flex items-end justify-between gap-2">
        <div>
          <div className="text-2xl font-extrabold tracking-tight text-slate-900 tabular-nums">
            {value}
          </div>
          <div className="mt-1 flex items-center gap-1.5">
            {delta && (
              <span className={`rounded-full px-1.5 py-0.5 text-[10px] font-bold ${deltaStyle}`}>
                {delta}
              </span>
            )}
            <span className="text-[11px] text-slate-500 truncate">{subtitle}</span>
          </div>
        </div>

        <div className="h-10 w-20 shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id={`spark-${title.replace(/\s+/g, "")}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={accentColor} stopOpacity={0.32} />
                  <stop offset="95%" stopColor={accentColor} stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <Area
                type="monotone"
                dataKey="v"
                stroke={accentColor}
                strokeWidth={2}
                fill={`url(#spark-${title.replace(/\s+/g, "")})`}
                isAnimationActive={true}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </motion.div>
  );
}

/* ============================================================================
 * 2. Smooth Spring-Animated Radial Security Posture Gauge
 * ==========================================================================*/
interface PostureRadialGaugeProps {
  score: number; // 0 to 100
  label: string;
  invertRisk?: boolean; // if true, high score = red (Risk Score); if false, high score = green (Posture)
}

export function PostureRadialGauge({ score, label, invertRisk = false }: PostureRadialGaugeProps) {
  const clamped = Math.max(0, Math.min(100, score));
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (clamped / 100) * circumference;

  const isCritical = invertRisk ? clamped >= 65 : clamped <= 35;
  const isWarning = invertRisk ? clamped >= 30 && clamped < 65 : clamped > 35 && clamped < 75;
  const strokeColor = isCritical ? "#EF4444" : isWarning ? "#F59E0B" : "#10B981";
  const badgeBg = isCritical
    ? "bg-red-50 text-red-700 ring-1 ring-red-200"
    : isWarning
    ? "bg-amber-50 text-amber-700 ring-1 ring-amber-200"
    : "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200";

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative h-36 w-36">
        <svg className="h-full w-full -rotate-90" viewBox="0 0 128 128">
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            stroke="#F1F5F9"
            strokeWidth="10"
          />
          <motion.circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            stroke={strokeColor}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-extrabold tracking-tight text-slate-900 tabular-nums">
            {Math.round(clamped)}
          </span>
          <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
            / 100
          </span>
        </div>
      </div>
      <span className={`mt-2 rounded-full px-3 py-0.5 text-[11px] font-bold ${badgeBg}`}>
        {label}
      </span>
    </div>
  );
}

/* ============================================================================
 * 3. 30-Day Security Risk & Attack Surface Trend AreaChart
 * ==========================================================================*/
const TREND_DATA = [
  { day: "Day 1", exposure: 72, mitigated: 18 },
  { day: "Day 5", exposure: 78, mitigated: 22 },
  { day: "Day 10", exposure: 85, mitigated: 25 },
  { day: "Day 15", exposure: 91, mitigated: 32 },
  { day: "Day 20", exposure: 88, mitigated: 45 },
  { day: "Day 25", exposure: 96, mitigated: 58 },
  { day: "Today", exposure: 100, mitigated: 64 },
];

export function RiskTrendAreaChart({ currentRisk }: { currentRisk: number }) {
  const data = TREND_DATA.map((d, i) =>
    i === TREND_DATA.length - 1 ? { ...d, exposure: Math.round(currentRisk) } : d
  );
  return (
    <div className="h-[220px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
          <defs>
            <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#EF4444" stopOpacity={0.25} />
              <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
            </linearGradient>
            <linearGradient id="mitGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#4F46E5" stopOpacity={0.22} />
              <stop offset="95%" stopColor="#4F46E5" stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" vertical={false} />
          <XAxis dataKey="day" tick={{ fontSize: 11, fill: "#64748B" }} axisLine={false} tickLine={false} />
          <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "#64748B" }} axisLine={false} tickLine={false} />
          <Tooltip
            contentStyle={{
              backgroundColor: "#ffffff",
              borderRadius: "12px",
              border: "1px solid #E2E8F0",
              boxShadow: "0 10px 25px -5px rgba(15,23,42,0.1)",
              fontSize: "12px",
            }}
          />
          <Legend wrapperStyle={{ fontSize: "11px", paddingTop: "8px" }} />
          <Area
            type="monotone"
            dataKey="exposure"
            name="Attack Path Risk Score (%)"
            stroke="#EF4444"
            strokeWidth={2.5}
            fill="url(#riskGrad)"
          />
          <Area
            type="monotone"
            dataKey="mitigated"
            name="Verified Controls Coverage (%)"
            stroke="#4F46E5"
            strokeWidth={2}
            fill="url(#mitGrad)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

/* ============================================================================
 * 4. Interactive SHAP Diverging Bar Chart
 * ==========================================================================*/
interface ShapItem {
  feature: string;
  label?: string;
  shap_value: number;
}

export function ShapWaterfallChart({ items }: { items: ShapItem[] }) {
  const data = items.map((f) => ({
    name: (f.label || f.feature).slice(0, 38),
    fullName: f.label || f.feature,
    value: Number(f.shap_value.toFixed(4)),
  }));

  if (data.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center rounded-xl border border-dashed border-slate-200 text-xs text-slate-400">
        Select an attack path to inspect its TreeSHAP attribution chart.
      </div>
    );
  }

  return (
    <div className="h-[280px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 6, right: 28, left: 20, bottom: 6 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" horizontal={false} />
          <XAxis type="number" tick={{ fontSize: 11, fill: "#64748B" }} axisLine={false} tickLine={false} />
          <YAxis
            type="category"
            dataKey="name"
            width={210}
            tick={{ fontSize: 11, fill: "#334155", fontWeight: 500 }}
            axisLine={false}
            tickLine={false}
          />
          <ReferenceLine x={0} stroke="#94A3B8" strokeWidth={1.5} />
          <Tooltip
            cursor={{ fill: "#F8FAFC" }}
            contentStyle={{
              backgroundColor: "#ffffff",
              borderRadius: "10px",
              border: "1px solid #E2E8F0",
              fontSize: "12px",
            }}
            formatter={(val: unknown) => [
              `${Number(val) > 0 ? "+" : ""}${Number(val).toFixed(4)} log-odds`,
              "SHAP Impact",
            ]}
          />
          <Bar dataKey="value" radius={[4, 4, 4, 4]} barSize={20}>
            {data.map((entry, idx) => (
              <Cell key={idx} fill={entry.value >= 0 ? "#EF4444" : "#10B981"} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/* ============================================================================
 * 5. 6-Model Benchmark Grouped Bar Chart
 * ==========================================================================*/
const BENCHMARK_DATA = [
  { model: "B0: CIS Rules", Precision: 26.0, Recall: 22.0, F1: 23.9 },
  { model: "B1: Graph Only", Precision: 24.1, Recall: 89.8, F1: 38.0 },
  { model: "B2: LogReg", Precision: 68.3, Recall: 71.2, F1: 69.7 },
  { model: "B3: Random Forest", Precision: 94.2, Recall: 83.1, F1: 88.3 },
  { model: "B4: PyG GNN", Precision: 77.8, Recall: 94.9, F1: 85.5 },
  { model: "B5: GNN+XGBoost", Precision: 100.0, Recall: 100.0, F1: 100.0 },
];

export function ModelBenchmarkChart() {
  return (
    <div className="h-[290px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={BENCHMARK_DATA} margin={{ top: 10, right: 16, left: -12, bottom: 4 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" vertical={false} />
          <XAxis dataKey="model" tick={{ fontSize: 11, fill: "#475569", fontWeight: 600 }} axisLine={false} tickLine={false} />
          <YAxis domain={[0, 100]} unit="%" tick={{ fontSize: 11, fill: "#64748B" }} axisLine={false} tickLine={false} />
          <Tooltip
            cursor={{ fill: "#F1F5F9" }}
            contentStyle={{
              backgroundColor: "#ffffff",
              borderRadius: "12px",
              border: "1px solid #E2E8F0",
              fontSize: "12px",
            }}
          />
          <Legend wrapperStyle={{ fontSize: "11px", paddingTop: "8px" }} />
          <Bar dataKey="Precision" fill="#6366F1" radius={[5, 5, 0, 0]} barSize={16} />
          <Bar dataKey="Recall" fill="#0EA5E9" radius={[5, 5, 0, 0]} barSize={16} />
          <Bar dataKey="F1" fill="#10B981" radius={[5, 5, 0, 0]} barSize={16} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/* ============================================================================
 * 6. Stripe/Apple-style Spring Toggle Switch for What-If Playground
 * ==========================================================================*/
interface AnimatedToggleSwitchProps {
  checked: boolean;
  onChange: () => void;
  activeColor?: string;
}

export function AnimatedToggleSwitch({
  checked,
  onChange,
  activeColor = "bg-emerald-600",
}: AnimatedToggleSwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={onChange}
      className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full p-0.5 transition-colors duration-200 ${
        checked ? activeColor : "bg-red-500"
      }`}
    >
      <motion.span
        layout
        transition={{ type: "spring", stiffness: 520, damping: 32 }}
        className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow-md ${
          checked ? "ml-auto" : "mr-auto"
        }`}
      />
    </button>
  );
}
