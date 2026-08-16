import React from "react";
import { useSoc, SocNavTab } from "../../context/SocContext.js";
import {
  LayoutDashboard,
  ShieldAlert,
  FileCode2,
  SearchCode,
  Fingerprint,
  Layers,
  MailWarning,
  Bot,
  FileText,
  Settings,
  ShieldCheck,
  Zap,
  Activity,
  Terminal,
} from "lucide-react";
import { SAMPLE_SCENARIOS } from "../../data/sampleLogs.js";

interface NavItem {
  id: SocNavTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: number | string;
  badgeColor?: string;
}

export const Sidebar: React.FC = () => {
  const {
    activeTab,
    setActiveTab,
    alerts,
    iocs,
    incidentReports,
    activeScenarioId,
    loadScenario,
    backendHealth,
  } = useSoc();

  const criticalAlertsCount = alerts.filter((a) => a.severity === "CRITICAL").length;

  const navItems: NavItem[] = [
    { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
    {
      id: "alerts",
      label: "Alerts Queue",
      icon: ShieldAlert,
      badge: alerts.length > 0 ? alerts.length : undefined,
      badgeColor: criticalAlertsCount > 0 ? "bg-red-500 text-white animate-pulse" : "bg-slate-800 text-slate-300",
    },
    { id: "log-analyzer", label: "Log Analyzer", icon: FileCode2 },
    {
      id: "investigations",
      label: "Investigations",
      icon: SearchCode,
      badge: alerts.filter((a) => a.status === "INVESTIGATING" || a.status === "NEW").length || undefined,
      badgeColor: "bg-cyan-950 text-cyan-300 border border-cyan-700/60",
    },
    {
      id: "ioc-extractor",
      label: "IOC Extractor",
      icon: Fingerprint,
      badge: iocs.length > 0 ? iocs.length : undefined,
      badgeColor: "bg-purple-950 text-purple-300 border border-purple-700/60",
    },
    { id: "mitre-attack", label: "MITRE ATT&CK", icon: Layers },
    { id: "phishing-analyzer", label: "Phishing Analyzer", icon: MailWarning },
    {
      id: "ai-analyst",
      label: "AI SOC Analyst",
      icon: Bot,
      badge: "Gemini 3.7",
      badgeColor: "bg-indigo-950 text-indigo-300 border border-indigo-700/60 text-[10px]",
    },
    {
      id: "incident-reports",
      label: "Incident Reports",
      icon: FileText,
      badge: incidentReports.length > 0 ? incidentReports.length : undefined,
      badgeColor: "bg-emerald-950 text-emerald-300 border border-emerald-700/60",
    },
    { id: "settings", label: "Settings", icon: Settings },
  ];

  return (
    <aside className="w-64 h-screen bg-slate-950 border-r border-slate-800/80 flex flex-col justify-between shrink-0 select-none z-20">
      {/* Brand Header */}
      <div className="p-4 border-b border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 text-white font-mono font-black text-lg">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-extrabold text-sm tracking-wide text-white font-mono">AI-SOC</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-300 font-mono font-bold">
                INVESTIGATOR
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-medium leading-tight">
              AI-assisted security monitoring & incident response
            </p>
          </div>
        </div>
      </div>

      {/* Navigation List */}
      <div className="flex-1 overflow-y-auto py-3 px-2 space-y-1 custom-scrollbar">
        <div className="px-3 py-1 text-[11px] font-mono font-bold uppercase tracking-wider text-slate-500">
          Core Operations
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;

          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all group ${
                isActive
                  ? "bg-gradient-to-r from-cyan-950/80 to-slate-900 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-950 font-semibold"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon
                  className={`w-4 h-4 transition-colors ${
                    isActive ? "text-cyan-400" : "text-slate-500 group-hover:text-slate-300"
                  }`}
                />
                <span>{item.label}</span>
              </div>

              {item.badge !== undefined && (
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                    item.badgeColor || "bg-slate-800 text-slate-300"
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Scenario Preset Selector & Telemetry Footer */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950/90 space-y-2.5">
        {/* Sample Scenario Preset */}
        <div className="space-y-1">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span className="flex items-center gap-1">
              <Terminal className="w-3 h-3 text-cyan-400" />
              Active Dataset:
            </span>
            <span className="text-[10px] text-cyan-400">Synthetic</span>
          </div>
          <select
            value={activeScenarioId}
            onChange={(e) => loadScenario(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700/80 rounded-md px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-sans"
          >
            {SAMPLE_SCENARIOS.map((sc) => (
              <option key={sc.id} value={sc.id} className="bg-slate-950 text-slate-200">
                {sc.name.length > 26 ? sc.name.substring(0, 24) + "..." : sc.name}
              </option>
            ))}
          </select>
        </div>

        {/* Backend & AI Status Indicator */}
        <div className="p-2 rounded-lg bg-slate-900/80 border border-slate-800/80 flex items-center justify-between text-[11px] font-mono">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-slate-300">Detection Engine</span>
          </div>
          <div className="flex items-center gap-1 text-[10px] text-purple-400 bg-purple-950/60 px-1.5 py-0.5 rounded border border-purple-800/50">
            <Zap className="w-2.5 h-2.5 text-purple-400" />
            Gemini AI
          </div>
        </div>
      </div>
    </aside>
  );
};
