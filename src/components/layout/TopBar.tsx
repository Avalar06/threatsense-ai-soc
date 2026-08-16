import React, { useState, useEffect } from "react";
import { useSoc } from "../../context/SocContext.js";
import {
  Clock,
  Radio,
  Search,
  UploadCloud,
  Bot,
  RefreshCw,
  Server,
  ShieldAlert,
} from "lucide-react";
import { SAMPLE_SCENARIOS } from "../../data/sampleLogs.js";

export const TopBar: React.FC = () => {
  const {
    events,
    alerts,
    activeTab,
    setActiveTab,
    loadScenario,
    activeScenarioId,
    backendHealth,
  } = useSoc();

  const [utcTime, setUtcTime] = useState<string>("");

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toISOString().replace("T", " ").replace("Z", " UTC"));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const criticalCount = alerts.filter((a) => a.severity === "CRITICAL").length;

  return (
    <header className="h-14 bg-slate-950/95 border-b border-slate-800/80 px-6 flex items-center justify-between z-10 select-none">
      {/* Left Telemetry Status */}
      <div className="flex items-center gap-4 text-xs font-mono">
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
          <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
          <span>SOC MONITOR: <strong className="text-emerald-400">ACTIVE</strong></span>
        </div>

        <div className="hidden md:flex items-center gap-1.5 text-slate-400">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-slate-300">{utcTime || "2026-08-16 05:40:00 UTC"}</span>
        </div>

        <div className="hidden lg:flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-900/60 border border-slate-800 text-slate-400">
          <Server className="w-3 h-3 text-slate-400" />
          <span>Events: <strong className="text-cyan-400">{events.length}</strong></span>
        </div>

        {criticalCount > 0 && (
          <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-red-950/80 border border-red-600/60 text-red-300 text-xs font-bold animate-pulse">
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
            <span>{criticalCount} CRITICAL ALERT{criticalCount > 1 ? "S" : ""}</span>
          </div>
        )}
      </div>

      {/* Right Action Bar */}
      <div className="flex items-center gap-3">
        {/* Scenario Quick Loader */}
        <div className="hidden sm:flex items-center gap-1.5 text-xs">
          <span className="text-slate-400 font-mono text-[11px]">Scenario:</span>
          <select
            value={activeScenarioId}
            onChange={(e) => loadScenario(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            {SAMPLE_SCENARIOS.map((sc) => (
              <option key={sc.id} value={sc.id} className="bg-slate-950">
                {sc.name.substring(0, 22)}...
              </option>
            ))}
          </select>
        </div>

        {/* Quick Ingest Logs Button */}
        <button
          onClick={() => setActiveTab("log-analyzer")}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 hover:text-white text-xs font-semibold transition-colors"
        >
          <UploadCloud className="w-3.5 h-3.5 text-cyan-400" />
          <span>Ingest Logs</span>
        </button>

        {/* AI Assistant Quick Toggle */}
        <button
          onClick={() => setActiveTab("ai-analyst")}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-950/80 hover:bg-indigo-900/90 border border-indigo-500/50 text-indigo-200 text-xs font-semibold shadow-sm transition-all"
        >
          <Bot className="w-3.5 h-3.5 text-indigo-400" />
          <span>AI Analyst</span>
        </button>
      </div>
    </header>
  );
};
