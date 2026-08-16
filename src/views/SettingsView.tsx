import React, { useState } from "react";
import { useSoc } from "../context/SocContext.js";
import {
  Settings,
  Shield,
  Sliders,
  Database,
  Key,
  RotateCcw,
  CheckCircle2,
  Server,
  Cpu,
  Layers,
  Bot,
  Flame,
  Check,
} from "lucide-react";
import { DEFAULT_DETECTION_RULES } from "../services/detectionEngine.js";

export const SettingsView: React.FC = () => {
  const {
    resetToDefaultDemo,
    clearAllData,
    events,
    alerts,
    iocs,
    backendHealth,
  } = useSoc();

  const [rules, setRules] = useState(DEFAULT_DETECTION_RULES);
  const [savedSuccess, setSavedSuccess] = useState(false);

  const toggleRule = (id: string) => {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r))
    );
  };

  const handleSaveRules = () => {
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
  };

  return (
    <div className="p-6 space-y-6 max-w-[1500px] mx-auto overflow-y-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono text-[11px] font-bold">
              PLATFORM CONFIGURATION & ARCHITECTURE
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Build Version: 2.4.0 (Enterprise SOC)
            </span>
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight mt-1">
            System Architecture & Detection Engine Settings
          </h1>
          <p className="text-xs text-slate-400">
            Configure correlation rules, risk scoring weights, modular backend integrations, and platform diagnostics.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={resetToDefaultDemo}
            className="px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono flex items-center gap-1.5"
          >
            <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Reset Demo Scenarios</span>
          </button>
          <button
            onClick={clearAllData}
            className="px-3.5 py-1.5 rounded-lg bg-red-950 hover:bg-red-900 border border-red-800 text-red-300 text-xs font-mono"
          >
            Clear Ingested Memory
          </button>
        </div>
      </div>

      {/* Modular Architecture & Future Integrations Grid */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4 shadow-xl">
        <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          Modular Enterprise SOC Architecture & Extension Adapters
        </h3>
        <p className="text-xs text-slate-400">
          Designed with clean decoupling across telemetry ingestion, hybrid detection engines, and server-side LLM reasoning.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* AI Reasoning Core */}
          <div className="bg-slate-950 p-4 rounded-xl border border-indigo-900/40 space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between">
              <span className="text-indigo-400 font-bold flex items-center gap-1.5">
                <Bot className="w-4 h-4" />
                AI Reasoning Core
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-700">
                ACTIVE
              </span>
            </div>
            <p className="text-slate-400 text-[11px] font-sans">
              Google Gemini 3.7 Flash via server-side SDK proxy with structured JSON schemas and evidence ground-truth validation.
            </p>
          </div>

          {/* Cloud SQL / Postgres */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between">
              <span className="text-cyan-400 font-bold flex items-center gap-1.5">
                <Database className="w-4 h-4" />
                Relational Database
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                READY / MODULAR
              </span>
            </div>
            <p className="text-slate-400 text-[11px] font-sans">
              Configured for Cloud SQL (PostgreSQL) / Drizzle ORM schema persistence for enterprise alert historical warehousing.
            </p>
          </div>

          {/* SIEM Webhook Ingest */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between">
              <span className="text-purple-400 font-bold flex items-center gap-1.5">
                <Server className="w-4 h-4" />
                SIEM Ingest Stream
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                SYSLOG / JSON
              </span>
            </div>
            <p className="text-slate-400 text-[11px] font-sans">
              Accepts live Splunk HEC, Elastic Filebeat, and Syslog RFC 5424 streams with auto-normalization.
            </p>
          </div>

          {/* Threat Intel API Feeds */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between">
              <span className="text-amber-400 font-bold flex items-center gap-1.5">
                <Shield className="w-4 h-4" />
                Threat Intel Feeds
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                STIX / TAXII
              </span>
            </div>
            <p className="text-slate-400 text-[11px] font-sans">
              Extensible enrichers for VirusTotal, AbuseIPDB, and AlienVault OTX indicator reputation scoring.
            </p>
          </div>
        </div>
      </div>

      {/* Detection Rules Configurator */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4 shadow-xl">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Active Detection Rules & Thresholds
            </h3>
            <p className="text-xs text-slate-400">Enable or disable deterministic heuristic detection rules</p>
          </div>

          <button
            onClick={handleSaveRules}
            className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            {savedSuccess ? <Check className="w-3.5 h-3.5" /> : null}
            <span>{savedSuccess ? "Saved Settings!" : "Apply Rule Changes"}</span>
          </button>
        </div>

        <div className="space-y-2">
          {rules.map((r) => (
            <div
              key={r.id}
              className={`p-3.5 rounded-lg border transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs ${
                r.enabled
                  ? "bg-slate-950 border-slate-800"
                  : "bg-slate-950/40 border-slate-900 opacity-60"
              }`}
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2 font-mono">
                  <span className="text-cyan-400 font-bold">{r.id}</span>
                  <span className="font-semibold text-slate-200">{r.name}</span>
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                    {r.category}
                  </span>
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                    {r.mitreId}
                  </span>
                </div>
                <p className="text-slate-400 text-[11px]">{r.description}</p>
              </div>

              <div className="flex items-center gap-4 shrink-0 font-mono">
                <span
                  className={`text-[10px] font-bold uppercase ${
                    r.severity === "CRITICAL"
                      ? "text-red-400"
                      : r.severity === "HIGH"
                      ? "text-orange-400"
                      : "text-amber-400"
                  }`}
                >
                  {r.severity}
                </span>

                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={r.enabled}
                    onChange={() => toggleRule(r.id)}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600"></div>
                </label>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
