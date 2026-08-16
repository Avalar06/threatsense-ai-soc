import React, { useState, useMemo } from "react";
import { useSoc } from "../context/SocContext.js";
import {
  Layers,
  ShieldAlert,
  Search,
  ExternalLink,
  Bot,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Zap,
} from "lucide-react";
import { MITRE_TACTICS, MitreTechniqueDefinition } from "../data/mitreDatabase.js";
import { queryMitreMapping } from "../services/apiClient.js";

export const MitreAttackView: React.FC = () => {
  const { alerts, events, activeAlert } = useSoc();

  const [search, setSearch] = useState("");
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechniqueDefinition | null>(null);
  const [aiAnalyzing, setAiAnalyzing] = useState(false);
  const [aiMappingResult, setAiMappingResult] = useState<any>(null);

  // Collect all active technique IDs from current alerts
  const activeTechniqueIds = useMemo(() => {
    const ids = new Set<string>();
    alerts.forEach((a) => {
      a.mitreTechniques.forEach((t) => ids.add(t.id));
    });
    return ids;
  }, [alerts]);

  const handleRunAiMitreMapping = async () => {
    setAiAnalyzing(true);
    try {
      const res = await queryMitreMapping(
        events.slice(0, 25),
        activeAlert?.title || "Security Incident Correlation",
        "Enterprise Endpoint Telemetry"
      );
      setAiMappingResult(res);
    } finally {
      setAiAnalyzing(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-[1700px] mx-auto overflow-y-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-indigo-950 border border-indigo-700/60 text-indigo-300 font-mono text-[11px] font-bold">
              THREAT INTELLIGENCE & FRAMEWORK
            </span>
            <span className="text-xs text-slate-400 font-mono">
              MITRE ATT&CK Matrix Enterprise v14
            </span>
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight mt-1">
            MITRE ATT&CK Framework Heatmap & Matrix
          </h1>
          <p className="text-xs text-slate-400">
            Real-time adversary technique mapping across the cyber kill chain based on ingested telemetry and alerts.
          </p>
        </div>

        {/* Action button */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleRunAiMitreMapping}
            disabled={aiAnalyzing}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-md transition-all disabled:opacity-50"
          >
            {aiAnalyzing ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Mapping Kill Chain...</span>
              </>
            ) : (
              <>
                <Bot className="w-3.5 h-3.5" />
                <span>AI Kill Chain Synthesis</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* AI Kill Chain Synthesis Card (if available) */}
      {aiMappingResult && (
        <div className="p-4 bg-indigo-950/60 border border-indigo-500/50 rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-indigo-400" />
              <h4 className="font-bold text-sm text-white font-mono">
                AI Threat Assessment: Kill Chain Stage &mdash; {aiMappingResult.killChainStage}
              </h4>
            </div>
            <button
              onClick={() => setAiMappingResult(null)}
              className="text-xs text-slate-400 hover:text-white"
            >
              Dismiss
            </button>
          </div>
          <p className="text-xs text-slate-300 font-mono">
            <strong>Analyst Advisory:</strong> {aiMappingResult.analystAdvice}
          </p>
        </div>
      )}

      {/* Search & Active Stats */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="relative w-72">
          <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search technique ID or name..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded bg-red-500 border border-red-400" />
            <span className="text-slate-300">Active Detected Technique ({activeTechniqueIds.size})</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded bg-slate-800 border border-slate-700" />
            <span className="text-slate-400">Baseline Matrix Technique</span>
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Multi-Column Matrix Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 overflow-x-auto">
        {MITRE_TACTICS.map((tactic) => {
          const matchingTechniques = tactic.techniques.filter((t) => {
            if (!search.trim()) return true;
            const q = search.toLowerCase();
            return t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q);
          });

          return (
            <div
              key={tactic.id}
              className="bg-slate-900/90 border border-slate-800 rounded-xl flex flex-col min-w-[200px]"
            >
              {/* Tactic Header */}
              <div className="p-3 bg-slate-950 border-b border-slate-800 rounded-t-xl">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-indigo-400 font-bold">{tactic.id}</span>
                  <span className="text-[10px] font-mono text-slate-500">
                    {matchingTechniques.length} techs
                  </span>
                </div>
                <h3 className="font-bold text-xs text-slate-100 mt-0.5 leading-tight">{tactic.name}</h3>
              </div>

              {/* Technique Cards */}
              <div className="p-2 space-y-2 flex-1 overflow-y-auto max-h-[500px] custom-scrollbar">
                {matchingTechniques.map((tech) => {
                  const isActive = activeTechniqueIds.has(tech.id);
                  return (
                    <button
                      key={tech.id}
                      onClick={() => setSelectedTechnique(tech)}
                      className={`w-full text-left p-2.5 rounded-lg border transition-all text-xs ${
                        isActive
                          ? "bg-red-950/70 border-red-500 text-red-200 shadow-md shadow-red-950 hover:bg-red-900/80"
                          : "bg-slate-950/80 border-slate-800/90 hover:border-slate-700 text-slate-300 hover:bg-slate-800/60"
                      }`}
                    >
                      <div className="flex items-center justify-between font-mono text-[11px] mb-1">
                        <span className={`font-bold ${isActive ? "text-red-300" : "text-indigo-400"}`}>
                          {tech.id}
                        </span>
                        {isActive && (
                          <span className="text-[9px] px-1.5 py-0.2 rounded bg-red-900/90 text-red-100 font-bold">
                            ACTIVE
                          </span>
                        )}
                      </div>
                      <div className="font-semibold text-[11px] line-clamp-2 leading-tight">
                        {tech.name}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {/* Technique Inspector Modal */}
      {selectedTechnique && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
              <div className="flex items-center gap-2">
                <Layers className="w-5 h-5 text-indigo-400" />
                <h4 className="font-bold text-sm text-slate-100 font-mono">
                  MITRE Technique: {selectedTechnique.id} - {selectedTechnique.name}
                </h4>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="text-slate-400 hover:text-white text-lg font-bold px-2"
              >
                ✕
              </button>
            </div>

            <div className="p-5 space-y-4 overflow-y-auto custom-scrollbar text-xs">
              {/* Tactic & Detection info */}
              <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono">
                <div>
                  <span className="text-slate-500 block text-[10px]">Tactic</span>
                  <span className="text-indigo-300 font-bold">{selectedTechnique.tactic}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Active Status</span>
                  <span
                    className={`font-bold ${
                      activeTechniqueIds.has(selectedTechnique.id) ? "text-red-400" : "text-slate-400"
                    }`}
                  >
                    {activeTechniqueIds.has(selectedTechnique.id) ? "DETECTED IN ACTIVE ALERTS" : "NOT OBSERVED"}
                  </span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-mono block mb-1 font-semibold">Description:</span>
                <p className="text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
                  {selectedTechnique.description}
                </p>
              </div>

              <div>
                <span className="text-slate-400 font-mono block mb-1 font-semibold">Detection / Validation Logic:</span>
                <div className="p-3 bg-slate-950 rounded-lg border border-cyan-800/40 text-cyan-300 font-mono text-[11px] leading-relaxed">
                  {selectedTechnique.detectionCheck}
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-mono block mb-1 font-semibold">Recommended Mitigations:</span>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-300">
                  {selectedTechnique.mitigation}
                </div>
              </div>
            </div>

            <div className="p-4 border-t border-slate-800 bg-slate-950 flex items-center justify-between">
              <a
                href={selectedTechnique.url}
                target="_blank"
                rel="noreferrer"
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                <span>View on attack.mitre.org</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
