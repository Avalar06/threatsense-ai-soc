import React, { useState } from "react";
import { useSoc } from "../context/SocContext";
import {
  ShieldAlert,
  Layers,
  Play,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Search,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Fingerprint,
  Info
} from "lucide-react";
import type { CorrelationRecord, DetectionStrategy } from "../types/soc";

export const CorrelationsView: React.FC = () => {
  const {
    correlations,
    detectionStrategies,
    correlationsLoading,
    triggerCorrelationsRun,
    openIncident,
    openInvestigationForAlert
  } = useSoc();

  const [selectedCorrelation, setSelectedCorrelation] = useState<CorrelationRecord | null>(null);
  const [activeTab, setActiveTab] = useState<"correlations" | "strategies">("correlations");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [runSummary, setRunSummary] = useState<string | null>(null);

  const handleRunEvaluation = async () => {
    setIsRunning(true);
    setRunSummary(null);
    try {
      const res = await triggerCorrelationsRun({ windowSeconds: 1800 });
      setRunSummary(
        `Evaluation Complete: Evaluated strategies. Found ${res.correlations.length} matching correlation patterns.`
      );
    } catch (err: any) {
      setRunSummary(`Correlation run failed: ${err.message || String(err)}`);
    } finally {
      setIsRunning(false);
    }
  };

  const filteredCorrelations = correlations.filter((c) => {
    if (selectedSeverity !== "ALL" && c.severity !== selectedSeverity) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        c.id.toLowerCase().includes(q) ||
        c.title.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        c.mitreTechniqueId.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case "CRITICAL":
        return "bg-rose-500/20 text-rose-400 border border-rose-500/30";
      case "HIGH":
        return "bg-orange-500/20 text-orange-400 border border-orange-500/30";
      case "MEDIUM":
        return "bg-amber-500/20 text-amber-400 border border-amber-500/30";
      default:
        return "bg-blue-500/20 text-blue-400 border border-blue-500/30";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 backdrop-blur border border-slate-800 p-6 rounded-xl shadow-lg">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <Layers className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                Production Detection & Multi-Stage Correlation Engine
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
                  Active
                </span>
              </h1>
              <p className="text-sm text-slate-400">
                Deterministic MITRE ATT&CK correlation, multi-host attack chain aggregation, and cryptographic SHA-256 fingerprint deduplication.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleRunEvaluation}
            disabled={isRunning || correlationsLoading}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition shadow-md shadow-indigo-600/20 disabled:opacity-50"
          >
            <Play className={`w-4 h-4 ${isRunning ? "animate-spin" : ""}`} />
            {isRunning ? "Evaluating Telemetry..." : "Run Multi-Stage Correlation"}
          </button>
        </div>
      </div>

      {runSummary && (
        <div className="p-4 rounded-lg bg-slate-900 border border-indigo-500/30 text-indigo-300 text-sm flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-indigo-400 flex-shrink-0" />
            <span>{runSummary}</span>
          </div>
          <button onClick={() => setRunSummary(null)} className="text-slate-400 hover:text-slate-200 text-xs font-medium">
            Dismiss
          </button>
        </div>
      )}

      {/* Navigation tabs */}
      <div className="flex items-center gap-4 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab("correlations")}
          className={`px-4 py-2 text-sm font-medium rounded-lg transition ${
            activeTab === "correlations"
              ? "bg-slate-800 text-indigo-400 border border-slate-700"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          Correlations ({correlations.length})
        </button>
        <button
          onClick={() => setActiveTab("strategies")}
          className={`px-4 py-2 text-sm font-medium rounded-lg transition ${
            activeTab === "strategies"
              ? "bg-slate-800 text-indigo-400 border border-slate-700"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          Detection Strategies ({detectionStrategies.length})
        </button>
      </div>

      {activeTab === "correlations" ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Correlation Records List */}
          <div className="lg:col-span-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="relative flex-1">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter correlations by title, technique, ID..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 text-sm bg-slate-900/60 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                />
              </div>
              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                className="bg-slate-900/60 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            {filteredCorrelations.length === 0 ? (
              <div className="p-12 text-center bg-slate-900/40 border border-slate-800/80 rounded-xl">
                <ShieldAlert className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                <h3 className="text-base font-medium text-slate-300">No Multi-Stage Correlations Found</h3>
                <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
                  Click "Run Multi-Stage Correlation" above to scan live event telemetry against MITRE ATT&CK detection strategies.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredCorrelations.map((corr) => (
                  <div
                    key={corr.id}
                    onClick={() => setSelectedCorrelation(corr)}
                    className={`p-4 rounded-xl border transition cursor-pointer ${
                      selectedCorrelation?.id === corr.id
                        ? "bg-slate-800/90 border-indigo-500/60 shadow-lg shadow-indigo-950/20"
                        : "bg-slate-900/60 border-slate-800/80 hover:bg-slate-800/50 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 text-xs font-semibold rounded ${getSeverityBadge(corr.severity)}`}>
                            {corr.severity}
                          </span>
                          <span className="text-xs font-mono text-indigo-400 bg-indigo-950/40 px-2 py-0.5 rounded border border-indigo-900/40">
                            {corr.mitreTechniqueId}
                          </span>
                          <span className="text-xs font-mono text-slate-500">{corr.id}</span>
                        </div>
                        <h4 className="text-sm font-semibold text-slate-200">{corr.title}</h4>
                      </div>
                      <ChevronRight className="w-4 h-4 text-slate-500 flex-shrink-0 mt-1" />
                    </div>

                    <p className="text-xs text-slate-400 mt-2 line-clamp-2">{corr.description}</p>

                    <div className="flex items-center gap-4 mt-3 pt-3 border-t border-slate-800/60 text-xs text-slate-400">
                      <div className="flex items-center gap-1">
                        <Fingerprint className="w-3.5 h-3.5 text-slate-500" />
                        <span className="font-mono text-slate-400">{corr.fingerprint.slice(0, 10)}...</span>
                      </div>
                      <div>
                        Events: <span className="font-medium text-slate-200">{corr.eventIds.length}</span>
                      </div>
                      <div>
                        Alerts: <span className="font-medium text-slate-200">{corr.alertIds.length}</span>
                      </div>
                      <div>
                        Risk Score: <span className="font-bold text-amber-400">{corr.riskScore}/100</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Correlation Detail View */}
          <div className="lg:col-span-6">
            {selectedCorrelation ? (
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-6 sticky top-6">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className={`px-2.5 py-1 text-xs font-semibold rounded ${getSeverityBadge(selectedCorrelation.severity)}`}>
                      {selectedCorrelation.severity} CORRELATION
                    </span>
                    <span className="text-xs text-slate-400 font-mono">
                      {new Date(selectedCorrelation.createdAt).toLocaleString()}
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-slate-100">{selectedCorrelation.title}</h3>
                  <p className="text-xs font-mono text-slate-500 mt-0.5">Correlation ID: {selectedCorrelation.id}</p>
                </div>

                {/* MITRE & Risk Metadata */}
                <div className="grid grid-cols-2 gap-3 p-3.5 bg-slate-950/60 rounded-lg border border-slate-800/80 text-xs">
                  <div>
                    <span className="text-slate-500">MITRE Tactic:</span>
                    <p className="text-slate-200 font-medium">{selectedCorrelation.mitreTactic}</p>
                  </div>
                  <div>
                    <span className="text-slate-500">Technique:</span>
                    <p className="text-indigo-300 font-mono font-medium">{selectedCorrelation.mitreTechniqueId}</p>
                  </div>
                  <div>
                    <span className="text-slate-500">Confidence Score:</span>
                    <p className="text-slate-200 font-medium">{selectedCorrelation.confidence}</p>
                  </div>
                  <div>
                    <span className="text-slate-500">Risk Score:</span>
                    <p className="text-amber-400 font-bold">{selectedCorrelation.riskScore}/100</p>
                  </div>
                </div>

                {/* Description */}
                <div>
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Analysis & Description</h4>
                  <p className="text-sm text-slate-300 bg-slate-950/40 p-3 rounded-lg border border-slate-800/60 leading-relaxed">
                    {selectedCorrelation.description}
                  </p>
                </div>

                {/* Evidence Entities */}
                <div>
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Correlation Evidence</h4>
                  <div className="space-y-2">
                    {selectedCorrelation.evidence.map((ev, idx) => (
                      <div key={idx} className="p-3 bg-slate-950/50 rounded-lg border border-slate-800/60 text-xs space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-indigo-300">{ev.summary}</span>
                          <span className="text-slate-500 text-[10px] uppercase font-mono">{ev.entityType}</span>
                        </div>
                        <p className="font-mono text-slate-400 text-[11px] truncate">Target: {ev.entityValue}</p>
                        {ev.rawLogSnippet && (
                          <pre className="mt-1 p-2 rounded bg-slate-900 text-slate-300 font-mono text-[10px] overflow-x-auto whitespace-pre-wrap">
                            {ev.rawLogSnippet}
                          </pre>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Explainable Contributors */}
                {selectedCorrelation.contributors && selectedCorrelation.contributors.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Risk Contributors</h4>
                    <div className="space-y-1.5">
                      {selectedCorrelation.contributors.map((c, i) => (
                        <div key={i} className="flex items-center justify-between text-xs p-2 rounded bg-slate-950/40 border border-slate-800/40">
                          <span className="text-slate-300">{c.factor}</span>
                          <span className="font-mono font-bold text-amber-400">+{c.weight} pts</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Fingerprint Deduplication Audit */}
                <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800/60 text-xs">
                  <div className="flex items-center gap-1.5 text-slate-400 mb-1">
                    <Fingerprint className="w-3.5 h-3.5 text-indigo-400" />
                    <span className="font-medium text-slate-300">Deterministic SHA-256 Fingerprint:</span>
                  </div>
                  <p className="font-mono text-[11px] text-slate-500 break-all">{selectedCorrelation.fingerprint}</p>
                </div>

                {/* Quick Linkage Actions */}
                <div className="flex items-center gap-3 pt-2 border-t border-slate-800">
                  {selectedCorrelation.incidentId && (
                    <button
                      onClick={() => openIncident(selectedCorrelation.incidentId!)}
                      className="flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 text-xs font-medium border border-indigo-500/30 transition"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      View Linked Incident
                    </button>
                  )}
                  {selectedCorrelation.alertIds.length > 0 && (
                    <button
                      onClick={() => openInvestigationForAlert(selectedCorrelation.alertIds[0])}
                      className="flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
                    >
                      <FileText className="w-3.5 h-3.5" />
                      Investigate Alerts ({selectedCorrelation.alertIds.length})
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <div className="p-12 text-center bg-slate-900/40 border border-slate-800/80 rounded-xl">
                <Info className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                <p className="text-sm text-slate-400">Select a correlation record to view its evidence, contributors, and attack chain details.</p>
              </div>
            )}
          </div>
        </div>
      ) : (
        /* Detection Strategies Catalog */
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {detectionStrategies.map((strat) => (
            <div key={strat.id} className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-mono bg-indigo-950/50 text-indigo-400 px-2 py-0.5 rounded border border-indigo-900/40">
                      {strat.mitreTechniqueId}
                    </span>
                    <span className="text-xs text-slate-500 uppercase">{strat.mitreTactic}</span>
                  </div>
                  <h4 className="text-sm font-bold text-slate-200">{strat.name}</h4>
                </div>
                <span className={`px-2 py-0.5 text-xs rounded-full font-medium ${
                  strat.isActive ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-slate-800 text-slate-400"
                }`}>
                  {strat.isActive ? "ACTIVE" : "DISABLED"}
                </span>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">{strat.description}</p>

              <div className="grid grid-cols-2 gap-2 text-xs pt-2 border-t border-slate-800/60 text-slate-400">
                <div>
                  Window: <span className="text-slate-200 font-mono">{strat.windowSeconds}s</span>
                </div>
                <div>
                  Threshold: <span className="text-slate-200 font-mono">{strat.thresholdCount} events</span>
                </div>
                <div>
                  Severity: <span className="text-slate-200 font-semibold">{strat.severity}</span>
                </div>
                <div>
                  Confidence: <span className="text-slate-200 font-semibold">{strat.confidence}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
