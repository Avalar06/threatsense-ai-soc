import React, { useState } from "react";
import { useSoc } from "../context/SocContext.js";
import {
  SearchCode,
  Bot,
  Zap,
  ShieldAlert,
  Clock,
  Fingerprint,
  Layers,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Terminal,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Share2,
  RefreshCw,
  ExternalLink,
  Shield,
  HelpCircle,
} from "lucide-react";
import { SeverityBadge } from "../components/common/SeverityBadge.js";
import { RiskScoreMeter } from "../components/common/RiskScoreMeter.js";
import { MitreTag } from "../components/common/MitreTag.js";
import { AlertStatus, Severity } from "../types/soc.js";

export const InvestigationWorkspaceView: React.FC = () => {
  const {
    activeAlert,
    alerts,
    setActiveAlertId,
    activeInvestigationTimeline,
    triggerAlertInvestigation,
    isInvestigating,
    updateAlertStatus,
    assignAlert,
    escalateAlertToIncident,
    setActiveTab,
    iocs,
  } = useSoc();

  const [customNotes, setCustomNotes] = useState<string>("");
  const [expandedTimelineId, setExpandedTimelineId] = useState<string | null>(null);
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);
  
  // Analyst assignment state
  const [isAssigning, setIsAssigning] = useState<boolean>(false);
  const [assignmentError, setAssignmentError] = useState<string | null>(null);

  // Escalate modal state
  const [showEscalateModal, setShowEscalateModal] = useState<boolean>(false);
  const [escalateTitle, setEscalateTitle] = useState<string>("");
  const [escalateSeverity, setEscalateSeverity] = useState<Severity>("HIGH");
  const [isEscalating, setIsEscalating] = useState<boolean>(false);
  const [escalationSuccess, setEscalationSuccess] = useState<string | null>(null);
  const [escalationError, setEscalationError] = useState<string | null>(null);

  if (!activeAlert) {
    return (
      <div className="p-10 text-center space-y-4 max-w-lg mx-auto">
        <ShieldAlert className="w-12 h-12 text-slate-600 mx-auto" />
        <h3 className="text-lg font-bold text-white">No Alert Selected</h3>
        <p className="text-xs text-slate-400">
          Select an alert from the Alerts Queue or Dashboard to begin investigation.
        </p>
        <button
          onClick={() => setActiveTab("alerts")}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-bold"
        >
          Go to Alerts Queue
        </button>
      </div>
    );
  }

  const handleRunInvestigation = () => {
    triggerAlertInvestigation(activeAlert.id, customNotes);
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIoc(id);
    setTimeout(() => setCopiedIoc(null), 2000);
  };

  const handleAnalystChange = async (newAnalyst: string) => {
    setAssignmentError(null);
    setIsAssigning(true);
    try {
      await assignAlert(activeAlert.id, newAnalyst);
    } catch (err: any) {
      setAssignmentError(err.message || "Failed to update analyst assignment.");
    } finally {
      setIsAssigning(false);
    }
  };

  const handleOpenEscalateModal = () => {
    setEscalateTitle(`Incident: ${activeAlert.title}`);
    setEscalateSeverity(activeAlert.severity);
    setEscalationError(null);
    setEscalationSuccess(null);
    setShowEscalateModal(true);
  };

  const handleConfirmEscalation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!escalateTitle.trim()) return;

    setIsEscalating(true);
    setEscalationError(null);
    try {
      const created = await escalateAlertToIncident(activeAlert.id, escalateTitle.trim(), escalateSeverity);
      setEscalationSuccess(`Successfully escalated alert to ${created.id}!`);
      setTimeout(() => {
        setShowEscalateModal(false);
      }, 1500);
    } catch (err: any) {
      setEscalationError(err.message || "Failed to escalate alert to incident.");
    } finally {
      setIsEscalating(false);
    }
  };

  const analysis = activeAlert.geminiAnalysis;

  // Filter IOCs related to this alert or source IP
  const relatedIocs = iocs.filter(
    (i) =>
      i.value === activeAlert.sourceIp ||
      i.value === activeAlert.destinationIp ||
      activeAlert.evidence.some((e) => e.includes(i.value))
  );

  const ANALYST_OPTIONS = [
    "Unassigned",
    "SOC-Tier2-Analyst",
    "Incident-Responder-Lead",
    "Threat-Hunter",
    "SOC-Tier1-Triage",
    "Senior-Security-Analyst",
  ];

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto overflow-y-auto">
      {/* Escalation Notification Banner */}
      {escalationSuccess && (
        <div className="p-3 bg-emerald-950/90 border border-emerald-500/50 rounded-xl flex items-center justify-between text-emerald-200 text-xs">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{escalationSuccess}</span>
          </div>
          <button
            onClick={() => setEscalationSuccess(null)}
            className="text-emerald-400 hover:text-emerald-200 text-xs font-mono"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Top Header & Alert Selector */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="px-2 py-0.5 rounded bg-indigo-950 border border-indigo-700/60 text-indigo-300 font-mono text-[11px] font-bold">
              INCIDENT INVESTIGATION WORKSPACE
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Alert ID: <strong className="text-cyan-400">{activeAlert.id}</strong>
            </span>
            <SeverityBadge severity={activeAlert.severity} size="sm" />
          </div>

          <h1 className="text-xl font-extrabold text-white tracking-tight">
            {activeAlert.title}
          </h1>

          <p className="text-xs text-slate-400">
            Detected via <strong>{activeAlert.detectionSource}</strong> ({activeAlert.ruleName || "Security Correlation Engine"}).
          </p>
        </div>

        {/* Quick Switch Alert Dropdown & Actions */}
        <div className="flex items-center flex-wrap gap-2.5">
          <div className="flex items-center gap-1.5 text-xs font-mono">
            <span className="text-slate-400">Switch Alert:</span>
            <select
              value={activeAlert.id}
              onChange={(e) => setActiveAlertId(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              {alerts.map((a) => (
                <option key={a.id} value={a.id} className="bg-slate-950">
                  [{a.severity.substring(0, 4)}] {a.title.substring(0, 30)}...
                </option>
              ))}
            </select>
          </div>

          {/* Investigate with Gemini Button */}
          <button
            onClick={handleRunInvestigation}
            disabled={isInvestigating}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-indigo-600 via-purple-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white font-bold text-xs shadow-lg shadow-indigo-600/20 transition-all disabled:opacity-50"
          >
            {isInvestigating ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Gemini Analyzing Evidence...</span>
              </>
            ) : (
              <>
                <Bot className="w-4 h-4" />
                <span>Investigate with Gemini</span>
              </>
            )}
          </button>

          {/* Escalate to Incident Button */}
          <button
            onClick={handleOpenEscalateModal}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-amber-950/80 hover:bg-amber-900 border border-amber-500/60 text-amber-200 font-semibold text-xs transition-colors"
          >
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <span>Escalate to Incident</span>
          </button>

          {/* Generate Report Button */}
          <button
            onClick={() => setActiveTab("incident-reports")}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-emerald-950 hover:bg-emerald-900 border border-emerald-500/60 text-emerald-200 font-semibold text-xs transition-colors"
          >
            <FileText className="w-4 h-4 text-emerald-400" />
            <span>Generate Report</span>
          </button>
        </div>
      </div>

      {/* Escalate to Incident Modal */}
      {showEscalateModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-amber-400" />
                <h3 className="font-bold text-base text-white">Escalate Alert to Incident</h3>
              </div>
              <button
                onClick={() => setShowEscalateModal(false)}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-300">
              This will create a new tracked Incident case and link alert <strong className="text-cyan-400 font-mono">{activeAlert.id}</strong> ({activeAlert.title}).
            </p>

            {escalationError && (
              <div className="p-2.5 bg-red-950/90 border border-red-700 rounded text-red-200 text-xs">
                {escalationError}
              </div>
            )}

            <form onSubmit={handleConfirmEscalation} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 font-mono mb-1">Incident Title:</label>
                <input
                  type="text"
                  value={escalateTitle}
                  onChange={(e) => setEscalateTitle(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-amber-500 font-sans"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 font-mono mb-1">Incident Severity:</label>
                <select
                  value={escalateSeverity}
                  onChange={(e) => setEscalateSeverity(e.target.value as Severity)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowEscalateModal(false)}
                  disabled={isEscalating}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isEscalating}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-bold transition-colors disabled:opacity-50"
                >
                  {isEscalating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                  <span>{isEscalating ? "Creating Incident..." : "Confirm Escalation"}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Main Grid: Alert Context Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Risk Score Card */}
        <div>
          <RiskScoreMeter
            score={activeAlert.riskScore}
            detectionConfidence={activeAlert.detectionConfidence}
            aiConfidence={activeAlert.aiConfidence}
          />
        </div>

        {/* Affected Asset Card */}
        <div className="p-3.5 bg-slate-900/90 border border-slate-800 rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Target Asset</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">FIN-TIER-1</span>
          </div>
          <div className="my-1">
            <span className="font-mono text-base font-bold text-white">{activeAlert.host}</span>
            <span className="text-xs text-slate-400 block font-mono">User: {activeAlert.username}</span>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">Dest IP: {activeAlert.destinationIp || "10.0.4.15"}</span>
        </div>

        {/* Threat Actor / Source IP */}
        <div className="p-3.5 bg-slate-900/90 border border-slate-800 rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Threat Origin</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-950 text-red-300 border border-red-800 font-mono">External</span>
          </div>
          <div className="my-1">
            <span className="font-mono text-base font-bold text-cyan-400">{activeAlert.sourceIp}</span>
            <span className="text-xs text-slate-400 block font-mono">Geolocation: Foreign AS</span>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">Related Events: {activeAlert.relatedEventIds.length}</span>
        </div>

        {/* Incident Status & Analyst Assignment */}
        <div className="p-3.5 bg-slate-900/90 border border-slate-800 rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Triage Status</span>
            <select
              value={activeAlert.status}
              onChange={(e) => updateAlertStatus(activeAlert.id, e.target.value as AlertStatus)}
              className="bg-slate-950 border border-slate-700 rounded px-2 py-0.5 text-[11px] font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="NEW">NEW</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="CONTAINED">CONTAINED</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
            </select>
          </div>
          <div className="my-1 text-xs text-slate-300">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] text-slate-400">Assigned Analyst:</span>
            </div>
            <select
              value={activeAlert.assignedTo || "Unassigned"}
              disabled={isAssigning}
              onChange={(e) => handleAnalystChange(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-[11px] font-mono text-slate-200 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            >
              {ANALYST_OPTIONS.map((analyst) => (
                <option key={analyst} value={analyst}>
                  {analyst}
                </option>
              ))}
            </select>
            {assignmentError && (
              <span className="text-[10px] text-red-400 block mt-0.5">{assignmentError}</span>
            )}
          </div>
          <span className="text-[10px] text-slate-400 font-mono">
            Updated: {activeAlert.updatedAt ? new Date(activeAlert.updatedAt).toLocaleTimeString() : "Just now"}
          </span>
        </div>
      </div>

      {/* GEMINI AI DEEP INVESTIGATION PANEL (Crucial Requirement) */}
      <div className="bg-slate-900/90 border border-indigo-500/40 rounded-xl overflow-hidden shadow-xl">
        <div className="p-4 bg-gradient-to-r from-indigo-950/90 to-slate-900 border-b border-indigo-500/40 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-indigo-900 border border-indigo-400 text-indigo-200">
              <Bot className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-white flex items-center gap-2">
                Gemini 3.7 AI Investigation & Root Cause Synthesis
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-indigo-900 text-indigo-300 border border-indigo-500/40">
                  SERVER-SIDE REASONING
                </span>
              </h3>
              <p className="text-xs text-slate-300">
                Ground-truth log verification with strict separation of observed evidence, inference, and uncertainty
              </p>
            </div>
          </div>

          <button
            onClick={handleRunInvestigation}
            disabled={isInvestigating}
            className="px-3 py-1.5 rounded-lg bg-indigo-900 hover:bg-indigo-800 text-white text-xs font-semibold border border-indigo-400 flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isInvestigating ? "animate-spin" : ""}`} />
            <span>Re-Evaluate Alert</span>
          </button>
        </div>

        {analysis ? (
          <div className="p-6 space-y-6 text-xs">
            {/* Executive Synopsis & Verdict */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400 font-mono text-[11px] uppercase">AI Verdict:</span>
                  <span
                    className={`px-2.5 py-0.5 rounded font-mono font-bold uppercase text-xs ${
                      analysis.verdict === "True Positive"
                        ? "bg-red-950 text-red-300 border border-red-700"
                        : analysis.verdict === "False Positive"
                        ? "bg-emerald-950 text-emerald-300 border border-emerald-700"
                        : "bg-amber-950 text-amber-300 border border-amber-700"
                    }`}
                  >
                    {analysis.verdict}
                  </span>
                  <span className="text-slate-400 font-mono text-[11px]">
                    (Confidence: <strong className="text-cyan-400">{analysis.confidenceScore}%</strong>)
                  </span>
                </div>
                <p className="text-slate-200 text-xs font-sans leading-relaxed pt-1">
                  {analysis.executiveSummary}
                </p>
              </div>
            </div>

            {/* 4-Box Clean Separation Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* 1. Observed Evidence */}
              <div className="bg-slate-950/80 p-4 rounded-xl border border-cyan-800/40 space-y-2">
                <h4 className="font-bold text-xs text-cyan-300 font-mono uppercase flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                  1. Observed Evidence (Ground-Truth Log Facts)
                </h4>
                <ul className="space-y-1.5 text-slate-300 list-disc list-inside">
                  {analysis.observedEvidence.map((ev, i) => (
                    <li key={i} className="leading-relaxed">
                      {ev}
                    </li>
                  ))}
                </ul>
              </div>

              {/* 2. Reasoning & Inferences */}
              <div className="bg-slate-950/80 p-4 rounded-xl border border-purple-800/40 space-y-2">
                <h4 className="font-bold text-xs text-purple-300 font-mono uppercase flex items-center gap-1.5">
                  <Zap className="w-4 h-4 text-purple-400" />
                  2. Reasoning & Analytical Inferences
                </h4>
                <ul className="space-y-1.5 text-slate-300 list-disc list-inside">
                  {analysis.reasoningAndInferences.map((inf, i) => (
                    <li key={i} className="leading-relaxed">
                      {inf}
                    </li>
                  ))}
                </ul>
              </div>

              {/* 3. Uncertainty & Gaps */}
              <div className="bg-slate-950/80 p-4 rounded-xl border border-amber-800/40 space-y-2">
                <h4 className="font-bold text-xs text-amber-300 font-mono uppercase flex items-center gap-1.5">
                  <HelpCircle className="w-4 h-4 text-amber-400" />
                  3. Uncertainty & Visibility Gaps
                </h4>
                <ul className="space-y-1.5 text-slate-300 list-disc list-inside">
                  {analysis.uncertaintyAndGaps.map((unc, i) => (
                    <li key={i} className="leading-relaxed">
                      {unc}
                    </li>
                  ))}
                </ul>
              </div>

              {/* 4. Recommended Containment & Investigation Steps */}
              <div className="bg-slate-950/80 p-4 rounded-xl border border-red-800/40 space-y-2">
                <h4 className="font-bold text-xs text-red-300 font-mono uppercase flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                  4. Actionable Containment & Next Steps
                </h4>
                <div className="space-y-2">
                  <div>
                    <span className="font-semibold text-slate-200 block text-[11px] text-red-400">Immediate Containment:</span>
                    <ul className="space-y-1 text-slate-300 list-disc list-inside">
                      {analysis.recommendedContainment.map((step, i) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="pt-1">
                    <span className="font-semibold text-slate-200 block text-[11px] text-cyan-400">Forensic Investigation:</span>
                    <ul className="space-y-1 text-slate-300 list-disc list-inside">
                      {analysis.recommendedInvestigation.map((step, i) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="p-8 text-center space-y-3">
            <Bot className="w-10 h-10 text-indigo-400 mx-auto" />
            <h4 className="text-sm font-bold text-slate-200">AI Deep Investigation Ready</h4>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Click &quot;Investigate with Gemini&quot; to synthesize all log evidence, evaluate attack progression, and extract containment steps.
            </p>
            <button
              onClick={handleRunInvestigation}
              disabled={isInvestigating}
              className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-md transition-colors"
            >
              Run Gemini Investigation Now
            </button>
          </div>
        )}
      </div>

      {/* Attack Timeline & Extracted IOCs Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Interactive Chronological Attack Timeline */}
        <div className="lg:col-span-2 bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                Chronological Attack Timeline
              </h3>
              <p className="text-xs text-slate-400">Sequence of observed malicious events leading to detection</p>
            </div>
            <span className="text-xs font-mono text-slate-400">
              {activeInvestigationTimeline.length} Chronological Nodes
            </span>
          </div>

          <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
            {activeInvestigationTimeline.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono">No timeline events mapped.</p>
            ) : (
              activeInvestigationTimeline.map((item, idx) => {
                const isExpanded = expandedTimelineId === item.id;
                return (
                  <div key={item.id} className="relative group">
                    {/* Node Dot */}
                    <div
                      className={`absolute -left-[27px] top-1.5 w-3.5 h-3.5 rounded-full border-2 border-slate-950 ${
                        item.severity === "CRITICAL"
                          ? "bg-red-500 shadow-sm shadow-red-500"
                          : item.severity === "HIGH"
                          ? "bg-orange-500"
                          : "bg-cyan-500"
                      }`}
                    />

                    <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 hover:border-slate-700 transition-all">
                      <div className="flex items-center justify-between text-xs">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-cyan-400 font-bold">{item.time}</span>
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] font-mono text-slate-300">
                            {item.stage}
                          </span>
                        </div>
                        <SeverityBadge severity={item.severity} size="sm" />
                      </div>

                      <h4 className="font-bold text-xs text-slate-100 mt-1.5">{item.title}</h4>
                      <p className="text-[11px] text-slate-400 font-mono mt-0.5">{item.description}</p>

                      {/* Expand raw evidence button */}
                      {item.rawEvidence && (
                        <div className="mt-2 pt-2 border-t border-slate-800/80">
                          <button
                            onClick={() => setExpandedTimelineId(isExpanded ? null : item.id)}
                            className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                          >
                            <span>{isExpanded ? "Hide Raw Telemetry" : "Inspect Raw Telemetry Payload"}</span>
                            {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                          </button>

                          {isExpanded && (
                            <pre className="mt-2 p-2.5 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-cyan-300 whitespace-pre-wrap break-all">
                              {item.rawEvidence}
                            </pre>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: IOCs & MITRE Mapping */}
        <div className="space-y-6">
          {/* IOCs Box */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
                <Fingerprint className="w-4 h-4 text-emerald-400" />
                Extracted Indicators (IOCs)
              </h3>
              <span className="font-mono text-xs text-slate-400">{relatedIocs.length} found</span>
            </div>

            <div className="space-y-2 max-h-72 overflow-y-auto custom-scrollbar">
              {relatedIocs.length === 0 ? (
                <p className="text-xs text-slate-500 font-mono">No specific IOCs matched for this alert.</p>
              ) : (
                relatedIocs.map((ioc) => (
                  <div
                    key={ioc.id}
                    className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs font-mono"
                  >
                    <div>
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                          {ioc.type}
                        </span>
                        <span
                          className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${
                            ioc.riskLevel === "MALICIOUS"
                              ? "text-red-400 bg-red-950/60"
                              : "text-amber-400 bg-amber-950/60"
                          }`}
                        >
                          {ioc.riskLevel}
                        </span>
                      </div>
                      <div className="font-bold text-slate-200 mt-1 break-all select-all">
                        {ioc.defangedValue}
                      </div>
                    </div>

                    <button
                      onClick={() => handleCopy(ioc.defangedValue, ioc.id)}
                      className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                      title="Copy Defanged IOC"
                    >
                      {copiedIoc === ioc.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* MITRE Techniques Covered */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-3">
            <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-400" />
              MITRE ATT&CK Alignment
            </h3>

            <div className="space-y-2">
              {activeAlert.mitreTechniques.map((tech) => (
                <div key={tech.id} className="p-3 bg-slate-950 rounded-lg border border-indigo-900/40 text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono font-bold text-indigo-300">{tech.id}</span>
                    <span className="text-[10px] font-mono text-cyan-400">Conf: {tech.confidence}%</span>
                  </div>
                  <h5 className="font-semibold text-slate-200 text-xs">{tech.name}</h5>
                  <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{tech.explanation}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
