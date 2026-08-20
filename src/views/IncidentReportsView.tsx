import React, { useState } from "react";
import { useSoc } from "../context/SocContext.js";
import {
  FileText,
  Bot,
  Download,
  Printer,
  Copy,
  Check,
  ShieldCheck,
  Calendar,
  AlertTriangle,
  Clock,
  Layers,
  Fingerprint,
  RefreshCw,
} from "lucide-react";
import { generateIncidentReportApi } from "../services/apiClient.js";
import { IncidentReport } from "../types/soc.js";

export const IncidentReportsView: React.FC = () => {
  const {
    activeAlert,
    activeInvestigationTimeline,
    iocs,
    events,
    incidentReports,
    saveIncidentReport,
    alerts,
    setActiveAlertId,
    reportsLoading,
    reportsError,
    loadReports,
  } = useSoc();

  const [generating, setGenerating] = useState(false);
  const [analystNotes, setAnalystNotes] = useState("");
  const [currentReport, setCurrentReport] = useState<IncidentReport | null>(
    incidentReports[0] || null
  );
  const [copied, setCopied] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Sync selected report if incidentReports updates
  React.useEffect(() => {
    if (!currentReport && incidentReports.length > 0) {
      setCurrentReport(incidentReports[0]);
    }
  }, [incidentReports, currentReport]);

  const handleGenerateReport = async () => {
    if (!activeAlert) return;
    setGenerating(true);
    setSaveError(null);
    try {
      const generated = await generateIncidentReportApi({
        alert: activeAlert,
        timeline: activeInvestigationTimeline,
        iocs,
        mitreMappings: activeAlert.mitreTechniques,
        analystNotes,
        rawEvents: events.slice(0, 30),
      });

      const nowIso = new Date().toISOString();
      const fullReport: IncidentReport = {
        id: `RPT-${Date.now().toString(36).toUpperCase()}`,
        reportTitle: generated.reportTitle || `SOC Incident Report: ${activeAlert.title} [${activeAlert.id}]`,
        incidentId: activeAlert.id,
        generatedAt: nowIso,
        createdAt: nowIso,
        author: "AI-SOC Autonomous Analyst (Lead Response)",
        status: "FINAL",
        classification: activeAlert.severity === "CRITICAL" ? "CRITICAL INCIDENT" : "SECURITY INCIDENT",
        executiveSummary: generated.executiveSummary || "",
        incidentDescription: generated.incidentDescription || "",
        detectionMethod: generated.detectionMethod || activeAlert.detectionSource,
        affectedAssets: generated.affectedAssets || [activeAlert.host],
        affectedUsers: generated.affectedUsers || [activeAlert.username],
        timeline: activeInvestigationTimeline,
        extractedIocs: iocs,
        mitreMappings: activeAlert.mitreTechniques,
        rootCauseAnalysis: generated.rootCauseAnalysis || "",
        riskAssessment: generated.riskAssessment || {
          quantitativeScore: activeAlert.riskScore,
          impactRating: activeAlert.severity,
          confidentialityImpact: "High",
          integrityImpact: "Medium",
          availabilityImpact: "Low",
        },
        containmentActionsCompleted: generated.containmentActionsCompleted || [
          `Quarantined host ${activeAlert.host}.`,
          `Blocked external IP ${activeAlert.sourceIp}.`,
        ],
        eradicationAndRemediation: generated.eradicationAndRemediation || [
          "Terminated suspicious process trees.",
          "Forced credential rotation on compromised accounts.",
        ],
        lessonsLearnedAndPreventativeControls: generated.lessonsLearnedAndPreventativeControls || [
          "Mandate MFA across all remote management endpoints.",
        ],
        analystConclusion: generated.analystConclusion || "Incident contained successfully within SLA thresholds.",
      };

      setCurrentReport(fullReport);
      await saveIncidentReport(fullReport);
    } catch (err: any) {
      setSaveError(err.message || "Failed to generate or save incident report");
    } finally {
      setGenerating(false);
    }
  };

  const handleCopyMarkdown = () => {
    if (!currentReport) return;
    const md = `# ${currentReport.reportTitle}
**Incident ID:** ${currentReport.incidentId} | **Date:** ${currentReport.createdAt} | **Classification:** ${currentReport.classification}

## 1. Executive Summary
${currentReport.executiveSummary}

## 2. Incident Description & Scope
- **Affected Assets:** ${currentReport.affectedAssets.join(", ")}
- **Affected Users:** ${currentReport.affectedUsers.join(", ")}
- **Detection Method:** ${currentReport.detectionMethod}

## 3. Root Cause Analysis
${currentReport.rootCauseAnalysis}

## 4. Quantitative Risk Assessment
- **Risk Score:** ${currentReport.riskAssessment.quantitativeScore}/100
- **Impact Rating:** ${currentReport.riskAssessment.impactRating}
- **Confidentiality:** ${currentReport.riskAssessment.confidentialityImpact}
- **Integrity:** ${currentReport.riskAssessment.integrityImpact}
- **Availability:** ${currentReport.riskAssessment.availabilityImpact}

## 5. Containment & Eradication Completed
${currentReport.containmentActionsCompleted.map((c) => `- ${c}`).join("\n")}

## 6. Preventative Controls & Lessons Learned
${currentReport.lessonsLearnedAndPreventativeControls.map((l) => `- ${l}`).join("\n")}

## 7. Analyst Conclusion
${currentReport.analystConclusion}
`;
    navigator.clipboard.writeText(md);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="p-6 space-y-6 max-w-[1500px] mx-auto overflow-y-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-700/60 text-emerald-300 font-mono text-[11px] font-bold">
              AUDIT & GOVERNANCE READY
            </span>
            <span className="text-xs text-slate-400 font-mono">
              NIST SP 800-61 Rev 2 Format
            </span>
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight mt-1">
            SOC Incident Report Generator
          </h1>
          <p className="text-xs text-slate-400">
            Synthesize full-scope security incident reports with root cause analysis, timeline logs, and remediation playbooks.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          {currentReport && (
            <>
              <button
                onClick={handleCopyMarkdown}
                className="px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono flex items-center gap-1.5 transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? "Copied MD!" : "Copy Markdown"}</span>
              </button>
              <button
                onClick={handlePrint}
                className="px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono flex items-center gap-1.5 transition-colors"
              >
                <Printer className="w-3.5 h-3.5 text-cyan-400" />
                <span>Print / PDF</span>
              </button>
            </>
          )}
        </div>
      </div>

      {/* Error Banners */}
      {(reportsError || saveError) && (
        <div className="bg-red-950/60 border border-red-800 rounded-xl p-3.5 flex items-center justify-between text-xs text-red-200">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{reportsError || saveError}</span>
          </div>
          <button
            onClick={() => {
              setSaveError(null);
              loadReports();
            }}
            className="px-2.5 py-1 bg-red-900/60 hover:bg-red-800 border border-red-700 rounded text-red-200 font-mono text-[11px]"
          >
            Retry
          </button>
        </div>
      )}

      {/* Generator Form & Saved Reports */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
        {incidentReports.length > 0 && (
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800 text-xs font-mono">
            <span className="text-slate-400">Persisted Saved Reports ({incidentReports.length}):</span>
            <select
              value={currentReport?.id || ""}
              onChange={(e) => {
                const found = incidentReports.find((r) => r.id === e.target.value);
                if (found) setCurrentReport(found);
              }}
              className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1 text-xs text-cyan-300 focus:outline-none focus:border-cyan-500 font-mono max-w-md truncate"
            >
              {incidentReports.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.id} - {r.reportTitle || "Report"} ({r.createdAt ? r.createdAt.substring(0, 10) : ""})
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">Generate Report for Alert:</span>
            <select
              value={activeAlert?.id || ""}
              onChange={(e) => setActiveAlertId(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              {alerts.map((a) => (
                <option key={a.id} value={a.id}>
                  [{a.severity}] {a.id} - {a.title.substring(0, 32)}...
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={handleGenerateReport}
            disabled={generating || !activeAlert}
            className="px-5 py-2 rounded-lg bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white font-bold text-xs shadow-lg flex items-center gap-2 transition-all disabled:opacity-50"
          >
            {generating ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Synthesizing Incident Report with Gemini...</span>
              </>
            ) : (
              <>
                <Bot className="w-4 h-4" />
                <span>Generate Comprehensive Incident Report</span>
              </>
            )}
          </button>
        </div>

        {/* Custom Analyst Notes Input */}
        <div className="text-xs">
          <span className="text-slate-400 font-mono block mb-1">
            Optional Lead Analyst Context / Investigation Notes:
          </span>
          <textarea
            rows={2}
            value={analystNotes}
            onChange={(e) => setAnalystNotes(e.target.value)}
            placeholder="Add any specific containment details, user interview feedback, or external forensic findings to include..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
          />
        </div>
      </div>

      {/* Rendered Incident Report Paper View */}
      {currentReport ? (
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-8 space-y-6 shadow-2xl text-slate-200 font-sans print:bg-white print:text-black print:border-none print:shadow-none">
          {/* Report Title & Metadata Header */}
          <div className="border-b border-slate-800 pb-5">
            <div className="flex items-center justify-between gap-4 mb-2">
              <span className="px-2.5 py-0.5 rounded bg-red-950 text-red-300 border border-red-700 font-mono text-[11px] font-bold">
                {currentReport.classification}
              </span>
              <span className="text-xs font-mono text-slate-400">
                Report ID: {currentReport.id}
              </span>
            </div>
            <h2 className="text-2xl font-black text-white tracking-tight">
              {currentReport.reportTitle}
            </h2>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-3 pt-3 border-t border-slate-800/80 text-xs font-mono text-slate-400">
              <div>
                <span>Date Created: </span>
                <strong className="text-slate-200">{currentReport.createdAt.replace("T", " ").substring(0, 19)}</strong>
              </div>
              <div>
                <span>Incident ID: </span>
                <strong className="text-cyan-400">{currentReport.incidentId}</strong>
              </div>
              <div>
                <span>Target Asset: </span>
                <strong className="text-slate-200">{currentReport.affectedAssets.join(", ")}</strong>
              </div>
              <div>
                <span>Target User: </span>
                <strong className="text-slate-200">{currentReport.affectedUsers.join(", ")}</strong>
              </div>
            </div>
          </div>

          {/* Section 1: Executive Summary */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold font-mono text-cyan-400 uppercase tracking-wider">
              1. Executive Summary
            </h3>
            <p className="text-xs leading-relaxed text-slate-300">
              {currentReport.executiveSummary}
            </p>
          </div>

          {/* Section 2: Detailed Incident Description & Scope */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold font-mono text-cyan-400 uppercase tracking-wider">
              2. Incident Description & Initial Detection
            </h3>
            <p className="text-xs leading-relaxed text-slate-300">
              {currentReport.incidentDescription}
            </p>
            <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 text-xs font-mono">
              Detection Mechanism: <strong className="text-slate-100">{currentReport.detectionMethod}</strong>
            </div>
          </div>

          {/* Section 3: Root Cause Analysis */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold font-mono text-cyan-400 uppercase tracking-wider">
              3. Root Cause Analysis
            </h3>
            <p className="text-xs leading-relaxed text-slate-300">
              {currentReport.rootCauseAnalysis}
            </p>
          </div>

          {/* Section 4: Quantitative Risk Assessment */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold font-mono text-cyan-400 uppercase tracking-wider">
              4. Quantitative Risk Assessment & Business Impact
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-900 p-3 rounded-lg border border-slate-800 text-xs font-mono">
              <div>
                <span className="text-slate-500 block text-[10px]">Calculated Risk</span>
                <span className="font-bold text-red-400 text-base">
                  {currentReport.riskAssessment.quantitativeScore}/100
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Confidentiality</span>
                <span className="font-bold text-orange-400">
                  {currentReport.riskAssessment.confidentialityImpact}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Integrity</span>
                <span className="font-bold text-amber-400">
                  {currentReport.riskAssessment.integrityImpact}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Availability</span>
                <span className="font-bold text-emerald-400">
                  {currentReport.riskAssessment.availabilityImpact}
                </span>
              </div>
            </div>
          </div>

          {/* Section 5: Containment & Remediation */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold font-mono text-cyan-400 uppercase tracking-wider">
              5. Containment, Eradication & Remediation Actions
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-slate-900 p-3.5 rounded-lg border border-slate-800 text-xs">
                <h5 className="font-semibold text-red-300 font-mono mb-1.5">Containment Executed:</h5>
                <ul className="space-y-1 text-slate-300 list-disc list-inside">
                  {currentReport.containmentActionsCompleted.map((c, i) => (
                    <li key={i}>{c}</li>
                  ))}
                </ul>
              </div>
              <div className="bg-slate-900 p-3.5 rounded-lg border border-slate-800 text-xs">
                <h5 className="font-semibold text-emerald-300 font-mono mb-1.5">Eradication & Recovery:</h5>
                <ul className="space-y-1 text-slate-300 list-disc list-inside">
                  {currentReport.eradicationAndRemediation.map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          {/* Section 6: Lessons Learned & Preventative Controls */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold font-mono text-cyan-400 uppercase tracking-wider">
              6. Preventative Controls & Hardening Playbook
            </h3>
            <ul className="space-y-1.5 text-xs text-slate-300 list-disc list-inside bg-slate-900 p-3.5 rounded-lg border border-slate-800">
              {currentReport.lessonsLearnedAndPreventativeControls.map((l, i) => (
                <li key={i}>{l}</li>
              ))}
            </ul>
          </div>

          {/* Section 7: Analyst Conclusion */}
          <div className="p-4 bg-emerald-950/40 border border-emerald-500/40 rounded-lg space-y-1 text-xs">
            <h4 className="font-bold text-emerald-300 font-mono">7. Lead Incident Handler Conclusion</h4>
            <p className="text-slate-300 leading-relaxed">{currentReport.analystConclusion}</p>
          </div>
        </div>
      ) : (
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-12 text-center space-y-3">
          <FileText className="w-12 h-12 text-emerald-500/50 mx-auto" />
          <h3 className="font-bold text-sm text-slate-200">No Incident Report Generated Yet</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Select an alert above and click &quot;Generate Comprehensive Incident Report&quot; to synthesize an audit-ready NIST incident brief.
          </p>
        </div>
      )}
    </div>
  );
};
