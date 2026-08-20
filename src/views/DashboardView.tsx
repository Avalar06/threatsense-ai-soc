import React, { useState, useMemo } from "react";
import { useSoc } from "../context/SocContext.js";
import {
  ShieldAlert,
  AlertTriangle,
  Flame,
  Activity,
  Search,
  Fingerprint,
  CheckCircle2,
  FileSearch,
  Zap,
  ArrowRight,
  Filter,
  ExternalLink,
  Shield,
  Layers,
  Terminal,
} from "lucide-react";
import { ThreatActivityChart } from "../components/charts/ThreatActivityChart.js";
import { SeverityDistributionChart } from "../components/charts/SeverityDistributionChart.js";
import { SeverityBadge } from "../components/common/SeverityBadge.js";
import { RiskScoreMeter } from "../components/common/RiskScoreMeter.js";
import { MitreTag } from "../components/common/MitreTag.js";
import { AlertStatus, Severity } from "../types/soc.js";
import { SAMPLE_SCENARIOS } from "../data/sampleLogs.js";

export const DashboardView: React.FC = () => {
  const {
    events,
    alerts,
    iocs,
    dashboardStats,
    statsLoading,
    statsError,
    alertsLoading,
    alertsError,
    setActiveTab,
    openInvestigationForAlert,
    updateAlertStatus,
    loadScenario,
    activeScenarioId,
    loadDashboardStats,
    loadAlerts,
  } = useSoc();

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [selectedStatus, setSelectedStatus] = useState<string>("ALL");
  const [selectedDetectionSource, setSelectedDetectionSource] = useState<string>("ALL");

  // Metrics (prioritizing persistent backend dashboardStats with local fallback)
  const metrics = useMemo(() => {
    const totalAlerts = dashboardStats?.totalAlerts ?? alerts.length;
    const criticalAlerts = dashboardStats?.criticalAlerts ?? alerts.filter((a) => a.severity === "CRITICAL").length;
    const highAlerts = dashboardStats?.highAlerts ?? alerts.filter((a) => a.severity === "HIGH").length;
    const mediumAlerts = dashboardStats?.mediumAlerts ?? alerts.filter((a) => a.severity === "MEDIUM").length;
    const detectedAnomalies = events.filter(
      (e) => e.status === "FLAGGED" || e.status === "ANOMALOUS" || e.severity === "CRITICAL"
    ).length;
    const activeInvestigations = (dashboardStats?.investigatingAlerts ?? 0) + (dashboardStats?.newAlerts ?? 0) ||
      alerts.filter((a) => a.status === "INVESTIGATING" || a.status === "NEW").length;
    const iocsCount = iocs.length;
    const incidentsResolved = dashboardStats?.resolvedAlerts ?? alerts.filter((a) => a.status === "RESOLVED").length;
    const activeHosts = dashboardStats?.activeHosts ?? new Set(alerts.map((a) => a.host).filter(Boolean)).size;
    const averageRiskScore = dashboardStats?.averageRiskScore ?? (alerts.length > 0 ? Math.round(alerts.reduce((acc, a) => acc + (a.riskScore || 0), 0) / alerts.length) : 0);

    return {
      totalAlerts,
      criticalAlerts,
      highAlerts,
      mediumAlerts,
      detectedAnomalies,
      activeInvestigations,
      iocsCount,
      incidentsResolved,
      activeHosts,
      averageRiskScore,
    };
  }, [dashboardStats, alerts, events, iocs]);

  // Filtered alerts
  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (selectedSeverity !== "ALL" && a.severity !== selectedSeverity) return false;
      if (selectedStatus !== "ALL" && a.status !== selectedStatus) return false;
      if (selectedDetectionSource !== "ALL" && a.detectionSource !== selectedDetectionSource) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          a.title.toLowerCase().includes(q) ||
          a.host.toLowerCase().includes(q) ||
          a.sourceIp.toLowerCase().includes(q) ||
          a.username.toLowerCase().includes(q) ||
          a.id.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [alerts, selectedSeverity, selectedStatus, selectedDetectionSource, searchQuery]);

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto overflow-y-auto">
      {/* Top Banner / Scenario Info */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/90 to-indigo-950/40 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-700/60 text-cyan-300 font-mono text-[11px] font-bold">
              SOC COMMAND CENTER
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Host Environment: CORP-PROD-DMZ
            </span>
          </div>
          <h1 className="text-xl font-extrabold text-white tracking-tight">
            Security Operations & Threat Investigation Overview
          </h1>
          <p className="text-xs text-slate-300">
            Real-time hybrid detection (Rule-based correlation, Statistical anomaly modeling, and Gemini 3.7 AI reasoning).
          </p>
        </div>

        {/* Quick Scenario Preset Chips */}
        <div className="flex items-center flex-wrap gap-2">
          <span className="text-xs text-slate-400 font-mono flex items-center gap-1">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            Quick Scenarios:
          </span>
          {SAMPLE_SCENARIOS.slice(0, 3).map((sc) => (
            <button
              key={sc.id}
              onClick={() => loadScenario(sc.id)}
              className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-all ${
                activeScenarioId === sc.id
                  ? "bg-cyan-950 text-cyan-300 border border-cyan-500 font-bold"
                  : "bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700"
              }`}
            >
              {sc.name.split(" ")[0]} ({sc.category.split(" ")[0]})
            </button>
          ))}
        </div>
      </div>

      {/* Error Banners */}
      {(statsError || alertsError) && (
        <div className="bg-red-950/60 border border-red-800 rounded-xl p-3.5 flex items-center justify-between text-xs text-red-200">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{statsError || alertsError} (Using cached/fallback values)</span>
          </div>
          <button
            onClick={() => {
              loadDashboardStats();
              loadAlerts();
            }}
            className="px-2.5 py-1 bg-red-900/60 hover:bg-red-800 border border-red-700 rounded text-red-200 font-mono text-[11px]"
          >
            Retry
          </button>
        </div>
      )}

      {/* 8 Top-Level Security KPI Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
        {/* Total Alerts */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Total Alerts</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-white">{metrics.totalAlerts}</span>
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
          </div>
          <span className="text-[10px] text-slate-400 font-mono">Normalized stream</span>
        </div>

        {/* Critical Alerts */}
        <div className="bg-red-950/30 border border-red-800/50 rounded-xl p-3.5 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-red-300 uppercase tracking-wider">Critical</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-red-400">{metrics.criticalAlerts}</span>
            <Flame className="w-4 h-4 text-red-400 animate-pulse" />
          </div>
          <span className="text-[10px] text-red-300/70 font-mono">Immediate SLA</span>
        </div>

        {/* High Alerts */}
        <div className="bg-orange-950/30 border border-orange-800/50 rounded-xl p-3.5 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-orange-300 uppercase tracking-wider">High</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-orange-400">{metrics.highAlerts}</span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <span className="text-[10px] text-orange-300/70 font-mono">High priority</span>
        </div>

        {/* Medium Alerts */}
        <div className="bg-amber-950/30 border border-amber-800/50 rounded-xl p-3.5 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-amber-300 uppercase tracking-wider">Medium</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-amber-400">{metrics.mediumAlerts}</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <span className="text-[10px] text-amber-300/70 font-mono">Triage pool</span>
        </div>

        {/* Detected Anomalies */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Anomalies</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-purple-400">{metrics.detectedAnomalies}</span>
            <Zap className="w-4 h-4 text-purple-400" />
          </div>
          <span className="text-[10px] text-slate-400 font-mono">Statistical flags</span>
        </div>

        {/* Active Investigations */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Investigations</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-cyan-400">{metrics.activeInvestigations}</span>
            <FileSearch className="w-4 h-4 text-cyan-400" />
          </div>
          <span className="text-[10px] text-slate-400 font-mono">In-progress</span>
        </div>

        {/* IOCs Detected */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">IOCs</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-emerald-400">{metrics.iocsCount}</span>
            <Fingerprint className="w-4 h-4 text-emerald-400" />
          </div>
          <span className="text-[10px] text-slate-400 font-mono">Extracted indicators</span>
        </div>

        {/* Incidents Resolved */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Resolved</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-slate-200">{metrics.incidentsResolved}</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <span className="text-[10px] text-slate-400 font-mono">Remediated</span>
        </div>
      </div>

      {/* Visual Analytics Row: Threat Activity Time Series & Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <ThreatActivityChart events={events} />
        </div>
        <div>
          <SeverityDistributionChart alerts={alerts} />
        </div>
      </div>

      {/* Recent Alerts Section */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        {/* Table Filter Controls Header */}
        <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              Security Alerts Queue
              <span className="text-xs font-mono font-normal text-slate-400">
                ({filteredAlerts.length} of {alerts.length})
              </span>
            </h2>
            <p className="text-xs text-slate-400">Prioritized triage queue with calculated risk scoring</p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
            {/* Search Input */}
            <div className="relative flex-1 md:w-60">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 transform -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search alerts, hosts, IPs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-700/80 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {/* Severity Filter */}
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            {/* Status Filter */}
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Statuses</option>
              <option value="NEW">New</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="CONTAINED">Contained</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>

            {/* Source Filter */}
            <select
              value={selectedDetectionSource}
              onChange={(e) => setSelectedDetectionSource(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Detection Sources</option>
              <option value="RULE_BASED">Rule-Based</option>
              <option value="ML_ANOMALY">ML Anomaly</option>
              <option value="GEMINI_AI">Gemini AI</option>
            </select>
          </div>
        </div>

        {/* Alerts Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Alert ID / Time</th>
                <th className="px-4 py-3">Detection / Title</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Risk Score</th>
                <th className="px-4 py-3">Host / Source IP</th>
                <th className="px-4 py-3">Username</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300 font-sans">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-10 text-slate-500 font-mono">
                    No alerts match the selected criteria.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    onClick={() => openInvestigationForAlert(alert.id)}
                  >
                    {/* Alert ID & Time */}
                    <td className="px-4 py-3 font-mono">
                      <div className="font-bold text-cyan-400">{alert.id}</div>
                      <div className="text-[10px] text-slate-400">
                        {alert.timestamp.replace("T", " ").replace("Z", "")}
                      </div>
                    </td>

                    {/* Title & Detection Type */}
                    <td className="px-4 py-3">
                      <div className="font-semibold text-slate-100 flex items-center gap-1.5">
                        {alert.title}
                      </div>
                      <div className="flex items-center gap-1.5 mt-1">
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
                          {alert.detectionSource}
                        </span>
                        {alert.mitreTechniques.slice(0, 1).map((t) => (
                          <MitreTag key={t.id} technique={t} compact />
                        ))}
                      </div>
                    </td>

                    {/* Severity */}
                    <td className="px-4 py-3">
                      <SeverityBadge severity={alert.severity} size="sm" />
                    </td>

                    {/* Risk Score Meter */}
                    <td className="px-4 py-3">
                      <RiskScoreMeter score={alert.riskScore} compact />
                    </td>

                    {/* Host / Source IP */}
                    <td className="px-4 py-3 font-mono text-[11px]">
                      <div className="text-slate-200 font-semibold">{alert.host}</div>
                      <div className="text-slate-400 flex items-center gap-1">
                        {alert.sourceIp}
                      </div>
                    </td>

                    {/* Username */}
                    <td className="px-4 py-3 font-mono text-slate-300">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">
                        {alert.username}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3">
                      <select
                        value={alert.status}
                        onClick={(e) => e.stopPropagation()}
                        onChange={(e) => updateAlertStatus(alert.id, e.target.value as AlertStatus)}
                        className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-[11px] font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
                      >
                        <option value="NEW">NEW</option>
                        <option value="INVESTIGATING">INVESTIGATING</option>
                        <option value="CONTAINED">CONTAINED</option>
                        <option value="RESOLVED">RESOLVED</option>
                        <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
                      </select>
                    </td>

                    {/* Actions */}
                    <td className="px-4 py-3 text-right" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => openInvestigationForAlert(alert.id)}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-500/50 text-indigo-200 font-semibold text-xs transition-all shadow-sm group-hover:border-cyan-400"
                      >
                        <span>Investigate</span>
                        <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
