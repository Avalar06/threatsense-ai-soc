import React, { useState, useMemo, useEffect } from "react";
import { useSoc } from "../context/SocContext.js";
import {
  FolderKanban,
  ShieldAlert,
  Search,
  Filter,
  Plus,
  RefreshCw,
  Clock,
  UserCheck,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  Shield,
  Layers,
  FileText,
  Copy,
  Check,
  Edit3,
  Save,
  X,
  Flame,
  Terminal,
  Activity,
} from "lucide-react";
import { SeverityBadge } from "../components/common/SeverityBadge.js";
import { RiskScoreMeter } from "../components/common/RiskScoreMeter.js";
import { MitreTag } from "../components/common/MitreTag.js";
import { Incident, IncidentStatus, Severity, Alert } from "../types/soc.js";

const ANALYST_OPTIONS = [
  "SOC-Tier2-Analyst",
  "Incident-Responder-Lead",
  "Threat-Hunter",
  "SOC-Tier1-Triage",
  "Senior-Security-Analyst",
  "Unassigned",
];

const STATUS_CONFIG: Record<
  IncidentStatus,
  { label: string; bg: string; text: string; border: string; dot: string }
> = {
  NEW: {
    label: "NEW",
    bg: "bg-blue-950/80",
    text: "text-blue-300",
    border: "border-blue-700/60",
    dot: "bg-blue-400",
  },
  OPEN: {
    label: "OPEN",
    bg: "bg-amber-950/80",
    text: "text-amber-300",
    border: "border-amber-700/60",
    dot: "bg-amber-400",
  },
  INVESTIGATING: {
    label: "INVESTIGATING",
    bg: "bg-purple-950/80",
    text: "text-purple-300",
    border: "border-purple-700/60",
    dot: "bg-purple-400",
  },
  CONTAINED: {
    label: "CONTAINED",
    bg: "bg-cyan-950/80",
    text: "text-cyan-300",
    border: "border-cyan-700/60",
    dot: "bg-cyan-400",
  },
  RESOLVED: {
    label: "RESOLVED",
    bg: "bg-emerald-950/80",
    text: "text-emerald-300",
    border: "border-emerald-700/60",
    dot: "bg-emerald-400",
  },
  CLOSED: {
    label: "CLOSED",
    bg: "bg-slate-900",
    text: "text-slate-400",
    border: "border-slate-800",
    dot: "bg-slate-500",
  },
};

const PRIORITY_CONFIG: Record<string, { bg: string; text: string; border: string }> = {
  P1: { bg: "bg-red-950/80", text: "text-red-300", border: "border-red-600/60" },
  P2: { bg: "bg-orange-950/80", text: "text-orange-300", border: "border-orange-600/60" },
  P3: { bg: "bg-amber-950/80", text: "text-amber-300", border: "border-amber-600/60" },
  P4: { bg: "bg-blue-950/80", text: "text-blue-300", border: "border-blue-600/60" },
};

export const IncidentsView: React.FC = () => {
  const {
    incidents,
    alerts,
    events,
    incidentsLoading,
    incidentsError,
    loadIncidents,
    activeIncidentId,
    setActiveIncidentId,
    updateIncidentRecord,
    createIncidentRecord,
    openInvestigationForAlert,
    setActiveTab,
  } = useSoc();

  // Filters
  const [search, setSearch] = useState("");
  const [selectedStatus, setSelectedStatus] = useState<string>("ALL");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [selectedPriority, setSelectedPriority] = useState<string>("ALL");
  const [selectedAnalyst, setSelectedAnalyst] = useState<string>("ALL");

  // Edit states for active incident
  const [editingTitle, setEditingTitle] = useState(false);
  const [titleValue, setTitleValue] = useState("");
  const [editingSummary, setEditingSummary] = useState(false);
  const [summaryValue, setSummaryValue] = useState("");
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccessMessage, setSaveSuccessMessage] = useState<string | null>(null);
  const [saveErrorMessage, setSaveErrorMessage] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // New Incident Modal state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newSeverity, setNewSeverity] = useState<Severity>("HIGH");
  const [newPriority, setNewPriority] = useState("P2");
  const [newAnalyst, setNewAnalyst] = useState("SOC-Tier2-Analyst");
  const [newSummary, setNewSummary] = useState("");
  const [newAlertIds, setNewAlertIds] = useState<string[]>([]);
  const [isCreating, setIsCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Filtered incidents
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      if (selectedStatus !== "ALL" && inc.status !== selectedStatus) return false;
      if (selectedSeverity !== "ALL" && inc.severity !== selectedSeverity) return false;
      if (selectedPriority !== "ALL" && inc.priority !== selectedPriority) return false;
      if (selectedAnalyst !== "ALL" && (inc.leadAnalyst || "Unassigned") !== selectedAnalyst) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchesTitle = inc.title.toLowerCase().includes(q);
        const matchesId = inc.id.toLowerCase().includes(q);
        const matchesAnalyst = inc.leadAnalyst ? inc.leadAnalyst.toLowerCase().includes(q) : false;
        const matchesSummary = inc.executiveSummary ? inc.executiveSummary.toLowerCase().includes(q) : false;
        return matchesTitle || matchesId || matchesAnalyst || matchesSummary;
      }
      return true;
    });
  }, [incidents, selectedStatus, selectedSeverity, selectedPriority, selectedAnalyst, search]);

  // Active Incident Selection
  const activeIncident = useMemo(() => {
    if (!activeIncidentId) return filteredIncidents[0] || incidents[0] || null;
    const found = incidents.find((i) => i.id === activeIncidentId);
    return found || filteredIncidents[0] || incidents[0] || null;
  }, [activeIncidentId, incidents, filteredIncidents]);

  // Sync edit values when active incident changes
  useEffect(() => {
    if (activeIncident) {
      setTitleValue(activeIncident.title);
      setSummaryValue(activeIncident.executiveSummary || "");
      setEditingTitle(false);
      setEditingSummary(false);
      setSaveSuccessMessage(null);
      setSaveErrorMessage(null);
    }
  }, [activeIncident?.id]);

  // Linked Alerts for Active Incident
  const linkedAlerts = useMemo<Alert[]>(() => {
    if (!activeIncident || !activeIncident.alertIds) return [];
    return activeIncident.alertIds
      .map((id) => alerts.find((a) => a.id === id))
      .filter((a): a is Alert => Boolean(a));
  }, [activeIncident, alerts]);

  // Correlated Events for Active Incident
  const correlatedEvents = useMemo(() => {
    if (!linkedAlerts.length) return [];
    const eventIds = new Set<string>();
    linkedAlerts.forEach((a) => {
      a.relatedEventIds?.forEach((eId) => eventIds.add(eId));
    });
    return events.filter((e) => eventIds.has(e.id));
  }, [linkedAlerts, events]);

  const showToast = (msg: string, isError = false) => {
    if (isError) {
      setSaveErrorMessage(msg);
      setSaveSuccessMessage(null);
    } else {
      setSaveSuccessMessage(msg);
      setSaveErrorMessage(null);
    }
    setTimeout(() => {
      setSaveSuccessMessage(null);
      setSaveErrorMessage(null);
    }, 3500);
  };

  const handleUpdateField = async (updates: Partial<Incident>) => {
    if (!activeIncident) return;
    setIsSaving(true);
    try {
      await updateIncidentRecord(activeIncident.id, updates);
      showToast("Incident updated successfully");
    } catch (err: any) {
      showToast(err.message || "Failed to update incident", true);
    } finally {
      setIsSaving(false);
    }
  };

  const handleSaveTitle = async () => {
    if (!activeIncident || !titleValue.trim()) return;
    await handleUpdateField({ title: titleValue.trim() });
    setEditingTitle(false);
  };

  const handleSaveSummary = async () => {
    if (!activeIncident) return;
    await handleUpdateField({ executiveSummary: summaryValue });
    setEditingSummary(false);
  };

  const handleCopyId = (id: string) => {
    navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) {
      setCreateError("Please provide an incident title.");
      return;
    }
    setIsCreating(true);
    setCreateError(null);
    try {
      const created = await createIncidentRecord({
        title: newTitle.trim(),
        severity: newSeverity,
        priority: newPriority,
        status: "OPEN",
        leadAnalyst: newAnalyst,
        executiveSummary: newSummary,
        alertIds: newAlertIds,
        containmentActions: [],
      });
      setShowCreateModal(false);
      setNewTitle("");
      setNewSummary("");
      setNewAlertIds([]);
      setActiveIncidentId(created.id);
      showToast(`Created incident ${created.id}`);
    } catch (err: any) {
      setCreateError(err.message || "Failed to create incident");
    } finally {
      setIsCreating(false);
    }
  };

  const resetFilters = () => {
    setSearch("");
    setSelectedStatus("ALL");
    setSelectedSeverity("ALL");
    setSelectedPriority("ALL");
    setSelectedAnalyst("ALL");
  };

  return (
    <div className="p-6 space-y-6 max-w-[1680px] mx-auto overflow-y-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-amber-950 border border-amber-700/60 text-amber-300 font-mono text-[11px] font-bold inline-flex items-center gap-1">
              <FolderKanban className="w-3 h-3 text-amber-400" />
              INCIDENT MANAGEMENT WORKSPACE
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Total Incidents: {incidents.length}
            </span>
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight mt-1">
            Security Incidents & Lifecycle Operations
          </h1>
          <p className="text-xs text-slate-400">
            Orchestrate incident triage, ownership assignment, severity escalation, linked detections, and executive summaries.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => loadIncidents()}
            disabled={incidentsLoading}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-semibold text-slate-200 transition-colors disabled:opacity-50"
            title="Reload incidents from database"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${incidentsLoading ? "animate-spin text-cyan-400" : ""}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-gradient-to-r from-amber-600 to-amber-500 hover:from-amber-500 hover:to-amber-400 text-white text-xs font-bold shadow-lg shadow-amber-950/40 transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>Create Incident</span>
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px] max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by incident ID, title, summary, or analyst..."
            className="w-full bg-slate-950 border border-slate-700/80 rounded-lg pl-9 pr-8 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500 font-sans"
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Dropdown Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Status */}
          <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 px-2.5 py-1.5 rounded-lg">
            <span className="text-[11px] font-mono text-slate-400">Status:</span>
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="bg-transparent text-xs text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="ALL" className="bg-slate-950 text-slate-200">All Statuses</option>
              <option value="NEW" className="bg-slate-950 text-blue-300">NEW</option>
              <option value="OPEN" className="bg-slate-950 text-amber-300">OPEN</option>
              <option value="INVESTIGATING" className="bg-slate-950 text-purple-300">INVESTIGATING</option>
              <option value="CONTAINED" className="bg-slate-950 text-cyan-300">CONTAINED</option>
              <option value="RESOLVED" className="bg-slate-950 text-emerald-300">RESOLVED</option>
              <option value="CLOSED" className="bg-slate-950 text-slate-400">CLOSED</option>
            </select>
          </div>

          {/* Severity */}
          <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 px-2.5 py-1.5 rounded-lg">
            <span className="text-[11px] font-mono text-slate-400">Severity:</span>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-transparent text-xs text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="ALL" className="bg-slate-950 text-slate-200">All Severities</option>
              <option value="CRITICAL" className="bg-slate-950 text-red-300">CRITICAL</option>
              <option value="HIGH" className="bg-slate-950 text-orange-300">HIGH</option>
              <option value="MEDIUM" className="bg-slate-950 text-amber-300">MEDIUM</option>
              <option value="LOW" className="bg-slate-950 text-blue-300">LOW</option>
            </select>
          </div>

          {/* Priority */}
          <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 px-2.5 py-1.5 rounded-lg">
            <span className="text-[11px] font-mono text-slate-400">Priority:</span>
            <select
              value={selectedPriority}
              onChange={(e) => setSelectedPriority(e.target.value)}
              className="bg-transparent text-xs text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="ALL" className="bg-slate-950 text-slate-200">All Priorities</option>
              <option value="P1" className="bg-slate-950 text-red-300">P1 - Critical</option>
              <option value="P2" className="bg-slate-950 text-orange-300">P2 - High</option>
              <option value="P3" className="bg-slate-950 text-amber-300">P3 - Medium</option>
              <option value="P4" className="bg-slate-950 text-blue-300">P4 - Low</option>
            </select>
          </div>

          {/* Lead Analyst */}
          <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 px-2.5 py-1.5 rounded-lg">
            <span className="text-[11px] font-mono text-slate-400">Lead:</span>
            <select
              value={selectedAnalyst}
              onChange={(e) => setSelectedAnalyst(e.target.value)}
              className="bg-transparent text-xs text-slate-200 focus:outline-none cursor-pointer max-w-[150px] truncate"
            >
              <option value="ALL" className="bg-slate-950 text-slate-200">All Analysts</option>
              {ANALYST_OPTIONS.map((a) => (
                <option key={a} value={a} className="bg-slate-950 text-slate-200">
                  {a}
                </option>
              ))}
            </select>
          </div>

          {(selectedStatus !== "ALL" ||
            selectedSeverity !== "ALL" ||
            selectedPriority !== "ALL" ||
            selectedAnalyst !== "ALL" ||
            search) && (
            <button
              onClick={resetFilters}
              className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-[11px] text-slate-300 transition-colors font-mono"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Global Error Banner */}
      {incidentsError && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800/80 flex items-center justify-between gap-3 text-xs text-red-200">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{incidentsError}</span>
          </div>
          <button
            onClick={() => loadIncidents()}
            className="px-2.5 py-1 rounded bg-red-900/60 hover:bg-red-800 border border-red-700/60 text-xs font-semibold text-red-100"
          >
            Retry
          </button>
        </div>
      )}

      {/* Save Success / Error Toast notification */}
      {saveSuccessMessage && (
        <div className="p-3 rounded-lg bg-emerald-950/70 border border-emerald-700/80 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{saveSuccessMessage}</span>
        </div>
      )}
      {saveErrorMessage && (
        <div className="p-3 rounded-lg bg-red-950/70 border border-red-700/80 text-red-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{saveErrorMessage}</span>
        </div>
      )}

      {/* Main Workspace Split Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* LEFT COLUMN: Incidents Queue (5 columns on large screens) */}
        <div className="lg:col-span-5 space-y-3">
          <div className="flex items-center justify-between px-1">
            <span className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
              Incident Queue ({filteredIncidents.length})
            </span>
            {incidentsLoading && (
              <span className="text-[11px] font-mono text-cyan-400 flex items-center gap-1">
                <RefreshCw className="w-3 h-3 animate-spin" />
                Loading...
              </span>
            )}
          </div>

          {filteredIncidents.length === 0 ? (
            <div className="p-8 rounded-xl bg-slate-900/60 border border-slate-800 text-center space-y-3">
              <FolderKanban className="w-10 h-10 text-slate-600 mx-auto" />
              <h3 className="text-sm font-bold text-slate-300">No Incidents Found</h3>
              <p className="text-xs text-slate-400 max-w-xs mx-auto">
                No incidents match your current search and filter criteria. You can create a new incident or escalate alerts from the queue.
              </p>
              <div className="flex justify-center gap-2 pt-2">
                <button
                  onClick={resetFilters}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300"
                >
                  Reset Filters
                </button>
                <button
                  onClick={() => setShowCreateModal(true)}
                  className="px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-xs text-white font-semibold"
                >
                  Create Incident
                </button>
              </div>
            </div>
          ) : (
            <div className="space-y-2.5 max-h-[calc(100vh-260px)] overflow-y-auto pr-1 custom-scrollbar">
              {filteredIncidents.map((incident) => {
                const isSelected = activeIncident?.id === incident.id;
                const statusCfg = STATUS_CONFIG[incident.status as IncidentStatus] || STATUS_CONFIG.OPEN;
                const priorityCfg = PRIORITY_CONFIG[incident.priority || "P2"] || PRIORITY_CONFIG.P2;
                const linkedCount = incident.alertIds ? incident.alertIds.length : 0;

                return (
                  <div
                    key={incident.id}
                    onClick={() => setActiveIncidentId(incident.id)}
                    className={`p-4 rounded-xl border transition-all cursor-pointer text-left space-y-2.5 ${
                      isSelected
                        ? "bg-slate-900/95 border-amber-500/80 shadow-md shadow-amber-950/30 ring-1 ring-amber-500/50"
                        : "bg-slate-900/50 border-slate-800 hover:bg-slate-900/80 hover:border-slate-700"
                    }`}
                  >
                    {/* Top row: ID, Severity, Priority, Status */}
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-xs font-bold text-amber-300">
                          {incident.id}
                        </span>
                        <span
                          className={`px-1.5 py-0.5 rounded border text-[10px] font-mono font-bold uppercase ${priorityCfg.bg} ${priorityCfg.text} ${priorityCfg.border}`}
                        >
                          {incident.priority || "P2"}
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5">
                        <SeverityBadge severity={incident.severity as Severity} size="sm" />
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-mono font-bold uppercase ${statusCfg.bg} ${statusCfg.text} ${statusCfg.border}`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full ${statusCfg.dot}`} />
                          {statusCfg.label}
                        </span>
                      </div>
                    </div>

                    {/* Title */}
                    <h4 className="text-xs font-bold text-slate-100 line-clamp-2 leading-relaxed">
                      {incident.title}
                    </h4>

                    {/* Footer metadata */}
                    <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono pt-1 border-t border-slate-800/60">
                      <div className="flex items-center gap-1.5 truncate max-w-[200px]">
                        <UserCheck className="w-3 h-3 text-slate-500 shrink-0" />
                        <span className="truncate">{incident.leadAnalyst || "Unassigned"}</span>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        {linkedCount > 0 && (
                          <span className="px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 text-[10px] font-bold">
                            {linkedCount} {linkedCount === 1 ? "Alert" : "Alerts"}
                          </span>
                        )}
                        <span className="text-[10px] text-slate-500">
                          {new Date(incident.createdAt).toLocaleDateString(undefined, {
                            month: "short",
                            day: "numeric",
                          })}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* RIGHT COLUMN: Detail & Lifecycle Management Panel (7 columns on large screens) */}
        <div className="lg:col-span-7">
          {!activeIncident ? (
            <div className="p-12 rounded-xl bg-slate-900/60 border border-slate-800 text-center space-y-3">
              <FolderKanban className="w-12 h-12 text-slate-600 mx-auto" />
              <h3 className="text-base font-bold text-white">No Incident Selected</h3>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">
                Select an incident from the queue to manage lifecycle status, priority, lead analyst, linked detections, and executive notes.
              </p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Incident Header & Lifecycle Controls Card */}
              <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4 shadow-lg">
                {/* Top header row */}
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  <div className="space-y-1 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-sm font-extrabold text-amber-400">
                        {activeIncident.id}
                      </span>
                      <button
                        onClick={() => handleCopyId(activeIncident.id)}
                        className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
                        title="Copy Incident ID"
                      >
                        {copiedId === activeIncident.id ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>

                      <span className="text-[11px] font-mono text-slate-500">
                        Created: {new Date(activeIncident.createdAt).toLocaleString()}
                      </span>
                      {activeIncident.closedAt && (
                        <span className="text-[11px] font-mono text-emerald-400">
                          Closed: {new Date(activeIncident.closedAt).toLocaleString()}
                        </span>
                      )}
                    </div>

                    {/* Title (with inline edit) */}
                    {editingTitle ? (
                      <div className="flex items-center gap-2 pt-1">
                        <input
                          type="text"
                          value={titleValue}
                          onChange={(e) => setTitleValue(e.target.value)}
                          className="flex-1 bg-slate-950 border border-amber-500 rounded px-2.5 py-1 text-sm font-bold text-white focus:outline-none"
                          autoFocus
                        />
                        <button
                          onClick={handleSaveTitle}
                          disabled={isSaving || !titleValue.trim()}
                          className="p-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white"
                          title="Save Title"
                        >
                          <Check className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => {
                            setTitleValue(activeIncident.title);
                            setEditingTitle(false);
                          }}
                          className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                          title="Cancel"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 pt-1 group">
                        <h2 className="text-lg font-bold text-white leading-snug">
                          {activeIncident.title}
                        </h2>
                        <button
                          onClick={() => setEditingTitle(true)}
                          className="opacity-0 group-hover:opacity-100 p-1 text-slate-400 hover:text-amber-400 transition-opacity"
                          title="Edit Title"
                        >
                          <Edit3 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setActiveTab("incident-reports")}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 flex items-center gap-1.5 transition-colors"
                    >
                      <FileText className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Reports</span>
                    </button>
                  </div>
                </div>

                {/* Triage & Lifecycle Controls Bar */}
                <div className="pt-3 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {/* Status Dropdown */}
                  <div className="space-y-1">
                    <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">
                      Lifecycle Status
                    </label>
                    <select
                      value={activeIncident.status}
                      disabled={isSaving}
                      onChange={(e) => {
                        const newStatus = e.target.value as IncidentStatus;
                        const updates: Partial<Incident> = { status: newStatus };
                        if (newStatus === "CLOSED" || newStatus === "RESOLVED") {
                          updates.closedAt = new Date().toISOString();
                        }
                        handleUpdateField(updates);
                      }}
                      className="w-full bg-slate-950 border border-slate-700 hover:border-slate-600 rounded-lg px-2.5 py-1.5 text-xs font-bold text-slate-100 focus:outline-none focus:border-amber-500 cursor-pointer"
                    >
                      <option value="NEW" className="bg-slate-950 text-blue-300">NEW</option>
                      <option value="OPEN" className="bg-slate-950 text-amber-300">OPEN</option>
                      <option value="INVESTIGATING" className="bg-slate-950 text-purple-300">INVESTIGATING</option>
                      <option value="CONTAINED" className="bg-slate-950 text-cyan-300">CONTAINED</option>
                      <option value="RESOLVED" className="bg-slate-950 text-emerald-300">RESOLVED</option>
                      <option value="CLOSED" className="bg-slate-950 text-slate-400">CLOSED</option>
                    </select>
                  </div>

                  {/* Severity Dropdown */}
                  <div className="space-y-1">
                    <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">
                      Severity Level
                    </label>
                    <select
                      value={activeIncident.severity}
                      disabled={isSaving}
                      onChange={(e) => handleUpdateField({ severity: e.target.value as Severity })}
                      className="w-full bg-slate-950 border border-slate-700 hover:border-slate-600 rounded-lg px-2.5 py-1.5 text-xs font-bold text-slate-100 focus:outline-none focus:border-amber-500 cursor-pointer"
                    >
                      <option value="CRITICAL" className="bg-slate-950 text-red-300">CRITICAL</option>
                      <option value="HIGH" className="bg-slate-950 text-orange-300">HIGH</option>
                      <option value="MEDIUM" className="bg-slate-950 text-amber-300">MEDIUM</option>
                      <option value="LOW" className="bg-slate-950 text-blue-300">LOW</option>
                    </select>
                  </div>

                  {/* Priority Dropdown */}
                  <div className="space-y-1">
                    <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">
                      Priority Rank
                    </label>
                    <select
                      value={activeIncident.priority || "P2"}
                      disabled={isSaving}
                      onChange={(e) => handleUpdateField({ priority: e.target.value })}
                      className="w-full bg-slate-950 border border-slate-700 hover:border-slate-600 rounded-lg px-2.5 py-1.5 text-xs font-bold text-slate-100 focus:outline-none focus:border-amber-500 cursor-pointer"
                    >
                      <option value="P1" className="bg-slate-950 text-red-300">P1 - Immediate</option>
                      <option value="P2" className="bg-slate-950 text-orange-300">P2 - High</option>
                      <option value="P3" className="bg-slate-950 text-amber-300">P3 - Medium</option>
                      <option value="P4" className="bg-slate-950 text-blue-300">P4 - Low</option>
                    </select>
                  </div>

                  {/* Lead Analyst Dropdown */}
                  <div className="space-y-1">
                    <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">
                      Lead Analyst
                    </label>
                    <select
                      value={activeIncident.leadAnalyst || "Unassigned"}
                      disabled={isSaving}
                      onChange={(e) => handleUpdateField({ leadAnalyst: e.target.value })}
                      className="w-full bg-slate-950 border border-slate-700 hover:border-slate-600 rounded-lg px-2.5 py-1.5 text-xs font-bold text-slate-100 focus:outline-none focus:border-amber-500 cursor-pointer truncate"
                    >
                      {ANALYST_OPTIONS.map((analyst) => (
                        <option key={analyst} value={analyst} className="bg-slate-950 text-slate-100">
                          {analyst}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>

              {/* Executive Summary Section */}
              <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-amber-400" />
                    <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
                      Executive Summary & Incident Notes
                    </h3>
                  </div>

                  {!editingSummary ? (
                    <button
                      onClick={() => {
                        setSummaryValue(activeIncident.executiveSummary || "");
                        setEditingSummary(true);
                      }}
                      className="flex items-center gap-1 text-xs font-semibold text-amber-400 hover:text-amber-300 transition-colors"
                    >
                      <Edit3 className="w-3.5 h-3.5" />
                      <span>Edit Summary</span>
                    </button>
                  ) : (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleSaveSummary}
                        disabled={isSaving}
                        className="flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold"
                      >
                        <Save className="w-3.5 h-3.5" />
                        <span>Save</span>
                      </button>
                      <button
                        onClick={() => {
                          setSummaryValue(activeIncident.executiveSummary || "");
                          setEditingSummary(false);
                        }}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
                      >
                        Cancel
                      </button>
                    </div>
                  )}
                </div>

                {editingSummary ? (
                  <textarea
                    value={summaryValue}
                    onChange={(e) => setSummaryValue(e.target.value)}
                    rows={5}
                    placeholder="Enter incident context, attack blast radius, initial findings, or escalation notes..."
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-sans leading-relaxed"
                  />
                ) : (
                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs text-slate-300 leading-relaxed min-h-[60px] whitespace-pre-wrap font-sans">
                    {activeIncident.executiveSummary || (
                      <span className="text-slate-500 italic">
                        No executive summary provided. Click "Edit Summary" to add analyst findings and impact analysis.
                      </span>
                    )}
                  </div>
                )}
              </div>

              {/* Linked Alerts Section */}
              <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-cyan-400" />
                    <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
                      Linked Security Alerts ({linkedAlerts.length})
                    </h3>
                  </div>

                  {linkedAlerts.length > 0 && (
                    <button
                      onClick={() => openInvestigationForAlert(linkedAlerts[0].id)}
                      className="flex items-center gap-1 text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition-colors"
                    >
                      <span>Investigate Primary Alert</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>

                {linkedAlerts.length === 0 ? (
                  <div className="p-6 rounded-lg bg-slate-950/50 border border-slate-800 text-center space-y-2">
                    <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto" />
                    <p className="text-xs text-slate-400">
                      No security alerts currently linked to this incident.
                    </p>
                    <button
                      onClick={() => setActiveTab("alerts")}
                      className="px-3 py-1.5 rounded bg-cyan-950 border border-cyan-700/60 text-cyan-300 text-xs font-semibold hover:bg-cyan-900/60"
                    >
                      Browse Alerts Queue
                    </button>
                  </div>
                ) : (
                  <div className="space-y-2.5">
                    {linkedAlerts.map((alert) => (
                      <div
                        key={alert.id}
                        className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800 hover:border-slate-700 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                      >
                        <div className="space-y-1.5 flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-xs font-bold text-cyan-400">
                              {alert.id}
                            </span>
                            <SeverityBadge severity={alert.severity} size="sm" />
                            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 font-mono text-[10px]">
                              {alert.status}
                            </span>
                            <span className="text-[10px] font-mono text-slate-500">
                              Source: {alert.detectionSource}
                            </span>
                          </div>

                          <h5 className="text-xs font-bold text-slate-100 truncate">
                            {alert.title}
                          </h5>

                          <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400 flex-wrap">
                            <span>Host: <strong className="text-slate-300">{alert.host}</strong></span>
                            <span>IP: <strong className="text-slate-300">{alert.sourceIp}</strong></span>
                            <span>Risk Score: <strong className="text-amber-400">{alert.riskScore}/100</strong></span>
                          </div>
                        </div>

                        <button
                          onClick={() => openInvestigationForAlert(alert.id)}
                          className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-cyan-950/80 border border-slate-700 hover:border-cyan-600 text-xs font-semibold text-cyan-300 flex items-center gap-1.5 shrink-0 transition-colors"
                          title="Open Alert in Investigation Workspace"
                        >
                          <span>Investigate</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Correlated Security Events */}
              {correlatedEvents.length > 0 && (
                <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-purple-400" />
                      <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
                        Correlated Security Events ({correlatedEvents.length})
                      </h3>
                    </div>
                  </div>

                  <div className="space-y-2 max-h-60 overflow-y-auto pr-1 custom-scrollbar">
                    {correlatedEvents.slice(0, 10).map((evt) => (
                      <div
                        key={evt.id}
                        className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80 text-xs space-y-1 font-mono"
                      >
                        <div className="flex items-center justify-between text-[10px] text-slate-400">
                          <span className="text-purple-400 font-bold">{evt.event_type}</span>
                          <span>{evt.timestamp}</span>
                        </div>
                        <p className="text-slate-200 text-[11px] font-sans">
                          {evt.message || evt.raw}
                        </p>
                        <div className="flex items-center gap-2 text-[10px] text-slate-500">
                          <span>Host: {evt.hostname}</span>
                          <span>User: {evt.username}</span>
                          <span>Action: {evt.action}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Containment Tracking Section (Read-Only Placeholder for Phase 4B-B) */}
              <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-emerald-400" />
                    <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
                      Containment Actions
                    </h3>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono text-[10px]">
                    Read-Only
                  </span>
                </div>

                {activeIncident.containmentActions && activeIncident.containmentActions.length > 0 ? (
                  <div className="space-y-1.5">
                    {activeIncident.containmentActions.map((action, idx) => (
                      <div
                        key={idx}
                        className="p-2 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-300 flex items-center gap-2"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        <span>{action}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 rounded bg-slate-950/60 border border-slate-800/80 text-xs text-slate-500 italic font-mono">
                    No active containment actions logged. Host isolation & network quarantine tracking will be enabled in Phase 4B-B.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* CREATE INCIDENT MODAL */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FolderKanban className="w-5 h-5 text-amber-400" />
                <h3 className="text-base font-bold text-white">Create Security Incident</h3>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {createError && (
              <div className="p-3 rounded bg-red-950/60 border border-red-800 text-xs text-red-200 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{createError}</span>
              </div>
            )}

            <form onSubmit={handleCreateIncident} className="space-y-3.5 text-xs">
              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">Incident Title *</label>
                <input
                  type="text"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g., Active Directory Compromise & Kerberoasting Activity"
                  required
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-amber-500"
                />
              </div>

              <div className="grid grid-cols-3 gap-2">
                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as Severity)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-200 focus:outline-none focus:border-amber-500"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Priority</label>
                  <select
                    value={newPriority}
                    onChange={(e) => setNewPriority(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-200 focus:outline-none focus:border-amber-500"
                  >
                    <option value="P1">P1 - Critical</option>
                    <option value="P2">P2 - High</option>
                    <option value="P3">P3 - Medium</option>
                    <option value="P4">P4 - Low</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold">Lead Analyst</label>
                  <select
                    value={newAnalyst}
                    onChange={(e) => setNewAnalyst(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-200 focus:outline-none focus:border-amber-500 truncate"
                  >
                    {ANALYST_OPTIONS.map((a) => (
                      <option key={a} value={a}>
                        {a}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">Executive Summary</label>
                <textarea
                  value={newSummary}
                  onChange={(e) => setNewSummary(e.target.value)}
                  rows={3}
                  placeholder="Provide incident context, attack surface, or affected assets..."
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-amber-500 font-sans"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isCreating || !newTitle.trim()}
                  className="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white font-bold"
                >
                  {isCreating ? "Creating..." : "Create Incident"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
