import React, { createContext, useContext, useEffect, useMemo, useState, useCallback } from "react";
import {
  Alert,
  AlertStatus,
  DashboardStats,
  GeminiInvestigationResult,
  Incident,
  IncidentReport,
  IncidentResponseAction,
  IOC,
  IocEnrichment,
  SecurityEvent,
  Severity,
  TimelineEvent,
} from "../types/soc.js";
import { SAMPLE_SCENARIOS } from "../data/sampleLogs.js";
import { extractIocsFromText } from "../services/iocExtractor.js";
import {
  checkBackendHealth,
  investigateAlertWithGemini,
  getDashboardStats as apiGetDashboardStats,
  getAlerts as apiGetAlerts,
  getLogs as apiGetLogs,
  getReports as apiGetReports,
  getIncidents as apiGetIncidents,
  createAlert as apiCreateAlert,
  updateAlert as apiUpdateAlert,
  ingestLogs as apiIngestLogs,
  createReport as apiCreateReport,
  createIncident as apiCreateIncident,
  updateIncident as apiUpdateIncident,
  closeIncident as apiCloseIncident,
  generateIncidentReportFromIncident as apiGenerateIncidentReportFromIncident,
  getIncidentTimeline as apiGetIncidentTimeline,
  getIncidentActions as apiGetIncidentActions,
  createIncidentAction as apiCreateIncidentAction,
  updateIncidentAction as apiUpdateIncidentAction,
  getIocs as apiGetIocs,
  enrichIoc as apiEnrichIoc,
  AlertFilterParams,
  LogFilterParams,
  ReportFilterParams,
  IncidentFilterParams,
  IocFilterParams,
  ApiError,
} from "../services/apiClient.js";

export type SocNavTab =
  | "dashboard"
  | "alerts"
  | "incidents"
  | "log-analyzer"
  | "investigations"
  | "ioc-extractor"
  | "mitre-attack"
  | "phishing-analyzer"
  | "ai-analyst"
  | "incident-reports"
  | "settings";

interface SocContextType {
  activeTab: SocNavTab;
  setActiveTab: (tab: SocNavTab) => void;
  events: SecurityEvent[];
  alerts: Alert[];
  iocs: IOC[];
  incidentReports: IncidentReport[];
  incidents: Incident[];
  incidentActions: IncidentResponseAction[];
  dashboardStats: DashboardStats | null;
  
  // Loading & Error States
  statsLoading: boolean;
  alertsLoading: boolean;
  logsLoading: boolean;
  reportsLoading: boolean;
  incidentsLoading: boolean;
  actionsLoading: boolean;
  iocsLoading: boolean;
  isIngesting: boolean;
  statsError: string | null;
  alertsError: string | null;
  logsError: string | null;
  reportsError: string | null;
  incidentsError: string | null;
  actionsError: string | null;
  iocsError: string | null;

  activeAlertId: string | null;
  setActiveAlertId: (id: string | null) => void;
  activeAlert: Alert | null;
  activeIncidentId: string | null;
  setActiveIncidentId: (id: string | null) => void;
  activeIncident: Incident | null;
  activeInvestigationTimeline: TimelineEvent[];
  activeScenarioId: string;
  backendHealth: { status: string; geminiKeyConfigured: boolean };
  isInvestigating: boolean;

  // Actions
  loadDashboardStats: () => Promise<void>;
  loadAlerts: (filters?: AlertFilterParams) => Promise<void>;
  loadLogs: (filters?: LogFilterParams) => Promise<void>;
  loadReports: (filters?: ReportFilterParams) => Promise<void>;
  loadIncidents: (filters?: IncidentFilterParams) => Promise<void>;
  loadIncidentActions: (incidentId: string) => Promise<void>;
  loadIocs: (filters?: IocFilterParams) => Promise<void>;
  loadScenario: (scenarioId: string) => Promise<void>;
  ingestLogs: (rawLogText: string, defaultHost?: string) => Promise<{ eventsIngested: number; alertsGenerated: number }>;
  triggerAlertInvestigation: (alertId: string, customNotes?: string) => Promise<GeminiInvestigationResult | null>;
  updateAlertStatus: (alertId: string, status: AlertStatus) => Promise<void>;
  assignAlert: (alertId: string, assignedTo: string) => Promise<void>;
  escalateAlertToIncident: (alertId: string, title?: string, severity?: Severity) => Promise<Incident>;
  saveIncidentReport: (report: IncidentReport) => Promise<void>;
  createIncidentRecord: (incident: Partial<Incident>) => Promise<Incident>;
  updateIncidentRecord: (id: string, updates: Partial<Incident>) => Promise<Incident>;
  closeIncidentCase: (incidentId: string, params: { closedBy: string; closureSummary: string }) => Promise<Incident>;
  generateReportForIncident: (incidentId: string, options?: Partial<IncidentReport>) => Promise<IncidentReport>;
  loadIncidentTimeline: (incidentId: string) => Promise<TimelineEvent[]>;
  createIncidentAction: (incidentId: string, action: Partial<IncidentResponseAction>) => Promise<IncidentResponseAction>;
  updateIncidentAction: (incidentId: string, actionId: string, updates: Partial<IncidentResponseAction>) => Promise<IncidentResponseAction>;
  enrichIocRecord: (iocId: string, forceRefresh?: boolean) => Promise<IocEnrichment>;
  resetToDefaultDemo: () => Promise<void>;
  clearAllData: () => void;
  openInvestigationForAlert: (alertId: string) => void;
  openIncident: (incidentId: string) => void;
}

const SocContext = createContext<SocContextType | undefined>(undefined);

export const SocProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeTab, setActiveTab] = useState<SocNavTab>("dashboard");
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [incidentReports, setIncidentReports] = useState<IncidentReport[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [incidentActions, setIncidentActions] = useState<IncidentResponseAction[]>([]);
  const [dashboardStats, setDashboardStats] = useState<DashboardStats | null>(null);

  // Status & Error flags
  const [statsLoading, setStatsLoading] = useState<boolean>(false);
  const [alertsLoading, setAlertsLoading] = useState<boolean>(false);
  const [logsLoading, setLogsLoading] = useState<boolean>(false);
  const [reportsLoading, setReportsLoading] = useState<boolean>(false);
  const [incidentsLoading, setIncidentsLoading] = useState<boolean>(false);
  const [actionsLoading, setActionsLoading] = useState<boolean>(false);
  const [iocsLoading, setIocsLoading] = useState<boolean>(false);
  const [isIngesting, setIsIngesting] = useState<boolean>(false);

  const [statsError, setStatsError] = useState<string | null>(null);
  const [alertsError, setAlertsError] = useState<string | null>(null);
  const [logsError, setLogsError] = useState<string | null>(null);
  const [reportsError, setReportsError] = useState<string | null>(null);
  const [incidentsError, setIncidentsError] = useState<string | null>(null);
  const [actionsError, setActionsError] = useState<string | null>(null);
  const [iocsError, setIocsError] = useState<string | null>(null);

  const [activeAlertId, setActiveAlertId] = useState<string | null>(null);
  const [activeIncidentId, setActiveIncidentId] = useState<string | null>(null);
  const [activeScenarioId, setActiveScenarioId] = useState<string>("scenario-apt-multistage");
  const [isInvestigating, setIsInvestigating] = useState<boolean>(false);
  const [backendHealth, setBackendHealth] = useState<{ status: string; geminiKeyConfigured: boolean }>({
    status: "checking",
    geminiKeyConfigured: false,
  });

  // ----------------------------------------------------
  // DATA LOADERS
  // ----------------------------------------------------
  const loadDashboardStats = useCallback(async () => {
    setStatsLoading(true);
    setStatsError(null);
    try {
      const data = await apiGetDashboardStats();
      setDashboardStats(data);
    } catch (err: any) {
      setStatsError(err.message || "Failed to load dashboard statistics");
    } finally {
      setStatsLoading(false);
    }
  }, []);

  const loadAlerts = useCallback(async (filters?: AlertFilterParams) => {
    setAlertsLoading(true);
    setAlertsError(null);
    try {
      const res = await apiGetAlerts(filters);
      setAlerts(res.alerts);
      if (res.alerts.length > 0) {
        setActiveAlertId((prev) => (prev && res.alerts.some((a) => a.id === prev) ? prev : res.alerts[0].id));
      }
    } catch (err: any) {
      setAlertsError(err.message || "Failed to load alerts");
    } finally {
      setAlertsLoading(false);
    }
  }, []);

  const loadIocs = useCallback(async (filters?: IocFilterParams) => {
    setIocsLoading(true);
    setIocsError(null);
    try {
      const res = await apiGetIocs(filters);
      setIocs(res.iocs);
    } catch (err: any) {
      setIocsError(err.message || "Failed to load IOCs");
    } finally {
      setIocsLoading(false);
    }
  }, []);

  const loadLogs = useCallback(async (filters?: LogFilterParams) => {
    setLogsLoading(true);
    setLogsError(null);
    try {
      const res = await apiGetLogs(filters);
      setEvents(res.events);
      
      // Extract IOCs from loaded events
      const allRaw = res.events.map((e) => `${e.raw} ${e.source_ip} ${e.destination_ip}`).join("\n");
      const extracted = extractIocsFromText(allRaw);
      setIocs(extracted);
    } catch (err: any) {
      setLogsError(err.message || "Failed to load logs");
    } finally {
      setLogsLoading(false);
    }
  }, []);

  const loadReports = useCallback(async (filters?: ReportFilterParams) => {
    setReportsLoading(true);
    setReportsError(null);
    try {
      const res = await apiGetReports(filters);
      setIncidentReports(res.reports);
    } catch (err: any) {
      setReportsError(err.message || "Failed to load incident reports");
    } finally {
      setReportsLoading(false);
    }
  }, []);

  const loadIncidents = useCallback(async (filters?: IncidentFilterParams) => {
    setIncidentsLoading(true);
    setIncidentsError(null);
    try {
      const res = await apiGetIncidents(filters);
      setIncidents(res.incidents);
      if (res.incidents.length > 0) {
        setActiveIncidentId((prev) => (prev && res.incidents.some((i) => i.id === prev) ? prev : res.incidents[0].id));
      }
    } catch (err: any) {
      setIncidentsError(err.message || "Failed to load incidents");
      console.warn("Failed to load incidents:", err);
    } finally {
      setIncidentsLoading(false);
    }
  }, []);

  const loadIncidentActions = useCallback(async (incidentId: string) => {
    if (!incidentId) return;
    setActionsLoading(true);
    setActionsError(null);
    try {
      const actions = await apiGetIncidentActions(incidentId);
      setIncidentActions(actions);
    } catch (err: any) {
      setActionsError(err.message || "Failed to load response actions");
      console.warn("Failed to load incident response actions:", err);
    } finally {
      setActionsLoading(false);
    }
  }, []);

  const loadIncidentTimeline = useCallback(async (incidentId: string): Promise<TimelineEvent[]> => {
    if (!incidentId) return [];
    try {
      return await apiGetIncidentTimeline(incidentId);
    } catch (err) {
      console.warn("Failed to load incident timeline:", err);
      return [];
    }
  }, []);

  const closeIncidentCase = async (
    incidentId: string,
    params: { closedBy: string; closureSummary: string }
  ): Promise<Incident> => {
    const updated = await apiCloseIncident(incidentId, params);
    setIncidents((prev) => prev.map((inc) => (inc.id === incidentId ? { ...inc, ...updated } : inc)));
    await loadDashboardStats();
    return updated;
  };

  const generateReportForIncident = async (
    incidentId: string,
    options?: Partial<IncidentReport>
  ): Promise<IncidentReport> => {
    const report = await apiGenerateIncidentReportFromIncident(incidentId, options);
    setIncidentReports((prev) => [report, ...prev.filter((r) => r.id !== report.id)]);
    await loadReports();
    return report;
  };

  const enrichIocRecord = async (iocId: string, forceRefresh?: boolean): Promise<IocEnrichment> => {
    const res = await apiEnrichIoc(iocId, forceRefresh);
    // Refresh IOC list
    await loadIocs();
    return res.data;
  };

  // Sync incident actions whenever activeIncidentId changes
  useEffect(() => {
    if (activeIncidentId) {
      loadIncidentActions(activeIncidentId);
    } else {
      setIncidentActions([]);
    }
  }, [activeIncidentId, loadIncidentActions]);

  // Ingest logs to backend
  const ingestLogs = useCallback(
    async (rawLogText: string, defaultHost = "CORP-ENDPOINT"): Promise<{ eventsIngested: number; alertsGenerated: number }> => {
      setIsIngesting(true);
      try {
        const result = await apiIngestLogs(rawLogText, defaultHost);
        
        // Refresh persistent backend state
        await Promise.all([
          loadDashboardStats(),
          loadAlerts(),
          loadLogs(),
        ]);

        if (result.alerts && result.alerts.length > 0) {
          setActiveAlertId(result.alerts[0].id);
        }

        // Also extract client-side IOC tags for instant search
        const extractedIocs = extractIocsFromText(rawLogText);
        setIocs((prev) => {
          const valSet = new Set(prev.map((i) => i.value));
          const newOnes = extractedIocs.filter((i) => !valSet.has(i.value));
          return [...newOnes, ...prev];
        });

        return {
          eventsIngested: result.eventsIngested,
          alertsGenerated: result.alertsGenerated,
        };
      } finally {
        setIsIngesting(false);
      }
    },
    [loadDashboardStats, loadAlerts, loadLogs]
  );

  const loadScenario = useCallback(
    async (scenarioId: string) => {
      const scenario = SAMPLE_SCENARIOS.find((s) => s.id === scenarioId) || SAMPLE_SCENARIOS[0];
      setActiveScenarioId(scenario.id);
      await ingestLogs(scenario.rawLog, "FIN-SRV-01");
    },
    [ingestLogs]
  );

  // Initial mount: check health and load all persistent backend data
  useEffect(() => {
    checkBackendHealth().then((res) => {
      setBackendHealth(res);
    });

    const initData = async () => {
      try {
        const alertsRes = await apiGetAlerts({ limit: 50 });
        if (alertsRes.alerts.length > 0) {
          // Persistence already has records, populate from backend
          setAlerts(alertsRes.alerts);
          setActiveAlertId(alertsRes.alerts[0].id);
          await Promise.all([
            loadDashboardStats(),
            loadLogs({ limit: 100 }),
            loadReports(),
            loadIncidents(),
          ]);
        } else {
          // Fresh database: seed default demo scenario into SQLite persistence
          await loadScenario("scenario-apt-multistage");
          await Promise.all([
            loadReports(),
            loadIncidents(),
          ]);
        }
      } catch (err) {
        console.warn("Backend initialization fell back to local scenario:", err);
        await loadScenario("scenario-apt-multistage");
      }
    };

    initData();
  }, [loadDashboardStats, loadLogs, loadReports, loadIncidents, loadScenario]);

  const activeAlert = useMemo(() => {
    if (!activeAlertId) return alerts[0] || null;
    return alerts.find((a) => a.id === activeAlertId) || alerts[0] || null;
  }, [activeAlertId, alerts]);

  const activeIncident = useMemo(() => {
    if (!activeIncidentId) return incidents[0] || null;
    return incidents.find((i) => i.id === activeIncidentId) || incidents[0] || null;
  }, [activeIncidentId, incidents]);

  // Timeline events for active alert
  const activeInvestigationTimeline = useMemo<TimelineEvent[]>(() => {
    if (!activeAlert) return [];

    const related = events.filter((e) => activeAlert.relatedEventIds?.includes(e.id));
    const sorted = related.length > 0 ? related : events.slice(0, 10);

    return sorted.map((evt, idx) => {
      let stage = "Execution";
      if (evt.event_type === "AUTH_FAILURE" || evt.event_type === "AUTH_SUCCESS") stage = "Initial Access";
      else if (evt.event_type === "PRIVILEGE_ESCALATE") stage = "Privilege Escalation";
      else if (evt.event_type === "NETWORK_CONNECT") stage = "Command & Control";
      else if (evt.event_type === "HTTP_REQUEST") stage = "Exploitation";

      return {
        id: `TL-${idx}-${evt.id}`,
        time: evt.timestamp ? evt.timestamp.replace("T", " ").replace("Z", "") : new Date().toISOString(),
        stage,
        title: evt.message ? evt.message.substring(0, 80) : `Security Event ${evt.id}`,
        description: `Host: ${evt.hostname} | User: ${evt.username} | Action: ${evt.action} [${evt.status}]`,
        severity: evt.severity,
        eventId: evt.id,
        rawEvidence: evt.raw,
        tactics: [stage],
      };
    });
  }, [activeAlert, events]);

  const triggerAlertInvestigation = async (
    alertId: string,
    customNotes?: string
  ): Promise<GeminiInvestigationResult | null> => {
    const targetAlert = alerts.find((a) => a.id === alertId) || activeAlert;
    if (!targetAlert) return null;

    setIsInvestigating(true);
    try {
      const relatedEvents = events.filter((e) => targetAlert.relatedEventIds?.includes(e.id));
      const result = await investigateAlertWithGemini(targetAlert, relatedEvents, customNotes);

      // Update alert in state with Gemini analysis
      const updatedNotes = customNotes ? `${targetAlert.notes ? targetAlert.notes + "\n" : ""}${customNotes}` : targetAlert.notes;
      
      // Persist status or notes to backend
      try {
        await apiUpdateAlert(targetAlert.id, {
          notes: updatedNotes,
          updatedAt: new Date().toISOString(),
        });
      } catch (err) {
        console.warn("Failed to persist investigation update to backend:", err);
      }

      setAlerts((prev) =>
        prev.map((a) =>
          a.id === targetAlert.id
            ? {
                ...a,
                notes: updatedNotes,
                geminiAnalysis: result,
                aiConfidence: result.confidenceScore,
                updatedAt: new Date().toISOString(),
              }
            : a
        )
      );

      // Merge new extracted IOCs from Gemini
      if (result.extractedIocs && result.extractedIocs.length > 0) {
        const geminiIocs: IOC[] = result.extractedIocs.map((gi) => ({
          id: `IOC-AI-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 5)}`,
          value: gi.value,
          defangedValue: gi.value.replace(/\./g, "[.]"),
          type: (gi.type?.toUpperCase() as any) || "DOMAIN",
          riskLevel: (gi.riskLevel?.toUpperCase() as any) || "SUSPICIOUS",
          context: gi.context || "Identified during Gemini AI deep investigation",
          confidence: result.confidenceScore,
          firstSeen: new Date().toISOString(),
          tags: ["AI-Extracted"],
        }));

        setIocs((prev) => {
          const valSet = new Set(prev.map((p) => p.value));
          const toAdd = geminiIocs.filter((g) => !valSet.has(g.value));
          return [...toAdd, ...prev];
        });
      }

      return result;
    } finally {
      setIsInvestigating(false);
    }
  };

  const updateAlertStatus = async (alertId: string, status: AlertStatus): Promise<void> => {
    // 1. Optimistic update
    const previousAlerts = [...alerts];
    setAlerts((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, status, updatedAt: new Date().toISOString() } : a))
    );

    try {
      // 2. Persist to backend
      const updated = await apiUpdateAlert(alertId, {
        status,
        updatedAt: new Date().toISOString(),
      });
      
      // 3. Confirm persisted state
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? { ...a, ...updated } : a)));
      
      // 4. Refresh stats
      await loadDashboardStats();
    } catch (err: any) {
      console.error("Failed to update alert status on backend:", err);
      // Revert on failure
      setAlerts(previousAlerts);
      throw err;
    }
  };

  const assignAlert = async (alertId: string, assignedTo: string): Promise<void> => {
    const previousAlerts = [...alerts];
    setAlerts((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, assignedTo, updatedAt: new Date().toISOString() } : a))
    );

    try {
      const updated = await apiUpdateAlert(alertId, {
        assignedTo,
        updatedAt: new Date().toISOString(),
      });
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? { ...a, ...updated } : a)));
    } catch (err: any) {
      console.error("Failed to update alert assignment on backend:", err);
      setAlerts(previousAlerts);
      throw err;
    }
  };

  const escalateAlertToIncident = async (
    alertId: string,
    title?: string,
    severity?: Severity
  ): Promise<Incident> => {
    const targetAlert = alerts.find((a) => a.id === alertId) || activeAlert;
    const incidentTitle = title || (targetAlert ? `Incident: ${targetAlert.title}` : `Incident for ${alertId}`);
    const incidentSeverity = severity || targetAlert?.severity || "HIGH";

    const newIncident: Partial<Incident> = {
      title: incidentTitle,
      severity: incidentSeverity,
      status: "OPEN",
      priority: "P1",
      leadAnalyst: targetAlert?.assignedTo || "SOC-Lead-Analyst",
      alertIds: [alertId],
      executiveSummary: targetAlert?.description || `Escalated from Alert ${alertId}`,
      containmentActions: [],
    };

    const created = await apiCreateIncident(newIncident);
    setIncidents((prev) => [created, ...prev.filter((i) => i.id !== created.id)]);
    setActiveIncidentId(created.id);
    
    // Automatically transition alert status to INVESTIGATING if it was NEW
    if (targetAlert && targetAlert.status === "NEW") {
      try {
        await updateAlertStatus(alertId, "INVESTIGATING");
      } catch (e) {
        console.warn("Failed to update alert status on escalation:", e);
      }
    }

    return created;
  };

  const saveIncidentReport = async (report: IncidentReport): Promise<void> => {
    try {
      const persisted = await apiCreateReport(report);
      setIncidentReports((prev) => [persisted, ...prev.filter((r) => r.id !== persisted.id)]);
      await loadReports();
    } catch (err) {
      console.error("Failed to persist report:", err);
      setIncidentReports((prev) => [report, ...prev]);
      throw err;
    }
  };

  const createIncidentRecord = async (incident: Partial<Incident>): Promise<Incident> => {
    const created = await apiCreateIncident(incident);
    setIncidents((prev) => [created, ...prev.filter((i) => i.id !== created.id)]);
    setActiveIncidentId(created.id);
    return created;
  };

  const updateIncidentRecord = async (id: string, updates: Partial<Incident>): Promise<Incident> => {
    const updated = await apiUpdateIncident(id, updates);
    setIncidents((prev) => prev.map((inc) => (inc.id === id ? { ...inc, ...updated } : inc)));
    return updated;
  };

  const createIncidentAction = async (
    incidentId: string,
    action: Partial<IncidentResponseAction>
  ): Promise<IncidentResponseAction> => {
    const created = await apiCreateIncidentAction(incidentId, action);
    setIncidentActions((prev) => [created, ...prev.filter((a) => a.id !== created.id)]);
    return created;
  };

  const updateIncidentAction = async (
    incidentId: string,
    actionId: string,
    updates: Partial<IncidentResponseAction>
  ): Promise<IncidentResponseAction> => {
    const updated = await apiUpdateIncidentAction(incidentId, actionId, updates);
    setIncidentActions((prev) => prev.map((a) => (a.id === actionId ? { ...a, ...updated } : a)));
    return updated;
  };

  const resetToDefaultDemo = async () => {
    await loadScenario("scenario-apt-multistage");
  };

  const clearAllData = () => {
    setActiveAlertId(null);
    setActiveIncidentId(null);
    setIncidentActions([]);
  };

  const openInvestigationForAlert = (alertId: string) => {
    setActiveAlertId(alertId);
    setActiveTab("investigations");
  };

  const openIncident = (incidentId: string) => {
    setActiveIncidentId(incidentId);
    setActiveTab("incidents");
  };

  return (
    <SocContext.Provider
      value={{
        activeTab,
        setActiveTab,
        events,
        alerts,
        iocs,
        incidentReports,
        incidents,
        incidentActions,
        dashboardStats,
        statsLoading,
        alertsLoading,
        logsLoading,
        reportsLoading,
        incidentsLoading,
        actionsLoading,
        iocsLoading,
        isIngesting,
        statsError,
        alertsError,
        logsError,
        reportsError,
        incidentsError,
        actionsError,
        iocsError,
        activeAlertId,
        setActiveAlertId,
        activeAlert,
        activeIncidentId,
        setActiveIncidentId,
        activeIncident,
        activeInvestigationTimeline,
        activeScenarioId,
        backendHealth,
        isInvestigating,
        loadDashboardStats,
        loadAlerts,
        loadLogs,
        loadReports,
        loadIncidents,
        loadIncidentActions,
        loadIocs,
        loadScenario,
        ingestLogs,
        triggerAlertInvestigation,
        updateAlertStatus,
        assignAlert,
        escalateAlertToIncident,
        saveIncidentReport,
        createIncidentRecord,
        updateIncidentRecord,
        closeIncidentCase,
        generateReportForIncident,
        loadIncidentTimeline,
        createIncidentAction,
        updateIncidentAction,
        enrichIocRecord,
        resetToDefaultDemo,
        clearAllData,
        openInvestigationForAlert,
        openIncident,
      }}
    >
      {children}
    </SocContext.Provider>
  );
};

export const useSoc = () => {
  const context = useContext(SocContext);
  if (!context) throw new Error("useSoc must be used within a SocProvider");
  return context;
};
