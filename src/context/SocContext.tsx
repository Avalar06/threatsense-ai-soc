import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import { Alert, AlertStatus, GeminiInvestigationResult, IncidentReport, IOC, SecurityEvent, TimelineEvent } from "../types/soc.js";
import { SAMPLE_SCENARIOS } from "../data/sampleLogs.js";
import { parseRawLogs } from "../services/logParser.js";
import { extractIocsFromText } from "../services/iocExtractor.js";
import { runDetectionEngine, DEFAULT_DETECTION_RULES } from "../services/detectionEngine.js";
import { checkBackendHealth, investigateAlertWithGemini } from "../services/apiClient.js";

export type SocNavTab =
  | "dashboard"
  | "alerts"
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
  activeAlertId: string | null;
  setActiveAlertId: (id: string | null) => void;
  activeAlert: Alert | null;
  activeInvestigationTimeline: TimelineEvent[];
  activeScenarioId: string;
  backendHealth: { status: string; geminiKeyConfigured: boolean };
  isInvestigating: boolean;
  loadScenario: (scenarioId: string) => void;
  ingestLogs: (rawLogText: string, defaultHost?: string) => void;
  triggerAlertInvestigation: (alertId: string, customNotes?: string) => Promise<GeminiInvestigationResult | null>;
  updateAlertStatus: (alertId: string, status: AlertStatus) => void;
  saveIncidentReport: (report: IncidentReport) => void;
  resetToDefaultDemo: () => void;
  clearAllData: () => void;
  openInvestigationForAlert: (alertId: string) => void;
}

const SocContext = createContext<SocContextType | undefined>(undefined);

export const SocProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeTab, setActiveTab] = useState<SocNavTab>("dashboard");
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [incidentReports, setIncidentReports] = useState<IncidentReport[]>([]);
  const [activeAlertId, setActiveAlertId] = useState<string | null>(null);
  const [activeScenarioId, setActiveScenarioId] = useState<string>("scenario-apt-multistage");
  const [isInvestigating, setIsInvestigating] = useState<boolean>(false);
  const [backendHealth, setBackendHealth] = useState<{ status: string; geminiKeyConfigured: boolean }>({
    status: "checking",
    geminiKeyConfigured: false,
  });

  // Check health on mount
  useEffect(() => {
    checkBackendHealth().then((res) => {
      setBackendHealth(res);
    });
  }, []);

  // Load default demo scenario on initial mount
  useEffect(() => {
    loadScenario("scenario-apt-multistage");
  }, []);

  const loadScenario = (scenarioId: string) => {
    const scenario = SAMPLE_SCENARIOS.find((s) => s.id === scenarioId) || SAMPLE_SCENARIOS[0];
    setActiveScenarioId(scenario.id);

    const parsedEvents = parseRawLogs(scenario.rawLog, "FIN-SRV-01");
    setEvents(parsedEvents);

    // Extract IOCs
    const extractedIocs = extractIocsFromText(scenario.rawLog);
    setIocs(extractedIocs);

    // Run Detection Engine
    const generatedAlerts = runDetectionEngine(parsedEvents, DEFAULT_DETECTION_RULES);
    setAlerts(generatedAlerts);

    if (generatedAlerts.length > 0) {
      setActiveAlertId(generatedAlerts[0].id);
    } else {
      setActiveAlertId(null);
    }
  };

  const ingestLogs = (rawLogText: string, defaultHost = "CORP-ENDPOINT") => {
    const parsedEvents = parseRawLogs(rawLogText, defaultHost);
    setEvents((prev) => [...parsedEvents, ...prev]);

    const extractedIocs = extractIocsFromText(rawLogText);
    setIocs((prev) => {
      const existingValues = new Set(prev.map((i) => i.value));
      const newIocs = extractedIocs.filter((i) => !existingValues.has(i.value));
      return [...newIocs, ...prev];
    });

    const newAlerts = runDetectionEngine(parsedEvents, DEFAULT_DETECTION_RULES);
    if (newAlerts.length > 0) {
      setAlerts((prev) => [...newAlerts, ...prev]);
      setActiveAlertId(newAlerts[0].id);
    }
  };

  const activeAlert = useMemo(() => {
    if (!activeAlertId) return alerts[0] || null;
    return alerts.find((a) => a.id === activeAlertId) || alerts[0] || null;
  }, [activeAlertId, alerts]);

  // Timeline events for active alert
  const activeInvestigationTimeline = useMemo<TimelineEvent[]>(() => {
    if (!activeAlert) return [];

    const related = events.filter((e) => activeAlert.relatedEventIds.includes(e.id));
    const sorted = related.length > 0 ? related : events.slice(0, 10);

    return sorted.map((evt, idx) => {
      let stage = "Execution";
      if (evt.event_type === "AUTH_FAILURE" || evt.event_type === "AUTH_SUCCESS") stage = "Initial Access";
      else if (evt.event_type === "PRIVILEGE_ESCALATE") stage = "Privilege Escalation";
      else if (evt.event_type === "NETWORK_CONNECT") stage = "Command & Control";
      else if (evt.event_type === "HTTP_REQUEST") stage = "Exploitation";

      return {
        id: `TL-${idx}-${evt.id}`,
        time: evt.timestamp.replace("T", " ").replace("Z", ""),
        stage,
        title: evt.message.substring(0, 80),
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
      const relatedEvents = events.filter((e) => targetAlert.relatedEventIds.includes(e.id));
      const result = await investigateAlertWithGemini(targetAlert, relatedEvents, customNotes);

      // Update alert in state with Gemini analysis
      setAlerts((prev) =>
        prev.map((a) =>
          a.id === targetAlert.id
            ? {
                ...a,
                geminiAnalysis: result,
                aiConfidence: result.confidenceScore,
                updatedAt: new Date().toISOString(),
              }
            : a
        )
      );

      // Also merge any new extracted IOCs from Gemini
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

  const updateAlertStatus = (alertId: string, status: AlertStatus) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, status, updatedAt: new Date().toISOString() } : a))
    );
  };

  const saveIncidentReport = (report: IncidentReport) => {
    setIncidentReports((prev) => [report, ...prev]);
  };

  const resetToDefaultDemo = () => {
    loadScenario("scenario-apt-multistage");
  };

  const clearAllData = () => {
    setEvents([]);
    setAlerts([]);
    setIocs([]);
    setActiveAlertId(null);
  };

  const openInvestigationForAlert = (alertId: string) => {
    setActiveAlertId(alertId);
    setActiveTab("investigations");
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
        activeAlertId,
        setActiveAlertId,
        activeAlert,
        activeInvestigationTimeline,
        activeScenarioId,
        backendHealth,
        isInvestigating,
        loadScenario,
        ingestLogs,
        triggerAlertInvestigation,
        updateAlertStatus,
        saveIncidentReport,
        resetToDefaultDemo,
        clearAllData,
        openInvestigationForAlert,
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
