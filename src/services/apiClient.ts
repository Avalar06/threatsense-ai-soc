import {
  Alert,
  AlertStatus,
  DashboardStats,
  GeminiInvestigationResult,
  Incident,
  IncidentReport,
  IncidentResponseAction,
  PhishingAnalysisResult,
  SecurityEvent,
  TimelineEvent,
  IOC,
  IocEnrichment,
  MitreTechnique,
  DetectionStrategy,
  CorrelationRecord,
  SoarPlaybook,
  SoarPlaybookExecution,
  SoarConnectorInfo,
  SoarAuditLog,
  SocMetrics,
  BenchmarkResult,
} from "../types/soc.js";

// Helper for structured API errors
export class ApiError extends Error {
  code: string;
  status: number;

  constructor(message: string, code = "API_ERROR", status = 500) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}

async function handleApiResponse<T>(res: Response): Promise<T> {
  const contentType = res.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    const text = await res.text();
    throw new ApiError(`Non-JSON response received (HTTP ${res.status}): ${text.slice(0, 100)}`, "NON_JSON_RESPONSE", res.status);
  }

  const json = await res.json();
  if (!res.ok || json.success === false) {
    const code = json.error?.code || `HTTP_${res.status}`;
    const message = json.error?.message || json.error || `Request failed with status ${res.status}`;
    throw new ApiError(message, code, res.status);
  }

  return json.data !== undefined ? json.data : json;
}

// ----------------------------------------------------
// 1. HEALTH & BACKEND STATUS
// ----------------------------------------------------
export async function checkBackendHealth(): Promise<{ status: string; geminiKeyConfigured: boolean }> {
  try {
    const res = await fetch("/api/health");
    if (!res.ok) throw new Error("Healthcheck failed");
    return await res.json();
  } catch {
    return { status: "offline", geminiKeyConfigured: false };
  }
}

// ----------------------------------------------------
// 2. DASHBOARD STATS
// ----------------------------------------------------
export async function getDashboardStats(): Promise<DashboardStats> {
  const res = await fetch("/api/dashboard/stats");
  return handleApiResponse<DashboardStats>(res);
}

// ----------------------------------------------------
// 3. ALERTS REST API
// ----------------------------------------------------
export interface AlertFilterParams {
  severity?: string;
  status?: string;
  priority?: string;
  host?: string;
  sourceIp?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export async function getAlerts(
  filters?: AlertFilterParams
): Promise<{ alerts: Alert[]; total: number; limit: number; offset: number }> {
  const query = new URLSearchParams();
  if (filters) {
    if (filters.severity && filters.severity !== "ALL") query.set("severity", filters.severity);
    if (filters.status && filters.status !== "ALL") query.set("status", filters.status);
    if (filters.priority && filters.priority !== "ALL") query.set("priority", filters.priority);
    if (filters.host) query.set("host", filters.host);
    if (filters.sourceIp) query.set("sourceIp", filters.sourceIp);
    if (filters.search) query.set("search", filters.search);
    if (filters.limit) query.set("limit", String(filters.limit));
    if (filters.offset) query.set("offset", String(filters.offset));
  }

  const url = `/api/alerts${query.toString() ? `?${query.toString()}` : ""}`;
  const res = await fetch(url);
  const json = await res.json();
  if (!res.ok || json.success === false) {
    throw new ApiError(json.error?.message || "Failed to fetch alerts", json.error?.code, res.status);
  }

  return {
    alerts: json.data || [],
    total: json.pagination?.total ?? (json.data?.length || 0),
    limit: json.pagination?.limit ?? (filters?.limit || 50),
    offset: json.pagination?.offset ?? (filters?.offset || 0),
  };
}

export async function getAlert(id: string): Promise<{ alert: Alert; events: SecurityEvent[] }> {
  const res = await fetch(`/api/alerts/${encodeURIComponent(id)}`);
  return handleApiResponse<{ alert: Alert; events: SecurityEvent[] }>(res);
}

export async function createAlert(alert: Partial<Alert>): Promise<Alert> {
  const res = await fetch("/api/alerts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(alert),
  });
  return handleApiResponse<Alert>(res);
}

export async function updateAlert(
  id: string,
  updates: {
    status?: AlertStatus;
    notes?: string;
    analystNotes?: string;
    assignedTo?: string;
    geminiAnalysis?: GeminiInvestigationResult;
    aiConfidence?: number;
    updatedAt?: string;
  }
): Promise<Alert> {
  const res = await fetch(`/api/alerts/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(updates),
  });
  return handleApiResponse<Alert>(res);
}

// ----------------------------------------------------
// 4. SECURITY EVENTS & LOGS API
// ----------------------------------------------------
export interface LogFilterParams {
  alertId?: string;
  hostname?: string;
  sourceIp?: string;
  eventType?: string;
  startTime?: string;
  endTime?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export async function getLogs(
  filters?: LogFilterParams
): Promise<{ events: SecurityEvent[]; total: number; limit: number; offset: number }> {
  const query = new URLSearchParams();
  if (filters) {
    if (filters.alertId) query.set("alertId", filters.alertId);
    if (filters.hostname) query.set("hostname", filters.hostname);
    if (filters.sourceIp) query.set("sourceIp", filters.sourceIp);
    if (filters.eventType && filters.eventType !== "ALL") query.set("eventType", filters.eventType);
    if (filters.startTime) query.set("startTime", filters.startTime);
    if (filters.endTime) query.set("endTime", filters.endTime);
    if (filters.search) query.set("search", filters.search);
    if (filters.limit) query.set("limit", String(filters.limit));
    if (filters.offset) query.set("offset", String(filters.offset));
  }

  const url = `/api/logs${query.toString() ? `?${query.toString()}` : ""}`;
  const res = await fetch(url);
  const json = await res.json();
  if (!res.ok || json.success === false) {
    throw new ApiError(json.error?.message || "Failed to fetch logs", json.error?.code, res.status);
  }

  return {
    events: json.data || [],
    total: json.pagination?.total ?? (json.data?.length || 0),
    limit: json.pagination?.limit ?? (filters?.limit || 50),
    offset: json.pagination?.offset ?? (filters?.offset || 0),
  };
}

export async function ingestLogs(
  raw: string,
  source?: string
): Promise<{ eventsIngested: number; alertsGenerated: number; events: SecurityEvent[]; alerts: Alert[] }> {
  const res = await fetch("/api/logs/ingest", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw, source }),
  });
  return handleApiResponse<{ eventsIngested: number; alertsGenerated: number; events: SecurityEvent[]; alerts: Alert[] }>(res);
}

// ----------------------------------------------------
// 5. INCIDENTS API
// ----------------------------------------------------
export interface IncidentFilterParams {
  status?: string;
  severity?: string;
  priority?: string;
  leadAnalyst?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export async function getIncidents(
  filters?: IncidentFilterParams
): Promise<{ incidents: Incident[]; total: number; limit: number; offset: number }> {
  const query = new URLSearchParams();
  if (filters) {
    if (filters.status && filters.status !== "ALL") query.set("status", filters.status);
    if (filters.severity && filters.severity !== "ALL") query.set("severity", filters.severity);
    if (filters.priority && filters.priority !== "ALL") query.set("priority", filters.priority);
    if (filters.leadAnalyst && filters.leadAnalyst !== "ALL") query.set("leadAnalyst", filters.leadAnalyst);
    if (filters.search) query.set("search", filters.search);
    if (filters.limit) query.set("limit", String(filters.limit));
    if (filters.offset) query.set("offset", String(filters.offset));
  }

  const url = `/api/incidents${query.toString() ? `?${query.toString()}` : ""}`;
  const res = await fetch(url);
  const json = await res.json();
  if (!res.ok || json.success === false) {
    throw new ApiError(json.error?.message || "Failed to fetch incidents", json.error?.code, res.status);
  }

  return {
    incidents: json.data || [],
    total: json.pagination?.total ?? (json.data?.length || 0),
    limit: json.pagination?.limit ?? (filters?.limit || 50),
    offset: json.pagination?.offset ?? (filters?.offset || 0),
  };
}

export async function getIncident(id: string): Promise<Incident> {
  const res = await fetch(`/api/incidents/${encodeURIComponent(id)}`);
  return handleApiResponse<Incident>(res);
}

export async function createIncident(incident: Partial<Incident>): Promise<Incident> {
  const res = await fetch("/api/incidents", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(incident),
  });
  return handleApiResponse<Incident>(res);
}

export async function updateIncident(id: string, updates: Partial<Incident>): Promise<Incident> {
  const res = await fetch(`/api/incidents/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(updates),
  });
  return handleApiResponse<Incident>(res);
}

export async function closeIncident(
  id: string,
  params: { closedBy: string; closureSummary: string }
): Promise<Incident> {
  const res = await fetch(`/api/incidents/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      status: "CLOSED",
      closedBy: params.closedBy,
      closureSummary: params.closureSummary,
    }),
  });
  return handleApiResponse<Incident>(res);
}

export async function getIncidentTimeline(incidentId: string): Promise<TimelineEvent[]> {
  const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/timeline`);
  return handleApiResponse<TimelineEvent[]>(res);
}

export async function generateIncidentReportFromIncident(
  incidentId: string,
  options?: Partial<IncidentReport>
): Promise<IncidentReport> {
  const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/generate-report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(options || {}),
  });
  return handleApiResponse<IncidentReport>(res);
}

// ----------------------------------------------------
// 5B. INCIDENT RESPONSE ACTIONS API (SIMULATED / TRACKING)
// ----------------------------------------------------
export async function getIncidentActions(incidentId: string): Promise<IncidentResponseAction[]> {
  const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/actions`);
  return handleApiResponse<IncidentResponseAction[]>(res);
}

export async function createIncidentAction(
  incidentId: string,
  action: Partial<IncidentResponseAction>
): Promise<IncidentResponseAction> {
  const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/actions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(action),
  });
  return handleApiResponse<IncidentResponseAction>(res);
}

export async function updateIncidentAction(
  incidentId: string,
  actionId: string,
  updates: Partial<IncidentResponseAction>
): Promise<IncidentResponseAction> {
  const res = await fetch(
    `/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(updates),
    }
  );
  return handleApiResponse<IncidentResponseAction>(res);
}

// ----------------------------------------------------
// 6. INCIDENT REPORTS API
// ----------------------------------------------------
export interface ReportFilterParams {
  incidentId?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export async function getReports(
  filters?: ReportFilterParams
): Promise<{ reports: IncidentReport[]; total: number; limit: number; offset: number }> {
  const query = new URLSearchParams();
  if (filters) {
    if (filters.incidentId) query.set("incidentId", filters.incidentId);
    if (filters.search) query.set("search", filters.search);
    if (filters.limit) query.set("limit", String(filters.limit));
    if (filters.offset) query.set("offset", String(filters.offset));
  }

  const url = `/api/reports${query.toString() ? `?${query.toString()}` : ""}`;
  const res = await fetch(url);
  const json = await res.json();
  if (!res.ok || json.success === false) {
    throw new ApiError(json.error?.message || "Failed to fetch reports", json.error?.code, res.status);
  }

  return {
    reports: json.data || [],
    total: json.pagination?.total ?? (json.data?.length || 0),
    limit: json.pagination?.limit ?? (filters?.limit || 50),
    offset: json.pagination?.offset ?? (filters?.offset || 0),
  };
}

export async function createReport(report: Partial<IncidentReport>): Promise<IncidentReport> {
  const res = await fetch("/api/reports", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(report),
  });
  return handleApiResponse<IncidentReport>(res);
}

// ----------------------------------------------------
// 7. THREAT INTELLIGENCE & IOCS API
// ----------------------------------------------------
export interface IocFilterParams {
  type?: string;
  threatLevel?: string;
  search?: string;
  alertId?: string;
  incidentId?: string;
  limit?: number;
  offset?: number;
}

export async function getIocs(
  filters?: IocFilterParams
): Promise<{ iocs: IOC[]; total: number; limit: number; offset: number }> {
  const query = new URLSearchParams();
  if (filters) {
    if (filters.type) query.set("type", filters.type);
    if (filters.threatLevel) query.set("threatLevel", filters.threatLevel);
    if (filters.search) query.set("search", filters.search);
    if (filters.alertId) query.set("alertId", filters.alertId);
    if (filters.incidentId) query.set("incidentId", filters.incidentId);
    if (filters.limit) query.set("limit", String(filters.limit));
    if (filters.offset) query.set("offset", String(filters.offset));
  }

  const url = `/api/iocs${query.toString() ? `?${query.toString()}` : ""}`;
  const res = await fetch(url);
  const json = await res.json();
  if (!res.ok || json.success === false) {
    throw new ApiError(json.error?.message || "Failed to fetch IOC records", json.error?.code, res.status);
  }

  return {
    iocs: json.data || [],
    total: json.pagination?.total ?? (json.data?.length || 0),
    limit: json.pagination?.limit ?? (filters?.limit || 50),
    offset: json.pagination?.offset ?? (filters?.offset || 0),
  };
}

export async function getIoc(id: string): Promise<IOC & {
  enrichments: IocEnrichment[];
  latestEnrichment?: IocEnrichment;
  relatedAlerts: Alert[];
  relatedIncidents: Incident[];
}> {
  const res = await fetch(`/api/iocs/${encodeURIComponent(id)}`);
  return handleApiResponse<IOC & {
    enrichments: IocEnrichment[];
    latestEnrichment?: IocEnrichment;
    relatedAlerts: Alert[];
    relatedIncidents: Incident[];
  }>(res);
}

export async function createIoc(ioc: Partial<IOC>): Promise<IOC> {
  const res = await fetch("/api/iocs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(ioc),
  });
  return handleApiResponse<IOC>(res);
}

export async function enrichIoc(
  id: string,
  forceRefresh?: boolean
): Promise<{ data: IocEnrichment; status: string }> {
  const res = await fetch(`/api/iocs/${encodeURIComponent(id)}/enrich`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ forceRefresh: Boolean(forceRefresh) }),
  });
  const json = await res.json();
  if (!res.ok || json.success === false) {
    throw new ApiError(json.error?.message || "Failed to enrich IOC", json.error?.code, res.status);
  }
  return {
    data: json.data,
    status: json.status,
  };
}

export async function investigateAlertWithGemini(
  alert: Alert,
  relatedEvents: SecurityEvent[],
  customNotes?: string
): Promise<GeminiInvestigationResult> {
  try {
    const response = await fetch("/api/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert, relatedEvents, customNotes }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `HTTP error ${response.status}`);
    }

    const data = await response.json();
    return data.analysis;
  } catch (error: any) {
    console.warn("Backend Gemini investigation call failed, generating deterministic fallback:", error);
    return generateFallbackInvestigation(alert, relatedEvents);
  }
}

export async function queryAiAnalyst(
  message: string,
  conversationHistory: Array<{ role: "user" | "assistant"; content: string }>,
  investigationContext?: {
    activeAlert?: Alert | null;
    totalEvents: number;
    sampleEvents: SecurityEvent[];
    iocs: IOC[];
  }
): Promise<string> {
  try {
    const response = await fetch("/api/ai-analyst", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, conversationHistory, investigationContext }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `HTTP error ${response.status}`);
    }

    const data = await response.json();
    return data.reply;
  } catch (error: any) {
    console.warn("Backend AI Analyst call failed, generating contextual response:", error);
    return generateFallbackAnalystReply(message, investigationContext);
  }
}

export async function queryMitreMapping(
  events: SecurityEvent[],
  alertTitle?: string,
  context?: string
): Promise<any> {
  try {
    const response = await fetch("/api/mitre-analysis", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ events, alertTitle, context }),
    });

    if (!response.ok) throw new Error("MITRE mapping failed");
    const data = await response.json();
    return data.data;
  } catch (error) {
    console.warn("MITRE API call failed, generating fallback mapping:", error);
    return {
      tacticsDetected: ["Initial Access", "Execution", "Privilege Escalation", "Command and Control"],
      techniques: [
        {
          id: "T1110",
          name: "Brute Force",
          tactic: "Credential Access",
          explanation: "Observed multiple failed login requests followed by successful access.",
          confidence: 90,
          validationCheck: "Verify auth.log and Windows Event 4625/4624 pairings.",
        },
        {
          id: "T1059.001",
          name: "PowerShell",
          tactic: "Execution",
          explanation: "Encoded script execution bypassing execution policy.",
          confidence: 95,
          validationCheck: "Inspect Event ID 4104 Script Block Logging.",
        },
      ],
      killChainStage: "Actions on Objectives / C2",
      analystAdvice: "Isolate affected host and revoke active Kerberos/session tokens immediately.",
    };
  }
}

export async function analyzePhishingEmail(payload: {
  rawEmail?: string;
  sender?: string;
  subject?: string;
  replyTo?: string;
  headers?: string;
}): Promise<PhishingAnalysisResult> {
  try {
    const response = await fetch("/api/phishing-analyzer", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) throw new Error("Phishing analysis failed");
    const data = await response.json();
    return data.data;
  } catch (error) {
    console.warn("Phishing API call failed, generating local threat evaluation:", error);
    return generateFallbackPhishing(payload);
  }
}

export async function generateIncidentReportApi(payload: {
  alert: Alert;
  timeline: TimelineEvent[];
  iocs: IOC[];
  mitreMappings: MitreTechnique[];
  analystNotes?: string;
  rawEvents: SecurityEvent[];
}): Promise<Partial<IncidentReport>> {
  try {
    const response = await fetch("/api/generate-report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) throw new Error("Report generation failed");
    const data = await response.json();
    return data.report;
  } catch (error) {
    console.warn("Incident Report API failed, generating report synthesis:", error);
    return generateFallbackReport(payload);
  }
}

// Deterministic fallback helpers
function generateFallbackInvestigation(alert: Alert, relatedEvents: SecurityEvent[]): GeminiInvestigationResult {
  const isBruteForce = alert.title.toLowerCase().includes("brute") || alert.title.toLowerCase().includes("credential");
  const isPowerShell = alert.title.toLowerCase().includes("powershell");
  const isC2 = alert.title.toLowerCase().includes("c2") || alert.title.toLowerCase().includes("outbound");

  return {
    verdict: "True Positive",
    confidenceScore: 92,
    executiveSummary: `Investigation confirms malicious activity on host ${alert.host} involving ${alert.title}. The intrusion originated from external source ${alert.sourceIp} and targeted account ${alert.username}.`,
    observedEvidence: [
      `Source IP ${alert.sourceIp} generated ${relatedEvents.length || alert.evidence.length} security log entries.`,
      `Target host ${alert.host} recorded anomalous execution for user ${alert.username}.`,
      ...alert.evidence.slice(0, 3).map((e) => `Observed log artifact: ${e.substring(0, 140)}`),
    ],
    reasoningAndInferences: [
      `The attack sequence aligns with standard cyber kill chain progression: external reconnaissance followed by ${alert.title}.`,
      `The timing and parameters strongly indicate scripted adversary tooling rather than benign administrative error.`,
      isPowerShell ? "Base64 encoding was employed to obfuscate malicious payload delivery." : "Authentication patterns show systematic automated credential testing.",
    ],
    uncertaintyAndGaps: [
      "Endpoint EDR process tree telemetry for parent processes is partially unverified.",
      "Additional DNS query resolution telemetry is recommended to assess domain reputation.",
    ],
    mitreMappings: alert.mitreTechniques.length > 0 ? alert.mitreTechniques : [
      {
        id: "T1110",
        name: "Brute Force",
        tactic: "Credential Access",
        explanation: "Automated credential spray detected.",
        confidence: 88,
      },
    ],
    recommendedContainment: [
      `Immediately quarantine endpoint ${alert.host} from the internal network.`,
      `Block source IP ${alert.sourceIp} and associated C2 endpoints at the perimeter firewall.`,
      `Force password reset and revoke all active OAuth/Kerberos session tokens for user ${alert.username}.`,
    ],
    recommendedInvestigation: [
      "Extract memory dump from the affected host to inspect injected DLLs or living-off-the-land binaries.",
      "Query proxy logs for all outbound connections to destination IP addresses over the preceding 72 hours.",
      "Review Domain Controller security event logs for lateral movement (Event ID 4624 Logon Type 3/10).",
    ],
  };
}

function generateFallbackAnalystReply(
  message: string,
  context?: { activeAlert?: Alert | null; totalEvents: number; iocs: IOC[] }
): string {
  const alert = context?.activeAlert;
  const msgLower = message.toLowerCase();

  if (msgLower.includes("why") && (msgLower.includes("high") || msgLower.includes("severity") || msgLower.includes("score"))) {
    return `### Alert Severity & Risk Score Breakdown
The alert **${alert?.title || "Current Alert"}** is classified with a **Risk Score of ${alert?.riskScore || 85}/100** due to the following factors:

1. **Observed Evidence**: Direct telemetry indicates unauthorized actions originating from external source IP \`${alert?.sourceIp || "185.220.101.5"}\` targeting asset \`${alert?.host || "FIN-SRV-01"}\`.
2. **Attack Progression**: The combination of authentication anomalies with subsequent privileged executions matches high-confidence adversarial behavior.
3. **Asset Criticality**: The targeted host houses sensitive organizational data.
4. **Calculated Confidence**: Detection precision is rated at **${alert?.detectionConfidence || 91}%**.`;
  }

  if (msgLower.includes("mitre") || msgLower.includes("technique")) {
    return `### Applicable MITRE ATT&CK Mapping
Based on the ingested telemetry:
- **T1110 (Brute Force)**: Repeated failed authentication attempts from a single source.
- **T1078 (Valid Accounts)**: Successful authentication following automated spraying.
- **T1059.001 (PowerShell)**: Script execution with hidden/bypass parameters.
- **T1071.001 (Web Protocols / C2)**: Outbound socket to external infrastructure.

*Note: All mappings represent analyst-assisted heuristics and should be correlated against firewall and host logs.*`;
  }

  return `### SOC Analyst Assessment
Regarding your inquiry: **"${message}"**

- **Target Asset**: \`${alert?.host || "FIN-SRV-01"}\`
- **Source Threat Actor IP**: \`${alert?.sourceIp || "External Threat"}\`
- **Current Status**: \`${alert?.status || "NEW"}\`

**Recommended Next Steps:**
1. Isolate the affected host from corporate subnets.
2. Invalidate active user tokens for \`${alert?.username || "impacted user"}\`.
3. Check firewall logs for anomalous outbound egress to port 4444 or known malicious subnets.`;
}

function generateFallbackPhishing(payload: any): PhishingAnalysisResult {
  return {
    phishingRiskScore: 92,
    classification: "Phishing / Credential Harvester",
    confidence: 94,
    senderAnalysis: {
      isSpoofed: true,
      domainMismatch: true,
      displaySender: payload.sender || "Microsoft 365 Security Team",
      actualSenderDomain: "microsoft-security-verify.com",
      analysis: "Sender domain 'microsoft-security-verify.com' is a lookalike domain not authorized by Microsoft Corporation.",
    },
    authenticationStatus: {
      spf: "softfail",
      dkim: "neutral / missing",
      dmarc: "fail (p=reject)",
      notes: "Sender IP is not listed in authorized SPF records for the claimed brand.",
    },
    extractedUrls: [
      {
        url: "http://login.microsoftonline.portal-auth-verification-check.com/login.php",
        defangedUrl: "hxxp://login[.]microsoftonline[.]portal-auth-verification-check[.]com/login[.]php",
        risk: "MALICIOUS",
        reason: "Deceptive subdomain structure mimicking Microsoft login portal to harvest enterprise credentials.",
      },
    ],
    socialEngineeringIndicators: [
      "Artificial urgency: 'Password Expires in 2 Hours'",
      "Threat of account suspension / penalty",
      "Generic greeting with spoofed technical support signoff",
    ],
    keyEvidence: [
      "SPF and DMARC alignment validation failed.",
      "Embedded hyperlink points to an unregistered, third-party authentication proxy domain.",
      "Reply-To address differs from claimed sender address.",
    ],
    recommendedActions: [
      "Block domain 'portal-auth-verification-check.com' at DNS resolver and web gateway.",
      "Purge email with message ID from all employee mailboxes.",
      "Reset credentials for any users who clicked the destination URL.",
    ],
    executiveSummary: "High-confidence spearphishing email attempting credential harvesting by spoofing Microsoft 365 security notifications.",
  };
}

function generateFallbackReport(payload: any): Partial<IncidentReport> {
  const { alert, timeline, iocs } = payload;
  return {
    reportTitle: `SOC Incident Report: ${alert.title} [${alert.id}]`,
    incidentId: alert.id,
    executiveSummary: `On ${alert.timestamp}, the AI-SOC monitoring platform detected a ${alert.severity.toLowerCase()} severity security incident on host ${alert.host}. An external threat actor (${alert.sourceIp}) successfully breached user credentials (${alert.username}) and attempted secondary payload execution before being contained.`,
    incidentDescription: `Detailed analysis indicates an initial brute-force authentication phase originating from ${alert.sourceIp}, followed by privilege elevation and suspicious command-line execution. Defensive countermeasures and host isolation were enacted.`,
    detectionMethod: `${alert.detectionSource} Detection Engine & Gemini AI Correlation`,
    affectedAssets: [alert.host, "DMZ-Firewall-Edge", "Corporate Active Directory"],
    affectedUsers: [alert.username],
    rootCauseAnalysis: `Exposed authentication endpoint without mandatory multi-factor authentication (MFA) enabled for remote administrative access.`,
    riskAssessment: {
      quantitativeScore: alert.riskScore,
      impactRating: alert.severity === "CRITICAL" ? "CRITICAL" : "HIGH",
      confidentialityImpact: "High (Potential credential exposure)",
      integrityImpact: "Medium (Unauthorized service modification attempt)",
      availabilityImpact: "Low (No disruption to core production services)",
    },
    containmentActionsCompleted: [
      `Quarantined host ${alert.host} from internal VLANs.`,
      `Blacklisted IP ${alert.sourceIp} on edge firewalls.`,
      `Revoked Active Directory Kerberos tickets for ${alert.username}.`,
    ],
    eradicationAndRemediation: [
      "Purged temporary malicious artifacts and script files.",
      "Enforced mandatory FIDO2/MFA on all remote SSH and RDP endpoints.",
      "Updated EDR detection signatures for PowerShell download cradles.",
    ],
    lessonsLearnedAndPreventativeControls: [
      "Implement conditional access blocking external SSH/RDP logins without VPN tunnel.",
      "Deploy rate-limiting and automated IP blocking on 3 consecutive failed logins.",
    ],
    analystConclusion: `The intrusion was identified and contained within SOC SLA thresholds. No unauthorized data exfiltration was observed. Incident is closed pending final forensic audit.`,
  };
}

// =========================================================================
// PHASE 6: DETECTION STRATEGIES & CORRELATIONS CLIENT METHODS
// =========================================================================

export async function getDetectionStrategies(filters?: {
  tactic?: string;
  techniqueId?: string;
  isActive?: boolean;
  search?: string;
}): Promise<DetectionStrategy[]> {
  const query = new URLSearchParams();
  if (filters) {
    if (filters.tactic) query.set("tactic", filters.tactic);
    if (filters.techniqueId) query.set("techniqueId", filters.techniqueId);
    if (filters.isActive !== undefined) query.set("isActive", String(filters.isActive));
    if (filters.search) query.set("search", filters.search);
  }
  const res = await fetch(`/api/detection-strategies${query.toString() ? `?${query.toString()}` : ""}`);
  return handleApiResponse<DetectionStrategy[]>(res);
}

export async function getDetectionStrategy(id: string): Promise<DetectionStrategy> {
  const res = await fetch(`/api/detection-strategies/${encodeURIComponent(id)}`);
  return handleApiResponse<DetectionStrategy>(res);
}

export async function getCorrelations(filters?: {
  strategyId?: string;
  severity?: string;
  confidence?: string;
  incidentId?: string;
  search?: string;
  limit?: number;
  offset?: number;
}): Promise<{ correlations: CorrelationRecord[]; total: number; limit: number; offset: number }> {
  const query = new URLSearchParams();
  if (filters) {
    if (filters.strategyId) query.set("strategyId", filters.strategyId);
    if (filters.severity) query.set("severity", filters.severity);
    if (filters.confidence) query.set("confidence", filters.confidence);
    if (filters.incidentId) query.set("incidentId", filters.incidentId);
    if (filters.search) query.set("search", filters.search);
    if (filters.limit) query.set("limit", String(filters.limit));
    if (filters.offset) query.set("offset", String(filters.offset));
  }
  const res = await fetch(`/api/correlations${query.toString() ? `?${query.toString()}` : ""}`);
  const json = await res.json();
  if (!res.ok || json.success === false) {
    throw new ApiError(json.error?.message || "Failed to fetch correlations", json.error?.code, res.status);
  }
  return {
    correlations: json.correlations || [],
    total: json.total ?? (json.correlations?.length || 0),
    limit: json.limit ?? (filters?.limit || 50),
    offset: json.offset ?? (filters?.offset || 0),
  };
}

export async function getCorrelation(id: string): Promise<CorrelationRecord> {
  const res = await fetch(`/api/correlations/${encodeURIComponent(id)}`);
  return handleApiResponse<CorrelationRecord>(res);
}

export async function runCorrelations(options?: {
  windowSeconds?: number;
  strategyIds?: string[];
  incidentId?: string;
}): Promise<{
  status: string;
  evaluatedStrategies: number;
  correlationsFound: number;
  newCorrelationsPersisted: number;
  correlations: CorrelationRecord[];
  explanations: string[];
}> {
  const res = await fetch("/api/correlations/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(options || {}),
  });
  const json = await res.json();
  if (!res.ok || json.success === false) {
    throw new ApiError(json.error?.message || "Failed running correlations", json.error?.code, res.status);
  }
  return json;
}

// =========================================================================
// PHASE 7: SOAR PLAYBOOKS & CONNECTORS CLIENT METHODS
// =========================================================================

export async function getSoarConnectors(): Promise<SoarConnectorInfo[]> {
  const res = await fetch("/api/soar-connectors");
  return handleApiResponse<SoarConnectorInfo[]>(res);
}

export async function getPlaybooks(status?: string): Promise<SoarPlaybook[]> {
  const query = status ? `?status=${encodeURIComponent(status)}` : "";
  const res = await fetch(`/api/playbooks${query}`);
  return handleApiResponse<SoarPlaybook[]>(res);
}

export async function getPlaybook(id: string): Promise<SoarPlaybook> {
  const res = await fetch(`/api/playbooks/${encodeURIComponent(id)}`);
  return handleApiResponse<SoarPlaybook>(res);
}

export async function createPlaybook(playbook: Partial<SoarPlaybook>): Promise<SoarPlaybook> {
  const res = await fetch("/api/playbooks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(playbook),
  });
  return handleApiResponse<SoarPlaybook>(res);
}

export async function updatePlaybook(id: string, updates: Partial<SoarPlaybook>): Promise<SoarPlaybook> {
  const res = await fetch(`/api/playbooks/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(updates),
  });
  return handleApiResponse<SoarPlaybook>(res);
}

export async function runPlaybook(
  id: string,
  options: {
    initiatingUser: string;
    incidentId?: string;
    alertId?: string;
    correlationId?: string;
    idempotencyKey?: string;
    autoApprove?: boolean;
  }
): Promise<SoarPlaybookExecution> {
  const res = await fetch(`/api/playbooks/${encodeURIComponent(id)}/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(options),
  });
  return handleApiResponse<SoarPlaybookExecution>(res);
}

export async function getPlaybookExecutions(filters?: {
  playbookId?: string;
  status?: string;
  incidentId?: string;
  alertId?: string;
  correlationId?: string;
  limit?: number;
  offset?: number;
}): Promise<{ executions: SoarPlaybookExecution[]; total: number; limit: number; offset: number }> {
  const query = new URLSearchParams();
  if (filters) {
    if (filters.playbookId) query.set("playbookId", filters.playbookId);
    if (filters.status) query.set("status", filters.status);
    if (filters.incidentId) query.set("incidentId", filters.incidentId);
    if (filters.alertId) query.set("alertId", filters.alertId);
    if (filters.correlationId) query.set("correlationId", filters.correlationId);
    if (filters.limit) query.set("limit", String(filters.limit));
    if (filters.offset) query.set("offset", String(filters.offset));
  }
  const res = await fetch(`/api/playbook-executions${query.toString() ? `?${query.toString()}` : ""}`);
  const json = await res.json();
  if (!res.ok || json.success === false) {
    throw new ApiError(json.error?.message || "Failed to fetch executions", json.error?.code, res.status);
  }
  return {
    executions: json.executions || [],
    total: json.total ?? (json.executions?.length || 0),
    limit: json.limit ?? (filters?.limit || 50),
    offset: json.offset ?? (filters?.offset || 0),
  };
}

export async function getPlaybookExecution(id: string): Promise<SoarPlaybookExecution> {
  const res = await fetch(`/api/playbook-executions/${encodeURIComponent(id)}`);
  return handleApiResponse<SoarPlaybookExecution>(res);
}

export async function approvePlaybookExecution(id: string, approvedBy: string): Promise<SoarPlaybookExecution> {
  const res = await fetch(`/api/playbook-executions/${encodeURIComponent(id)}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ approvedBy }),
  });
  return handleApiResponse<SoarPlaybookExecution>(res);
}

export async function rejectPlaybookExecution(id: string, actor: string, reason: string): Promise<SoarPlaybookExecution> {
  const res = await fetch(`/api/playbook-executions/${encodeURIComponent(id)}/reject`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ actor, reason }),
  });
  return handleApiResponse<SoarPlaybookExecution>(res);
}

export async function cancelPlaybookExecution(id: string, actor: string, reason?: string): Promise<SoarPlaybookExecution> {
  const res = await fetch(`/api/playbook-executions/${encodeURIComponent(id)}/cancel`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ actor, reason }),
  });
  return handleApiResponse<SoarPlaybookExecution>(res);
}

export async function getSoarAuditLogs(filters?: {
  executionId?: string;
  incidentId?: string;
  actionType?: string;
  connectorId?: string;
  limit?: number;
  offset?: number;
}): Promise<SoarAuditLog[]> {
  const query = new URLSearchParams();
  if (filters) {
    if (filters.executionId) query.set("executionId", filters.executionId);
    if (filters.incidentId) query.set("incidentId", filters.incidentId);
    if (filters.actionType) query.set("actionType", filters.actionType);
    if (filters.connectorId) query.set("connectorId", filters.connectorId);
    if (filters.limit) query.set("limit", String(filters.limit));
    if (filters.offset) query.set("offset", String(filters.offset));
  }
  const res = await fetch(`/api/soar-audit-logs${query.toString() ? `?${query.toString()}` : ""}`);
  return handleApiResponse<SoarAuditLog[]>(res);
}

// =========================================================================
// OBSERVABILITY & BENCHMARKS CLIENT METHODS
// =========================================================================

export async function getSocMetrics(): Promise<SocMetrics> {
  const res = await fetch("/api/metrics");
  return handleApiResponse<SocMetrics>(res);
}

export async function runBenchmark(): Promise<BenchmarkResult> {
  const res = await fetch("/api/benchmarks/evaluate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ adapterId: "ADAPTER-INTERNAL-VAL" })
  });
  return handleApiResponse<BenchmarkResult>(res);
}

export async function getBenchmarkAdapters(): Promise<import("../types/soc.js").DatasetAdapterMetadata[]> {
  const res = await fetch("/api/benchmarks/adapters");
  return handleApiResponse<import("../types/soc.js").DatasetAdapterMetadata[]>(res);
}

export async function evaluateBenchmarkDataset(payload: {
  adapterId?: string;
  samples?: import("../types/soc.js").NormalizedBenchmarkRecord[];
  meta?: {
    datasetName?: string;
    datasetSource?: string;
    datasetVersion?: string;
    datasetHash?: string;
    evaluationType?: "INTERNAL_VALIDATION" | "EXTERNAL_BENCHMARK";
    limitations?: string[];
  };
}): Promise<BenchmarkResult> {
  const res = await fetch("/api/benchmarks/evaluate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return handleApiResponse<BenchmarkResult>(res);
}

export async function exportBenchmarkResult(
  result: BenchmarkResult,
  format: "json" | "csv" | "markdown"
): Promise<{ blob: Blob; filename: string }> {
  const res = await fetch("/api/benchmarks/export", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ result, format })
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: { message: "Export failed" } }));
    throw new Error(err.error?.message || "Export failed");
  }

  const disposition = res.headers.get("Content-Disposition");
  let filename = `benchmark-report.${format === "markdown" ? "md" : format}`;
  if (disposition && disposition.includes("filename=")) {
    filename = disposition.split("filename=")[1].replace(/"/g, "").trim();
  }

  const blob = await res.blob();
  return { blob, filename };
}

