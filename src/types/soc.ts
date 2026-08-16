export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";

export type AlertStatus = "NEW" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "FALSE_POSITIVE";

export type DetectionSource = "RULE_BASED" | "ML_ANOMALY" | "GEMINI_AI";

export interface SecurityEvent {
  id: string;
  timestamp: string; // ISO 8601 or normalized format
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  username: string;
  hostname: string;
  process?: string;
  event_type: string; // AUTH_FAILURE, AUTH_SUCCESS, PROCESS_CREATE, NETWORK_CONNECT, PRIVILEGE_ESCALATE, FILE_MOD, HTTP_REQUEST, etc.
  action: "ALLOW" | "BLOCK" | "EXECUTE" | "LOGIN_FAIL" | "LOGIN_SUCCESS" | "ESCALATE" | "QUERY" | "UNKNOWN";
  status: "SUCCESS" | "FAILURE" | "ANOMALOUS" | "FLAGGED";
  message: string;
  severity: Severity;
  raw: string;
  metadata?: Record<string, any>;
}

export interface MitreTechnique {
  id: string; // e.g. "T1110.001"
  name: string;
  tactic: string; // e.g. "Credential Access"
  subtechnique?: string;
  explanation: string;
  confidence: number; // 0 - 100
  evidenceRefs?: string[];
  validationStatus?: "VERIFIED" | "AI_SUGGESTED" | "UNCONFIRMED";
  mitigation?: string;
  url?: string;
}

export interface TimelineEvent {
  id: string;
  time: string;
  stage: string;
  title: string;
  description: string;
  severity: Severity;
  eventId?: string;
  rawEvidence?: string;
  tactics?: string[];
}

export interface IOC {
  id: string;
  value: string;
  defangedValue: string;
  type: "IPV4" | "IPV6" | "DOMAIN" | "URL" | "EMAIL" | "HASH_SHA256" | "HASH_MD5" | "FILE_PATH" | "USERNAME" | "PROCESS";
  riskLevel: "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "UNKNOWN";
  context: string;
  sourceEventId?: string;
  confidence: number; // 0 - 100
  firstSeen?: string;
  tags?: string[];
}

export interface GeminiInvestigationResult {
  verdict: "True Positive" | "False Positive" | "Suspicious Activity" | "Inconclusive";
  confidenceScore: number; // 0 - 100
  executiveSummary: string;
  observedEvidence: string[];
  reasoningAndInferences: string[];
  uncertaintyAndGaps: string[];
  mitreMappings: MitreTechnique[];
  recommendedContainment: string[];
  recommendedInvestigation: string[];
  extractedIocs?: Array<{
    type: string;
    value: string;
    riskLevel: string;
    context: string;
  }>;
}

export interface Alert {
  id: string;
  title: string;
  timestamp: string;
  severity: Severity;
  detectionSource: DetectionSource;
  ruleId?: string;
  ruleName?: string;
  riskScore: number; // 0 - 100 (application logic calculated)
  detectionConfidence: number; // 0 - 100
  aiConfidence?: number; // 0 - 100
  host: string;
  sourceIp: string;
  destinationIp?: string;
  username: string;
  status: AlertStatus;
  evidence: string[];
  relatedEventIds: string[];
  mitreTechniques: MitreTechnique[];
  description: string;
  notes?: string;
  geminiAnalysis?: GeminiInvestigationResult;
  updatedAt?: string;
}

export interface IncidentReport {
  id: string;
  incidentId: string;
  reportTitle: string;
  generatedAt: string;
  createdAt?: string;
  author: string;
  status?: "DRAFT" | "FINAL" | "SUBMITTED";
  classification?: string;
  executiveSummary: string;
  incidentDescription: string;
  detectionMethod: string;
  affectedAssets: string[];
  affectedUsers: string[];
  timeline: TimelineEvent[];
  iocs?: IOC[];
  extractedIocs?: IOC[];
  evidence?: string[];
  mitreMappings: MitreTechnique[];
  riskAssessment: {
    quantitativeScore: number; // 0-100
    impactRating: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
    confidentialityImpact?: string;
    integrityImpact?: string;
    availabilityImpact?: string;
  };
  rootCauseAnalysis: string;
  containmentActionsCompleted: string[];
  eradicationAndRemediation: string[];
  lessonsLearnedAndPreventativeControls: string[];
  analystConclusion: string;
}

export interface PhishingAnalysisResult {
  phishingRiskScore: number; // 0 - 100
  classification: string;
  confidence: number;
  senderAnalysis: {
    isSpoofed: boolean;
    domainMismatch: boolean;
    displaySender?: string;
    actualSenderDomain?: string;
    analysis: string;
  };
  authenticationStatus: {
    spf: string;
    dkim: string;
    dmarc: string;
    notes?: string;
  };
  extractedUrls: Array<{
    url: string;
    defangedUrl: string;
    risk: string;
    reason?: string;
  }>;
  socialEngineeringIndicators: string[];
  keyEvidence: string[];
  recommendedActions: string[];
  executiveSummary: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  enabled: boolean;
  description: string;
  mitreId: string;
  thresholds: Record<string, number>;
}
