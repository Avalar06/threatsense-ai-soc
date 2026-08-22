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
  command_line?: string;
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

export interface IocEnrichment {
  id: string;
  iocId: string;
  provider: string;
  reputation: "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "UNKNOWN";
  threatLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  confidence: number; // 0 - 100
  classification?: string;
  firstSeen?: string;
  lastSeen?: string;
  enrichedAt: string;
  source?: string;
  summary: string;
  metadata?: Record<string, unknown> | null;
  status?: "ENRICHED" | "NOT_CONFIGURED" | "UNAVAILABLE" | "FAILED";
  createdAt: string;
  updatedAt: string;
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
  lastSeen?: string;
  tags?: string[];
  enrichments?: IocEnrichment[];
  latestEnrichment?: IocEnrichment | null;
  relatedAlertCount?: number;
  relatedIncidentCount?: number;
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
  assignedTo?: string;
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

export interface DashboardStats {
  totalAlerts: number;
  criticalAlerts: number;
  highAlerts: number;
  mediumAlerts: number;
  lowAlerts: number;
  infoAlerts: number;
  newAlerts: number;
  investigatingAlerts: number;
  resolvedAlerts: number;
  closedAlerts: number;
  activeHosts: number;
  averageRiskScore: number;
  alertsBySeverity?: Record<string, number>;
  alertsByStatus?: Record<string, number>;
}

export type IncidentStatus = "NEW" | "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "CLOSED";

export type ResponseActionType =
  | "ISOLATE_HOST"
  | "BLOCK_IP"
  | "BLOCK_DOMAIN"
  | "DISABLE_ACCOUNT"
  | "KILL_PROCESS"
  | "COLLECT_EVIDENCE";

export type ResponseTargetType =
  | "HOST"
  | "IP"
  | "DOMAIN"
  | "ACCOUNT"
  | "PROCESS"
  | "EVIDENCE";

export type ResponseActionStatus =
  | "REQUESTED"
  | "APPROVED"
  | "EXECUTED"
  | "FAILED"
  | "CANCELLED";

export interface IncidentResponseAction {
  id: string;
  incidentId: string;
  actionType: ResponseActionType;
  targetType: ResponseTargetType;
  target: string;
  status: ResponseActionStatus;
  requestedBy: string;
  approvedBy?: string;
  requestedAt: string;
  approvedAt?: string;
  executedAt?: string;
  result?: string;
  notes?: string;
  metadata?: Record<string, unknown> | null;
  createdAt: string;
  updatedAt: string;
}

export const VALID_ACTION_TARGET_MAP: Record<ResponseActionType, ResponseTargetType[]> = {
  ISOLATE_HOST: ["HOST"],
  BLOCK_IP: ["IP"],
  BLOCK_DOMAIN: ["DOMAIN"],
  DISABLE_ACCOUNT: ["ACCOUNT"],
  KILL_PROCESS: ["PROCESS"],
  COLLECT_EVIDENCE: ["EVIDENCE", "HOST"],
};

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus | string;
  priority?: string;
  leadAnalyst?: string;
  assignedTo?: string;
  createdAt: string;
  updatedAt: string;
  closedAt?: string;
  closedBy?: string;
  closureSummary?: string;
  alertIds?: string[];
  executiveSummary?: string;
  containmentActions?: string[];
  responseActions?: IncidentResponseAction[];
  summary?: string;
  scope?: string;
  tags?: string[];
  alerts?: Alert[];
  reports?: IncidentReport[];
}

// ==========================================
// PHASE 6: DETECTION STRATEGY & CORRELATION
// ==========================================

export type CorrelationConfidence = "HIGH" | "MEDIUM" | "LOW" | "INSUFFICIENT";

export interface DetectionStrategy {
  id: string;
  name: string;
  description: string;
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  attackVersion: string;
  analyticConditions: string[];
  requiredTelemetry: string[];
  supportedPlatforms: string[];
  severity: Severity;
  confidenceModel: {
    baseConfidence: CorrelationConfidence;
    minEvidenceCount: number;
    evidenceWeights?: Record<string, number>;
  };
  evidenceRequirements: string[];
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface RiskContributor {
  factor: string;
  contribution: number;
}

export interface CorrelationEvidence {
  eventIds: string[];
  alertIds: string[];
  iocIds: string[];
  timestamps: string[];
  hosts: string[];
  users: string[];
  sourceIps: string[];
  destinationIps?: string[];
  details?: Record<string, unknown>;
}

export interface CorrelationRecord {
  id: string;
  strategyId: string;
  analyticId: string;
  strategyName?: string;
  matchedEventIds: string[];
  matchedAlertIds: string[];
  iocIds?: string[];
  incidentId?: string;
  severity: Severity;
  confidence: CorrelationConfidence;
  riskScore: number; // 0 - 100
  contributors: RiskContributor[];
  evidence: CorrelationEvidence;
  explanation: string;
  fingerprint: string;
  createdAt: string;
  updatedAt: string;
}

// ==========================================
// PHASE 7: SOAR ORCHESTRATION & CONNECTORS
// ==========================================

export type SoarConnectorStatus = "CONFIGURED" | "NOT_CONFIGURED" | "HEALTHY" | "UNHEALTHY";

export type SoarConnectorCategory =
  | "EDR"
  | "SIEM"
  | "FIREWALL"
  | "IDENTITY"
  | "CLOUD"
  | "EMAIL"
  | "NETWORK"
  | "GENERIC";

export interface SoarConnectorInfo {
  id: string;
  name: string;
  category: SoarConnectorCategory;
  status: SoarConnectorStatus;
  capabilities: ResponseActionType[];
  healthMessage?: string;
  supportsRollback: boolean;
  supportsVerification: boolean;
  lastCheckedAt?: string;
}

export type PlaybookStatus = "DRAFT" | "ENABLED" | "DISABLED";

export type PlaybookTriggerType = "ALERT" | "CORRELATION" | "INCIDENT" | "MANUAL";

export type PlaybookExecutionStatus =
  | "PENDING"
  | "APPROVAL_REQUIRED"
  | "APPROVED"
  | "EXECUTING"
  | "SUCCEEDED"
  | "FAILED"
  | "TIMED_OUT"
  | "CANCELLED"
  | "VERIFYING";

export interface PlaybookActionDefinition {
  stepId: string;
  name: string;
  actionType: ResponseActionType;
  connectorCategory: SoarConnectorCategory;
  targetExpression: string; // e.g. "{{host}}", "{{sourceIp}}", "{{username}}"
  timeoutMs?: number;
  retryLimit?: number;
  requireVerification?: boolean;
  rollbackAction?: ResponseActionType;
}

export interface PlaybookPolicy {
  requiresApproval: boolean;
  minSeverity?: Severity;
  allowedRoles?: string[];
  autoExecuteIfConfidence?: CorrelationConfidence;
}

export interface SoarPlaybook {
  id: string;
  name: string;
  description: string;
  version: string;
  status: PlaybookStatus;
  triggerType: PlaybookTriggerType;
  triggerConditions: Record<string, unknown>;
  policy: PlaybookPolicy;
  actions: PlaybookActionDefinition[];
  createdAt: string;
  updatedAt: string;
}

export interface PlaybookStepState {
  stepId: string;
  actionType: ResponseActionType;
  target: string;
  targetType: ResponseTargetType;
  status: PlaybookExecutionStatus;
  connectorId?: string;
  providerRequestId?: string;
  providerResponse?: Record<string, unknown>;
  verificationResult?: {
    verified: boolean;
    message: string;
    timestamp: string;
  };
  retryCount: number;
  error?: string;
  startedAt?: string;
  completedAt?: string;
}

export interface SoarPlaybookExecution {
  id: string;
  playbookId: string;
  playbookName: string;
  playbookVersion: string;
  incidentId?: string;
  alertId?: string;
  correlationId?: string;
  initiatingUser: string;
  status: PlaybookExecutionStatus;
  approvedBy?: string;
  approvedAt?: string;
  rejectionReason?: string;
  currentStepIndex: number;
  totalSteps: number;
  stepsState: PlaybookStepState[];
  idempotencyKey: string;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
}

export interface SoarAuditLog {
  id: string;
  executionId?: string;
  incidentId?: string;
  actionType: string;
  connectorId: string;
  targetType: string;
  target: string;
  actor: string;
  eventType:
    | "APPROVAL_REQUESTED"
    | "APPROVED"
    | "REJECTED"
    | "EXECUTION_STARTED"
    | "EXECUTION_SUCCEEDED"
    | "EXECUTION_FAILED"
    | "VERIFIED"
    | "VERIFICATION_FAILED"
    | "ROLLBACK_STARTED"
    | "ROLLBACK_SUCCEEDED"
    | "ROLLBACK_FAILED"
    | "CANCELLED";
  details?: Record<string, unknown> | string;
  timestamp: string;
}

// ==========================================
// OBSERVABILITY & BENCHMARKS
// ==========================================

export interface SocMetrics {
  ingestion: {
    totalEvents: number;
    rejectedEvents: number;
    avgLatencyMs: number;
  };
  detection: {
    totalDetections: number;
    avgLatencyMs: number;
  };
  correlation: {
    totalCorrelations: number;
    avgLatencyMs: number;
    insufficientTelemetryCount: number;
  };
  soar: {
    totalExecutions: number;
    successfulExecutions: number;
    failedExecutions: number;
    pendingApprovals: number;
    avgExecutionLatencyMs: number;
  };
  threatIntel: {
    totalLookups: number;
    cacheHits: number;
    providerFailures: number;
  };
}

export interface PerClassBenchmarkMetric {
  attackClass: string;
  totalSamples: number;
  truePositives: number;
  falseNegatives: number;
  recall: number;
  detectionRate: number;
}

export interface BenchmarkLatencyDistribution {
  meanMs: number;
  medianMs: number;
  p95Ms: number;
  p99Ms: number;
}

export interface DatasetAdapterMetadata {
  adapterId: string;
  datasetName: string;
  officialSource: string;
  referenceUrl: string;
  datasetVersion: string;
  license?: string;
  status: "AVAILABLE" | "EXTERNAL_DATASET_NOT_AVAILABLE";
  sampleCount: number;
  maliciousCount: number;
  benignCount: number;
  labelSchema: string;
  preprocessingVersion: string;
  ingestionInstructions?: string;
  expectedFormat?: string;
}

export interface NormalizedBenchmarkRecord {
  sourceRecordId: string;
  sourceDataset: string;
  originalLabel: string;
  normalizedLabel: "ATTACK" | "BENIGN";
  attackClass?: string;
  expectedTechnique?: string;
  event: SecurityEvent;
}

export interface BenchmarkResult {
  benchmarkId: string;
  datasetName: string;
  datasetSource?: string;
  datasetVersion: string;
  datasetHash?: string;
  evaluationType: "INTERNAL_VALIDATION" | "EXTERNAL_BENCHMARK";
  rulesetVersion?: string;
  environment?: string;
  totalEventsEvaluated: number;
  attackEventsCount: number;
  normalEventsCount: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  accuracy: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  throughputEventsPerSecond: number;
  meanDetectionLatencyMs: number;
  meanCorrelationLatencyMs: number;
  latencyDistribution: BenchmarkLatencyDistribution;
  perClassMetrics: PerClassBenchmarkMetric[];
  correlationEvaluation: "NOT_AVAILABLE" | "EVALUATED" | "INSUFFICIENT_ATTACK_CHAINS";
  correlationCandidateCount?: number;
  confirmedCorrelationsCount?: number;
  measuredAt: string;
  memoryUsageMb: number;
  limitations: string[];
  researchIntegrityStatement: string;
}

export type BenchmarkExportFormat = "json" | "csv" | "markdown";

