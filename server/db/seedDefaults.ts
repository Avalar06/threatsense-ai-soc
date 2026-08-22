/**
 * ThreatSense AI - Default Seed Data for Detection Strategies and SOAR Playbooks
 * 
 * Provides official MITRE ATT&CK v15.1 Detection Strategies and production SOAR Playbooks.
 */

import type { DetectionStrategy, SoarPlaybook } from "../../src/types/soc.js";
import type { DatabaseSync } from "node:sqlite";
import { safeJsonStringify } from "./schema.js";

export const DEFAULT_DETECTION_STRATEGIES: DetectionStrategy[] = [
  {
    id: "STRAT-001",
    name: "Brute Force to Valid Account Authentication",
    description: "Correlates repeated failed authentications followed by a successful authentication from the same source IP or targeting the same user context within a 15-minute window.",
    techniqueId: "T1110.001",
    techniqueName: "Password Guessing",
    tactic: "Credential Access",
    attackVersion: "v15.1",
    analyticConditions: [
      "Count of failed authentications (AUTH_FAILURE / LOGIN_FAIL) >= 2 from source IP",
      "Subsequent successful authentication (AUTH_SUCCESS / LOGIN_SUCCESS) from same source IP or user",
      "Timestamp delta <= 15 minutes (900 seconds)"
    ],
    requiredTelemetry: [
      "security_events:AUTH_FAILURE",
      "security_events:AUTH_SUCCESS"
    ],
    supportedPlatforms: ["Windows", "Linux", "Cloud / IAM"],
    severity: "CRITICAL",
    confidenceModel: {
      baseConfidence: "HIGH",
      minEvidenceCount: 3,
      evidenceWeights: {
        priorFailures: 30,
        successMatch: 40,
        dcTarget: 20,
        offHours: 10
      }
    },
    evidenceRequirements: [
      "Prior failure event IDs and timestamps",
      "Successful logon event ID and timestamp",
      "Matching source IP and targeted username"
    ],
    isActive: true,
    createdAt: "2026-08-22T00:00:00.000Z",
    updatedAt: "2026-08-22T00:00:00.000Z"
  },
  {
    id: "STRAT-002",
    name: "Credential Access to Privileged Escalation",
    description: "Correlates credential extraction or LSASS memory access events with subsequent administrative privilege escalation (e.g. sudo elevation, debug rights) on the same host.",
    techniqueId: "T1003.001",
    techniqueName: "OS Credential Dumping: LSASS Memory",
    tactic: "Credential Access",
    attackVersion: "v15.1",
    analyticConditions: [
      "Observed credential dumping or suspicious process targeting security authority",
      "Privilege escalation event (PRIVILEGE_ESCALATE / sudo su / Event 4672) on same hostname",
      "Timestamp delta <= 15 minutes"
    ],
    requiredTelemetry: [
      "security_events:PROCESS_CREATE",
      "security_events:PRIVILEGE_ESCALATE"
    ],
    supportedPlatforms: ["Windows", "Linux"],
    severity: "CRITICAL",
    confidenceModel: {
      baseConfidence: "HIGH",
      minEvidenceCount: 2,
      evidenceWeights: {
        credentialDumpObserved: 45,
        privilegeEscalated: 45,
        privilegedAccountTargeted: 10
      }
    },
    evidenceRequirements: [
      "Credential extraction event ID",
      "Privilege escalation event ID",
      "Hostname and username"
    ],
    isActive: true,
    createdAt: "2026-08-22T00:00:00.000Z",
    updatedAt: "2026-08-22T00:00:00.000Z"
  },
  {
    id: "STRAT-003",
    name: "Suspicious Script Execution to Outbound Network Connection",
    description: "Correlates hidden or encoded script execution (PowerShell / Bash / Scripting Engine) with subsequent outbound network connections from the same host to an external IP.",
    techniqueId: "T1059.001",
    techniqueName: "PowerShell Execution",
    tactic: "Execution",
    attackVersion: "v15.1",
    analyticConditions: [
      "Process execution with suspicious flags (e.g., -EncodedCommand, -nop, -w hidden, curl | bash)",
      "Outbound network connection (NETWORK_CONNECT / HTTP_REQUEST) originating from the same host within 15 minutes"
    ],
    requiredTelemetry: [
      "security_events:PROCESS_CREATE",
      "security_events:NETWORK_CONNECT"
    ],
    supportedPlatforms: ["Windows", "Linux"],
    severity: "HIGH",
    confidenceModel: {
      baseConfidence: "HIGH",
      minEvidenceCount: 2,
      evidenceWeights: {
        suspiciousExecution: 40,
        outboundConnect: 40,
        externalDestination: 20
      }
    },
    evidenceRequirements: [
      "Process command line event ID",
      "Network connection event ID",
      "Hostname and destination IP/port"
    ],
    isActive: true,
    createdAt: "2026-08-22T00:00:00.000Z",
    updatedAt: "2026-08-22T00:00:00.000Z"
  },
  {
    id: "STRAT-004",
    name: "Indicator of Compromise (IOC) Cross-Event Reuse",
    description: "Correlates observations of the exact same high-risk IP, domain, or file hash across multiple distinct security events or alerts across the environment.",
    techniqueId: "T1071",
    techniqueName: "Application Layer Protocol",
    tactic: "Command and Control",
    attackVersion: "v15.1",
    analyticConditions: [
      "Identical IOC value appearing across >= 2 distinct security events or alerts",
      "IOC threat level is SUSPICIOUS or MALICIOUS"
    ],
    requiredTelemetry: [
      "ioc_records",
      "security_events"
    ],
    supportedPlatforms: ["Windows", "Linux", "Network"],
    severity: "HIGH",
    confidenceModel: {
      baseConfidence: "MEDIUM",
      minEvidenceCount: 2,
      evidenceWeights: {
        iocMatches: 50,
        providerReputation: 30,
        distinctEvents: 20
      }
    },
    evidenceRequirements: [
      "IOC record ID and defanged value",
      "List of matching event IDs",
      "Distinct hostnames or source IPs involved"
    ],
    isActive: true,
    createdAt: "2026-08-22T00:00:00.000Z",
    updatedAt: "2026-08-22T00:00:00.000Z"
  },
  {
    id: "STRAT-005",
    name: "Multi-Host Lateral Movement / Reconnaissance Probing",
    description: "Correlates a single remote source IP or compromised user context probing or attempting access across 2 or more distinct hostnames within the configured correlation window.",
    techniqueId: "T1046",
    techniqueName: "Network Service Discovery",
    tactic: "Discovery",
    attackVersion: "v15.1",
    analyticConditions: [
      "Same source IP or username appearing across >= 2 distinct hostnames",
      "Network connect, discovery, or authentication event types",
      "Observed within 15-minute time window"
    ],
    requiredTelemetry: [
      "security_events:NETWORK_CONNECT",
      "security_events:AUTH_FAILURE",
      "security_events:AUTH_SUCCESS"
    ],
    supportedPlatforms: ["Windows", "Linux", "Network"],
    severity: "HIGH",
    confidenceModel: {
      baseConfidence: "HIGH",
      minEvidenceCount: 2,
      evidenceWeights: {
        multipleHosts: 50,
        reconActivity: 30,
        timeProximity: 20
      }
    },
    evidenceRequirements: [
      "Source IP or username",
      "List of distinct targeted hostnames",
      "Matched event IDs"
    ],
    isActive: true,
    createdAt: "2026-08-22T00:00:00.000Z",
    updatedAt: "2026-08-22T00:00:00.000Z"
  }
];

export const DEFAULT_SOAR_PLAYBOOKS: SoarPlaybook[] = [
  {
    id: "PLAYBOOK-001",
    name: "Critical Endpoint Isolation & Forensic Evidence Collection",
    description: "Quarantines a compromised endpoint via EDR/Network connectors to halt lateral spread and initiates automated memory/log evidence capture.",
    version: "1.0.0",
    status: "ENABLED",
    triggerType: "INCIDENT",
    triggerConditions: {
      minSeverity: "HIGH",
      requireHost: true
    },
    policy: {
      requiresApproval: true,
      minSeverity: "HIGH",
      allowedRoles: ["SOC_LEAD", "SECURITY_ENGINEER", "INCIDENT_RESPONDER"],
      autoExecuteIfConfidence: "HIGH"
    },
    actions: [
      {
        stepId: "STEP-1",
        name: "Network Endpoint Isolation",
        actionType: "ISOLATE_HOST",
        connectorCategory: "EDR",
        targetExpression: "{{host}}",
        timeoutMs: 15000,
        retryLimit: 2,
        requireVerification: true,
        rollbackAction: "ISOLATE_HOST"
      },
      {
        stepId: "STEP-2",
        name: "Forensic Evidence Collection",
        actionType: "COLLECT_EVIDENCE",
        connectorCategory: "EDR",
        targetExpression: "{{host}}",
        timeoutMs: 30000,
        retryLimit: 1,
        requireVerification: true
      }
    ],
    createdAt: "2026-08-22T00:00:00.000Z",
    updatedAt: "2026-08-22T00:00:00.000Z"
  },
  {
    id: "PLAYBOOK-002",
    name: "Malicious Threat Indicator Firewall Perimeter Block",
    description: "Applies edge firewall / network security blocking policies against confirmed malicious external IP addresses or command-and-control infrastructure.",
    version: "1.0.0",
    status: "ENABLED",
    triggerType: "CORRELATION",
    triggerConditions: {
      minSeverity: "HIGH",
      requireSourceIp: true
    },
    policy: {
      requiresApproval: true,
      minSeverity: "HIGH",
      allowedRoles: ["SOC_ANALYST", "SOC_LEAD", "SECURITY_ENGINEER"]
    },
    actions: [
      {
        stepId: "STEP-1",
        name: "Perimeter Ingress/Egress Drop Rule",
        actionType: "BLOCK_IP",
        connectorCategory: "FIREWALL",
        targetExpression: "{{sourceIp}}",
        timeoutMs: 10000,
        retryLimit: 3,
        requireVerification: true
      }
    ],
    createdAt: "2026-08-22T00:00:00.000Z",
    updatedAt: "2026-08-22T00:00:00.000Z"
  },
  {
    id: "PLAYBOOK-003",
    name: "Compromised User Identity Containment & Session Revocation",
    description: "Suspends account credentials in Identity Provider (IdP) and terminates all active OAuth/SSO sessions for compromised user contexts.",
    version: "1.0.0",
    status: "ENABLED",
    triggerType: "ALERT",
    triggerConditions: {
      categories: ["Authentication", "Credential Compromise"],
      requireUsername: true
    },
    policy: {
      requiresApproval: true,
      minSeverity: "MEDIUM",
      allowedRoles: ["SOC_ANALYST", "SOC_LEAD", "IAM_ADMIN"]
    },
    actions: [
      {
        stepId: "STEP-1",
        name: "Disable IAM Account & Invalidate Tokens",
        actionType: "DISABLE_ACCOUNT",
        connectorCategory: "IDENTITY",
        targetExpression: "{{username}}",
        timeoutMs: 10000,
        retryLimit: 2,
        requireVerification: true
      }
    ],
    createdAt: "2026-08-22T00:00:00.000Z",
    updatedAt: "2026-08-22T00:00:00.000Z"
  }
];

export function seedDefaultsIfEmpty(db: DatabaseSync): void {
  // 1. Seed Detection Strategies
  const stratCountRow = db.prepare("SELECT COUNT(*) as count FROM detection_strategies").get() as { count: number };
  if (!stratCountRow || stratCountRow.count === 0) {
    const insertStrat = db.prepare(`
      INSERT INTO detection_strategies (
        id, name, description, technique_id, technique_name, tactic,
        attack_version, analytic_conditions, required_telemetry,
        supported_platforms, severity, confidence_model, evidence_requirements,
        is_active, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?
      )
    `);

    for (const strat of DEFAULT_DETECTION_STRATEGIES) {
      insertStrat.run(
        strat.id,
        strat.name,
        strat.description,
        strat.techniqueId,
        strat.techniqueName,
        strat.tactic,
        strat.attackVersion,
        safeJsonStringify(strat.analyticConditions),
        safeJsonStringify(strat.requiredTelemetry),
        safeJsonStringify(strat.supportedPlatforms),
        strat.severity,
        safeJsonStringify(strat.confidenceModel),
        safeJsonStringify(strat.evidenceRequirements),
        strat.isActive ? 1 : 0,
        strat.createdAt,
        strat.updatedAt
      );
    }
  }

  // 2. Seed SOAR Playbooks
  const playbookCountRow = db.prepare("SELECT COUNT(*) as count FROM soar_playbooks").get() as { count: number };
  if (!playbookCountRow || playbookCountRow.count === 0) {
    const insertPlaybook = db.prepare(`
      INSERT INTO soar_playbooks (
        id, name, description, version, status,
        trigger_type, trigger_conditions, policy, actions,
        created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?
      )
    `);

    for (const pb of DEFAULT_SOAR_PLAYBOOKS) {
      insertPlaybook.run(
        pb.id,
        pb.name,
        pb.description,
        pb.version,
        pb.status,
        pb.triggerType,
        safeJsonStringify(pb.triggerConditions),
        safeJsonStringify(pb.policy),
        safeJsonStringify(pb.actions),
        pb.createdAt,
        pb.updatedAt
      );
    }
  }
}
