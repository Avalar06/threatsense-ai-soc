import { Alert, DetectionRule, SecurityEvent, Severity } from "../types/soc.js";
import { MITRE_TACTICS } from "../data/mitreDatabase.js";

export const DEFAULT_DETECTION_RULES: DetectionRule[] = [
  {
    id: "RULE-001",
    name: "High-Frequency Authentication Failures (Brute Force)",
    category: "Authentication",
    severity: "HIGH",
    enabled: true,
    description: "Detects multiple failed login attempts against one or more accounts from the same source IP in a short window.",
    mitreId: "T1110",
    thresholds: { failedLoginsThreshold: 3, windowSeconds: 300 },
  },
  {
    id: "RULE-002",
    name: "Successful Authentication Post-Brute Force",
    category: "Credential Compromise",
    severity: "CRITICAL",
    enabled: true,
    description: "Detects a successful authentication event from an IP that previously generated multiple failed logons.",
    mitreId: "T1078",
    thresholds: { priorFailuresRequired: 2 },
  },
  {
    id: "RULE-003",
    name: "Suspicious PowerShell & Encoded Execution",
    category: "Execution",
    severity: "CRITICAL",
    enabled: true,
    description: "Detects execution of PowerShell with hidden window, bypass flags, or Base64 -EncodedCommand scripts.",
    mitreId: "T1059.001",
    thresholds: {},
  },
  {
    id: "RULE-004",
    name: "Privilege Escalation & Unauthorized Sudo",
    category: "Privilege Escalation",
    severity: "HIGH",
    enabled: true,
    description: "Detects sudo su escalation, assigning debug privileges (Event 4672), or adding users to Domain Admins.",
    mitreId: "T1548.003",
    thresholds: {},
  },
  {
    id: "RULE-005",
    name: "Port Scanning & Network Reconnaissance",
    category: "Discovery",
    severity: "MEDIUM",
    enabled: true,
    description: "Detects a single source IP probing multiple distinct destination ports in rapid succession.",
    mitreId: "T1046",
    thresholds: { distinctPortThreshold: 4 },
  },
  {
    id: "RULE-006",
    name: "Known C2 Beaconing & High-Risk Outbound Connection",
    category: "Command & Control",
    severity: "CRITICAL",
    enabled: true,
    description: "Detects outbound network connections to flagged C2 infrastructure or CobaltStrike listeners.",
    mitreId: "T1071.001",
    thresholds: {},
  },
  {
    id: "RULE-007",
    name: "Web Application SQL Injection / Path Traversal Probing",
    category: "Initial Access",
    severity: "HIGH",
    enabled: true,
    description: "Detects SQL injection signatures (UNION SELECT, ' OR '1'='1) or path traversal payloads in HTTP requests.",
    mitreId: "T1190",
    thresholds: {},
  },
  {
    id: "RULE-008",
    name: "Suspicious Windows Service Installation",
    category: "Persistence",
    severity: "HIGH",
    enabled: true,
    description: "Detects Event ID 7045 indicating installation of unfamiliar binaries or services.",
    mitreId: "T1543.003",
    thresholds: {},
  },
  {
    id: "RULE-009",
    name: "OS Credential Dumping & LSASS Access",
    category: "Credential Access",
    severity: "CRITICAL",
    enabled: true,
    description: "Detects memory dump commands targeting lsass.exe, mimi.dll, or Mimikatz artifacts.",
    mitreId: "T1003.001",
    thresholds: {},
  },
];

let alertCounter = 500;
function generateAlertId(): string {
  alertCounter += 1;
  return `ALT-${Date.now().toString(36).toUpperCase()}-${alertCounter}`;
}

// Transparent Mathematical Risk Score Calculator
export function calculateRiskScore(params: {
  severity: Severity;
  eventCount: number;
  isOffHours: boolean;
  isDomainControllerOrFinance: boolean;
  hasC2OrMalwareSignature: boolean;
}): { riskScore: number; confidence: number } {
  const severityBase: Record<Severity, number> = {
    CRITICAL: 88,
    HIGH: 72,
    MEDIUM: 52,
    LOW: 32,
    INFORMATIONAL: 15,
  };

  const base = severityBase[params.severity] || 50;
  const frequencyFactor = Math.min(params.eventCount * 3, 20);
  const assetWeight = params.isDomainControllerOrFinance ? 15 : 5;
  const offHoursWeight = params.isOffHours ? 8 : 0;
  const sigBonus = params.hasC2OrMalwareSignature ? 12 : 0;

  const rawScore = Math.round(base * 0.5 + frequencyFactor * 0.2 + assetWeight + offHoursWeight + sigBonus);
  const riskScore = Math.min(100, Math.max(10, rawScore));

  // Detection confidence based on clarity of indicators
  const confidence = params.hasC2OrMalwareSignature
    ? 94
    : params.severity === "CRITICAL"
    ? 91
    : params.severity === "HIGH"
    ? 85
    : 78;

  return { riskScore, confidence };
}

export function runDetectionEngine(events: SecurityEvent[], rules = DEFAULT_DETECTION_RULES): Alert[] {
  const alerts: Alert[] = [];
  if (!events || events.length === 0) return alerts;

  // Group events by source_ip and by host
  const eventsByIp: Record<string, SecurityEvent[]> = {};
  const eventsByHost: Record<string, SecurityEvent[]> = {};

  for (const evt of events) {
    if (!eventsByIp[evt.source_ip]) eventsByIp[evt.source_ip] = [];
    eventsByIp[evt.source_ip].push(evt);

    if (!eventsByHost[evt.hostname]) eventsByHost[evt.hostname] = [];
    eventsByHost[evt.hostname].push(evt);
  }

  // Check Rule 1: High-Frequency Auth Failures (Brute Force)
  const r1 = rules.find((r) => r.id === "RULE-001" && r.enabled);
  if (r1) {
    for (const [ip, ipEvents] of Object.entries(eventsByIp)) {
      const failEvents = ipEvents.filter((e) => e.event_type === "AUTH_FAILURE" || e.status === "FAILURE");
      if (failEvents.length >= (r1.thresholds.failedLoginsThreshold || 3)) {
        const targetedUsers = Array.from(new Set(failEvents.map((e) => e.username)));
        const targetHost = failEvents[0].hostname;
        const isDC = targetHost.includes("DC") || targetHost.includes("FIN");

        const { riskScore, confidence } = calculateRiskScore({
          severity: "HIGH",
          eventCount: failEvents.length,
          isOffHours: checkIsOffHours(failEvents[0].timestamp),
          isDomainControllerOrFinance: isDC,
          hasC2OrMalwareSignature: false,
        });

        alerts.push({
          id: generateAlertId(),
          title: `Brute Force Authentication Attempt (${failEvents.length} Failures)`,
          timestamp: failEvents[failEvents.length - 1].timestamp,
          severity: "HIGH",
          detectionSource: "RULE_BASED",
          ruleId: "RULE-001",
          ruleName: r1.name,
          riskScore,
          detectionConfidence: confidence,
          host: targetHost,
          sourceIp: ip,
          destinationIp: failEvents[0].destination_ip,
          username: targetedUsers.join(", "),
          status: "NEW",
          evidence: failEvents.map((e) => `[${e.timestamp}] ${e.message}`),
          relatedEventIds: failEvents.map((e) => e.id),
          mitreTechniques: [
            {
              id: "T1110",
              name: "Brute Force",
              tactic: "Credential Access",
              subtechnique: "T1110.001 Password Guessing",
              explanation: `Observed ${failEvents.length} sequential failed authentication attempts targeting users: ${targetedUsers.join(", ")} from source IP ${ip}.`,
              confidence: 90,
              validationStatus: "VERIFIED",
            },
          ],
          description: `Repeated authentication failures detected from remote IP ${ip} targeting accounts (${targetedUsers.join(", ")}) on host ${targetHost}.`,
        });
      }
    }
  }

  // Check Rule 2: Successful Auth Post-Brute Force (Credential Compromise)
  const r2 = rules.find((r) => r.id === "RULE-002" && r.enabled);
  if (r2) {
    for (const [ip, ipEvents] of Object.entries(eventsByIp)) {
      const failEvents = ipEvents.filter((e) => e.event_type === "AUTH_FAILURE" || e.status === "FAILURE");
      const successEvents = ipEvents.filter((e) => e.event_type === "AUTH_SUCCESS" || e.status === "SUCCESS" && e.action === "LOGIN_SUCCESS");

      if (failEvents.length >= 2 && successEvents.length > 0) {
        const lastSuccess = successEvents[0];
        const isDC = lastSuccess.hostname.includes("DC") || lastSuccess.hostname.includes("FIN");

        const { riskScore, confidence } = calculateRiskScore({
          severity: "CRITICAL",
          eventCount: failEvents.length + successEvents.length,
          isOffHours: checkIsOffHours(lastSuccess.timestamp),
          isDomainControllerOrFinance: isDC,
          hasC2OrMalwareSignature: false,
        });

        alerts.push({
          id: generateAlertId(),
          title: `Possible Credential Compromise (Successful Login Post-Failures)`,
          timestamp: lastSuccess.timestamp,
          severity: "CRITICAL",
          detectionSource: "RULE_BASED",
          ruleId: "RULE-002",
          ruleName: r2.name,
          riskScore,
          detectionConfidence: confidence,
          host: lastSuccess.hostname,
          sourceIp: ip,
          destinationIp: lastSuccess.destination_ip,
          username: lastSuccess.username,
          status: "NEW",
          evidence: [
            ...failEvents.map((e) => `Prior Failure: [${e.timestamp}] ${e.message}`),
            `Accepted Logon: [${lastSuccess.timestamp}] ${lastSuccess.message}`,
          ],
          relatedEventIds: [...failEvents.map((e) => e.id), lastSuccess.id],
          mitreTechniques: [
            {
              id: "T1078",
              name: "Valid Accounts",
              tactic: "Initial Access",
              explanation: `Successful logon achieved for account ${lastSuccess.username} following ${failEvents.length} prior failed attempts from external IP ${ip}.`,
              confidence: 94,
              validationStatus: "VERIFIED",
            },
          ],
          description: `Account '${lastSuccess.username}' was successfully logged into from ${ip} after multiple failed attempts, indicating potential password guessing or credential stuffing success.`,
        });
      }
    }
  }

  // Check Rule 3: Suspicious PowerShell / Encoded Execution
  const r3 = rules.find((r) => r.id === "RULE-003" && r.enabled);
  if (r3) {
    const psEvents = events.filter(
      (e) =>
        e.process?.toLowerCase().includes("powershell") ||
        e.raw.toLowerCase().includes("-encodedcommand") ||
        e.raw.toLowerCase().includes("downloadstring") ||
        e.raw.toLowerCase().includes("exec bypass")
    );

    if (psEvents.length > 0) {
      for (const evt of psEvents) {
        const { riskScore, confidence } = calculateRiskScore({
          severity: "CRITICAL",
          eventCount: 1,
          isOffHours: checkIsOffHours(evt.timestamp),
          isDomainControllerOrFinance: true,
          hasC2OrMalwareSignature: true,
        });

        alerts.push({
          id: generateAlertId(),
          title: `Suspicious Encoded PowerShell Execution`,
          timestamp: evt.timestamp,
          severity: "CRITICAL",
          detectionSource: "RULE_BASED",
          ruleId: "RULE-003",
          ruleName: r3.name,
          riskScore,
          detectionConfidence: confidence,
          host: evt.hostname,
          sourceIp: evt.source_ip,
          destinationIp: evt.destination_ip,
          username: evt.username,
          status: "NEW",
          evidence: [evt.raw],
          relatedEventIds: [evt.id],
          mitreTechniques: [
            {
              id: "T1059.001",
              name: "Command and Scripting Interpreter: PowerShell",
              tactic: "Execution",
              explanation: "PowerShell executed with hidden window and bypass flags to download and execute remote payload.",
              confidence: 96,
              validationStatus: "VERIFIED",
            },
            {
              id: "T1027",
              name: "Obfuscated Files or Information",
              tactic: "Defense Evasion",
              explanation: "Use of Base64 -EncodedCommand to conceal execution arguments from static inspection.",
              confidence: 92,
              validationStatus: "VERIFIED",
            },
          ],
          description: `Obfuscated PowerShell execution detected on ${evt.hostname} invoking WebClient download cradle.`,
        });
      }
    }
  }

  // Check Rule 4: Privilege Escalation & Unauthorized Sudo
  const r4 = rules.find((r) => r.id === "RULE-004" && r.enabled);
  if (r4) {
    const privEvents = events.filter(
      (e) =>
        e.event_type === "PRIVILEGE_ESCALATE" ||
        e.raw.includes("sudo su") ||
        e.raw.includes("EventID=4672") ||
        e.raw.includes("Domain Admins")
    );

    if (privEvents.length > 0) {
      const first = privEvents[0];
      const { riskScore, confidence } = calculateRiskScore({
        severity: "HIGH",
        eventCount: privEvents.length,
        isOffHours: checkIsOffHours(first.timestamp),
        isDomainControllerOrFinance: true,
        hasC2OrMalwareSignature: false,
      });

      alerts.push({
        id: generateAlertId(),
        title: `Privilege Escalation Activity Detected`,
        timestamp: first.timestamp,
        severity: "HIGH",
        detectionSource: "RULE_BASED",
        ruleId: "RULE-004",
        ruleName: r4.name,
        riskScore,
        detectionConfidence: confidence,
        host: first.hostname,
        sourceIp: first.source_ip,
        destinationIp: first.destination_ip,
        username: first.username,
        status: "NEW",
        evidence: privEvents.map((e) => e.raw),
        relatedEventIds: privEvents.map((e) => e.id),
        mitreTechniques: [
          {
            id: "T1548.003",
            name: "Abuse Elevation Control Mechanism: Sudo and Sudoers",
            tactic: "Privilege Escalation",
            explanation: `User ${first.username} elevated permissions to root / admin level.`,
            confidence: 90,
            validationStatus: "VERIFIED",
          },
        ],
        description: `Privilege elevation detected on host ${first.hostname} for account ${first.username}.`,
      });
    }
  }

  // Check Rule 5: Port Scanning
  const r5 = rules.find((r) => r.id === "RULE-005" && r.enabled);
  if (r5) {
    for (const [ip, ipEvents] of Object.entries(eventsByIp)) {
      const portHits = new Set(ipEvents.map((e) => e.destination_port).filter(Boolean));
      if (portHits.size >= (r5.thresholds.distinctPortThreshold || 4)) {
        const { riskScore, confidence } = calculateRiskScore({
          severity: "MEDIUM",
          eventCount: ipEvents.length,
          isOffHours: false,
          isDomainControllerOrFinance: false,
          hasC2OrMalwareSignature: false,
        });

        alerts.push({
          id: generateAlertId(),
          title: `Network Port Sweep / Scanning Activity (${portHits.size} Ports Probed)`,
          timestamp: ipEvents[0].timestamp,
          severity: "MEDIUM",
          detectionSource: "RULE_BASED",
          ruleId: "RULE-005",
          ruleName: r5.name,
          riskScore,
          detectionConfidence: confidence,
          host: ipEvents[0].hostname,
          sourceIp: ip,
          destinationIp: ipEvents[0].destination_ip,
          username: "anonymous",
          status: "NEW",
          evidence: ipEvents.slice(0, 8).map((e) => e.raw),
          relatedEventIds: ipEvents.slice(0, 8).map((e) => e.id),
          mitreTechniques: [
            {
              id: "T1046",
              name: "Network Service Scanning",
              tactic: "Discovery",
              explanation: `Source IP ${ip} probed ${portHits.size} distinct ports (${Array.from(portHits).join(", ")}) across network perimeter.`,
              confidence: 88,
              validationStatus: "VERIFIED",
            },
          ],
          description: `Rapid multi-port SYN sweep detected from IP ${ip} attempting to identify open services.`,
        });
      }
    }
  }

  // Check Rule 6: C2 Outbound Connection
  const r6 = rules.find((r) => r.id === "RULE-006" && r.enabled);
  if (r6) {
    const c2Events = events.filter(
      (e) =>
        e.raw.toLowerCase().includes("c2") ||
        e.raw.toLowerCase().includes("cobaltstrike") ||
        e.destination_port === 4444 ||
        e.raw.includes("194.26.29.112")
    );

    if (c2Events.length > 0) {
      const first = c2Events[0];
      const { riskScore, confidence } = calculateRiskScore({
        severity: "CRITICAL",
        eventCount: c2Events.length,
        isOffHours: true,
        isDomainControllerOrFinance: true,
        hasC2OrMalwareSignature: true,
      });

      alerts.push({
        id: generateAlertId(),
        title: `Suspicious Outbound Command & Control (C2) Connection`,
        timestamp: first.timestamp,
        severity: "CRITICAL",
        detectionSource: "RULE_BASED",
        ruleId: "RULE-006",
        ruleName: r6.name,
        riskScore,
        detectionConfidence: confidence,
        host: first.hostname,
        sourceIp: first.source_ip,
        destinationIp: first.destination_ip,
        username: first.username,
        status: "NEW",
        evidence: c2Events.map((e) => e.raw),
        relatedEventIds: c2Events.map((e) => e.id),
        mitreTechniques: [
          {
            id: "T1071.001",
            name: "Application Layer Protocol: Web Protocols",
            tactic: "Command and Control",
            explanation: `Outbound beacon connection established to remote IP ${first.destination_ip}:${first.destination_port || 4444}.`,
            confidence: 96,
            validationStatus: "VERIFIED",
          },
        ],
        description: `Host ${first.hostname} established persistent outbound socket to suspected C2 node ${first.destination_ip}.`,
      });
    }
  }

  // Check Rule 7: Web SQLi / Path Traversal
  const r7 = rules.find((r) => r.id === "RULE-007" && r.enabled);
  if (r7) {
    const webAttackEvents = events.filter(
      (e) =>
        e.raw.toLowerCase().includes("union select") ||
        e.raw.toLowerCase().includes("' or '1'='1") ||
        e.raw.toLowerCase().includes("sqlmap") ||
        e.raw.toLowerCase().includes("/etc/passwd") ||
        e.raw.toLowerCase().includes("cmd.php")
    );

    if (webAttackEvents.length > 0) {
      const first = webAttackEvents[0];
      const { riskScore, confidence } = calculateRiskScore({
        severity: "HIGH",
        eventCount: webAttackEvents.length,
        isOffHours: false,
        isDomainControllerOrFinance: false,
        hasC2OrMalwareSignature: true,
      });

      alerts.push({
        id: generateAlertId(),
        title: `Web Application Exploitation Attempt (SQLi & Path Traversal)`,
        timestamp: first.timestamp,
        severity: "HIGH",
        detectionSource: "RULE_BASED",
        ruleId: "RULE-007",
        ruleName: r7.name,
        riskScore,
        detectionConfidence: confidence,
        host: first.hostname,
        sourceIp: first.source_ip,
        destinationIp: first.destination_ip,
        username: first.username,
        status: "NEW",
        evidence: webAttackEvents.map((e) => e.raw),
        relatedEventIds: webAttackEvents.map((e) => e.id),
        mitreTechniques: [
          {
            id: "T1190",
            name: "Exploit Public-Facing Application",
            tactic: "Initial Access",
            explanation: "Automated SQL injection probe and web shell invocation detected in web server access logs.",
            confidence: 94,
            validationStatus: "VERIFIED",
          },
        ],
        description: `Exploitation signatures detected targeting web services on ${first.hostname} from IP ${first.source_ip}.`,
      });
    }
  }

  // Check Rule 8: Windows Service Installation
  const r8 = rules.find((r) => r.id === "RULE-008" && r.enabled);
  if (r8) {
    const svcEvents = events.filter((e) => e.raw.includes("EventID=7045") || e.event_type === "SERVICE_CREATE");
    if (svcEvents.length > 0) {
      const first = svcEvents[0];
      const { riskScore, confidence } = calculateRiskScore({
        severity: "HIGH",
        eventCount: 1,
        isOffHours: true,
        isDomainControllerOrFinance: true,
        hasC2OrMalwareSignature: false,
      });

      alerts.push({
        id: generateAlertId(),
        title: `Suspicious Windows Service Installation (Persistence)`,
        timestamp: first.timestamp,
        severity: "HIGH",
        detectionSource: "RULE_BASED",
        ruleId: "RULE-008",
        ruleName: r8.name,
        riskScore,
        detectionConfidence: confidence,
        host: first.hostname,
        sourceIp: first.source_ip,
        destinationIp: first.destination_ip,
        username: first.username,
        status: "NEW",
        evidence: svcEvents.map((e) => e.raw),
        relatedEventIds: svcEvents.map((e) => e.id),
        mitreTechniques: [
          {
            id: "T1543.003",
            name: "Create or Modify System Process: Windows Service",
            tactic: "Persistence",
            explanation: "New system service created executing binary from non-standard directory.",
            confidence: 88,
            validationStatus: "VERIFIED",
          },
        ],
        description: `Unrecognized Windows Service created on ${first.hostname} with persistence attributes.`,
      });
    }
  }

  // Check Rule 9: LSASS Dumping
  const r9 = rules.find((r) => r.id === "RULE-009" && r.enabled);
  if (r9) {
    const lsassEvents = events.filter(
      (e) =>
        e.raw.toLowerCase().includes("dumplsass") ||
        e.raw.toLowerCase().includes("mimi.dll") ||
        e.raw.toLowerCase().includes("mimikatz") ||
        (e.raw.toLowerCase().includes("lsass") && (e.raw.toLowerCase().includes("dump") || e.process?.toLowerCase().includes("procdump")))
    );

    if (lsassEvents.length > 0) {
      const first = lsassEvents[0];
      const { riskScore, confidence } = calculateRiskScore({
        severity: "CRITICAL",
        eventCount: 1,
        isOffHours: true,
        isDomainControllerOrFinance: true,
        hasC2OrMalwareSignature: true,
      });

      alerts.push({
        id: generateAlertId(),
        title: `OS Credential Dumping Attempt (LSASS Memory)`,
        timestamp: first.timestamp,
        severity: "CRITICAL",
        detectionSource: "RULE_BASED",
        ruleId: "RULE-009",
        ruleName: r9.name,
        riskScore,
        detectionConfidence: confidence,
        host: first.hostname,
        sourceIp: first.source_ip,
        destinationIp: first.destination_ip,
        username: first.username,
        status: "NEW",
        evidence: lsassEvents.map((e) => e.raw),
        relatedEventIds: lsassEvents.map((e) => e.id),
        mitreTechniques: [
          {
            id: "T1003.001",
            name: "OS Credential Dumping: LSASS Memory",
            tactic: "Credential Access",
            explanation: "Process attempted memory dump of Local Security Authority Subsystem Service (lsass.exe).",
            confidence: 98,
            validationStatus: "VERIFIED",
          },
        ],
        description: `High-impact credential theft attempt detected attempting to dump LSASS memory on ${first.hostname}.`,
      });
    }
  }

  return alerts;
}

export function analyzeSecurityEvent(event: SecurityEvent): Alert | null {
  const alerts = runDetectionEngine([event]);
  return alerts.length > 0 ? alerts[0] : null;
}

function checkIsOffHours(timestampStr: string): boolean {
  try {
    const d = new Date(timestampStr);
    const hour = d.getUTCHours();
    return hour >= 0 && hour <= 5;
  } catch {
    return false;
  }
}
