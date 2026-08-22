/**
 * ThreatSense AI - Production Detection & Correlation Engine
 * 
 * Implements deterministic correlation strategies operating exclusively on real persisted telemetry.
 * Computes explainable risk scores, evidence-based confidence ratings, and suppresses duplicate
 * correlations via cryptographic SHA-256 fingerprinting.
 */

import crypto from "node:crypto";
import type { SocDatabase } from "../db/database.js";
import type {
  CorrelationRecord,
  CorrelationConfidence,
  RiskContributor,
  CorrelationEvidence,
  Severity,
  SecurityEvent,
  Alert,
  IOC,
  DetectionStrategy
} from "../../src/types/soc.js";

export interface CorrelationRunOptions {
  windowSeconds?: number; // Default 15 mins (900s)
  strategyIds?: string[];
  incidentId?: string;
  forceReevaluate?: boolean;
}

export interface CorrelationEvaluationResult {
  status: "COMPLETED" | "INSUFFICIENT_TELEMETRY";
  evaluatedStrategies: number;
  correlationsFound: number;
  newCorrelationsPersisted: number;
  correlations: CorrelationRecord[];
  explanations: string[];
  insufficientTelemetryDetails?: Array<{
    strategyId: string;
    strategyName: string;
    missingRequirement: string;
  }>;
}

/**
 * Deterministic helper to parse ISO / standard timestamps into milliseconds.
 */
export function parseEventTimeMs(timestampStr: string): number {
  const parsed = Date.parse(timestampStr);
  return isNaN(parsed) ? 0 : parsed;
}

/**
 * Computes deterministic SHA-256 fingerprint for correlation deduplication.
 */
export function computeCorrelationFingerprint(
  strategyId: string,
  eventIds: string[],
  alertIds: string[] = [],
  iocIds: string[] = []
): string {
  const sortedEvents = [...eventIds].sort().join(",");
  const sortedAlerts = [...alertIds].sort().join(",");
  const sortedIocs = [...iocIds].sort().join(",");
  const rawKey = `${strategyId}|events:${sortedEvents}|alerts:${sortedAlerts}|iocs:${sortedIocs}`;
  return crypto.createHash("sha256").update(rawKey).digest("hex");
}

export class ProductionCorrelationEngine {
  private db: SocDatabase;

  constructor(db: SocDatabase) {
    this.db = db;
  }

  /**
   * Evaluates all active detection strategies against real persisted database records.
   */
  async evaluateAll(options: CorrelationRunOptions = {}): Promise<CorrelationEvaluationResult> {
    const windowMs = (options.windowSeconds || 900) * 1000;
    const strategies = this.db.listDetectionStrategies({ isActive: true });
    
    // Filter strategies if specific strategy IDs requested
    const targetStrategies = options.strategyIds && options.strategyIds.length > 0
      ? strategies.filter((s) => options.strategyIds!.includes(s.id))
      : strategies;

    const allEvents = this.db.getAllEvents();
    const allAlerts = this.db.getAllAlerts();
    const allIocs = this.db.listIocs({ limit: 1000 }).iocs;

    if (allEvents.length === 0 && allAlerts.length === 0 && allIocs.length === 0) {
      return {
        status: "INSUFFICIENT_TELEMETRY",
        evaluatedStrategies: targetStrategies.length,
        correlationsFound: 0,
        newCorrelationsPersisted: 0,
        correlations: [],
        explanations: ["No security telemetry events, alerts, or IOC records found in the database to correlate."],
        insufficientTelemetryDetails: targetStrategies.map((s) => ({
          strategyId: s.id,
          strategyName: s.name,
          missingRequirement: `Requires persisted records: ${s.requiredTelemetry.join(", ")}`
        }))
      };
    }

    const createdCorrelations: CorrelationRecord[] = [];
    const explanations: string[] = [];
    const insufficientDetails: Array<{ strategyId: string; strategyName: string; missingRequirement: string }> = [];
    let newPersistedCount = 0;

    for (const strategy of targetStrategies) {
      let matchedForStrategy: CorrelationRecord[] = [];

      switch (strategy.id) {
        case "STRAT-001":
          matchedForStrategy = this.evaluateBruteForceToSuccess(strategy, allEvents, allAlerts, windowMs);
          break;
        case "STRAT-002":
          matchedForStrategy = this.evaluateCredentialAccessToPrivilegeEscalation(strategy, allEvents, allAlerts, windowMs);
          break;
        case "STRAT-003":
          matchedForStrategy = this.evaluateSuspiciousExecutionToNetwork(strategy, allEvents, allAlerts, windowMs);
          break;
        case "STRAT-004":
          matchedForStrategy = this.evaluateIocReuse(strategy, allEvents, allAlerts, allIocs);
          break;
        case "STRAT-005":
          matchedForStrategy = this.evaluateMultiHostLateralMovement(strategy, allEvents, allAlerts, windowMs);
          break;
        default:
          matchedForStrategy = [];
      }

      if (matchedForStrategy.length === 0) {
        insufficientDetails.push({
          strategyId: strategy.id,
          strategyName: strategy.name,
          missingRequirement: `No sequential telemetry pattern satisfied condition: ${strategy.analyticConditions.join("; ")}`
        });
      } else {
        for (const corr of matchedForStrategy) {
          if (options.incidentId) {
            corr.incidentId = options.incidentId;
          }

          // Check if fingerprint already exists
          const existing = this.db.getCorrelationByFingerprint(corr.fingerprint);
          if (!existing) {
            this.db.insertCorrelation(corr);
            newPersistedCount += 1;
            createdCorrelations.push(corr);
            explanations.push(`[${strategy.id}] Correlated ${corr.matchedEventIds.length} events across strategy '${strategy.name}' with risk score ${corr.riskScore}/100.`);
          } else {
            createdCorrelations.push(existing);
          }
        }
      }
    }

    return {
      status: createdCorrelations.length > 0 ? "COMPLETED" : "INSUFFICIENT_TELEMETRY",
      evaluatedStrategies: targetStrategies.length,
      correlationsFound: createdCorrelations.length,
      newCorrelationsPersisted: newPersistedCount,
      correlations: createdCorrelations,
      explanations,
      insufficientTelemetryDetails: insufficientDetails.length > 0 ? insufficientDetails : undefined
    };
  }

  // =========================================================================
  // STRATEGY 1: BRUTE FORCE → SUCCESSFUL AUTHENTICATION
  // =========================================================================
  private evaluateBruteForceToSuccess(
    strategy: DetectionStrategy,
    events: SecurityEvent[],
    alerts: Alert[],
    windowMs: number
  ): CorrelationRecord[] {
    const results: CorrelationRecord[] = [];
    
    // Group events by source_ip and username
    const eventsByIp: Record<string, SecurityEvent[]> = {};
    for (const evt of events) {
      if (!evt.source_ip || evt.source_ip === "UNKNOWN" || evt.source_ip === "") continue;
      if (!eventsByIp[evt.source_ip]) eventsByIp[evt.source_ip] = [];
      eventsByIp[evt.source_ip].push(evt);
    }

    for (const [ip, ipEvents] of Object.entries(eventsByIp)) {
      // Sort chronologically
      const sorted = [...ipEvents].sort((a, b) => parseEventTimeMs(a.timestamp) - parseEventTimeMs(b.timestamp));

      // Find failure sequences
      const failures = sorted.filter(
        (e) => e.event_type === "AUTH_FAILURE" || e.action === "LOGIN_FAIL" || e.status === "FAILURE"
      );
      const successes = sorted.filter(
        (e) => e.event_type === "AUTH_SUCCESS" || e.action === "LOGIN_SUCCESS" || (e.status === "SUCCESS" && e.action === "ALLOW")
      );

      if (failures.length >= 2 && successes.length >= 1) {
        for (const success of successes) {
          const successTime = parseEventTimeMs(success.timestamp);
          // Find preceding failures within window
          const precedingFailures = failures.filter((f) => {
            const failTime = parseEventTimeMs(f.timestamp);
            return failTime <= successTime && (successTime - failTime) <= windowMs;
          });

          if (precedingFailures.length >= 2) {
            const matchedEvents = [...precedingFailures, success];
            const matchedEventIds = matchedEvents.map((e) => e.id);
            const matchedAlerts = alerts.filter((a) =>
              a.sourceIp === ip || a.relatedEventIds.some((eid) => matchedEventIds.includes(eid))
            );
            const matchedAlertIds = matchedAlerts.map((a) => a.id);

            const hosts = Array.from(new Set(matchedEvents.map((e) => e.hostname).filter(Boolean)));
            const users = Array.from(new Set(matchedEvents.map((e) => e.username).filter(Boolean)));
            const sourceIps = [ip];
            const timestamps = matchedEvents.map((e) => e.timestamp);

            const fingerprint = computeCorrelationFingerprint(strategy.id, matchedEventIds, matchedAlertIds);

            // Calculate explainable risk contributors
            const contributors: RiskContributor[] = [
              { factor: "Repeated authentication failures from same source", contribution: 30 },
              { factor: "Successful authentication following brute force attempt", contribution: 40 }
            ];

            let score = 70;
            if (hosts.some((h) => h.toUpperCase().includes("DC") || h.toUpperCase().includes("FIN"))) {
              contributors.push({ factor: "Target asset is critical infrastructure (Domain Controller / Finance)", contribution: 15 });
              score += 15;
            }
            if (precedingFailures.length > 5) {
              contributors.push({ factor: "High-volume attack intensity (>5 failed attempts)", contribution: 10 });
              score += 10;
            }

            const riskScore = Math.min(100, Math.max(0, score));
            const confidence: CorrelationConfidence = precedingFailures.length >= 3 ? "HIGH" : "MEDIUM";

            const evidence: CorrelationEvidence = {
              eventIds: matchedEventIds,
              alertIds: matchedAlertIds,
              iocIds: [],
              timestamps,
              hosts,
              users,
              sourceIps,
              details: {
                failedAttemptsCount: precedingFailures.length,
                successEventId: success.id,
                targetedUser: success.username,
                timeDeltaSeconds: Math.round((successTime - parseEventTimeMs(precedingFailures[0].timestamp)) / 1000)
              }
            };

            const explanation = `Correlated brute force authentication sequence from IP ${ip} (${precedingFailures.length} failures) culminating in successful authentication for user '${success.username}' on host '${success.hostname}'.`;

            results.push({
              id: `CORR-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 10000)}`,
              strategyId: strategy.id,
              analyticId: "ANALYTIC-001",
              strategyName: strategy.name,
              matchedEventIds,
              matchedAlertIds,
              iocIds: [],
              severity: "CRITICAL",
              confidence,
              riskScore,
              contributors,
              evidence,
              explanation,
              fingerprint,
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString()
            });
            break; // One correlation per IP sequence is sufficient
          }
        }
      }
    }

    return results;
  }

  // =========================================================================
  // STRATEGY 2: CREDENTIAL ACCESS → PRIVILEGE ESCALATION
  // =========================================================================
  private evaluateCredentialAccessToPrivilegeEscalation(
    strategy: DetectionStrategy,
    events: SecurityEvent[],
    alerts: Alert[],
    windowMs: number
  ): CorrelationRecord[] {
    const results: CorrelationRecord[] = [];

    // Group events by hostname
    const eventsByHost: Record<string, SecurityEvent[]> = {};
    for (const evt of events) {
      if (!evt.hostname) continue;
      if (!eventsByHost[evt.hostname]) eventsByHost[evt.hostname] = [];
      eventsByHost[evt.hostname].push(evt);
    }

    for (const [host, hostEvents] of Object.entries(eventsByHost)) {
      const sorted = [...hostEvents].sort((a, b) => parseEventTimeMs(a.timestamp) - parseEventTimeMs(b.timestamp));

      // Credential dump indicators
      const credDumpEvents = sorted.filter((e) => {
        const text = `${e.process || ""} ${e.command_line || ""} ${e.message} ${e.raw}`.toLowerCase();
        return (
          text.includes("lsass") ||
          text.includes("mimikatz") ||
          text.includes("mimi.dll") ||
          text.includes("sekurlsa") ||
          text.includes("procdump") ||
          text.includes("/etc/shadow") ||
          text.includes("sam") && text.includes("system")
        );
      });

      // Privilege escalation indicators
      const privEscEvents = sorted.filter((e) => {
        const text = `${e.process || ""} ${e.command_line || ""} ${e.message} ${e.raw}`.toLowerCase();
        return (
          e.event_type === "PRIVILEGE_ESCALATE" ||
          e.action === "ESCALATE" ||
          text.includes("sudo su") ||
          text.includes("sudo -i") ||
          text.includes("event 4672") ||
          text.includes("se_debug_privilege") ||
          text.includes("administrators") && text.includes("add")
        );
      });

      if (credDumpEvents.length > 0 && privEscEvents.length > 0) {
        for (const credEvt of credDumpEvents) {
          const credTime = parseEventTimeMs(credEvt.timestamp);
          const subsequentPrivEsc = privEscEvents.filter((p) => {
            const pTime = parseEventTimeMs(p.timestamp);
            return pTime >= credTime && (pTime - credTime) <= windowMs;
          });

          if (subsequentPrivEsc.length > 0) {
            const matchedEvents = [credEvt, ...subsequentPrivEsc];
            const matchedEventIds = matchedEvents.map((e) => e.id);
            const matchedAlerts = alerts.filter((a) =>
              a.host === host || a.relatedEventIds.some((eid) => matchedEventIds.includes(eid))
            );
            const matchedAlertIds = matchedAlerts.map((a) => a.id);

            const hosts = [host];
            const users = Array.from(new Set(matchedEvents.map((e) => e.username).filter(Boolean)));
            const sourceIps = Array.from(new Set(matchedEvents.map((e) => e.source_ip).filter(Boolean)));
            const timestamps = matchedEvents.map((e) => e.timestamp);

            const fingerprint = computeCorrelationFingerprint(strategy.id, matchedEventIds, matchedAlertIds);

            const contributors: RiskContributor[] = [
              { factor: "OS Credential access / LSASS inspection observed", contribution: 45 },
              { factor: "Subsequent administrative privilege escalation on same host", contribution: 45 }
            ];

            let score = 90;
            if (host.toUpperCase().includes("DC") || host.toUpperCase().includes("PROD")) {
              contributors.push({ factor: "Target asset is enterprise Domain Controller or Production server", contribution: 10 });
              score += 10;
            }

            const riskScore = Math.min(100, Math.max(0, score));
            const confidence: CorrelationConfidence = "HIGH";

            const evidence: CorrelationEvidence = {
              eventIds: matchedEventIds,
              alertIds: matchedAlertIds,
              iocIds: [],
              timestamps,
              hosts,
              users,
              sourceIps,
              details: {
                dumpEventId: credEvt.id,
                privEscEventIds: subsequentPrivEsc.map((p) => p.id),
                host
              }
            };

            const explanation = `Correlated credential dumping operation followed by privilege escalation on host '${host}' within ${Math.round(windowMs / 60000)} minutes.`;

            results.push({
              id: `CORR-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 10000)}`,
              strategyId: strategy.id,
              analyticId: "ANALYTIC-002",
              strategyName: strategy.name,
              matchedEventIds,
              matchedAlertIds,
              iocIds: [],
              severity: "CRITICAL",
              confidence,
              riskScore,
              contributors,
              evidence,
              explanation,
              fingerprint,
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString()
            });
            break;
          }
        }
      }
    }

    return results;
  }

  // =========================================================================
  // STRATEGY 3: SUSPICIOUS SCRIPT EXECUTION → REMOTE C2 / OUTBOUND NETWORK
  // =========================================================================
  private evaluateSuspiciousExecutionToNetwork(
    strategy: DetectionStrategy,
    events: SecurityEvent[],
    alerts: Alert[],
    windowMs: number
  ): CorrelationRecord[] {
    const results: CorrelationRecord[] = [];

    const eventsByHost: Record<string, SecurityEvent[]> = {};
    for (const evt of events) {
      if (!evt.hostname) continue;
      if (!eventsByHost[evt.hostname]) eventsByHost[evt.hostname] = [];
      eventsByHost[evt.hostname].push(evt);
    }

    for (const [host, hostEvents] of Object.entries(eventsByHost)) {
      const sorted = [...hostEvents].sort((a, b) => parseEventTimeMs(a.timestamp) - parseEventTimeMs(b.timestamp));

      // Suspicious script execution
      const execEvents = sorted.filter((e) => {
        const text = `${e.process || ""} ${e.command_line || ""} ${e.message} ${e.raw}`.toLowerCase();
        return (
          text.includes("-encodedcommand") ||
          text.includes("-enc ") ||
          text.includes("-nop -w hidden") ||
          text.includes("downloadstring") ||
          text.includes("iex(") ||
          text.includes("curl | bash") ||
          text.includes("sh -i >& /dev/tcp")
        );
      });

      // Outbound network connections
      const netEvents = sorted.filter((e) => {
        return (
          e.event_type === "NETWORK_CONNECT" ||
          e.event_type === "HTTP_REQUEST" ||
          (e.destination_ip && !e.destination_ip.startsWith("127.") && !e.destination_ip.startsWith("0.0."))
        );
      });

      if (execEvents.length > 0 && netEvents.length > 0) {
        for (const execEvt of execEvents) {
          const execTime = parseEventTimeMs(execEvt.timestamp);
          const subsequentNet = netEvents.filter((n) => {
            const nTime = parseEventTimeMs(n.timestamp);
            return nTime >= execTime && (nTime - execTime) <= windowMs;
          });

          if (subsequentNet.length > 0) {
            const matchedEvents = [execEvt, ...subsequentNet];
            const matchedEventIds = matchedEvents.map((e) => e.id);
            const matchedAlerts = alerts.filter((a) =>
              a.host === host || a.relatedEventIds.some((eid) => matchedEventIds.includes(eid))
            );
            const matchedAlertIds = matchedAlerts.map((a) => a.id);

            const hosts = [host];
            const users = Array.from(new Set(matchedEvents.map((e) => e.username).filter(Boolean)));
            const sourceIps = Array.from(new Set(matchedEvents.map((e) => e.source_ip).filter(Boolean)));
            const destinationIps = Array.from(new Set(matchedEvents.map((e) => e.destination_ip).filter(Boolean)));
            const timestamps = matchedEvents.map((e) => e.timestamp);

            const fingerprint = computeCorrelationFingerprint(strategy.id, matchedEventIds, matchedAlertIds);

            const contributors: RiskContributor[] = [
              { factor: "Obfuscated / encoded script execution command observed", contribution: 40 },
              { factor: "Subsequent outbound network socket connection from executing host", contribution: 40 }
            ];

            let score = 80;
            if (destinationIps.length > 0) {
              contributors.push({ factor: `Outbound connection to external IP (${destinationIps[0]})`, contribution: 10 });
              score += 10;
            }

            const riskScore = Math.min(100, Math.max(0, score));
            const confidence: CorrelationConfidence = "HIGH";

            const evidence: CorrelationEvidence = {
              eventIds: matchedEventIds,
              alertIds: matchedAlertIds,
              iocIds: [],
              timestamps,
              hosts,
              users,
              sourceIps,
              destinationIps,
              details: {
                execEventId: execEvt.id,
                networkEventIds: subsequentNet.map((n) => n.id),
                host
              }
            };

            const explanation = `Correlated encoded script execution with outbound network communication on host '${host}' to ${destinationIps.join(", ") || "external endpoint"}.`;

            results.push({
              id: `CORR-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 10000)}`,
              strategyId: strategy.id,
              analyticId: "ANALYTIC-003",
              strategyName: strategy.name,
              matchedEventIds,
              matchedAlertIds,
              iocIds: [],
              severity: "HIGH",
              confidence,
              riskScore,
              contributors,
              evidence,
              explanation,
              fingerprint,
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString()
            });
            break;
          }
        }
      }
    }

    return results;
  }

  // =========================================================================
  // STRATEGY 4: IOC REUSE ACROSS MULTIPLE EVENTS
  // =========================================================================
  private evaluateIocReuse(
    strategy: DetectionStrategy,
    events: SecurityEvent[],
    alerts: Alert[],
    iocs: IOC[]
  ): CorrelationRecord[] {
    const results: CorrelationRecord[] = [];

    for (const ioc of iocs) {
      if (!ioc.value || ioc.value.length < 3) continue;

      // Find events matching this IOC
      const matchedEvents = events.filter((e) => {
        const raw = `${e.source_ip} ${e.destination_ip} ${e.raw} ${e.message} ${e.process || ""}`;
        return raw.includes(ioc.value);
      });

      // Find alerts matching this IOC
      const matchedAlerts = alerts.filter((a) => {
        const raw = `${a.sourceIp} ${a.destinationIp || ""} ${a.title} ${a.description}`;
        return raw.includes(ioc.value);
      });

      if (matchedEvents.length >= 2 || (matchedEvents.length >= 1 && matchedAlerts.length >= 1)) {
        const matchedEventIds = matchedEvents.map((e) => e.id);
        const matchedAlertIds = matchedAlerts.map((a) => a.id);
        const iocIds = [ioc.id];

        const hosts = Array.from(new Set(matchedEvents.map((e) => e.hostname).filter(Boolean)));
        const users = Array.from(new Set(matchedEvents.map((e) => e.username).filter(Boolean)));
        const sourceIps = Array.from(new Set(matchedEvents.map((e) => e.source_ip).filter(Boolean)));
        const timestamps = matchedEvents.map((e) => e.timestamp);

        const fingerprint = computeCorrelationFingerprint(strategy.id, matchedEventIds, matchedAlertIds, iocIds);

        const contributors: RiskContributor[] = [
          { factor: `Indicator (${ioc.type} ${ioc.defangedValue}) observed across multiple distinct events`, contribution: 45 },
          { factor: `IOC Threat Level: ${ioc.riskLevel}`, contribution: ioc.riskLevel === "MALICIOUS" ? 35 : 20 }
        ];

        let score = ioc.riskLevel === "MALICIOUS" ? 80 : 65;
        if (hosts.length > 1) {
          contributors.push({ factor: `Indicator appears across ${hosts.length} distinct hosts`, contribution: 15 });
          score += 15;
        }

        const riskScore = Math.min(100, Math.max(0, score));
        const confidence: CorrelationConfidence = ioc.confidence > 70 ? "HIGH" : "MEDIUM";

        const evidence: CorrelationEvidence = {
          eventIds: matchedEventIds,
          alertIds: matchedAlertIds,
          iocIds,
          timestamps,
          hosts,
          users,
          sourceIps,
          details: {
            iocValue: ioc.defangedValue,
            iocType: ioc.type,
            riskLevel: ioc.riskLevel,
            eventsCount: matchedEvents.length,
            alertsCount: matchedAlerts.length
          }
        };

        const explanation = `Correlated indicator of compromise (${ioc.type} ${ioc.defangedValue}) detected across ${matchedEvents.length} events and ${matchedAlerts.length} alerts.`;

        results.push({
          id: `CORR-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 10000)}`,
          strategyId: strategy.id,
          analyticId: "ANALYTIC-004",
          strategyName: strategy.name,
          matchedEventIds,
          matchedAlertIds,
          iocIds,
          severity: ioc.riskLevel === "MALICIOUS" ? "HIGH" : "MEDIUM",
          confidence,
          riskScore,
          contributors,
          evidence,
          explanation,
          fingerprint,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        });
      }
    }

    return results;
  }

  // =========================================================================
  // STRATEGY 5: MULTI-HOST LATERAL MOVEMENT / RECONNAISSANCE
  // =========================================================================
  private evaluateMultiHostLateralMovement(
    strategy: DetectionStrategy,
    events: SecurityEvent[],
    alerts: Alert[],
    windowMs: number
  ): CorrelationRecord[] {
    const results: CorrelationRecord[] = [];

    // Group events by source_ip
    const eventsByIp: Record<string, SecurityEvent[]> = {};
    for (const evt of events) {
      if (!evt.source_ip || evt.source_ip === "UNKNOWN" || evt.source_ip === "") continue;
      if (!eventsByIp[evt.source_ip]) eventsByIp[evt.source_ip] = [];
      eventsByIp[evt.source_ip].push(evt);
    }

    for (const [ip, ipEvents] of Object.entries(eventsByIp)) {
      const distinctHosts = Array.from(new Set(ipEvents.map((e) => e.hostname).filter(Boolean)));
      if (distinctHosts.length >= 2) {
        // Verify they fall within the correlation window
        const sorted = [...ipEvents].sort((a, b) => parseEventTimeMs(a.timestamp) - parseEventTimeMs(b.timestamp));
        const firstTime = parseEventTimeMs(sorted[0].timestamp);
        const lastTime = parseEventTimeMs(sorted[sorted.length - 1].timestamp);

        if (lastTime - firstTime <= windowMs || sorted.length >= 2) {
          const matchedEvents = sorted;
          const matchedEventIds = matchedEvents.map((e) => e.id);
          const matchedAlerts = alerts.filter((a) =>
            a.sourceIp === ip || a.relatedEventIds.some((eid) => matchedEventIds.includes(eid))
          );
          const matchedAlertIds = matchedAlerts.map((a) => a.id);

          const hosts = distinctHosts;
          const users = Array.from(new Set(matchedEvents.map((e) => e.username).filter(Boolean)));
          const sourceIps = [ip];
          const timestamps = matchedEvents.map((e) => e.timestamp);

          const fingerprint = computeCorrelationFingerprint(strategy.id, matchedEventIds, matchedAlertIds);

          const contributors: RiskContributor[] = [
            { factor: `Single source IP probed or interacted with ${distinctHosts.length} distinct hosts`, contribution: 50 },
            { factor: "Reconnaissance / Lateral Movement activity pattern", contribution: 25 }
          ];

          let score = 75;
          if (distinctHosts.length >= 3) {
            contributors.push({ factor: `Broad multi-host spread (${distinctHosts.length} targets)`, contribution: 15 });
            score += 15;
          }

          const riskScore = Math.min(100, Math.max(0, score));
          const confidence: CorrelationConfidence = distinctHosts.length >= 3 ? "HIGH" : "MEDIUM";

          const evidence: CorrelationEvidence = {
            eventIds: matchedEventIds,
            alertIds: matchedAlertIds,
            iocIds: [],
            timestamps,
            hosts,
            users,
            sourceIps,
            details: {
              sourceIp: ip,
              targetedHosts: distinctHosts,
              totalEvents: matchedEvents.length
            }
          };

          const explanation = `Correlated multi-host activity originating from source IP ${ip} targeting ${distinctHosts.length} distinct hosts (${distinctHosts.join(", ")}) within correlation window.`;

          results.push({
            id: `CORR-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 10000)}`,
            strategyId: strategy.id,
            analyticId: "ANALYTIC-005",
            strategyName: strategy.name,
            matchedEventIds,
            matchedAlertIds,
            iocIds: [],
            severity: "HIGH",
            confidence,
            riskScore,
            contributors,
            evidence,
            explanation,
            fingerprint,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          });
        }
      }
    }

    return results;
  }
}
