import express, { Request, Response, Router } from "express";
import { ai } from "./geminiClient.js";
import { Type } from "@google/genai";
import { SocDatabase } from "./db/database.js";
import { parseRawLogs } from "../src/services/logParser.js";
import { runDetectionEngine } from "../src/services/detectionEngine.js";
import { enrichmentService } from "./services/iocEnrichmentService.js";
import type {
  Alert,
  SecurityEvent,
  IncidentReport,
  ResponseActionType,
  ResponseTargetType,
  ResponseActionStatus,
  IOC,
  IocEnrichment,
  TimelineEvent,
  MitreTechnique,
  GeminiInvestigationResult,
} from "../src/types/soc.js";
import { VALID_ACTION_TARGET_MAP } from "../src/types/soc.js";

export const apiRouter: Router = express.Router();

apiRouter.use(express.json({ limit: "10mb" }));

let dbInstance: SocDatabase | null = null;

export function getSocDatabase(): SocDatabase {
  if (!dbInstance) {
    dbInstance = new SocDatabase();
  }
  return dbInstance;
}

export function setSocDatabase(db: SocDatabase | null) {
  dbInstance = db;
}

export function buildIncidentTimeline(incidentId: string, db: SocDatabase): TimelineEvent[] {
  const incident = db.getIncidentById(incidentId);
  if (!incident) return [];

  const timelineEvents: TimelineEvent[] = [];

  // 1. Incident Creation Milestone
  timelineEvents.push({
    id: `TL-INC-CREATE-${incident.id}`,
    time: incident.createdAt,
    stage: "INCIDENT_CREATION",
    title: `Incident Created: ${incident.title}`,
    description: `Incident created with severity ${incident.severity} and priority ${incident.priority || "P2"}. Lead analyst assigned: ${incident.leadAnalyst || "Unassigned"}.`,
    severity: (incident.severity as any) || "HIGH",
  });

  // 2. Linked Alerts and their Security Events
  const alertIds = incident.alertIds || [];
  for (const alertId of alertIds) {
    const alert = db.getAlertById(alertId);
    if (!alert) continue;

    timelineEvents.push({
      id: `TL-ALT-${alert.id}`,
      time: alert.timestamp,
      stage: "DETECTION_TRIGGERED",
      title: `Alert Triggered: ${alert.title}`,
      description: `Rule '${alert.ruleName || alert.ruleId || alert.detectionSource}' triggered on host ${alert.host} (Source IP: ${alert.sourceIp}). Risk score: ${alert.riskScore}/100.`,
      severity: alert.severity,
      eventId: alert.id,
      tactics: (alert.mitreTechniques || []).map((m) => m.tactic),
    });

    if (alert.geminiAnalysis) {
      timelineEvents.push({
        id: `TL-AI-${alert.id}`,
        time: alert.updatedAt || alert.timestamp,
        stage: "AI_INVESTIGATION",
        title: `AI Investigation Verdict: ${alert.geminiAnalysis.verdict}`,
        description: `Gemini Confidence: ${alert.geminiAnalysis.confidenceScore}%. ${alert.geminiAnalysis.executiveSummary}`,
        severity: alert.severity,
      });
    }

    const events = db.getEventsByAlertId(alert.id);
    for (const evt of events) {
      timelineEvents.push({
        id: `TL-EVT-${evt.id}`,
        time: evt.timestamp,
        stage: "TELEMETRY_OBSERVED",
        title: `Security Event: ${evt.event_type} [${evt.action}]`,
        description: `${evt.message} (User: ${evt.username}, Host: ${evt.hostname}, Process: ${evt.process || "N/A"})`,
        severity: evt.severity,
        eventId: evt.id,
        rawEvidence: evt.raw,
      });
    }
  }

  // 3. Response Actions
  const actions = db.getIncidentActionsByIncidentId(incident.id);
  for (const action of actions) {
    timelineEvents.push({
      id: `TL-ACT-REQ-${action.id}`,
      time: action.requestedAt,
      stage: "ACTION_REQUESTED",
      title: `Response Action Requested: ${action.actionType}`,
      description: `Target: ${action.targetType} [${action.target}] requested by ${action.requestedBy}. Notes: ${action.notes || "None"}`,
      severity: "MEDIUM",
    });

    if (action.approvedAt) {
      timelineEvents.push({
        id: `TL-ACT-APP-${action.id}`,
        time: action.approvedAt,
        stage: "ACTION_APPROVED",
        title: `Response Action Approved: ${action.actionType}`,
        description: `Approved by ${action.approvedBy || "SOC Manager"} for target ${action.target}.`,
        severity: "LOW",
      });
    }

    if (action.executedAt) {
      timelineEvents.push({
        id: `TL-ACT-EXE-${action.id}`,
        time: action.executedAt,
        stage: "ACTION_EXECUTED",
        title: `Response Action Executed (Simulated): ${action.actionType}`,
        description: `Status: ${action.status}. Result: ${action.result || "Simulated execution recorded in SOC database."}`,
        severity: action.status === "FAILED" ? "HIGH" : "INFORMATIONAL",
      });
    }
  }

  // 4. Extracted IOCs & Enrichments
  const iocs = db.getIocsByIncidentId(incident.id);
  for (const ioc of iocs) {
    timelineEvents.push({
      id: `TL-IOC-${ioc.id}`,
      time: ioc.firstSeen || incident.createdAt,
      stage: "IOC_EXTRACTED",
      title: `IOC Extracted: ${ioc.type}`,
      description: `Indicator ${ioc.defangedValue || ioc.value} identified in incident telemetry with confidence ${ioc.confidence}%.`,
      severity: ioc.riskLevel === "MALICIOUS" ? "CRITICAL" : ioc.riskLevel === "SUSPICIOUS" ? "HIGH" : "MEDIUM",
    });

    const enrichments = db.getEnrichmentsByIocId(ioc.id);
    for (const enr of enrichments) {
      timelineEvents.push({
        id: `TL-ENR-${enr.id}`,
        time: enr.enrichedAt,
        stage: "IOC_ENRICHED",
        title: `Threat Intel: ${enr.provider} (${(enr as any).status || "PROCESSED"})`,
        description: `Threat Level: ${enr.threatLevel}, Reputation: ${enr.reputation}. ${enr.summary}`,
        severity: (enr.threatLevel as any) || "INFORMATIONAL",
      });
    }
  }

  // 5. Generated Incident Reports
  const reports = db.listReports({ incidentId: incident.id }).reports;
  for (const rpt of reports) {
    timelineEvents.push({
      id: `TL-RPT-${rpt.id}`,
      time: rpt.generatedAt || rpt.createdAt || incident.createdAt,
      stage: "REPORT_PUBLISHED",
      title: `Incident Report Published: ${rpt.reportTitle}`,
      description: `Author: ${rpt.author}. Status: ${rpt.status || "FINAL"}. Classification: ${rpt.classification || "INTERNAL"}`,
      severity: "INFORMATIONAL",
    });
  }

  // 6. Case Closure Milestone (if closed)
  if (incident.closedAt) {
    timelineEvents.push({
      id: `TL-INC-CLOSE-${incident.id}`,
      time: incident.closedAt,
      stage: "CASE_CLOSED",
      title: `Incident Case Closed`,
      description: `Closed by ${incident.closedBy || "SOC Lead"}. Closure Summary: ${incident.closureSummary || "Incident lifecycle closed successfully."}`,
      severity: "INFORMATIONAL",
    });
  }

  // Sort strictly chronological ascending
  return timelineEvents.sort((a, b) => {
    const tA = new Date(a.time).getTime() || 0;
    const tB = new Date(b.time).getTime() || 0;
    return tA - tB;
  });
}

function sendError(res: Response, status: number, code: string, message: string) {
  return res.status(status).json({
    success: false,
    error: {
      code,
      message,
    },
  });
}

// Robust generation with automatic model fallback & retry if quota or demand limit is reached
async function generateWithFallback(params: {
  contents: any;
  config?: any;
  primaryModel?: string;
}) {
  const primary = params.primaryModel || "gemini-3.7-flash";
  const fallback = "gemini-3.1-flash-lite";

  try {
    return await ai.models.generateContent({
      model: primary,
      contents: params.contents,
      config: params.config,
    });
  } catch (error: any) {
    const errorStr = (error.message || "") + " " + JSON.stringify(error);
    const isTransientOrQuota =
      errorStr.includes("429") ||
      errorStr.includes("503") ||
      errorStr.includes("RESOURCE_EXHAUSTED") ||
      errorStr.includes("UNAVAILABLE") ||
      errorStr.includes("high demand") ||
      errorStr.includes("quota") ||
      errorStr.includes("Overloaded");

    if (isTransientOrQuota) {
      console.warn(`[Gemini API] Primary model ${primary} unavailable/rate-limited, falling back to ${fallback}`);
      try {
        return await ai.models.generateContent({
          model: fallback,
          contents: params.contents,
          config: params.config,
        });
      } catch (fallbackError: any) {
        // Short pause and one retry on fallback model
        await new Promise((r) => setTimeout(r, 1000));
        return await ai.models.generateContent({
          model: fallback,
          contents: params.contents,
          config: params.config,
        });
      }
    }
    throw error;
  }
}

// 1. Health check endpoint
apiRouter.get("/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    service: "AI-SOC Investigator Backend",
    timestamp: new Date().toISOString(),
    geminiKeyConfigured: Boolean(process.env.GEMINI_API_KEY),
  });
});

// 2. Alert Investigation with Gemini
apiRouter.post("/investigate", async (req: Request, res: Response) => {
  try {
    const { alert, relatedEvents, customNotes } = req.body;
    if (!alert) {
      return res.status(400).json({ error: "Missing alert object in request payload" });
    }

    const systemInstruction = `You are a Senior Level 3 SOC Analyst and Incident Responder investigating a security alert.
Analyze ONLY the supplied security evidence, alerts, and raw event data.
CRITICAL RULES:
1. Do NOT hallucinate or invent event timestamps, IP addresses, usernames, or evidence not present in the payload.
2. Strictly separate:
   - Observed Evidence (verifiable facts directly present in log events)
   - Reasoning / Inferences (logical analysis of what the evidence implies)
   - Uncertainty & Alternative Hypotheses (false positive possibilities, missing log visibility)
   - Recommended Containment & Investigation Steps (concrete, prioritized tactical actions for a SOC analyst)
3. Provide realistic MITRE ATT&CK mapping based strictly on the observed technique mechanics.
Return output adhering to the requested JSON schema.`;

    const prompt = `Investigate the following security alert and related events:
ALERT SUMMARY:
- Alert ID: ${alert.id}
- Title: ${alert.title}
- Severity: ${alert.severity}
- Calculated Risk Score: ${alert.riskScore}/100
- Detection Method: ${alert.detectionSource}
- Affected Host: ${alert.host || "N/A"}
- Source IP: ${alert.sourceIp || "N/A"}
- Destination IP: ${alert.destinationIp || "N/A"}
- Username: ${alert.username || "N/A"}
- Evidence Summary: ${JSON.stringify(alert.evidence || [])}

RELATED NORMALIZED LOG EVENTS (${(relatedEvents || []).length} events):
${JSON.stringify((relatedEvents || []).slice(0, 40), null, 2)}

ANALYST NOTES / CONTEXT:
${customNotes || "Standard automated investigation trigger."}`;

    const response = await generateWithFallback({
      contents: prompt,
      config: {
        systemInstruction,
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            verdict: {
              type: Type.STRING,
              description: "True Positive, False Positive, Suspicious Activity, or Inconclusive",
            },
            confidenceScore: {
              type: Type.NUMBER,
              description: "Confidence in percentage between 0 and 100",
            },
            executiveSummary: {
              type: Type.STRING,
              description: "Clear, 2-3 sentence executive synopsis of what happened",
            },
            observedEvidence: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "Strictly verifiable facts with specific event references",
            },
            reasoningAndInferences: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "Logical deduction linking evidence to attack methodology",
            },
            uncertaintyAndGaps: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "Gaps in log visibility, benign explanations, or uncertainties",
            },
            mitreMappings: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  id: { type: Type.STRING },
                  name: { type: Type.STRING },
                  tactic: { type: Type.STRING },
                  explanation: { type: Type.STRING },
                  confidence: { type: Type.NUMBER },
                },
                required: ["id", "name", "tactic", "explanation"],
              },
            },
            recommendedContainment: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "Immediate isolation, credential reset, or firewall block actions",
            },
            recommendedInvestigation: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "Specific follow-up queries (e.g. check DNS logs, host forensic triage)",
            },
            extractedIocs: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  type: { type: Type.STRING },
                  value: { type: Type.STRING },
                  riskLevel: { type: Type.STRING },
                  context: { type: Type.STRING },
                },
                required: ["type", "value", "riskLevel"],
              },
            },
          },
          required: [
            "verdict",
            "confidenceScore",
            "executiveSummary",
            "observedEvidence",
            "reasoningAndInferences",
            "uncertaintyAndGaps",
            "mitreMappings",
            "recommendedContainment",
            "recommendedInvestigation",
          ],
        },
      },
    });

    const parsed = JSON.parse(response.text?.trim() || "{}");

    // Phase 4A: Persist Gemini Investigation Result directly into SQLite for the target alert
    if (alert && alert.id && getSocDatabase().existsAlert(alert.id)) {
      try {
        getSocDatabase().updateAlert(alert.id, {
          geminiAnalysis: parsed,
          aiConfidence: typeof parsed.confidenceScore === "number" ? parsed.confidenceScore : undefined,
          updatedAt: new Date().toISOString(),
        });
      } catch (persistErr: any) {
        console.error("Failed to persist Gemini investigation result to database:", persistErr);
        return res.status(500).json({
          error: "Failed to persist AI investigation result to database",
          details: persistErr.message,
        });
      }
    }

    return res.json({ success: true, analysis: parsed });
  } catch (error: any) {
    console.error("Error in /api/investigate:", error);
    return res.status(500).json({
      error: error.message || "Failed to complete AI investigation",
      details: error.stack,
    });
  }
});

// 3. AI SOC Analyst Assistant (Chat & Q&A)
apiRouter.post("/ai-analyst", async (req: Request, res: Response) => {
  try {
    const { message, conversationHistory, investigationContext } = req.body;
    if (!message) {
      return res.status(400).json({ error: "Missing message in request body" });
    }

    const systemInstruction = `You are a Tier 3 Cyber Defense AI Analyst in a Security Operations Center (SOC).
Your role is to assist security analysts in investigating alerts, interpreting complex logs, validating MITRE ATT&CK techniques, and formulating incident response playbooks.

GUIDELINES:
- Always base your answers on the provided Active Investigation & Log Context.
- Distinguish between facts observed in logs and your analytical deductions.
- Structure responses clearly with bullet points, code/log snippets, and bold headers where appropriate.
- When referencing IP addresses, ports, or processes from the context, be exact.
- If asked about something not in the context, explicitly say that additional telemetry is required.`;

    const contextSummary = investigationContext
      ? `CURRENT SOC WORKSPACE CONTEXT:
Active Alert: ${JSON.stringify(investigationContext.activeAlert || null)}
Ingested Events Count: ${investigationContext.totalEvents || 0}
Sample Events: ${JSON.stringify((investigationContext.sampleEvents || []).slice(0, 15), null, 2)}
Known IOCs: ${JSON.stringify(investigationContext.iocs || [])}
Risk Score: ${investigationContext.activeAlert?.riskScore || "N/A"}`
      : "No specific alert is currently pinned. Provide general SOC expertise and guidance.";

    const contents = [];

    if (conversationHistory && Array.isArray(conversationHistory)) {
      for (const turn of conversationHistory.slice(-8)) {
        contents.push({
          role: turn.role === "assistant" ? "model" : "user",
          parts: [{ text: turn.content }],
        });
      }
    }

    contents.push({
      role: "user",
      parts: [
        {
          text: `${contextSummary}\n\nUSER QUESTION: ${message}`,
        },
      ],
    });

    const response = await generateWithFallback({
      contents,
      config: {
        systemInstruction,
        temperature: 0.2,
      },
    });

    return res.json({
      success: true,
      reply: response.text || "No response generated.",
    });
  } catch (error: any) {
    console.error("Error in /api/ai-analyst:", error);
    return res.status(500).json({
      error: error.message || "AI Analyst encountered an error",
    });
  }
});

// 4. MITRE ATT&CK Mapping Reasoning
apiRouter.post("/mitre-analysis", async (req: Request, res: Response) => {
  try {
    const { events, alertTitle, context } = req.body;

    const systemInstruction = `You are a MITRE ATT&CK Framework Specialist.
Map the provided security events to specific Enterprise MITRE ATT&CK Tactics and Techniques.
Provide precise technique IDs (e.g. T1110, T1059.001, T1078, T1046, T1003).
Explain why each technique applies based on specific event attributes, and note confidence and validation steps.`;

    const prompt = `Analyze these security logs and map them to MITRE ATT&CK:
ALERT CONTEXT: ${alertTitle || "Custom Log Sequence"}
ADDITIONAL CONTEXT: ${context || "N/A"}
LOG EVENTS:
${JSON.stringify((events || []).slice(0, 25), null, 2)}`;

    const response = await generateWithFallback({
      contents: prompt,
      config: {
        systemInstruction,
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            tacticsDetected: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            techniques: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  id: { type: Type.STRING },
                  name: { type: Type.STRING },
                  tactic: { type: Type.STRING },
                  subtechnique: { type: Type.STRING },
                  explanation: { type: Type.STRING },
                  supportingEvidence: { type: Type.STRING },
                  confidence: { type: Type.NUMBER },
                  validationCheck: { type: Type.STRING },
                },
                required: ["id", "name", "tactic", "explanation", "confidence"],
              },
            },
            killChainStage: { type: Type.STRING },
            analystAdvice: { type: Type.STRING },
          },
          required: ["tacticsDetected", "techniques", "killChainStage", "analystAdvice"],
        },
      },
    });

    const parsed = JSON.parse(response.text?.trim() || "{}");
    return res.json({ success: true, data: parsed });
  } catch (error: any) {
    console.error("Error in /api/mitre-analysis:", error);
    return res.status(500).json({ error: error.message || "MITRE mapping failed" });
  }
});

// 5. Phishing Analyzer
apiRouter.post("/phishing-analyzer", async (req: Request, res: Response) => {
  try {
    const { rawEmail, sender, subject, replyTo, headers } = req.body;
    if (!rawEmail && !headers) {
      return res.status(400).json({ error: "Missing email content or headers" });
    }

    const systemInstruction = `You are a Senior Email Security Analyst and Phishing Incident Responder.
Analyze the provided email headers, body text, URLs, and metadata.
Assess phishing risk, identify brand impersonation, deceptive homographs, urgent/threatening language, credential harvest lures, and authentication failures (SPF/DKIM/DMARC).
Output structured JSON. Do not state an email is definitely malicious if evidence is ambiguous; label as 'Suspicious' with appropriate confidence.`;

    const prompt = `Analyze this email for phishing & social engineering indicators:
SENDER: ${sender || "Extracted from raw headers"}
SUBJECT: ${subject || "N/A"}
REPLY-TO: ${replyTo || "N/A"}
RAW HEADERS & CONTENT:
${(rawEmail || headers || "").slice(0, 6000)}`;

    const response = await generateWithFallback({
      contents: prompt,
      config: {
        systemInstruction,
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            phishingRiskScore: {
              type: Type.NUMBER,
              description: "0 to 100 risk score based on objective threat signals",
            },
            classification: {
              type: Type.STRING,
              description: "Phishing, Business Email Compromise (BEC), Credential Harvester, Malware Delivery, Spam, or Benign/Legitimate",
            },
            confidence: { type: Type.NUMBER },
            senderAnalysis: {
              type: Type.OBJECT,
              properties: {
                isSpoofed: { type: Type.BOOLEAN },
                domainMismatch: { type: Type.BOOLEAN },
                displaySender: { type: Type.STRING },
                actualSenderDomain: { type: Type.STRING },
                analysis: { type: Type.STRING },
              },
              required: ["isSpoofed", "domainMismatch", "analysis"],
            },
            authenticationStatus: {
              type: Type.OBJECT,
              properties: {
                spf: { type: Type.STRING },
                dkim: { type: Type.STRING },
                dmarc: { type: Type.STRING },
                notes: { type: Type.STRING },
              },
              required: ["spf", "dkim", "dmarc"],
            },
            extractedUrls: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  url: { type: Type.STRING },
                  defangedUrl: { type: Type.STRING },
                  risk: { type: Type.STRING },
                  reason: { type: Type.STRING },
                },
                required: ["url", "defangedUrl", "risk"],
              },
            },
            socialEngineeringIndicators: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            keyEvidence: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            recommendedActions: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            executiveSummary: { type: Type.STRING },
          },
          required: [
            "phishingRiskScore",
            "classification",
            "confidence",
            "senderAnalysis",
            "authenticationStatus",
            "extractedUrls",
            "socialEngineeringIndicators",
            "keyEvidence",
            "recommendedActions",
            "executiveSummary",
          ],
        },
      },
    });

    const parsed = JSON.parse(response.text?.trim() || "{}");
    return res.json({ success: true, data: parsed });
  } catch (error: any) {
    console.error("Error in /api/phishing-analyzer:", error);
    return res.status(500).json({ error: error.message || "Phishing analysis failed" });
  }
});

// 6. Comprehensive SOC Incident Report Generator
apiRouter.post("/generate-report", async (req: Request, res: Response) => {
  try {
    const { alert, timeline, iocs, mitreMappings, analystNotes, rawEvents } = req.body;
    if (!alert) {
      return res.status(400).json({ error: "Missing alert data for report generation" });
    }

    const systemInstruction = `You are a Lead Incident Response Commander writing an official, audit-ready SOC Incident Report.
Draft a complete, professional cybersecurity incident report following standard NIST SP 800-61 Rev. 2 guidelines.
Synthesize all provided evidence, attack timeline, IOCs, and MITRE ATT&CK techniques.
Maintain high technical rigor and ensure all recommendations are actionable.`;

    const prompt = `Generate a comprehensive SOC Incident Report for the following incident:
INCIDENT DETAILS:
- ID: ${alert.id}
- Title: ${alert.title}
- Severity: ${alert.severity}
- Risk Score: ${alert.riskScore}/100
- Status: ${alert.status}
- Host: ${alert.host}
- Source IP: ${alert.sourceIp}
- Username: ${alert.username}
- Detection Source: ${alert.detectionSource}

CHRONOLOGICAL TIMELINE:
${JSON.stringify(timeline || [], null, 2)}

INDICATORS OF COMPROMISE (IOCs):
${JSON.stringify(iocs || [], null, 2)}

MITRE ATT&CK TECHNIQUES:
${JSON.stringify(mitreMappings || [], null, 2)}

ANALYST NOTES:
${analystNotes || "None"}

RAW LOG HIGHLIGHTS (${(rawEvents || []).length} events):
${JSON.stringify((rawEvents || []).slice(0, 20), null, 2)}`;

    const response = await generateWithFallback({
      contents: prompt,
      config: {
        systemInstruction,
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            reportTitle: { type: Type.STRING },
            incidentId: { type: Type.STRING },
            executiveSummary: { type: Type.STRING },
            incidentDescription: { type: Type.STRING },
            detectionMethod: { type: Type.STRING },
            affectedAssets: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            affectedUsers: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            rootCauseAnalysis: { type: Type.STRING },
            riskAssessment: {
              type: Type.OBJECT,
              properties: {
                quantitativeScore: { type: Type.NUMBER },
                impactRating: { type: Type.STRING },
                confidentialityImpact: { type: Type.STRING },
                integrityImpact: { type: Type.STRING },
                availabilityImpact: { type: Type.STRING },
              },
              required: ["quantitativeScore", "impactRating"],
            },
            containmentActionsCompleted: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            eradicationAndRemediation: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            lessonsLearnedAndPreventativeControls: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            analystConclusion: { type: Type.STRING },
          },
          required: [
            "reportTitle",
            "incidentId",
            "executiveSummary",
            "incidentDescription",
            "detectionMethod",
            "affectedAssets",
            "affectedUsers",
            "rootCauseAnalysis",
            "riskAssessment",
            "containmentActionsCompleted",
            "eradicationAndRemediation",
            "lessonsLearnedAndPreventativeControls",
            "analystConclusion",
          ],
        },
      },
    });

    const parsed = JSON.parse(response.text?.trim() || "{}");
    return res.json({ success: true, report: parsed });
  } catch (error: any) {
    console.error("Error in /api/generate-report:", error);
    return res.status(500).json({ error: error.message || "Report generation failed" });
  }
});

// 7. IOC Threat Intelligence & Enrichment
apiRouter.post("/ioc-enrich", async (req: Request, res: Response) => {
  try {
    const { iocs } = req.body;
    if (!iocs || !Array.isArray(iocs)) {
      return res.status(400).json({ error: "Missing iocs array in request" });
    }

    const systemInstruction = `You are a Threat Intelligence Analyst. Enrich the provided Indicators of Compromise (IOCs).
For each indicator, assess threat category, risk level (MALICIOUS, SUSPICIOUS, BENIGN), confidence (0-100), and contextual summary.`;

    const prompt = `Enrich the following IOCs with threat intelligence context:
${JSON.stringify(iocs.slice(0, 20), null, 2)}`;

    const response = await generateWithFallback({
      contents: prompt,
      config: {
        systemInstruction,
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            enrichedIocs: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  type: { type: Type.STRING },
                  value: { type: Type.STRING },
                  defangedValue: { type: Type.STRING },
                  riskLevel: { type: Type.STRING },
                  confidence: { type: Type.NUMBER },
                  threatActor: { type: Type.STRING },
                  context: { type: Type.STRING },
                },
                required: ["type", "value", "riskLevel", "confidence", "context"],
              },
            },
          },
          required: ["enrichedIocs"],
        },
      },
    });

    const parsed = JSON.parse(response.text?.trim() || '{"enrichedIocs": []}');
    return res.json({ success: true, ...parsed });
  } catch (error: any) {
    console.error("Error in /api/ioc-enrich:", error);
    return res.status(500).json({ error: error.message || "IOC enrichment failed" });
  }
});

// ==========================================
// PHASE 2: ALERTS REST API
// ==========================================

// GET /api/alerts - List alerts with filters & pagination
apiRouter.get("/alerts", (req: Request, res: Response) => {
  try {
    const { severity, status, priority, search, host, sourceIp, limit, offset } = req.query;
    const result = getSocDatabase().listAlerts({
      severity: typeof severity === "string" ? severity : undefined,
      status: typeof status === "string" ? status : undefined,
      priority: typeof priority === "string" ? priority : undefined,
      search: typeof search === "string" ? search : undefined,
      host: typeof host === "string" ? host : undefined,
      sourceIp: typeof sourceIp === "string" ? sourceIp : undefined,
      limit: limit ? Number(limit) : undefined,
      offset: offset ? Number(offset) : undefined,
    });
    return res.json({
      success: true,
      data: result.alerts,
      pagination: {
        limit: result.limit,
        offset: result.offset,
        total: result.total,
      },
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to retrieve alerts");
  }
});

// GET /api/alerts/:id - Retrieve alert and associated security events
apiRouter.get("/alerts/:id", (req: Request, res: Response) => {
  try {
    const alert = getSocDatabase().getAlertById(req.params.id);
    if (!alert) {
      return sendError(res, 404, "NOT_FOUND", `Alert with ID '${req.params.id}' was not found`);
    }
    const events = getSocDatabase().getEventsByAlertId(req.params.id);
    return res.json({
      success: true,
      data: {
        alert,
        events,
      },
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to retrieve alert");
  }
});

// POST /api/alerts - Create alert with validation and conflict detection
apiRouter.post("/alerts", (req: Request, res: Response) => {
  try {
    const body = req.body;
    if (!body || typeof body !== "object") {
      return sendError(res, 400, "INVALID_REQUEST", "Request body must be a valid JSON object");
    }

    const { id, title, severity, status, riskScore } = body;
    if (!id || typeof id !== "string" || !id.trim()) {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: id (non-empty string)");
    }
    if (!title || typeof title !== "string" || !title.trim()) {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: title (non-empty string)");
    }
    if (!severity || typeof severity !== "string") {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: severity");
    }
    if (!status || typeof status !== "string") {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: status");
    }
    if (typeof riskScore !== "number" || isNaN(riskScore)) {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: riskScore (number 0-100)");
    }

    if (getSocDatabase().existsAlert(id)) {
      return sendError(res, 409, "CONFLICT", `Alert with ID '${id}' already exists`);
    }

    const alert: Alert = {
      id,
      title,
      severity: severity as Alert["severity"],
      riskScore,
      status: status as Alert["status"],
      host: body.host || "UNKNOWN_HOST",
      sourceIp: body.sourceIp || "0.0.0.0",
      destinationIp: body.destinationIp,
      username: body.username || "UNKNOWN_USER",
      detectionSource: body.detectionSource || "RULE_BASED",
      ruleId: body.ruleId,
      ruleName: body.ruleName,
      detectionConfidence: body.detectionConfidence ?? 100,
      aiConfidence: body.aiConfidence,
      description: body.description || "",
      evidence: Array.isArray(body.evidence) ? body.evidence : [],
      relatedEventIds: Array.isArray(body.relatedEventIds) ? body.relatedEventIds : [],
      mitreTechniques: Array.isArray(body.mitreTechniques) ? body.mitreTechniques : [],
      notes: body.notes || body.analystNotes,
      geminiAnalysis: body.geminiAnalysis,
      timestamp: body.createdAt || body.timestamp || new Date().toISOString(),
      updatedAt: body.updatedAt || new Date().toISOString(),
    };

    getSocDatabase().insertAlert(alert);
    return res.status(201).json({
      success: true,
      data: alert,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to create alert");
  }
});

// PATCH /api/alerts/:id - Update analyst-controlled fields (status, notes, assignedTo, geminiAnalysis)
apiRouter.patch("/alerts/:id", (req: Request, res: Response) => {
  try {
    const existing = getSocDatabase().getAlertById(req.params.id);
    if (!existing) {
      return sendError(res, 404, "NOT_FOUND", `Alert with ID '${req.params.id}' was not found`);
    }

    const body = req.body;
    if (!body || typeof body !== "object") {
      return sendError(res, 400, "INVALID_REQUEST", "Request body must be a valid JSON object");
    }

    const updates: Partial<Alert> = {};
    if (body.status !== undefined) {
      if (typeof body.status !== "string") {
        return sendError(res, 400, "INVALID_REQUEST", "status must be a string");
      }
      updates.status = body.status as Alert["status"];
    }
    if (body.notes !== undefined || body.analystNotes !== undefined) {
      updates.notes = body.notes !== undefined ? String(body.notes) : String(body.analystNotes);
    }
    if (body.assignedTo !== undefined || body.assigned_to !== undefined) {
      const rawAssigned = body.assignedTo !== undefined ? body.assignedTo : body.assigned_to;
      if (rawAssigned !== null && typeof rawAssigned !== "string") {
        return sendError(res, 400, "INVALID_REQUEST", "assignedTo must be a string or null");
      }
      updates.assignedTo = rawAssigned ? String(rawAssigned).trim() : undefined;
    }
    if (body.geminiAnalysis !== undefined || body.gemini_analysis !== undefined) {
      const rawAnalysis = body.geminiAnalysis !== undefined ? body.geminiAnalysis : body.gemini_analysis;
      if (rawAnalysis !== null && typeof rawAnalysis !== "object") {
        return sendError(res, 400, "INVALID_REQUEST", "geminiAnalysis must be a valid object or null");
      }
      updates.geminiAnalysis = rawAnalysis;
      if (rawAnalysis && typeof rawAnalysis.confidenceScore === "number") {
        updates.aiConfidence = rawAnalysis.confidenceScore;
      }
    }
    if (body.aiConfidence !== undefined) {
      if (typeof body.aiConfidence !== "number" || isNaN(body.aiConfidence)) {
        return sendError(res, 400, "INVALID_REQUEST", "aiConfidence must be a valid number");
      }
      updates.aiConfidence = body.aiConfidence;
    }
    if (body.updatedAt !== undefined) {
      updates.updatedAt = String(body.updatedAt);
    }

    getSocDatabase().updateAlert(req.params.id, updates);
    const updated = getSocDatabase().getAlertById(req.params.id);
    return res.json({
      success: true,
      data: updated,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to update alert");
  }
});

// ==========================================
// PHASE 2: LOGS & SECURITY EVENTS API
// ==========================================

// GET /api/logs - List security events with filters & pagination
apiRouter.get("/logs", (req: Request, res: Response) => {
  try {
    const { alertId, hostname, sourceIp, eventType, startTime, endTime, search, limit, offset } = req.query;
    const result = getSocDatabase().listSecurityEvents({
      alertId: typeof alertId === "string" ? alertId : undefined,
      hostname: typeof hostname === "string" ? hostname : undefined,
      sourceIp: typeof sourceIp === "string" ? sourceIp : undefined,
      eventType: typeof eventType === "string" ? eventType : undefined,
      startTime: typeof startTime === "string" ? startTime : undefined,
      endTime: typeof endTime === "string" ? endTime : undefined,
      search: typeof search === "string" ? search : undefined,
      limit: limit ? Number(limit) : undefined,
      offset: offset ? Number(offset) : undefined,
    });
    return res.json({
      success: true,
      data: result.events,
      pagination: {
        limit: result.limit,
        offset: result.offset,
        total: result.total,
      },
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to retrieve security events");
  }
});

// POST /api/logs/ingest - Server-side log ingestion pipeline (Parse -> Detect -> Persist -> Correlate)
apiRouter.post("/logs/ingest", (req: Request, res: Response) => {
  try {
    const body = req.body;
    if (!body || typeof body !== "object") {
      return sendError(res, 400, "INVALID_REQUEST", "Request body must be a JSON object");
    }

    const { raw, source } = body;
    if (typeof raw !== "string" || !raw.trim()) {
      return sendError(res, 400, "INVALID_REQUEST", "Field 'raw' must be a non-empty string");
    }

    // Input length protection (5MB maximum raw payload)
    if (raw.length > 5_000_000) {
      return sendError(res, 400, "PAYLOAD_TOO_LARGE", "Raw log payload exceeds maximum allowed size (5MB)");
    }

    // 1. Normalize raw logs via existing deterministic parser
    const defaultHost = typeof source === "string" && source.trim() ? source.trim() : "INGESTED-ENDPOINT";
    const events = parseRawLogs(raw, defaultHost);

    if (events.length === 0) {
      return res.json({
        success: true,
        data: {
          eventsIngested: 0,
          alertsGenerated: 0,
          events: [],
          alerts: [],
        },
      });
    }

    // 2. Execute deterministic detection engine against normalized events
    const alerts = runDetectionEngine(events);

    // 3. Persist normalized events
    getSocDatabase().insertEventsBatch(events);

    // 4. Persist generated alerts and update correlated event links
    for (const alert of alerts) {
      getSocDatabase().insertAlert(alert);
      if (Array.isArray(alert.relatedEventIds)) {
        for (const evtId of alert.relatedEventIds) {
          getSocDatabase().updateEventAlertId(evtId, alert.id);
        }
      }
    }

    return res.json({
      success: true,
      data: {
        eventsIngested: events.length,
        alertsGenerated: alerts.length,
        events,
        alerts,
      },
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to ingest logs");
  }
});

// ==========================================
// PHASE 2: DASHBOARD METRICS API
// ==========================================

// GET /api/dashboard/stats - Aggregated stats from SQLite persistence
apiRouter.get("/dashboard/stats", (_req: Request, res: Response) => {
  try {
    const stats = getSocDatabase().getDashboardStats();
    return res.json({
      success: true,
      data: stats,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to calculate dashboard statistics");
  }
});

// ==========================================
// PHASE 2: INCIDENT REPORTS API
// ==========================================

// GET /api/reports - List incident reports with optional filtering
apiRouter.get("/reports", (req: Request, res: Response) => {
  try {
    const { incidentId, search, limit, offset } = req.query;
    const result = getSocDatabase().listReports({
      incidentId: typeof incidentId === "string" ? incidentId : undefined,
      search: typeof search === "string" ? search : undefined,
      limit: limit ? Number(limit) : undefined,
      offset: offset ? Number(offset) : undefined,
    });
    return res.json({
      success: true,
      data: result.reports,
      pagination: {
        limit: result.limit,
        offset: result.offset,
        total: result.total,
      },
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to retrieve incident reports");
  }
});

// POST /api/reports - Persist structured incident report
apiRouter.post("/reports", (req: Request, res: Response) => {
  try {
    const body = req.body;
    if (!body || typeof body !== "object") {
      return sendError(res, 400, "INVALID_REQUEST", "Request body must be a JSON object");
    }

    const reportTitle = body.reportTitle || body.title;
    const author = body.author;
    if (!reportTitle || typeof reportTitle !== "string" || !reportTitle.trim()) {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: reportTitle");
    }
    if (!author || typeof author !== "string" || !author.trim()) {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: author");
    }

    const id = body.id || `RPT-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;

    const report: IncidentReport = {
      id,
      incidentId: body.incidentId || "INC-GENERIC",
      reportTitle: reportTitle.trim(),
      author: author.trim(),
      status: body.status || "DRAFT",
      classification: body.classification || "INTERNAL",
      executiveSummary: body.executiveSummary || "",
      incidentDescription: body.incidentDescription || body.description || "",
      detectionMethod: body.detectionMethod || "RULE_BASED",
      affectedAssets: Array.isArray(body.affectedAssets) ? body.affectedAssets : [],
      affectedUsers: Array.isArray(body.affectedUsers) ? body.affectedUsers : [],
      timeline: Array.isArray(body.timeline) ? body.timeline : [],
      iocs: Array.isArray(body.iocs) ? body.iocs : [],
      evidence: Array.isArray(body.evidence) ? body.evidence : [],
      mitreMappings: Array.isArray(body.mitreMappings) ? body.mitreMappings : [],
      riskAssessment: body.riskAssessment || {
        quantitativeScore: 50,
        impactRating: "MEDIUM",
      },
      rootCauseAnalysis: body.rootCauseAnalysis || "",
      containmentActionsCompleted: Array.isArray(body.containmentActionsCompleted)
        ? body.containmentActionsCompleted
        : [],
      eradicationAndRemediation: Array.isArray(body.eradicationAndRemediation)
        ? body.eradicationAndRemediation
        : [],
      lessonsLearnedAndPreventativeControls: Array.isArray(body.lessonsLearnedAndPreventativeControls)
        ? body.lessonsLearnedAndPreventativeControls
        : [],
      analystConclusion: body.analystConclusion || "",
      createdAt: body.createdAt || new Date().toISOString(),
      generatedAt: body.generatedAt || new Date().toISOString(),
    };

    getSocDatabase().insertReport(report);
    return res.status(201).json({
      success: true,
      data: report,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to persist incident report");
  }
});

// ==========================================
// PHASE 2: INCIDENTS REST API FOUNDATION
// ==========================================

// GET /api/incidents - List incidents with status/severity filters
apiRouter.get("/incidents", (req: Request, res: Response) => {
  try {
    const { status, severity, priority, leadAnalyst, search, limit, offset } = req.query;
    const result = getSocDatabase().listIncidents({
      status: typeof status === "string" ? status : undefined,
      severity: typeof severity === "string" ? severity : undefined,
      priority: typeof priority === "string" ? priority : undefined,
      leadAnalyst: typeof leadAnalyst === "string" ? leadAnalyst : undefined,
      search: typeof search === "string" ? search : undefined,
      limit: limit ? Number(limit) : undefined,
      offset: offset ? Number(offset) : undefined,
    });
    return res.json({
      success: true,
      data: result.incidents,
      pagination: {
        limit: result.limit,
        offset: result.offset,
        total: result.total,
      },
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to retrieve incidents");
  }
});

// GET /api/incidents/:id - Retrieve incident by ID with linked alerts, response actions, iocs, and reports
apiRouter.get("/incidents/:id", (req: Request, res: Response) => {
  try {
    const incident = getSocDatabase().getIncidentById(req.params.id);
    if (!incident) {
      return sendError(res, 404, "NOT_FOUND", `Incident with ID '${req.params.id}' was not found`);
    }

    const linkedAlerts = (incident.alertIds || [])
      .map((alertId) => getSocDatabase().getAlertById(alertId))
      .filter((a): a is Alert => Boolean(a));

    const responseActions = getSocDatabase().getIncidentActionsByIncidentId(incident.id);
    const iocs = getSocDatabase().getIocsByIncidentId(incident.id);
    const reports = getSocDatabase().listReports({ incidentId: incident.id }).reports;

    return res.json({
      success: true,
      data: {
        ...incident,
        alerts: linkedAlerts,
        responseActions,
        iocs,
        reports,
      },
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to retrieve incident");
  }
});

// GET /api/incidents/:id/timeline - Retrieve chronological lifecycle timeline for an incident
apiRouter.get("/incidents/:id/timeline", (req: Request, res: Response) => {
  try {
    const incident = getSocDatabase().getIncidentById(req.params.id);
    if (!incident) {
      return sendError(res, 404, "NOT_FOUND", `Incident with ID '${req.params.id}' was not found`);
    }

    const timeline = buildIncidentTimeline(req.params.id, getSocDatabase());
    return res.json({
      success: true,
      data: timeline,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to retrieve incident timeline");
  }
});

// POST /api/incidents/:id/generate-report - Generate comprehensive persistent incident report
apiRouter.post("/incidents/:id/generate-report", (req: Request, res: Response) => {
  try {
    const incident = getSocDatabase().getIncidentById(req.params.id);
    if (!incident) {
      return sendError(res, 404, "NOT_FOUND", `Incident with ID '${req.params.id}' was not found`);
    }

    const body = req.body || {};
    const linkedAlerts = (incident.alertIds || [])
      .map((alertId) => getSocDatabase().getAlertById(alertId))
      .filter((a): a is Alert => Boolean(a));

    const responseActions = getSocDatabase().getIncidentActionsByIncidentId(incident.id);
    const iocs = getSocDatabase().getIocsByIncidentId(incident.id);
    const timeline = buildIncidentTimeline(incident.id, getSocDatabase());

    // Gather events
    const allEvents: SecurityEvent[] = [];
    for (const alert of linkedAlerts) {
      const evts = getSocDatabase().getEventsByAlertId(alert.id);
      allEvents.push(...evts);
    }

    // Determine affected assets and users
    const affectedAssets = Array.from(
      new Set(
        linkedAlerts
          .map((a) => a.host)
          .concat(allEvents.map((e) => e.hostname))
          .filter(Boolean)
      )
    );

    const affectedUsers = Array.from(
      new Set(
        linkedAlerts
          .map((a) => a.username)
          .concat(allEvents.map((e) => e.username))
          .filter(Boolean)
      )
    );

    // Determine MITRE techniques
    const mitreMap = new Map<string, MitreTechnique>();
    for (const alert of linkedAlerts) {
      for (const tech of alert.mitreTechniques || []) {
        mitreMap.set(tech.id, tech);
      }
    }
    const mitreMappings = Array.from(mitreMap.values());

    // Calculate max risk score
    const maxRiskScore = linkedAlerts.length > 0
      ? Math.max(...linkedAlerts.map((a) => a.riskScore || 50))
      : incident.severity === "CRITICAL"
      ? 95
      : incident.severity === "HIGH"
      ? 80
      : incident.severity === "MEDIUM"
      ? 55
      : 25;

    // Completed containment actions
    const containmentActionsCompleted = responseActions
      .filter((a) => a.status === "EXECUTED")
      .map(
        (a) =>
          `[SIMULATED] Executed ${a.actionType} on target ${a.targetType} [${a.target}] (Requested by ${a.requestedBy}, Approved by ${a.approvedBy || "System"}). Result: ${a.result || "Success"}`
      )
      .concat(incident.containmentActions || []);

    const now = new Date().toISOString();
    const reportId = body.id || `RPT-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;

    const report: IncidentReport = {
      id: reportId,
      incidentId: incident.id,
      reportTitle:
        body.reportTitle || `SOC Incident Report: ${incident.title} [${incident.id}]`,
      author:
        body.author ||
        incident.leadAnalyst ||
        "Autonomous AI-SOC Senior Incident Responder",
      status: (body.status as any) || "FINAL",
      classification:
        body.classification ||
        (incident.severity === "CRITICAL"
          ? "CRITICAL INCIDENT"
          : incident.severity === "HIGH"
          ? "HIGH-SEVERITY INCIDENT"
          : "SECURITY INCIDENT"),
      executiveSummary:
        body.executiveSummary ||
        incident.executiveSummary ||
        (linkedAlerts.length > 0
          ? linkedAlerts.map((a) => a.description || a.title).join("; ")
          : `Comprehensive incident investigation for case ${incident.id}.`),
      incidentDescription:
        body.incidentDescription ||
        `Investigation into ${incident.title} involving ${linkedAlerts.length} correlated alerts, ${allEvents.length} security telemetry events, and ${iocs.length} identified indicators across ${affectedAssets.length} host assets.`,
      detectionMethod:
        body.detectionMethod ||
        Array.from(new Set(linkedAlerts.map((a) => a.detectionSource || "RULE_BASED"))).join(", ") ||
        "DETERMINISTIC_SIEM_DETECTION",
      affectedAssets,
      affectedUsers,
      timeline,
      iocs,
      evidence: Array.from(new Set(linkedAlerts.flatMap((a) => a.evidence || []))),
      mitreMappings,
      riskAssessment: body.riskAssessment || {
        quantitativeScore: maxRiskScore,
        impactRating: incident.severity,
        confidentialityImpact: incident.severity === "CRITICAL" ? "High" : "Medium",
        integrityImpact: "High",
        availabilityImpact: "Low",
      },
      rootCauseAnalysis:
        body.rootCauseAnalysis ||
        (linkedAlerts.length > 0
          ? `Root cause identified through alert rule '${linkedAlerts[0].ruleName || linkedAlerts[0].ruleId || "SIEM Correlation"}' triggered on host ${linkedAlerts[0].host}.`
          : "Root cause analysis completed."),
      containmentActionsCompleted,
      eradicationAndRemediation:
        body.eradicationAndRemediation || [
          "Isolated affected endpoints from enterprise production subnets.",
          "Revoked active Kerberos and OAuth access tokens for compromised accounts.",
          "Terminated malicious process trees and quarantined dropped artifacts.",
          "Enforced perimeter and host-level firewall blocklists for correlated indicators.",
        ],
      lessonsLearnedAndPreventativeControls:
        body.lessonsLearnedAndPreventativeControls || [
          "Enforce hardware-backed MFA on all exposed administrative access panels.",
          "Harden EDR script execution blocking rules against PowerShell obfuscation.",
          "Implement automated credential revocation upon multi-alert correlation.",
          "Review network egress filtering for anomalous non-standard destination ports.",
        ],
      analystConclusion:
        body.analystConclusion ||
        (incident.status === "CLOSED"
          ? `Incident resolved and closed by ${incident.closedBy || "SOC Lead"}. Closure summary: ${incident.closureSummary || "Case resolved."}`
          : `Incident is in '${incident.status}' state under supervision of ${incident.leadAnalyst || "SOC Team"}.`),
      createdAt: now,
      generatedAt: now,
    };

    getSocDatabase().insertReport(report);
    return res.status(201).json({
      success: true,
      data: report,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to generate incident report");
  }
});

// POST /api/incidents - Create incident record with referenced alert validation & deduplication
apiRouter.post("/incidents", (req: Request, res: Response) => {
  try {
    const body = req.body;
    if (!body || typeof body !== "object") {
      return sendError(res, 400, "INVALID_REQUEST", "Request body must be a JSON object");
    }

    const { title, severity, status } = body;
    if (!title || typeof title !== "string" || !title.trim()) {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: title");
    }
    if (!severity || typeof severity !== "string") {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: severity");
    }
    if (!status || typeof status !== "string") {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: status");
    }

    const id = body.id || `INC-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;

    if (getSocDatabase().existsIncident(id)) {
      return sendError(res, 409, "CONFLICT", `Incident with ID '${id}' already exists`);
    }

    // Validate and deduplicate alert IDs
    let validatedAlertIds: string[] = [];
    if (body.alertIds !== undefined) {
      if (!Array.isArray(body.alertIds)) {
        return sendError(res, 400, "INVALID_REQUEST", "alertIds must be an array of string IDs");
      }
      const rawIds: string[] = body.alertIds.map((item: any) => String(item).trim()).filter(Boolean);
      const uniqueIds: string[] = Array.from(new Set<string>(rawIds));

      // Ensure every referenced alert exists
      for (const alertId of uniqueIds) {
        if (!getSocDatabase().existsAlert(alertId)) {
          return sendError(res, 404, "NOT_FOUND", `Referenced alert '${alertId}' was not found in database`);
        }
      }
      validatedAlertIds = uniqueIds;
    }

    const now = new Date().toISOString();
    const incident = {
      id,
      title: title.trim(),
      severity,
      status,
      priority: body.priority || "P2",
      leadAnalyst: body.leadAnalyst ? String(body.leadAnalyst).trim() : undefined,
      alertIds: validatedAlertIds,
      executiveSummary: body.executiveSummary || "",
      containmentActions: Array.isArray(body.containmentActions) ? body.containmentActions : [],
      createdAt: body.createdAt || now,
      updatedAt: body.updatedAt || now,
      closedAt: body.closedAt,
      closedBy: body.closedBy ? String(body.closedBy).trim() : undefined,
      closureSummary: body.closureSummary ? String(body.closureSummary).trim() : undefined,
    };

    getSocDatabase().insertIncident(incident);
    return res.status(201).json({
      success: true,
      data: incident,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to create incident");
  }
});

// PATCH /api/incidents/:id - Update incident lifecycle fields with closure validation
apiRouter.patch("/incidents/:id", (req: Request, res: Response) => {
  try {
    const existing = getSocDatabase().getIncidentById(req.params.id);
    if (!existing) {
      return sendError(res, 404, "NOT_FOUND", `Incident with ID '${req.params.id}' was not found`);
    }

    const body = req.body;
    if (!body || typeof body !== "object") {
      return sendError(res, 400, "INVALID_REQUEST", "Request body must be a JSON object");
    }

    // Lifecycle enforcement: Closed incidents cannot regress status unless explicitly authorized
    if (existing.status === "CLOSED" && body.status !== undefined && body.status !== "CLOSED") {
      return sendError(
        res,
        400,
        "INVALID_LIFECYCLE_TRANSITION",
        "Incident is in CLOSED status and cannot regress lifecycle"
      );
    }

    const updates: Partial<typeof existing> = {};
    if (body.title !== undefined) updates.title = String(body.title).trim();
    if (body.severity !== undefined) updates.severity = String(body.severity);
    if (body.priority !== undefined) updates.priority = String(body.priority);
    if (body.leadAnalyst !== undefined) updates.leadAnalyst = body.leadAnalyst ? String(body.leadAnalyst).trim() : undefined;
    if (body.executiveSummary !== undefined) updates.executiveSummary = String(body.executiveSummary);
    if (Array.isArray(body.containmentActions)) updates.containmentActions = body.containmentActions;
    
    // Case Closure Handling
    if (body.status === "CLOSED") {
      if (!body.closureSummary || typeof body.closureSummary !== "string" || !body.closureSummary.trim()) {
        return sendError(res, 400, "CLOSURE_SUMMARY_REQUIRED", "closureSummary is required to close an incident");
      }
      if (!body.closedBy || typeof body.closedBy !== "string" || !body.closedBy.trim()) {
        return sendError(res, 400, "CLOSED_BY_REQUIRED", "closedBy analyst name/ID is required to close an incident");
      }

      updates.status = "CLOSED";
      updates.closedBy = body.closedBy.trim();
      updates.closureSummary = body.closureSummary.trim();
      updates.closedAt = new Date().toISOString(); // Server generated
    } else if (body.status !== undefined) {
      updates.status = String(body.status);
    }

    if (body.closureSummary !== undefined && body.status !== "CLOSED") {
      updates.closureSummary = String(body.closureSummary).trim();
    }
    if (body.closedBy !== undefined && body.status !== "CLOSED") {
      updates.closedBy = String(body.closedBy).trim();
    }

    if (body.alertIds !== undefined) {
      if (!Array.isArray(body.alertIds)) {
        return sendError(res, 400, "INVALID_REQUEST", "alertIds must be an array of string IDs");
      }
      const rawIds: string[] = body.alertIds.map((item: any) => String(item).trim()).filter(Boolean);
      const uniqueIds: string[] = Array.from(new Set<string>(rawIds));

      for (const alertId of uniqueIds) {
        if (!getSocDatabase().existsAlert(alertId)) {
          return sendError(res, 404, "NOT_FOUND", `Referenced alert '${alertId}' was not found in database`);
        }
      }
      updates.alertIds = uniqueIds;
    }

    if (body.updatedAt !== undefined) updates.updatedAt = String(body.updatedAt);

    getSocDatabase().updateIncident(req.params.id, updates);
    const updated = getSocDatabase().getIncidentById(req.params.id);
    return res.json({
      success: true,
      data: updated,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to update incident");
  }
});

// ==========================================
// 6. INCIDENT RESPONSE ACTIONS API (SIMULATED / TRACKING ONLY)
// ==========================================

const ALLOWED_ACTION_TYPES: ResponseActionType[] = [
  "ISOLATE_HOST",
  "BLOCK_IP",
  "BLOCK_DOMAIN",
  "DISABLE_ACCOUNT",
  "KILL_PROCESS",
  "COLLECT_EVIDENCE",
];

const ALLOWED_TARGET_TYPES: ResponseTargetType[] = [
  "HOST",
  "IP",
  "DOMAIN",
  "ACCOUNT",
  "PROCESS",
  "EVIDENCE",
];

// GET /api/incidents/:id/actions - Get all response actions for an incident
apiRouter.get("/incidents/:id/actions", (req: Request, res: Response) => {
  try {
    if (!getSocDatabase().existsIncident(req.params.id)) {
      return sendError(res, 404, "NOT_FOUND", `Incident with ID '${req.params.id}' was not found`);
    }

    const actions = getSocDatabase().getIncidentActionsByIncidentId(req.params.id);
    return res.json({
      success: true,
      data: actions,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to retrieve incident response actions");
  }
});

// POST /api/incidents/:id/actions - Create response action in REQUESTED state
apiRouter.post("/incidents/:id/actions", (req: Request, res: Response) => {
  try {
    const incidentId = req.params.id;
    if (!getSocDatabase().existsIncident(incidentId)) {
      return sendError(res, 404, "NOT_FOUND", `Incident with ID '${incidentId}' was not found`);
    }

    const body = req.body;
    if (!body || typeof body !== "object") {
      return sendError(res, 400, "INVALID_REQUEST", "Request body must be a JSON object");
    }

    const { actionType, targetType, target, requestedBy, notes, metadata } = body;

    if (!actionType || !ALLOWED_ACTION_TYPES.includes(actionType as ResponseActionType)) {
      return sendError(
        res,
        400,
        "INVALID_ACTION_TYPE",
        `Invalid actionType '${actionType}'. Allowed types: ${ALLOWED_ACTION_TYPES.join(", ")}`
      );
    }

    if (!targetType || !ALLOWED_TARGET_TYPES.includes(targetType as ResponseTargetType)) {
      return sendError(
        res,
        400,
        "INVALID_TARGET_TYPE",
        `Invalid targetType '${targetType}'. Allowed types: ${ALLOWED_TARGET_TYPES.join(", ")}`
      );
    }

    // Validate actionType -> targetType compatibility
    const validTargets = VALID_ACTION_TARGET_MAP[actionType as ResponseActionType] || [];
    if (!validTargets.includes(targetType as ResponseTargetType)) {
      return sendError(
        res,
        400,
        "TARGET_TYPE_MISMATCH",
        `Target type '${targetType}' is invalid for action type '${actionType}'. Valid target types: ${validTargets.join(", ")}`
      );
    }

    if (!target || typeof target !== "string" || !target.trim()) {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: target");
    }

    if (!requestedBy || typeof requestedBy !== "string" || !requestedBy.trim()) {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: requestedBy");
    }

    const now = new Date().toISOString();
    const id = body.id || `ACT-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;

    const action = {
      id,
      incidentId,
      actionType: actionType as ResponseActionType,
      targetType: targetType as ResponseTargetType,
      target: target.trim(),
      status: "REQUESTED",
      requestedBy: requestedBy.trim(),
      requestedAt: body.requestedAt || now,
      notes: notes ? String(notes).trim() : undefined,
      metadata: metadata && typeof metadata === "object" ? metadata : undefined,
      createdAt: now,
      updatedAt: now,
    };

    getSocDatabase().insertIncidentAction(action);

    return res.status(201).json({
      success: true,
      data: action,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to create incident response action");
  }
});

// PATCH /api/incidents/:id/actions/:actionId - Controlled lifecycle transition & notes update
apiRouter.patch("/incidents/:id/actions/:actionId", (req: Request, res: Response) => {
  try {
    const { id: incidentId, actionId } = req.params;

    if (!getSocDatabase().existsIncident(incidentId)) {
      return sendError(res, 404, "NOT_FOUND", `Incident with ID '${incidentId}' was not found`);
    }

    const existingAction = getSocDatabase().getIncidentActionById(actionId);
    if (!existingAction) {
      return sendError(res, 404, "NOT_FOUND", `Response action with ID '${actionId}' was not found`);
    }

    // Ensure action belongs to the requested incident
    if (existingAction.incidentId !== incidentId) {
      return sendError(
        res,
        400,
        "INVALID_REQUEST",
        `Action '${actionId}' does not belong to incident '${incidentId}'`
      );
    }

    const body = req.body;
    if (!body || typeof body !== "object") {
      return sendError(res, 400, "INVALID_REQUEST", "Request body must be a JSON object");
    }

    const now = new Date().toISOString();
    const updates: Partial<typeof existingAction> = {};

    if (body.status !== undefined) {
      const targetStatus = String(body.status).toUpperCase();
      const currentStatus = existingAction.status;

      if (currentStatus === "REQUESTED") {
        if (targetStatus === "APPROVED") {
          updates.status = "APPROVED";
          updates.approvedBy = body.approvedBy ? String(body.approvedBy).trim() : "SOC-Lead-Analyst";
          updates.approvedAt = body.approvedAt || now;
        } else if (targetStatus === "CANCELLED") {
          updates.status = "CANCELLED";
          updates.result = body.result ? String(body.result) : "Action cancelled by analyst.";
        } else if (targetStatus === "REQUESTED") {
          // No-op status update
        } else {
          return sendError(
            res,
            400,
            "INVALID_TRANSITION",
            `Cannot transition action from REQUESTED to '${targetStatus}'. Allowed transitions: APPROVED, CANCELLED`
          );
        }
      } else if (currentStatus === "APPROVED") {
        if (targetStatus === "EXECUTED") {
          updates.status = "EXECUTED";
          updates.executedAt = body.executedAt || now;
          updates.result = body.result
            ? String(body.result)
            : `Simulated containment action (${existingAction.actionType} on ${existingAction.target}) recorded successfully.`;
        } else if (targetStatus === "FAILED") {
          updates.status = "FAILED";
          updates.result = body.result
            ? String(body.result)
            : `Simulated action failed during execution.`;
        } else if (targetStatus === "CANCELLED") {
          updates.status = "CANCELLED";
          updates.result = body.result ? String(body.result) : "Action cancelled by analyst.";
        } else if (targetStatus === "APPROVED") {
          // No-op status update
        } else {
          return sendError(
            res,
            400,
            "INVALID_TRANSITION",
            `Cannot transition action from APPROVED to '${targetStatus}'. Allowed transitions: EXECUTED, FAILED, CANCELLED`
          );
        }
      } else if (["EXECUTED", "FAILED", "CANCELLED"].includes(currentStatus)) {
        if (targetStatus !== currentStatus) {
          return sendError(
            res,
            400,
            "INVALID_TRANSITION",
            `Action is in terminal status '${currentStatus}' and cannot be transitioned to '${targetStatus}'`
          );
        }
      } else {
        return sendError(
          res,
          400,
          "INVALID_TRANSITION",
          `Unknown current status '${currentStatus}'`
        );
      }
    }

    if (body.notes !== undefined) {
      updates.notes = String(body.notes).trim();
    }
    if (body.result !== undefined && !updates.result) {
      updates.result = String(body.result).trim();
    }
    if (body.approvedBy !== undefined && !updates.approvedBy) {
      updates.approvedBy = String(body.approvedBy).trim();
    }

    getSocDatabase().updateIncidentAction(actionId, updates);
    const updated = getSocDatabase().getIncidentActionById(actionId);

    return res.json({
      success: true,
      data: updated,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to update response action");
  }
});

// ==========================================
// 7. THREAT INTELLIGENCE & IOC MANAGEMENT API
// ==========================================

// Helper to defang an IOC value safely
function defangIocValue(value: string, type: string): string {
  if (!value) return "";
  if (type === "IPV4" || type === "IPV6") {
    return value.replace(/\./g, "[.]").replace(/:/g, "[:]");
  }
  if (type === "DOMAIN" || type === "URL") {
    return value.replace(/\./g, "[.]").replace(/https:\/\//g, "hxxps://").replace(/http:\/\//g, "hxxp://");
  }
  if (type === "EMAIL") {
    return value.replace(/@/g, "[at]").replace(/\./g, "[.]");
  }
  return value;
}

// GET /api/iocs - List indicators of compromise with filtering & pagination
apiRouter.get("/iocs", (req: Request, res: Response) => {
  try {
    const { type, threatLevel, search, alertId, incidentId, limit, offset } = req.query;

    if (typeof incidentId === "string" && incidentId.trim()) {
      const incidentIocs = getSocDatabase().getIocsByIncidentId(incidentId.trim());
      const enrichedIocs = incidentIocs.map((ioc) => ({
        ...ioc,
        latestEnrichment: getSocDatabase().getLatestEnrichmentByIocId(ioc.id),
      }));
      return res.json({
        success: true,
        data: enrichedIocs,
        pagination: {
          total: enrichedIocs.length,
          limit: enrichedIocs.length,
          offset: 0,
        },
      });
    }

    if (typeof alertId === "string" && alertId.trim()) {
      const alertIocs = getSocDatabase().getIocsByAlertId(alertId.trim());
      const enrichedIocs = alertIocs.map((ioc) => ({
        ...ioc,
        latestEnrichment: getSocDatabase().getLatestEnrichmentByIocId(ioc.id),
      }));
      return res.json({
        success: true,
        data: enrichedIocs,
        pagination: {
          total: enrichedIocs.length,
          limit: enrichedIocs.length,
          offset: 0,
        },
      });
    }

    const result = getSocDatabase().listIocs({
      type: typeof type === "string" ? type : undefined,
      threatLevel: typeof threatLevel === "string" ? threatLevel : undefined,
      search: typeof search === "string" ? search : undefined,
      limit: limit ? Number(limit) : undefined,
      offset: offset ? Number(offset) : undefined,
    });

    return res.json({
      success: true,
      data: result.iocs,
      pagination: {
        total: result.total,
        limit: result.limit,
        offset: result.offset,
      },
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to retrieve IOC records");
  }
});

// GET /api/iocs/:id - Retrieve single IOC with enrichments and correlated entities
apiRouter.get("/iocs/:id", (req: Request, res: Response) => {
  try {
    const ioc = getSocDatabase().getIocById(req.params.id);
    if (!ioc) {
      return sendError(res, 404, "NOT_FOUND", `IOC with ID '${req.params.id}' was not found`);
    }

    const enrichments = getSocDatabase().getEnrichmentsByIocId(ioc.id);
    const latestEnrichment = getSocDatabase().getLatestEnrichmentByIocId(ioc.id);

    // Correlate related alerts
    const alerts = getSocDatabase().getAllAlerts().filter((a) => {
      return (
        a.sourceIp === ioc.value ||
        a.destinationIp === ioc.value ||
        a.host === ioc.value ||
        (a.evidence || []).some((ev) => ev.includes(ioc.value))
      );
    });

    // Correlate related incidents
    const alertIdSet = new Set(alerts.map((a) => a.id));
    const incidents = getSocDatabase().getAllIncidents().filter((inc) => {
      return (inc.alertIds || []).some((aId) => alertIdSet.has(aId));
    });

    return res.json({
      success: true,
      data: {
        ...ioc,
        enrichments,
        latestEnrichment,
        relatedAlerts: alerts,
        relatedIncidents: incidents,
      },
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to retrieve IOC details");
  }
});

// POST /api/iocs - Register / insert an IOC
apiRouter.post("/iocs", (req: Request, res: Response) => {
  try {
    const body = req.body;
    if (!body || typeof body !== "object") {
      return sendError(res, 400, "INVALID_REQUEST", "Request body must be a JSON object");
    }

    const { value, type } = body;
    if (!value || typeof value !== "string" || !value.trim()) {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: value");
    }
    if (!type || typeof type !== "string") {
      return sendError(res, 400, "INVALID_REQUEST", "Missing required field: type");
    }

    const trimmedValue = value.trim();
    const id = body.id || `IOC-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;
    const defangedValue = body.defangedValue || defangIocValue(trimmedValue, type);

    const ioc: IOC = {
      id,
      value: trimmedValue,
      defangedValue,
      type: type as IOC["type"],
      riskLevel: body.riskLevel || "UNKNOWN",
      context: body.context || "",
      sourceEventId: body.sourceEventId,
      confidence: Number(body.confidence || 0),
      firstSeen: body.firstSeen || new Date().toISOString(),
      tags: Array.isArray(body.tags) ? body.tags : [],
    };

    getSocDatabase().insertIoc(ioc);
    return res.status(201).json({
      success: true,
      data: ioc,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to register IOC");
  }
});

// POST /api/iocs/:id/enrich - Enrich IOC with threat intelligence (Safe Demo Mode compliant)
apiRouter.post("/api/iocs/:id/enrich", async (req: Request, res: Response) => {
  try {
    const ioc = getSocDatabase().getIocById(req.params.id);
    if (!ioc) {
      return sendError(res, 404, "NOT_FOUND", `IOC with ID '${req.params.id}' was not found`);
    }

    const forceRefresh = Boolean(req.body?.forceRefresh);
    const existingEnrichment = getSocDatabase().getLatestEnrichmentByIocId(ioc.id);

    const result = await enrichmentService.enrichIoc(
      ioc,
      existingEnrichment as any,
      forceRefresh
    );

    const now = new Date().toISOString();
    const enrichmentRecord = {
      id: `ENR-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`,
      iocId: ioc.id,
      provider: result.provider,
      reputation: result.reputation,
      threatLevel: result.threatLevel,
      confidence: result.confidence,
      classification: result.classification,
      firstSeen: result.firstSeen,
      lastSeen: result.lastSeen,
      enrichedAt: now,
      source: result.source,
      summary: result.summary,
      metadata: result.metadata || null,
      createdAt: now,
      updatedAt: now,
    };

    getSocDatabase().insertIocEnrichment(enrichmentRecord);

    return res.json({
      success: true,
      data: enrichmentRecord,
      status: result.status,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to enrich IOC");
  }
});

// Route alias without leading /api if router is mounted on /api
apiRouter.post("/iocs/:id/enrich", async (req: Request, res: Response) => {
  try {
    const ioc = getSocDatabase().getIocById(req.params.id);
    if (!ioc) {
      return sendError(res, 404, "NOT_FOUND", `IOC with ID '${req.params.id}' was not found`);
    }

    const forceRefresh = Boolean(req.body?.forceRefresh);
    const existingEnrichment = getSocDatabase().getLatestEnrichmentByIocId(ioc.id);

    const result = await enrichmentService.enrichIoc(
      ioc,
      existingEnrichment as any,
      forceRefresh
    );

    const now = new Date().toISOString();
    const enrichmentRecord = {
      id: `ENR-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`,
      iocId: ioc.id,
      provider: result.provider,
      reputation: result.reputation,
      threatLevel: result.threatLevel,
      confidence: result.confidence,
      classification: result.classification,
      firstSeen: result.firstSeen,
      lastSeen: result.lastSeen,
      enrichedAt: now,
      source: result.source,
      summary: result.summary,
      metadata: result.metadata || null,
      createdAt: now,
      updatedAt: now,
    };

    getSocDatabase().insertIocEnrichment(enrichmentRecord);

    return res.json({
      success: true,
      data: enrichmentRecord,
      status: result.status,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to enrich IOC");
  }
});


