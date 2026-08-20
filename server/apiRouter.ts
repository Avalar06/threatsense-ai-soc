import express, { Request, Response, Router } from "express";
import { ai } from "./geminiClient.js";
import { Type } from "@google/genai";
import { SocDatabase } from "./db/database.js";
import { parseRawLogs } from "../src/services/logParser.js";
import { runDetectionEngine } from "../src/services/detectionEngine.js";
import type { Alert, SecurityEvent, IncidentReport } from "../src/types/soc.js";

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

// PATCH /api/alerts/:id - Update analyst-controlled fields
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
      updates.status = body.status;
    }
    if (body.notes !== undefined || body.analystNotes !== undefined) {
      updates.notes = body.notes !== undefined ? String(body.notes) : String(body.analystNotes);
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
    const { status, severity, priority, search, limit, offset } = req.query;
    const result = getSocDatabase().listIncidents({
      status: typeof status === "string" ? status : undefined,
      severity: typeof severity === "string" ? severity : undefined,
      priority: typeof priority === "string" ? priority : undefined,
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

// GET /api/incidents/:id - Retrieve incident by ID
apiRouter.get("/incidents/:id", (req: Request, res: Response) => {
  try {
    const incident = getSocDatabase().getIncidentById(req.params.id);
    if (!incident) {
      return sendError(res, 404, "NOT_FOUND", `Incident with ID '${req.params.id}' was not found`);
    }
    return res.json({
      success: true,
      data: incident,
    });
  } catch {
    return sendError(res, 500, "INTERNAL_ERROR", "Failed to retrieve incident");
  }
});

// POST /api/incidents - Create incident record
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

    const now = new Date().toISOString();
    const incident = {
      id,
      title: title.trim(),
      severity,
      status,
      priority: body.priority || "P2",
      leadAnalyst: body.leadAnalyst,
      alertIds: Array.isArray(body.alertIds) ? body.alertIds : [],
      executiveSummary: body.executiveSummary || "",
      containmentActions: Array.isArray(body.containmentActions) ? body.containmentActions : [],
      createdAt: body.createdAt || now,
      updatedAt: body.updatedAt || now,
      closedAt: body.closedAt,
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

// PATCH /api/incidents/:id - Update incident lifecycle fields
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

    const updates: Partial<typeof existing> = {};
    if (body.status !== undefined) updates.status = String(body.status);
    if (body.priority !== undefined) updates.priority = String(body.priority);
    if (body.leadAnalyst !== undefined) updates.leadAnalyst = String(body.leadAnalyst);
    if (body.executiveSummary !== undefined) updates.executiveSummary = String(body.executiveSummary);
    if (Array.isArray(body.containmentActions)) updates.containmentActions = body.containmentActions;
    if (Array.isArray(body.alertIds)) updates.alertIds = body.alertIds;
    if (body.closedAt !== undefined) updates.closedAt = String(body.closedAt);
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

