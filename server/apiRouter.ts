import express, { Request, Response, Router } from "express";
import { ai } from "./geminiClient.js";
import { Type } from "@google/genai";

export const apiRouter: Router = express.Router();

apiRouter.use(express.json({ limit: "10mb" }));

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

