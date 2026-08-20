import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "http";
import express from "express";
import { getDatabase, closeDatabase } from "../../server/db/database.js";
import { apiRouter } from "../../server/apiRouter.js";

describe("Phase 4A: Persistent AI Investigation & Alert/Incident Foundation Tests", () => {
  let server: http.Server;
  let baseUrl: string;
  let testAlertId: string;
  let testAlertId2: string;

  before(async () => {
    // Initialize fresh in-memory database
    getDatabase(":memory:");

    const app = express();
    app.use(express.json());
    app.use("/api", apiRouter);

    server = http.createServer(app);
    await new Promise<void>((resolve) => {
      server.listen(0, () => {
        const address = server.address() as any;
        baseUrl = `http://127.0.0.1:${address.port}`;
        resolve();
      });
    });

    // Ingest logs to generate alerts for testing
    const sampleLog = `2026-08-20T10:00:00Z host=CORP-WS-01 src_ip=198.51.100.99 user=analyst process=powershell status=FLAGGED msg="Mimikatz sekurlsa::logonpasswords"
2026-08-20T10:00:01Z host=CORP-WS-02 src_ip=198.51.100.100 user=admin process=cmd status=FLAGGED msg="vssadmin delete shadows /all /quiet"`;

    const ingestRes = await fetch(`${baseUrl}/api/logs/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw: sampleLog, source: "CORP-WS-01" }),
    });
    const ingestJson = await ingestRes.json();
    assert.equal(ingestRes.status, 200);
    assert.ok(ingestJson.data.alerts.length >= 2);
    testAlertId = ingestJson.data.alerts[0].id;
    testAlertId2 = ingestJson.data.alerts[1].id;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    closeDatabase();
  });

  // ----------------------------------------------------
  // 1. ANALYST ASSIGNMENT PERSISTENCE
  // ----------------------------------------------------
  it("1. PATCH /api/alerts/:id updates and persists assignedTo analyst", async () => {
    const patchRes = await fetch(`${baseUrl}/api/alerts/${testAlertId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ assignedTo: "SOC-Tier2-Analyst" }),
    });
    assert.equal(patchRes.status, 200);
    const patchJson = await patchRes.json();
    assert.equal(patchJson.success, true);
    assert.equal(patchJson.data.assignedTo, "SOC-Tier2-Analyst");

    // Verify GET /api/alerts/:id retrieves persisted analyst
    const getRes = await fetch(`${baseUrl}/api/alerts/${testAlertId}`);
    assert.equal(getRes.status, 200);
    const getJson = await getRes.json();
    assert.equal(getJson.success, true);
    assert.equal(getJson.data.alert.assignedTo, "SOC-Tier2-Analyst");
  });

  it("2. PATCH /api/alerts/:id can reassign or unassign analyst", async () => {
    const patchRes = await fetch(`${baseUrl}/api/alerts/${testAlertId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ assignedTo: "Incident-Responder-Lead" }),
    });
    assert.equal(patchRes.status, 200);
    const patchJson = await patchRes.json();
    assert.equal(patchJson.data.assignedTo, "Incident-Responder-Lead");

    const getRes = await fetch(`${baseUrl}/api/alerts/${testAlertId}`);
    const getJson = await getRes.json();
    assert.equal(getJson.data.alert.assignedTo, "Incident-Responder-Lead");
  });

  // ----------------------------------------------------
  // 2. GEMINI INVESTIGATION PERSISTENCE
  // ----------------------------------------------------
  it("3. PATCH /api/alerts/:id persists structured Gemini analysis & confidence", async () => {
    const mockAnalysis = {
      verdict: "True Positive",
      confidenceScore: 95,
      executiveSummary: "Confirmed LSASS credential access activity via Mimikatz in memory.",
      observedEvidence: [
        "Process powershell executing sekurlsa::logonpasswords",
        "Source IP 198.51.100.99 originating outside standard subnet",
      ],
      reasoningAndInferences: [
        "Attacker attempting to dump plaintext credentials and NTLM hashes.",
        "Probable lateral movement preparation phase.",
      ],
      uncertaintyAndGaps: [
        "Unclear if token impersonation succeeded before detection.",
      ],
      recommendedContainment: [
        "Isolate endpoint CORP-WS-01 from network immediately.",
        "Force password reset and revoke active Kerberos TGTs for compromised accounts.",
      ],
      recommendedInvestigation: [
        "Inspect event 4624/4625 authentication events on domain controllers.",
      ],
      extractedIocs: [
        { type: "IP", value: "198.51.100.99", riskLevel: "MALICIOUS", context: "Command and control source" },
      ],
    };

    const patchRes = await fetch(`${baseUrl}/api/alerts/${testAlertId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        geminiAnalysis: mockAnalysis,
      }),
    });
    assert.equal(patchRes.status, 200);
    const patchJson = await patchRes.json();
    assert.equal(patchJson.success, true);
    assert.equal(patchJson.data.aiConfidence, 95);
    assert.deepEqual(patchJson.data.geminiAnalysis.verdict, "True Positive");
    assert.equal(patchJson.data.geminiAnalysis.observedEvidence.length, 2);

    // Verify GET /api/alerts/:id loads persisted AI analysis
    const getRes = await fetch(`${baseUrl}/api/alerts/${testAlertId}`);
    assert.equal(getRes.status, 200);
    const getJson = await getRes.json();
    assert.equal(getJson.success, true);
    assert.ok(getJson.data.alert.geminiAnalysis);
    assert.equal(getJson.data.alert.geminiAnalysis.verdict, "True Positive");
    assert.equal(getJson.data.alert.geminiAnalysis.confidenceScore, 95);
    assert.equal(getJson.data.alert.aiConfidence, 95);
  });

  // ----------------------------------------------------
  // 3. ALERT -> INCIDENT ESCALATION & VALIDATION
  // ----------------------------------------------------
  let testIncidentId: string;

  it("4. POST /api/incidents creates incident linked to existing alert", async () => {
    const payload = {
      title: "Active Credential Dumping Incident - CORP-WS-01",
      severity: "CRITICAL",
      status: "OPEN",
      priority: "P1",
      leadAnalyst: "Incident-Responder-Lead",
      alertIds: [testAlertId],
      executiveSummary: "Mimikatz execution detected and escalated for full containment.",
    };

    const res = await fetch(`${baseUrl}/api/incidents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    assert.equal(res.status, 201);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.ok(json.data.id.startsWith("INC-"));
    assert.deepEqual(json.data.alertIds, [testAlertId]);
    assert.equal(json.data.leadAnalyst, "Incident-Responder-Lead");
    testIncidentId = json.data.id;
  });

  it("5. GET /api/incidents/:id returns incident and populates linked alerts", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}`);
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(json.data.id, testIncidentId);
    assert.equal(json.data.alertIds.length, 1);
    assert.equal(json.data.alerts.length, 1);
    assert.equal(json.data.alerts[0].id, testAlertId);
    assert.equal(json.data.alerts[0].assignedTo, "Incident-Responder-Lead");
  });

  it("6. POST /api/incidents deduplicates duplicate alert IDs cleanly", async () => {
    const payload = {
      title: "Multi-Host Incident with duplicate alert references",
      severity: "HIGH",
      status: "OPEN",
      alertIds: [testAlertId, testAlertId2, testAlertId, testAlertId2],
    };

    const res = await fetch(`${baseUrl}/api/incidents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    assert.equal(res.status, 201);
    const json = await res.json();
    assert.equal(json.success, true);
    // Should deduplicate 4 items to 2 unique alert IDs
    assert.equal(json.data.alertIds.length, 2);
    assert.ok(json.data.alertIds.includes(testAlertId));
    assert.ok(json.data.alertIds.includes(testAlertId2));
  });

  it("7. POST /api/incidents rejects non-existent alert IDs with 404 NOT_FOUND", async () => {
    const payload = {
      title: "Invalid Alert Linking Incident",
      severity: "HIGH",
      status: "OPEN",
      alertIds: ["NON-EXISTENT-ALERT-99999"],
    };

    const res = await fetch(`${baseUrl}/api/incidents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    assert.equal(res.status, 404);
    const json = await res.json();
    assert.equal(json.success, false);
    assert.equal(json.error.code, "NOT_FOUND");
    assert.ok(json.error.message.includes("NON-EXISTENT-ALERT-99999"));
  });

  it("8. PATCH /api/incidents/:id rejects non-existent alert IDs with 404 NOT_FOUND", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        alertIds: ["FAKE-ALERT-ID-12345"],
      }),
    });

    assert.equal(res.status, 404);
    const json = await res.json();
    assert.equal(json.success, false);
    assert.equal(json.error.code, "NOT_FOUND");
  });

  it("9. PATCH /api/incidents/:id accepts valid linked alerts & deduplicates", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        alertIds: [testAlertId, testAlertId2, testAlertId],
        status: "CONTAINED",
      }),
    });

    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(json.data.status, "CONTAINED");
    assert.equal(json.data.alertIds.length, 2);

    // Verify GET /api/incidents/:id reflects populated alerts
    const getRes = await fetch(`${baseUrl}/api/incidents/${testIncidentId}`);
    const getJson = await getRes.json();
    assert.equal(getJson.data.alerts.length, 2);
  });

  it("10. PATCH /api/alerts/:id returns 404 for non-existent alert", async () => {
    const res = await fetch(`${baseUrl}/api/alerts/DOES_NOT_EXIST`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ assignedTo: "SOC-Tier1-Triage" }),
    });

    assert.equal(res.status, 404);
    const json = await res.json();
    assert.equal(json.success, false);
    assert.equal(json.error.code, "NOT_FOUND");
  });
});
