import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "http";
import express from "express";
import fs from "node:fs";
import path from "node:path";
import { getDatabase, closeDatabase, SocDatabase } from "../../server/db/database.js";
import { apiRouter } from "../../server/apiRouter.js";

describe("Phase 4B-C & Phase 5: Intelligence-Driven Incident Management & Case Closure Integration Tests", () => {
  let server: http.Server;
  let baseUrl: string;
  let testIncidentId: string;
  let testAlertId: string;
  let testIocId: string;
  const tempDbPath = path.join(process.cwd(), "data", `test_phase5_${Date.now()}.db`);

  before(async () => {
    // Initialize file-based database for persistence tests
    getDatabase(tempDbPath);
    const socDb = new SocDatabase(tempDbPath);

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

    // 1. Create a test alert
    const alertRes = await fetch(`${baseUrl}/api/alerts`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: `ALT-TEST-PHASE5-${Date.now()}`,
        title: "Malicious Cobalt Strike Beaconing Detected",
        severity: "CRITICAL",
        status: "NEW",
        sourceIp: "198.51.100.44",
        destinationIp: "203.0.113.88",
        host: "FIN-SRV-01",
        username: "victim_admin",
        riskScore: 92,
        detectionConfidence: 95,
        detectionSource: "SURICATA_IDS",
        mitreTechniques: [
          { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control", confidence: 90 },
          { id: "T1059.001", name: "PowerShell", tactic: "Execution", confidence: 95 },
        ],
        evidence: ["TCP socket opened to 198.51.100.44:443", "Base64 encoded powershell cradle"],
      }),
    });
    const alertJson = await alertRes.json();
    assert.equal(alertRes.status, 201);
    testAlertId = alertJson.data.id;

    // 2. Ingest related security event
    socDb.insertEvent({
      id: `EVT-TEST-${Date.now()}`,
      timestamp: new Date().toISOString(),
      source_ip: "198.51.100.44",
      destination_ip: "203.0.113.88",
      event_type: "NETWORK_EGRESS",
      severity: "CRITICAL",
      message: "Suspicious TLS outbound handshake to Cobalt Strike C2 controller",
      hostname: "FIN-SRV-01",
      username: "victim_admin",
      action: "BLOCK",
      status: "ANOMALOUS",
      process: "powershell.exe",
      raw: "Mar 10 14:02:15 FIN-SRV-01 EDR[4412]: Alert: Encrypted C2 Beacon to 198.51.100.44:443",
    }, testAlertId);

    // 3. Create test incident linked to alert
    const incRes = await fetch(`${baseUrl}/api/incidents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: "Financial Server APT Infiltration & Data Exfiltration",
        severity: "CRITICAL",
        status: "INVESTIGATING",
        priority: "P1",
        leadAnalyst: "Incident-Responder-Lead",
        alertIds: [testAlertId],
        executiveSummary: "Adversary gained initial foothold on FIN-SRV-01 and attempted C2 connection.",
      }),
    });
    const incJson = await incRes.json();
    assert.equal(incRes.status, 201);
    testIncidentId = incJson.data.id;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    closeDatabase();
    if (fs.existsSync(tempDbPath)) {
      try {
        fs.unlinkSync(tempDbPath);
      } catch {}
    }
  });

  // ====================================================
  // 1. THREAT INTELLIGENCE & IOC MANAGEMENT TESTS
  // ====================================================

  it("1. POST /api/iocs registers an IOC with automatic defanging", async () => {
    const res = await fetch(`${baseUrl}/api/iocs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        value: "198.51.100.44",
        type: "IPV4",
        riskLevel: "MALICIOUS",
        confidence: 90,
        context: "Cobalt Strike C2 server",
      }),
    });

    const json = await res.json();
    assert.equal(res.status, 201);
    assert.equal(json.success, true);
    assert.equal(json.data.value, "198.51.100.44");
    assert.equal(json.data.defangedValue, "198[.]51[.]100[.]44");
    assert.equal(json.data.type, "IPV4");
    testIocId = json.data.id;
  });

  it("2. POST /api/iocs registers domain with safe defanging", async () => {
    const res = await fetch(`${baseUrl}/api/iocs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        value: "evil-c2.threat-domain.com",
        type: "DOMAIN",
        riskLevel: "SUSPICIOUS",
        confidence: 85,
        context: "Command & Control domain",
      }),
    });

    const json = await res.json();
    assert.equal(res.status, 201);
    assert.equal(json.data.defangedValue, "evil-c2[.]threat-domain[.]com");
  });

  it("3. GET /api/iocs lists IOCs with filtering", async () => {
    const res = await fetch(`${baseUrl}/api/iocs?type=IPV4`);
    const json = await res.json();
    assert.equal(res.status, 200);
    assert.equal(json.success, true);
    assert.ok(Array.isArray(json.data));
    assert.ok(json.data.some((i: any) => i.id === testIocId));
  });

  it("4. GET /api/iocs/:id retrieves IOC details with correlated alerts and incidents", async () => {
    const res = await fetch(`${baseUrl}/api/iocs/${testIocId}`);
    const json = await res.json();
    assert.equal(res.status, 200);
    assert.equal(json.success, true);
    assert.equal(json.data.id, testIocId);
    assert.ok(Array.isArray(json.data.relatedAlerts));
    assert.ok(Array.isArray(json.data.relatedIncidents));
    assert.ok(json.data.relatedAlerts.some((a: any) => a.id === testAlertId));
    assert.ok(json.data.relatedIncidents.some((i: any) => i.id === testIncidentId));
  });

  it("5. POST /api/iocs/:id/enrich enriches IOC via provider engine (Demo/Configured mode)", async () => {
    const res = await fetch(`${baseUrl}/api/iocs/${testIocId}/enrich`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ forceRefresh: true }),
    });

    const json = await res.json();
    assert.equal(res.status, 200);
    assert.equal(json.success, true);
    assert.ok(json.data.id);
    assert.equal(json.data.iocId, testIocId);
    assert.ok(json.data.provider);
    assert.ok(json.data.reputation);
    assert.ok(json.data.threatLevel);
    assert.ok(json.data.summary);
  });

  it("6. GET /api/iocs/:id returns persisted enrichments", async () => {
    const res = await fetch(`${baseUrl}/api/iocs/${testIocId}`);
    const json = await res.json();
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(json.data.enrichments));
    assert.ok(json.data.enrichments.length >= 1);
    assert.equal(json.data.enrichments[0].iocId, testIocId);
  });

  // ====================================================
  // 2. RESPONSE ACTION TRACKING INTEGRATION
  // ====================================================

  it("7. Response actions can be executed on the incident", async () => {
    // Request action
    const reqRes = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actionType: "ISOLATE_HOST",
        targetType: "HOST",
        target: "FIN-SRV-01",
        requestedBy: "Incident-Responder-Lead",
        notes: "Quarantine affected host immediately",
      }),
    });
    const reqJson = await reqRes.json();
    assert.equal(reqRes.status, 201);
    const actionId = reqJson.data.id;

    // Approve action
    const appRes = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions/${actionId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "APPROVED",
        approvedBy: "SOC-Director",
      }),
    });
    assert.equal(appRes.status, 200);

    // Execute action
    const execRes = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions/${actionId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "EXECUTED",
        result: "Endpoint FIN-SRV-01 successfully isolated from internal subnets.",
      }),
    });
    const execJson = await execRes.json();
    assert.equal(execRes.status, 200);
    assert.equal(execJson.data.status, "EXECUTED");
  });

  // ====================================================
  // 3. TIMELINE AGGREGATION TESTS
  // ====================================================

  it("8. GET /api/incidents/:id/timeline synthesizes chronological lifecycle timeline", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/timeline`);
    const json = await res.json();
    assert.equal(res.status, 200);
    assert.equal(json.success, true);
    assert.ok(Array.isArray(json.data));
    assert.ok(json.data.length >= 3);

    // Verify presence of creation, detection, and action stages
    const stages = json.data.map((e: any) => e.stage);
    assert.ok(stages.includes("INCIDENT_CREATION"));
    assert.ok(stages.includes("DETECTION_TRIGGERED"));
    assert.ok(stages.includes("ACTION_REQUESTED"));
    assert.ok(stages.includes("ACTION_EXECUTED"));

    // Verify chronological order
    for (let i = 0; i < json.data.length - 1; i++) {
      const t1 = new Date(json.data[i].time).getTime();
      const t2 = new Date(json.data[i + 1].time).getTime();
      assert.ok(t1 <= t2, "Timeline events must be chronologically ordered");
    }
  });

  // ====================================================
  // 4. INCIDENT REPORT GENERATION TESTS
  // ====================================================

  it("9. POST /api/incidents/:id/generate-report synthesizes comprehensive report", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/generate-report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        author: "Senior Incident Responder Lead",
        classification: "CRITICAL INCIDENT",
      }),
    });

    const json = await res.json();
    assert.equal(res.status, 201);
    assert.equal(json.success, true);
    assert.equal(json.data.incidentId, testIncidentId);
    assert.ok(json.data.reportTitle.includes("Financial Server"));
    assert.ok(Array.isArray(json.data.affectedAssets));
    assert.ok(json.data.affectedAssets.includes("FIN-SRV-01"));
    assert.ok(Array.isArray(json.data.affectedUsers));
    assert.ok(json.data.affectedUsers.includes("victim_admin"));
    assert.ok(Array.isArray(json.data.timeline));
    assert.ok(json.data.timeline.length > 0);
    assert.ok(Array.isArray(json.data.mitreMappings));
    assert.ok(json.data.mitreMappings.some((m: any) => m.id === "T1071.001"));
    assert.ok(Array.isArray(json.data.containmentActionsCompleted));
    assert.ok(json.data.containmentActionsCompleted.some((c: string) => c.includes("FIN-SRV-01")));
  });

  it("10. GET /api/reports?incidentId=... retrieves generated report", async () => {
    const res = await fetch(`${baseUrl}/api/reports?incidentId=${testIncidentId}`);
    const json = await res.json();
    assert.equal(res.status, 200);
    assert.equal(json.success, true);
    assert.ok(json.data.length >= 1);
    assert.equal(json.data[0].incidentId, testIncidentId);
  });

  // ====================================================
  // 5. CASE CLOSURE & LIFECYCLE ENFORCEMENT TESTS
  // ====================================================

  it("11. PATCH /api/incidents/:id rejects status CLOSED without closureSummary", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "CLOSED",
        closedBy: "Lead-Analyst-Alice",
      }),
    });

    const json = await res.json();
    assert.equal(res.status, 400);
    assert.equal(json.success, false);
    assert.equal(json.error.code, "CLOSURE_SUMMARY_REQUIRED");
  });

  it("12. PATCH /api/incidents/:id rejects status CLOSED without closedBy", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "CLOSED",
        closureSummary: "Incident fully mitigated and contained.",
      }),
    });

    const json = await res.json();
    assert.equal(res.status, 400);
    assert.equal(json.success, false);
    assert.equal(json.error.code, "CLOSED_BY_REQUIRED");
  });

  it("13. PATCH /api/incidents/:id successfully closes case with required metadata", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "CLOSED",
        closedBy: "Lead-Analyst-Alice",
        closureSummary: "C2 connection terminated, endpoint isolated, and compromised credentials revoked.",
      }),
    });

    const json = await res.json();
    assert.equal(res.status, 200);
    assert.equal(json.success, true);
    assert.equal(json.data.status, "CLOSED");
    assert.equal(json.data.closedBy, "Lead-Analyst-Alice");
    assert.equal(
      json.data.closureSummary,
      "C2 connection terminated, endpoint isolated, and compromised credentials revoked."
    );
    assert.ok(json.data.closedAt);
  });

  it("14. Closed incident rejects status regression", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "OPEN",
      }),
    });

    const json = await res.json();
    assert.equal(res.status, 400);
    assert.equal(json.success, false);
    assert.equal(json.error.code, "INVALID_LIFECYCLE_TRANSITION");
  });

  it("15. Timeline reflects CASE_CLOSED milestone after incident closure", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/timeline`);
    const json = await res.json();
    assert.equal(res.status, 200);
    const closureEvent = json.data.find((e: any) => e.stage === "CASE_CLOSED");
    assert.ok(closureEvent);
    assert.ok(closureEvent.description.includes("Lead-Analyst-Alice"));
    assert.ok(closureEvent.description.includes("C2 connection terminated"));
  });
});
