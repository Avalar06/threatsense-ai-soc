import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "http";
import express from "express";
import { getDatabase, initDatabase, closeDatabase } from "../../server/db/database.js";
import { apiRouter } from "../../server/apiRouter.js";

describe("Phase 3 Persistence & Full Lifecycle Integration Tests", () => {
  let server: http.Server;
  let baseUrl: string;

  before(async () => {
    // Initialize fresh DB for tests
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
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    closeDatabase();
  });

  it("1. GET /api/dashboard/stats returns empty initial statistics", async () => {
    const res = await fetch(`${baseUrl}/api/dashboard/stats`);
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(json.data.totalAlerts, 0);
    assert.equal(json.data.criticalAlerts, 0);
    assert.equal(json.data.resolvedAlerts, 0);
  });

  it("2. POST /api/logs/ingest persists security events & triggers alerts", async () => {
    const sampleLog = `2026-08-20T10:00:00Z host=DC-01 src_ip=198.51.100.44 user=root process=sshd status=FAILURE msg="Failed password for root"
2026-08-20T10:00:01Z host=DC-01 src_ip=198.51.100.44 user=root process=sshd status=FAILURE msg="Failed password for root"
2026-08-20T10:00:02Z host=DC-01 src_ip=198.51.100.44 user=root process=mimikatz status=FLAGGED msg="Mimikatz LSASS credential dumper executed"
2026-08-20T10:00:03Z host=DC-01 src_ip=198.51.100.44 user=root process=powershell status=FLAGGED msg="Invoke-Mimikatz sekurlsa::logonpasswords"`;

    const res = await fetch(`${baseUrl}/api/logs/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw: sampleLog, source: "DC-01" }),
    });

    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(json.data.eventsIngested, 4);
    assert.ok(json.data.alertsGenerated > 0, "Alerts should be generated");
  });

  it("3. GET /api/dashboard/stats reflects newly ingested data", async () => {
    const res = await fetch(`${baseUrl}/api/dashboard/stats`);
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.ok(json.data.totalAlerts > 0, "Total alerts should be > 0");
    assert.equal(json.data.activeHosts, 1);
  });

  it("4. PATCH /api/alerts/:id updates status and persists in SQLite database", async () => {
    // First get the generated alerts
    const alertsRes = await fetch(`${baseUrl}/api/alerts`);
    const alertsJson = await alertsRes.json();
    assert.ok(alertsJson.data.length > 0);
    const targetAlert = alertsJson.data[0];

    // Update status to INVESTIGATING
    const updateRes = await fetch(`${baseUrl}/api/alerts/${targetAlert.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "INVESTIGATING", notes: "Lead analyst initiated triage." }),
    });
    assert.equal(updateRes.status, 200);
    const updateJson = await updateRes.json();
    assert.equal(updateJson.data.status, "INVESTIGATING");
    assert.equal(updateJson.data.notes, "Lead analyst initiated triage.");
  });

  it("5. Verifies persistence across simulated frontend reload / fresh query", async () => {
    // Re-fetch all alerts as if the user refreshed the browser
    const reloadRes = await fetch(`${baseUrl}/api/alerts`);
    const reloadJson = await reloadRes.json();
    assert.equal(reloadRes.status, 200);
    
    const investigatingAlert = reloadJson.data.find((a: any) => a.status === "INVESTIGATING");
    assert.ok(investigatingAlert, "Alert must remain in INVESTIGATING state after simulated refresh");
    assert.equal(investigatingAlert.notes, "Lead analyst initiated triage.");
  });

  it("6. POST /api/reports persists incident reports across sessions", async () => {
    const reportPayload = {
      id: "RPT-PHASE3-TEST",
      reportTitle: "NIST Incident Report: Mimikatz LSASS Dump on DC-01",
      incidentId: "ALT-TEST-001",
      createdAt: new Date().toISOString(),
      author: "Senior SOC Analyst",
      status: "FINAL",
      classification: "CRITICAL INCIDENT",
      executiveSummary: "Unauthorized credential access attempted on primary domain controller DC-01.",
      incidentDescription: "Attacker executed Mimikatz process to extract Kerberos tickets from LSASS memory.",
      detectionMethod: "RULE_BASED",
      affectedAssets: ["DC-01"],
      affectedUsers: ["root"],
      timeline: [],
      extractedIocs: [],
      mitreMappings: [{ id: "T1003.001", name: "LSASS Memory", tactic: "Credential Access" }],
      rootCauseAnalysis: "Phishing credential access followed by remote execution.",
      riskAssessment: {
        quantitativeScore: 95,
        impactRating: "CRITICAL",
        confidentialityImpact: "High",
        integrityImpact: "High",
        availabilityImpact: "Low",
      },
      containmentActionsCompleted: ["Isolated DC-01 host.", "Revoked admin Kerberos tickets."],
      eradicationAndRemediation: ["Terminated unauthorized mimikatz process."],
      lessonsLearnedAndPreventativeControls: ["Enforce LSA protection and Credential Guard."],
      analystConclusion: "Threat eradicated and endpoints verified clean.",
    };

    const createRes = await fetch(`${baseUrl}/api/reports`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(reportPayload),
    });

    assert.equal(createRes.status, 201);
    const createJson = await createRes.json();
    assert.equal(createJson.data.id, "RPT-PHASE3-TEST");

    // Fetch reports to confirm persistence
    const fetchRes = await fetch(`${baseUrl}/api/reports`);
    const fetchJson = await fetchRes.json();
    assert.equal(fetchRes.status, 200);
    const persisted = fetchJson.data.find((r: any) => r.id === "RPT-PHASE3-TEST");
    assert.ok(persisted, "Persisted report must be present in GET /api/reports");
    assert.equal(persisted.reportTitle, "NIST Incident Report: Mimikatz LSASS Dump on DC-01");
  });
});
