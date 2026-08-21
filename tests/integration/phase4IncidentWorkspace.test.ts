import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "http";
import express from "express";
import fs from "node:fs";
import path from "node:path";
import { getDatabase, initDatabase, closeDatabase, SocDatabase } from "../../server/db/database.js";
import { apiRouter } from "../../server/apiRouter.js";

describe("Phase 4B-A: Incident Management Workspace & Lifecycle Integration Tests", () => {
  let server: http.Server;
  let baseUrl: string;
  let testAlertId1: string;
  let testAlertId2: string;
  let createdIncidentId: string;
  const tempDbPath = path.join(process.cwd(), "data", `test_phase4b_${Date.now()}.db`);

  before(async () => {
    // Initialize file-based database for persistence tests
    getDatabase(tempDbPath);

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

    // Ingest logs to produce alerts to link with incidents
    const sampleLog = `2026-08-20T10:00:00Z host=DC-01 src_ip=198.51.100.45 user=attacker process=cmd status=FLAGGED msg="Mimikatz sekurlsa::logonpasswords"
2026-08-20T10:00:02Z host=DC-01 src_ip=198.51.100.45 user=attacker process=powershell status=FLAGGED msg="vssadmin delete shadows /all /quiet"`;

    const ingestRes = await fetch(`${baseUrl}/api/logs/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw: sampleLog, source: "DC-01" }),
    });
    const ingestJson = await ingestRes.json();
    assert.equal(ingestRes.status, 200);
    assert.ok(ingestJson.data.alerts.length >= 2);
    testAlertId1 = ingestJson.data.alerts[0].id;
    testAlertId2 = ingestJson.data.alerts[1].id;
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

  // ----------------------------------------------------
  // 1. INCIDENT CREATION & LINKAGE
  // ----------------------------------------------------
  it("1. POST /api/incidents creates incident linked to existing alerts", async () => {
    const payload = {
      title: "Domain Controller Compromise & Kerberoasting",
      severity: "HIGH",
      priority: "P2",
      status: "OPEN",
      leadAnalyst: "SOC-Tier2-Analyst",
      executiveSummary: "Multiple reconnaissance and credential dumping attempts detected targeting DC-01.",
      alertIds: [testAlertId1, testAlertId2],
      containmentActions: [],
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
    assert.equal(json.data.title, payload.title);
    assert.equal(json.data.severity, "HIGH");
    assert.equal(json.data.priority, "P2");
    assert.equal(json.data.status, "OPEN");
    assert.equal(json.data.leadAnalyst, "SOC-Tier2-Analyst");
    assert.deepEqual(json.data.alertIds, [testAlertId1, testAlertId2]);
    createdIncidentId = json.data.id;
  });

  // ----------------------------------------------------
  // 2. GET INCIDENTS & RETRIEVE BY ID
  // ----------------------------------------------------
  it("2. GET /api/incidents returns list containing created incident", async () => {
    const res = await fetch(`${baseUrl}/api/incidents`);
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.ok(Array.isArray(json.data));
    const found = json.data.find((i: any) => i.id === createdIncidentId);
    assert.ok(found);
    assert.equal(found.title, "Domain Controller Compromise & Kerberoasting");
  });

  it("3. GET /api/incidents/:id returns incident with hydrated linked alerts", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}`);
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(json.data.id, createdIncidentId);
    assert.ok(Array.isArray(json.data.alerts));
    assert.equal(json.data.alerts.length, 2);
    assert.equal(json.data.alerts[0].id, testAlertId1);
    assert.equal(json.data.alerts[1].id, testAlertId2);
  });

  // ----------------------------------------------------
  // 3. LIFECYCLE FIELD UPDATES (PATCH)
  // ----------------------------------------------------
  it("4. PATCH /api/incidents/:id updates status and persists lifecycle transition", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "INVESTIGATING" }),
    });
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.data.status, "INVESTIGATING");

    // Verify persistence via GET
    const getRes = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}`);
    const getJson = await getRes.json();
    assert.equal(getJson.data.status, "INVESTIGATING");
  });

  it("5. PATCH /api/incidents/:id updates severity to CRITICAL", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ severity: "CRITICAL" }),
    });
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.data.severity, "CRITICAL");

    const getRes = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}`);
    const getJson = await getRes.json();
    assert.equal(getJson.data.severity, "CRITICAL");
  });

  it("6. PATCH /api/incidents/:id updates priority to P1", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ priority: "P1" }),
    });
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.data.priority, "P1");

    const getRes = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}`);
    const getJson = await getRes.json();
    assert.equal(getJson.data.priority, "P1");
  });

  it("7. PATCH /api/incidents/:id updates lead analyst", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ leadAnalyst: "Incident-Responder-Lead" }),
    });
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.data.leadAnalyst, "Incident-Responder-Lead");

    const getRes = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}`);
    const getJson = await getRes.json();
    assert.equal(getJson.data.leadAnalyst, "Incident-Responder-Lead");
  });

  it("8. PATCH /api/incidents/:id updates executive summary", async () => {
    const updatedSummary = "Full root cause analysis complete: adversary utilized stolen credentials from host DC-01.";
    const res = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ executiveSummary: updatedSummary }),
    });
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.data.executiveSummary, updatedSummary);

    const getRes = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}`);
    const getJson = await getRes.json();
    assert.equal(getJson.data.executiveSummary, updatedSummary);
  });

  // ----------------------------------------------------
  // 4. ERROR HANDLING & 404 RESPONSES
  // ----------------------------------------------------
  it("9. GET /api/incidents/:id with non-existent ID returns 404", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/INC-NONEXISTENT-999`);
    assert.equal(res.status, 404);
    const json = await res.json();
    assert.equal(json.success, false);
    assert.equal(json.error.code, "NOT_FOUND");
  });

  it("10. PATCH /api/incidents/:id with non-existent ID returns 404", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/INC-NONEXISTENT-999`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "CLOSED" }),
    });
    assert.equal(res.status, 404);
    const json = await res.json();
    assert.equal(json.success, false);
    assert.equal(json.error.code, "NOT_FOUND");
  });

  // ----------------------------------------------------
  // 5. FILTERING CAPABILITIES
  // ----------------------------------------------------
  it("11. GET /api/incidents filters correctly by status, severity, priority, leadAnalyst, and search", async () => {
    // Filter by status INVESTIGATING
    const resStatus = await fetch(`${baseUrl}/api/incidents?status=INVESTIGATING`);
    const jsonStatus = await resStatus.json();
    assert.ok(jsonStatus.data.some((i: any) => i.id === createdIncidentId));

    // Filter by mismatching status
    const resMismatch = await fetch(`${baseUrl}/api/incidents?status=RESOLVED`);
    const jsonMismatch = await resMismatch.json();
    assert.ok(!jsonMismatch.data.some((i: any) => i.id === createdIncidentId));

    // Filter by severity CRITICAL
    const resSev = await fetch(`${baseUrl}/api/incidents?severity=CRITICAL`);
    const jsonSev = await resSev.json();
    assert.ok(jsonSev.data.some((i: any) => i.id === createdIncidentId));

    // Filter by leadAnalyst
    const resAnalyst = await fetch(`${baseUrl}/api/incidents?leadAnalyst=Incident-Responder-Lead`);
    const jsonAnalyst = await resAnalyst.json();
    assert.ok(jsonAnalyst.data.some((i: any) => i.id === createdIncidentId));

    // Search query
    const resSearch = await fetch(`${baseUrl}/api/incidents?search=Kerberoasting`);
    const jsonSearch = await resSearch.json();
    assert.ok(jsonSearch.data.some((i: any) => i.id === createdIncidentId));
  });

  // ----------------------------------------------------
  // 6. DISK REOPEN & PERSISTENCE SURVIVABILITY
  // ----------------------------------------------------
  it("12. Incident updates survive database close and reopen", () => {
    // Close database connection
    closeDatabase();

    // Reopen database directly from disk file
    const reopenedDb = initDatabase(tempDbPath);
    const repo = new SocDatabase(reopenedDb);

    const record = repo.getIncidentById(createdIncidentId);
    assert.ok(record);
    assert.equal(record.id, createdIncidentId);
    assert.equal(record.status, "INVESTIGATING");
    assert.equal(record.severity, "CRITICAL");
    assert.equal(record.priority, "P1");
    assert.equal(record.leadAnalyst, "Incident-Responder-Lead");
    assert.equal(record.executiveSummary, "Full root cause analysis complete: adversary utilized stolen credentials from host DC-01.");
    assert.deepEqual(record.alertIds, [testAlertId1, testAlertId2]);

    reopenedDb.close();
  });
});
