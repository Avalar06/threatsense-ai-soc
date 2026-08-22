import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "http";
import express from "express";
import fs from "node:fs";
import path from "node:path";
import { getDatabase, closeDatabase, SocDatabase } from "../../server/db/database.js";
import { apiRouter } from "../../server/apiRouter.js";

describe("Phase 4B-B: Persistent Response & Containment Action Tracking Integration Tests", () => {
  let server: http.Server;
  let baseUrl: string;
  let testIncidentId: string;
  let testIncidentId2: string;
  let createdActionId: string;
  const tempDbPath = path.join(process.cwd(), "data", `test_phase4bb_${Date.now()}.db`);

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

    // Create test incidents
    const incRes1 = await fetch(`${baseUrl}/api/incidents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: "Active APT29 Host Compromise & Lateral Movement",
        severity: "CRITICAL",
        status: "INVESTIGATING",
        priority: "P1",
        leadAnalyst: "Incident-Responder-Lead",
        containmentActions: ["Legacy: Network isolate DC-01 firewall rule"],
      }),
    });
    const incJson1 = await incRes1.json();
    assert.equal(incRes1.status, 201);
    testIncidentId = incJson1.data.id;

    const incRes2 = await fetch(`${baseUrl}/api/incidents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: "Secondary Phishing Incident",
        severity: "MEDIUM",
        status: "OPEN",
        priority: "P3",
      }),
    });
    const incJson2 = await incRes2.json();
    testIncidentId2 = incJson2.data.id;
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
  // 1. ACTION CREATION & VALIDATION
  // ----------------------------------------------------
  it("1. POST /api/incidents/:id/actions creates action in REQUESTED status", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actionType: "ISOLATE_HOST",
        targetType: "HOST",
        target: "FIN-SRV-01",
        requestedBy: "Threat-Hunter",
        notes: "Isolate financial server to prevent data staging",
      }),
    });

    assert.equal(res.status, 201);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.ok(json.data.id.startsWith("ACT-"));
    assert.equal(json.data.incidentId, testIncidentId);
    assert.equal(json.data.actionType, "ISOLATE_HOST");
    assert.equal(json.data.targetType, "HOST");
    assert.equal(json.data.target, "FIN-SRV-01");
    assert.equal(json.data.status, "REQUESTED");
    assert.equal(json.data.requestedBy, "Threat-Hunter");
    assert.equal(json.data.notes, "Isolate financial server to prevent data staging");
    assert.ok(json.data.requestedAt);

    createdActionId = json.data.id;
  });

  it("2. POST /api/incidents/:id/actions rejects invalid actionType", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actionType: "UNAUTHORIZED_ACTION",
        targetType: "HOST",
        target: "CORP-WS-01",
        requestedBy: "Analyst",
      }),
    });

    assert.equal(res.status, 400);
    const json = await res.json();
    assert.equal(json.success, false);
    assert.equal(json.error.code, "INVALID_ACTION_TYPE");
  });

  it("3. POST /api/incidents/:id/actions rejects incompatible targetType for actionType", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actionType: "BLOCK_IP",
        targetType: "ACCOUNT", // IP blocking cannot target ACCOUNT
        target: "bad_user",
        requestedBy: "Analyst",
      }),
    });

    assert.equal(res.status, 400);
    const json = await res.json();
    assert.equal(json.success, false);
    assert.equal(json.error.code, "TARGET_TYPE_MISMATCH");
  });

  it("4. POST /api/incidents/:id/actions rejects missing target or requestedBy", async () => {
    const res1 = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actionType: "BLOCK_IP",
        targetType: "IP",
        target: "   ",
        requestedBy: "Analyst",
      }),
    });
    assert.equal(res1.status, 400);

    const res2 = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actionType: "BLOCK_IP",
        targetType: "IP",
        target: "198.51.100.23",
        requestedBy: "",
      }),
    });
    assert.equal(res2.status, 400);
  });

  it("5. POST /api/incidents/:id/actions returns 404 for non-existent incident", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/INC-NON-EXISTENT/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actionType: "BLOCK_IP",
        targetType: "IP",
        target: "198.51.100.23",
        requestedBy: "Analyst",
      }),
    });

    assert.equal(res.status, 404);
  });

  // ----------------------------------------------------
  // 2. RETRIEVAL & HYDRATION
  // ----------------------------------------------------
  it("6. GET /api/incidents/:id/actions returns all actions for the incident", async () => {
    // Add another action
    await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actionType: "BLOCK_IP",
        targetType: "IP",
        target: "198.51.100.99",
        requestedBy: "SOC-Tier2-Analyst",
        notes: "Block C2 IP at perimeter",
      }),
    });

    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions`);
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(json.data.length, 2);
    assert.ok(json.data.some((a: any) => a.actionType === "ISOLATE_HOST"));
    assert.ok(json.data.some((a: any) => a.actionType === "BLOCK_IP"));
  });

  it("7. GET /api/incidents/:id returns responseActions array and legacy containmentActions", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}`);
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.ok(Array.isArray(json.data.responseActions));
    assert.equal(json.data.responseActions.length, 2);
    // Legacy containment actions preserved
    assert.deepEqual(json.data.containmentActions, ["Legacy: Network isolate DC-01 firewall rule"]);
  });

  // ----------------------------------------------------
  // 3. LIFECYCLE STATE TRANSITIONS
  // ----------------------------------------------------
  it("8. PATCH /api/incidents/:id/actions/:actionId rejects REQUESTED -> EXECUTED without approval", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions/${createdActionId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "EXECUTED",
      }),
    });

    assert.equal(res.status, 400);
    const json = await res.json();
    assert.equal(json.success, false);
    assert.equal(json.error.code, "INVALID_TRANSITION");
  });

  it("9. PATCH /api/incidents/:id/actions/:actionId transitions REQUESTED -> APPROVED", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions/${createdActionId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "APPROVED",
        approvedBy: "Incident-Responder-Lead",
      }),
    });

    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(json.data.status, "APPROVED");
    assert.equal(json.data.approvedBy, "Incident-Responder-Lead");
    assert.ok(json.data.approvedAt);
  });

  it("10. PATCH /api/incidents/:id/actions/:actionId transitions APPROVED -> EXECUTED (simulated)", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions/${createdActionId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "EXECUTED",
        result: "Simulated host isolation verified on FIN-SRV-01",
      }),
    });

    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.success, true);
    assert.equal(json.data.status, "EXECUTED");
    assert.ok(json.data.executedAt);
    assert.equal(json.data.result, "Simulated host isolation verified on FIN-SRV-01");
  });

  it("11. PATCH /api/incidents/:id/actions/:actionId rejects transition from terminal EXECUTED state", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions/${createdActionId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "CANCELLED",
      }),
    });

    assert.equal(res.status, 400);
    const json = await res.json();
    assert.equal(json.success, false);
    assert.equal(json.error.code, "INVALID_TRANSITION");
  });

  it("12. PATCH /api/incidents/:id/actions/:actionId supports CANCELLED transition from REQUESTED", async () => {
    // Create new action
    const createRes = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actionType: "KILL_PROCESS",
        targetType: "PROCESS",
        target: "powershell.exe",
        requestedBy: "Analyst",
      }),
    });
    const createJson = await createRes.json();
    const actionId = createJson.data.id;

    // Cancel it
    const patchRes = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions/${actionId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "CANCELLED",
        result: "Process was legitimate admin script",
      }),
    });

    assert.equal(patchRes.status, 200);
    const patchJson = await patchRes.json();
    assert.equal(patchJson.data.status, "CANCELLED");
    assert.equal(patchJson.data.result, "Process was legitimate admin script");
  });

  it("13. PATCH /api/incidents/:id/actions/:actionId supports FAILED transition from APPROVED", async () => {
    // Create new action
    const createRes = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actionType: "DISABLE_ACCOUNT",
        targetType: "ACCOUNT",
        target: "admin_backup",
        requestedBy: "Analyst",
      }),
    });
    const createJson = await createRes.json();
    const actionId = createJson.data.id;

    // Approve it
    await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions/${actionId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "APPROVED" }),
    });

    // Mark as FAILED
    const failRes = await fetch(`${baseUrl}/api/incidents/${testIncidentId}/actions/${actionId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "FAILED",
        result: "Simulated active directory connection timeout",
      }),
    });

    assert.equal(failRes.status, 200);
    const failJson = await failRes.json();
    assert.equal(failJson.data.status, "FAILED");
    assert.equal(failJson.data.result, "Simulated active directory connection timeout");
  });

  it("14. PATCH /api/incidents/:id/actions/:actionId rejects cross-incident action mismatch", async () => {
    const res = await fetch(`${baseUrl}/api/incidents/${testIncidentId2}/actions/${createdActionId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ notes: "Attempt cross-incident modification" }),
    });

    assert.equal(res.status, 400);
  });

  // ----------------------------------------------------
  // 4. DATABASE INTEGRITY
  // ----------------------------------------------------
  it("15. Direct SQLite query verifies persisted columns and types", () => {
    const socDb = new SocDatabase(getDatabase());
    const action = socDb.getIncidentActionById(createdActionId);
    assert.ok(action);
    assert.equal(action.id, createdActionId);
    assert.equal(action.incidentId, testIncidentId);
    assert.equal(action.actionType, "ISOLATE_HOST");
    assert.equal(action.targetType, "HOST");
    assert.equal(action.target, "FIN-SRV-01");
    assert.equal(action.status, "EXECUTED");
    assert.equal(action.approvedBy, "Incident-Responder-Lead");
  });
});
