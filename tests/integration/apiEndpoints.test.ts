import { apiRouter } from "../../server/apiRouter.js";
import express from "express";
import http from "http";

console.log("▶ [TEST SUITE] Running Backend API Integration Tests...");

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string) {
  if (condition) {
    console.log(`  ✓ PASS: ${testName}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${testName}`);
    failed++;
  }
}

async function runTests() {
  const app = express();
  app.use(express.json({ limit: "5mb" }));
  app.use("/api", apiRouter);

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address() as any;
  const baseUrl = `http://localhost:${address.port}/api`;

  try {
    // Test 1: GET /api/health
    const healthRes = await fetch(`${baseUrl}/health`);
    const healthData = await healthRes.json();
    assert(healthRes.status === 200, "GET /api/health returns 200 OK");
    assert(healthData.status === "ok", "GET /api/health status is 'ok'");

    // Test 2: Validation on POST /api/investigate with empty body
    const badInvRes = await fetch(`${baseUrl}/investigate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert(badInvRes.status === 400, "POST /api/investigate with empty body returns 400 Bad Request");

    // Test 3: Validation on POST /api/phishing-analyzer with missing data
    const badPhishRes = await fetch(`${baseUrl}/phishing-analyzer`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert(badPhishRes.status === 400, "POST /api/phishing-analyzer with empty body returns 400 Bad Request");

    // Test 4: Validation on POST /api/generate-report with missing alert
    const badRptRes = await fetch(`${baseUrl}/generate-report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert(badRptRes.status === 400, "POST /api/generate-report with empty body returns 400 Bad Request");

    // Test 5: Validation on POST /api/ioc-enrich with invalid payload
    const badIocRes = await fetch(`${baseUrl}/ioc-enrich`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ iocs: "not-an-array" }),
    });
    assert(badIocRes.status === 400, "POST /api/ioc-enrich with invalid payload returns 400 Bad Request");
  } finally {
    server.close();
  }

  console.log(`\nAPI Integration Test Results: ${passed} passed, ${failed} failed.\n`);
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error("API test runner exception:", err);
  process.exit(1);
});
