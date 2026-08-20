import { apiRouter, setSocDatabase } from "../../server/apiRouter.js";
import { createDevApiApp } from "../../server/apiMiddleware.js";
import { SocDatabase } from "../../server/db/database.js";
import express from "express";
import http from "http";

console.log("▶ [TEST SUITE] Running Backend API Integration Tests...");

// Isolate test database in-memory
const testDb = new SocDatabase(":memory:");
setSocDatabase(testDb);

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
  app.use(express.json({ limit: "10mb" }));
  app.use("/api", apiRouter);

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address() as any;
  const baseUrl = `http://localhost:${address.port}/api`;

  try {
    // ----------------------------------------------------
    // 1. HEALTH & CORE GEMINI ENDPOINTS VALIDATION
    // ----------------------------------------------------
    const healthRes = await fetch(`${baseUrl}/health`);
    const healthData = await healthRes.json();
    assert(healthRes.status === 200, "GET /api/health returns 200 OK");
    assert(healthData.status === "ok", "GET /api/health status is 'ok'");

    const badInvRes = await fetch(`${baseUrl}/investigate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert(badInvRes.status === 400, "POST /api/investigate with empty body returns 400 Bad Request");

    const badPhishRes = await fetch(`${baseUrl}/phishing-analyzer`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert(badPhishRes.status === 400, "POST /api/phishing-analyzer with empty body returns 400 Bad Request");

    const badRptRes = await fetch(`${baseUrl}/generate-report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert(badRptRes.status === 400, "POST /api/generate-report with empty body returns 400 Bad Request");

    const badIocRes = await fetch(`${baseUrl}/ioc-enrich`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ iocs: "not-an-array" }),
    });
    assert(badIocRes.status === 400, "POST /api/ioc-enrich with invalid payload returns 400 Bad Request");

    // ----------------------------------------------------
    // 2. ALERTS REST API
    // ----------------------------------------------------
    // GET /api/alerts initially empty
    const initAlertsRes = await fetch(`${baseUrl}/alerts`);
    const initAlerts = await initAlertsRes.json();
    assert(initAlertsRes.status === 200, "GET /api/alerts returns 200 OK");
    assert(initAlerts.success === true, "GET /api/alerts returns success: true");
    assert(Array.isArray(initAlerts.data), "GET /api/alerts returns array in data");
    assert(typeof initAlerts.pagination?.total === "number", "GET /api/alerts returns pagination metadata");

    // POST /api/alerts - missing fields validation
    const badAlertRes = await fetch(`${baseUrl}/alerts`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "Incomplete Alert" }),
    });
    assert(badAlertRes.status === 400, "POST /api/alerts with missing required fields returns 400");

    // POST /api/alerts - valid creation
    const sampleAlert = {
      id: "ALT-TEST-001",
      title: "Suspicious PowerShell Base64 Execution",
      severity: "CRITICAL",
      riskScore: 88,
      status: "NEW",
      host: "FIN-SRV-01",
      sourceIp: "10.0.4.15",
      destinationIp: "198.51.100.44",
      username: "SYSTEM",
      detectionSource: "RULE_BASED",
      ruleId: "RULE-003",
      ruleName: "Suspicious PowerShell Execution",
      detectionConfidence: 95,
      description: "Encoded PowerShell command observed downloading payload",
      evidence: ["powershell.exe -enc SQBFAFgA"],
      relatedEventIds: ["EVT-P01"],
      mitreTechniques: [
        {
          id: "T1059.001",
          name: "Command and Scripting Interpreter: PowerShell",
          tactic: "Execution",
        },
      ],
      createdAt: new Date().toISOString(),
    };

    const createAlertRes = await fetch(`${baseUrl}/alerts`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(sampleAlert),
    });
    const createdAlertData = await createAlertRes.json();
    assert(createAlertRes.status === 201, "POST /api/alerts with valid payload returns 201 Created");
    assert(createdAlertData.data?.id === "ALT-TEST-001", "Created alert returns correct ID");

    // POST /api/alerts - duplicate ID conflict
    const dupAlertRes = await fetch(`${baseUrl}/alerts`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(sampleAlert),
    });
    assert(dupAlertRes.status === 409, "POST /api/alerts duplicate ID returns 409 Conflict");

    // Create a second alert for filtering and stats
    await fetch(`${baseUrl}/alerts`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: "ALT-TEST-002",
        title: "Brute Force SSH Attack",
        severity: "HIGH",
        riskScore: 75,
        status: "IN_PROGRESS",
        host: "WEB-PROXY-01",
        sourceIp: "203.0.113.88",
        username: "root",
        detectionSource: "RULE_BASED",
        ruleId: "RULE-001",
        detectionConfidence: 90,
        createdAt: new Date().toISOString(),
      }),
    });

    // GET /api/alerts/:id - retrieve existing
    const getAlertRes = await fetch(`${baseUrl}/alerts/ALT-TEST-001`);
    const getAlertData = await getAlertRes.json();
    assert(getAlertRes.status === 200, "GET /api/alerts/:id returns 200 OK");
    assert(getAlertData.data?.alert?.id === "ALT-TEST-001", "GET /api/alerts/:id returns target alert");
    assert(Array.isArray(getAlertData.data?.events), "GET /api/alerts/:id returns related events array");

    // GET /api/alerts/:id - missing alert returns 404
    const missingAlertRes = await fetch(`${baseUrl}/alerts/ALT-NONEXISTENT`);
    assert(missingAlertRes.status === 404, "GET /api/alerts/:id for non-existent alert returns 404 Not Found");

    // GET /api/alerts with filters
    const filterSevRes = await fetch(`${baseUrl}/alerts?severity=CRITICAL`);
    const filterSevData = await filterSevRes.json();
    assert(filterSevRes.status === 200, "GET /api/alerts?severity=CRITICAL returns 200");
    assert(filterSevData.data.length === 1 && filterSevData.data[0].id === "ALT-TEST-001", "Filtering alerts by severity returns matching records");

    const filterHostRes = await fetch(`${baseUrl}/alerts?host=WEB-PROXY`);
    const filterHostData = await filterHostRes.json();
    assert(filterHostData.data.length === 1 && filterHostData.data[0].id === "ALT-TEST-002", "Filtering alerts by host substring returns matching record");

    const searchAlertRes = await fetch(`${baseUrl}/alerts?search=PowerShell`);
    const searchAlertData = await searchAlertRes.json();
    assert(searchAlertData.data.length === 1 && searchAlertData.data[0].id === "ALT-TEST-001", "Searching alerts by keyword returns matching record");

    // PATCH /api/alerts/:id - updating analyst fields
    const patchAlertRes = await fetch(`${baseUrl}/alerts/ALT-TEST-001`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "RESOLVED",
        analystNotes: "Confirmed false alarm triggered during red team emulation.",
      }),
    });
    const patchAlertData = await patchAlertRes.json();
    assert(patchAlertRes.status === 200, "PATCH /api/alerts/:id returns 200 OK");
    assert(patchAlertData.data?.status === "RESOLVED", "PATCH /api/alerts/:id persists updated status");
    assert(patchAlertData.data?.notes?.includes("red team"), "PATCH /api/alerts/:id persists updated analyst notes");

    // PATCH /api/alerts/:id - missing returns 404
    const patchMissingRes = await fetch(`${baseUrl}/alerts/ALT-DOES-NOT-EXIST`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "CLOSED" }),
    });
    assert(patchMissingRes.status === 404, "PATCH /api/alerts/:id for non-existent alert returns 404");

    // ----------------------------------------------------
    // 3. SERVER-SIDE LOG INGESTION & PIPELINE
    // ----------------------------------------------------
    // Ingestion validation: empty payload
    const emptyIngestRes = await fetch(`${baseUrl}/logs/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert(emptyIngestRes.status === 400, "POST /api/logs/ingest with empty body returns 400 Bad Request");

    // Ingestion validation: non-string raw
    const badRawIngestRes = await fetch(`${baseUrl}/logs/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw: 12345 }),
    });
    assert(badRawIngestRes.status === 400, "POST /api/logs/ingest with non-string raw returns 400 Bad Request");

    // Ingestion test: Windows Security Event Log with Brute Force
    const windowsLogPayload = `
2026-08-20T04:12:01Z EventID=4625 Computer=DC-CORP-01 User=administrator src_ip=198.51.100.99 Status=0xC000006D SubStatus=0xC000006A Message="An account failed to log on"
2026-08-20T04:12:03Z EventID=4625 Computer=DC-CORP-01 User=administrator src_ip=198.51.100.99 Status=0xC000006D SubStatus=0xC000006A Message="An account failed to log on"
2026-08-20T04:12:05Z EventID=4625 Computer=DC-CORP-01 User=administrator src_ip=198.51.100.99 Status=0xC000006D SubStatus=0xC000006A Message="An account failed to log on"
2026-08-20T04:12:08Z EventID=4624 Computer=DC-CORP-01 User=administrator src_ip=198.51.100.99 LogonType=3 Message="An account was successfully logged on"
`;
    const winIngestRes = await fetch(`${baseUrl}/logs/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw: windowsLogPayload, source: "DC-CORP-01" }),
    });
    const winIngestData = await winIngestRes.json();
    assert(winIngestRes.status === 200, "POST /api/logs/ingest with Windows logs returns 200 OK");
    assert(winIngestData.data?.eventsIngested === 4, "Windows log ingestion parsed exactly 4 events");
    assert(winIngestData.data?.alertsGenerated >= 1, "Deterministic detection engine generated security alert(s)");

    // Ingestion test: Linux auth.log / Syslog with Mimikatz/Suspicious command
    const linuxSyslogPayload = `
Aug 20 04:30:10 srv-linux-01 sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 44322 ssh2
Aug 20 04:30:15 srv-linux-01 sudo: pam_unix(sudo:auth): authentication failure; logname=analyst uid=1000 euid=0 tty=/dev/pts/1 ruser=analyst rhost= user=root
Aug 20 04:30:20 srv-linux-01 bash[9999]: mimikatz sekurlsa::logonpasswords
`;
    const linuxIngestRes = await fetch(`${baseUrl}/logs/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw: linuxSyslogPayload, source: "srv-linux-01" }),
    });
    const linuxIngestData = await linuxIngestRes.json();
    assert(linuxIngestRes.status === 200, "POST /api/logs/ingest with Linux Syslog returns 200 OK");
    assert(linuxIngestData.data?.eventsIngested === 3, "Linux Syslog ingestion parsed exactly 3 events");
    assert(linuxIngestData.data?.alertsGenerated >= 1, "Detection engine detected Mimikatz/privilege alert");

    // Ingestion test: Web Access log with SQL injection
    const webLogPayload = `
198.51.100.77 - - [20/Aug/2026:04:45:00 +0000] "GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20admin HTTP/1.1" 200 4522
`;
    const webIngestRes = await fetch(`${baseUrl}/logs/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw: webLogPayload, source: "WEB-GATEWAY" }),
    });
    const webIngestData = await webIngestRes.json();
    assert(webIngestRes.status === 200, "POST /api/logs/ingest with Web access log returns 200 OK");
    assert(webIngestData.data?.eventsIngested === 1, "Web log parsed 1 event");

    // ----------------------------------------------------
    // 4. LOGS & SECURITY EVENTS REST API
    // ----------------------------------------------------
    const allLogsRes = await fetch(`${baseUrl}/logs`);
    const allLogsData = await allLogsRes.json();
    assert(allLogsRes.status === 200, "GET /api/logs returns 200 OK");
    assert(allLogsData.data.length >= 8, "GET /api/logs returns all ingested events");
    assert(allLogsData.pagination?.total >= 8, "GET /api/logs total matches count");

    // Filter logs by hostname
    const filterLogHostRes = await fetch(`${baseUrl}/logs?hostname=DC-CORP-01`);
    const filterLogHostData = await filterLogHostRes.json();
    assert(filterLogHostData.data.length === 4, "Filtering logs by hostname returns exact matching events");

    // Filter logs by source IP
    const filterLogIpRes = await fetch(`${baseUrl}/logs?sourceIp=198.51.100.99`);
    const filterLogIpData = await filterLogIpRes.json();
    assert(filterLogIpData.data.length === 4, "Filtering logs by source IP returns exact matching events");

    // ----------------------------------------------------
    // 5. DASHBOARD STATS API
    // ----------------------------------------------------
    const statsRes = await fetch(`${baseUrl}/dashboard/stats`);
    const statsData = await statsRes.json();
    assert(statsRes.status === 200, "GET /api/dashboard/stats returns 200 OK");
    assert(statsData.success === true, "GET /api/dashboard/stats returns success: true");
    assert(statsData.data?.totalAlerts >= 3, "Dashboard stats totalAlerts reflects persisted records");
    assert(typeof statsData.data?.criticalAlerts === "number", "Dashboard stats contains criticalAlerts count");
    assert(typeof statsData.data?.highAlerts === "number", "Dashboard stats contains highAlerts count");
    assert(statsData.data?.activeHosts >= 2, "Dashboard stats activeHosts reflects distinct hosts");
    assert(typeof statsData.data?.averageRiskScore === "number", "Dashboard stats contains calculated averageRiskScore");

    // ----------------------------------------------------
    // 6. INCIDENT REPORTS API
    // ----------------------------------------------------
    // Missing required fields on POST /api/reports
    const badReportRes = await fetch(`${baseUrl}/reports`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ executiveSummary: "No title or author" }),
    });
    assert(badReportRes.status === 400, "POST /api/reports with missing required fields returns 400");

    // Valid report creation
    const sampleReport = {
      id: "RPT-2026-001",
      incidentId: "INC-2026-001",
      reportTitle: "Security Incident Investigation - Host DC-CORP-01",
      author: "Lead SOC Analyst",
      status: "FINAL",
      classification: "CONFIDENTIAL",
      executiveSummary: "Credential stuffing campaign resulted in isolated login attempt.",
      incidentDescription: "Multiple Event 4625 followed by Event 4624.",
      detectionMethod: "RULE_BASED",
      affectedAssets: ["DC-CORP-01"],
      affectedUsers: ["administrator"],
      timeline: [],
      mitreMappings: [],
      riskAssessment: {
        quantitativeScore: 78,
        impactRating: "HIGH",
      },
      rootCauseAnalysis: "Stale administrator credentials exposed in external breach dump.",
      containmentActionsCompleted: ["Account password rotated", "MFA enforced"],
      eradicationAndRemediation: ["Source IP blocked at perimeter firewall"],
      lessonsLearnedAndPreventativeControls: ["Implement geofencing rules"],
      analystConclusion: "Threat successfully contained with zero data exfiltration.",
    };

    const createReportRes = await fetch(`${baseUrl}/reports`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(sampleReport),
    });
    const createReportData = await createReportRes.json();
    assert(createReportRes.status === 201, "POST /api/reports returns 201 Created");
    assert(createReportData.data?.id === "RPT-2026-001", "Report created with correct ID");

    // GET /api/reports
    const getReportsRes = await fetch(`${baseUrl}/reports`);
    const getReportsData = await getReportsRes.json();
    assert(getReportsRes.status === 200, "GET /api/reports returns 200 OK");
    assert(getReportsData.data.length >= 1, "GET /api/reports returns persisted reports");

    // ----------------------------------------------------
    // 7. INCIDENTS API FOUNDATION
    // ----------------------------------------------------
    const badIncRes = await fetch(`${baseUrl}/incidents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert(badIncRes.status === 400, "POST /api/incidents with missing fields returns 400");

    const sampleIncident = {
      id: "INC-2026-001",
      title: "Domain Controller Brute-Force Incident",
      severity: "CRITICAL",
      status: "OPEN",
      priority: "P1",
      leadAnalyst: "Alex Morgan",
      alertIds: ["ALT-TEST-001"],
      executiveSummary: "Active adversary probing DC credentials",
      containmentActions: ["Isolate host", "Revoke active session tokens"],
    };

    const createIncRes = await fetch(`${baseUrl}/incidents`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(sampleIncident),
    });
    const createIncData = await createIncRes.json();
    assert(createIncRes.status === 201, "POST /api/incidents returns 201 Created");
    assert(createIncData.data?.id === "INC-2026-001", "Incident created with correct ID");

    // GET /api/incidents
    const getIncListRes = await fetch(`${baseUrl}/incidents`);
    const getIncListData = await getIncListRes.json();
    assert(getIncListRes.status === 200, "GET /api/incidents returns 200 OK");
    assert(getIncListData.data.length >= 1, "GET /api/incidents returns incidents array");

    // GET /api/incidents/:id
    const getIncRes = await fetch(`${baseUrl}/incidents/INC-2026-001`);
    const getIncData = await getIncRes.json();
    assert(getIncRes.status === 200, "GET /api/incidents/:id returns 200 OK");
    assert(getIncData.data?.id === "INC-2026-001", "GET /api/incidents/:id returns target incident");

    // GET /api/incidents/:id - missing returns 404
    const getIncMissingRes = await fetch(`${baseUrl}/incidents/INC-NONEXISTENT`);
    assert(getIncMissingRes.status === 404, "GET /api/incidents/:id for missing incident returns 404");

    // PATCH /api/incidents/:id
    const patchIncRes = await fetch(`${baseUrl}/incidents/INC-2026-001`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: "CONTAINED",
        priority: "P1",
        leadAnalyst: "Sarah Connor",
      }),
    });
    const patchIncData = await patchIncRes.json();
    assert(patchIncRes.status === 200, "PATCH /api/incidents/:id returns 200 OK");
    assert(patchIncData.data?.status === "CONTAINED", "PATCH /api/incidents/:id updates status");
    assert(patchIncData.data?.leadAnalyst === "Sarah Connor", "PATCH /api/incidents/:id updates lead analyst");

    // PATCH /api/incidents/:id - missing returns 404
    const patchIncMissingRes = await fetch(`${baseUrl}/incidents/INC-DOES-NOT-EXIST`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "CLOSED" }),
    });
    assert(patchIncMissingRes.status === 404, "PATCH /api/incidents/:id for non-existent incident returns 404");

    // ----------------------------------------------------
    // 8. SECURITY & INJECTION RESILIENCE
    // ----------------------------------------------------
    // SQL Injection attempt in alert search parameter
    const sqlInjSearchRes = await fetch(`${baseUrl}/alerts?search=' OR '1'='1`);
    const sqlInjSearchData = await sqlInjSearchRes.json();
    assert(sqlInjSearchRes.status === 200, "SQL injection attempt in search parameter handled safely");
    assert(Array.isArray(sqlInjSearchData.data), "Search parameter returns structured array without crashing");

    // SQL Injection attempt in host filter parameter
    const sqlInjHostRes = await fetch(`${baseUrl}/alerts?host='; DROP TABLE alerts; --`);
    assert(sqlInjHostRes.status === 200, "SQL injection attempt in host filter handled safely");

    // Verify alerts table is still intact and operable
    const verifyTableRes = await fetch(`${baseUrl}/alerts`);
    assert(verifyTableRes.status === 200, "Alerts table was not dropped or compromised by SQL injection attempt");

    // Error response hygiene (no stack traces leaked)
    assert(
      !JSON.stringify(badAlertRes).includes("at ") && !JSON.stringify(badIncRes).includes("node:"),
      "Error responses return clean JSON without leaking server stack traces"
    );

    // ----------------------------------------------------
    // 9. DEV SERVER MIDDLEWARE & ROUTING REGRESSION TESTS
    // ----------------------------------------------------
    const devApp = createDevApiApp();
    const devServer = http.createServer(devApp);
    await new Promise<void>((resolve) => devServer.listen(0, resolve));
    const devAddress = devServer.address() as any;
    const devBaseUrl = `http://localhost:${devAddress.port}/api`;

    try {
      // Direct dev middleware test: GET /api/health returns 200 JSON
      const devHealthRes = await fetch(`${devBaseUrl}/health`);
      const devHealthData = await devHealthRes.json();
      assert(devHealthRes.status === 200, "Dev Middleware: GET /api/health returns 200 OK");
      assert(devHealthData.status === "ok", "Dev Middleware: GET /api/health returns JSON body");

      // Direct dev middleware test: GET /api/dashboard/stats returns 200 JSON
      const devStatsRes = await fetch(`${devBaseUrl}/dashboard/stats`);
      const devStatsData = await devStatsRes.json();
      assert(devStatsRes.status === 200, "Dev Middleware: GET /api/dashboard/stats returns 200 OK");
      assert(devStatsData.success === true, "Dev Middleware: GET /api/dashboard/stats returns success: true");
      assert(typeof devStatsData.data?.totalAlerts === "number", "Dev Middleware: GET /api/dashboard/stats returns totalAlerts");

      // Direct dev middleware test: GET /api/alerts returns 200 JSON
      const devAlertsRes = await fetch(`${devBaseUrl}/alerts`);
      const devAlertsData = await devAlertsRes.json();
      assert(devAlertsRes.status === 200, "Dev Middleware: GET /api/alerts returns 200 OK");
      assert(Array.isArray(devAlertsData.data), "Dev Middleware: GET /api/alerts returns array");

      // Direct dev middleware test: GET /api/logs returns 200 JSON
      const devLogsRes = await fetch(`${devBaseUrl}/logs`);
      const devLogsData = await devLogsRes.json();
      assert(devLogsRes.status === 200, "Dev Middleware: GET /api/logs returns 200 OK");
      assert(Array.isArray(devLogsData.data), "Dev Middleware: GET /api/logs returns array");

      // Direct dev middleware test: Unmatched /api route returns JSON 404 (not HTML)
      const devUnknownRes = await fetch(`${devBaseUrl}/non-existent-endpoint`);
      const devUnknownContentType = devUnknownRes.headers.get("content-type") || "";
      const devUnknownData = await devUnknownRes.json();
      assert(devUnknownRes.status === 404, "Dev Middleware: GET /api/non-existent-endpoint returns 404 Not Found");
      assert(devUnknownContentType.includes("application/json"), "Dev Middleware: Unmatched /api route returns application/json Content-Type");
      assert(devUnknownData.success === false, "Dev Middleware: Unmatched /api route returns success: false");
      assert(devUnknownData.error?.code === "NOT_FOUND", "Dev Middleware: Unmatched /api route returns error.code 'NOT_FOUND'");
    } finally {
      devServer.close();
    }

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
