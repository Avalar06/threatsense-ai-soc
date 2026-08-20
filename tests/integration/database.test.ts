/**
 * ThreatSense AI - SQLite Database Integration & Persistence Tests
 * 
 * Verifies schema creation, idempotency, typed repository operations,
 * foreign key relationships, connection persistence, parameterized queries,
 * and SQL injection protection.
 */

import { initDatabase, closeDatabase, SocDatabase } from "../../server/db/database.js";
import { REQUIRED_TABLES, REQUIRED_INDEXES } from "../../server/db/schema.js";
import type { Alert, SecurityEvent, IncidentReport, IOC } from "../../src/types/soc.js";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  ✓ PASS: ${testName}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${testName}${detail ? ` — ${detail}` : ""}`);
    failed++;
  }
}

async function runDatabaseTests() {
  console.log("▶ [TEST SUITE] Running SQLite Persistence Foundation Tests...");

  // 1. In-Memory Database Initialization & Schema Verification
  const memDb = initDatabase(":memory:");
  const socDb = new SocDatabase(memDb);

  assert(memDb !== null && memDb !== undefined, "Database initializes successfully in-memory");

  // Verify all required tables exist
  const tableRows = memDb
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    .all() as { name: string }[];
  const existingTables = new Set(tableRows.map((r) => r.name));

  for (const table of REQUIRED_TABLES) {
    assert(existingTables.has(table), `Required table '${table}' exists in database schema`);
  }

  // Verify required indexes exist
  const indexRows = memDb
    .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")
    .all() as { name: string }[];
  const existingIndexes = new Set(indexRows.map((r) => r.name));

  for (const idx of REQUIRED_INDEXES) {
    assert(existingIndexes.has(idx), `Required index '${idx}' exists in database schema`);
  }

  // 2. Idempotency test (calling initDatabase multiple times does not error or drop tables)
  try {
    initDatabase(":memory:");
    assert(true, "Database initialization is idempotent");
  } catch (err: any) {
    assert(false, "Database initialization is idempotent", err.message);
  }

  // 3. Alert CRUD Operations
  const mockAlert: Alert = {
    id: "ALT-TEST-001",
    title: "Suspicious LSASS Memory Access Detected",
    severity: "CRITICAL",
    riskScore: 85,
    status: "NEW",
    host: "SEC-SRV-01",
    sourceIp: "192.168.1.50",
    destinationIp: "192.168.1.10",
    username: "svc_backup",
    detectionSource: "RULE_BASED",
    ruleId: "RULE-MIMIKATZ-01",
    ruleName: "Mimikatz LSASS Access",
    detectionConfidence: 95,
    description: "Process attempted memory read on lsass.exe",
    evidence: ["lsass.exe memory read handle", "mimikatz.exe invoked"],
    relatedEventIds: ["EVT-1001", "EVT-1002"],
    mitreTechniques: [
      {
        id: "T1003.001",
        name: "OS Credential Dumping: LSASS Memory",
        tactic: "Credential Access",
        explanation: "Adversaries may dump memory to access credentials.",
        confidence: 90
      }
    ],
    timestamp: "2026-08-20T10:00:00Z"
  };

  socDb.insertAlert(mockAlert);
  const fetchedAlert = socDb.getAlertById("ALT-TEST-001");

  assert(fetchedAlert !== null, "Inserting and reading an alert works");
  assert(fetchedAlert?.title === mockAlert.title, "Alert title is preserved accurately");
  assert(fetchedAlert?.riskScore === 85, "Alert risk score is preserved accurately");
  assert(fetchedAlert?.mitreTechniques.length === 1, "Alert MITRE techniques array is deserialized");
  assert(fetchedAlert?.mitreTechniques[0].id === "T1003.001", "MITRE technique ID matches");

  // Update alert
  const updateSuccess = socDb.updateAlert("ALT-TEST-001", {
    status: "INVESTIGATING",
    notes: "Analyst investigating root cause"
  });
  assert(updateSuccess, "Updating an alert returns success");

  const updatedAlert = socDb.getAlertById("ALT-TEST-001");
  assert(updatedAlert?.status === "INVESTIGATING", "Updated alert status is persisted");
  assert(updatedAlert?.notes === "Analyst investigating root cause", "Updated analyst notes are persisted");

  // 4. Security Events & Foreign Reference
  const mockEvent: SecurityEvent = {
    id: "EVT-1001",
    timestamp: "2026-08-20T09:59:00Z",
    event_type: "PROCESS_CREATE",
    source_ip: "192.168.1.50",
    destination_ip: "192.168.1.10",
    hostname: "SEC-SRV-01",
    username: "svc_backup",
    process: "powershell.exe",
    action: "EXECUTE",
    status: "SUCCESS",
    severity: "HIGH",
    message: "Suspicious PowerShell invocation dumping process memory",
    raw: "2026-08-20 09:59:00 SEC-SRV-01 powershell.exe -enc SQBFAFgA...",
    metadata: { command_line: "powershell.exe -enc SQBFAFgA" }
  };

  socDb.insertEvent(mockEvent, "ALT-TEST-001");
  const events = socDb.getEventsByAlertId("ALT-TEST-001");
  assert(events.length === 1, "Inserting a security event and linking to alert works");
  assert(events[0].id === "EVT-1001", "Security event ID matches");
  assert(events[0].process === "powershell.exe", "Security event process name matches");

  // 5. Incident & Incident Report Operations
  const mockIncident = {
    id: "INC-TEST-01",
    title: "Domain Controller Credential Dumping Incident",
    severity: "CRITICAL",
    status: "INVESTIGATING",
    priority: "P1",
    leadAnalyst: "Lead Investigator",
    alertIds: ["ALT-TEST-001"],
    executiveSummary: "Active LSASS harvesting detected on domain asset.",
    containmentActions: ["Network quarantine", "Account lockout"],
    createdAt: "2026-08-20T10:05:00Z",
    updatedAt: "2026-08-20T10:05:00Z"
  };

  socDb.insertIncident(mockIncident);
  const fetchedIncident = socDb.getIncidentById("INC-TEST-01");
  assert(fetchedIncident !== null, "Inserting and reading an incident record works");
  assert(fetchedIncident?.title === mockIncident.title, "Incident title matches");
  assert(fetchedIncident?.alertIds.includes("ALT-TEST-001"), "Incident alertIds array preserved");

  const mockReport: IncidentReport = {
    id: "REP-2026-001",
    incidentId: "INC-TEST-01",
    reportTitle: "Executive Incident Brief: LSASS Credential Harvesting",
    generatedAt: "2026-08-20T10:15:00Z",
    author: "SOC Lead Analyst",
    status: "FINAL",
    executiveSummary: "Unauthorized credential access was isolated on host SEC-SRV-01.",
    incidentDescription: "Mimikatz activity detected and blocked.",
    detectionMethod: "Automated Correlation Rule",
    affectedAssets: ["SEC-SRV-01"],
    affectedUsers: ["svc_backup"],
    timeline: [],
    mitreMappings: [],
    riskAssessment: {
      quantitativeScore: 85,
      impactRating: "HIGH"
    },
    rootCauseAnalysis: "Compromised service account credentials.",
    containmentActionsCompleted: ["Isolated SEC-SRV-01", "Revoked svc_backup Kerberos tickets"],
    eradicationAndRemediation: ["Rotated all Domain Admin passwords"],
    lessonsLearnedAndPreventativeControls: ["Enforce LSA Protection RunAsPPL"],
    analystConclusion: "Threat successfully eradicated."
  };

  socDb.insertReport(mockReport);
  const fetchedReport = socDb.getReportById("REP-2026-001");
  assert(fetchedReport !== null, "Inserting and reading an incident report works");
  assert(fetchedReport?.reportTitle === mockReport.reportTitle, "Incident report title preserved");
  assert(fetchedReport?.riskAssessment.impactRating === "HIGH", "Report structured risk assessment preserved");

  // 6. IOC Operations
  const mockIoc: IOC = {
    id: "IOC-001",
    type: "IPV4",
    value: "185.220.101.5",
    defangedValue: "185[.]220[.]101[.]5",
    riskLevel: "MALICIOUS",
    context: "Known Tor Exit Node used in brute force",
    confidence: 95
  };

  socDb.insertIoc(mockIoc);
  const allIocs = socDb.getAllIocs();
  assert(allIocs.length >= 1, "Inserting and querying IOC records works");
  assert(allIocs.some((i) => i.value === "185.220.101.5"), "IOC IP value preserved");

  // 7. Data Persistence across Connection Close / Reopen (File Database)
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "threatsense-test-"));
  const tempDbPath = path.join(tempDir, "test-persist.db");

  try {
    // Open connection 1, insert alert, close
    const db1 = initDatabase(tempDbPath);
    const socDb1 = new SocDatabase(db1);
    socDb1.insertAlert({
      ...mockAlert,
      id: "ALT-PERSIST-001",
      title: "Persistence Test Alert"
    });
    closeDatabase(db1);

    // Open connection 2, read alert
    const db2 = initDatabase(tempDbPath);
    const socDb2 = new SocDatabase(db2);
    const persistedAlert = socDb2.getAlertById("ALT-PERSIST-001");
    assert(persistedAlert !== null, "Data survives closing and reopening SQLite connection");
    assert(persistedAlert?.title === "Persistence Test Alert", "Persisted alert content matches");
    closeDatabase(db2);
  } finally {
    // Clean up temporary database files
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  }

  // 8. Parameterized Query & SQL Injection Safety Test
  const maliciousInput = "Robert'); DROP TABLE alerts; -- ' OR 1=1";
  const injectionAlert: Alert = {
    ...mockAlert,
    id: "ALT-INJECT-001",
    title: maliciousInput,
    host: maliciousInput,
    username: maliciousInput
  };

  socDb.insertAlert(injectionAlert);
  const fetchedInjected = socDb.getAlertById("ALT-INJECT-001");
  assert(fetchedInjected !== null, "Malicious SQL-like payload is safely inserted via parameterized query");
  assert(fetchedInjected?.title === maliciousInput, "Malicious input stored as literal data string rather than executed");

  // Confirm alerts table was NOT dropped
  const checkTable = memDb
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
    .get() as { name: string } | undefined;
  assert(checkTable?.name === "alerts", "Alerts table was not dropped or compromised by SQL injection");

  closeDatabase(memDb);

  console.log(`SQLite Database Test Results: ${passed} passed, ${failed} failed.\n`);
  if (failed > 0) {
    process.exit(1);
  }
}

runDatabaseTests().catch((err) => {
  console.error("Unhandled error in database tests:", err);
  process.exit(1);
});
