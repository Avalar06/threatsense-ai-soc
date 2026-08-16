import { runDetectionEngine, calculateRiskScore } from "../../src/services/detectionEngine";
import { parseRawLogs } from "../../src/services/logParser";
import { SAMPLE_SCENARIOS } from "../../src/data/sampleLogs";

console.log("▶ [TEST SUITE] Running Detection Engine & Rule Matching Tests...");

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

// 1. Test Brute-Force & Lateral Movement Scenario
const bruteForceScenario = SAMPLE_SCENARIOS.find(s => s.id === "scenario-bruteforce-lateral") || SAMPLE_SCENARIOS[0];
const events1 = parseRawLogs(bruteForceScenario.rawLog, "DC-01");
const alerts1 = runDetectionEngine(events1);

assert(alerts1.length > 0, "Scenario 1 generated security alerts");
const bruteAlert = alerts1.find(a => a.ruleId.includes("BRUTE") || a.title.toLowerCase().includes("brute") || a.title.toLowerCase().includes("login") || a.title.toLowerCase().includes("powershell") || a.title.toLowerCase().includes("credential"));
assert(Boolean(bruteAlert), "Scenario 1 detected attack pattern alert");

// 2. Test Benign Traffic (Zero False Positives for Standard User Actions)
const benignRawLogs = `2026-08-16 09:00:00 EventID=4624 User=alice Host=WS-01 Status=SUCCESS
2026-08-16 09:05:00 EventID=4688 User=alice Host=WS-01 Process=outlook.exe
2026-08-16 09:10:00 EventID=4688 User=alice Host=WS-01 Process=chrome.exe
2026-08-16 11:30:00 EventID=4624 User=bob Host=WS-02 Status=SUCCESS`;
const benignEvents = parseRawLogs(benignRawLogs, "CORP-LAN");
const benignAlerts = runDetectionEngine(benignEvents);
assert(benignAlerts.length === 0, "Benign standard office workflow generates 0 false-positive alerts");

// 3. Test Risk Score Bounds (0 - 100)
for (const alert of alerts1) {
  assert(alert.riskScore >= 0 && alert.riskScore <= 100, `Alert [${alert.id}] risk score ${alert.riskScore} is within 0-100`);
}

// 4. Test Pass-the-Hash & Mimikatz Detection
const mimikatzRaw = `2026-08-16 03:15:00 EventID=4688 User=SYSTEM Host=DC-01 Process=mimikatz.exe CommandLine=sekurlsa::logonpasswords`;
const mimiEvents = parseRawLogs(mimikatzRaw, "DC-01");
const mimiAlerts = runDetectionEngine(mimiEvents);
const mimiAlert = mimiAlerts.find(a => a.title.toLowerCase().includes("credential") || a.title.toLowerCase().includes("mimikatz") || a.evidence.some(e => e.includes("mimikatz")));
assert(Boolean(mimiAlert), "Detected Mimikatz Credential Dumping activity");

console.log(`\nDetection Engine Test Results: ${passed} passed, ${failed} failed.\n`);
if (failed > 0) process.exit(1);
