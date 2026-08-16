import { parseRawLogs } from "../../src/services/logParser";

console.log("▶ [TEST SUITE] Running Log Parser Tests...");

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

// Test 1: Empty input
const emptyResult = parseRawLogs("", "TEST-HOST");
assert(emptyResult.length === 0, "Empty raw input returns empty array");

// Test 2: Windows Event Log format
const windowsRaw = `2026-08-16 03:14:22 EventID=4625 User=Administrator SourceIP=185.220.101.5 Host=DC-01 LogonType=3 Status=0xC000006D SubStatus=0xC000006A
2026-08-16 03:14:25 EventID=4624 User=Administrator SourceIP=185.220.101.5 Host=DC-01 LogonType=3 Status=0x0`;
const windowsEvents = parseRawLogs(windowsRaw, "DC-01");
assert(windowsEvents.length === 2, "Parsed 2 Windows event lines");
assert(windowsEvents[0].source_ip === "185.220.101.5", "Windows Event 1 extracted correct Source IP");
assert(windowsEvents[0].username === "Administrator", "Windows Event 1 extracted correct Username");
assert(windowsEvents[0].status === "FAILURE", "Windows Event 4625 marked as FAILURE");
assert(windowsEvents[1].status === "SUCCESS", "Windows Event 4624 marked as SUCCESS");

// Test 3: Linux Auth.log / Syslog format
const syslogRaw = `Aug 16 04:12:01 srv-linux-01 sshd[14221]: Failed password for invalid user admin from 192.168.1.105 port 55212 ssh2
Aug 16 04:12:05 srv-linux-01 sshd[14221]: Accepted password for root from 192.168.1.105 port 55212 ssh2`;
const syslogEvents = parseRawLogs(syslogRaw, "srv-linux-01");
assert(syslogEvents.length === 2, "Parsed 2 Syslog lines");
assert(syslogEvents[0].source_ip === "192.168.1.105", "Syslog extracted correct Source IP");
assert(syslogEvents[0].status === "FAILURE", "Syslog failed password marked as FAILURE");
assert(syslogEvents[1].status === "SUCCESS", "Syslog accepted password marked as SUCCESS");

// Test 4: Web Server Access Log (SQLi / Web Shell)
const webRaw = `185.220.101.5 - - [16/Aug/2026:03:30:10 +0000] "GET /login.php?id=1' UNION SELECT null,password FROM users-- HTTP/1.1" 200 4520`;
const webEvents = parseRawLogs(webRaw, "WEB-01");
assert(webEvents.length === 1, "Parsed 1 Web Access log line");
assert(webEvents[0].source_ip === "185.220.101.5", "Web log extracted correct client IP");
assert(webEvents[0].raw.includes("UNION SELECT"), "Web log retained SQL injection string");

console.log(`\nLog Parser Test Results: ${passed} passed, ${failed} failed.\n`);
if (failed > 0) process.exit(1);
