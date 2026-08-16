import { extractIocsFromText, defangIoc } from "../../src/services/iocExtractor";

console.log("▶ [TEST SUITE] Running IOC Extractor & Defanging Tests...");

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

// Test 1: IPv4 Extraction and Defanging
const sampleIp = "Attacker connected from 185.220.101.5 to server 10.0.0.1";
const ipIocs = extractIocsFromText(sampleIp);
assert(ipIocs.length >= 1, "Extracted IP IOCs");
const pubIp = ipIocs.find(i => i.value === "185.220.101.5");
assert(Boolean(pubIp), "Found target public IP");
assert(pubIp?.defangedValue === "185[.]220[.]101[.]5", "IP defanging correctly replaced dots with [.]");

// Test 2: URL & Domain Extraction
const sampleUrl = "C2 Callback beaconing to http://evil-command-and-control.com/rat.php";
const urlIocs = extractIocsFromText(sampleUrl);
const foundUrl = urlIocs.find(i => i.type === "URL");
assert(Boolean(foundUrl), "Extracted URL");
assert(foundUrl?.defangedValue.startsWith("hxxp://"), "URL defanging replaced http:// with hxxp://");
assert(foundUrl?.defangedValue.includes("[.]"), "URL defanging defanged domain part");

// Test 3: SHA256 and MD5 File Hashes
const sampleHashes = "Dropper payload hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 and md5 5d41402abc4b2a76b9719d911017c592";
const hashIocs = extractIocsFromText(sampleHashes);
const sha256 = hashIocs.find(i => i.type === "HASH_SHA256");
const md5 = hashIocs.find(i => i.type === "HASH_MD5");
assert(Boolean(sha256), "Extracted SHA-256 hash");
assert(Boolean(md5), "Extracted MD5 hash");

// Test 4: Windows & Linux File Paths
const samplePaths = "Dropped artifact to C:\\Windows\\System32\\drivers\\evil.sys and /tmp/.stealth_miner";
const pathIocs = extractIocsFromText(samplePaths);
const winPath = pathIocs.find(i => i.type === "FILE_PATH" && i.value.includes("evil.sys"));
assert(Boolean(winPath), "Extracted Windows file path");

console.log(`\nIOC Extractor Test Results: ${passed} passed, ${failed} failed.\n`);
if (failed > 0) process.exit(1);
