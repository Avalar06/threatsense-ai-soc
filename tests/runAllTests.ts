import { execSync } from "child_process";

console.log("==================================================");
console.log("  AI-SOC INVESTIGATOR — AUTOMATED TEST RUNNER   ");
console.log("==================================================\n");

const tests = [
  "tests/unit/logParser.test.ts",
  "tests/unit/iocExtractor.test.ts",
  "tests/unit/detectionEngine.test.ts",
  "tests/integration/apiEndpoints.test.ts",
  "tests/integration/database.test.ts",
  "tests/integration/phase3Persistence.test.ts",
  "tests/integration/phase4Foundation.test.ts",
  "tests/integration/phase4IncidentWorkspace.test.ts"
];

let totalPassed = 0;
let totalFailed = 0;

for (const testFile of tests) {
  try {
    console.log(`Executing ${testFile}...`);
    execSync(`npx tsx ${testFile}`, { stdio: "inherit" });
    totalPassed++;
  } catch (error) {
    console.error(`❌ Test failed in ${testFile}`);
    totalFailed++;
  }
}

console.log("==================================================");
console.log(`TOTAL SUITES: ${tests.length} | PASSED: ${totalPassed} | FAILED: ${totalFailed}`);
console.log("==================================================");

if (totalFailed > 0) {
  process.exit(1);
} else {
  console.log("✅ ALL UNIT & INTEGRATION TEST SUITES PASSED!");
}
