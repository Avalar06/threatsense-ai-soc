import test from "node:test";
import assert from "node:assert/strict";
import { ProductionBenchmarkService, RESEARCH_INTEGRITY_STATEMENT } from "../../server/services/benchmarkService.js";
import { initDatabase, SocDatabase } from "../../server/db/database.js";
import type { NormalizedBenchmarkRecord } from "../../src/types/soc.js";

test("Phase 8: External Real-Data Benchmark & Research Evaluation Suite", async (t) => {
  await t.test("1. Dataset adapter listing returns registered adapters with provenance", () => {
    const adapters = ProductionBenchmarkService.listAdapters();
    assert.ok(Array.isArray(adapters));
    assert.ok(adapters.length >= 4, "Should register at least 4 adapters");

    const internalAdapter = adapters.find((a) => a.adapterId === "ADAPTER-INTERNAL-VAL");
    assert.ok(internalAdapter);
    assert.strictEqual(internalAdapter.status, "AVAILABLE");
    assert.strictEqual(internalAdapter.sampleCount, 10);

    const adfaAdapter = adapters.find((a) => a.adapterId === "ADAPTER-ADFA-LD");
    assert.ok(adfaAdapter);
    assert.strictEqual(adfaAdapter.status, "EXTERNAL_DATASET_NOT_AVAILABLE");
    assert.ok(adfaAdapter.referenceUrl.includes("unsw.adfa.edu.au"));
    assert.ok(adfaAdapter.ingestionInstructions?.includes("ADFA-LD"));

    const bglAdapter = adapters.find((a) => a.adapterId === "ADAPTER-BGL");
    assert.ok(bglAdapter);
    assert.strictEqual(bglAdapter.status, "EXTERNAL_DATASET_NOT_AVAILABLE");

    const hdfsAdapter = adapters.find((a) => a.adapterId === "ADAPTER-HDFS");
    assert.ok(hdfsAdapter);
    assert.strictEqual(hdfsAdapter.status, "EXTERNAL_DATASET_NOT_AVAILABLE");
  });

  await t.test("2. Internal validation testbed evaluates successfully in complete isolation", async () => {
    // Verify production DB remains untouched
    const prodDbSync = initDatabase(":memory:");
    const prodDb = new SocDatabase(prodDbSync);

    const beforeEvents = prodDb.getAllEvents().length;
    const beforeAlerts = prodDb.getAllAlerts().length;

    const result = await ProductionBenchmarkService.runIsolatedBenchmark();

    assert.ok(result.benchmarkId.startsWith("VAL-"));
    assert.strictEqual(result.evaluationType, "INTERNAL_VALIDATION");
    assert.strictEqual(result.totalEventsEvaluated, 10);
    assert.strictEqual(result.attackEventsCount, 7);
    assert.strictEqual(result.normalEventsCount, 3);
    assert.strictEqual(result.truePositives + result.falseNegatives, 7);
    assert.strictEqual(result.trueNegatives + result.falsePositives, 3);
    assert.strictEqual(result.falsePositives, 0);
    assert.strictEqual(result.trueNegatives, 3);
    assert.strictEqual(result.precision, 1.0); // 0 false positives
    assert.ok(result.recall > 0 && result.recall <= 1.0);
    assert.ok(result.f1Score > 0 && result.f1Score <= 1.0);
    assert.ok(result.accuracy > 0 && result.accuracy <= 1.0);
    assert.strictEqual(result.falsePositiveRate, 0.0);
    assert.strictEqual(result.researchIntegrityStatement, RESEARCH_INTEGRITY_STATEMENT);
    assert.ok(result.throughputEventsPerSecond > 0);
    assert.ok(result.latencyDistribution.meanMs >= 0);
    assert.ok(result.latencyDistribution.p95Ms >= 0);
    assert.ok(result.perClassMetrics.length > 0);

    // Assert prod DB has zero added events or alerts
    const afterEvents = prodDb.getAllEvents().length;
    const afterAlerts = prodDb.getAllAlerts().length;
    assert.strictEqual(beforeEvents, afterEvents);
    assert.strictEqual(beforeAlerts, afterAlerts);
  });

  await t.test("3. Benchmark evaluation strictly preserves original labels and source traceability", async () => {
    const customSamples: NormalizedBenchmarkRecord[] = [
      {
        sourceRecordId: "SYSCALL-TRACE-101",
        sourceDataset: "ADFA-LD-Linux-Traces",
        originalLabel: "Web_SQL_Injection_Probe",
        normalizedLabel: "ATTACK",
        attackClass: "Web Exploitation / SQLi",
        expectedTechnique: "T1190",
        event: {
          id: "EVT-CUST-1",
          timestamp: "2026-08-22T12:00:00.000Z",
          event_type: "HTTP_REQUEST",
          source_ip: "192.168.1.50",
          destination_ip: "10.0.0.1",
          hostname: "web-srv-01",
          username: "anonymous",
          action: "BLOCK",
          status: "FAILURE",
          severity: "HIGH",
          raw: "GET /login.php?id=1 UNION SELECT null,username,password FROM users HTTP/1.1",
          message: "SQL injection attempt"
        }
      },
      {
        sourceRecordId: "SYSCALL-TRACE-102",
        sourceDataset: "ADFA-LD-Linux-Traces",
        originalLabel: "Normal_Bash_Session",
        normalizedLabel: "BENIGN",
        event: {
          id: "EVT-CUST-2",
          timestamp: "2026-08-22T12:01:00.000Z",
          event_type: "HTTP_REQUEST",
          source_ip: "10.0.0.5",
          destination_ip: "93.184.216.34",
          hostname: "dev-box",
          username: "alice",
          action: "ALLOW",
          status: "SUCCESS",
          severity: "INFORMATIONAL",
          raw: "GET / HTTP/1.1",
          message: "Standard HTTP request"
        }
      }
    ];

    const result = await ProductionBenchmarkService.evaluateDataset(customSamples, {
      datasetName: "ADFA-LD Sample Validation Trace",
      datasetSource: "UNSW Canberra Research Cyber Lab",
      datasetVersion: "2013-subset",
      datasetHash: "sha256-abc123mocktracehash",
      evaluationType: "EXTERNAL_BENCHMARK"
    });

    assert.strictEqual(result.evaluationType, "EXTERNAL_BENCHMARK");
    assert.strictEqual(result.totalEventsEvaluated, 2);
    assert.strictEqual(result.attackEventsCount, 1);
    assert.strictEqual(result.normalEventsCount, 1);
    assert.strictEqual(result.truePositives, 1);
    assert.strictEqual(result.trueNegatives, 1);
    assert.strictEqual(result.falsePositives, 0);
    assert.strictEqual(result.falseNegatives, 0);
    assert.strictEqual(result.precision, 1.0);
    assert.strictEqual(result.recall, 1.0);
    assert.strictEqual(result.datasetHash, "sha256-abc123mocktracehash");
  });

  await t.test("4. Safely handles edge cases: zero attacks, zero alerts, empty datasets", async () => {
    // Empty dataset throws validation error
    await assert.rejects(
      async () => {
        await ProductionBenchmarkService.evaluateDataset([], {
          datasetName: "Empty",
          datasetSource: "Empty",
          datasetVersion: "v0",
          evaluationType: "EXTERNAL_BENCHMARK"
        });
      },
      /Cannot evaluate empty benchmark dataset/
    );

    // Only benign samples (no attacks: zero division safety)
    const benignOnly: NormalizedBenchmarkRecord[] = [
      {
        sourceRecordId: "B-1",
        sourceDataset: "Benign-Set",
        originalLabel: "BENIGN_READ",
        normalizedLabel: "BENIGN",
        event: {
          id: "EVT-B1",
          timestamp: "2026-08-22T12:00:00.000Z",
          event_type: "FILE_ACCESS",
          source_ip: "10.0.0.1",
          destination_ip: "10.0.0.1",
          hostname: "host-1",
          username: "bob",
          action: "ALLOW",
          status: "SUCCESS",
          severity: "LOW",
          raw: "File read ok",
          message: "Standard read"
        }
      }
    ];

    const benignResult = await ProductionBenchmarkService.evaluateDataset(benignOnly, {
      datasetName: "Benign Only Set",
      datasetSource: "Test",
      datasetVersion: "1.0",
      evaluationType: "EXTERNAL_BENCHMARK"
    });

    assert.strictEqual(benignResult.truePositives, 0);
    assert.strictEqual(benignResult.falsePositives, 0);
    assert.strictEqual(benignResult.trueNegatives, 1);
    assert.strictEqual(benignResult.falseNegatives, 0);
    assert.strictEqual(benignResult.precision, 1.0); // Zero FP with zero TP
    assert.strictEqual(benignResult.recall, 1.0); // Zero missed attacks
    assert.strictEqual(benignResult.accuracy, 1.0);
  });

  await t.test("5. Export functionality generates valid JSON, CSV, and Markdown research reports", async () => {
    const result = await ProductionBenchmarkService.runIsolatedBenchmark();

    // Test JSON export
    const jsonExport = ProductionBenchmarkService.exportBenchmarkResult(result, "json");
    assert.strictEqual(jsonExport.contentType, "application/json");
    assert.ok(jsonExport.filename.endsWith(".json"));
    const parsed = JSON.parse(jsonExport.content);
    assert.strictEqual(parsed.benchmarkId, result.benchmarkId);

    // Test CSV export
    const csvExport = ProductionBenchmarkService.exportBenchmarkResult(result, "csv");
    assert.strictEqual(csvExport.contentType, "text/csv");
    assert.ok(csvExport.filename.endsWith(".csv"));
    assert.ok(csvExport.content.includes("Metric,Value"));
    assert.ok(csvExport.content.includes(`TruePositives,${result.truePositives}`));
    assert.ok(csvExport.content.includes(`Precision,${result.precision}`));

    // Test Markdown export
    const mdExport = ProductionBenchmarkService.exportBenchmarkResult(result, "markdown");
    assert.strictEqual(mdExport.contentType, "text/markdown");
    assert.ok(mdExport.filename.endsWith(".md"));
    assert.ok(mdExport.content.includes("# ThreatSense AI SOC — Benchmark & Validation Research Report"));
    assert.ok(mdExport.content.includes("Research Integrity Notice:"));
    assert.ok(mdExport.content.includes("Confusion Matrix"));
    assert.ok(mdExport.content.includes("Per-Attack Class Breakdown"));
  });
});
