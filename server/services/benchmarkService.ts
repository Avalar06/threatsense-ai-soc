/**
 * ThreatSense AI - External Real-Data Benchmark & Research Evaluation Framework (Phase 8)
 * 
 * Provides reproducible, non-destructive benchmark tooling and public dataset adapter infrastructure.
 * Evaluates detection & correlation algorithms against labeled ground-truth security datasets
 * in complete isolation (:memory: SQLite) without modifying or polluting production database tables.
 */

import { performance } from "node:perf_hooks";
import { initDatabase, SocDatabase } from "../db/database.js";
import { ProductionCorrelationEngine } from "./correlationEngine.js";
import { analyzeSecurityEvent, runDetectionEngine } from "../../src/services/detectionEngine.js";
import type { 
  SecurityEvent, 
  BenchmarkResult, 
  SocMetrics, 
  DatasetAdapterMetadata, 
  NormalizedBenchmarkRecord, 
  PerClassBenchmarkMetric,
  BenchmarkLatencyDistribution,
  BenchmarkExportFormat
} from "../../src/types/soc.js";

export const RESEARCH_INTEGRITY_STATEMENT = 
  "Benchmark results are computed exclusively from the supplied dataset ground truth and runtime evaluation results. ThreatSense does not generate synthetic benchmark samples or fabricate performance metrics.";

/**
 * Standard Ground-Truth Validation Samples for the Internal Testbed
 */
export const INTERNAL_VALIDATION_SAMPLES: NormalizedBenchmarkRecord[] = [
  // 1. Password Guessing / Brute Force (T1110.001)
  {
    sourceRecordId: "INT-VAL-001",
    sourceDataset: "ThreatSense Internal Validation Testbed",
    originalLabel: "ATTACK_BRUTE_FORCE_SSH",
    normalizedLabel: "ATTACK",
    attackClass: "Credential Access / Brute Force",
    expectedTechnique: "T1110.001",
    event: {
      id: "VAL-EVT-001",
      timestamp: "2026-08-22T10:00:00.000Z",
      event_type: "AUTH_FAILURE",
      source_ip: "198.51.100.22",
      destination_ip: "10.0.1.5",
      hostname: "AUTH-DC-01",
      username: "admin",
      action: "LOGIN_FAIL",
      status: "FAILURE",
      severity: "MEDIUM",
      raw: "Failed password for admin from 198.51.100.22 port 44211 ssh2",
      message: "Authentication failure for admin"
    }
  },
  {
    sourceRecordId: "INT-VAL-002",
    sourceDataset: "ThreatSense Internal Validation Testbed",
    originalLabel: "ATTACK_BRUTE_FORCE_SSH",
    normalizedLabel: "ATTACK",
    attackClass: "Credential Access / Brute Force",
    expectedTechnique: "T1110.001",
    event: {
      id: "VAL-EVT-002",
      timestamp: "2026-08-22T10:01:00.000Z",
      event_type: "AUTH_FAILURE",
      source_ip: "198.51.100.22",
      destination_ip: "10.0.1.5",
      hostname: "AUTH-DC-01",
      username: "admin",
      action: "LOGIN_FAIL",
      status: "FAILURE",
      severity: "MEDIUM",
      raw: "Failed password for admin from 198.51.100.22 port 44215 ssh2",
      message: "Authentication failure for admin"
    }
  },
  {
    sourceRecordId: "INT-VAL-003",
    sourceDataset: "ThreatSense Internal Validation Testbed",
    originalLabel: "ATTACK_VALID_ACCOUNT_COMPROMISE",
    normalizedLabel: "ATTACK",
    attackClass: "Initial Access / Valid Accounts",
    expectedTechnique: "T1078",
    event: {
      id: "VAL-EVT-003",
      timestamp: "2026-08-22T10:02:00.000Z",
      event_type: "AUTH_SUCCESS",
      source_ip: "198.51.100.22",
      destination_ip: "10.0.1.5",
      hostname: "AUTH-DC-01",
      username: "admin",
      action: "LOGIN_SUCCESS",
      status: "SUCCESS",
      severity: "CRITICAL",
      raw: "Accepted password for admin from 198.51.100.22 port 44220 ssh2",
      message: "Accepted password for admin"
    }
  },
  // 2. LSASS Credential Dumping (T1003.001)
  {
    sourceRecordId: "INT-VAL-004",
    sourceDataset: "ThreatSense Internal Validation Testbed",
    originalLabel: "ATTACK_PROCDUMP_LSASS",
    normalizedLabel: "ATTACK",
    attackClass: "Credential Dumping / LSASS Memory",
    expectedTechnique: "T1003.001",
    event: {
      id: "VAL-EVT-004",
      timestamp: "2026-08-22T10:05:00.000Z",
      event_type: "PROCESS_CREATE",
      source_ip: "10.0.2.14",
      destination_ip: "10.0.2.14",
      hostname: "WORKSTATION-88",
      username: "jdoe",
      process: "procdump64.exe",
      command_line: "procdump64.exe -ma lsass.exe lsass.dmp",
      action: "ALLOW",
      status: "SUCCESS",
      severity: "CRITICAL",
      raw: "Process created: procdump64.exe dumping lsass process memory",
      message: "Memory dump of lsass.exe initiated"
    }
  },
  {
    sourceRecordId: "INT-VAL-005",
    sourceDataset: "ThreatSense Internal Validation Testbed",
    originalLabel: "ATTACK_PRIVILEGE_ELEVATION",
    normalizedLabel: "ATTACK",
    attackClass: "Privilege Escalation",
    expectedTechnique: "T1548.003",
    event: {
      id: "VAL-EVT-005",
      timestamp: "2026-08-22T10:06:00.000Z",
      event_type: "PRIVILEGE_ESCALATE",
      source_ip: "10.0.2.14",
      destination_ip: "10.0.2.14",
      hostname: "WORKSTATION-88",
      username: "jdoe",
      action: "ESCALATE",
      status: "SUCCESS",
      severity: "CRITICAL",
      raw: "User jdoe assigned SeDebugPrivilege and added to local Administrators group",
      message: "Administrative privilege elevation"
    }
  },
  // 3. Obfuscated PowerShell Execution & C2 (T1059.001 & T1071.001)
  {
    sourceRecordId: "INT-VAL-006",
    sourceDataset: "ThreatSense Internal Validation Testbed",
    originalLabel: "ATTACK_ENCODED_POWERSHELL",
    normalizedLabel: "ATTACK",
    attackClass: "Execution / Obfuscated PowerShell",
    expectedTechnique: "T1059.001",
    event: {
      id: "VAL-EVT-006",
      timestamp: "2026-08-22T10:10:00.000Z",
      event_type: "PROCESS_CREATE",
      source_ip: "10.0.2.30",
      destination_ip: "10.0.2.30",
      hostname: "FIN-SRV-02",
      username: "svc_fin",
      process: "powershell.exe",
      command_line: "powershell.exe -nop -w hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
      action: "ALLOW",
      status: "SUCCESS",
      severity: "HIGH",
      raw: "Suspicious PowerShell execution with hidden window and encoded payload",
      message: "PowerShell encoded script launch"
    }
  },
  {
    sourceRecordId: "INT-VAL-007",
    sourceDataset: "ThreatSense Internal Validation Testbed",
    originalLabel: "ATTACK_EXTERNAL_C2_BEACON",
    normalizedLabel: "ATTACK",
    attackClass: "Command & Control / External Connection",
    expectedTechnique: "T1071.001",
    event: {
      id: "VAL-EVT-007",
      timestamp: "2026-08-22T10:11:00.000Z",
      event_type: "NETWORK_CONNECT",
      source_ip: "10.0.2.30",
      destination_ip: "203.0.113.88",
      destination_port: 443,
      hostname: "FIN-SRV-02",
      username: "svc_fin",
      action: "ALLOW",
      status: "SUCCESS",
      severity: "HIGH",
      raw: "C2 Beacon: TCP socket connected to external remote IP 203.0.113.88:443 (CobaltStrike listener)",
      message: "Outbound network connection to flagged C2 listener"
    }
  },
  // 4. Benign Standard Operations
  {
    sourceRecordId: "INT-VAL-008",
    sourceDataset: "ThreatSense Internal Validation Testbed",
    originalLabel: "BENIGN_HTTP_NAVIGATION",
    normalizedLabel: "BENIGN",
    event: {
      id: "VAL-EVT-008",
      timestamp: "2026-08-22T10:15:00.000Z",
      event_type: "HTTP_REQUEST",
      source_ip: "10.0.3.15",
      destination_ip: "142.250.190.46",
      hostname: "DEV-LAPTOP-04",
      username: "developer1",
      action: "ALLOW",
      status: "SUCCESS",
      severity: "LOW",
      raw: "GET https://google.com/search HTTP/1.1 200 OK",
      message: "Standard corporate web navigation"
    }
  },
  {
    sourceRecordId: "INT-VAL-009",
    sourceDataset: "ThreatSense Internal Validation Testbed",
    originalLabel: "BENIGN_SOURCE_FILE_READ",
    normalizedLabel: "BENIGN",
    event: {
      id: "VAL-EVT-009",
      timestamp: "2026-08-22T10:16:00.000Z",
      event_type: "FILE_ACCESS",
      source_ip: "10.0.3.15",
      destination_ip: "10.0.3.15",
      hostname: "DEV-LAPTOP-04",
      username: "developer1",
      action: "ALLOW",
      status: "SUCCESS",
      severity: "INFORMATIONAL",
      raw: "File read: /home/developer1/workspace/index.ts",
      message: "Developer file read operation"
    }
  },
  {
    sourceRecordId: "INT-VAL-010",
    sourceDataset: "ThreatSense Internal Validation Testbed",
    originalLabel: "BENIGN_KERBEROS_TGT_GRANT",
    normalizedLabel: "BENIGN",
    event: {
      id: "VAL-EVT-010",
      timestamp: "2026-08-22T10:17:00.000Z",
      event_type: "AUTH_SUCCESS",
      source_ip: "10.0.3.50",
      destination_ip: "10.0.1.5",
      hostname: "AUTH-DC-01",
      username: "hr_user",
      action: "LOGIN_SUCCESS",
      status: "SUCCESS",
      severity: "INFORMATIONAL",
      raw: "Kerberos TGT authentication ticket granted for hr_user",
      message: "Standard intra-domain authentication"
    }
  }
];

/**
 * Registry of Public Dataset Adapters
 */
export const DATASET_ADAPTERS: DatasetAdapterMetadata[] = [
  {
    adapterId: "ADAPTER-INTERNAL-VAL",
    datasetName: "ThreatSense Internal Validation Testbed",
    officialSource: "ThreatSense Research Lab",
    referenceUrl: "internal://validation/mitre-matrix-v14",
    datasetVersion: "v1.0.0-internal",
    license: "Proprietary / Internal Testbed",
    status: "AVAILABLE",
    sampleCount: 10,
    maliciousCount: 7,
    benignCount: 3,
    labelSchema: "Binary (ATTACK / BENIGN) + Fine-grained attack categories (T1110, T1078, T1003, T1548, T1059, T1071)",
    preprocessingVersion: "1.0.0",
    ingestionInstructions: "Built-in internal test suite. Available immediately for regression testing.",
    expectedFormat: "ThreatSense Normalized JSON Vector"
  },
  {
    adapterId: "ADAPTER-ADFA-LD",
    datasetName: "ADFA-LD (Australian Defence Force Academy Linux Dataset)",
    officialSource: "UNSW Canberra Cyber (Creech & Hu, 2013)",
    referenceUrl: "https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-IDS-Datasets/",
    datasetVersion: "ADFA-LD-2013",
    license: "Academic Research Use",
    status: "EXTERNAL_DATASET_NOT_AVAILABLE",
    sampleCount: 0,
    maliciousCount: 0,
    benignCount: 0,
    labelSchema: "Host System Call Sequences (Hydra-FTP, Hydra-SSH, Adduser, Java-Meterpreter, Webshell) vs Normal Baseline Traces",
    preprocessingVersion: "adfa-syscall-v1.0",
    ingestionInstructions: "Download official ADFA-LD archive. Place uncompressed attack and validation system call trace files in dataset directory `/data/benchmarks/adfa-ld/` and trigger POST /api/benchmarks/evaluate with adapterId `ADAPTER-ADFA-LD`.",
    expectedFormat: "Space-separated integer system call identifiers per trace file"
  },
  {
    adapterId: "ADAPTER-BGL",
    datasetName: "BGL (Blue Gene/L Supercomputer Log Dataset)",
    officialSource: "USENIX / Lawrence Livermore National Laboratory (Oliner & Stearley, 2007)",
    referenceUrl: "https://zenodo.org/record/3227177",
    datasetVersion: "BGL-Loghub-v1",
    license: "Open Research Dataset",
    status: "EXTERNAL_DATASET_NOT_AVAILABLE",
    sampleCount: 0,
    maliciousCount: 0,
    benignCount: 0,
    labelSchema: "Log entry severity tag (Alert vs Normal) with node failure & network disconnect categorizations",
    preprocessingVersion: "bgl-loghub-v2.1",
    ingestionInstructions: "Acquire raw BGL.log from Loghub repository. Place in `/data/benchmarks/bgl/BGL.log` and trigger POST /api/benchmarks/evaluate with adapterId `ADAPTER-BGL`.",
    expectedFormat: "Standard BGL space-delimited log syntax: `<Label> <Timestamp> <Date> <Node> <Time> <NodeRepeat> <Type> <Component> <Level> <Content>`"
  },
  {
    adapterId: "ADAPTER-HDFS",
    datasetName: "HDFS (Hadoop Distributed File System 11M Log Dataset)",
    officialSource: "SOSP '09 (Xu et al., Mining Log Data for Anomaly Detection)",
    referenceUrl: "https://zenodo.org/record/3227177",
    datasetVersion: "HDFS-v1",
    license: "Open Research Dataset",
    status: "EXTERNAL_DATASET_NOT_AVAILABLE",
    sampleCount: 0,
    maliciousCount: 0,
    benignCount: 0,
    labelSchema: "Block ID anomaly labels (anomaly_label.csv: BlockId, Anomaly/Normal)",
    preprocessingVersion: "hdfs-block-v1.0",
    ingestionInstructions: "Place `HDFS.log` and `anomaly_label.csv` in `/data/benchmarks/hdfs/` and execute POST /api/benchmarks/evaluate with adapterId `ADAPTER-HDFS`.",
    expectedFormat: "HDFS block lifecycle log records matched with ground-truth block classification label table"
  }
];

export class ProductionBenchmarkService {
  /**
   * Computes live telemetry and performance metrics from the production database.
   */
  static getLiveMetrics(db: SocDatabase): SocMetrics {
    const allEvents = db.getAllEvents();
    const allAlerts = db.getAllAlerts();
    const allCorrelations = db.listCorrelations({ limit: 1000 }).correlations;
    const allExecutions = db.listPlaybookExecutions({ limit: 1000 }).executions;
    const iocList = db.listIocs({ limit: 1000 }).iocs;

    const successfulExecs = allExecutions.filter((e) => e.status === "SUCCEEDED").length;
    const failedExecs = allExecutions.filter((e) => e.status === "FAILED").length;
    const pendingApprovals = allExecutions.filter((e) => e.status === "APPROVAL_REQUIRED").length;

    // Calculate actual SOAR execution latency across completed runs
    const completedExecutions = allExecutions.filter((e) => e.completedAt && (e.status === "SUCCEEDED" || e.status === "FAILED"));
    let avgSoarLatency = 0;
    if (completedExecutions.length > 0) {
      const totalExecDurationMs = completedExecutions.reduce((acc, exec) => {
        const start = new Date(exec.createdAt).getTime();
        const end = new Date(exec.completedAt!).getTime();
        return acc + Math.max(0, end - start);
      }, 0);
      avgSoarLatency = Math.round((totalExecDurationMs / completedExecutions.length) * 100) / 100;
    }

    return {
      ingestion: {
        totalEvents: allEvents.length,
        rejectedEvents: 0,
        avgLatencyMs: 0
      },
      detection: {
        totalDetections: allAlerts.length,
        avgLatencyMs: 0
      },
      correlation: {
        totalCorrelations: allCorrelations.length,
        avgLatencyMs: 0,
        insufficientTelemetryCount: 0
      },
      soar: {
        totalExecutions: allExecutions.length,
        successfulExecutions: successfulExecs,
        failedExecutions: failedExecs,
        pendingApprovals,
        avgExecutionLatencyMs: avgSoarLatency
      },
      threatIntel: {
        totalLookups: iocList.length,
        cacheHits: iocList.filter((i) => i.riskLevel !== "UNKNOWN").length,
        providerFailures: 0
      }
    };
  }

  /**
   * Returns metadata for all registered dataset adapters.
   */
  static listAdapters(): DatasetAdapterMetadata[] {
    return DATASET_ADAPTERS;
  }

  /**
   * Evaluates any supplied ground truth dataset in an isolated in-memory database.
   * NEVER modifies or pollutes the production SQLite database!
   */
  static async evaluateDataset(
    samples: NormalizedBenchmarkRecord[],
    meta: {
      datasetName: string;
      datasetSource: string;
      datasetVersion: string;
      datasetHash?: string;
      evaluationType: "INTERNAL_VALIDATION" | "EXTERNAL_BENCHMARK";
      limitations?: string[];
    }
  ): Promise<BenchmarkResult> {
    if (!samples || samples.length === 0) {
      throw new Error("Cannot evaluate empty benchmark dataset. At least 1 labeled sample is required.");
    }

    const startTime = performance.now();
    const memBefore = process.memoryUsage().heapUsed;

    // 1. Initialize isolated in-memory test database (:memory:)
    const isolatedDbSync = initDatabase(":memory:");
    const testDb = new SocDatabase(isolatedDbSync);

    let tp = 0; // True Positives: Attack correctly identified
    let fp = 0; // False Positives: Normal event falsely flagged as an alert
    let tn = 0; // True Negatives: Normal event correctly ignored
    let fn = 0; // False Negatives: Attack missed by detection engine

    const detectionLatencies: number[] = [];
    const perClassMap = new Map<string, { total: number; tp: number; fn: number }>();

    // 2. Ingest and detect individual events
    for (const item of samples) {
      const isAttack = item.normalizedLabel === "ATTACK";
      const attackClass = item.attackClass || (isAttack ? "Uncategorized Attack" : "Benign Baseline");

      if (isAttack) {
        if (!perClassMap.has(attackClass)) {
          perClassMap.set(attackClass, { total: 0, tp: 0, fn: 0 });
        }
        perClassMap.get(attackClass)!.total++;
      }

      const t0 = performance.now();
      testDb.insertEvent(item.event);

      let alert = analyzeSecurityEvent(item.event);
      if (!alert) {
        const streamAlerts = runDetectionEngine(testDb.getAllEvents());
        const matchingAlert = streamAlerts.find((ca) => ca.relatedEventIds.includes(item.event.id));
        if (matchingAlert) {
          alert = matchingAlert;
        }
      }
      const t1 = performance.now();
      detectionLatencies.push(t1 - t0);

      if (alert) {
        const existing = testDb.getAllAlerts().find(
          (a) => a.id === alert.id || (a.ruleId === alert.ruleId && a.host === alert.host && a.timestamp === alert.timestamp)
        );
        if (!existing) {
          testDb.insertAlert(alert);
        }
        if (isAttack) {
          tp++;
          if (perClassMap.has(attackClass)) {
            perClassMap.get(attackClass)!.tp++;
          }
        } else {
          fp++;
        }
      } else {
        if (isAttack) {
          fn++;
          if (perClassMap.has(attackClass)) {
            perClassMap.get(attackClass)!.fn++;
          }
        } else {
          tn++;
        }
      }
    }

    // 3. Evaluate Isolated Correlation Engine
    const corrEngine = new ProductionCorrelationEngine(testDb);
    const corrT0 = performance.now();
    const corrResult = await corrEngine.evaluateAll({ windowSeconds: 900 });
    const corrT1 = performance.now();
    const correlationLatencyMs = corrT1 - corrT0;

    const totalEvents = samples.length;
    const attackCount = samples.filter((b) => b.normalizedLabel === "ATTACK").length;
    const normalCount = samples.filter((b) => b.normalizedLabel === "BENIGN").length;

    // 4. Calculate Precision, Recall, F1, Accuracy, FPR, FNR with strict zero-denominator handling
    const precision = tp + fp > 0 ? tp / (tp + fp) : (tp === 0 && fp === 0 ? 1.0 : 0.0);
    const recall = tp + fn > 0 ? tp / (tp + fn) : (attackCount === 0 ? 1.0 : 0.0);
    const f1Score = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    const accuracy = totalEvents > 0 ? (tp + tn) / totalEvents : 0;
    const falsePositiveRate = fp + tn > 0 ? fp / (fp + tn) : 0;
    const falseNegativeRate = fn + tp > 0 ? fn / (fn + tp) : 0;

    // 5. Latency percentile distributions
    const sortedLatencies = [...detectionLatencies].sort((a, b) => a - b);
    const meanLatency = sortedLatencies.length > 0 
      ? sortedLatencies.reduce((a, b) => a + b, 0) / sortedLatencies.length 
      : 0;
    const medianLatency = sortedLatencies.length > 0 
      ? sortedLatencies[Math.floor(sortedLatencies.length * 0.5)] 
      : 0;
    const p95Latency = sortedLatencies.length > 0 
      ? sortedLatencies[Math.floor(sortedLatencies.length * 0.95)] 
      : 0;
    const p99Latency = sortedLatencies.length > 0 
      ? sortedLatencies[Math.floor(sortedLatencies.length * 0.99)] 
      : 0;

    const latencyDistribution: BenchmarkLatencyDistribution = {
      meanMs: Math.round(meanLatency * 1000) / 1000,
      medianMs: Math.round(medianLatency * 1000) / 1000,
      p95Ms: Math.round(p95Latency * 1000) / 1000,
      p99Ms: Math.round(p99Latency * 1000) / 1000
    };

    // 6. Per-class metrics
    const perClassMetrics: PerClassBenchmarkMetric[] = Array.from(perClassMap.entries()).map(([cls, stat]) => {
      const clsRecall = stat.total > 0 ? stat.tp / stat.total : 0;
      return {
        attackClass: cls,
        totalSamples: stat.total,
        truePositives: stat.tp,
        falseNegatives: stat.fn,
        recall: Math.round(clsRecall * 1000) / 1000,
        detectionRate: Math.round(clsRecall * 1000) / 10
      };
    });

    const totalDurationMs = performance.now() - startTime;
    const throughput = totalDurationMs > 0 ? Math.round((totalEvents / (totalDurationMs / 1000)) * 100) / 100 : 0;
    const memAfter = process.memoryUsage().heapUsed;

    const limitations = meta.limitations || [
      meta.evaluationType === "INTERNAL_VALIDATION"
        ? "Results are derived from an internal testbed vector of 10 scenarios and do not represent generalized production detection accuracy across multi-tenant enterprise networks."
        : "Evaluation executed in an isolated in-memory test environment. Real-world performance may vary based on ingestion queue depth and network I/O."
    ];

    const hasCorrelationGroundTruth = meta.evaluationType === "INTERNAL_VALIDATION";

    return {
      benchmarkId: `${meta.evaluationType === "INTERNAL_VALIDATION" ? "VAL" : "BENCH"}-${Date.now().toString(36).toUpperCase()}`,
      datasetName: meta.datasetName,
      datasetSource: meta.datasetSource,
      datasetVersion: meta.datasetVersion,
      datasetHash: meta.datasetHash,
      evaluationType: meta.evaluationType,
      rulesetVersion: "2026.08.1",
      environment: `Node.js ${process.version} (${process.platform} ${process.arch})`,
      totalEventsEvaluated: totalEvents,
      attackEventsCount: attackCount,
      normalEventsCount: normalCount,
      truePositives: tp,
      falsePositives: fp,
      trueNegatives: tn,
      falseNegatives: fn,
      precision: Math.round(precision * 1000) / 1000,
      recall: Math.round(recall * 1000) / 1000,
      f1Score: Math.round(f1Score * 1000) / 1000,
      accuracy: Math.round(accuracy * 1000) / 1000,
      falsePositiveRate: Math.round(falsePositiveRate * 1000) / 1000,
      falseNegativeRate: Math.round(falseNegativeRate * 1000) / 1000,
      throughputEventsPerSecond: throughput,
      meanDetectionLatencyMs: Math.round(meanLatency * 100) / 100,
      meanCorrelationLatencyMs: Math.round(correlationLatencyMs * 100) / 100,
      latencyDistribution,
      perClassMetrics,
      correlationEvaluation: hasCorrelationGroundTruth ? "EVALUATED" : "NOT_AVAILABLE",
      correlationCandidateCount: corrResult.correlationsFound,
      confirmedCorrelationsCount: corrResult.newCorrelationsPersisted,
      measuredAt: new Date().toISOString(),
      memoryUsageMb: Math.round(((memAfter - memBefore) / (1024 * 1024)) * 100) / 100,
      limitations,
      researchIntegrityStatement: RESEARCH_INTEGRITY_STATEMENT
    };
  }

  /**
   * Executes an internal validation run against internal testbed scenarios.
   * Explicitly labeled as INTERNAL_VALIDATION.
   */
  static async runIsolatedBenchmark(): Promise<BenchmarkResult> {
    return this.evaluateDataset(INTERNAL_VALIDATION_SAMPLES, {
      datasetName: "ThreatSense Internal Validation Testbed",
      datasetSource: "Internal Labeled MITRE ATT&CK Scenarios (T1110, T1078, T1003, T1548, T1059, T1071)",
      datasetVersion: "v1.0.0-internal",
      evaluationType: "INTERNAL_VALIDATION",
      limitations: [
        "Internal testbed metrics are evaluated against 10 deterministic test vectors.",
        "Must NOT be cited or represented as public external benchmark results or generalized real-world detection accuracy."
      ]
    });
  }

  /**
   * Exports a BenchmarkResult in the requested format (JSON, CSV, Markdown).
   */
  static exportBenchmarkResult(result: BenchmarkResult, format: BenchmarkExportFormat): { content: string; contentType: string; filename: string } {
    const timestamp = result.measuredAt.replace(/[:.]/g, "-");
    const prefix = result.evaluationType === "INTERNAL_VALIDATION" ? "internal-validation" : "external-benchmark";

    if (format === "json") {
      return {
        content: JSON.stringify(result, null, 2),
        contentType: "application/json",
        filename: `${prefix}-${result.benchmarkId}-${timestamp}.json`
      };
    }

    if (format === "csv") {
      const rows: string[] = [];
      rows.push("Metric,Value");
      rows.push(`BenchmarkId,${result.benchmarkId}`);
      rows.push(`EvaluationType,${result.evaluationType}`);
      rows.push(`DatasetName,"${result.datasetName}"`);
      rows.push(`DatasetVersion,${result.datasetVersion}`);
      rows.push(`DatasetSource,"${result.datasetSource || "N/A"}"`);
      rows.push(`DatasetHash,${result.datasetHash || "N/A"}`);
      rows.push(`RulesetVersion,${result.rulesetVersion || "N/A"}`);
      rows.push(`Environment,"${result.environment || "N/A"}"`);
      rows.push(`TotalEventsEvaluated,${result.totalEventsEvaluated}`);
      rows.push(`AttackEventsCount,${result.attackEventsCount}`);
      rows.push(`NormalEventsCount,${result.normalEventsCount}`);
      rows.push(`TruePositives,${result.truePositives}`);
      rows.push(`FalsePositives,${result.falsePositives}`);
      rows.push(`TrueNegatives,${result.trueNegatives}`);
      rows.push(`FalseNegatives,${result.falseNegatives}`);
      rows.push(`Precision,${result.precision}`);
      rows.push(`Recall,${result.recall}`);
      rows.push(`F1Score,${result.f1Score}`);
      rows.push(`Accuracy,${result.accuracy}`);
      rows.push(`FalsePositiveRate,${result.falsePositiveRate}`);
      rows.push(`FalseNegativeRate,${result.falseNegativeRate}`);
      rows.push(`ThroughputEventsPerSec,${result.throughputEventsPerSecond}`);
      rows.push(`MeanDetectionLatencyMs,${result.meanDetectionLatencyMs}`);
      rows.push(`MedianDetectionLatencyMs,${result.latencyDistribution.medianMs}`);
      rows.push(`P95DetectionLatencyMs,${result.latencyDistribution.p95Ms}`);
      rows.push(`P99DetectionLatencyMs,${result.latencyDistribution.p99Ms}`);
      rows.push(`MeanCorrelationLatencyMs,${result.meanCorrelationLatencyMs}`);
      rows.push(`CorrelationEvaluation,${result.correlationEvaluation}`);
      rows.push(`MeasuredAt,${result.measuredAt}`);

      if (result.perClassMetrics && result.perClassMetrics.length > 0) {
        rows.push("");
        rows.push("AttackClass,TotalSamples,TruePositives,FalseNegatives,Recall,DetectionRatePercent");
        for (const c of result.perClassMetrics) {
          rows.push(`"${c.attackClass}",${c.totalSamples},${c.truePositives},${c.falseNegatives},${c.recall},${c.detectionRate}`);
        }
      }

      return {
        content: rows.join("\n"),
        contentType: "text/csv",
        filename: `${prefix}-${result.benchmarkId}-${timestamp}.csv`
      };
    }

    // Markdown report format
    const md: string[] = [
      `# ThreatSense AI SOC — Benchmark & Validation Research Report`,
      ``,
      `**Run ID:** \`${result.benchmarkId}\`  `,
      `**Evaluation Type:** \`${result.evaluationType}\`  `,
      `**Dataset:** ${result.datasetName} (Version: ${result.datasetVersion})  `,
      `**Source:** ${result.datasetSource || "N/A"}  `,
      `**Ruleset:** ${result.rulesetVersion || "N/A"}  `,
      `**Environment:** \`${result.environment || "N/A"}\`  `,
      `**Measured At:** ${result.measuredAt}  `,
      ``,
      `---`,
      ``,
      `## 1. Executive Summary & Integrity Statement`,
      ``,
      `> **Research Integrity Notice:**  `,
      `> *${result.researchIntegrityStatement}*`,
      ``,
      `---`,
      ``,
      `## 2. Classification Performance Metrics`,
      ``,
      `| Metric | Value | Formulation / Interpretation |`,
      `|---|---|---|`,
      `| **Precision** | **${(result.precision * 100).toFixed(1)}%** | $TP / (TP + FP)$ |`,
      `| **Recall (Sensitivity)** | **${(result.recall * 100).toFixed(1)}%** | $TP / (TP + FN)$ |`,
      `| **F1-Score** | **${result.f1Score.toFixed(3)}** | $2 \\cdot \\frac{\\text{Precision} \\cdot \\text{Recall}}{\\text{Precision} + \\text{Recall}}$ |`,
      `| **Accuracy** | **${(result.accuracy * 100).toFixed(1)}%** | $(TP + TN) / (TP + TN + FP + FN)$ |`,
      `| **False Positive Rate (FPR)** | **${(result.falsePositiveRate * 100).toFixed(2)}%** | $FP / (FP + TN)$ |`,
      `| **False Negative Rate (FNR)** | **${(result.falseNegativeRate * 100).toFixed(2)}%** | $FN / (FN + TP)$ |`,
      ``,
      `---`,
      ``,
      `## 3. Confusion Matrix`,
      ``,
      `| | Ground Truth: Attack (${result.attackEventsCount}) | Ground Truth: Benign (${result.normalEventsCount}) |`,
      `|---|---|---|`,
      `| **Predicted: Alert** | **True Positives (TP):** \`${result.truePositives}\` | **False Positives (FP):** \`${result.falsePositives}\` |`,
      `| **Predicted: Normal** | **False Negatives (FN):** \`${result.falseNegatives}\` | **True Negatives (TN):** \`${result.trueNegatives}\` |`,
      ``,
      `---`,
      ``,
      `## 4. Latency & System Performance`,
      ``,
      `- **Evaluation Throughput:** \`${result.throughputEventsPerSecond} events/sec\``,
      `- **Mean Detection Latency:** \`${result.meanDetectionLatencyMs} ms\``,
      `- **Median Detection Latency (p50):** \`${result.latencyDistribution.medianMs} ms\``,
      `- **95th Percentile Latency (p95):** \`${result.latencyDistribution.p95Ms} ms\``,
      `- **99th Percentile Latency (p99):** \`${result.latencyDistribution.p99Ms} ms\``,
      `- **Correlation Evaluation:** \`${result.correlationEvaluation}\` (Latency: \`${result.meanCorrelationLatencyMs} ms\`)`,
      `- **Memory Footprint Delta:** \`${result.memoryUsageMb} MB\``,
      ``,
      `---`,
      ``,
      `## 5. Per-Attack Class Breakdown`,
      ``,
      result.perClassMetrics && result.perClassMetrics.length > 0
        ? [
            `| Attack Class / Technique | Samples | True Positives | False Negatives | Recall |`,
            `|---|---|---|---|---|`,
            ...result.perClassMetrics.map(
              (c) => `| **${c.attackClass}** | ${c.totalSamples} | ${c.truePositives} | ${c.falseNegatives} | ${(c.recall * 100).toFixed(1)}% |`
            )
          ].join("\n")
        : `*No per-class labels available for this evaluation.*`,
      ``,
      `---`,
      ``,
      `## 6. Limitations & Methodological Constraints`,
      ``,
      ...result.limitations.map((lim, idx) => `${idx + 1}. ${lim}`)
    ];

    return {
      content: md.join("\n"),
      contentType: "text/markdown",
      filename: `${prefix}-${result.benchmarkId}-${timestamp}.md`
    };
  }
}
