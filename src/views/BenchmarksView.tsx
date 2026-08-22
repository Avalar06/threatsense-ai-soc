import React, { useState, useEffect, useCallback } from "react";
import { useSoc } from "../context/SocContext";
import {
  Activity,
  Gauge,
  Play,
  CheckCircle2,
  AlertTriangle,
  Cpu,
  Zap,
  Shield,
  Layers,
  Database,
  BarChart3,
  RefreshCw,
  Clock,
  Download,
  FileText,
  FileSpreadsheet,
  FileCode,
  Info,
  ExternalLink,
  BookOpen,
  Terminal,
  ShieldCheck,
  AlertCircle
} from "lucide-react";
import type { BenchmarkResult, DatasetAdapterMetadata, BenchmarkExportFormat } from "../types/soc";
import { getBenchmarkAdapters, evaluateBenchmarkDataset, exportBenchmarkResult } from "../services/apiClient";

export const BenchmarksView: React.FC = () => {
  const { socMetrics, loadSocMetrics, runBenchmarkSuite } = useSoc();
  const [activeTab, setActiveTab] = useState<"internal" | "external">("internal");
  const [benchmarkResult, setBenchmarkResult] = useState<BenchmarkResult | null>(null);
  const [adapters, setAdapters] = useState<DatasetAdapterMetadata[]>([]);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedAdapter, setSelectedAdapter] = useState<DatasetAdapterMetadata | null>(null);

  const loadAdapters = useCallback(async () => {
    try {
      const data = await getBenchmarkAdapters();
      setAdapters(data);
    } catch (err: any) {
      console.error("Failed loading dataset adapters:", err);
    }
  }, []);

  useEffect(() => {
    loadSocMetrics();
    loadAdapters();
  }, [loadSocMetrics, loadAdapters]);

  const handleRunInternalValidation = async () => {
    setIsRunning(true);
    setError(null);
    try {
      const result = await runBenchmarkSuite();
      setBenchmarkResult(result);
      await loadSocMetrics();
    } catch (err: any) {
      setError(err.message || "Failed to execute internal validation suite.");
    } finally {
      setIsRunning(false);
    }
  };

  const handleRunExternalAdapter = async (adapter: DatasetAdapterMetadata) => {
    setIsRunning(true);
    setError(null);
    try {
      const result = await evaluateBenchmarkDataset({ adapterId: adapter.adapterId });
      setBenchmarkResult(result);
    } catch (err: any) {
      setError(err.message || `Adapter '${adapter.datasetName}' returned EXTERNAL_DATASET_NOT_AVAILABLE. Please supply raw dataset files per instructions.`);
    } finally {
      setIsRunning(false);
    }
  };

  const handleExport = async (format: BenchmarkExportFormat) => {
    if (!benchmarkResult) return;
    setIsExporting(true);
    try {
      const { blob, filename } = await exportBenchmarkResult(benchmarkResult, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err: any) {
      setError(`Failed exporting ${format.toUpperCase()} report: ${err.message}`);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 backdrop-blur border border-slate-800 p-6 rounded-xl shadow-lg">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <Gauge className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                SOC Observability & Benchmark Evaluation
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
                  Isolated Benchmark Harness
                </span>
              </h1>
              <p className="text-sm text-slate-400">
                Non-destructive detection and correlation benchmarking with strict separation between Internal Validation and External Datasets.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              loadSocMetrics();
              loadAdapters();
            }}
            className="p-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition border border-slate-700"
            title="Refresh Metrics & Adapters"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={handleRunInternalValidation}
            disabled={isRunning}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition shadow-md shadow-indigo-600/20 disabled:opacity-50"
          >
            <Play className={`w-4 h-4 ${isRunning ? "animate-spin" : ""}`} />
            {isRunning ? "Running Evaluation..." : "Execute Internal Validation"}
          </button>
        </div>
      </div>

      {/* Research Integrity Statement Banner */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-indigo-500/30 flex items-start gap-3">
        <ShieldCheck className="w-5 h-5 text-indigo-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 leading-relaxed">
          <strong className="text-indigo-300 uppercase tracking-wide block mb-0.5">Research Integrity Policy</strong>
          Benchmark results are computed exclusively from the supplied dataset ground truth and runtime evaluation results.
          ThreatSense does not generate synthetic benchmark samples or fabricate performance metrics.
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-500/30 text-rose-300 text-sm flex items-start gap-2">
          <AlertCircle className="w-5 h-5 shrink-0 mt-0.5 text-rose-400" />
          <div>{error}</div>
        </div>
      )}

      {/* Live Observability Telemetry Cards */}
      <div>
        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
          <Activity className="w-4 h-4 text-indigo-400" />
          Live SOC Operational Telemetry
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Ingestion */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-slate-400 text-xs">
              <span className="font-semibold uppercase">Event Ingestion</span>
              <Database className="w-4 h-4 text-indigo-400" />
            </div>
            <div className="text-2xl font-bold text-slate-100">
              {socMetrics?.ingestion.totalEvents ?? 0}
            </div>
            <div className="text-xs text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/60">
              <span>Avg Latency:</span>
              <span className="font-mono text-emerald-400">{socMetrics?.ingestion.avgLatencyMs ?? 0} ms</span>
            </div>
          </div>

          {/* Detections */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-slate-400 text-xs">
              <span className="font-semibold uppercase">Security Alerts</span>
              <Shield className="w-4 h-4 text-orange-400" />
            </div>
            <div className="text-2xl font-bold text-slate-100">
              {socMetrics?.detection.totalDetections ?? 0}
            </div>
            <div className="text-xs text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/60">
              <span>Detection Latency:</span>
              <span className="font-mono text-emerald-400">{socMetrics?.detection.avgLatencyMs ?? 0} ms</span>
            </div>
          </div>

          {/* Correlations */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-slate-400 text-xs">
              <span className="font-semibold uppercase">Multi-Stage Correlations</span>
              <Layers className="w-4 h-4 text-indigo-400" />
            </div>
            <div className="text-2xl font-bold text-slate-100">
              {socMetrics?.correlation.totalCorrelations ?? 0}
            </div>
            <div className="text-xs text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/60">
              <span>Correlation Latency:</span>
              <span className="font-mono text-emerald-400">{socMetrics?.correlation.avgLatencyMs ?? 0} ms</span>
            </div>
          </div>

          {/* SOAR */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-slate-400 text-xs">
              <span className="font-semibold uppercase">SOAR Executions</span>
              <Zap className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-slate-100">
              {socMetrics?.soar.totalExecutions ?? 0}
            </div>
            <div className="text-xs text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/60">
              <span>Pending Approvals:</span>
              <span className="font-mono font-bold text-amber-400">{socMetrics?.soar.pendingApprovals ?? 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs for Internal Validation vs External Datasets */}
      <div className="flex items-center gap-3 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab("internal")}
          className={`px-4 py-2 rounded-lg text-sm font-semibold transition ${
            activeTab === "internal"
              ? "bg-indigo-600/20 text-indigo-300 border border-indigo-500/40"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          Internal Validation Suite
        </button>
        <button
          onClick={() => setActiveTab("external")}
          className={`px-4 py-2 rounded-lg text-sm font-semibold transition flex items-center gap-2 ${
            activeTab === "external"
              ? "bg-indigo-600/20 text-indigo-300 border border-indigo-500/40"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          External Dataset Adapters (ADFA-LD, BGL, HDFS)
          <span className="text-[10px] px-2 py-0.5 rounded bg-amber-950/60 text-amber-400 border border-amber-800/40 font-mono">
            NOT LOADED
          </span>
        </button>
      </div>

      {/* Tab A: Internal Validation */}
      {activeTab === "internal" && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-indigo-400" />
              Internal Validation Evaluation Results
            </h2>
            {benchmarkResult && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-500 mr-2">Export Report:</span>
                <button
                  onClick={() => handleExport("json")}
                  disabled={isExporting}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700"
                >
                  <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                  JSON
                </button>
                <button
                  onClick={() => handleExport("csv")}
                  disabled={isExporting}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700"
                >
                  <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
                  CSV
                </button>
                <button
                  onClick={() => handleExport("markdown")}
                  disabled={isExporting}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700"
                >
                  <FileText className="w-3.5 h-3.5 text-indigo-400" />
                  Markdown
                </button>
              </div>
            )}
          </div>

          {benchmarkResult ? (
            <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 space-y-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 pb-4 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono bg-indigo-950/60 text-indigo-400 px-2 py-0.5 rounded border border-indigo-900/40">
                      {benchmarkResult.benchmarkId}
                    </span>
                    <span className="text-xs font-semibold px-2 py-0.5 rounded bg-blue-950/60 text-blue-400 border border-blue-900/40">
                      {benchmarkResult.evaluationType}
                    </span>
                    <span className="text-xs text-slate-400">Testbed: {benchmarkResult.datasetName} ({benchmarkResult.datasetVersion})</span>
                  </div>
                  <h3 className="text-base font-bold text-slate-100 mt-1">Internal Validation Performance Metrics</h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Notice: Evaluated against 10 internal labeled MITRE ATT&CK scenarios in an isolated in-memory SQLite database.
                  </p>
                </div>
                <div className="text-xs text-slate-500 font-mono">
                  Evaluated At: {new Date(benchmarkResult.measuredAt).toLocaleString()}
                </div>
              </div>

              {/* Metrics Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-xs text-slate-500">Internal Precision:</span>
                  <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">
                    {(benchmarkResult.precision * 100).toFixed(1)}%
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1">TP / (TP + FP)</p>
                </div>

                <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-xs text-slate-500">Internal Recall:</span>
                  <div className="text-2xl font-bold text-indigo-400 font-mono mt-1">
                    {(benchmarkResult.recall * 100).toFixed(1)}%
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1">TP / (TP + FN)</p>
                </div>

                <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-xs text-slate-500">Internal F1-Score:</span>
                  <div className="text-2xl font-bold text-amber-400 font-mono mt-1">
                    {benchmarkResult.f1Score.toFixed(3)}
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1">Harmonic mean of P & R</p>
                </div>

                <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-xs text-slate-500">Evaluation Throughput:</span>
                  <div className="text-2xl font-bold text-cyan-400 font-mono mt-1">
                    {benchmarkResult.throughputEventsPerSecond} <span className="text-xs text-slate-400">evt/s</span>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1">In-Memory Pipeline Rate</p>
                </div>
              </div>

              {/* Confusion Matrix & Latency percentiles */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-lg bg-slate-950/50 border border-slate-800/80 space-y-3">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase">Confusion Matrix Distribution</h4>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
                      <span className="text-slate-500 text-[10px]">True Positives (TP):</span>
                      <p className="text-emerald-400 font-bold text-sm">{benchmarkResult.truePositives}</p>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
                      <span className="text-slate-500 text-[10px]">False Positives (FP):</span>
                      <p className="text-rose-400 font-bold text-sm">{benchmarkResult.falsePositives}</p>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
                      <span className="text-slate-500 text-[10px]">True Negatives (TN):</span>
                      <p className="text-slate-300 font-bold text-sm">{benchmarkResult.trueNegatives}</p>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
                      <span className="text-slate-500 text-[10px]">False Negatives (FN):</span>
                      <p className="text-amber-400 font-bold text-sm">{benchmarkResult.falseNegatives}</p>
                    </div>
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-slate-950/50 border border-slate-800/80 space-y-3">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase">Latency Percentiles & Resource Delta</h4>
                  <div className="space-y-1.5 text-xs">
                    <div className="flex items-center justify-between p-1.5 bg-slate-900 rounded border border-slate-800">
                      <span className="text-slate-400">Mean Detection Latency:</span>
                      <span className="font-mono text-emerald-400 font-bold">{benchmarkResult.meanDetectionLatencyMs} ms</span>
                    </div>
                    <div className="flex items-center justify-between p-1.5 bg-slate-900 rounded border border-slate-800">
                      <span className="text-slate-400">Median (p50) Latency:</span>
                      <span className="font-mono text-emerald-400">{benchmarkResult.latencyDistribution.medianMs} ms</span>
                    </div>
                    <div className="flex items-center justify-between p-1.5 bg-slate-900 rounded border border-slate-800">
                      <span className="text-slate-400">95th Percentile (p95):</span>
                      <span className="font-mono text-cyan-400">{benchmarkResult.latencyDistribution.p95Ms} ms</span>
                    </div>
                    <div className="flex items-center justify-between p-1.5 bg-slate-900 rounded border border-slate-800">
                      <span className="text-slate-400">Mean Correlation Latency:</span>
                      <span className="font-mono text-indigo-400 font-bold">{benchmarkResult.meanCorrelationLatencyMs} ms</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Per-Class Breakdown Table */}
              {benchmarkResult.perClassMetrics && benchmarkResult.perClassMetrics.length > 0 && (
                <div className="p-4 rounded-lg bg-slate-950/50 border border-slate-800/80 space-y-3">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase">Per-Attack Class Breakdown</h4>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 font-semibold">
                          <th className="py-2 px-3">Attack Category / Technique</th>
                          <th className="py-2 px-3">Evaluated Samples</th>
                          <th className="py-2 px-3">True Positives</th>
                          <th className="py-2 px-3">False Negatives</th>
                          <th className="py-2 px-3">Detection Rate</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {benchmarkResult.perClassMetrics.map((item, idx) => (
                          <tr key={idx} className="hover:bg-slate-900/50">
                            <td className="py-2 px-3 font-medium text-slate-200">{item.attackClass}</td>
                            <td className="py-2 px-3 text-slate-400">{item.totalSamples}</td>
                            <td className="py-2 px-3 text-emerald-400 font-semibold">{item.truePositives}</td>
                            <td className="py-2 px-3 text-amber-400 font-semibold">{item.falseNegatives}</td>
                            <td className="py-2 px-3 font-mono text-indigo-400">
                              {(item.recall * 100).toFixed(1)}%
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Limitations Notice */}
              <div className="p-4 rounded-lg bg-slate-950/30 border border-slate-800/60 text-xs text-slate-400 space-y-1">
                <span className="font-semibold text-slate-300 uppercase text-[10px]">Methodological Limitations:</span>
                <ul className="list-disc pl-4 space-y-0.5 text-slate-500">
                  {benchmarkResult.limitations.map((lim, idx) => (
                    <li key={idx}>{lim}</li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center bg-slate-900/40 border border-slate-800 rounded-xl">
              <Cpu className="w-10 h-10 text-slate-600 mx-auto mb-3" />
              <h3 className="text-base font-medium text-slate-300">No Internal Validation Executed Yet</h3>
              <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
                Click "Execute Internal Validation" to evaluate precision, recall, latency, and throughput in an isolated in-memory test database.
              </p>
            </div>
          )}
        </div>
      )}

      {/* Tab B: External Dataset Adapters */}
      {activeTab === "external" && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Database className="w-4 h-4 text-indigo-400" />
              External Public Dataset Adapters & Ingestion Architecture
            </h2>
            <span className="text-xs px-2.5 py-1 rounded bg-amber-950/60 border border-amber-800/40 text-amber-400 font-mono">
              EXTERNAL_BENCHMARK_NOT_AVAILABLE
            </span>
          </div>

          <p className="text-xs text-slate-400">
            ThreatSense includes normalized adapters for major cybersecurity research datasets.
            To evaluate against public research datasets, acquire raw traces and trigger adapter evaluation.
          </p>

          {/* Adapter Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {adapters
              .filter((a) => a.adapterId !== "ADAPTER-INTERNAL-VAL")
              .map((adapter) => (
                <div
                  key={adapter.adapterId}
                  className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between space-y-4"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono uppercase bg-slate-800 text-slate-400 px-2 py-0.5 rounded">
                        {adapter.adapterId}
                      </span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-rose-950/60 text-rose-400 border border-rose-900/40 font-semibold">
                        {adapter.status}
                      </span>
                    </div>

                    <h3 className="text-sm font-bold text-slate-100">{adapter.datasetName}</h3>
                    <p className="text-xs text-slate-400">
                      <strong>Source:</strong> {adapter.officialSource}
                    </p>
                    <p className="text-xs text-slate-400">
                      <strong>License:</strong> {adapter.license || "Research Use"}
                    </p>
                    <p className="text-xs text-slate-400">
                      <strong>Label Schema:</strong> {adapter.labelSchema}
                    </p>
                  </div>

                  <div className="pt-3 border-t border-slate-800/80 space-y-2">
                    <button
                      onClick={() => setSelectedAdapter(adapter)}
                      className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition"
                    >
                      <BookOpen className="w-3.5 h-3.5 text-indigo-400" />
                      View Ingestion Instructions
                    </button>
                    <button
                      onClick={() => handleRunExternalAdapter(adapter)}
                      disabled={isRunning}
                      className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 text-xs font-semibold border border-indigo-500/30 transition disabled:opacity-50"
                    >
                      <Play className="w-3.5 h-3.5" />
                      Trigger Adapter Evaluation
                    </button>
                  </div>
                </div>
              ))}
          </div>

          {/* Selected Adapter Ingestion Modal / Detail Panel */}
          {selectedAdapter && (
            <div className="p-6 rounded-xl bg-slate-900 border border-indigo-500/40 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-indigo-400" />
                  <h3 className="text-sm font-bold text-slate-100">
                    Ingestion Guide: {selectedAdapter.datasetName} ({selectedAdapter.datasetVersion})
                  </h3>
                </div>
                <button
                  onClick={() => setSelectedAdapter(null)}
                  className="text-xs text-slate-400 hover:text-slate-200"
                >
                  Close
                </button>
              </div>

              <div className="space-y-3 text-xs text-slate-300">
                <div>
                  <span className="text-slate-500 font-semibold block uppercase text-[10px]">Official Reference:</span>
                  <a
                    href={selectedAdapter.referenceUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="text-indigo-400 hover:underline flex items-center gap-1 mt-0.5"
                  >
                    {selectedAdapter.referenceUrl}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>

                <div>
                  <span className="text-slate-500 font-semibold block uppercase text-[10px]">Expected File Format:</span>
                  <p className="font-mono bg-slate-950 p-2 rounded border border-slate-800 text-slate-300 mt-1">
                    {selectedAdapter.expectedFormat}
                  </p>
                </div>

                <div>
                  <span className="text-slate-500 font-semibold block uppercase text-[10px]">Step-by-Step Instructions:</span>
                  <p className="bg-slate-950/60 p-3 rounded border border-slate-800 text-slate-400 mt-1 leading-relaxed">
                    {selectedAdapter.ingestionInstructions}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
