import React, { useState, useMemo } from "react";
import { useSoc } from "../context/SocContext.js";
import {
  FileCode2,
  UploadCloud,
  Play,
  Bot,
  Search,
  Filter,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  FileText,
  Terminal,
  Layers,
  ArrowRight,
  ShieldAlert,
} from "lucide-react";
import { SeverityBadge } from "../components/common/SeverityBadge.js";
import { SAMPLE_SCENARIOS } from "../data/sampleLogs.js";
import { SecurityEvent } from "../types/soc.js";

export const LogAnalyzerView: React.FC = () => {
  const { events, ingestLogs, loadScenario, setActiveTab, openInvestigationForAlert, alerts } = useSoc();

  const [rawText, setRawText] = useState("");
  const [selectedHost, setSelectedHost] = useState("FIN-SRV-01");
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState("ALL");
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [ingestionMessage, setIngestionMessage] = useState<string | null>(null);

  const handleIngest = () => {
    if (!rawText.trim()) return;
    ingestLogs(rawText, selectedHost);
    setIngestionMessage(`Successfully parsed & ingested events into memory.`);
    setTimeout(() => setIngestionMessage(null), 4000);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (evt) => {
      const content = evt.target?.result as string;
      if (content) {
        setRawText(content);
        ingestLogs(content, file.name.replace(/\.[^/.]+$/, ""));
        setIngestionMessage(`Uploaded and parsed '${file.name}' successfully.`);
        setTimeout(() => setIngestionMessage(null), 4000);
      }
    };
    reader.readAsText(file);
  };

  const handleCopyRaw = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  // Filter events
  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      if (filterType !== "ALL" && e.event_type !== filterType) return false;
      if (filterStatus !== "ALL" && e.status !== filterStatus) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        return (
          e.message.toLowerCase().includes(q) ||
          e.source_ip.toLowerCase().includes(q) ||
          e.username.toLowerCase().includes(q) ||
          e.hostname.toLowerCase().includes(q) ||
          e.raw.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [events, filterType, filterStatus, search]);

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto overflow-y-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-700/60 text-cyan-300 font-mono text-[11px] font-bold">
              LOG INGESTION & NORMALIZATION PIPELINE
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Schema: SOC-Event-V2 (Normalized)
            </span>
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight mt-1">
            Log Analyzer & Schema Normalizer
          </h1>
          <p className="text-xs text-slate-400">
            Ingest raw syslog, Windows Security Event Logs, Nginx/Apache logs, or CSVs. Automatically parses and maps to security entities.
          </p>
        </div>

        {/* Action Shortcuts */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setActiveTab("dashboard")}
            className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-semibold"
          >
            View Dashboard
          </button>
          <button
            onClick={() => setActiveTab("investigations")}
            className="px-3.5 py-1.5 rounded-lg bg-indigo-950 hover:bg-indigo-900 border border-indigo-500/50 text-indigo-200 text-xs font-semibold flex items-center gap-1.5"
          >
            <Bot className="w-3.5 h-3.5 text-indigo-400" />
            <span>Investigate Current Alerts ({alerts.length})</span>
          </button>
        </div>
      </div>

      {/* Ingestion & Sample Scenarios Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Input Textarea & Ingestion Box */}
        <div className="lg:col-span-2 bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
              <UploadCloud className="w-4 h-4 text-cyan-400" />
              Raw Log Ingestion Interface
            </h3>
            <div className="flex items-center gap-2">
              <label className="cursor-pointer px-3 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded-lg text-xs font-mono text-slate-200 transition-colors">
                <span>Upload .log / .txt / .csv</span>
                <input
                  type="file"
                  accept=".log,.txt,.csv,.json"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
            </div>
          </div>

          <textarea
            rows={6}
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder="Paste raw log lines here (Syslog, Windows Event XML/Key-value, Nginx access logs, or CSV)...&#10;Example:&#10;2026-08-16T03:10:02Z host=FIN-SRV-01 src_ip=185.220.101.5 user=admin process=sshd status=FAILURE msg=&quot;Failed password for invalid user admin&quot;"
            className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 custom-scrollbar"
          />

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-mono">Target Host:</span>
              <input
                type="text"
                value={selectedHost}
                onChange={(e) => setSelectedHost(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-xs font-mono text-slate-200 w-36"
              />
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setRawText("")}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono"
              >
                Clear
              </button>
              <button
                type="button"
                onClick={handleIngest}
                className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-bold text-xs shadow-md flex items-center gap-1.5 transition-all"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Parse & Run Detection Engine</span>
              </button>
            </div>
          </div>

          {ingestionMessage && (
            <div className="p-2.5 rounded-lg bg-emerald-950/70 border border-emerald-500/50 text-emerald-300 text-xs font-mono flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{ingestionMessage}</span>
            </div>
          )}
        </div>

        {/* Right: 1-Click Sample Scenarios */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-3">
          <div>
            <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2 mb-1">
              <Terminal className="w-4 h-4 text-purple-400" />
              Pre-Packaged Sample Log Scenarios
            </h3>
            <p className="text-xs text-slate-400 mb-3">
              Load realistic synthetic attack scenarios with 1-click for immediate SOC evaluation:
            </p>

            <div className="space-y-2">
              {SAMPLE_SCENARIOS.map((sc) => (
                <button
                  key={sc.id}
                  onClick={() => {
                    loadScenario(sc.id);
                    setRawText(sc.rawLog);
                  }}
                  className="w-full text-left p-2.5 rounded-lg bg-slate-950/80 hover:bg-slate-800/90 border border-slate-800 hover:border-cyan-500/50 transition-all group"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-slate-200 group-hover:text-cyan-300">
                      {sc.name}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                      {sc.category}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-1 mt-1 font-mono">
                    Threat: {sc.highlightedThreat}
                  </p>
                </button>
              ))}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span>Synthetic Dataset</span>
            <span className="font-mono text-cyan-400">{events.length} Normalized Events</span>
          </div>
        </div>
      </div>

      {/* Normalized Events Grid */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-lg space-y-0">
        {/* Table Filter Controls */}
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Parsed & Normalized Security Events Table
            </h3>
            <p className="text-xs text-slate-400">Standardized telemetry schema ready for detection rules and AI reasoning</p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Search */}
            <div className="relative w-64">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 transform -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search parsed fields, messages..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {/* Event Type Filter */}
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Event Types</option>
              <option value="AUTH_FAILURE">AUTH_FAILURE</option>
              <option value="AUTH_SUCCESS">AUTH_SUCCESS</option>
              <option value="PROCESS_CREATE">PROCESS_CREATE</option>
              <option value="PRIVILEGE_ESCALATE">PRIVILEGE_ESCALATE</option>
              <option value="NETWORK_CONNECT">NETWORK_CONNECT</option>
              <option value="HTTP_REQUEST">HTTP_REQUEST</option>
            </select>

            {/* Status Filter */}
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Statuses</option>
              <option value="FLAGGED">FLAGGED</option>
              <option value="ANOMALOUS">ANOMALOUS</option>
              <option value="FAILURE">FAILURE</option>
              <option value="SUCCESS">SUCCESS</option>
            </select>
          </div>
        </div>

        {/* Events Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase text-[11px] border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Source IP : Port</th>
                <th className="px-4 py-3">Dest IP : Port</th>
                <th className="px-4 py-3">Host / User</th>
                <th className="px-4 py-3">Process</th>
                <th className="px-4 py-3">Event Type</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Message & Evidence</th>
                <th className="px-4 py-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={9} className="text-center py-12 text-slate-500">
                    No events currently match the selected criteria.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((evt) => (
                  <tr
                    key={evt.id}
                    className="hover:bg-slate-800/50 transition-colors cursor-pointer"
                    onClick={() => setSelectedEvent(evt)}
                  >
                    {/* Timestamp */}
                    <td className="px-4 py-3 text-slate-400 whitespace-nowrap">
                      {evt.timestamp.replace("T", " ").replace("Z", "")}
                    </td>

                    {/* Source IP */}
                    <td className="px-4 py-3 text-cyan-300 whitespace-nowrap">
                      {evt.source_ip}
                      {evt.source_port ? `:${evt.source_port}` : ""}
                    </td>

                    {/* Dest IP */}
                    <td className="px-4 py-3 text-slate-300 whitespace-nowrap">
                      {evt.destination_ip}
                      {evt.destination_port ? `:${evt.destination_port}` : ""}
                    </td>

                    {/* Host & User */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="text-slate-200 font-bold">{evt.hostname}</span>
                      <span className="text-slate-400 block text-[10px]">@{evt.username}</span>
                    </td>

                    {/* Process */}
                    <td className="px-4 py-3 text-amber-300 whitespace-nowrap">
                      {evt.process || "system"}
                    </td>

                    {/* Event Type */}
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] border border-slate-700">
                        {evt.event_type}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          evt.status === "FLAGGED"
                            ? "bg-red-950 text-red-300 border border-red-700"
                            : evt.status === "ANOMALOUS"
                            ? "bg-purple-950 text-purple-300 border border-purple-700"
                            : evt.status === "FAILURE"
                            ? "bg-amber-950 text-amber-300 border border-amber-700"
                            : "bg-emerald-950 text-emerald-300 border border-emerald-700"
                        }`}
                      >
                        {evt.status}
                      </span>
                    </td>

                    {/* Message */}
                    <td className="px-4 py-3 max-w-xs truncate text-slate-200 font-sans" title={evt.message}>
                      {evt.message}
                    </td>

                    {/* Details action */}
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(evt);
                        }}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px]"
                      >
                        View Raw
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Raw Event Modal / Drawer */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
              <div className="flex items-center gap-2">
                <FileCode2 className="w-5 h-5 text-cyan-400" />
                <h4 className="font-bold text-sm text-slate-100 font-mono">
                  Normalized Event Inspector: {selectedEvent.id}
                </h4>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white text-lg font-bold px-2"
              >
                ✕
              </button>
            </div>

            <div className="p-5 space-y-4 overflow-y-auto custom-scrollbar text-xs">
              {/* Normalized Fields Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono">
                <div>
                  <span className="text-slate-500 block text-[10px]">Timestamp</span>
                  <span className="text-slate-200 font-bold">{selectedEvent.timestamp}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Source IP:Port</span>
                  <span className="text-cyan-400 font-bold">
                    {selectedEvent.source_ip}:{selectedEvent.source_port || "N/A"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Dest IP:Port</span>
                  <span className="text-slate-300 font-bold">
                    {selectedEvent.destination_ip}:{selectedEvent.destination_port || "N/A"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Target Host / User</span>
                  <span className="text-slate-200 font-bold">
                    {selectedEvent.hostname} ({selectedEvent.username})
                  </span>
                </div>
              </div>

              {/* Message */}
              <div>
                <span className="text-slate-400 font-mono block mb-1">Normalized Message:</span>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-100 font-mono">
                  {selectedEvent.message}
                </div>
              </div>

              {/* Raw Payload */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-slate-400 font-mono">Raw Log Record:</span>
                  <button
                    onClick={() => handleCopyRaw(selectedEvent.raw)}
                    className="flex items-center gap-1 text-[11px] font-mono text-cyan-400 hover:text-cyan-300"
                  >
                    {copiedRaw ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedRaw ? "Copied" : "Copy Raw Payload"}</span>
                  </button>
                </div>
                <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-cyan-300 font-mono text-[11px] whitespace-pre-wrap break-all select-all">
                  {selectedEvent.raw}
                </pre>
              </div>
            </div>

            <div className="p-4 border-t border-slate-800 bg-slate-950 flex items-center justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
