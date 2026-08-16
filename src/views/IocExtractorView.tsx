import React, { useState, useMemo } from "react";
import { useSoc } from "../context/SocContext.js";
import {
  Fingerprint,
  Copy,
  Check,
  Search,
  Download,
  Filter,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Trash2,
  Share2,
} from "lucide-react";
import { extractIocsFromText } from "../services/iocExtractor.js";
import { IOC } from "../types/soc.js";

export const IocExtractorView: React.FC = () => {
  const { iocs } = useSoc();

  const [inputRaw, setInputRaw] = useState("");
  const [extractedItems, setExtractedItems] = useState<IOC[]>([]);
  const [selectedType, setSelectedType] = useState<string>("ALL");
  const [selectedRisk, setSelectedRisk] = useState<string>("ALL");
  const [search, setSearch] = useState("");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [bulkCopied, setBulkCopied] = useState<string | null>(null);

  // Combine store IOCs with any custom extracted in this view
  const allIocs = useMemo(() => {
    const combined = [...extractedItems, ...iocs];
    const uniqueMap = new Map<string, IOC>();
    combined.forEach((i) => {
      if (!uniqueMap.has(i.value)) {
        uniqueMap.set(i.value, i);
      }
    });
    return Array.from(uniqueMap.values());
  }, [extractedItems, iocs]);

  const handleExtract = () => {
    if (!inputRaw.trim()) return;
    const newIocs = extractIocsFromText(inputRaw);
    setExtractedItems(newIocs);
  };

  const handleCopySingle = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleCopyBulk = (format: "csv" | "json" | "defanged") => {
    if (format === "csv") {
      const header = "Type,Value,DefangedValue,RiskLevel,Confidence,Context\n";
      const rows = filteredIocs
        .map((i) => `"${i.type}","${i.value}","${i.defangedValue}","${i.riskLevel}",${i.confidence},"${i.context}"`)
        .join("\n");
      navigator.clipboard.writeText(header + rows);
      setBulkCopied("CSV");
    } else if (format === "json") {
      navigator.clipboard.writeText(JSON.stringify(filteredIocs, null, 2));
      setBulkCopied("JSON");
    } else {
      const list = filteredIocs.map((i) => i.defangedValue).join("\n");
      navigator.clipboard.writeText(list);
      setBulkCopied("Defanged List");
    }
    setTimeout(() => setBulkCopied(null), 2500);
  };

  // Filter logic
  const filteredIocs = useMemo(() => {
    return allIocs.filter((i) => {
      if (selectedType !== "ALL" && i.type !== selectedType) return false;
      if (selectedRisk !== "ALL" && i.riskLevel !== selectedRisk) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        return (
          i.value.toLowerCase().includes(q) ||
          i.defangedValue.toLowerCase().includes(q) ||
          i.context.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [allIocs, selectedType, selectedRisk, search]);

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto overflow-y-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-purple-950 border border-purple-700/60 text-purple-300 font-mono text-[11px] font-bold">
              THREAT ARTIFACTS & SIGNATURES
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Auto-Defanging Enabled
            </span>
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight mt-1">
            IOC Extractor & Defanger
          </h1>
          <p className="text-xs text-slate-400">
            Extract, categorize, sanitize (defang), and export Indicators of Compromise from raw log feeds or alert payloads.
          </p>
        </div>

        {/* Bulk Export Options */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => handleCopyBulk("defanged")}
            className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono transition-colors"
          >
            {bulkCopied === "Defanged List" ? "Copied!" : "Copy Defanged List"}
          </button>
          <button
            onClick={() => handleCopyBulk("csv")}
            className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono transition-colors"
          >
            {bulkCopied === "CSV" ? "Copied CSV!" : "Export CSV"}
          </button>
          <button
            onClick={() => handleCopyBulk("json")}
            className="px-3.5 py-1.5 rounded-lg bg-purple-950 hover:bg-purple-900 border border-purple-500/60 text-purple-200 text-xs font-mono transition-colors"
          >
            {bulkCopied === "JSON" ? "Copied JSON!" : "Export JSON"}
          </button>
        </div>
      </div>

      {/* Input Extraction Box */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-3">
        <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
          <Fingerprint className="w-4 h-4 text-purple-400" />
          Paste Telemetry / Payload for IOC Extraction
        </h3>

        <textarea
          rows={4}
          value={inputRaw}
          onChange={(e) => setInputRaw(e.target.value)}
          placeholder="Paste raw log lines, malicious PowerShell, email headers, or network traffic snippets...&#10;Example: Downloaded stage2 from http://evil-command-c2.top/payload.exe to C:\ProgramData\updater.exe and contacted 185.220.101.5:4444 (sha256: 8f9b4c2a1e7d3b5f9a8c7e6d5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a)"
          className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-purple-500 custom-scrollbar"
        />

        <div className="flex items-center justify-between">
          <span className="text-xs text-slate-400 font-mono">
            Supported: IPv4, IPv6, Domain, URL, SHA256, MD5, File Paths, Emails
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setInputRaw("");
                setExtractedItems([]);
              }}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono"
            >
              Clear
            </button>
            <button
              onClick={handleExtract}
              className="px-4 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs font-mono shadow-md transition-colors"
            >
              Extract & Defang
            </button>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3 flex-1">
          <div className="relative w-72">
            <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search IOCs, defanged values..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono"
            />
          </div>

          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-purple-500 font-mono"
          >
            <option value="ALL">All Types</option>
            <option value="IPV4">IPv4</option>
            <option value="DOMAIN">Domain</option>
            <option value="URL">URL</option>
            <option value="HASH_SHA256">SHA-256</option>
            <option value="HASH_MD5">MD5</option>
            <option value="FILE_PATH">File Path</option>
            <option value="EMAIL">Email</option>
          </select>

          <select
            value={selectedRisk}
            onChange={(e) => setSelectedRisk(e.target.value)}
            className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-purple-500 font-mono"
          >
            <option value="ALL">All Risk Levels</option>
            <option value="MALICIOUS">Malicious</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="BENIGN">Benign</option>
          </select>
        </div>

        <span className="text-xs text-slate-400 font-mono">
          Showing <strong className="text-white">{filteredIocs.length}</strong> indicators
        </span>
      </div>

      {/* IOC Grid Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase text-[11px] border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Defanged Value (Safe)</th>
                <th className="px-4 py-3">Original Raw Value</th>
                <th className="px-4 py-3">Risk Level</th>
                <th className="px-4 py-3">Confidence</th>
                <th className="px-4 py-3">Context / Artifact Type</th>
                <th className="px-4 py-3 text-right">Copy</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredIocs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-slate-500">
                    No Indicators of Compromise match current criteria.
                  </td>
                </tr>
              ) : (
                filteredIocs.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-slate-800/40 transition-colors">
                    {/* Type */}
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-purple-300 border border-purple-800/40 text-[10px]">
                        {ioc.type}
                      </span>
                    </td>

                    {/* Defanged Value */}
                    <td className="px-4 py-3 font-bold text-slate-100 select-all break-all max-w-sm">
                      {ioc.defangedValue}
                    </td>

                    {/* Raw Value */}
                    <td className="px-4 py-3 text-slate-400 select-all break-all max-w-xs text-[11px]">
                      {ioc.value}
                    </td>

                    {/* Risk Level */}
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          ioc.riskLevel === "MALICIOUS"
                            ? "bg-red-950 text-red-300 border border-red-700"
                            : ioc.riskLevel === "SUSPICIOUS"
                            ? "bg-amber-950 text-amber-300 border border-amber-700"
                            : "bg-emerald-950 text-emerald-300 border border-emerald-700"
                        }`}
                      >
                        {ioc.riskLevel}
                      </span>
                    </td>

                    {/* Confidence */}
                    <td className="px-4 py-3 text-cyan-400 font-bold">
                      {ioc.confidence}%
                    </td>

                    {/* Context */}
                    <td className="px-4 py-3 text-slate-300 font-sans text-[11px] max-w-xs truncate" title={ioc.context}>
                      {ioc.context}
                    </td>

                    {/* Copy action */}
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => handleCopySingle(ioc.defangedValue, ioc.id)}
                        className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                        title="Copy Defanged Value"
                      >
                        {copiedId === ioc.id ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
