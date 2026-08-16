import React from "react";
import { Alert, Severity } from "../../types/soc.js";
import { PieChart, Shield } from "lucide-react";

interface SeverityDistributionChartProps {
  alerts: Alert[];
}

export const SeverityDistributionChart: React.FC<SeverityDistributionChartProps> = ({ alerts }) => {
  const counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFORMATIONAL: 0,
  };

  alerts.forEach((a) => {
    if (counts[a.severity] !== undefined) {
      counts[a.severity] += 1;
    }
  });

  const total = alerts.length || 1;

  const severityConfigs: Array<{
    sev: Severity;
    label: string;
    color: string;
    bg: string;
    border: string;
  }> = [
    { sev: "CRITICAL", label: "Critical", color: "bg-red-500", bg: "bg-red-950/40", border: "border-red-600/50" },
    { sev: "HIGH", label: "High", color: "bg-orange-500", bg: "bg-orange-950/40", border: "border-orange-600/50" },
    { sev: "MEDIUM", label: "Medium", color: "bg-amber-500", bg: "bg-amber-950/40", border: "border-amber-600/50" },
    { sev: "LOW", label: "Low", color: "bg-blue-500", bg: "bg-blue-950/40", border: "border-blue-600/50" },
    { sev: "INFORMATIONAL", label: "Info", color: "bg-slate-500", bg: "bg-slate-900", border: "border-slate-700" },
  ];

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-indigo-950/70 border border-indigo-500/40 text-indigo-400">
              <PieChart className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-slate-100">Alert Severity Breakdown</h3>
              <p className="text-xs text-slate-400">Distribution across threat classification tiers</p>
            </div>
          </div>
          <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
            {alerts.length} Total Alerts
          </span>
        </div>

        {/* Horizontal Stacked Bar */}
        <div className="w-full h-3.5 bg-slate-950 rounded-full overflow-hidden flex border border-slate-800 mb-4">
          {severityConfigs.map((cfg) => {
            const count = counts[cfg.sev];
            const pct = (count / total) * 100;
            if (pct === 0) return null;
            return (
              <div
                key={cfg.sev}
                className={`${cfg.color} h-full transition-all duration-300`}
                style={{ width: `${pct}%` }}
                title={`${cfg.label}: ${count} (${Math.round(pct)}%)`}
              />
            );
          })}
        </div>

        {/* Severity List */}
        <div className="space-y-2">
          {severityConfigs.map((cfg) => {
            const count = counts[cfg.sev];
            const pct = Math.round((count / total) * 100);
            return (
              <div
                key={cfg.sev}
                className={`flex items-center justify-between p-2 rounded-lg border ${cfg.bg} ${cfg.border} text-xs`}
              >
                <div className="flex items-center gap-2">
                  <span className={`w-2.5 h-2.5 rounded-full ${cfg.color}`} />
                  <span className="font-semibold text-slate-200">{cfg.label}</span>
                </div>
                <div className="flex items-center gap-3 font-mono">
                  <span className="text-slate-400">{pct}%</span>
                  <span className="font-bold text-white px-2 py-0.5 rounded bg-slate-950/80 border border-slate-800">
                    {count}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="pt-3 mt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
        <span className="flex items-center gap-1">
          <Shield className="w-3.5 h-3.5 text-cyan-400" />
          Rule-based & AI Triaged
        </span>
        <span className="text-slate-400">
          Critical/High Ratio:{" "}
          <strong className="text-amber-400 font-mono">
            {Math.round(((counts.CRITICAL + counts.HIGH) / total) * 100)}%
          </strong>
        </span>
      </div>
    </div>
  );
};
