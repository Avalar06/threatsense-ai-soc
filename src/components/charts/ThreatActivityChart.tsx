import React, { useState } from "react";
import { SecurityEvent } from "../../types/soc.js";
import { Activity, ShieldAlert, Zap } from "lucide-react";

interface ThreatActivityChartProps {
  events: SecurityEvent[];
}

export const ThreatActivityChart: React.FC<ThreatActivityChartProps> = ({ events }) => {
  const [hoveredPoint, setHoveredPoint] = useState<{
    timeLabel: string;
    totalCount: number;
    failureCount: number;
    anomalousCount: number;
    x: number;
    y: number;
  } | null>(null);

  // Generate 12 time buckets across the dataset
  const buckets = React.useMemo(() => {
    if (events.length === 0) {
      return Array.from({ length: 12 }, (_, i) => ({
        timeLabel: `${String(i * 2).padStart(2, "0")}:00`,
        totalCount: Math.floor(Math.sin(i / 2) * 5) + 8,
        failureCount: i % 3 === 0 ? 3 : 1,
        anomalousCount: i === 6 || i === 7 ? 4 : 0,
      }));
    }

    // Group events into 12 buckets
    const bucketCount = 12;
    const bucketData = Array.from({ length: bucketCount }, (_, i) => ({
      timeLabel: `T-${(bucketCount - i) * 5}m`,
      totalCount: 0,
      failureCount: 0,
      anomalousCount: 0,
    }));

    events.forEach((evt, idx) => {
      const bIdx = idx % bucketCount;
      bucketData[bIdx].totalCount += 1;
      if (evt.status === "FAILURE") bucketData[bIdx].failureCount += 1;
      if (evt.status === "FLAGGED" || evt.status === "ANOMALOUS" || evt.severity === "CRITICAL") {
        bucketData[bIdx].anomalousCount += 1;
      }
    });

    return bucketData;
  }, [events]);

  const maxVal = Math.max(...buckets.map((b) => b.totalCount), 5);
  const chartHeight = 160;
  const chartWidth = 560;
  const paddingX = 40;
  const paddingY = 25;

  const points = buckets.map((b, i) => {
    const x = paddingX + (i / (buckets.length - 1)) * (chartWidth - paddingX * 2);
    const y = chartHeight - paddingY - (b.totalCount / maxVal) * (chartHeight - paddingY * 2);
    const yAnom = chartHeight - paddingY - (b.anomalousCount / maxVal) * (chartHeight - paddingY * 2);
    return { ...b, x, y, yAnom };
  });

  const pathD = points.reduce((acc, p, i) => `${acc} ${i === 0 ? "M" : "L"} ${p.x},${p.y}`, "");
  const areaD = `${pathD} L ${points[points.length - 1].x},${chartHeight - paddingY} L ${points[0].x},${chartHeight - paddingY} Z`;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 relative overflow-hidden flex flex-col justify-between">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-950/70 border border-cyan-500/40 text-cyan-400">
            <Activity className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
              Threat Activity & Event Volume
              <span className="text-[11px] px-2 py-0.5 rounded-full bg-cyan-950 border border-cyan-800/60 text-cyan-300 font-mono">
                LIVE TELEMETRY
              </span>
            </h3>
            <p className="text-xs text-slate-400">Time-series distribution of ingested events and flagged anomalies</p>
          </div>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
            <span className="text-slate-300">Total Volume</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
            <span className="text-slate-300">Anomalies / Spikes</span>
          </div>
        </div>
      </div>

      {/* SVG Chart */}
      <div className="relative w-full h-[170px]">
        <svg viewBox={`0 0 ${chartWidth} ${chartHeight}`} className="w-full h-full overflow-visible">
          <defs>
            <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
            </linearGradient>
            <linearGradient id="anomGlow" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#ef4444" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          {[0.25, 0.5, 0.75, 1].map((ratio, idx) => {
            const y = chartHeight - paddingY - ratio * (chartHeight - paddingY * 2);
            return (
              <line
                key={idx}
                x1={paddingX}
                y1={y}
                x2={chartWidth - paddingX}
                y2={y}
                stroke="#1e293b"
                strokeDasharray="3 3"
                strokeWidth="1"
              />
            );
          })}

          {/* Area fill */}
          <path d={areaD} fill="url(#areaGradient)" />

          {/* Line stroke */}
          <path d={pathD} fill="none" stroke="#06b6d4" strokeWidth="2.5" strokeLinecap="round" />

          {/* Data Points & Anomalies */}
          {points.map((p, i) => {
            const hasAnomaly = p.anomalousCount > 0;
            return (
              <g key={i} className="cursor-pointer">
                {hasAnomaly && (
                  <circle
                    cx={p.x}
                    cy={p.y}
                    r="8"
                    className="fill-red-500/20 stroke-red-500 animate-pulse"
                    strokeWidth="1.5"
                  />
                )}
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={hasAnomaly ? "5" : "3.5"}
                  fill={hasAnomaly ? "#ef4444" : "#06b6d4"}
                  stroke="#0f172a"
                  strokeWidth="2"
                  onMouseEnter={() => setHoveredPoint(p)}
                  onMouseLeave={() => setHoveredPoint(null)}
                />
              </g>
            );
          })}

          {/* X Axis Labels */}
          {points.filter((_, i) => i % 2 === 0).map((p, i) => (
            <text
              key={i}
              x={p.x}
              y={chartHeight - 6}
              textAnchor="middle"
              className="fill-slate-500 text-[10px] font-mono select-none"
            >
              {p.timeLabel}
            </text>
          ))}
        </svg>

        {/* Hover Tooltip */}
        {hoveredPoint && (
          <div
            className="absolute z-30 pointer-events-none transform -translate-x-1/2 -translate-y-full mb-2 bg-slate-950 border border-cyan-500/60 rounded-lg p-2 shadow-xl shadow-black text-left text-xs font-mono"
            style={{
              left: `${(hoveredPoint.x / chartWidth) * 100}%`,
              top: `${(hoveredPoint.y / chartHeight) * 100}%`,
            }}
          >
            <div className="text-cyan-300 font-bold border-b border-slate-800 pb-1 mb-1">
              Time: {hoveredPoint.timeLabel}
            </div>
            <div className="text-slate-300">Total Events: <strong className="text-white">{hoveredPoint.totalCount}</strong></div>
            <div className="text-amber-400">Failed Logons: <strong>{hoveredPoint.failureCount}</strong></div>
            {hoveredPoint.anomalousCount > 0 && (
              <div className="text-red-400 font-bold flex items-center gap-1 mt-0.5">
                <Zap className="w-3 h-3 text-red-400" />
                {hoveredPoint.anomalousCount} Anomalous Flags
              </div>
            )}
          </div>
        )}
      </div>

      {/* Summary Footer */}
      <div className="grid grid-cols-3 gap-3 pt-3 mt-2 border-t border-slate-800 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-slate-400">Total Ingested:</span>
          <span className="font-mono font-bold text-white">{events.length}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-slate-400">Peak Rate:</span>
          <span className="font-mono font-bold text-cyan-400">{maxVal} eps</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-slate-400">Threat Flags:</span>
          <span className="font-mono font-bold text-red-400">
            {events.filter((e) => e.status === "FLAGGED" || e.severity === "CRITICAL").length}
          </span>
        </div>
      </div>
    </div>
  );
};
