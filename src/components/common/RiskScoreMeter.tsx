import React from "react";

interface RiskScoreMeterProps {
  score: number; // 0 - 100
  detectionConfidence?: number; // 0 - 100
  aiConfidence?: number; // 0 - 100
  compact?: boolean;
}

export const RiskScoreMeter: React.FC<RiskScoreMeterProps> = ({
  score,
  detectionConfidence = 88,
  aiConfidence,
  compact = false,
}) => {
  const clampedScore = Math.min(100, Math.max(0, score));

  // Color logic
  let scoreColor = "text-emerald-400 border-emerald-500/50 bg-emerald-950/30";
  let barColor = "bg-emerald-500";
  let rating = "LOW";

  if (clampedScore >= 80) {
    scoreColor = "text-red-400 border-red-500/50 bg-red-950/30";
    barColor = "bg-red-500";
    rating = "CRITICAL";
  } else if (clampedScore >= 60) {
    scoreColor = "text-orange-400 border-orange-500/50 bg-orange-950/30";
    barColor = "bg-orange-500";
    rating = "HIGH";
  } else if (clampedScore >= 40) {
    scoreColor = "text-amber-400 border-amber-500/50 bg-amber-950/30";
    barColor = "bg-amber-500";
    rating = "MEDIUM";
  }

  if (compact) {
    return (
      <div className="flex items-center gap-2">
        <div className="w-16 h-2 bg-slate-800 rounded-full overflow-hidden border border-slate-700">
          <div className={`h-full ${barColor}`} style={{ width: `${clampedScore}%` }} />
        </div>
        <span className="font-mono font-bold text-xs text-slate-200">
          {clampedScore}
          <span className="text-slate-500 text-[10px]">/100</span>
        </span>
      </div>
    );
  }

  return (
    <div className="p-3.5 bg-slate-900/90 border border-slate-800 rounded-lg flex flex-col gap-2.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Risk Score</span>
          <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${scoreColor} font-bold`}>
            {rating}
          </span>
        </div>
        <div className="text-right">
          <span className="font-mono text-xl font-extrabold text-white tracking-tight">
            {clampedScore}
          </span>
          <span className="text-slate-400 text-xs font-mono">/100</span>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
        <div
          className={`h-full ${barColor} transition-all duration-500`}
          style={{ width: `${clampedScore}%` }}
        />
      </div>

      {/* Confidence Indicators */}
      <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-800/80 text-[11px]">
        <div className="flex flex-col">
          <span className="text-slate-400">Detection Conf:</span>
          <span className="font-mono font-semibold text-cyan-400">{detectionConfidence}%</span>
        </div>
        <div className="flex flex-col">
          <span className="text-slate-400">AI Confidence:</span>
          <span className="font-mono font-semibold text-purple-400">
            {aiConfidence !== undefined ? `${aiConfidence}%` : "Pending Eval"}
          </span>
        </div>
      </div>
    </div>
  );
};
