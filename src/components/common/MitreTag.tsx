import React, { useState } from "react";
import { MitreTechnique } from "../../types/soc.js";
import { ExternalLink, ShieldAlert } from "lucide-react";

interface MitreTagProps {
  technique: MitreTechnique;
  compact?: boolean;
}

export const MitreTag: React.FC<MitreTagProps> = ({ technique, compact = false }) => {
  const [showTooltip, setShowTooltip] = useState(false);

  return (
    <div className="relative inline-block">
      <button
        type="button"
        onClick={() => setShowTooltip(!showTooltip)}
        onMouseEnter={() => setShowTooltip(true)}
        onMouseLeave={() => setShowTooltip(false)}
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-indigo-950/60 border border-indigo-500/40 text-indigo-300 hover:bg-indigo-900/60 transition-colors text-xs font-mono"
      >
        <span className="font-bold text-indigo-200">{technique.id}</span>
        {!compact && <span className="text-slate-400 font-sans truncate max-w-[130px]">{technique.name}</span>}
      </button>

      {showTooltip && (
        <div className="absolute z-50 bottom-full left-0 mb-2 w-72 p-3 bg-slate-900 border border-indigo-500/50 rounded-lg shadow-xl shadow-black/80 text-left pointer-events-auto">
          <div className="flex items-center justify-between gap-2 mb-1.5 pb-1.5 border-b border-slate-800">
            <span className="font-mono font-bold text-xs text-indigo-400 flex items-center gap-1">
              <ShieldAlert className="w-3.5 h-3.5 text-indigo-400" />
              {technique.id}
            </span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-900/50 text-indigo-200 uppercase font-semibold">
              {technique.tactic}
            </span>
          </div>

          <h5 className="font-semibold text-xs text-slate-100 mb-1">{technique.name}</h5>
          <p className="text-[11px] text-slate-300 leading-relaxed mb-2">{technique.explanation}</p>

          <div className="flex items-center justify-between text-[10px] pt-1.5 border-t border-slate-800 text-slate-400">
            <span>Confidence: <strong className="text-cyan-400 font-mono">{technique.confidence}%</strong></span>
            <a
              href={`https://attack.mitre.org/techniques/${technique.id.replace(".", "/")}`}
              target="_blank"
              rel="noreferrer"
              className="text-indigo-400 hover:text-indigo-300 inline-flex items-center gap-0.5"
            >
              MITRE Docs <ExternalLink className="w-2.5 h-2.5" />
            </a>
          </div>
        </div>
      )}
    </div>
  );
};
