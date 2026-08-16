import React from "react";
import { Severity } from "../../types/soc.js";

interface SeverityBadgeProps {
  severity: Severity;
  size?: "sm" | "md" | "lg";
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = "md" }) => {
  const styles: Record<Severity, { bg: string; text: string; border: string; dot: string }> = {
    CRITICAL: {
      bg: "bg-red-950/80",
      text: "text-red-300",
      border: "border-red-600/60",
      dot: "bg-red-500",
    },
    HIGH: {
      bg: "bg-orange-950/80",
      text: "text-orange-300",
      border: "border-orange-600/60",
      dot: "bg-orange-500",
    },
    MEDIUM: {
      bg: "bg-amber-950/80",
      text: "text-amber-300",
      border: "border-amber-600/60",
      dot: "bg-amber-500",
    },
    LOW: {
      bg: "bg-blue-950/80",
      text: "text-blue-300",
      border: "border-blue-600/60",
      dot: "bg-blue-400",
    },
    INFORMATIONAL: {
      bg: "bg-slate-900",
      text: "text-slate-300",
      border: "border-slate-700",
      dot: "bg-slate-400",
    },
  };

  const current = styles[severity] || styles.INFORMATIONAL;

  const sizeClasses = {
    sm: "px-1.5 py-0.5 text-xs font-mono tracking-wider",
    md: "px-2.5 py-1 text-xs font-semibold tracking-wider",
    lg: "px-3 py-1.5 text-sm font-semibold tracking-wider",
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border uppercase ${current.bg} ${current.text} ${current.border} ${sizeClasses[size]}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${current.dot} ${severity === "CRITICAL" ? "animate-ping" : ""}`} />
      {severity}
    </span>
  );
};
