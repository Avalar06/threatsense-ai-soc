import React, { useState } from "react";
import {
  MailWarning,
  Send,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Shield,
  Bot,
  RefreshCw,
  Copy,
  Check,
  ShieldAlert,
  HelpCircle,
} from "lucide-react";
import { analyzePhishingEmail } from "../services/apiClient.js";
import { PhishingAnalysisResult } from "../types/soc.js";

const SAMPLE_PHISHING_EMAIL = `From: "Microsoft 365 Security Support" <admin-security-notification@microsoft-security-verify.com>
To: victim.executive@corp-finance.internal
Reply-To: security-reply@secureserver-notice-m365.com
Subject: URGENT: Mandatory Multi-Factor Authentication Reset Required Within 2 Hours
Date: Sat, 16 Aug 2026 03:00:15 +0000
Authentication-Results: spf=softfail (sender IP 194.26.29.112 is not permitted); dkim=neutral (no key for domain); dmarc=fail action=none header.from=microsoft-security-verify.com

Dear Valued Employee,

Your Microsoft 365 Enterprise workspace password and security tokens have expired due to recent policy updates. Failure to re-verify your identity within 2 hours will result in immediate suspension of corporate email access and ERP system lockout.

Please immediately verify your corporate Active Directory credentials by accessing the secure gateway below:
http://login.microsoftonline.portal-auth-verification-check.com/login.php?ref=fin_corp

Regards,
Microsoft Cloud Security Operations Team
Global IT Infrastructure Services`;

export const PhishingAnalyzerView: React.FC = () => {
  const [rawEmail, setRawEmail] = useState(SAMPLE_PHISHING_EMAIL);
  const [sender, setSender] = useState("admin-security-notification@microsoft-security-verify.com");
  const [subject, setSubject] = useState("URGENT: Mandatory Multi-Factor Authentication Reset Required Within 2 Hours");
  const [replyTo, setReplyTo] = useState("security-reply@secureserver-notice-m365.com");
  const [headers, setHeaders] = useState("Authentication-Results: spf=softfail; dkim=neutral; dmarc=fail");
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState<PhishingAnalysisResult | null>(null);
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);

  const handleAnalyze = async () => {
    setLoading(true);
    try {
      const result = await analyzePhishingEmail({
        rawEmail,
        sender,
        subject,
        replyTo,
        headers,
      });
      setAnalysis(result);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedUrl(text);
    setTimeout(() => setCopiedUrl(null), 2000);
  };

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto overflow-y-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-amber-950 border border-amber-700/60 text-amber-300 font-mono text-[11px] font-bold">
              EMAIL THREAT ANALYSIS MODULE
            </span>
            <span className="text-xs text-slate-400 font-mono">
              SPF / DKIM / DMARC & Homograph Detection
            </span>
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight mt-1">
            Phishing & Social Engineering Analyzer
          </h1>
          <p className="text-xs text-slate-400">
            Inspect email headers, authenticate DNS records, detect brand impersonation, and defang embedded URLs using Gemini reasoning.
          </p>
        </div>

        <button
          onClick={() => {
            setRawEmail(SAMPLE_PHISHING_EMAIL);
            setSender("admin-security-notification@microsoft-security-verify.com");
            setSubject("URGENT: Mandatory Multi-Factor Authentication Reset Required Within 2 Hours");
            setReplyTo("security-reply@secureserver-notice-m365.com");
            setHeaders("Authentication-Results: spf=softfail; dkim=neutral; dmarc=fail");
          }}
          className="px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono"
        >
          Reload Sample Email
        </button>
      </div>

      {/* Input Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Email Header / Body Input */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-bold text-sm text-slate-100 flex items-center gap-2">
              <MailWarning className="w-4 h-4 text-amber-400" />
              Raw Email Payload / RFC 822 Headers
            </h3>
            <span className="text-[11px] font-mono text-slate-400">RFC 822 / MIME</span>
          </div>

          <textarea
            rows={10}
            value={rawEmail}
            onChange={(e) => setRawEmail(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-amber-500 custom-scrollbar"
          />

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
            <div>
              <span className="text-slate-400 block text-[10px]">Claimed Sender Address</span>
              <input
                type="text"
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 mt-1"
              />
            </div>
            <div>
              <span className="text-slate-400 block text-[10px]">Reply-To Header</span>
              <input
                type="text"
                value={replyTo}
                onChange={(e) => setReplyTo(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 mt-1"
              />
            </div>
          </div>

          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="w-full py-2.5 rounded-lg bg-gradient-to-r from-amber-600 via-orange-600 to-red-600 hover:from-amber-500 hover:to-red-500 text-white font-bold text-xs shadow-lg flex items-center justify-center gap-2 transition-all disabled:opacity-50"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Evaluating Headers & URLs with Gemini...</span>
              </>
            ) : (
              <>
                <Bot className="w-4 h-4" />
                <span>Analyze Phishing Risk & Deceptive Indicators</span>
              </>
            )}
          </button>
        </div>

        {/* Results Panel */}
        <div className="space-y-4">
          {analysis ? (
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4 shadow-xl">
              {/* Risk Meter Header */}
              <div className="flex items-center justify-between p-4 bg-slate-950 rounded-lg border border-red-900/40">
                <div>
                  <span className="text-[10px] font-mono uppercase text-slate-400">Classification</span>
                  <div className="text-base font-extrabold text-red-400">{analysis.classification}</div>
                  <span className="text-xs text-slate-400 font-mono">
                    Confidence: <strong className="text-cyan-400">{analysis.confidence}%</strong>
                  </span>
                </div>

                <div className="text-right">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Phishing Risk Score</span>
                  <div className="text-2xl font-black font-mono text-red-400">
                    {analysis.phishingRiskScore}
                    <span className="text-xs text-slate-500 font-normal">/100</span>
                  </div>
                </div>
              </div>

              {/* Sender & Domain Spoofing Analysis */}
              <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 space-y-2 text-xs">
                <h4 className="font-bold text-slate-200 font-mono flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-amber-400" />
                  Sender Domain Impersonation
                </h4>
                <p className="text-slate-300 leading-relaxed">{analysis.senderAnalysis.analysis}</p>
                <div className="flex items-center gap-3 font-mono text-[11px] pt-1 border-t border-slate-800 text-slate-400">
                  <span>
                    Spoofed:{" "}
                    <strong className={analysis.senderAnalysis.isSpoofed ? "text-red-400" : "text-emerald-400"}>
                      {analysis.senderAnalysis.isSpoofed ? "YES (FLAGGED)" : "NO"}
                    </strong>
                  </span>
                  <span>
                    Domain Mismatch:{" "}
                    <strong className={analysis.senderAnalysis.domainMismatch ? "text-red-400" : "text-emerald-400"}>
                      {analysis.senderAnalysis.domainMismatch ? "DETECTED" : "NONE"}
                    </strong>
                  </span>
                </div>
              </div>

              {/* Authentication Status Grid (SPF / DKIM / DMARC) */}
              <div className="grid grid-cols-3 gap-2 text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
                  <span className="text-[10px] text-slate-500 block">SPF</span>
                  <span className="font-bold text-amber-400 uppercase">{analysis.authenticationStatus.spf}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
                  <span className="text-[10px] text-slate-500 block">DKIM</span>
                  <span className="font-bold text-slate-400 uppercase">{analysis.authenticationStatus.dkim}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-center">
                  <span className="text-[10px] text-slate-500 block">DMARC</span>
                  <span className="font-bold text-red-400 uppercase">{analysis.authenticationStatus.dmarc}</span>
                </div>
              </div>

              {/* Extracted Deceptive URLs */}
              <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 space-y-2 text-xs">
                <h4 className="font-bold text-slate-200 font-mono flex items-center justify-between">
                  <span>Extracted Embedded URLs</span>
                  <span className="text-[10px] text-red-400">{analysis.extractedUrls.length} identified</span>
                </h4>
                {analysis.extractedUrls.map((u, i) => (
                  <div key={i} className="p-2.5 rounded bg-slate-900 border border-red-900/50 space-y-1 font-mono">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-red-950 text-red-300 border border-red-800">
                        {u.risk}
                      </span>
                      <button
                        onClick={() => handleCopy(u.defangedUrl)}
                        className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                      >
                        {copiedUrl === u.defangedUrl ? "Copied" : "Copy Defanged"}
                      </button>
                    </div>
                    <div className="font-bold text-red-300 break-all select-all text-[11px]">{u.defangedUrl}</div>
                    <p className="text-[11px] text-slate-400 font-sans">{u.reason}</p>
                  </div>
                ))}
              </div>

              {/* SOC Playbook Actions */}
              <div className="bg-slate-950 p-3.5 rounded-lg border border-emerald-900/40 space-y-2 text-xs">
                <h4 className="font-bold text-emerald-300 font-mono flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  Recommended SOC Response Playbook
                </h4>
                <ul className="space-y-1 text-slate-300 list-disc list-inside">
                  {analysis.recommendedActions.map((act, i) => (
                    <li key={i}>{act}</li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-10 text-center space-y-3">
              <MailWarning className="w-12 h-12 text-amber-500/50 mx-auto" />
              <h3 className="font-bold text-sm text-slate-200">Awaiting Email Submission</h3>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">
                Paste RFC 822 email or headers on the left and click &quot;Analyze Phishing Risk&quot; to inspect domain spoofing and malicious link targets.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
