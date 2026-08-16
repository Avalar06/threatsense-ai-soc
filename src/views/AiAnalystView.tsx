import React, { useState, useRef, useEffect } from "react";
import { useSoc } from "../context/SocContext.js";
import {
  Bot,
  Send,
  Sparkles,
  ShieldAlert,
  Terminal,
  HelpCircle,
  RefreshCw,
  Copy,
  Check,
  User,
  Shield,
  Layers,
  Zap,
} from "lucide-react";
import { queryAiAnalyst } from "../services/apiClient.js";

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: string;
}

export const AiAnalystView: React.FC = () => {
  const { activeAlert, events, iocs, alerts, setActiveAlertId } = useSoc();

  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "m-0",
      role: "assistant",
      content: `Hello Analyst. I am your **AI SOC Copilot** powered by **Gemini 3.7 Flash**.

I have ingested telemetry from **${events.length} security events** and **${alerts.length} active alerts**.
${
  activeAlert
    ? `Currently focused on **Alert ${activeAlert.id}: ${activeAlert.title}** (Target: \`${activeAlert.host}\`, Source: \`${activeAlert.sourceIp}\`, Risk Score: **${activeAlert.riskScore}/100**).`
    : "No specific alert is pinned. You can select one from the top bar or ask general queries."
}

How can I assist your investigation?`,
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);

  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const presetQuestions = [
    "Why was this alert classified as high severity?",
    "Is this consistent with a brute-force attack?",
    "What evidence supports this conclusion?",
    "What should I investigate next?",
    "Which MITRE ATT&CK techniques may apply?",
    "Show me the suspicious events associated with this IP.",
    "Summarize this incident for a SOC Lead.",
  ];

  const handleSend = async (customText?: string) => {
    const textToSend = customText || input;
    if (!textToSend.trim() || loading) return;

    const userMsg: ChatMessage = {
      id: `usr-${Date.now()}`,
      role: "user",
      content: textToSend,
      timestamp: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!customText) setInput("");
    setLoading(true);

    try {
      const historyPayload = messages.map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const contextPayload = {
        activeAlert,
        totalEvents: events.length,
        sampleEvents: events.slice(0, 20),
        iocs,
      };

      const reply = await queryAiAnalyst(textToSend, historyPayload, contextPayload);

      const botMsg: ChatMessage = {
        id: `bot-${Date.now()}`,
        role: "assistant",
        content: reply,
        timestamp: new Date().toLocaleTimeString(),
      };

      setMessages((prev) => [...prev, botMsg]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          id: `bot-err-${Date.now()}`,
          role: "assistant",
          content: `⚠️ Error communicating with AI SOC backend: ${err.message || "Unknown error"}. Please check server connectivity.`,
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-4 max-w-[1400px] mx-auto h-[calc(100vh-5rem)] flex flex-col">
      {/* Header & Investigation Context Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-indigo-950 border border-indigo-500/50 text-indigo-300">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="font-bold text-base text-white">AI SOC Analyst Assistant</h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-indigo-950 text-indigo-300 border border-indigo-700/60 font-bold">
                GEMINI 3.7 FLASH
              </span>
            </div>
            <p className="text-xs text-slate-400">Contextual query assistant with grounded log evidence verification</p>
          </div>
        </div>

        {/* Pinned Alert Context Indicator */}
        <div className="flex items-center gap-2 text-xs font-mono bg-slate-950 p-2 rounded-lg border border-slate-800">
          <span className="text-slate-500">Pinned Context:</span>
          <select
            value={activeAlert?.id || ""}
            onChange={(e) => setActiveAlertId(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-cyan-300 focus:outline-none focus:border-cyan-500"
          >
            {alerts.map((a) => (
              <option key={a.id} value={a.id}>
                {a.id} - {a.title.substring(0, 24)}... (Risk: {a.riskScore})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Preset Quick Queries Bar */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 shrink-0 custom-scrollbar">
        <span className="text-xs text-slate-500 font-mono flex items-center gap-1 shrink-0">
          <Sparkles className="w-3 h-3 text-indigo-400" />
          Fast Queries:
        </span>
        {presetQuestions.map((q, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(q)}
            disabled={loading}
            className="shrink-0 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-white text-xs font-mono transition-colors disabled:opacity-50"
          >
            {q}
          </button>
        ))}
      </div>

      {/* Messages Container */}
      <div className="flex-1 bg-slate-950/80 border border-slate-800 rounded-xl p-5 overflow-y-auto space-y-4 custom-scrollbar shadow-inner">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
          >
            {msg.role === "assistant" && (
              <div className="w-8 h-8 rounded-lg bg-indigo-950 border border-indigo-500/50 flex items-center justify-center text-indigo-300 shrink-0">
                <Bot className="w-4 h-4" />
              </div>
            )}

            <div
              className={`max-w-2xl rounded-xl p-4 text-xs leading-relaxed font-sans shadow-md ${
                msg.role === "user"
                  ? "bg-cyan-950/80 border border-cyan-700/60 text-cyan-100 font-medium"
                  : "bg-slate-900 border border-slate-800 text-slate-200"
              }`}
            >
              <div className="flex items-center justify-between gap-4 mb-2 pb-1 border-b border-slate-800/80 text-[10px] font-mono text-slate-400">
                <span>{msg.role === "user" ? "SOC Analyst" : "AI Cyber Defense Assistant"}</span>
                <span>{msg.timestamp}</span>
              </div>

              {/* Render formatted message content */}
              <div className="prose prose-invert prose-xs max-w-none space-y-2 whitespace-pre-wrap">
                {msg.content}
              </div>
            </div>

            {msg.role === "user" && (
              <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-700/60 flex items-center justify-center text-cyan-300 shrink-0">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-3 justify-start">
            <div className="w-8 h-8 rounded-lg bg-indigo-950 border border-indigo-500/50 flex items-center justify-center text-indigo-300 shrink-0">
              <Bot className="w-4 h-4 animate-spin" />
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5 text-xs text-slate-400 font-mono flex items-center gap-2">
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-indigo-400" />
              <span>Analyzing investigation telemetry and correlating evidence...</span>
            </div>
          </div>
        )}

        <div ref={chatEndRef} />
      </div>

      {/* Input Box */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSend();
        }}
        className="flex items-center gap-2 bg-slate-900 border border-slate-700 p-2 rounded-xl shrink-0"
      >
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={`Ask about alert ${activeAlert?.id || ""}, IOCs, attack timeline, or containment playbooks...`}
          className="flex-1 bg-transparent px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none font-sans"
        />
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg font-bold text-xs flex items-center gap-1.5 transition-colors shadow-md"
        >
          <Send className="w-3.5 h-3.5" />
          <span>Send</span>
        </button>
      </form>
    </div>
  );
};
