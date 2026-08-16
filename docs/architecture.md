# AI-SOC Architecture Documentation

## Overview
The **AI-SOC Investigator & Threat Intelligence Platform** combines deterministic security analysis engines with server-side Gemini 3.7 Flash models. It processes raw endpoint and network telemetry, extracts verifiable artifacts, correlates multi-stage attack patterns against MITRE ATT&CK Enterprise v14, and generates audit-ready NIST SP 800-61 Rev 2 incident reports.

---

## 1. End-to-End Data Flow

```text
Raw Log Ingestion (Windows, Syslog, Web, CSV)
      │
      ▼
Multi-Format Log Parser (logParser.ts)
      │
      ▼
Normalized Security Events (SecurityEvent[])
      │
      ▼
Detection & Correlation Engine (detectionEngine.ts)
 ├── Rule Evaluation & MITRE Tactic Tagging
 └── Multi-Dimensional Risk Scoring (0–100)
      │
      ▼
Security Alerts Generated (SecurityAlert[])
      │
      ▼
Interactive SOC Investigation Workspace
 ├── Chronological Event Timeline
 ├── Regex IOC Extractor & Defanger (iocExtractor.ts)
 └── MITRE ATT&CK Matrix Alignment
      │
      ▼
Server-Side Gemini 3.7 Flash Reasoning Engine (/api/investigate, /api/generate-report)
 ├── Ground-Truth Evidence Separation
 ├── Analytical Inferences & Threat Actor Attribution
 ├── Uncertainty / Visibility Gap Analysis
 └── Prioritized SLA Containment Directives
      │
      ▼
Executive Incident Reports (NIST SP 800-61 Rev 2)
```

---

## 2. Client vs Server Boundary

### Client-Side Responsibilities (React 19 + TypeScript + Tailwind v4)
- Fast, low-latency UI rendering and responsive visualization (Recharts).
- Immediate client-side log parsing and normalization without sending raw enterprise telemetry across external networks prematurely.
- Interactive IOC search, extraction, and automated defanging (`hxxp://`, `[.]`).
- State management across multiple concurrent alert investigations (`SocContext`).
- Incident report preview, Markdown export, and PDF generation.

### Server-Side Responsibilities (Node.js + Express + `@google/genai`)
- Secure proxy endpoints for Gemini 3.7 Flash model invocation.
- Prompt injection defenses and strict JSON schema enforcement via `@google/genai` types.
- Threat intelligence enrichment (`/api/ioc-enrich`) and deep incident report synthesis (`/api/generate-report`).
- Safe fallback routing to `gemini-3.1-flash-lite` if primary API quota limits or transient network failures occur.
- Total isolation of `GEMINI_API_KEY` to prevent client-side bundle exposure.

---

## 3. Threat Model & Security Controls

| Threat / Risk | Mitigating Architecture Control |
|---|---|
| **API Key Leakage** | `GEMINI_API_KEY` is strictly managed server-side. No `VITE_` prefix, no client-side bundle leakage. |
| **Prompt Injection** | Telemetry logs are encapsulated strictly as untrusted data payloads within JSON blocks with explicit system instructions prohibiting execution of instructions found in log lines. |
| **Hallucinated Evidence** | Strict JSON schema mandates separation of observed verifiable evidence from analytical inferences and uncertainty gaps. |
| **Malicious File Execution** | Uploaded log files are parsed purely as text data streams. No binaries, scripts, or active macros are ever executed. |
| **Rate Limits & API Outages** | Built-in graceful fallbacks and exponential backoff retry handling. |
