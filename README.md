# ThreatSense AI — SOC Investigator & Threat Intelligence Platform

[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![Type Checking](https://img.shields.io/badge/TypeScript-5.8_Strict-blue.svg)]()
[![AI Engine](https://img.shields.io/badge/AI_Engine-Gemini_3.7_Flash_%2F_3.1_Flash--Lite-purple.svg)]()
[![Framework](https://img.shields.io/badge/Reporting-NIST_SP_800--61_Rev._2--Informed-orange.svg)]()
[![MITRE](https://img.shields.io/badge/Dataset-MITRE_ATT%26CK_v14_(Pinned)-red.svg)]()

An AI-assisted Security Operations Center (SOC) investigation and threat intelligence platform designed for rapid alert triage, evidence synthesis, kill-chain mapping, automated IOC defanging, and structured incident report generation.

---

## 1. Overview & Problem Statement

Modern Security Operations Center (SOC) analysts face high alert volumes, fragmented forensic telemetry across disparate log formats, and time-consuming manual triage workflows.

**ThreatSense AI** bridges the gap between raw SIEM telemetry and incident response workflows:
- **Telemetry Ingestion & Normalization:** Ingests and standardizes heterogeneous logs (Windows Event Logs, Linux Syslog, Web Access logs, CSV).
- **Deterministic Detection Engine:** Executes rule-based correlation mapped to tactics and techniques from the pinned MITRE ATT&CK Enterprise v14 dataset.
- **AI-Assisted Investigation Reasoning:** Integrates server-side **Gemini 3.7 Flash** (with resilient fallback to **Gemini 3.1 Flash-Lite**) to assist analysts in synthesizing tactical context, identifying suspicious activity, assessing risk, and structuring remediation recommendations.
- **Evidence vs. Inference Separation:** Explicitly distinguishes directly observed verifiable evidence from analytical inferences and visibility gaps to reduce unsupported conclusions and aid analyst verification.
- **NIST SP 800-61 Rev. 2-Informed Incident Reporting:** Synthesizes structured incident reports patterned after NIST SP 800-61 Rev. 2 response phases (Preparation, Detection & Analysis, Containment/Eradication, Post-Incident Activity) for peer review and executive briefing.

> **Note:** ThreatSense AI is an **AI-assisted investigation platform**, not a fully autonomous or self-acting SOC. All AI-generated hypotheses, risk scores, and containment checklists are advisory and require review and validation by a qualified security analyst.

---

## 2. Key Capabilities

### 🛡️ Deterministic Detection & SIEM Ingestion
- **Multi-Format Log Parser (`src/services/logParser.ts`):** Normalizes Windows Security Event Logs (Event IDs 4624, 4625, 4688, 4720, 4728, 4738, 7045), Linux Syslog/auth.log (sshd, sudo), and Web Server access logs into unified `SecurityEvent` schemas.
- **Correlation & Detection Rules (`src/services/detectionEngine.ts`):** Rule engine detecting credential dumping (e.g., Mimikatz, LSASS memory access), brute-force authentication bursts, pass-the-hash indicators, suspicious process spawns, web shells, and obfuscated PowerShell commands.
- **Multi-Factor Risk Scoring:** Calculates risk scores (0–100) based on asset criticality, detection severity, event frequency, and MITRE tactic progression.

### 🧠 Server-Side AI-Assisted Investigation (Gemini 3.7 Flash)
- **Incident Investigation Copilot (`/api/investigate`):** Analyzes alerts and correlated event streams to identify attack progression, summarize tactical findings, and suggest prioritized containment checklists.
- **Interactive SOC Assistant (`/api/ai-analyst`):** Multi-turn conversational investigation assistant for querying event artifacts, validating hypotheses, and assessing impact.
- **MITRE Kill-Chain Analysis (`/api/mitre-analysis`):** Maps correlated techniques into tactical progression sequences.
- **Threat Intelligence IOC Enrichment (`/api/ioc-enrich`):** AI-assisted indicator contextualization, threat actor association, and infrastructure profiling.
- **Phishing & Email Header Analysis (`/api/phishing-analyzer`):** Evaluates RFC 822 email headers, authentication mechanisms (SPF, DKIM, DMARC), spoofing risk, and domain anomalies.
- **Incident Report Synthesis (`/api/generate-report`):** Generates structured incident reports with executive summaries, timeline reconstruction, evidence tables, and containment actions.

### 🔍 Tactical SOC Utilities
- **IOC Extractor & Defanger (`src/services/iocExtractor.ts`):** Regex-based extraction of IPv4, IPv6, MD5, SHA-256, URLs, domains, and file paths with automated safety defanging (`hxxp://`, `185[.]220[.]101[.]5`) and export options (CSV, JSON, Defanged Text).
- **Pinned MITRE ATT&CK Matrix Navigator (`src/data/mitreDatabase.ts`):** Interactive enterprise matrix covering techniques from the pinned Enterprise v14 dataset.

---

## 3. Technology Stack & Architecture

- **Frontend:** React 19, TypeScript (Strict Mode), Tailwind CSS v4, Motion, Recharts, Lucide Icons
- **Backend & API Layer:** Node.js, Express router (`/server/apiRouter.ts`), Vite development proxy middleware (`/server/apiMiddleware.ts`)
- **Persistence Foundation:** Server-side SQLite persistence (`data/threatsense.db`, excluded from Git; no external database server required)
- **AI Integration:** `@google/genai` TypeScript SDK (Gemini 3.7 Flash with automated fallback to Gemini 3.1 Flash-Lite)
- **Pinned Datasets & Framework References:** MITRE ATT&CK Enterprise v14 (pinned repository dataset), NIST SP 800-61 Rev. 2-informed report schema

---

## 4. Security Architecture & API Key Hygiene

ThreatSense AI is engineered with strict server-side API key boundaries:

- **Server-Side API Key Isolation:** The Gemini API key (`GEMINI_API_KEY`) is consumed exclusively within the Node.js/Express backend layer (`server/geminiClient.ts` / `server/apiRouter.ts`).
- **No Client-Side Key Exposure:** There are **zero** `VITE_` prefixed secret variables. Production client bundles (`dist/`) contain no credentials, API keys, or cloud secrets.
- **Dynamic On-Demand Initialization:** The backend client uses dynamic proxy instantiation with `dotenv`, loading the API key at request time to support standard Node.js development environments.
- **Repository Hygiene:** `.env` and `.env.local` files as well as local SQLite database files (`data/*.db`, `data/*.db-*`) are strictly excluded via `.gitignore`. A sanitized template (`.env.example`) is provided.
- **Untrusted Input Handling:** Raw event logs, syslog lines, and email headers are handled purely as untrusted text data. No uploaded strings or script commands are executed on the host.
- **Prompt-Injection Mitigation:** Input telemetry is encapsulated within structured JSON data blocks with explicit system instructions prohibiting execution of instructions embedded in raw log messages.
- **Hardened HTTP Headers:** Express middleware sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 1; mode=block`, and `Referrer-Policy: strict-origin-when-cross-origin`.

---

## 5. Verification & Test Status

All components have been validated locally via automated test suites and live API checks:

- **Automated Test Results:** **5 test suites passed (0 failed)**
  - `tests/unit/logParser.test.ts`: **13 tests passed** (Windows Event logs, Linux Syslog/auth.log, Web access logs, edge cases)
  - `tests/unit/iocExtractor.test.ts`: **9 tests passed** (IPv4, SHA-256, MD5, URLs, domain extraction, safe defanging)
  - `tests/unit/detectionEngine.test.ts`: **11 tests passed** (Brute-force detection, Mimikatz detection, zero false-positives on benign logs, risk score bounds 0–100)
  - `tests/integration/apiEndpoints.test.ts`: **6 tests passed** (Health check, route validation, bad request rejection)
  - `tests/integration/database.test.ts`: **Database integration passed** (SQLite schema verification, CRUD persistence, relationship preservation, parameterized SQL injection safety)
- **Dependency Audit:** `npm audit` reports **0 vulnerabilities**.
- **TypeScript Static Verification:** `npm run lint` (`tsc --noEmit`) passes with **0 errors**.
- **Production Bundle:** `npm run build` completes successfully.
- **Live Gemini Verification:** Verified with live `POST /api/investigate` calls returning structured verdict, confidence score, and executive summary. Resilient fallback to `gemini-3.1-flash-lite` was validated under transient rate limits/high demand.

---

## 6. Local Installation & Setup Guide

### Prerequisites
- **Node.js:** Node.js 20+ recommended (Node.js 18+ supported)
- **npm:** v9+
- **Gemini API Key:** Obtain an API key from [Google AI Studio](https://aistudio.google.com/)

### Step 1: Clone the Repository
```bash
git clone https://github.com/Avalar06/threatsense-ai-soc.git
cd threatsense-ai-soc
```

### Step 2: Install Dependencies
```bash
npm install
```

### Step 3: Configure Environment Variables
Create a local `.env` file from the provided template:
```bash
cp .env.example .env
```
Open `.env` and configure your API key (the file is ignored by Git):
```env
GEMINI_API_KEY="your_gemini_api_key_here"
```

### Step 4: Run Automated Tests
```bash
npm test
```

### Step 5: Start the Development Server
```bash
npm run dev
```
Navigate to `http://localhost:3000` in your web browser.

### Step 6: Build and Run Production Server
```bash
npm run build
npm start
```

---

## 7. Project Structure

```text
threatsense-ai-soc/
├── docs/
│   ├── architecture.md           # End-to-end data flow and threat model
│   └── security.md               # Security architecture, headers, and AI safeguards
├── server/
│   ├── db/
│   │   ├── database.ts           # SQLite database connection & typed repository
│   │   └── schema.ts             # Tables, indexes, and JSON serialization helpers
│   ├── apiMiddleware.ts          # Vite dev-server proxy middleware
│   ├── apiRouter.ts              # Server-side Express API routes & Gemini handlers
│   └── geminiClient.ts           # Server-side Gemini client with dynamic key resolution
├── src/
│   ├── components/               # UI components, layout, metric charts, badges
│   ├── context/                  # SOC Context state management (alerts, events)
│   ├── data/
│   │   ├── mitreDatabase.ts      # Pinned MITRE ATT&CK Enterprise v14 dataset
│   │   └── sampleLogs.ts         # Realistic synthetic attack scenarios for benchmarking
│   ├── services/
│   │   ├── detectionEngine.ts    # Deterministic correlation rules & risk scoring
│   │   ├── iocExtractor.ts       # Regex IOC extraction and safety defanging
│   │   └── logParser.ts          # Multi-format SIEM log parser & normalizer
│   ├── types/                    # TypeScript interfaces (SecurityEvent, Alert, Report)
│   ├── views/                    # Dashboard, Alerts, Investigation, Reports, Phishing views
│   └── App.tsx                   # Main SPA shell and navigation
├── tests/
│   ├── integration/
│   │   └── apiEndpoints.test.ts  # Backend Express route integration tests
│   ├── unit/
│   │   ├── detectionEngine.test.ts # Detection rule and scoring unit tests
│   │   ├── iocExtractor.test.ts    # IOC extraction and defanging unit tests
│   │   └── logParser.test.ts       # Multi-format log parser unit tests
│   └── runAllTests.ts            # Master test suite runner
├── LICENSE                       # MIT License
├── server.ts                     # Production Express server
├── package.json                  # Dependencies, metadata, and scripts
├── package-lock.json             # Locked dependency tree
├── vite.config.ts                # Vite configuration with Tailwind v4 & dev middleware
└── tsconfig.json                 # Strict TypeScript configuration
```

---

## 8. Limitations & Scope

- **Synthetic Telemetry:** The bundled attack scenarios (e.g., AD privilege escalation, web shell activity, brute force) utilize realistic synthetic security telemetry for demonstration, research, and benchmarking.
- **Rule-Based Engine Scope:** The built-in detection engine uses deterministic pattern-matching rules designed for portfolio and demonstration workflows. It is not a replacement for an enterprise SIEM/EDR platform (e.g., Splunk, Microsoft Sentinel, CrowdStrike Falcon).
- **AI Recommendation Advisory Status:** All AI verdicts, confidence ratings, and containment checklists are advisory and must be validated by a human security analyst before operational action.
- **No Active Host Actions:** The platform does not execute live network isolation, process termination, firewall modification, or active endpoint remediation.
- **Threat Intelligence Enrichment:** IOC enrichment is AI-assisted using the language model's trained knowledge base unless a commercial external threat intelligence API (e.g., VirusTotal, AlienVault OTX) is integrated.
- **Pinned MITRE ATT&CK Dataset:** The application includes a pinned MITRE ATT&CK Enterprise v14 dataset. It does not automatically synchronize with subsequent ATT&CK releases.
- **NIST SP 800-61 Structure:** The incident reporting format is informed by NIST SP 800-61 Rev. 2. It does not represent certified compliance with NIST SP 800-61 Rev. 3.
- **Platform Classification:** ThreatSense AI is a cybersecurity engineering portfolio and research platform, not a certified enterprise SOC appliance.

---

## 9. License

This project is open-source software licensed under the [MIT License](LICENSE).
See the [LICENSE](LICENSE) file for full copyright and permission notices.
