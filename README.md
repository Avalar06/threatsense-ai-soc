# AI-SOC Investigator & Threat Intelligence Platform

[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![Type Checking](https://img.shields.io/badge/TypeScript-5.8_Strict-blue.svg)]()
[![AI Model](https://img.shields.io/badge/AI_Engine-Gemini_3.7_Flash-purple.svg)]()
[![Security](https://img.shields.io/badge/Standards-NIST_SP_800--61_Rev2-orange.svg)]()
[![MITRE](https://img.shields.io/badge/Framework-MITRE_ATT%26CK_v14-red.svg)]()

An autonomous Security Operations Center (SOC) investigation and threat intelligence platform designed for rapid alert triage, evidence synthesis, kill chain mapping, automated IOC defanging, and audit-grade incident report generation.

---

## 1. Overview & Problem Statement
Modern SOC teams are overwhelmed with tens of thousands of daily alerts, leading to alert fatigue, missed detections, and delayed containment response times. 

**AI-SOC Investigator** bridges the gap between raw SIEM telemetry and incident response:
- Ingests and normalizes multi-format logs (Windows Event Logs, Linux Syslog, Nginx/Apache, CSV).
- Employs deterministic correlation rules mapped to the MITRE ATT&CK matrix.
- Couples rule-based triage with server-side **Gemini 3.7 Flash** reasoning to generate deep tactical investigations with zero client-side credential exposure.
- Separates observed facts from AI inferences to eliminate hallucinations.
- Generates **NIST SP 800-61 Rev. 2** compliant incident reports ready for CISO/executive review.

---

## 2. Key Features

- **Autonomous AI Incident Copilot (`/api/investigate`, `/api/ai-analyst`):**
  - Ground-truth evidence verification.
  - Multi-turn investigation assistant.
  - Prioritized containment action checklists.
- **SIEM Log Ingestion & Normalization (`logParser.ts`):**
  - Normalizes heterogeneous syslog and Windows Event lines into standard `SecurityEvent` schemas.
- **Deterministic Detection Engine (`detectionEngine.ts`):**
  - Rule-based detection for Brute-Force, Pass-the-Hash, Mimikatz dumping, Port Scans, Web Shells, and Obfuscated PowerShell.
  - Quantitative Risk Scoring (0–100) combining asset criticality, tactic severity, and event volume.
- **MITRE ATT&CK Matrix & Heatmap (`mitreDatabase.ts`):**
  - Live interactive enterprise matrix highlighting active techniques (e.g., T1110, T1059.001, T1003, T1071.001).
- **IOC Extractor & Auto-Defanger (`iocExtractor.ts`):**
  - Regex extraction of IPv4, IPv6, MD5, SHA-256, URLs, and Domains.
  - Automatic safety defanging (`hxxp://`, `185[.]220[.]101[.]5`) with CSV, JSON, and text export.
- **Phishing & Email Header Analyzer (`/api/phishing-analyzer`):**
  - RFC 822 header inspection, SPF/DKIM/DMARC status evaluation, and homograph domain detection.
- **NIST SP 800-61 Incident Report Generator (`/api/generate-report`):**
  - Root cause analysis, risk impact rating, containment logs, and 1-click Markdown/PDF export.

---

## 3. Technology Stack

- **Frontend:** React 19, TypeScript, Tailwind CSS v4, Motion, Recharts, Lucide Icons
- **Backend & Middleware:** Node.js, Express, Vite Proxy Middleware
- **AI Reasoning:** `@google/genai` (Gemini 3.7 Flash with automatic fallback to Gemini 3.1 Flash-Lite)
- **Standards & Frameworks:** MITRE ATT&CK Enterprise v14, NIST SP 800-61 Rev. 2

---

## 4. Security Architecture

- **Server-Side API Key Protection:** The `GEMINI_API_KEY` is strictly server-side. No `VITE_` API keys are exposed to the client browser or production build.
- **Untrusted Input Handling:** All uploaded log files, headers, and strings are treated as untrusted text. No scripts, shell commands, or binaries are executed.
- **Prompt Injection Defense:** Strict data encapsulation in JSON blocks with system instructions preventing log text from overriding analyst instructions.
- **Security Headers:** Configured with `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 1; mode=block`, and `Referrer-Policy: strict-origin-when-cross-origin`.

---

## 5. Local Installation & Development Guide

### Prerequisites
- Node.js (v18 or v20+)
- npm (v9+)
- A Gemini API Key from [Google AI Studio](https://aistudio.google.com/)

### Step 1: Clone the Repository
```bash
git clone https://github.com/your-username/ai-soc-investigator.git
cd ai-soc-investigator
```

### Step 2: Install Dependencies
```bash
npm install
```

### Step 3: Configure Environment Variables
Create a `.env` file in the root directory:
```bash
cp .env.example .env
```
Open `.env` and set your key:
```env
GEMINI_API_KEY="your_actual_gemini_api_key_here"
```

### Step 4: Run the Development Server
```bash
npm run dev
```
Open your browser at `http://localhost:3000`.

### Step 5: Run Automated Tests
```bash
npm test
```

### Step 6: Production Build & Run
```bash
npm run build
npm start
```

---

## 6. Project Structure

```text
├── docs/
│   ├── architecture.md       # Complete data flow and threat modeling
│   └── security.md           # Security headers, key hygiene, and AI defense
├── server/
│   ├── apiMiddleware.ts      # Vite dev server proxy middleware
│   ├── apiRouter.ts          # Server-side Express API routes & Gemini handlers
│   └── geminiClient.ts       # Server-side Google GenAI client instance
├── src/
│   ├── components/           # UI components, layout, charts, badges
│   ├── context/              # SOC Context state management (alerts, events)
│   ├── data/                 # MITRE ATT&CK v14 dataset & 5 sample attack scenarios
│   ├── services/             # Deterministic parser, detection engine, IOC extractor
│   ├── types/                # Strict TypeScript schemas (SecurityEvent, Alert, Report)
│   ├── views/                # Dashboard, Alerts, Investigation, Reports, Phishing views
│   └── App.tsx               # Root SPA layout & navigation
├── tests/
│   ├── runAllTests.ts        # Master automated test runner
│   └── unit/                 # Deterministic test suites for parser, detection, and IOCs
├── server.ts                 # Production Express static & API server
├── package.json              # NPM dependencies & scripts
├── vite.config.ts            # Vite & Tailwind CSS v4 configuration
└── tsconfig.json             # Strict TypeScript configuration
```

---

## 7. Limitations & Synthetic Data Notice
- **Sample Scenarios:** The pre-configured scenarios (e.g., APT-Style Intrusion, AD Privilege Escalation) utilize realistic synthetic security telemetry for demonstration and benchmarking purposes.
- **Rule Detection vs. AI Analysis:** Deterministic rules detect indicators with high speed locally; server-side Gemini synthesizes the contextual narrative, uncertainty factors, and containment steps.

---

## 8. License
Distributed under the MIT License. See `LICENSE` for more information.
