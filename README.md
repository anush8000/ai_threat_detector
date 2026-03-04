# 🛡️ AI Powered Cloud Threat Detection System

A real-time AWS cloud security monitoring dashboard with ML-based anomaly detection, RAG-grounded AI analysis, and CIS/NIST compliance tracking — built with Next.js 16 and Steampipe.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Security Checks](#security-checks)
- [ML Anomaly Detection](#ml-anomaly-detection)
- [AI SecOps Copilot (RAG)](#ai-secops-copilot-rag)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)

---

## Overview

This project is an enterprise-grade cloud security dashboard designed to continuously monitor AWS infrastructure for misconfigurations, vulnerabilities, and runtime threats. It integrates three core intelligence systems:

1. **Static Configuration Analysis** — 20 SQL-based AWS security checks via Steampipe
2. **ML Runtime Anomaly Detection** — Isolation Forest algorithm for behavioral analysis
3. **AI-Powered SecOps Copilot** — RAG-grounded threat analysis using Groq LLaMA 3.3 70B

The dashboard presents a unified bento-style interface with real-time charts, risk scoring, compliance tracking, and per-issue remediation commands.

---

## Features

### 🔍 Security Posture Management
- **20 AWS security checks** spanning S3, EC2, IAM, VPC, RDS, KMS, CloudTrail, Lambda, and EBS
- **CIS Benchmark & NIST 800-53 control mapping** on every detected issue
- **Per-issue remediation** — click any issue to reveal a copy-paste AWS CLI fix command
- **Drift detection** — compares current scan to previous to surface newly introduced issues

### 📊 Analytics & Visualization
- **Severity distribution** — donut pie chart (Critical / High / Medium / Low)
- **Issues by service category** — horizontal bar chart grouped by AWS service
- **Risk exposure trend** — live line chart updated on every scan refresh
- **Compliance score** — percentage of service categories passing checks

### 🤖 ML Behavioral Analysis (CWPP)
- **Isolation Forest** (100 trees, 256 max samples) trained on a synthetic 500-event baseline
- Scores each EC2 runtime event 0–100 on anomaly likelihood
- Classifies anomalies as `HIGH` / `MEDIUM` / `LOW` threat levels
- Identifies contributing factors: high CPU, outbound spikes, suspicious ports, brute-force logins

### 🧠 AI SecOps Copilot
- Powered by **Groq API** (LLaMA 3.3 70B Versatile)
- Uses **RAG** to retrieve relevant CIS/NIST controls before inference
- Returns structured output: Summary, Risk Level, Attack Vectors, Remediation steps
- Built-in rate limiting (20 requests/hour)

### 🎨 Enterprise UI
- Minimalist dark mode design inspired by Linear and Vercel
- Monospace data typography, smooth fade-up animations
- Fully responsive bento grid layout

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Next.js 16 App                          │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                  Dashboard.tsx (Client)              │   │
│  │   ┌──────────┐  ┌────────────┐  ┌────────────────┐  │   │
│  │   │ Issue    │  │ Charts     │  │ SecOps Copilot │  │   │
│  │   │ Feed     │  │ (Recharts) │  │ + CWPP Panel   │  │   │
│  │   └──────────┘  └────────────┘  └────────────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                  │
│         ┌────────────────┼─────────────────┐               │
│         ▼                ▼                 ▼               │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ /api/scan   │  │/api/steampipe│  │/api/ai-summary│      │
│  │ (healthchk) │  │  (SQL runs)  │  │  (Groq+RAG)  │      │
│  └─────────────┘  └──────────────┘  └──────────────┘      │
│                          │                 │               │
└──────────────────────────┼─────────────────┼───────────────┘
                           ▼                 ▼
                    ┌────────────┐    ┌──────────────────┐
                    │ Steampipe  │    │  Groq Cloud API  │
                    │  (pg:9193) │    │ LLaMA 3.3 70B    │
                    └────────────┘    └──────────────────┘
                           │
                    ┌────────────┐
                    │ AWS Cloud  │
                    │ (live data)│
                    └────────────┘
```

---

## Security Checks

All 20 checks are whitelisted server-side in `/api/steampipe`. The client sends only a `checkId` — never raw SQL.

| Check ID | Service | CIS/NIST Control | Severity |
|---|---|---|---|
| `S3_PUBLIC` | S3 | CIS-2.1.5 | High |
| `S3_NO_ENC` | S3 | CIS-2.1.2 | Medium |
| `S3_NO_LOG` | S3 | CIS-3.1 | Low |
| `EC2_PUBLIC` | EC2 | CIS-5.6 | Medium |
| `EC2_IMDSV2` | EC2 | AWS-IMDSV2 | High |
| `SG_OPEN` | VPC | CIS-5.3 | **Critical** |
| `SG_SSH` | VPC | CIS-5.1 | **Critical** |
| `SG_RDP` | VPC | CIS-5.2 | **Critical** |
| `IAM_NO_MFA` | IAM | CIS-1.10 | **Critical** |
| `IAM_OLD_KEY` | IAM | NIST-AC-2 | High |
| `CT_DISABLED` | CloudTrail | CIS-3.1 | High |
| `CT_NO_VALIDATION` | CloudTrail | CIS-3.2 | Medium |
| `EBS_UNENC` | EBS | CIS-2.2.1 | High |
| `RDS_PUBLIC` | RDS | CIS-2.3.2 | **Critical** |
| `RDS_NO_ENC` | RDS | CIS-2.3.1 | High |
| `RDS_NO_BACKUP` | RDS | AWS-BP | Medium |
| `KMS_NO_ROT` | KMS | CIS-3.8 | Medium |
| `VPC_NO_FLOW` | VPC | CIS-3.9 | Medium |
| `LAMBDA_PUBLIC` | Lambda | LAMBDA-PUB | High |

> **Fallback**: When Steampipe is unavailable, the dashboard loads a set of realistic mock issues so the UI remains fully functional for demonstrations.

---

## ML Anomaly Detection

The runtime monitor (`services/runtimeMonitor.ts`) implements a from-scratch **Isolation Forest** — a state-of-the-art unsupervised anomaly detection algorithm.

### How it works

1. **Training**: A synthetic baseline of 500 "normal" EC2 runtime events is generated at module load. Events cover CPU, memory, network, disk, process count, suspicious ports, and failed logins.
2. **Forest construction**: 100 isolation trees are built; each tree randomly selects a feature and a split value, isolating points progressively.
3. **Scoring**: The average path length across all trees is normalized to a 0–100 anomaly score. Shorter paths = more anomalous (isolated quickly).
4. **Classification**: Scores ≥ 70 = `HIGH`, ≥ 45 = `MEDIUM`, < 45 = `LOW`.

### Feature vector (9 dimensions)
`cpuUsage`, `memoryUsage`, `networkIn`, `networkOut`, `diskReadIops`, `diskWriteIops`, `processCount`, `suspiciousPortCount`, `failedLogins`

### Risk score formula (per issue)
```
riskScore = severityWeight × exposureWeight
```
- Severity weights: critical=5, high=4, medium=3, low=2
- Exposure weights: Public=5, Internal=3, Restricted=1

---

## AI SecOps Copilot (RAG)

The `/api/ai-summary` endpoint implements Retrieval-Augmented Generation:

1. **Retrieval**: The top 3 CIS/NIST controls most relevant to the detected issues are fetched from the local security knowledge base (`lib/rag/securityKnowledgeBase.ts`)
2. **Augmentation**: Retrieved controls are injected into the system prompt as authoritative context
3. **Generation**: Groq's LLaMA 3.3 70B Versatile produces a structured analysis

**Output format:**
```
SUMMARY: <threat narrative citing CIS control IDs>
RISK_LEVEL: <LOW | MEDIUM | HIGH | CRITICAL>
ATTACK_VECTORS: - <list of attack paths>
REMEDIATION: - <actionable steps with AWS CLI commands>
```

**Rate limiting**: 20 requests/hour, sliding window, in-memory.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Next.js 16 (App Router) |
| Language | TypeScript 5 |
| UI | React 19 |
| Charts | Recharts 3 |
| Icons | Lucide React |
| Styling | Vanilla CSS (custom design system) |
| Database | PostgreSQL via `pg` (Steampipe listens on port 9193) |
| AI Inference | Groq API — LLaMA 3.3 70B Versatile |
| Data Source | Steampipe (AWS plugin) |
| ML Algorithm | Isolation Forest (implemented in TypeScript) |

---

## Project Structure

```
collegeprojectnew/
├── app/
│   ├── api/
│   │   ├── scan/route.ts          # Health-check endpoint
│   │   ├── steampipe/route.ts     # SQL whitelist + Steampipe query runner
│   │   └── ai-summary/route.ts   # RAG-grounded Groq AI endpoint
│   ├── components/
│   │   └── Dashboard.tsx          # Main dashboard UI (client component)
│   ├── globals.css                # Design system tokens + utility classes
│   ├── layout.tsx                 # Root layout
│   └── page.tsx                   # Entry point → renders Dashboard
├── services/
│   └── runtimeMonitor.ts          # Isolation Forest ML + mock EC2 events
├── utils/
│   ├── riskScore.ts               # Risk score calculation (severity × exposure)
│   ├── threatCategory.ts          # Maps issue type to threat category
│   └── driftDetection.ts          # Compares scan snapshots for delta
├── lib/
│   └── rag/
│       └── securityKnowledgeBase.ts # CIS/NIST control index + RAG retrieval
├── public/                         # Static assets
├── .env.local                      # Environment variables (not committed)
├── next.config.ts
├── package.json
└── tsconfig.json
```

---

## Getting Started

### Prerequisites

- Node.js 20+
- [Steampipe](https://steampipe.io/downloads) with the AWS plugin installed
- A Groq API key (free at [console.groq.com](https://console.groq.com))
- AWS credentials configured (`~/.aws/credentials` or env vars)

### Installation

```bash
# 1. Install dependencies
npm install

# 2. Configure environment variables (see below)
cp .env.local.example .env.local

# 3. Start Steampipe service
steampipe service start

# 4. Run the development server
npm run dev
```

The app will be available at **http://localhost:5000**

### Demo Mode (no AWS required)

If `STEAMPIPE_PASSWORD` is not set or Steampipe is unreachable, the dashboard automatically falls back to a rich set of **mock security issues** — ideal for demos and presentations.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `STEAMPIPE_PASSWORD` | Yes* | Password for Steampipe's built-in PostgreSQL service |
| `GROQ_API_KEY` | Yes* | API key for Groq cloud inference (LLaMA 3.3 70B) |

> \* The app runs in demo mode without these variables, but live AWS scanning and AI analysis will be disabled.

Create a `.env.local` file in the project root:
```env
STEAMPIPE_PASSWORD=your_steampipe_password_here
GROQ_API_KEY=gsk_your_groq_api_key_here
```

---

## API Reference

### `GET /api/scan`
Health check. Returns server status and timestamp.

### `GET /api/steampipe?checkId={CHECK_ID}`
Runs a whitelisted security check against Steampipe.
- Valid `checkId` values: `S3_PUBLIC`, `S3_NO_ENC`, `EC2_PUBLIC`, `SG_OPEN`, `IAM_NO_MFA`, etc. (see full list above)
- Returns `{ rows: [...], rowCount: N }`

### `POST /api/ai-summary`
Generates a RAG-grounded AI threat analysis.

**Request body:**
```json
{
  "issues": [{ "type": "...", "description": "...", "severity": "critical" }],
  "riskScore": 85,
  "complianceScore": 60,
  "counts": { "critical": 2, "high": 3, "medium": 1, "low": 0 }
}
```

**Response:**
```json
{
  "summary": "SUMMARY: ...\nRISK_LEVEL: HIGH\n...",
  "remaining": 18,
  "ragControls": [{ "id": "CIS-5.3", "framework": "CIS", "title": "...", "severity": "..." }]
}
```

### `GET /api/ai-summary`
Returns current rate limit status: `{ remaining, total, resetInMins }`

---

## Compliance Frameworks

This system maps findings to the following frameworks:

- **CIS AWS Foundations Benchmark v3** — comprehensive AWS hardening guidelines
- **NIST SP 800-53 Rev 5** — federal security and privacy controls
- **AWS Security Best Practices** — AWS-specific operational security guidance

---

*Built as a college capstone project demonstrating cloud security engineering, machine learning, and AI integration.*
