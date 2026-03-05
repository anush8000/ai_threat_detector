# AI-Powered Cloud Threat Detection System

An enterprise-grade, multi-cloud security posture management dashboard. It aggregates security vulnerabilities across AWS, GCP, and Azure using [Steampipe](https://steampipe.io/), runs local ML anomaly detection on runtime workloads, and provides an AI SecOps Copilot for automated remediation analysis using Groq's high-speed inference.

## 🌟 Key Features

- **Multi-Cloud Pre-Flight Checks**: Live querying of cloud environments (AWS, GCP, Azure) to detect misconfigurations.
- **AI SecOps Copilot**: Groq-powered contextual analysis of active security threats. Includes an interactive chat interface for follow-up investigations and remediation commands.
- **Runtime Anomaly ML**: Synthetic local workload scoring to detect behavioral anomalies (e.g., suspicious port usage, high CPU load combined with disk spikes).
- **Executive Reporting**: Automated compliance scoring, risk trend graphing, and severity distributions.
- **Premium "Mirror UI"**: A custom-designed glassmorphic, enterprise-ready dashboard with animated skeletons, high-contrast typography, and smooth layouts inspired by Apple HIG.
- **Secure Authentication**: Built-in credential-based authentication utilizing Next.js Edge Middleware to protect API routes and dashboard views.

## 🛡️ Architecture & Components
The application interface is fundamentally scalable:
- `DashboardHeader`: Navigation, context syncing, and multi-cloud toggling.
- `StatCards`: High-level metrics, compliance percentages, and total risk score.
- `IssueFeed`: A detailed, expanding vulnerability list with CI/CD friendly remediation commands.
- `MLWorkloads`: Live anomaly detection tracker.
- `AICopilot`: Auto-summarizing RAG chatbot tuned for SecOps workflows.
- `ComplianceChart`: Interactive visualization of risk dispersion.

## 🚀 Getting Started

### Prerequisites

1.  **Node.js 18+**
2.  **Groq API Key**: Get one at [console.groq.com](https://console.groq.com).
3.  **Local Steampipe Dashboard (Optional)**: Steampipe must be running in service mode locally on port 9194 with adequate cloud plugins (aws, gcp, azure) installed and configured if you wish to run live queries instead of using the provided mock data fallback.

### Installation

1. Clone the repo and navigate to the project directory.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Set your environment variables in `.env.local`:
   ```env
   GROQ_API_KEY="your_groq_api_key_here"
   STEAMPIPE_PASSWORD="your_secure_dashboard_password"
   STEAMPIPE_URL="http://localhost:9194"
   ```
4. Run the development server:
   ```bash
   npm run dev
   ```
5. Access the secure dashboard at `http://localhost:3000`. You will be prompted to login using the `STEAMPIPE_PASSWORD`.

## 🧪 Testing Coverage

The application maintains a high-integrity robust testing suite powered by Vitest & React Testing Library.

**20+ Integration Tests Covering:**
1. Component Lifecycle & Skeleton Loaders
2. Multi-Cloud Filtering interactions (AWS, GCP, Azure views)
3. API Fallbacks and Error Boundary Catching
4. Dynamic Recharts Renderings (Pie & Bar charts)
5. AI Copilot RAG flows (including timeouts, typing states, and chat boundaries)
6. Complex UI State Manipulations (Expanding/collapsing remediation hints)

Run tests simply via:
```bash
npm run test
```

## 🛠️ Code Quality
- **Zero ESLint Errors**: Strictly typed components and structured TypeScript definitions.
- **Rate Limiters**: All API routes (`/api/ai-chat`, `/api/ai-summary`, `/api/steampipe`) include IP-based memory-safe sliding window rate limiters (with garbage collection to prevent memory leaks in production). 

## ⚖️ License
MIT License.
