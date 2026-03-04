# CloudGuard AI Upgrade — Install Guide
# Repo: ai_threat_detector | Port: 5000

## Step 1 — Install recharts (REQUIRED — not in your package.json)

cd ai_threat_detector
npm install recharts
npm install --save-dev @types/recharts

## Step 2 — Copy upgrade files into your project

# These 5 files are exact drop-in replacements:

cp upgrade/app/api/steampipe/route.ts          app/api/steampipe/route.ts
cp upgrade/app/api/ai-summary/route.ts         app/api/ai-summary/route.ts
cp upgrade/app/components/Dashboard.tsx        app/components/Dashboard.tsx
cp upgrade/services/runtimeMonitor.ts          services/runtimeMonitor.ts

# Create the new lib/rag/ directory and copy the knowledge base:
mkdir -p lib/rag
cp upgrade/lib/rag/securityKnowledgeBase.ts    lib/rag/securityKnowledgeBase.ts

## Step 3 — Verify your .env.local has both keys

cat .env.local
# Should contain:
# GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxx
# STEAMPIPE_PASSWORD=your_steampipe_password

## Step 4 — Start Steampipe (in WSL Ubuntu terminal)

steampipe service start
# Confirm it's on port 9193:
steampipe service status

## Step 5 — Run the app

npm run dev
# App runs at: http://localhost:5000

## What changed in each file:

### app/api/steampipe/route.ts
- FIXED: client.release() now in finally block (was leaking connections on error)
- ADDED: SQL injection protection (only SELECT allowed)
- ADDED: Pool config (max:10, connectionTimeout:8s, idleTimeout:30s)

### app/api/ai-summary/route.ts  
- ADDED: RAG engine import from lib/rag/securityKnowledgeBase.ts
- ADDED: Retrieves 4 relevant CIS/NIST controls before every Groq call
- ADDED: Structured prompt that cites real control IDs (CIS-5.3, CIS-2.1.5 etc)
- CHANGED: temperature 0.7 → 0.3 (more factual, less hallucination)
- KEPT: All your rate limiter logic exactly unchanged
- KEPT: Groq model (llama-3.3-70b-versatile) unchanged
- BACKWARD COMPATIBLE: Still handles old { prompt: string } format

### app/components/Dashboard.tsx
- EXPANDED: 3 checks → 20 checks (S3, EC2, IMDSv2, SG/SSH/RDP, IAM/MFA/OldKeys,
  CloudTrail/Validation, EBS, RDS/Public/Enc, KMS, VPC FlowLogs, Lambda, S3Logging)
- ADDED: Recharts PieChart (severity distribution)
- ADDED: Recharts BarChart (issues by AWS service)  
- ADDED: Recharts LineChart (risk score trend across refreshes)
- ADDED: CIS control badge on each issue card (e.g. "CIS-5.3")
- ADDED: Click-to-expand remediation command per issue
- ADDED: Compliance Score in header (% of check categories passing)
- ADDED: RAG AI sends structured issues array (not just plain text)
- ADDED: Shows retrieved CIS/NIST controls in AI panel after analysis
- KEPT: All existing imports (calculateRiskScore, getThreatCategory, compareScans)
- KEPT: Exact same UI layout (3-col, KPI cards, dark CWPP panel, indigo AI panel)
- KEPT: Mock data fallback with yellow warning banner

### services/runtimeMonitor.ts
- REPLACED: Rule-based calculateAnomalyScore() → Isolation Forest ML (100 trees)
- ADDED: Trains on 500 synthetic normal baseline samples on module load
- ADDED: Contributing features list (which signals triggered the anomaly)
- ADDED: Recommendation text per instance
- KEPT: mockRuntimeEvents — same exact shape your Dashboard already uses
- KEPT: Same function name and return type (score, threatLevel)

### lib/rag/securityKnowledgeBase.ts (NEW FILE)
- 18 CIS AWS Foundations v2.0 controls + NIST SP 800-53 controls
- Pure TypeScript TF-IDF cosine similarity engine (no external dependencies)
- retrieveControls(query, topK) — finds relevant controls for any issue text
- buildRAGPrompt() — builds structured prompt with CIS context injected

## Troubleshooting

### "Cannot find module recharts"
→ Run: npm install recharts

### "Cannot find module '@/lib/rag/securityKnowledgeBase'"  
→ Check tsconfig.json has: "paths": { "@/*": ["./*"] }
→ If not, add it. Or change the import to: '../../lib/rag/securityKnowledgeBase'

### "Steampipe connection refused"
→ All 20 checks will fail gracefully → mock data activates automatically
→ App still runs and demonstrates all features

### TypeScript path alias not working
In ai-summary/route.ts, change line 3 from:
  import { buildRAGPrompt, retrieveControls } from '@/lib/rag/securityKnowledgeBase';
to:
  import { buildRAGPrompt, retrieveControls } from '../../../lib/rag/securityKnowledgeBase';
