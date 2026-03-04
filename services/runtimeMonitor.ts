// services/runtimeMonitor.ts
// UPGRADED: Isolation Forest ML replaces rule-based anomaly scoring
// INTERFACE UNCHANGED: mockRuntimeEvents + calculateAnomalyScore() work exactly 
// as before in Dashboard — just the scoring is now real ML (100 trees)

export interface RuntimeEvent {
  instanceId: string;
  cpuUsage: number;
  memoryUsage: number;
  networkIn: number;
  networkOut: number;
  suspiciousPorts: number[];
  processCount: number;
  diskReadIops: number;
  diskWriteIops: number;
  failedLogins: number;
}

// Return type kept compatible with existing Dashboard usage
export interface AnomalyScoreResult {
  score: number;
  threatLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  contributingFeatures: string[];
  recommendation: string;
}

// ─── ISOLATION FOREST IMPLEMENTATION ─────────────────────────────────────────
interface INode {
  leaf: boolean;
  size?: number;
  fi?: number;      // feature index
  sv?: number;      // split value
  left?: INode;
  right?: INode;
}

function c(n: number): number {
  if (n <= 1) return 0;
  const H = Math.log(n - 1) + 0.5772156649; // Euler-Mascheroni
  return 2 * H - (2 * (n - 1)) / n;
}

function buildNode(data: number[][], idx: number[], depth: number, maxDepth: number): INode {
  if (idx.length <= 1 || depth >= maxDepth) return { leaf: true, size: idx.length };
  const fi = Math.floor(Math.random() * data[0].length);
  const vals = idx.map(i => data[i][fi]);
  const min = Math.min(...vals), max = Math.max(...vals);
  if (min === max) return { leaf: true, size: idx.length };
  const sv = min + Math.random() * (max - min);
  return {
    leaf: false, fi, sv,
    left:  buildNode(data, idx.filter(i => data[i][fi] < sv),  depth + 1, maxDepth),
    right: buildNode(data, idx.filter(i => data[i][fi] >= sv), depth + 1, maxDepth),
  };
}

function pathLen(x: number[], node: INode, d: number): number {
  if (node.leaf) return d + c(node.size || 1);
  return x[node.fi!] < node.sv!
    ? pathLen(x, node.left!, d + 1)
    : pathLen(x, node.right!, d + 1);
}

class IsolationForest {
  private trees: INode[] = [];
  private n = 0;
  private means: number[] = [];
  private stds: number[] = [];

  fit(data: number[][], nTrees = 100, maxSamples = 256) {
    const nf = data[0].length;
    this.means = Array(nf).fill(0);
    this.stds  = Array(nf).fill(1);
    // Compute mean and std for normalization
    for (let f = 0; f < nf; f++) {
      const vals = data.map(r => r[f]);
      this.means[f] = vals.reduce((a, b) => a + b, 0) / vals.length;
      const variance = vals.reduce((a, b) => a + (b - this.means[f]) ** 2, 0) / vals.length;
      this.stds[f] = Math.sqrt(variance) || 1;
    }
    const norm = data.map(row => row.map((v, f) => (v - this.means[f]) / this.stds[f]));
    this.n = data.length;
    const maxDepth = Math.ceil(Math.log2(Math.min(maxSamples, this.n)));
    for (let t = 0; t < nTrees; t++) {
      const size = Math.min(maxSamples, norm.length);
      const idx: number[] = [];
      while (idx.length < size) idx.push(Math.floor(Math.random() * norm.length));
      this.trees.push(buildNode(norm, idx, 0, maxDepth));
    }
  }

  score(point: number[]): number {
    const norm = point.map((v, f) => (v - this.means[f]) / this.stds[f]);
    const avgLen = this.trees.reduce((s, t) => s + pathLen(norm, t, 0), 0) / this.trees.length;
    const raw = Math.pow(2, -avgLen / c(this.n));
    // Scale: raw ~0.5 = normal, ~1.0 = highly anomalous → map to 0-100
    return Math.round(Math.min(100, Math.max(0, (raw - 0.3) / 0.7 * 100)));
  }
}

// ─── TRAIN ON SYNTHETIC NORMAL BASELINE (executes once on module load) ────────
const _forest = new IsolationForest();
(() => {
  const baseline: number[][] = [];
  const r = (lo: number, hi: number) => lo + Math.random() * (hi - lo);
  for (let i = 0; i < 500; i++) {
    baseline.push([
      r(5, 70),    // cpuUsage: normal workload
      r(20, 75),   // memoryUsage
      r(0.1, 50),  // networkIn Mbps
      r(0.1, 30),  // networkOut Mbps
      r(10, 500),  // diskReadIops
      r(5, 200),   // diskWriteIops
      r(20, 150),  // processCount
      0,           // suspiciousPortCount: always 0 in normal
      r(0, 3),     // failedLogins: very low in normal
    ]);
  }
  _forest.fit(baseline);
})();

// ─── calculateAnomalyScore — same function name, same return shape ─────────────
export function calculateAnomalyScore(event: RuntimeEvent): AnomalyScoreResult {
  const features = [
    event.cpuUsage,
    event.memoryUsage,
    event.networkIn,
    event.networkOut,
    event.diskReadIops,
    event.diskWriteIops,
    event.processCount,
    event.suspiciousPorts.length,  // count of suspicious ports
    event.failedLogins,
  ];

  const score = _forest.score(features);
  const threatLevel: AnomalyScoreResult['threatLevel'] =
    score >= 70 ? 'HIGH' : score >= 45 ? 'MEDIUM' : 'LOW';

  // Identify which features contributed most to the anomaly
  const contributing: string[] = [];
  if (event.cpuUsage > 85)                  contributing.push(`High CPU (${event.cpuUsage}%)`);
  if (event.memoryUsage > 90)               contributing.push(`High Memory (${event.memoryUsage}%)`);
  if (event.networkOut > 100)               contributing.push(`Unusual Outbound Traffic (${event.networkOut} Mbps) — possible exfiltration`);
  if (event.suspiciousPorts.length > 0)     contributing.push(`Suspicious Ports Active: ${event.suspiciousPorts.join(', ')} — possible C2`);
  if (event.failedLogins > 10)              contributing.push(`Brute Force Detected (${event.failedLogins} failed logins/min)`);
  if (event.processCount > 300)             contributing.push(`Process Explosion (${event.processCount} processes)`);
  if (event.diskReadIops > 2000)            contributing.push(`Abnormal Disk Reads (${event.diskReadIops} IOPS) — possible data staging`);
  if (contributing.length === 0 && score >= 45) {
    contributing.push('Subtle behavioral deviation detected by Isolation Forest model');
  }

  const recommendation =
    score >= 70
      ? '⚠️ IMMEDIATE ACTION: Isolate instance, rotate IAM credentials, capture memory forensics, initiate incident response.'
      : score >= 45
      ? '🔍 INVESTIGATE: Review CloudTrail for this instance, check for unauthorized processes or cron jobs, inspect outbound connections.'
      : '✅ Normal workload behavior. Continue monitoring.';

  return { score, threatLevel, contributingFeatures: contributing, recommendation };
}

// ─── MOCK RUNTIME EVENTS (kept same shape — Dashboard reads these directly) ───
export const mockRuntimeEvents: RuntimeEvent[] = [
  {
    instanceId: 'i-0abcdef1234567890',
    cpuUsage: 95,
    memoryUsage: 88,
    networkIn: 5,
    networkOut: 180,      // HIGH outbound — data exfiltration pattern
    diskReadIops: 2500,   // HIGH reads — data staging
    diskWriteIops: 20,
    processCount: 320,    // HIGH process count
    suspiciousPorts: [4444, 1337],  // C2 framework ports
    failedLogins: 48,     // Brute force in progress
  },
  {
    instanceId: 'i-0987654321fedcba0',
    cpuUsage: 45,
    memoryUsage: 52,
    networkIn: 12,
    networkOut: 8,
    diskReadIops: 120,
    diskWriteIops: 60,
    processCount: 95,
    suspiciousPorts: [],
    failedLogins: 1,
  },
  {
    instanceId: 'i-0fedcba9876543210',
    cpuUsage: 12,
    memoryUsage: 35,
    networkIn: 2,
    networkOut: 350,      // VERY HIGH outbound — active exfiltration
    diskReadIops: 2500,   // Reading everything before exfil
    diskWriteIops: 10,
    processCount: 45,
    suspiciousPorts: [31337],  // Elite/leet port
    failedLogins: 0,
  },
];
