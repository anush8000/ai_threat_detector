export interface RuntimeEvent {
  instanceId: string;
  cpuUsage: number;
  suspiciousPorts: number[];
  outboundConnections: number;
}

export function calculateAnomalyScore(event: RuntimeEvent) {
  let score = 0;
  if (event.cpuUsage > 90) score += 40;
  const badPorts = [4444, 1337];
  const foundBadPorts = event.suspiciousPorts.filter(p => badPorts.includes(p));
  score += foundBadPorts.length * 30;
  if (event.outboundConnections > 200) score += 30;

  let threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
  if (score >= 70) threatLevel = 'HIGH';
  else if (score >= 40) threatLevel = 'MEDIUM';

  return { score, threatLevel };
}

export const mockRuntimeEvents: RuntimeEvent[] = [
  {
    instanceId: 'i-0abcdef1234567890',
    cpuUsage: 95,
    suspiciousPorts: [4444],
    outboundConnections: 250,
  },
  {
    instanceId: 'i-0987654321fedcba0',
    cpuUsage: 45,
    suspiciousPorts: [],
    outboundConnections: 50,
  }
];
