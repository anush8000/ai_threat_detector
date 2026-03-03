export interface Issue {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  resource: string;
  description: string;
  region?: string;
  exposure?: 'Public' | 'Internal' | 'Restricted';
  riskScore?: number;
}

export function calculateRiskScore(issue: Issue): number {
  const severityWeights = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
  };

  const exposureWeights = {
    Public: 5,
    Internal: 3,
    Restricted: 1,
  };

  const sWeight = severityWeights[issue.severity] || 1;
  const eWeight = exposureWeights[issue.exposure || 'Internal'];

  return sWeight * eWeight;
}
