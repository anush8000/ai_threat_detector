export interface SecurityIssue {
    id: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    type: string;
    resource: string;
    description: string;
    region?: string;
    threatCategory?: string;
    riskScore?: number;
    checkId?: string;
    cisControl?: string;
    remediationHint?: string;
    provider?: 'aws' | 'gcp' | 'azure';
}

export interface DashboardStats {
    publicS3Buckets: number;
    publicInstances: number;
    openSecurityGroups: number;
    totalInstances: number;
    criticalIssues: number;
    highIssues: number;
    totalRiskScore: number;
}

export interface SteampipeResponse {
    rows: Record<string, unknown>[];
}

export interface TrendPoint {
    time: string;
    score: number;
}

export interface CheckDef {
    id: string;
    provider: 'aws' | 'gcp' | 'azure';
    sql: string;
    mapRow: (row: Record<string, unknown>) => SecurityIssue;
}
