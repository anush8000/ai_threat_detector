'use client';

import { useEffect, useState, useCallback } from 'react';
import { 
  Shield, Lock, Sparkles, 
  Activity, Zap, TrendingUp, BarChart3, ShieldAlert, Cpu, Terminal 
} from 'lucide-react';
import { calculateRiskScore, Issue as RiskIssue } from '../../utils/riskScore';
import { getThreatCategory } from '../../utils/threatCategory';
import { compareScans } from '../../utils/driftDetection';
import { calculateAnomalyScore, mockRuntimeEvents } from '../../services/runtimeMonitor';

interface SecurityIssue {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  resource: string;
  description: string;
  region?: string;
  threatCategory?: string;
  riskScore?: number;
}

interface DashboardStats {
  publicS3Buckets: number;
  publicInstances: number;
  openSecurityGroups: number;
  totalInstances: number;
  criticalIssues: number;
  highIssues: number;
  totalRiskScore: number;
}

interface SteampipeResponse {
  rows: Record<string, unknown>[];
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats>({
    publicS3Buckets: 0,
    publicInstances: 0,
    openSecurityGroups: 0,
    totalInstances: 0,
    criticalIssues: 0,
    highIssues: 0,
    totalRiskScore: 0,
  });
  const [issues, setIssues] = useState<SecurityIssue[]>([]);
  const [prevIssues, setPrevIssues] = useState<SecurityIssue[]>([]);
  const [aiSummary, setAiSummary] = useState<string>('');
  const [generatingAI, setGeneratingAI] = useState(false);
  const [usingMock, setUsingMock] = useState(false);
  useEffect(() => {
  fetch("/api/scan")
    .then(res => res.json())
    .then(data => {
      setStats(prev => ({
        ...prev,
        totalRiskScore: data.riskScore,
        criticalIssues: data.severity === "CRITICAL" ? 1 : 0,
        highIssues: data.severity === "HIGH" ? 1 : 0,
        openSecurityGroups: data.publicExposure ? 1 : 0,
      }));
    });
}, []);

  const processIssues = useCallback((rawIssues: SecurityIssue[]): SecurityIssue[] => {
    return rawIssues.map(issue => {
      const riskIssue: RiskIssue = {
        ...issue,
        exposure: issue.type.includes('Public') || issue.type.includes('Permissive') ? 'Public' : 'Internal'
      };
      return {
        ...issue,
        riskScore: calculateRiskScore(riskIssue),
        threatCategory: getThreatCategory(riskIssue)
      };
    });
  }, []);

  const setMockData = useCallback(() => {
    const mockIssues: SecurityIssue[] = [
      {
        id: '1', severity: 'critical', type: 'Overly Permissive Security Group',
        resource: 'sg-web-server (sg-0a1b2c3d4e5f6)',
        description: '"sg-web-server" allows unrestricted inbound traffic (0.0.0.0/0) in VPC: vpc-12345678 — Web server SG',
        region: 'us-east-1',
      },
      {
        id: '2', severity: 'high', type: 'Public S3 Bucket',
        resource: 'customer-data-backup',
        description: 'Bucket "customer-data-backup" has public access — ACLs: ❌ Policy: ❌ IgnoreACL: ❌ Restrict: ❌',
        region: 'us-west-2',
      },
      {
        id: '3', severity: 'high', type: 'Public S3 Bucket',
        resource: 'app-logs-2024',
        description: 'Bucket "app-logs-2024" has public access — ACLs: ❌ Policy: ✅ IgnoreACL: ❌ Restrict: ✅',
        region: 'eu-west-1',
      },
      {
        id: '4', severity: 'medium', type: 'Public EC2 Instance',
        resource: 'web-server-prod (t3.medium)',
        description: 'Instance "i-0abc123def456" is publicly accessible — IP: 54.123.45.67 | DNS: ec2-54-123-45-67.compute-1.amazonaws.com',
        region: 'us-east-1',
      },
      {
        id: '5', severity: 'medium', type: 'Public EC2 Instance',
        resource: 'api-server-01 (t3.large)',
        description: 'Instance "i-0def456abc123" is publicly accessible — IP: 52.98.76.54',
        region: 'us-west-2',
      },
      {
        id: '6', severity: 'critical', type: 'Overly Permissive Security Group',
        resource: 'sg-database (sg-9z8y7x6w5v4)',
        description: '"sg-database" allows unrestricted inbound traffic (0.0.0.0/0) in VPC: vpc-87654321 — DB SG with SSH open',
        region: 'us-east-1',
      },
    ];
    const processed = processIssues(mockIssues);
    setPrevIssues(processed.slice(0, 4));
    setIssues(processed);
    const totalRisk = processed.reduce((sum, i) => sum + (i.riskScore || 0), 0);
    setStats({ 
      publicS3Buckets: 2, 
      publicInstances: 2, 
      openSecurityGroups: 2, 
      totalInstances: 15, 
      criticalIssues: 2, 
      highIssues: 2,
      totalRiskScore: totalRisk
    });
  }, [processIssues]);

  const fetchSecurityData = useCallback(async () => {
    try {
      setUsingMock(false);

      const s3Query = `
        SELECT name, block_public_acls, block_public_policy,
               ignore_public_acls, restrict_public_buckets, region
        FROM aws_s3_bucket
        WHERE NOT block_public_acls OR NOT block_public_policy
           OR NOT ignore_public_acls OR NOT restrict_public_buckets
      `;
      const ec2Query = `
        SELECT instance_id, instance_type, region,
               public_ip_address, public_dns_name, tags
        FROM aws_ec2_instance
        WHERE public_ip_address IS NOT NULL
        LIMIT 50
      `;
      const sgQuery = `
        SELECT group_id, group_name, description, region, vpc_id
        FROM aws_vpc_security_group
        WHERE ip_permissions::text LIKE '%0.0.0.0/0%'
        LIMIT 50
      `;
      const totalQuery = `SELECT COUNT(*) as total FROM aws_ec2_instance`;

      const [s3Res, ec2Res, sgRes, totalRes] = await Promise.allSettled([
        fetch(`/api/steampipe?query=${encodeURIComponent(s3Query)}`),
        fetch(`/api/steampipe?query=${encodeURIComponent(ec2Query)}`),
        fetch(`/api/steampipe?query=${encodeURIComponent(sgQuery)}`),
        fetch(`/api/steampipe?query=${encodeURIComponent(totalQuery)}`),
      ]);

      let s3Data: SteampipeResponse = { rows: [] };
      let ec2Data: SteampipeResponse = { rows: [] };
      let sgData: SteampipeResponse = { rows: [] };
      let totalData: SteampipeResponse = { rows: [{ total: 0 }] };

      if (s3Res.status === 'fulfilled' && s3Res.value.ok) s3Data = await s3Res.value.json();
      if (ec2Res.status === 'fulfilled' && ec2Res.value.ok) ec2Data = await ec2Res.value.json();
      if (sgRes.status === 'fulfilled' && sgRes.value.ok) sgData = await sgRes.value.json();
      if (totalRes.status === 'fulfilled' && totalRes.value.ok) totalData = await totalRes.value.json();

      const securityIssues: SecurityIssue[] = [];

      s3Data.rows?.forEach((b) => {
        securityIssues.push({
          id: `s3-${b.name}`,
          severity: 'high',
          type: 'Public S3 Bucket',
          resource: String(b.name),
          description: `Bucket &quot;${b.name}&quot; has public access — ACLs: ${b.block_public_acls ? '✅' : '❌'} Policy: ${b.block_public_policy ? '✅' : '❌'} IgnoreACL: ${b.ignore_public_acls ? '✅' : '❌'} Restrict: ${b.restrict_public_buckets ? '✅' : '❌'}`,
          region: String(b.region),
        });
      });

      ec2Data.rows?.forEach((i) => {
        const tags = i.tags as Record<string, string> | undefined;
        const name = tags?.Name || i.instance_id;
        securityIssues.push({
          id: `ec2-${i.instance_id}`,
          severity: 'medium',
          type: 'Public EC2 Instance',
          resource: `${name} (${i.instance_type})`,
          description: `Instance &quot;${i.instance_id}&quot; is publicly accessible — IP: ${i.public_ip_address}${i.public_dns_name ? ' | DNS: ' + i.public_dns_name : ''}`,
          region: String(i.region),
        });
      });

      sgData.rows?.forEach((sg) => {
        const name = sg.group_name || sg.group_id;
        securityIssues.push({
          id: `sg-${sg.group_id}`,
          severity: 'critical',
          type: 'Overly Permissive Security Group',
          resource: `${name} (${sg.group_id})`,
          description: `&quot;${name}&quot; allows unrestricted inbound traffic (0.0.0.0/0)${sg.vpc_id ? ' in VPC: ' + sg.vpc_id : ''}${sg.description ? ' — ' + sg.description : ''}`,
          region: String(sg.region),
        });
      });

      const processed = processIssues(securityIssues);
      setPrevIssues(prev => prev.length > 0 ? prev : processed);
      setIssues(processed);
      
      const totalRisk = processed.reduce((sum, i) => sum + (i.riskScore || 0), 0);

      setStats({
        publicS3Buckets: s3Data.rows?.length || 0,
        publicInstances: ec2Data.rows?.length || 0,
        openSecurityGroups: sgData.rows?.length || 0,
        totalInstances: Number((totalData.rows?.[0] as { total: number })?.total || 0),
        criticalIssues: processed.filter(i => i.severity === 'critical').length,
        highIssues: processed.filter(i => i.severity === 'high').length,
        totalRiskScore: totalRisk,
      });
    } catch (err) {
      console.error('Error fetching security data:', err);
      setUsingMock(true);
      setMockData();
    }
  }, [processIssues, setMockData]);

  useEffect(() => {
    fetchSecurityData();
  }, [fetchSecurityData]);

  const generateAISummary = async () => {
    setGeneratingAI(true);
    try {
      const prompt = `You are a senior cloud security expert. Analyze these findings:
   
Security Statistics:
- Public S3 Buckets: ${stats.publicS3Buckets}
- Public EC2 Instances: ${stats.publicInstances}
- Overly Permissive Security Groups: ${stats.openSecurityGroups}
- Total Risk Score: ${stats.totalRiskScore}
- Critical Issues: ${stats.criticalIssues}

Provide a concise summary and risk assessment.`;

      const res = await fetch('/api/ai-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt }),
      });

      if (!res.ok) throw new Error('API Error');
      const data = await res.json();
      setAiSummary(data.summary);
    } catch {
      setAiSummary(`❌ Error generating AI analysis.`);
    } finally {
      setGeneratingAI(false);
    }
  };

  const drift = compareScans(prevIssues, issues);

  const severityColor = (s: string) => ({
    critical: 'bg-red-100 text-red-800 border-red-200',
    high:     'bg-orange-100 text-orange-800 border-orange-200',
    medium:   'bg-yellow-100 text-yellow-800 border-yellow-200',
    low:      'bg-blue-100 text-blue-800 border-blue-200',
  }[s] ?? 'bg-blue-100 text-blue-800 border-blue-200');

  const severityBadge = (s: string) => ({
    critical: 'bg-red-500 text-white',
    high:     'bg-orange-500 text-white',
    medium:   'bg-yellow-500 text-white',
    low:      'bg-blue-500 text-white',
  }[s] ?? 'bg-blue-500 text-white');

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 pb-12">
      <div className="bg-white border-b border-gray-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-6 py-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-10 h-10 text-blue-600" />
            <div>
              <h1 className="text-3xl font-bold text-gray-900">AI-Powered Threat Detection System</h1>
              <p className="text-gray-500 mt-1 text-sm font-medium">CSPM &amp; CWPP Security Dashboard</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="bg-blue-50 border border-blue-100 px-4 py-2 rounded-lg">
              <p className="text-xs text-blue-600 font-bold uppercase tracking-wider">Overall Risk Score</p>
              <p className="text-2xl font-black text-blue-900">{stats.totalRiskScore}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {usingMock && (
          <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-lg text-sm text-yellow-800">
            ⚠️ <strong>Steampipe not reachable.</strong> Showing mock data for demonstration.
          </div>
        )}
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-200">
            <div className="flex items-center gap-3 mb-2">
              <BarChart3 className="w-5 h-5 text-gray-400" />
              <h3 className="text-sm font-bold text-gray-800">Threat Risk Overview</h3>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-gray-100 border border-gray-300 p-4 rounded-lg shadow-sm">
                <p className="text-[10px] text-gray-800 uppercase font-bold">Total Issues</p>
                <p className="text-3xl font-extrabold text-gray-900">{issues.length}</p>
              </div>
              <div className="bg-red-50 p-2 rounded">
                <p className="text-[10px] text-red-400 uppercase font-bold">Critical</p>
                <p className="text-xl font-bold text-red-600">{stats.criticalIssues}</p>
              </div>
            </div>
          </div>

          <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-200">
            <div className="flex items-center gap-3 mb-2">
              <TrendingUp className="w-5 h-5 text-gray-400" />
              <h3 className="text-sm font-bold text-gray-600">Configuration Drift</h3>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-green-50 p-2 rounded">
                <p className="text-[10px] text-green-500 uppercase font-bold">New Detected</p>
                <p className="text-xl font-bold text-green-600">+{drift.added.length}</p>
              </div>
              <div className="bg-gray-50 p-2 rounded">
                <p className="text-[10px] text-gray-400 uppercase font-bold">Resolved</p>
                <p className="text-xl font-bold text-gray-500">-{drift.removed.length}</p>
              </div>
            </div>
          </div>

          <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-200 md:col-span-2">
            <div className="flex items-center gap-3 mb-2">
              <Zap className="w-5 h-5 text-yellow-500" />
              <h3 className="text-sm font-bold text-gray-600">Active Threat Mitigation</h3>
            </div>
            <div className="flex items-center gap-4">
               <div className="flex-1 bg-yellow-50 p-2 rounded border border-yellow-100">
                 <p className="text-[10px] text-yellow-600 uppercase font-bold">AI Mitigation Strategy</p>
                 <p className="text-xs text-yellow-800 mt-1 line-clamp-2">Analyzing {stats.criticalIssues} critical vectors for automated remediation paths.</p>
               </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2 space-y-8">
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
              <div className="px-6 py-4 bg-gray-50 border-b border-gray-200 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Activity className="w-5 h-5 text-blue-600" />
                  <h2 className="text-xl font-bold text-gray-900">CSPM Configuration Threat Detection</h2>
                </div>
                <button onClick={fetchSecurityData} className="text-xs font-bold text-blue-600 hover:text-blue-800 uppercase tracking-wider">
                  Refresh Scan
                </button>
              </div>
              <div className="p-6">
                <div className="space-y-4">
                  {issues.map(issue => (
                    <div key={issue.id} className={`${severityColor(issue.severity)} rounded-lg p-4 border flex items-start gap-4`}>
                      <div className={`mt-1 p-2 rounded-lg ${severityBadge(issue.severity)}`}>
                        <ShieldAlert className="w-4 h-4" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-[10px] font-black uppercase px-1.5 py-0.5 rounded bg-white/50 border border-current">
                            {issue.threatCategory}
                          </span>
                          <h3 className="font-bold text-sm">{issue.type}</h3>
                        </div>
                        <p className="text-xs opacity-80 mb-2">{issue.description}</p>
                        <div className="flex items-center gap-4 text-[10px] font-bold uppercase tracking-tight opacity-60">
                          <span className="flex items-center gap-1"><Lock className="w-3 h-3" /> {issue.resource}</span>
                          <span className="flex items-center gap-1"><Zap className="w-3 h-3" /> Risk Score: {issue.riskScore}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-slate-900 rounded-xl shadow-xl border border-slate-800 overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-3 bg-slate-900/50">
                <Terminal className="w-5 h-5 text-emerald-400" />
                <h2 className="text-xl font-bold text-white">CWPP Runtime Threat Detection</h2>
                <span className="ml-auto px-2 py-0.5 rounded text-[10px] font-black bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 uppercase tracking-widest">Live Monitoring</span>
              </div>
              <div className="p-6 space-y-4">
                {mockRuntimeEvents.map(event => {
                  const { score, threatLevel } = calculateAnomalyScore(event);
                  return (
                    <div key={event.instanceId} className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 flex items-center gap-6">
                      <div className="p-3 bg-slate-800 rounded-full border border-slate-700">
                        <Cpu className={`w-6 h-6 ${threatLevel === 'HIGH' ? 'text-red-400 animate-pulse' : 'text-emerald-400'}`} />
                      </div>
                      <div className="flex-1 grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div>
                          <p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Instance ID</p>
                          <p className="text-xs text-slate-300 font-mono truncate">{event.instanceId}</p>
                        </div>
                        <div>
                          <p className="text-[10px] text-slate-500 font-bold uppercase mb-1">CPU Load</p>
                          <p className={`text-sm font-bold ${event.cpuUsage > 80 ? 'text-red-400' : 'text-slate-300'}`}>{event.cpuUsage}%</p>
                        </div>
                        <div>
                          <p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Suspicious Ports</p>
                          <p className="text-xs text-slate-300">{event.suspiciousPorts.length > 0 ? event.suspiciousPorts.join(', ') : 'None'}</p>
                        </div>
                        <div className="text-right">
                          <p className="text-[10px] text-slate-500 font-bold uppercase mb-1">Anomaly Index</p>
                          <span className={`text-[10px] font-black px-2 py-1 rounded border ${
                            threatLevel === 'HIGH' ? 'bg-red-500/20 text-red-400 border-red-500/30' : 
                            threatLevel === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                            'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                          }`}>
                            {threatLevel} ({score})
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="space-y-8">
            <div className="bg-gradient-to-b from-indigo-600 to-blue-700 rounded-xl shadow-lg border border-indigo-500/30 overflow-hidden text-white">
              <div className="p-6 border-b border-white/10 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-6 h-6 text-indigo-200" />
                  <h2 className="text-xl font-bold">AI Threat Analysis</h2>
                </div>
                <button 
                  onClick={generateAISummary}
                  disabled={generatingAI}
                  className="p-2 bg-white/10 hover:bg-white/20 rounded-lg transition-colors disabled:opacity-50"
                >
                  <Activity className={`w-4 h-4 ${generatingAI ? 'animate-spin' : ''}`} />
                </button>
              </div>
              <div className="p-6 space-y-4">
                {aiSummary ? (
                  <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4 border border-white/10">
                    <p className="text-sm text-indigo-50 leading-relaxed italic">&quot;{aiSummary}&quot;</p>
                  </div>
                ) : (
                  <div className="text-center py-8 opacity-60">
                    <Activity className="w-12 h-12 mx-auto mb-3 opacity-20" />
                    <p className="text-xs uppercase font-black tracking-widest">Ready for Deep Scan</p>
                  </div>
                )}
                <button 
                  onClick={generateAISummary}
                  disabled={generatingAI}
                  className="w-full py-3 bg-white text-indigo-700 rounded-xl font-black text-xs uppercase tracking-widest hover:bg-indigo-50 transition-all shadow-xl"
                >
                  {generatingAI ? 'Synthesizing...' : 'Run Neural Analysis'}
                </button>
              </div>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <h3 className="text-sm font-black text-gray-900 uppercase tracking-widest mb-4">Security Insights</h3>
              <div className="space-y-3">
                <div className="flex items-center gap-3 text-xs">
                  <div className="w-2 h-2 rounded-full bg-red-500" />
                  <span className="font-bold text-gray-700">Data Exposure Risk:</span>
                  <span className="ml-auto text-gray-500">{issues.filter(i => i.threatCategory === 'Data Exposure').length}</span>
                </div>
                <div className="flex items-center gap-3 text-xs">
                  <div className="w-2 h-2 rounded-full bg-orange-500" />
                  <span className="font-bold text-gray-700">Attack Surface:</span>
                  <span className="ml-auto text-gray-500">{issues.filter(i => i.threatCategory === 'Attack Surface').length}</span>
                </div>
                <div className="flex items-center gap-3 text-xs">
                  <div className="w-2 h-2 rounded-full bg-blue-500" />
                  <span className="font-bold text-gray-700">Network Exposure:</span>
                  <span className="ml-auto text-gray-500">{issues.filter(i => i.threatCategory === 'Network Exposure').length}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

       
      </div>
    </div>
  );
}
