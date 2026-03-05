'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import { calculateRiskScore, Issue as RiskIssue } from '../../utils/riskScore';
import { getThreatCategory } from '../../utils/threatCategory';
import { compareScans } from '../../utils/driftDetection';

// Import extracted components
import { SecurityIssue, DashboardStats, SteampipeResponse, TrendPoint } from './dashboard/types';
import { CLOUD_CHECKS, MOCK_ISSUES } from './dashboard/constants';
import { DashboardHeader } from './dashboard/DashboardHeader';
import { StatCards } from './dashboard/StatCards';
import { IssueFeed } from './dashboard/IssueFeed';
import { AICopilot } from './dashboard/AICopilot';
import { MLWorkloads } from './dashboard/MLWorkloads';
import { ComplianceCharts, RiskTrendChart } from './dashboard/ComplianceChart';
import { DashboardSkeleton } from './dashboard/DashboardSkeleton';

// Compliance score calc
function getComplianceScore(issues: SecurityIssue[], availableChecks: ReturnType<typeof CLOUD_CHECKS.filter>) {
  const allPrefixes = [...new Set(availableChecks.map((c) => c.id.split('_')[0]))];
  const failPrefixes = [
    ...new Set(issues.map((i) => i.checkId?.split('_')[0]).filter(Boolean) as string[]),
  ];
  const passCount = allPrefixes.filter((p) => !failPrefixes.includes(p)).length;
  const percentage = allPrefixes.length === 0 ? 100 : Math.round((passCount / allPrefixes.length) * 100);
  return { score: percentage, pass: passCount, total: allPrefixes.length };
}

export default function Dashboard() {
  const [selectedCloud, setSelectedCloud] = useState<'all' | 'aws' | 'gcp' | 'azure'>('all');

  const [stats, setStats] = useState<DashboardStats>({
    publicS3Buckets: 0, publicInstances: 0, openSecurityGroups: 0,
    totalInstances: 0, criticalIssues: 0, highIssues: 0, totalRiskScore: 0,
  });

  const [issues, setIssues] = useState<SecurityIssue[]>([]);
  const [prevIssues, setPrevIssues] = useState<SecurityIssue[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [riskTrend, setRiskTrend] = useState<TrendPoint[]>([]);
  const [loading, setLoading] = useState(true);

  // AI Copilot state
  const [aiSummary, setAiSummary] = useState<string>('');
  const [generatingAI, setGeneratingAI] = useState(false);
  const [aiError, setAiError] = useState('');
  const [chatHistory, setChatHistory] = useState<{ role: 'user' | 'assistant'; content: string }[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [sendingChat, setSendingChat] = useState(false);

  const processIssues = useCallback((raw: SecurityIssue[]): SecurityIssue[] => {
    const publicChecks = new Set(['S3_PUBLIC', 'EC2_PUBLIC', 'SG_OPEN', 'SG_SSH', 'SG_RDP', 'RDS_PUBLIC', 'LAMBDA_PUBLIC', 'GCP_STORAGE_PUBLIC', 'GCP_COMPUTE_PUBLIC', 'AZURE_VM_PUBLIC', 'AZURE_BLOB_PUBLIC']);
    return raw.map((issue) => {
      const exposure: RiskIssue['exposure'] = publicChecks.has(issue.checkId || '') ? 'Public' : 'Internal';
      const ri: RiskIssue = { ...issue, exposure };
      return { ...issue, riskScore: calculateRiskScore(ri), threatCategory: getThreatCategory(ri) };
    });
  }, []);

  const setMockData = useCallback(() => {
    const mocksToRun = selectedCloud === 'all' ? MOCK_ISSUES : MOCK_ISSUES.filter((m) => m.provider === selectedCloud);
    const processed = processIssues(mocksToRun);
    setPrevIssues(processed.slice(0, 4));
    setIssues(processed);

    const totalRisk = processed.reduce((s, i) => s + (i.riskScore || 0), 0);
    setStats({
      publicS3Buckets: mocksToRun.filter((i) => ['S3_PUBLIC', 'GCP_STORAGE_PUBLIC', 'AZURE_BLOB_PUBLIC'].includes(i.checkId!)).length,
      publicInstances: mocksToRun.filter((i) => ['EC2_PUBLIC', 'GCP_COMPUTE_PUBLIC', 'AZURE_VM_PUBLIC'].includes(i.checkId!)).length,
      openSecurityGroups: mocksToRun.filter((i) => ['SG_OPEN', 'SG_SSH', 'SG_RDP'].includes(i.checkId!)).length,
      totalInstances: 15,
      criticalIssues: processed.filter((i) => i.severity === 'critical').length,
      highIssues: processed.filter((i) => i.severity === 'high').length,
      totalRiskScore: totalRisk,
    });

    const timeLabel = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    setRiskTrend([{ time: timeLabel, score: totalRisk }, { time: timeLabel, score: totalRisk }]);
  }, [processIssues, selectedCloud]);

  const fetchSecurityData = useCallback(async () => {
    setLoading(true);
    setAiSummary('');
    setChatHistory([]);
    try {
      const checksToRun = selectedCloud === 'all' ? CLOUD_CHECKS : CLOUD_CHECKS.filter((c) => c.provider === selectedCloud);
      const results = await Promise.allSettled(
        checksToRun.map((check) =>
          fetch(`/api/steampipe?checkId=${encodeURIComponent(check.id)}`)
            .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
            .then((data: SteampipeResponse) => ({ check, rows: data.rows || [] }))
        )
      );

      const allIssues: SecurityIssue[] = [];
      let anySuccess = false;

      results.forEach((r) => {
        if (r.status === 'fulfilled') {
          anySuccess = true;
          r.value.rows.forEach((row) => {
            try { allIssues.push(r.value.check.mapRow(row)); } catch { /* skip */ }
          });
        }
      });

      if (!anySuccess) throw new Error('All checks failed');

      const processed = processIssues(allIssues);
      setPrevIssues((prev) => (prev.length > 0 ? prev : processed));
      setIssues(processed);

      const totalRisk = processed.reduce((s, i) => s + (i.riskScore || 0), 0);
      setStats({
        publicS3Buckets: allIssues.filter((i) => ['S3_PUBLIC', 'GCP_STORAGE_PUBLIC', 'AZURE_BLOB_PUBLIC'].includes(i.checkId!)).length,
        publicInstances: allIssues.filter((i) => ['EC2_PUBLIC', 'GCP_COMPUTE_PUBLIC', 'AZURE_VM_PUBLIC'].includes(i.checkId!)).length,
        openSecurityGroups: allIssues.filter((i) => ['SG_OPEN', 'SG_SSH', 'SG_RDP'].includes(i.checkId!)).length,
        totalInstances: 0,
        criticalIssues: processed.filter((i) => i.severity === 'critical').length,
        highIssues: processed.filter((i) => i.severity === 'high').length,
        totalRiskScore: totalRisk,
      });

      const timeLabel = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
      setRiskTrend((prev) => {
        if (prev.length === 0) return [{ time: timeLabel, score: totalRisk }, { time: timeLabel, score: totalRisk }];
        return [...prev.slice(-9), { time: timeLabel, score: totalRisk }];
      });
    } catch {
      setMockData();
    } finally {
      setLoading(false);
    }
  }, [processIssues, setMockData, selectedCloud]);

  useEffect(() => {
    fetchSecurityData();
  }, [fetchSecurityData]);

  const generateAISummary = async () => {
    setGeneratingAI(true);
    setAiError('');
    setChatHistory([]);
    setChatInput('');
    try {
      const counts = {
        critical: issues.filter((i) => i.severity === 'critical').length,
        high: issues.filter((i) => i.severity === 'high').length,
        medium: issues.filter((i) => i.severity === 'medium').length,
        low: issues.filter((i) => i.severity === 'low').length,
      };

      const checksToRun = selectedCloud === 'all' ? CLOUD_CHECKS : CLOUD_CHECKS.filter((c) => c.provider === selectedCloud);
      const compliance = getComplianceScore(issues, checksToRun);

      const res = await fetch('/api/ai-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          issues: issues.slice(0, 8).map((i) => ({ type: i.type, description: i.description, severity: i.severity })),
          riskScore: stats.totalRiskScore,
          complianceScore: compliance.score,
          counts,
        }),
      });

      if (!res.ok) throw new Error((await res.json()).error || 'API Error');
      const data = await res.json();
      setAiSummary(data.summary);
    } catch (e) {
      setAiError(e instanceof Error ? e.message : 'Error generating AI analysis.');
    } finally {
      setGeneratingAI(false);
    }
  };

  const handleSendChat = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!chatInput.trim() || sendingChat) return;

    const newUserMsg = { role: 'user' as const, content: chatInput.trim() };
    setChatHistory((prev) => [...prev, newUserMsg]);
    setChatInput('');
    setSendingChat(true);

    try {
      const res = await fetch('/api/ai-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: [...chatHistory, newUserMsg], context: aiSummary }),
      });
      const data = await res.json();
      if (data.reply) {
        setChatHistory((prev) => [...prev, { role: 'assistant', content: data.reply }]);
      }
    } catch (err) {
      console.error('Chat error:', err);
    } finally {
      setSendingChat(false);
    }
  };

  const drift = compareScans(prevIssues, issues);

  const checksToRunForCompliance = selectedCloud === 'all' ? CLOUD_CHECKS : CLOUD_CHECKS.filter((c) => c.provider === selectedCloud);
  const complianceScore = getComplianceScore(issues, checksToRunForCompliance).score;

  const getServiceCategory = (checkId: string) => {
    if (!checkId) return 'Other';
    if (checkId.startsWith('GCP_')) return `GCP ${checkId.split('_')[1] || ''}`;
    if (checkId.startsWith('AZURE_')) return `Azure ${checkId.split('_')[1] || ''}`;
    return checkId.split('_')[0];
  };

  const pieData = useMemo(() => {
    return [
      { name: 'Critical', value: stats.criticalIssues },
      { name: 'High', value: stats.highIssues },
      { name: 'Medium', value: issues.filter((i) => i.severity === 'medium').length },
      { name: 'Low', value: issues.filter((i) => i.severity === 'low').length },
    ].filter((d) => d.value > 0);
  }, [stats.criticalIssues, stats.highIssues, issues]);

  const catData = useMemo(() => {
    return [...new Set(issues.map((i) => getServiceCategory(i.checkId || '')))]
      .map((cat) => ({
        category: cat,
        count: issues.filter((i) => getServiceCategory(i.checkId || '') === cat).length,
      }))
      .sort((a, b) => b.count - a.count);
  }, [issues]);

  const anomaliesCount = 1; // You can pull actual count if necessary from mockRuntimeEvents like in MLWorkload

  if (loading && issues.length === 0) {
    return <DashboardSkeleton />;
  }

  return (
    <div className="flex flex-col min-h-screen bg-[#000000]">
      <DashboardHeader
        selectedCloud={selectedCloud}
        setSelectedCloud={setSelectedCloud}
        loading={loading}
        onRefresh={fetchSecurityData}
      />

      <main className="py-8 px-7 max-w-[1600px] mx-auto w-full flex flex-col gap-8 flex-1">
        <StatCards
          stats={stats}
          issues={issues}
          addedIssuesCount={drift.added.length}
          complianceScore={complianceScore}
          anomaliesCount={anomaliesCount}
        />

        <section className="grid grid-cols-1 lg:grid-cols-[1fr_380px] gap-4 animate-enter" style={{ animationDelay: '0.1s' }}>
          <IssueFeed
            issues={issues}
            expandedId={expandedId}
            setExpandedId={setExpandedId}
          />

          <div className="flex flex-col gap-4 h-[750px]">
            <AICopilot
              generatingAI={generatingAI}
              aiError={aiError}
              aiSummary={aiSummary}
              chatHistory={chatHistory}
              chatInput={chatInput}
              setChatInput={setChatInput}
              sendingChat={sendingChat}
              generateAISummary={generateAISummary}
              handleSendChat={handleSendChat}
            />
            <MLWorkloads selectedCloud={selectedCloud} />
            <RiskTrendChart riskTrend={riskTrend} />
          </div>
        </section>

        <ComplianceCharts pieData={pieData} catData={catData} />
      </main>
    </div>
  );
}
