import { DashboardStats, SecurityIssue } from './types';

interface StatCardsProps {
    stats: DashboardStats;
    issues: SecurityIssue[];
    addedIssuesCount: number;
    complianceScore: number;
    anomaliesCount: number;
}

export function StatCards({ stats, issues, addedIssuesCount, complianceScore, anomaliesCount }: StatCardsProps) {
    const riskColor =
        stats.totalRiskScore > 100
            ? 'var(--accent-red)'
            : stats.totalRiskScore > 50
                ? 'var(--accent-orange)'
                : 'var(--accent-green)';

    return (
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 animate-enter" style={{ animationDelay: '0s' }}>
            <div className="surface-card p-6">
                <div className="text-xs uppercase font-medium tracking-widest text-white/60 mb-2">Total Risk Score</div>
                <div className="text-[3.5rem] leading-none font-semibold tracking-tighter tabular-nums" style={{ color: riskColor }}>
                    {stats.totalRiskScore}
                </div>
                <div className="text-sm text-white/40 mt-2">Aggregated system vulnerability</div>
            </div>

            <div className="surface-card p-6">
                <div className="text-xs uppercase font-medium tracking-widest text-white/60 mb-2">Active Issues</div>
                <div className="text-[3.5rem] leading-none font-semibold tracking-tighter tabular-nums text-white">
                    {issues.length}
                </div>
                <div className="text-sm text-white/40 mt-2">+{addedIssuesCount} newly detected</div>
            </div>

            <div className="surface-card p-6">
                <div className="text-xs uppercase font-medium tracking-widest text-white/60 mb-2">Compliance Status</div>
                <div className="text-[3.5rem] leading-none font-semibold tracking-tighter tabular-nums text-green-500">
                    {complianceScore}%
                </div>
                <div className="mt-3">
                    <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
                        <div
                            className="h-full rounded-full bg-green-500 transition-all duration-1000 ease-out"
                            style={{ width: `${complianceScore}%` }}
                        />
                    </div>
                </div>
            </div>

            <div className="surface-card p-6">
                <div className="text-xs uppercase font-medium tracking-widest text-white/60 mb-2">Runtime Anomalies</div>
                <div className="text-[3.5rem] leading-none font-semibold tracking-tighter tabular-nums text-orange-500" suppressHydrationWarning>
                    {anomaliesCount}
                </div>
                <div className="text-sm text-white/40 mt-2">ML Behavior Detection Engine</div>
            </div>
        </section>
    );
}
