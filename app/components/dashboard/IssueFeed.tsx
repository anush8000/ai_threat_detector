import { Activity, CheckCircle } from 'lucide-react';
import { SecurityIssue } from './types';

interface IssueFeedProps {
    issues: SecurityIssue[];
    expandedId: string | null;
    setExpandedId: (id: string | null) => void;
}

export function IssueFeed({ issues, expandedId, setExpandedId }: IssueFeedProps) {
    return (
        <div className="surface-card flex flex-col h-[750px] overflow-hidden">
            <div className="p-5 px-6 flex items-center justify-between border-b border-white/5">
                <div className="flex items-center gap-2">
                    <Activity size={16} className="text-blue-500" />
                    <span className="text-base font-medium tracking-tight">Configuration & Vulnerabilities</span>
                </div>
                <span className="status-pill low">{issues.length} Items</span>
            </div>

            <div className="custom-scrollbar flex-1 overflow-y-auto p-2">
                {issues.length === 0 ? (
                    <div className="p-20 text-center flex flex-col items-center justify-center h-full">
                        <CheckCircle size={32} className="text-green-500 mb-4" />
                        <div className="text-xl font-medium tracking-tight">All Clear</div>
                        <div className="text-sm text-white/50 mt-2">Infrastructure conforms to security baselines.</div>
                    </div>
                ) : (
                    issues.map((issue) => {
                        const open = expandedId === issue.id;
                        const sevStyle = issue.severity;

                        return (
                            <div key={issue.id} className="mb-2">
                                <div
                                    className={`interactive-row ${open ? 'bg-white/[0.04]' : ''}`}
                                    onClick={() => setExpandedId(open ? null : issue.id)}
                                >
                                    <div className="flex gap-4">
                                        <div className="mt-1">
                                            <div className={`status-pill ${sevStyle}`}>{issue.severity}</div>
                                        </div>
                                        <div className="flex-1">
                                            <div className="flex items-baseline gap-3 mb-1">
                                                <span className="text-sm font-semibold font-mono">{issue.id}</span>
                                                {issue.cisControl && (
                                                    <span className="text-[10px] font-bold tracking-wider text-blue-400 uppercase">
                                                        {issue.cisControl}
                                                    </span>
                                                )}
                                                <span className="text-xs text-white/40 font-medium">{issue.resource}</span>
                                            </div>
                                            <div className="text-[0.95rem] font-medium text-white mb-1.5">{issue.type}</div>
                                            <div className="text-sm text-white/60 leading-relaxed">{issue.description}</div>
                                        </div>
                                    </div>
                                </div>

                                {open && issue.remediationHint && (
                                    <div className="m-2 mt-0 p-4 bg-green-500/[0.03] border border-green-500/20 rounded-xl animate-enter">
                                        <div className="text-[10px] uppercase font-bold tracking-wider text-green-500 mb-2">
                                            RECOMMENDED REMEDIATION
                                        </div>
                                        <div className="font-mono text-xs text-white/90">
                                            <span className="text-green-500 mr-2">$</span>
                                            {issue.remediationHint}
                                        </div>
                                    </div>
                                )}
                            </div>
                        );
                    })
                )}
            </div>
        </div>
    );
}
