import { Cpu } from 'lucide-react';
import { calculateAnomalyScore, mockRuntimeEvents } from '../../../services/runtimeMonitor';

interface MLWorkloadsProps {
    selectedCloud: 'all' | 'aws' | 'gcp' | 'azure';
}

export function MLWorkloads({ selectedCloud }: MLWorkloadsProps) {
    const events = selectedCloud === 'all'
        ? mockRuntimeEvents
        : mockRuntimeEvents.filter((e) => e.provider === selectedCloud);

    return (
        <div className="surface-card flex-1 flex flex-col min-h-0">
            <div className="p-5 px-6 border-b border-white/5">
                <div className="flex items-center gap-2 mb-1">
                    <Cpu size={16} className="text-purple-400" />
                    <span className="text-base font-semibold tracking-tight text-white">Active ML Workloads</span>
                </div>
                <div className="text-[10px] uppercase font-bold tracking-wider text-purple-400/60">
                    Real-time Behavioral Analysis
                </div>
            </div>

            <div className="custom-scrollbar p-0 overflow-y-auto flex-1 flex flex-col">
                {events.map((event) => {
                    const { score, threatLevel } = calculateAnomalyScore(event);
                    const lvlColor =
                        threatLevel === 'HIGH'
                            ? 'text-red-400'
                            : threatLevel === 'MEDIUM'
                                ? 'text-orange-400'
                                : 'text-green-400';

                    return (
                        <div
                            key={event.instanceId}
                            className="px-6 py-4 border-b border-white/5 hover:bg-white/[0.02] transition-colors last:border-0 relative group flex-shrink-0"
                        >
                            <div className="absolute left-0 top-0 bottom-0 w-[2px] bg-transparent group-hover:bg-purple-500/50 transition-colors" />
                            <div className="flex justify-between items-center mb-1.5">
                                <span className="font-mono text-[0.9rem] font-medium text-white/90">
                                    {event.instanceId}
                                </span>
                                <span className={`font-mono text-base font-bold ${lvlColor}`} suppressHydrationWarning>
                                    {score}
                                </span>
                            </div>
                            <div className="flex justify-between items-center text-xs">
                                <span className="text-white/50" suppressHydrationWarning>
                                    CPU: <span className="text-white/80">{event.cpuUsage}%</span>
                                </span>
                                <span
                                    className={event.suspiciousPorts.length > 0 ? 'text-red-400/80' : 'text-white/40'}
                                    suppressHydrationWarning>
                                    Ports: {event.suspiciousPorts.length > 0 ? event.suspiciousPorts.join(',') : 'Standard'}
                                </span>
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
