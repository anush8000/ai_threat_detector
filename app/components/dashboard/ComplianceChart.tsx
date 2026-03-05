import {
    ResponsiveContainer, PieChart, Pie, Cell, Tooltip,
    BarChart, Bar, XAxis, YAxis, AreaChart, Area
} from 'recharts';
import { TrendPoint } from './types';

interface ComplianceChartProps {
    pieData: { name: string; value: number }[];
    catData: { category: string; count: number }[];
}

interface RiskTrendChartProps {
    riskTrend: TrendPoint[];
}

export function RiskTrendChart({ riskTrend }: RiskTrendChartProps) {
    if (riskTrend.length <= 1) return null;

    return (
        <div className="surface-card p-6 flex flex-col justify-between flex-shrink-0">
            <div className="flex items-center justify-between mb-4">
                <div className="text-[10px] uppercase font-bold tracking-wider text-white/50">RISK EXPOSURE TREND</div>
                <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.6)] animate-pulse" />
                    <span className="text-xs text-blue-400 font-medium tracking-wide">Live</span>
                </div>
            </div>
            <div className="h-[140px] -mx-2">
                <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={riskTrend} margin={{ top: 5, right: 0, left: 0, bottom: 0 }}>
                        <defs>
                            <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                            </linearGradient>
                        </defs>
                        <XAxis dataKey="time" type="category" tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }} axisLine={false} tickLine={false} minTickGap={20} />
                        <YAxis tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }} axisLine={false} tickLine={false} domain={['auto', 'auto']} width={35} />
                        <Tooltip contentStyle={{ backgroundColor: 'rgba(0,0,0,0.8)', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }} itemStyle={{ color: '#fff' }} cursor={{ stroke: 'rgba(255,255,255,0.1)', strokeWidth: 1, strokeDasharray: '3 3' }} />
                        <Area type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorScore)" isAnimationActive={false} />
                    </AreaChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
}

export function ComplianceCharts({ pieData, catData }: ComplianceChartProps) {
    if (pieData.length === 0 && catData.length === 0) return null;

    return (
        <section className="grid grid-cols-1 lg:grid-cols-3 gap-4 animate-enter" style={{ animationDelay: '0.2s' }}>
            {pieData.length > 0 && (
                <div className="surface-card p-6 h-[300px]">
                    <div className="text-sm font-semibold tracking-tight mb-4 text-white">Severity Distribution</div>
                    <div className="w-full h-[200px]">
                        <ResponsiveContainer>
                            <PieChart>
                                <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} stroke="none" dataKey="value" paddingAngle={2}>
                                    {pieData.map((d, i) => {
                                        const bg = d.name === 'Critical' ? '#ef4444' : d.name === 'High' ? '#f97316' : d.name === 'Medium' ? '#eab308' : '#3b82f6';
                                        return <Cell key={i} fill={bg} />;
                                    })}
                                </Pie>
                                <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ backgroundColor: 'rgba(0,0,0,0.8)', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }} itemStyle={{ color: '#fff' }} />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            )}

            {catData.length > 0 && (
                <div className="surface-card p-6 h-[300px] lg:col-span-2">
                    <div className="text-sm font-semibold tracking-tight mb-4 text-white">Issues by Service Category</div>
                    <div className="w-full h-[200px]">
                        <ResponsiveContainer>
                            <BarChart data={catData.slice(0, 5)} layout="vertical" margin={{ left: -20, right: 10 }}>
                                <XAxis type="number" hide />
                                <YAxis dataKey="category" type="category" tick={{ fill: 'rgba(255,255,255,0.7)', fontSize: 11 }} axisLine={false} tickLine={false} width={80} />
                                <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} contentStyle={{ backgroundColor: 'rgba(0,0,0,0.8)', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }} itemStyle={{ color: '#fff' }} />
                                <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} barSize={16}>
                                    {catData.map((d, i) => <Cell key={i} fill={i % 2 === 0 ? '#3b82f6' : '#6366f1'} />)}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            )}
        </section>
    );
}
