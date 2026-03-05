import { Shield, RefreshCw } from 'lucide-react';

interface DashboardHeaderProps {
    selectedCloud: 'all' | 'aws' | 'gcp' | 'azure';
    setSelectedCloud: (cloud: 'all' | 'aws' | 'gcp' | 'azure') => void;
    loading: boolean;
    onRefresh: () => void;
}

export function DashboardHeader({ selectedCloud, setSelectedCloud, loading, onRefresh }: DashboardHeaderProps) {
    return (
        <header className="h-[64px] bg-black/60 backdrop-blur-xl sticky top-0 z-50 flex items-center px-8">
            <div className="flex items-center gap-3 flex-1">
                <Shield size={20} className="text-white" />
                <span className="text-lg font-semibold tracking-tight">AI Powered Cloud Threat Detection System</span>
            </div>
            <div className="flex items-center gap-4">
                {/* MULTI-CLOUD TOGGLE */}
                <div className="hidden sm:flex items-center p-1 bg-white/5 border border-white/10 rounded-full mr-4 text-sm font-medium">
                    {(['all', 'aws', 'gcp', 'azure'] as const).map((cloud) => (
                        <button
                            key={cloud}
                            aria-label={`Filter by ${cloud} cloud`}
                            onClick={() => setSelectedCloud(cloud)}
                            className={`px-3 py-1 rounded-full transition-colors ${selectedCloud === cloud ? 'bg-white text-black' : 'text-white/60 hover:text-white'
                                }`}
                        >
                            {cloud === 'all' ? 'All Clouds' : cloud.toUpperCase()}
                        </button>
                    ))}
                </div>

                <div className="flex items-center gap-2">
                    <span className="text-[0.95rem] font-medium tracking-tight text-white/80">System Active</span>
                    <div className="live-pulse" />
                </div>
                <button
                    className="action-btn secondary"
                    onClick={onRefresh}
                    disabled={loading}
                    aria-label="Refresh Security Data"
                >
                    <RefreshCw size={14} className={`mr-1.5 ${loading ? 'animate-spin' : ''}`} />
                    {loading ? 'Refreshing...' : 'Refresh'}
                </button>
            </div>
        </header>
    );
}
