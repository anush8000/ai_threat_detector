'use client';

import { useState } from 'react';
import { Shield, ArrowRight, Lock } from 'lucide-react';

export default function LoginPage() {
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ password }),
            });

            if (res.ok) {
                window.location.href = '/';
            } else {
                const data = await res.json();
                setError(data.error || 'Invalid credentials');
            }
        } catch {
            setError('A network error occurred');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-black flex items-center justify-center p-4">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(50,50,50,0.4)_0,rgba(0,0,0,1)_100%)] pointer-events-none" />

            <div className="surface-card w-full max-w-md p-8 relative z-10 animate-enter border border-white/10 shadow-2xl">
                <div className="flex justify-center mb-6">
                    <div className="p-3 bg-white/5 rounded-2xl border border-white/10 shadow-[0_0_30px_rgba(255,255,255,0.05)]">
                        <Shield size={32} className="text-white" />
                    </div>
                </div>

                <h1 className="text-2xl font-semibold tracking-tight text-white mb-2 text-center">
                    Terminal Access
                </h1>
                <p className="text-white/50 text-sm text-center mb-8">
                    Enter master password to access SecOps Copilot
                </p>

                <form onSubmit={handleSubmit} className="space-y-4">
                    <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <Lock size={16} className="text-white/30" />
                        </div>
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            className="w-full bg-white/5 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-white placeholder:text-white/30 focus:outline-none focus:border-white/30 focus:bg-white/10 transition-all font-mono text-sm tracking-widest"
                            placeholder="••••••••"
                            required
                        />
                    </div>

                    {error && (
                        <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-xs text-center font-medium">
                            {error}
                        </div>
                    )}

                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full bg-white text-black hover:bg-white/90 py-3 rounded-xl font-medium tracking-wide flex items-center justify-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {loading ? 'Authenticating...' : 'Authorize'}
                        {!loading && <ArrowRight size={16} />}
                    </button>
                </form>
            </div>
        </div>
    );
}
