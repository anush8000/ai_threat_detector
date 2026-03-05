'use client';

import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertOctagon, RefreshCw } from 'lucide-react';

interface Props {
    children?: ReactNode;
}

interface State {
    hasError: boolean;
    error?: Error;
}

export class ErrorBoundary extends Component<Props, State> {
    public state: State = {
        hasError: false
    };

    public static getDerivedStateFromError(error: Error): State {
        return { hasError: true, error };
    }

    public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        console.error('Uncaught error:', error, errorInfo);
    }

    private handleReset = () => {
        this.setState({ hasError: false, error: undefined });
        window.location.reload();
    };

    public render() {
        if (this.state.hasError) {
            return (
                <div className="min-h-screen bg-black flex items-center justify-center p-6">
                    <div className="surface-card max-w-lg w-full p-8 border border-red-500/20 shadow-[0_0_50px_rgba(239,68,68,0.1)]">
                        <div className="flex items-center gap-3 mb-6 text-red-500">
                            <AlertOctagon size={32} />
                            <h1 className="text-xl font-semibold tracking-tight text-white">Application Error</h1>
                        </div>

                        <p className="text-white/70 text-sm mb-6 leading-relaxed">
                            The dashboard encountered an unexpected error. This is usually due to a temporary problem connecting to the data source or rendering an unhandled edge case.
                        </p>

                        {this.state.error && (
                            <div className="bg-black/50 border border-white/10 rounded-lg p-4 mb-6 font-mono text-xs text-red-400/80 overflow-x-auto">
                                {this.state.error.message}
                            </div>
                        )}

                        <button
                            onClick={this.handleReset}
                            className="w-full py-3 bg-white text-black hover:bg-white/90 rounded-xl font-medium tracking-wide flex items-center justify-center gap-2 transition-all"
                        >
                            <RefreshCw size={16} />
                            Reload Application
                        </button>
                    </div>
                </div>
            );
        }

        return this.props.children;
    }
}
