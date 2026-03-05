import { Sparkles, Send } from 'lucide-react';
import ReactMarkdown from 'react-markdown';

interface AICopilotProps {
    generatingAI: boolean;
    aiError: string;
    aiSummary: string;
    chatHistory: { role: 'user' | 'assistant'; content: string }[];
    chatInput: string;
    setChatInput: (val: string) => void;
    sendingChat: boolean;
    generateAISummary: () => void;
    handleSendChat: (e?: React.FormEvent) => void;
}

export function AICopilot({
    generatingAI,
    aiError,
    aiSummary,
    chatHistory,
    chatInput,
    setChatInput,
    sendingChat,
    generateAISummary,
    handleSendChat,
}: AICopilotProps) {
    return (
        <div
            className={`surface-card flex flex-col relative overflow-hidden transition-all duration-500 min-h-0 max-h-[350px] flex-shrink-0 ${generatingAI
                    ? 'ai-processing-bg border-indigo-500/50'
                    : 'border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.05)]'
                }`}
        >
            <div className="p-5 px-6 border-b border-indigo-500/10 flex justify-between items-center bg-indigo-500/5 backdrop-blur-sm relative z-10">
                <div className="flex items-center gap-2">
                    <Sparkles
                        size={18}
                        className={generatingAI ? 'text-white animate-pulse' : 'text-indigo-400'}
                    />
                    <span className="text-base font-semibold tracking-tight text-white">SecOps Copilot</span>
                </div>
                <button
                    onClick={generateAISummary}
                    disabled={generatingAI}
                    aria-label="Assess with AI Copilot"
                    aria-expanded="false"
                    className="bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/30 px-4 py-1.5 rounded-lg text-xs font-bold tracking-wide disabled:opacity-50 transition-all shadow-[0_0_15px_rgba(99,102,241,0.1)] hover:shadow-[0_0_25px_rgba(99,102,241,0.3)]"
                >
                    {generatingAI ? 'SYNTHESIZING...' : 'ASSESS'}
                </button>
            </div>

            <div className="flex flex-col flex-1 relative z-10 min-h-0">
                <div className="p-6 overflow-y-auto custom-scrollbar flex-1">
                    {aiError && (
                        <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm mb-4">
                            {aiError}
                        </div>
                    )}
                    {aiSummary ? (
                        <div
                            className={`markdown-prose text-[0.95rem] text-white/90 leading-relaxed ${generatingAI ? 'opacity-50' : 'animate-enter'
                                }`}
                        >
                            <ReactMarkdown>{aiSummary}</ReactMarkdown>
                            {generatingAI && <span className="typing-cursor" />}

                            {chatHistory.length > 0 && (
                                <div className="mt-6 flex flex-col gap-3 border-t border-white/10 pt-5">
                                    {chatHistory.map((msg, idx) => (
                                        <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                                            <div
                                                className={`markdown-prose max-w-[85%] px-4 py-2.5 rounded-2xl text-[0.9rem] leading-relaxed ${msg.role === 'user'
                                                        ? 'bg-indigo-500/20 text-indigo-100 border border-indigo-500/30 rounded-br-sm'
                                                        : 'bg-white/5 text-white/90 border border-white/10 rounded-bl-sm'
                                                    }`}
                                            >
                                                <ReactMarkdown>{msg.content}</ReactMarkdown>
                                            </div>
                                        </div>
                                    ))}
                                    {sendingChat && (
                                        <div className="flex justify-start">
                                            <div className="px-4 py-2.5 bg-white/5 text-white/90 border border-white/10 rounded-2xl rounded-bl-sm">
                                                <span className="typing-cursor" />
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    ) : (
                        <div className="text-[0.95rem] text-white/60 leading-relaxed font-medium">
                            {!generatingAI ? (
                                'Copilot is ready to analyze active threats and context via retrieval augmented generation.'
                            ) : (
                                <span className="typing-cursor" />
                            )}
                        </div>
                    )}
                </div>

                {aiSummary && (
                    <div className="p-3 px-5 border-t border-white/10 bg-black/20 backdrop-blur-md focus-within:bg-indigo-500/10 focus-within:border-t-indigo-500/30 transition-all duration-300">
                        <form onSubmit={handleSendChat} className="flex items-center gap-3">
                            <input
                                type="text"
                                value={chatInput}
                                onChange={(e) => setChatInput(e.target.value)}
                                placeholder="Ask Copilot about this summary..."
                                className="flex-1 bg-transparent text-sm text-white placeholder-white/30 outline-none w-full"
                                disabled={sendingChat}
                            />
                            <button
                                type="submit"
                                disabled={!chatInput.trim() || sendingChat}
                                aria-label="Send Copilot Message"
                                className="p-1.5 text-indigo-400 hover:text-indigo-300 disabled:opacity-50 transition-colors"
                            >
                                <Send size={16} />
                            </button>
                        </form>
                    </div>
                )}
            </div>
        </div>
    );
}
