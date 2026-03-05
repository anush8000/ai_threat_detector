import { NextRequest, NextResponse } from 'next/server';

const RATE_LIMIT = {
    maxPerHour: 50,
    windowMs: 60 * 60 * 1000,
};

interface RateLimitStore { count: number; windowStart: number; }
const rateLimitStore: RateLimitStore = { count: 0, windowStart: Date.now() };

function checkRateLimit(): { allowed: boolean; remaining: number; resetInMs: number } {
    const now = Date.now();
    const elapsed = now - rateLimitStore.windowStart;
    if (elapsed >= RATE_LIMIT.windowMs) {
        rateLimitStore.count = 0;
        rateLimitStore.windowStart = now;
    }
    const remaining = RATE_LIMIT.maxPerHour - rateLimitStore.count;
    const resetInMs = RATE_LIMIT.windowMs - (now - rateLimitStore.windowStart);
    if (remaining <= 0) return { allowed: false, remaining: 0, resetInMs };
    rateLimitStore.count++;
    return { allowed: true, remaining: remaining - 1, resetInMs };
}

export async function POST(request: NextRequest) {
    try {
        const { allowed, resetInMs } = checkRateLimit();
        const resetInMins = Math.ceil(resetInMs / 60000);

        if (!allowed) {
            return NextResponse.json(
                { error: `Hourly chat limit reached. Resets in ${resetInMins} minute(s).` },
                { status: 429 }
            );
        }

        const { messages, context } = await request.json();
        const apiKey = process.env.GROQ_API_KEY;
        if (!apiKey) return NextResponse.json({ error: 'GROQ_API_KEY is not set' }, { status: 500 });

        const systemPrompt = {
            role: 'system',
            content: `You are a SecOps Copilot. You are discussing this security summary with the user:\n\n${context}\n\nKeep your answers concise, actionable, and strictly related to cloud security.`
        };

        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
            body: JSON.stringify({
                model: 'llama-3.3-70b-versatile',
                max_tokens: 500,
                temperature: 0.3,
                messages: [systemPrompt, ...messages],
            }),
        });

        if (!response.ok) throw new Error('Failed to fetch from Groq');

        const data = await response.json();
        const reply = data.choices?.[0]?.message?.content || 'Error generating response';

        return NextResponse.json({ reply });
    } catch (error) {
        return NextResponse.json({ error: (error as Error).message }, { status: 500 });
    }
}
