import { NextRequest, NextResponse } from 'next/server';

// ─── In-memory rate limiter ───────────────────────────────────────────────────
// Groq free tier: 30 RPM, 14,400 RPD for llama-3.3-70b-versatile
// We conservatively enforce 20 RPH (requests per hour) to stay safely under limits
const RATE_LIMIT = {
  maxPerHour: 20,       // max requests allowed per hour
  windowMs: 60 * 60 * 1000, // 1 hour window in ms
};

interface RateLimitStore {
  count: number;
  windowStart: number;
}

// Single global store (resets on server restart — fine for a college project)
const rateLimitStore: RateLimitStore = {
  count: 0,
  windowStart: Date.now(),
};

function checkRateLimit(): { allowed: boolean; remaining: number; resetInMs: number } {
  const now = Date.now();
  const elapsed = now - rateLimitStore.windowStart;

  // Reset window if 1 hour has passed
  if (elapsed >= RATE_LIMIT.windowMs) {
    rateLimitStore.count = 0;
    rateLimitStore.windowStart = now;
  }

  const remaining = RATE_LIMIT.maxPerHour - rateLimitStore.count;
  const resetInMs = RATE_LIMIT.windowMs - (now - rateLimitStore.windowStart);

  if (remaining <= 0) {
    return { allowed: false, remaining: 0, resetInMs };
  }

  rateLimitStore.count++;
  return { allowed: true, remaining: remaining - 1, resetInMs };
}

// ─── Route handler ────────────────────────────────────────────────────────────
export async function GET() {
  // Expose current quota status to the frontend
  const now = Date.now();
  const elapsed = now - rateLimitStore.windowStart;
  if (elapsed >= RATE_LIMIT.windowMs) {
    rateLimitStore.count = 0;
    rateLimitStore.windowStart = now;
  }
  const remaining = RATE_LIMIT.maxPerHour - rateLimitStore.count;
  const resetInMs = RATE_LIMIT.windowMs - (now - rateLimitStore.windowStart);
  const resetInMins = Math.ceil(resetInMs / 60000);

  return NextResponse.json({
    remaining,
    total: RATE_LIMIT.maxPerHour,
    resetInMins,
  });
}

export async function POST(request: NextRequest) {
  // ── 1. Rate limit check ──
  const { allowed, remaining, resetInMs } = checkRateLimit();
  const resetInMins = Math.ceil(resetInMs / 60000);

  if (!allowed) {
    return NextResponse.json(
      {
        error: `Hourly limit reached (${RATE_LIMIT.maxPerHour} requests/hour). Resets in ${resetInMins} minute(s).`,
        resetInMins,
      },
      {
        status: 429,
        headers: {
          'X-RateLimit-Limit':     String(RATE_LIMIT.maxPerHour),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset':     String(resetInMins),
          'Retry-After':           String(Math.ceil(resetInMs / 1000)),
        },
      }
    );
  }

  // ── 2. Validate request ──
  let body: any;
  try {
    body = await request.json();
    if (!body) throw new Error('Missing Findings');
  } catch {
    return NextResponse.json(
      { error: 'Invalid or missing request body ' }, { status: 400 });
  }

  // ── 3. Check API key ──
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { error: 'API is not set' },
      { status: 500 }
    );
  }

  // ── 4. Call Groq API (OpenAI-compatible) ──
  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model:       'llama-3.3-70b-versatile', // best free model on Groq
        max_tokens:  1024,
        temperature: 0.7,
        messages: [
          {
            role:"system",
            content: `You are a senior cloud security analyst.

Return your answer strictly in this format:

SUMMARY:
<short executive summary>

RISK_LEVEL:
<LOW | MEDIUM | HIGH | CRITICAL>

ATTACK_VECTORS:
- item
- item

REMEDIATION:
- step
- step

Analyze these findings:`
          },
          {
            role:"user",
            content: JSON.stringify(body),
          },
        ],
      }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      console.error('API error:', err);

      // If Groq itself rate limits us, surface it clearly
      if (response.status === 429) {
        return NextResponse.json(
          { error: 'Please wait a moment and try again.' },
          { status: 429 }
        );
      }

      return NextResponse.json(
        { error: `API Error ${response.status}`, details: err.error?.message || 'Unknown error' },
        { status: response.status }
      );
    }

    const data = await response.json();
    const summary = data.choices?.[0]?.message?.content || 'Unable to generate summary';

    return NextResponse.json(
      { summary, remaining },
      {
        headers: {
          'X-RateLimit-Limit':     String(RATE_LIMIT.maxPerHour),
          'X-RateLimit-Remaining': String(remaining),
          'X-RateLimit-Reset':     String(resetInMins),
        },
      }
    );
  } catch (error) {
    console.error('AI summary error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to generate summary' },
      { status: 500 }
    );
  }
}