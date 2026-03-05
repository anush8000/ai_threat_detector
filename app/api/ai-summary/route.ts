// app/api/ai-summary/route.ts
// UPGRADED: RAG-grounded prompts — retrieves CIS/NIST controls before Groq call
// BACKWARD COMPATIBLE: still handles { prompt: string } from old Dashboard code
// KEPT EXACTLY: rate limiter, Groq model, error handling, response shape

import { NextRequest, NextResponse } from 'next/server';
import { buildRAGPrompt, retrieveControls } from '@/lib/rag/securityKnowledgeBase';

// ─── Rate limiter (kept exactly from original) ────────────────────────────────
const RATE_LIMIT = {
  maxPerHour: 20,
  windowMs: 60 * 60 * 1000,
};
const rateLimitStore = new Map<string, { count: number; windowStart: number }>();
let lastCleanup = Date.now();

function checkRateLimit(ip: string): { allowed: boolean; remaining: number; resetInMs: number } {
  const now = Date.now();

  // Lazy cleanup every 10 minutes
  if (now - lastCleanup > 10 * 60 * 1000) {
    for (const [key, record] of rateLimitStore.entries()) {
      if (now - record.windowStart > RATE_LIMIT.windowMs) {
        rateLimitStore.delete(key);
      }
    }
    lastCleanup = now;
  }

  let record = rateLimitStore.get(ip);

  if (!record || now - record.windowStart >= RATE_LIMIT.windowMs) {
    record = { count: 0, windowStart: now };
    rateLimitStore.set(ip, record);
  }

  const remaining = RATE_LIMIT.maxPerHour - record.count;
  const resetInMs = RATE_LIMIT.windowMs - (now - record.windowStart);

  if (remaining <= 0) return { allowed: false, remaining: 0, resetInMs };

  record.count++;
  return { allowed: true, remaining: remaining - 1, resetInMs };
}

// ─── GET — quota status (kept exactly from original) ─────────────────────────
export async function GET(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  let record = rateLimitStore.get(ip);
  const now = Date.now();
  if (!record || now - record.windowStart >= RATE_LIMIT.windowMs) {
    record = { count: 0, windowStart: now };
  }
  const remaining = Math.max(0, RATE_LIMIT.maxPerHour - record.count);
  const resetInMs = Math.max(0, RATE_LIMIT.windowMs - (now - record.windowStart));
  const resetInMins = Math.ceil(resetInMs / 60000);
  return NextResponse.json({ remaining, total: RATE_LIMIT.maxPerHour, resetInMins });
}

// ─── POST — RAG-grounded AI analysis ─────────────────────────────────────────
export async function POST(request: NextRequest) {
  // Rate limit
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  const { allowed, remaining, resetInMs } = checkRateLimit(ip);
  const resetInMins = Math.ceil(resetInMs / 60000);

  if (!allowed) {
    return NextResponse.json(
      { error: `Hourly limit reached (${RATE_LIMIT.maxPerHour} requests/hour). Resets in ${resetInMins} minute(s).`, resetInMins },
      {
        status: 429, headers: {
          'X-RateLimit-Limit': String(RATE_LIMIT.maxPerHour),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': String(resetInMins),
          'Retry-After': String(Math.ceil(resetInMs / 1000)),
        }
      }
    );
  }

  // Parse body
  let body: {
    // New structured format (from upgraded Dashboard)
    issues?: Array<{ type: string; description: string; severity: string }>;
    riskScore?: number;
    complianceScore?: number;
    counts?: { critical: number; high: number; medium: number; low: number };
    // Legacy format (from original Dashboard — keep working)
    prompt?: string;
  };

  try {
    body = await request.json();
    if (!body) throw new Error('Missing body');
  } catch {
    return NextResponse.json({ error: 'Invalid or missing request body' }, { status: 400 });
  }

  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return NextResponse.json({ error: 'GROQ_API_KEY is not set' }, { status: 500 });

  // ── Build RAG-grounded prompt ─────────────────────────────────────────────
  let finalPrompt: string;
  let ragControlsForResponse: Array<{ id: string; framework: string; title: string; severity: string }> = [];

  if (body.issues && Array.isArray(body.issues)) {
    // ── NEW PATH: structured issues — full RAG grounding ──
    const topIssues = body.issues.slice(0, 6).map(i => ({
      type: i.type || 'Unknown',
      description: i.description || '',
      severity: i.severity || 'low',
    }));

    finalPrompt = buildRAGPrompt({
      riskScore: body.riskScore || 0,
      complianceScore: body.complianceScore || 100,
      counts: body.counts || { critical: 0, high: 0, medium: 0, low: 0 },
      topIssues,
    });

    const issueQuery = topIssues.map(i => `${i.type} ${i.severity} ${i.description}`).join(' ');
    const { controls } = retrieveControls(issueQuery, 3);
    ragControlsForResponse = controls.map(c => ({
      id: c.id, framework: c.framework, title: c.title, severity: c.severity,
    }));

  } else if (body.prompt) {
    // ── LEGACY PATH: old { prompt } string — augment with RAG context ──
    // Original Dashboard still works, but now AI has CIS controls as context
    const { contextBlock, controls } = retrieveControls(body.prompt, 3);
    finalPrompt = `You are a senior cloud security analyst.

Use these CIS/NIST controls as your authoritative reference:

=== RETRIEVED SECURITY CONTROLS ===
${contextBlock}

=== FINDINGS TO ANALYZE ===
${body.prompt}

Return STRICTLY in this format:

SUMMARY:
<cite specific CIS control IDs>

RISK_LEVEL:
<LOW | MEDIUM | HIGH | CRITICAL>

ATTACK_VECTORS:
- item

REMEDIATION:
- step with AWS CLI command`;

    ragControlsForResponse = controls.map(c => ({
      id: c.id, framework: c.framework, title: c.title, severity: c.severity,
    }));

  } else {
    return NextResponse.json({ error: 'Request must include issues array or prompt string' }, { status: 400 });
  }

  // ── Call Groq API (same model, same error handling as original) ───────────
  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        max_tokens: 1024,
        temperature: 0.3, // lowered from 0.7 → more factual security responses
        messages: [
          {
            role: 'system',
            content: 'You are a senior AWS cloud security engineer specializing in CIS Benchmarks and NIST 800-53. Always cite specific control IDs. Be precise and actionable.',
          },
          { role: 'user', content: finalPrompt },
        ],
      }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      if (response.status === 429) {
        return NextResponse.json({ error: 'Please wait a moment and try again.' }, { status: 429 });
      }
      return NextResponse.json(
        { error: `API Error ${response.status}`, details: (err as { error?: { message?: string } }).error?.message || 'Unknown error' },
        { status: response.status }
      );
    }

    const data = await response.json();
    const summary = data.choices?.[0]?.message?.content || 'Unable to generate summary';

    // Response includes ragControls so Dashboard can show retrieved controls
    return NextResponse.json(
      { summary, remaining, ragControls: ragControlsForResponse },
      {
        headers: {
          'X-RateLimit-Limit': String(RATE_LIMIT.maxPerHour),
          'X-RateLimit-Remaining': String(remaining),
          'X-RateLimit-Reset': String(resetInMins),
        }
      }
    );

  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to generate summary' },
      { status: 500 }
    );
  }
}
