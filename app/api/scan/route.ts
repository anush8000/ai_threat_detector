// app/api/scan/route.ts
// Returns a health-check response. Real security metrics are computed
// directly in the Dashboard from Steampipe queries (or mock data).
import { NextResponse } from "next/server";

export async function GET() {
    return NextResponse.json({
        status: "ok",
        message: "Use /api/steampipe to run security checks",
        timestamp: new Date().toISOString(),
    });
}