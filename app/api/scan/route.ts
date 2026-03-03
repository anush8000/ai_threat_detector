import { NextResponse } from "next/server";

export async function GET(){
    return NextResponse.json({
        publicExposure: true,
        riskScore: 80,
        severity: "CRITICAL",
    });
}