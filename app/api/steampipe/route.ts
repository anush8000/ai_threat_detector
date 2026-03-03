import { NextRequest, NextResponse } from 'next/server';
import { Pool } from 'pg';

const pool = new Pool({
  user: 'steampipe',
  password: process.env.STEAMPIPE_PASSWORD || 'your_steampipe_password',
  host: '127.0.0.1',
  port: 9193,
  database: 'steampipe',
});

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const query = searchParams.get('query');

    if (!query) {
      return NextResponse.json(
        { error: 'Query parameter is required' },
        { status: 400 }
      );
    }

    const client = await pool.connect();
    const result = await client.query(query);
    client.release();

    return NextResponse.json({
      rows: result.rows,
      rowCount: result.rowCount,
    });
  } catch (error) {
    console.error('Database error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Database query failed' },
      { status: 500 }
    );
  }
}