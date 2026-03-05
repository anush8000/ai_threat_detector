// app/api/steampipe/route.ts
// SECURITY FIX: query whitelisting replaces the old arbitrary-SQL approach.
// Only queries that match one of the pre-approved AWS_CHECKS query IDs are
// executed. The full SQL is looked up server-side — never trusted from client.

import { NextRequest, NextResponse } from 'next/server';
import { Pool } from 'pg';

// ── Approved query registry ────────────────────────────────────────────────
// These are the exact same SQL strings defined in Dashboard.tsx AWS_CHECKS.
// We keep them here too so the server controls what runs — the client only
// sends the check `id`, never raw SQL.
const APPROVED_QUERIES: Record<string, string> = {
  S3_PUBLIC: `SELECT name, block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets, region FROM aws_s3_bucket WHERE NOT block_public_acls OR NOT block_public_policy OR NOT ignore_public_acls OR NOT restrict_public_buckets`,
  S3_NO_ENC: `SELECT name, region FROM aws_s3_bucket WHERE server_side_encryption_configuration IS NULL LIMIT 50`,
  S3_NO_LOG: `SELECT name, region FROM aws_s3_bucket WHERE logging IS NULL LIMIT 50`,
  EC2_PUBLIC: `SELECT instance_id, instance_type, region, public_ip_address, public_dns_name, tags FROM aws_ec2_instance WHERE public_ip_address IS NOT NULL LIMIT 50`,
  EC2_IMDSV2: `SELECT instance_id, region, metadata_options->>'HttpTokens' as http_tokens FROM aws_ec2_instance WHERE metadata_options->>'HttpTokens' != 'required' AND state->>'Name' = 'running' LIMIT 50`,
  SG_OPEN: `SELECT group_id, group_name, description, region, vpc_id FROM aws_vpc_security_group WHERE ip_permissions::text LIKE '%0.0.0.0/0%' LIMIT 50`,
  SG_SSH: `SELECT group_id, group_name, region FROM aws_vpc_security_group WHERE ip_permissions::text LIKE '%\"toPort\": 22%' AND ip_permissions::text LIKE '%0.0.0.0/0%' LIMIT 50`,
  SG_RDP: `SELECT group_id, group_name, region FROM aws_vpc_security_group WHERE ip_permissions::text LIKE '%\"toPort\": 3389%' AND ip_permissions::text LIKE '%0.0.0.0/0%' LIMIT 50`,
  IAM_NO_MFA: `SELECT name, user_id, mfa_enabled, password_last_used FROM aws_iam_user WHERE mfa_enabled = false LIMIT 50`,
  IAM_OLD_KEY: `SELECT user_name, access_key_id, date_part('day', now() - create_date) as age_days FROM aws_iam_access_key WHERE status = 'Active' AND date_part('day', now() - create_date) > 90 LIMIT 50`,
  CT_DISABLED: `SELECT name, is_logging, home_region FROM aws_cloudtrail_trail WHERE is_logging = false LIMIT 50`,
  CT_NO_VALIDATION: `SELECT name, home_region FROM aws_cloudtrail_trail WHERE log_file_validation_enabled = false AND is_logging = true LIMIT 50`,
  EBS_UNENC: `SELECT volume_id, volume_type, size, availability_zone FROM aws_ebs_volume WHERE encrypted = false AND state = 'in-use' LIMIT 50`,
  RDS_PUBLIC: `SELECT db_instance_identifier, engine, engine_version, region FROM aws_rds_db_instance WHERE publicly_accessible = true LIMIT 50`,
  RDS_NO_ENC: `SELECT db_instance_identifier, engine, region FROM aws_rds_db_instance WHERE storage_encrypted = false LIMIT 50`,
  RDS_NO_BACKUP: `SELECT db_instance_identifier, engine, region FROM aws_rds_db_instance WHERE backup_retention_period = 0 LIMIT 50`,
  KMS_NO_ROT: `SELECT id, region FROM aws_kms_key WHERE key_manager = 'CUSTOMER' AND key_state = 'Enabled' AND rotation_enabled = false LIMIT 50`,
  VPC_NO_FLOW: `SELECT v.vpc_id, v.region, v.cidr_block FROM aws_vpc v LEFT JOIN aws_vpc_flow_log f ON v.vpc_id = f.resource_id WHERE f.flow_log_id IS NULL AND v.is_default = false LIMIT 50`,
  LAMBDA_PUBLIC: `SELECT name, region, runtime FROM aws_lambda_function WHERE policy::text LIKE '%"Principal": "*"%' OR policy::text LIKE '%"Principal":"*"%' LIMIT 50`,

  // ── GCP Checks ─────────────────────────────────────────────────────────────
  GCP_STORAGE_PUBLIC: `SELECT name, location FROM gcp_storage_bucket WHERE iam_policy::text LIKE '%allUsers%' OR iam_policy::text LIKE '%allAuthenticatedUsers%' LIMIT 50`,
  GCP_COMPUTE_PUBLIC: `SELECT name, zone FROM gcp_compute_instance WHERE network_interfaces::text LIKE '%accessConfigs%' AND network_interfaces::text LIKE '%ONE_TO_ONE_NAT%' LIMIT 50`,

  // ── Azure Checks ───────────────────────────────────────────────────────────
  AZURE_VM_PUBLIC: `SELECT name, region FROM azure_compute_virtual_machine WHERE public_ips IS NOT NULL LIMIT 50`,
  AZURE_BLOB_PUBLIC: `SELECT name, region FROM azure_storage_container WHERE public_access = 'Blob' OR public_access = 'Container' LIMIT 50`,
};

// ── Connection pool ────────────────────────────────────────────────────────
const steampipePassword = process.env.STEAMPIPE_PASSWORD;

const pool = steampipePassword
  ? new Pool({
    user: 'steampipe',
    password: steampipePassword,
    host: '127.0.0.1',
    port: 9193,
    database: 'steampipe',
    max: 10,
    connectionTimeoutMillis: 8000,
    idleTimeoutMillis: 30000,
  })
  : null; // No pool if env var not set — requests will return 503

// ── In-Memory Rate Limiter ─────────────────────────────────────────────────
// OWASP Fix: Prevents DB connection pool exhaustion (Denial of Service)
const rateLimitStore = new Map<string, { count: number; timestamp: number }>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const windowMs = 60 * 1000; // 1 minute window
  const maxRequests = 30; // Max 30 requests per minute per IP

  const record = rateLimitStore.get(ip);
  if (!record || now - record.timestamp > windowMs) {
    rateLimitStore.set(ip, { count: 1, timestamp: now });
    return true;
  }

  if (record.count >= maxRequests) return false;

  record.count++;
  return true;
}

export async function GET(request: NextRequest) {
  // ── Rate Limiting ─────────────────────────────────────────────────────────
  const ip = request.headers.get("x-forwarded-for") || "unknown_ip";
  if (!checkRateLimit(ip)) {
    return NextResponse.json(
      { error: "Too many requests. Please try again later.", rows: [], rowCount: 0 },
      { status: 429 }
    );
  }

  if (!pool) {
    return NextResponse.json(
      { error: 'STEAMPIPE_PASSWORD environment variable is not set', rows: [], rowCount: 0 },
      { status: 503 }
    );
  }

  const { searchParams } = new URL(request.url);
  const checkId = searchParams.get('checkId');

  // ── Whitelist validation ──────────────────────────────────────────────────
  if (!checkId) {
    return NextResponse.json(
      { error: 'checkId parameter is required. Provide the check ID (e.g. S3_PUBLIC)', rows: [] },
      { status: 400 }
    );
  }

  const approvedSQL = APPROVED_QUERIES[checkId.toUpperCase()];
  if (!approvedSQL) {
    return NextResponse.json(
      { error: `Unknown check ID: "${checkId}". Must be one of: ${Object.keys(APPROVED_QUERIES).join(', ')}`, rows: [] },
      { status: 400 }
    );
  }

  // ── Execute whitelisted query ─────────────────────────────────────────────
  let client;
  try {
    client = await pool.connect();
    const result = await client.query(approvedSQL);
    return NextResponse.json({ rows: result.rows, rowCount: result.rowCount });
  } catch (error) {
    // OWASP Fix: Do not leak raw DB stack traces or query structures to client
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error(`[Internal DB Error] Steampipe error for check ${checkId}:`, errorMessage);

    return NextResponse.json(
      { error: 'Internal Server Error: Query failed', rows: [], rowCount: 0 },
      { status: 500 }
    );
  } finally {
    if (client) client.release(); // Always release connection back to pool
  }
}
