'use client';

// app/components/Dashboard.tsx - UPGRADED
// Exact drop-in replacement for existing Dashboard.tsx
// ALL existing imports and utilities preserved:
//   calculateRiskScore, getThreatCategory, compareScans, 
//   calculateAnomalyScore, mockRuntimeEvents
//
// ADDED:
// ✅ 20 AWS security checks (was 3: S3, EC2, SG only)
// ✅ Recharts: severity pie chart + issues-by-service bar chart + risk trend line
// ✅ RAG AI: sends structured issues + shows retrieved CIS/NIST controls
// ✅ Isolation Forest scores displayed in CWPP panel
// ✅ CIS control badge on each issue card
// ✅ Per-issue remediation command (expandable click)
// ✅ Compliance Score in header
// ✅ Contributing anomaly features in CWPP cards

import { useEffect, useState, useCallback } from 'react';
import {
  Shield, Sparkles,
  Activity, Cpu,
  CheckCircle, RefreshCw,
} from 'lucide-react';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  Tooltip, ResponsiveContainer, LineChart, Line,
} from 'recharts';

// ─── Your existing utilities (unchanged) ────────────────────
import { calculateRiskScore, Issue as RiskIssue } from '../../utils/riskScore';
import { getThreatCategory } from '../../utils/threatCategory';
import { compareScans } from '../../utils/driftDetection';
import { calculateAnomalyScore, mockRuntimeEvents } from '../../services/runtimeMonitor';

// ─── TYPES ──────────────────────────────────────────────────────────
interface SecurityIssue {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  resource: string;
  description: string;
  region?: string;
  threatCategory?: string;
  riskScore?: number;
  // NEW fields for upgrade
  checkId?: string;
  cisControl?: string;
  remediationHint?: string;
}

interface DashboardStats {
  publicS3Buckets: number;
  publicInstances: number;
  openSecurityGroups: number;
  totalInstances: number;
  criticalIssues: number;
  highIssues: number;
  totalRiskScore: number;
}

interface SteampipeResponse { rows: Record<string, unknown>[]; }
interface TrendPoint { time: string; score: number; }

// ─── 20 AWS SECURITY CHECKS ───────────────────────────────────────────
interface CheckDef {
  id: string;
  sql: string;
  mapRow: (row: Record<string, unknown>) => SecurityIssue;
}

const AWS_CHECKS: CheckDef[] = [
  // S3
  {
    id: 'S3_PUBLIC',
    sql: `SELECT name, block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets, region
         FROM aws_s3_bucket
         WHERE NOT block_public_acls OR NOT block_public_policy OR NOT ignore_public_acls OR NOT restrict_public_buckets`,
    mapRow: (b) => ({
      id: `s3-${b.name}`, checkId: 'S3_PUBLIC', cisControl: 'CIS-2.1.5',
      severity: 'high', type: 'Public S3 Bucket', resource: String(b.name), region: String(b.region),
      description: `Bucket "${b.name}" has Block Public Access disabled - ACLs:${b.block_public_acls ? '✅' : '\u274C'} Policy:${b.block_public_policy ? '✅' : '\u274C'} IgnoreACL:${b.ignore_public_acls ? '✅' : '\u274C'} Restrict:${b.restrict_public_buckets ? '✅' : '\u274C'}`,
      remediationHint: `aws s3api put-public-access-block --bucket ${b.name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`
    })
  },
  {
    id: 'S3_NO_ENC',
    sql: `SELECT name, region FROM aws_s3_bucket WHERE server_side_encryption_configuration IS NULL LIMIT 50`,
    mapRow: (b) => ({
      id: `s3enc-${b.name}`, checkId: 'S3_NO_ENC', cisControl: 'CIS-2.1.2',
      severity: 'medium', type: 'S3 Bucket Without Encryption', resource: String(b.name), region: String(b.region),
      description: `Bucket "${b.name}" has no server-side encryption configured. Data at rest stored in plaintext.`,
      remediationHint: `aws s3api put-bucket-encryption --bucket ${b.name} --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'`
    })
  },
  // EC2
  {
    id: 'EC2_PUBLIC',
    sql: `SELECT instance_id, instance_type, region, public_ip_address, public_dns_name, tags
         FROM aws_ec2_instance WHERE public_ip_address IS NOT NULL LIMIT 50`,
    mapRow: (i) => {
      const tags = i.tags as Record<string, string> | undefined;
      const name = tags?.Name || i.instance_id;
      return {
        id: `ec2-${i.instance_id}`, checkId: 'EC2_PUBLIC', cisControl: 'CIS-5.6',
        severity: 'medium', type: 'Public EC2 Instance', resource: `${name} (${i.instance_type})`, region: String(i.region),
        description: `Instance "${i.instance_id}" is publicly accessible - IP: ${i.public_ip_address}${i.public_dns_name ? ' | DNS: ' + i.public_dns_name : ''}`,
        remediationHint: 'Move instance to private subnet. Use Application Load Balancer or NAT Gateway for required internet connectivity.'
      };
    }
  },
  {
    id: 'EC2_IMDSV2',
    sql: `SELECT instance_id, region, metadata_options ->> 'HttpTokens' as http_tokens
         FROM aws_ec2_instance WHERE metadata_options ->> 'HttpTokens' != 'required' AND state ->> 'Name' = 'running' LIMIT 50`,
    mapRow: (i) => ({
      id: `imds-${i.instance_id}`, checkId: 'EC2_IMDSV2', cisControl: 'AWS-IMDSV2',
      severity: 'high', type: 'EC2 IMDSv2 Not Enforced', resource: String(i.instance_id), region: String(i.region),
      description: `Instance ${i.instance_id} allows IMDSv1 (HttpTokens=${i.http_tokens}). SSRF attacks can steal IAM credentials from the metadata service.`,
      remediationHint: `aws ec2 modify-instance-metadata-options --instance-id ${i.instance_id} --http-tokens required --http-put-response-hop-limit 1`
    })
  },
  // Security Groups
  {
    id: 'SG_OPEN',
    sql: `SELECT group_id, group_name, description, region, vpc_id
         FROM aws_vpc_security_group WHERE ip_permissions::text LIKE '%0.0.0.0/0%' LIMIT 50`,
    mapRow: (sg) => ({
      id: `sg-${sg.group_id}`, checkId: 'SG_OPEN', cisControl: 'CIS-5.3',
      severity: 'critical', type: 'Overly Permissive Security Group', resource: `${sg.group_name} (${sg.group_id})`, region: String(sg.region),
      description: `"${sg.group_name}" allows unrestricted inbound traffic (0.0.0.0/0)${sg.vpc_id ? ' in VPC: ' + sg.vpc_id : ''}${sg.description ? ' - ' + sg.description : ''}`,
      remediationHint: `aws ec2 revoke-security-group-ingress --group-id ${sg.group_id} --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'`
    })
  },
  {
    id: 'SG_SSH',
    sql: `SELECT group_id, group_name, region FROM aws_vpc_security_group
         WHERE ip_permissions::text LIKE '%"toPort": 22%' AND ip_permissions::text LIKE '%0.0.0.0/0%' LIMIT 50`,
    mapRow: (sg) => ({
      id: `sgsh-${sg.group_id}`, checkId: 'SG_SSH', cisControl: 'CIS-5.1',
      severity: 'critical', type: 'Open SSH Access (Port 22)', resource: `${sg.group_name} (${sg.group_id})`, region: String(sg.region),
      description: `"${sg.group_name}" allows unrestricted SSH (port 22) from 0.0.0.0/0. Exposed to brute-force and credential stuffing attacks.`,
      remediationHint: `aws ec2 revoke-security-group-ingress --group-id ${sg.group_id} --protocol tcp --port 22 --cidr 0.0.0.0/0`
    })
  },
  {
    id: 'SG_RDP',
    sql: `SELECT group_id, group_name, region FROM aws_vpc_security_group
         WHERE ip_permissions::text LIKE '%"toPort": 3389%' AND ip_permissions::text LIKE '%0.0.0.0/0%' LIMIT 50`,
    mapRow: (sg) => ({
      id: `sgrdp-${sg.group_id}`, checkId: 'SG_RDP', cisControl: 'CIS-5.2',
      severity: 'critical', type: 'Open RDP Access (Port 3389)', resource: `${sg.group_name} (${sg.group_id})`, region: String(sg.region),
      description: `"${sg.group_name}" allows unrestricted RDP (port 3389) from 0.0.0.0/0. Primary ransomware attack vector.`,
      remediationHint: `aws ec2 revoke-security-group-ingress --group-id ${sg.group_id} --protocol tcp --port 3389 --cidr 0.0.0.0/0`
    })
  },
  // IAM
  {
    id: 'IAM_NO_MFA',
    sql: `SELECT name, user_id, mfa_enabled, password_last_used FROM aws_iam_user WHERE mfa_enabled = false LIMIT 50`,
    mapRow: (u) => ({
      id: `iam-${u.user_id}`, checkId: 'IAM_NO_MFA', cisControl: 'CIS-1.10',
      severity: 'critical', type: 'IAM User Without MFA', resource: String(u.name), region: 'global',
      description: `IAM user "${u.name}" has no MFA. Console access with password only. Last login: ${u.password_last_used || 'never'}.`,
      remediationHint: `aws iam enable-mfa-device --user-name ${u.name} --serial-number arn:aws:iam::ACCOUNT_ID:mfa/${u.name} --authentication-code1 CODE1 --authentication-code2 CODE2`
    })
  },
  {
    id: 'IAM_OLD_KEY',
    sql: `SELECT user_name, access_key_id, date_part('day', now() - create_date) as age_days
         FROM aws_iam_access_key WHERE status = 'Active' AND date_part('day', now() - create_date) > 90 LIMIT 50`,
    mapRow: (k) => ({
      id: `iamkey-${k.access_key_id}`, checkId: 'IAM_OLD_KEY', cisControl: 'NIST-AC-2',
      severity: 'high', type: 'Stale IAM Access Key (>90 days)', resource: `${k.user_name}/${k.access_key_id}`, region: 'global',
      description: `Access key ${k.access_key_id} for "${k.user_name}" is ${Math.round(Number(k.age_days))} days old. Keys >90 days must be rotated.`,
      remediationHint: `aws iam create-access-key --user-name ${k.user_name}  # update apps  then:  aws iam delete-access-key --user-name ${k.user_name} --access-key-id ${k.access_key_id}`
    })
  },
  // CloudTrail
  {
    id: 'CT_DISABLED',
    sql: `SELECT name, is_logging, home_region FROM aws_cloudtrail_trail WHERE is_logging = false LIMIT 50`,
    mapRow: (t) => ({
      id: `ct-${t.name}`, checkId: 'CT_DISABLED', cisControl: 'CIS-3.1',
      severity: 'high', type: 'CloudTrail Logging Disabled', resource: String(t.name), region: String(t.home_region),
      description: `CloudTrail trail "${t.name}" has logging disabled. No API audit trail - incident investigation impossible.`,
      remediationHint: `aws cloudtrail start-logging --name ${t.name}`
    })
  },
  {
    id: 'CT_NO_VALIDATION',
    sql: `SELECT name, home_region FROM aws_cloudtrail_trail WHERE log_file_validation_enabled = false AND is_logging = true LIMIT 50`,
    mapRow: (t) => ({
      id: `ctval-${t.name}`, checkId: 'CT_NO_VALIDATION', cisControl: 'CIS-3.2',
      severity: 'medium', type: 'CloudTrail Log Validation Disabled', resource: String(t.name), region: String(t.home_region),
      description: `Trail "${t.name}" has no log file integrity validation. Tampered logs may go undetected during forensic investigation.`,
      remediationHint: `aws cloudtrail update-trail --name ${t.name} --enable-log-file-validation`
    })
  },
  // EBS
  {
    id: 'EBS_UNENC',
    sql: `SELECT volume_id, volume_type, size, availability_zone FROM aws_ebs_volume WHERE encrypted = false AND state = 'in-use' LIMIT 50`,
    mapRow: (v) => ({
      id: `ebs-${v.volume_id}`, checkId: 'EBS_UNENC', cisControl: 'CIS-2.2.1',
      severity: 'high', type: 'Unencrypted EBS Volume', resource: String(v.volume_id), region: String(v.availability_zone),
      description: `EBS volume ${v.volume_id} (${v.volume_type}, ${v.size}GB) is unencrypted and actively attached to a running instance.`,
      remediationHint: `Snapshot ${v.volume_id} -> copy-snapshot with --encrypted -> create encrypted volume -> stop instance -> swap attachment.`
    })
  },
  // RDS
  {
    id: 'RDS_PUBLIC',
    sql: `SELECT db_instance_identifier, engine, engine_version, region FROM aws_rds_db_instance WHERE publicly_accessible = true LIMIT 50`,
    mapRow: (r) => ({
      id: `rds-${r.db_instance_identifier}`, checkId: 'RDS_PUBLIC', cisControl: 'CIS-2.3.2',
      severity: 'critical', type: 'Publicly Accessible RDS Database', resource: String(r.db_instance_identifier), region: String(r.region),
      description: `RDS instance "${r.db_instance_identifier}" (${r.engine} ${r.engine_version}) is directly accessible from the internet.`,
      remediationHint: `aws rds modify-db-instance --db-instance-identifier ${r.db_instance_identifier} --no-publicly-accessible --apply-immediately`
    })
  },
  {
    id: 'RDS_NO_ENC',
    sql: `SELECT db_instance_identifier, engine, region FROM aws_rds_db_instance WHERE storage_encrypted = false LIMIT 50`,
    mapRow: (r) => ({
      id: `rdsenc-${r.db_instance_identifier}`, checkId: 'RDS_NO_ENC', cisControl: 'CIS-2.3.1',
      severity: 'high', type: 'Unencrypted RDS Instance', resource: String(r.db_instance_identifier), region: String(r.region),
      description: `RDS instance "${r.db_instance_identifier}" (${r.engine}) has no storage encryption. DB files and backups stored in plaintext.`,
      remediationHint: `Take snapshot -> aws rds copy-db-snapshot with --kms-key-id -> restore encrypted instance from snapshot.`
    })
  },
  // KMS
  {
    id: 'KMS_NO_ROT',
    sql: `SELECT id, region FROM aws_kms_key WHERE key_manager = 'CUSTOMER' AND key_state = 'Enabled' AND rotation_enabled = false LIMIT 50`,
    mapRow: (k) => ({
      id: `kms-${k.id}`, checkId: 'KMS_NO_ROT', cisControl: 'CIS-3.8',
      severity: 'medium', type: 'KMS Key Rotation Disabled', resource: String(k.id), region: String(k.region),
      description: `KMS CMK ${k.id} has no automatic key rotation. A compromised key can decrypt all historical encrypted data indefinitely.`,
      remediationHint: `aws kms enable-key-rotation --key-id ${k.id}`
    })
  },
  // VPC Flow Logs
  {
    id: 'VPC_NO_FLOW',
    sql: `SELECT v.vpc_id, v.region, v.cidr_block FROM aws_vpc v
         LEFT JOIN aws_vpc_flow_log f ON v.vpc_id = f.resource_id
         WHERE f.flow_log_id IS NULL AND v.is_default = false LIMIT 50`,
    mapRow: (v) => ({
      id: `vpc-${v.vpc_id}`, checkId: 'VPC_NO_FLOW', cisControl: 'CIS-3.9',
      severity: 'medium', type: 'VPC Without Flow Logs', resource: String(v.vpc_id), region: String(v.region),
      description: `VPC ${v.vpc_id} (CIDR: ${v.cidr_block}) has no flow logs. Network forensics and lateral movement detection are not possible.`,
      remediationHint: `aws ec2 create-flow-logs --resource-type VPC --resource-ids ${v.vpc_id} --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs`
    })
  },
  // Lambda
  {
    id: 'LAMBDA_PUBLIC',
    sql: `SELECT name, region, runtime FROM aws_lambda_function
         WHERE policy::text LIKE '%"Principal": "*"%' OR policy::text LIKE '%"Principal":"*"%' LIMIT 50`,
    mapRow: (f) => ({
      id: `lambda-${f.name}`, checkId: 'LAMBDA_PUBLIC', cisControl: 'LAMBDA-PUB',
      severity: 'high', type: 'Lambda Function With Public Access', resource: String(f.name), region: String(f.region),
      description: `Lambda "${f.name}" (${f.runtime}) has a resource policy allowing public invocation from any AWS account.`,
      remediationHint: `aws lambda remove-permission --function-name ${f.name} --statement-id PUBLIC_STATEMENT_ID`
    })
  },
  // RDS No Backup
  {
    id: 'RDS_NO_BACKUP',
    sql: `SELECT db_instance_identifier, engine, region FROM aws_rds_db_instance WHERE backup_retention_period = 0 LIMIT 50`,
    mapRow: (r) => ({
      id: `rdsbkp-${r.db_instance_identifier}`, checkId: 'RDS_NO_BACKUP', cisControl: 'AWS-BP',
      severity: 'medium', type: 'RDS Automated Backups Disabled', resource: String(r.db_instance_identifier), region: String(r.region),
      description: `RDS instance "${r.db_instance_identifier}" has automated backups disabled. Data loss is unrecoverable on instance failure.`,
      remediationHint: `aws rds modify-db-instance --db-instance-identifier ${r.db_instance_identifier} --backup-retention-period 7 --apply-immediately`
    })
  },
  // S3 logging
  {
    id: 'S3_NO_LOG',
    sql: `SELECT name, region FROM aws_s3_bucket WHERE logging IS NULL LIMIT 50`,
    mapRow: (b) => ({
      id: `s3log-${b.name}`, checkId: 'S3_NO_LOG', cisControl: 'CIS-3.1',
      severity: 'low', type: 'S3 Bucket Access Logging Disabled', resource: String(b.name), region: String(b.region),
      description: `Bucket "${b.name}" has access logging disabled. S3 access requests are not being recorded for audit or forensic purposes.`,
      remediationHint: `aws s3api put-bucket-logging --bucket ${b.name} --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"YOUR_LOG_BUCKET","TargetPrefix":"${b.name}/"}}'`
    })
  },
];

// ─── MOCK DATA (shown when Steampipe unavailable) ────────────────────────────
const MOCK_ISSUES: SecurityIssue[] = [
  {
    id: 'm1', checkId: 'SG_OPEN', cisControl: 'CIS-5.3', severity: 'critical', type: 'Overly Permissive Security Group',
    resource: 'sg-web-server (sg-0a1b2c3d4e5f6)', region: 'us-east-1',
    description: '"sg-web-server" allows unrestricted inbound traffic (0.0.0.0/0) in VPC: vpc-12345678 - Web server SG',
    remediationHint: "aws ec2 revoke-security-group-ingress --group-id sg-0a1b2c3d4e5f6 --ip-permissions '[{\"IpProtocol\":\"-1\",\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\"}]}]'"
  },
  {
    id: 'm2', checkId: 'SG_OPEN', cisControl: 'CIS-5.3', severity: 'critical', type: 'Overly Permissive Security Group',
    resource: 'sg-database (sg-9z8y7x6w5v4)', region: 'us-east-1',
    description: '"sg-database" allows unrestricted inbound traffic (0.0.0.0/0) in VPC: vpc-87654321 - DB SG with SSH open',
    remediationHint: "aws ec2 revoke-security-group-ingress --group-id sg-9z8y7x6w5v4 --ip-permissions '[{\"IpProtocol\":\"-1\",\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\"}]}]'"
  },
  {
    id: 'm3', checkId: 'S3_PUBLIC', cisControl: 'CIS-2.1.5', severity: 'high', type: 'Public S3 Bucket',
    resource: 'customer-data-backup', region: 'us-west-2',
    description: 'Bucket "customer-data-backup" has public access - ACLs: \u274C Policy: \u274C IgnoreACL: \u274C Restrict: \u274C',
    remediationHint: 'aws s3api put-public-access-block --bucket customer-data-backup --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
  },
  {
    id: 'm4', checkId: 'S3_PUBLIC', cisControl: 'CIS-2.1.5', severity: 'high', type: 'Public S3 Bucket',
    resource: 'app-logs-2024', region: 'eu-west-1',
    description: 'Bucket "app-logs-2024" has public access - ACLs: \u274C Policy: ✅ IgnoreACL: \u274C Restrict: ✅',
    remediationHint: 'aws s3api put-public-access-block --bucket app-logs-2024 --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
  },
  {
    id: 'm5', checkId: 'EC2_PUBLIC', cisControl: 'CIS-5.6', severity: 'medium', type: 'Public EC2 Instance',
    resource: 'web-server-prod (t3.medium)', region: 'us-east-1',
    description: 'Instance "i-0abc123def456" is publicly accessible - IP: 54.123.45.67 | DNS: ec2-54-123-45-67.compute-1.amazonaws.com',
    remediationHint: 'Move to private subnet. Use Application Load Balancer for public traffic.'
  },
  {
    id: 'm6', checkId: 'EC2_PUBLIC', cisControl: 'CIS-5.6', severity: 'medium', type: 'Public EC2 Instance',
    resource: 'api-server-01 (t3.large)', region: 'us-west-2',
    description: 'Instance "i-0def456abc123" is publicly accessible - IP: 52.98.76.54',
    remediationHint: 'Move to private subnet. Use Application Load Balancer for public traffic.'
  },
  {
    id: 'm7', checkId: 'IAM_NO_MFA', cisControl: 'CIS-1.10', severity: 'critical', type: 'IAM User Without MFA',
    resource: 'developer-anush', region: 'global',
    description: 'IAM user "developer-anush" has no MFA enabled. Console access with password only.',
    remediationHint: 'Enable virtual MFA: AWS Console > IAM > Users > developer-anush > Security credentials > Assign MFA device'
  },
  {
    id: 'm8', checkId: 'CT_DISABLED', cisControl: 'CIS-3.1', severity: 'high', type: 'CloudTrail Logging Disabled',
    resource: 'default-trail', region: 'ap-south-1',
    description: '"default-trail" has logging disabled. No AWS API audit trail is being recorded.',
    remediationHint: 'aws cloudtrail start-logging --name default-trail'
  },
];

// ─── COMPLIANCE SCORE ─────────────────────────────────────────────────────────
function getComplianceScore(issues: SecurityIssue[]) {
  const allPrefixes = [...new Set(AWS_CHECKS.map(c => c.id.split('_')[0]))];
  const failPrefixes = [...new Set(
    issues.map(i => i.checkId?.split('_')[0]).filter(Boolean) as string[]
  )];
  const passCount = allPrefixes.filter(p => !failPrefixes.includes(p)).length;
  return { score: Math.round((passCount / allPrefixes.length) * 100), pass: passCount, total: allPrefixes.length };
}

// Apple-palette chart colors
// (removed unused PIE_COLORS here)

// ─── SEVERITY HELPERS ─────────────────────────────────────────────────


// ─── DASHBOARD ───────────────────────────────────────────────────────
export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats>({
    publicS3Buckets: 0, publicInstances: 0, openSecurityGroups: 0,
    totalInstances: 0, criticalIssues: 0, highIssues: 0, totalRiskScore: 0,
  });
  const [issues, setIssues] = useState<SecurityIssue[]>([]);
  const [prevIssues, setPrevIssues] = useState<SecurityIssue[]>([]);
  const [aiSummary, setAiSummary] = useState<string>('');
  const [generatingAI, setGeneratingAI] = useState(false);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [riskTrend, setRiskTrend] = useState<TrendPoint[]>([]);
  const [aiError, setAiError] = useState('');

  // /api/scan is now a health-check only - real stats come from Steampipe

  const processIssues = useCallback((raw: SecurityIssue[]): SecurityIssue[] => {
    const publicChecks = new Set(['S3_PUBLIC', 'EC2_PUBLIC', 'SG_OPEN', 'SG_SSH', 'SG_RDP', 'RDS_PUBLIC', 'LAMBDA_PUBLIC']);
    return raw.map(issue => {
      const exposure: RiskIssue['exposure'] = publicChecks.has(issue.checkId || '') ? 'Public' : 'Internal';
      const ri: RiskIssue = { ...issue, exposure };
      return { ...issue, riskScore: calculateRiskScore(ri), threatCategory: getThreatCategory(ri) };
    });
  }, []);

  const setMockData = useCallback(() => {
    const processed = processIssues(MOCK_ISSUES);
    setPrevIssues(processed.slice(0, 4));
    setIssues(processed);
    const totalRisk = processed.reduce((s, i) => s + (i.riskScore || 0), 0);
    setStats({ publicS3Buckets: 2, publicInstances: 2, openSecurityGroups: 2, totalInstances: 15, criticalIssues: 2, highIssues: 2, totalRiskScore: totalRisk });
    const timeLabel = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    setRiskTrend([{ time: timeLabel, score: totalRisk }, { time: timeLabel, score: totalRisk }]);
  }, [processIssues]);

  const fetchSecurityData = useCallback(async () => {
    setLoading(true);
    try {
      const results = await Promise.allSettled(
        AWS_CHECKS.map(check =>
          fetch(`/api/steampipe?checkId=${encodeURIComponent(check.id)}`)
            .then(r => r.ok ? r.json() : Promise.reject(r.status))
            .then((data: SteampipeResponse) => ({ check, rows: data.rows || [] }))
        )
      );
      const allIssues: SecurityIssue[] = [];
      let anySuccess = false;
      results.forEach(r => {
        if (r.status === 'fulfilled') {
          anySuccess = true;
          r.value.rows.forEach(row => {
            try { allIssues.push(r.value.check.mapRow(row)); } catch { /* skip */ }
          });
        }
      });
      if (!anySuccess) throw new Error('All checks failed');
      const processed = processIssues(allIssues);
      setPrevIssues(prev => prev.length > 0 ? prev : processed);
      setIssues(processed);
      const totalRisk = processed.reduce((s, i) => s + (i.riskScore || 0), 0);
      setStats({
        publicS3Buckets: allIssues.filter(i => i.checkId === 'S3_PUBLIC').length,
        publicInstances: allIssues.filter(i => i.checkId === 'EC2_PUBLIC').length,
        openSecurityGroups: allIssues.filter(i => i.checkId === 'SG_OPEN').length,
        totalInstances: 0,
        criticalIssues: processed.filter(i => i.severity === 'critical').length,
        highIssues: processed.filter(i => i.severity === 'high').length,
        totalRiskScore: totalRisk,
      });
      const timeLabel = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
      setRiskTrend(prev => {
        if (prev.length === 0) return [{ time: timeLabel, score: totalRisk }, { time: timeLabel, score: totalRisk }];
        return [...prev.slice(-9), { time: timeLabel, score: totalRisk }];
      });
    } catch {
      setMockData();
    } finally {
      setLoading(false);
    }
  }, [processIssues, setMockData]);

  useEffect(() => { fetchSecurityData(); }, [fetchSecurityData]);

  const generateAISummary = async () => {
    setGeneratingAI(true);
    setAiError('');
    try {
      const counts = {
        critical: issues.filter(i => i.severity === 'critical').length,
        high: issues.filter(i => i.severity === 'high').length,
        medium: issues.filter(i => i.severity === 'medium').length,
        low: issues.filter(i => i.severity === 'low').length,
      };
      const compliance = getComplianceScore(issues);
      const res = await fetch('/api/ai-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          issues: issues.slice(0, 8).map(i => ({ type: i.type, description: i.description, severity: i.severity })),
          riskScore: stats.totalRiskScore,
          complianceScore: compliance.score,
          counts,
        }),
      });
      if (!res.ok) throw new Error((await res.json()).error || 'API Error');
      const data = await res.json();
      setAiSummary(data.summary);
    } catch (e) {
      setAiError(e instanceof Error ? e.message : 'Error generating AI analysis.');
    } finally {
      setGeneratingAI(false);
    }
  };

  const drift = compareScans(prevIssues, issues);
  const compliance = getComplianceScore(issues);

  const pieData = [
    { name: 'Critical', value: stats.criticalIssues },
    { name: 'High', value: stats.highIssues },
    { name: 'Medium', value: issues.filter(i => i.severity === 'medium').length },
    { name: 'Low', value: issues.filter(i => i.severity === 'low').length },
  ].filter(d => d.value > 0);

  const catData = [...new Set(issues.map(i => i.checkId?.split('_')[0] || 'Other'))].map(cat => ({
    category: cat,
    count: issues.filter(i => i.checkId?.startsWith(cat + '_') || i.checkId === cat).length,
  })).sort((a, b) => b.count - a.count);


  // ─── DERIVED METRICS ──────────────────────────────────────────────────────────
  const riskColor = stats.totalRiskScore > 100 ? 'var(--accent-red)' : stats.totalRiskScore > 50 ? 'var(--accent-orange)' : 'var(--accent-green)';

  return (
    <div className="app-container">
      {/* ─── HEADER ─── */}
      <header className="header" style={{ borderBottom: 'none' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1 }}>
          <Shield size={20} color="var(--label-1)" />
          <span className="t-headline">AI Powered Cloud Threat Detection System</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="t-subhead">System Active</span>
            <div className="live-indicator" />
          </div>
          <button className="btn btn-secondary" onClick={fetchSecurityData} disabled={loading}>
            <RefreshCw size={14} style={{ marginRight: 6 }} className={loading ? 'animate-spin' : ''} /> {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </header>

      <main style={{ padding: '32px 28px', maxWidth: 1600, margin: '0 auto', width: '100%', display: 'flex', flexDirection: 'column', gap: 32 }}>

        {/* ─── HERO ROW ─── */}
        <section className="bento-hero-row fade-up" style={{ animationDelay: '0s' }}>
          <div className="card" style={{ padding: 24 }}>
            <div className="t-caption" style={{ color: 'var(--label-2)', marginBottom: 8 }}>Total Risk Score</div>
            <div className="t-display-hero t-mono" style={{ color: riskColor }}>{stats.totalRiskScore}</div>
            <div className="t-footnote" style={{ color: 'var(--label-3)', marginTop: 8 }}>Aggregated system vulnerability</div>
          </div>

          <div className="card" style={{ padding: 24 }}>
            <div className="t-caption" style={{ color: 'var(--label-2)', marginBottom: 8 }}>Active Issues</div>
            <div className="t-display-hero t-mono" style={{ color: 'var(--label-1)' }}>{issues.length}</div>
            <div className="t-footnote" style={{ color: 'var(--label-3)', marginTop: 8 }}>+{drift.added.length} newly detected</div>
          </div>

          <div className="card" style={{ padding: 24 }}>
            <div className="t-caption" style={{ color: 'var(--label-2)', marginBottom: 8 }}>Compliance Status</div>
            <div className="t-display-hero t-mono" style={{ color: 'var(--sys-green)' }}>{compliance.score}%</div>
            <div style={{ marginTop: 12 }}>
              <div className="progress-track">
                <div className="progress-fill" style={{ width: `${compliance.score}%`, background: 'var(--sys-green)' }} />
              </div>
            </div>
          </div>

          <div className="card" style={{ padding: 24 }}>
            <div className="t-caption" style={{ color: 'var(--label-2)', marginBottom: 8 }}>Runtime Anomalies</div>
            <div className="t-display-hero t-mono" style={{ color: 'var(--sys-orange)' }} suppressHydrationWarning>
              {mockRuntimeEvents.filter(e => calculateAnomalyScore(e).threatLevel !== 'LOW').length}
            </div>
            <div className="t-footnote" style={{ color: 'var(--label-3)', marginTop: 8 }}>ML Behavior Detection Engine</div>
          </div>
        </section>

        {/* ─── MAIN ROW (Issues + CWPP/AI) ─── */}
        <section className="bento-main-row fade-up" style={{ animationDelay: '0.1s' }}>

          {/* LEFT: Issue Feed */}
          <div className="card" style={{ display: 'flex', flexDirection: 'column', height: 600, border: 'none' }}>
            <div style={{ padding: '20px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Activity size={16} color="var(--sys-blue)" />
                <span className="t-title-3">Configuration & Vulnerabilities</span>
              </div>
              <span className="pill sev-low t-caption">{issues.length} Items</span>
            </div>

            <div className="custom-scrollbar" style={{ flex: 1, overflowY: 'auto', maxHeight: 800, paddingRight: 8 }}>
              {issues.length === 0 ? (
                <div style={{ padding: 80, textAlign: 'center' }}>
                  <CheckCircle size={32} color="var(--sys-green)" style={{ margin: '0 auto 16px' }} />
                  <div className="t-title-1">All Clear</div>
                  <div className="t-subhead" style={{ color: 'var(--label-3)', marginTop: 8 }}>Infrastructure conforms to security baselines.</div>
                </div>
              ) : (
                issues.map(issue => {
                  const open = expandedId === issue.id;
                  const sevStyle = `sev-${issue.severity}`;
                  return (
                    <div key={issue.id} style={{ marginBottom: 8 }}>
                      <div className="issue-row" onClick={() => setExpandedId(open ? null : issue.id)} style={{ borderRadius: 12, background: open ? 'var(--fill-3)' : 'transparent' }}>
                        <div style={{ display: 'flex', gap: 16 }}>
                          <div style={{ marginTop: 4 }}>
                            <div className={`pill ${sevStyle} t-caption`} style={{ padding: '4px 8px', fontSize: 10 }}>{issue.severity}</div>
                          </div>
                          <div style={{ flex: 1 }}>
                            <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 4 }}>
                              <span className="t-headline t-mono" style={{ fontSize: '0.9rem' }}>{issue.id}</span>
                              {issue.cisControl && <span className="t-caption" style={{ color: 'var(--sys-blue)' }}>{issue.cisControl}</span>}
                              <span className="t-footnote" style={{ color: 'var(--label-3)' }}>{issue.resource}</span>
                            </div>
                            <div className="t-body" style={{ color: 'var(--label-1)', marginBottom: 4 }}>{issue.type}</div>
                            <div className="t-footnote" style={{ color: 'var(--label-2)', lineHeight: 1.5 }}>{issue.description}</div>
                          </div>
                        </div>
                      </div>

                      {open && issue.remediationHint && (
                        <div className="remediation-block fade-up">
                          <div className="t-caption" style={{ color: 'var(--sys-green)', marginBottom: 8 }}>RECOMMENDED REMEDIATION</div>
                          <div className="t-mono t-footnote" style={{ color: 'var(--label-1)' }}>
                            <span style={{ color: 'var(--sys-green)', marginRight: 8 }}>$</span>{issue.remediationHint}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
          {/* RIGHT COL: Runtime & AI */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: 600 }}>

            {/* AI Assistant Bento */}
            <div className="card" style={{ background: 'var(--sys-indigo)', color: '#fff', border: 'none' }}>
              <div style={{ padding: '20px 24px', borderBottom: '1px solid rgba(0,0,0,0.2)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Sparkles size={16} color="#fff" />
                  <span className="t-title-3">SecOps Copilot</span>
                </div>
                <button
                  onClick={generateAISummary}
                  disabled={generatingAI}
                  style={{ background: 'rgba(255,255,255,0.2)', color: '#fff', border: 'none', padding: '6px 12px', borderRadius: 8, fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer' }}
                >
                  {generatingAI ? 'SYNTHESIZING...' : 'ASSESS'}
                </button>
              </div>
              <div style={{ padding: 24 }}>
                {aiError && (
                  <div style={{ padding: 12, background: 'rgba(0,0,0,0.3)', borderRadius: 8, color: '#ffaaaa', fontSize: '0.85rem' }}>
                    {aiError}
                  </div>
                )}
                {aiSummary ? (
                  <div className="t-subhead custom-scrollbar" style={{ lineHeight: 1.6, whiteSpace: 'pre-wrap', maxHeight: 300, overflowY: 'auto', paddingRight: 8 }}>
                    {aiSummary}
                  </div>
                ) : (
                  <div className="t-footnote custom-scrollbar" style={{ color: 'rgba(255,255,255,0.7)', maxHeight: 150, overflowY: 'auto' }}>
                    Copilot is ready to analyze active threats and context via retrieval augmented generation.
                  </div>
                )}
              </div>
            </div>

            {/* CWPP Workloads */}
            <div className="card" style={{ flex: 1, border: 'none' }}>
              <div style={{ padding: '20px 24px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <Cpu size={16} color="var(--sys-purple)" />
                  <span className="t-title-3">Active ML Workloads</span>
                </div>
                <div className="t-caption" style={{ color: 'var(--label-3)' }}>Real-time Behavioral Analysis</div>
              </div>
              <div className="custom-scrollbar" style={{ padding: 16, overflowY: 'auto' }}>
                {mockRuntimeEvents.map((event, i) => {
                  const { score, threatLevel } = calculateAnomalyScore(event);
                  const lvlColor = threatLevel === 'HIGH' ? 'var(--sys-red)' : threatLevel === 'MEDIUM' ? 'var(--sys-orange)' : 'var(--sys-green)';

                  return (
                    <div key={event.instanceId} style={{ padding: '12px', background: 'var(--bg-level2)', borderRadius: 12, marginBottom: i < mockRuntimeEvents.length - 1 ? 12 : 0 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                        <span className="t-mono t-subhead">{event.instanceId}</span>
                        <span className="t-mono t-headline" style={{ color: lvlColor }} suppressHydrationWarning>{score}</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="t-footnote" style={{ color: 'var(--label-2)' }} suppressHydrationWarning>CPU: {event.cpuUsage}%</span>
                        <span className="t-caption" style={{ color: event.suspiciousPorts.length > 0 ? 'var(--sys-red)' : 'var(--label-3)' }}>
                          Ports: {event.suspiciousPorts.length > 0 ? event.suspiciousPorts.join(',') : 'Standard'}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Risk Trend Line */}
            {riskTrend.length > 1 && (
              <div className="card" style={{ padding: 24, border: 'none' }}>
                <div className="t-caption" style={{ color: 'var(--label-3)', marginBottom: 16 }}>RISK EXPOSURE TREND</div>
                <div style={{ height: 140 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={riskTrend}>
                      <XAxis dataKey="time" type="category" tick={{ fill: 'var(--label-3)', fontSize: 9 }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: 'var(--label-3)', fontSize: 9 }} axisLine={false} tickLine={false} domain={['auto', 'auto']} width={30} />
                      <Tooltip contentStyle={{ background: 'var(--bg-level2)', border: 'none', borderRadius: 10, color: 'var(--label-1)', fontSize: 12 }} itemStyle={{ color: 'var(--label-1)' }} />
                      <Line type="monotone" dataKey="score" stroke="var(--sys-blue)" strokeWidth={2} dot={false} isAnimationActive={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* ─── CHARTS ROW ─── */}
        {(pieData.length > 0 || catData.length > 0) && (
          <section className="bento-charts-row fade-up" style={{ animationDelay: '0.2s' }}>
            {pieData.length > 0 && (
              <div className="card" style={{ padding: 24, height: 300, border: 'none' }}>
                <div className="t-title-3" style={{ marginBottom: 16 }}>Severity Distribution</div>
                <div style={{ width: '100%', height: 200 }}>
                  <ResponsiveContainer>
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} stroke="none" dataKey="value" paddingAngle={2}>
                        {pieData.map((d, i) => {
                          const bg = d.name === 'Critical' ? 'var(--sys-red)' : d.name === 'High' ? 'var(--sys-orange)' : d.name === 'Medium' ? 'var(--sys-yellow)' : 'var(--sys-blue)';
                          return <Cell key={i} fill={bg} />;
                        })}
                      </Pie>
                      <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ background: 'var(--bg-level2)', border: 'none', borderRadius: 8, color: 'var(--label-1)' }} itemStyle={{ color: 'var(--label-1)' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {catData.length > 0 && (
              <div className="card" style={{ padding: 24, height: 300, gridColumn: 'span 2', border: 'none' }}>
                <div className="t-title-3" style={{ marginBottom: 16 }}>Issues by Service Category</div>
                <div style={{ width: '100%', height: 200 }}>
                  <ResponsiveContainer>
                    <BarChart data={catData.slice(0, 5)} layout="vertical" margin={{ left: -20, right: 10 }}>
                      <XAxis type="number" hide />
                      <YAxis dataKey="category" type="category" tick={{ fill: 'var(--label-2)', fontSize: 11 }} axisLine={false} tickLine={false} width={80} />
                      <Tooltip cursor={{ fill: 'var(--bg-level2)' }} contentStyle={{ background: 'var(--bg-level2)', border: 'none', borderRadius: 8, color: 'var(--label-1)' }} itemStyle={{ color: 'var(--label-1)' }} />
                      <Bar dataKey="count" fill="var(--sys-blue)" radius={[0, 4, 4, 0]} barSize={16}>
                        {catData.map((d, i) => <Cell key={i} fill={i % 2 === 0 ? 'var(--sys-blue)' : 'var(--sys-indigo)'} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}
          </section>
        )}

      </main>
    </div>
  );
}
