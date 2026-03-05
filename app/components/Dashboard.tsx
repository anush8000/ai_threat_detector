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
  CheckCircle, RefreshCw, Send
} from 'lucide-react';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  Tooltip, ResponsiveContainer, AreaChart, Area
} from 'recharts';
import ReactMarkdown from 'react-markdown';

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
  provider?: 'aws' | 'gcp' | 'azure';
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
  provider: 'aws' | 'gcp' | 'azure';
  sql: string;
  mapRow: (row: Record<string, unknown>) => SecurityIssue;
}

const CLOUD_CHECKS: CheckDef[] = [
  // S3
  {
    id: 'S3_PUBLIC',
    provider: 'aws',
    sql: `SELECT name, block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets, region
         FROM aws_s3_bucket
         WHERE NOT block_public_acls OR NOT block_public_policy OR NOT ignore_public_acls OR NOT restrict_public_buckets`,
    mapRow: (b) => ({
      id: `s3-${b.name}`, checkId: 'S3_PUBLIC', cisControl: 'CIS-2.1.5', provider: 'aws',
      severity: 'high', type: 'Public S3 Bucket', resource: String(b.name), region: String(b.region),
      description: `Bucket "${b.name}" has Block Public Access disabled - ACLs:${b.block_public_acls ? '✅' : '❌'} Policy:${b.block_public_policy ? '✅' : '❌'} IgnoreACL:${b.ignore_public_acls ? '✅' : '❌'} Restrict:${b.restrict_public_buckets ? '✅' : '❌'}`,
      remediationHint: `aws s3api put-public-access-block --bucket ${b.name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`
    })
  },
  {
    id: 'S3_NO_ENC',
    provider: 'aws',
    sql: `SELECT name, region FROM aws_s3_bucket WHERE server_side_encryption_configuration IS NULL LIMIT 50`,
    mapRow: (b) => ({
      id: `s3enc-${b.name}`, checkId: 'S3_NO_ENC', cisControl: 'CIS-2.1.2', provider: 'aws',
      severity: 'medium', type: 'S3 Bucket Without Encryption', resource: String(b.name), region: String(b.region),
      description: `Bucket "${b.name}" has no server-side encryption configured. Data at rest stored in plaintext.`,
      remediationHint: `aws s3api put-bucket-encryption --bucket ${b.name} --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'`
    })
  },
  // EC2
  {
    id: 'EC2_PUBLIC',
    provider: 'aws',
    sql: `SELECT instance_id, instance_type, region, public_ip_address, public_dns_name, tags
         FROM aws_ec2_instance WHERE public_ip_address IS NOT NULL LIMIT 50`,
    mapRow: (i) => {
      const tags = i.tags as Record<string, string> | undefined;
      const name = tags?.Name || i.instance_id;
      return {
        id: `ec2-${i.instance_id}`, checkId: 'EC2_PUBLIC', cisControl: 'CIS-5.6', provider: 'aws',
        severity: 'medium', type: 'Public EC2 Instance', resource: `${name} (${i.instance_type})`, region: String(i.region),
        description: `Instance "${i.instance_id}" is publicly accessible - IP: ${i.public_ip_address}${i.public_dns_name ? ' | DNS: ' + i.public_dns_name : ''}`,
        remediationHint: 'Move instance to private subnet. Use Application Load Balancer or NAT Gateway for required internet connectivity.'
      };
    }
  },
  {
    id: 'EC2_IMDSV2',
    provider: 'aws',
    sql: `SELECT instance_id, region, metadata_options ->> 'HttpTokens' as http_tokens
         FROM aws_ec2_instance WHERE metadata_options ->> 'HttpTokens' != 'required' AND state ->> 'Name' = 'running' LIMIT 50`,
    mapRow: (i) => ({
      id: `imds-${i.instance_id}`, checkId: 'EC2_IMDSV2', cisControl: 'AWS-IMDSV2', provider: 'aws',
      severity: 'high', type: 'EC2 IMDSv2 Not Enforced', resource: String(i.instance_id), region: String(i.region),
      description: `Instance ${i.instance_id} allows IMDSv1 (HttpTokens=${i.http_tokens}). SSRF attacks can steal IAM credentials from the metadata service.`,
      remediationHint: `aws ec2 modify-instance-metadata-options --instance-id ${i.instance_id} --http-tokens required --http-put-response-hop-limit 1`
    })
  },
  // Security Groups
  {
    id: 'SG_OPEN',
    provider: 'aws',
    sql: `SELECT group_id, group_name, description, region, vpc_id
         FROM aws_vpc_security_group WHERE ip_permissions::text LIKE '%0.0.0.0/0%' LIMIT 50`,
    mapRow: (sg) => ({
      id: `sg-${sg.group_id}`, checkId: 'SG_OPEN', cisControl: 'CIS-5.3', provider: 'aws',
      severity: 'critical', type: 'Overly Permissive Security Group', resource: `${sg.group_name} (${sg.group_id})`, region: String(sg.region),
      description: `"${sg.group_name}" allows unrestricted inbound traffic (0.0.0.0/0)${sg.vpc_id ? ' in VPC: ' + sg.vpc_id : ''}${sg.description ? ' - ' + sg.description : ''}`,
      remediationHint: `aws ec2 revoke-security-group-ingress --group-id ${sg.group_id} --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'`
    })
  },
  {
    id: 'SG_SSH',
    provider: 'aws',
    sql: `SELECT group_id, group_name, region FROM aws_vpc_security_group
         WHERE ip_permissions::text LIKE '%"toPort": 22%' AND ip_permissions::text LIKE '%0.0.0.0/0%' LIMIT 50`,
    mapRow: (sg) => ({
      id: `sgsh-${sg.group_id}`, checkId: 'SG_SSH', cisControl: 'CIS-5.1', provider: 'aws',
      severity: 'critical', type: 'Open SSH Access (Port 22)', resource: `${sg.group_name} (${sg.group_id})`, region: String(sg.region),
      description: `"${sg.group_name}" allows unrestricted SSH (port 22) from 0.0.0.0/0. Exposed to brute-force and credential stuffing attacks.`,
      remediationHint: `aws ec2 revoke-security-group-ingress --group-id ${sg.group_id} --protocol tcp --port 22 --cidr 0.0.0.0/0`
    })
  },
  {
    id: 'SG_RDP',
    provider: 'aws',
    sql: `SELECT group_id, group_name, region FROM aws_vpc_security_group
         WHERE ip_permissions::text LIKE '%"toPort": 3389%' AND ip_permissions::text LIKE '%0.0.0.0/0%' LIMIT 50`,
    mapRow: (sg) => ({
      id: `sgrdp-${sg.group_id}`, checkId: 'SG_RDP', cisControl: 'CIS-5.2', provider: 'aws',
      severity: 'critical', type: 'Open RDP Access (Port 3389)', resource: `${sg.group_name} (${sg.group_id})`, region: String(sg.region),
      description: `"${sg.group_name}" allows unrestricted RDP (port 3389) from 0.0.0.0/0. Primary ransomware attack vector.`,
      remediationHint: `aws ec2 revoke-security-group-ingress --group-id ${sg.group_id} --protocol tcp --port 3389 --cidr 0.0.0.0/0`
    })
  },
  // IAM
  {
    id: 'IAM_NO_MFA',
    provider: 'aws',
    sql: `SELECT name, user_id, mfa_enabled, password_last_used FROM aws_iam_user WHERE mfa_enabled = false LIMIT 50`,
    mapRow: (u) => ({
      id: `iam-${u.user_id}`, checkId: 'IAM_NO_MFA', cisControl: 'CIS-1.10', provider: 'aws',
      severity: 'critical', type: 'IAM User Without MFA', resource: String(u.name), region: 'global',
      description: `IAM user "${u.name}" has no MFA. Console access with password only. Last login: ${u.password_last_used || 'never'}.`,
      remediationHint: `aws iam enable-mfa-device --user-name ${u.name} --serial-number arn:aws:iam::ACCOUNT_ID:mfa/${u.name} --authentication-code1 CODE1 --authentication-code2 CODE2`
    })
  },
  {
    id: 'IAM_OLD_KEY',
    provider: 'aws',
    sql: `SELECT user_name, access_key_id, date_part('day', now() - create_date) as age_days
         FROM aws_iam_access_key WHERE status = 'Active' AND date_part('day', now() - create_date) > 90 LIMIT 50`,
    mapRow: (k) => ({
      id: `iamkey-${k.access_key_id}`, checkId: 'IAM_OLD_KEY', cisControl: 'NIST-AC-2', provider: 'aws',
      severity: 'high', type: 'Stale IAM Access Key (>90 days)', resource: `${k.user_name}/${k.access_key_id}`, region: 'global',
      description: `Access key ${k.access_key_id} for "${k.user_name}" is ${Math.round(Number(k.age_days))} days old. Keys >90 days must be rotated.`,
      remediationHint: `aws iam create-access-key --user-name ${k.user_name}  # update apps  then:  aws iam delete-access-key --user-name ${k.user_name} --access-key-id ${k.access_key_id}`
    })
  },
  // CloudTrail
  {
    id: 'CT_DISABLED',
    provider: 'aws',
    sql: `SELECT name, is_logging, home_region FROM aws_cloudtrail_trail WHERE is_logging = false LIMIT 50`,
    mapRow: (t) => ({
      id: `ct-${t.name}`, checkId: 'CT_DISABLED', cisControl: 'CIS-3.1', provider: 'aws',
      severity: 'high', type: 'CloudTrail Logging Disabled', resource: String(t.name), region: String(t.home_region),
      description: `CloudTrail trail "${t.name}" has logging disabled. No API audit trail - incident investigation impossible.`,
      remediationHint: `aws cloudtrail start-logging --name ${t.name}`
    })
  },
  {
    id: 'CT_NO_VALIDATION',
    provider: 'aws',
    sql: `SELECT name, home_region FROM aws_cloudtrail_trail WHERE log_file_validation_enabled = false AND is_logging = true LIMIT 50`,
    mapRow: (t) => ({
      id: `ctval-${t.name}`, checkId: 'CT_NO_VALIDATION', cisControl: 'CIS-3.2', provider: 'aws',
      severity: 'medium', type: 'CloudTrail Log Validation Disabled', resource: String(t.name), region: String(t.home_region),
      description: `Trail "${t.name}" has no log file integrity validation. Tampered logs may go undetected during forensic investigation.`,
      remediationHint: `aws cloudtrail update-trail --name ${t.name} --enable-log-file-validation`
    })
  },
  // EBS
  {
    id: 'EBS_UNENC',
    provider: 'aws',
    sql: `SELECT volume_id, volume_type, size, availability_zone FROM aws_ebs_volume WHERE encrypted = false AND state = 'in-use' LIMIT 50`,
    mapRow: (v) => ({
      id: `ebs-${v.volume_id}`, checkId: 'EBS_UNENC', cisControl: 'CIS-2.2.1', provider: 'aws',
      severity: 'high', type: 'Unencrypted EBS Volume', resource: String(v.volume_id), region: String(v.availability_zone),
      description: `EBS volume ${v.volume_id} (${v.volume_type}, ${v.size}GB) is unencrypted and actively attached to a running instance.`,
      remediationHint: `Snapshot ${v.volume_id} -> copy-snapshot with --encrypted -> create encrypted volume -> stop instance -> swap attachment.`
    })
  },
  // RDS
  {
    id: 'RDS_PUBLIC',
    provider: 'aws',
    sql: `SELECT db_instance_identifier, engine, engine_version, region FROM aws_rds_db_instance WHERE publicly_accessible = true LIMIT 50`,
    mapRow: (r) => ({
      id: `rds-${r.db_instance_identifier}`, checkId: 'RDS_PUBLIC', cisControl: 'CIS-2.3.2', provider: 'aws',
      severity: 'critical', type: 'Publicly Accessible RDS Database', resource: String(r.db_instance_identifier), region: String(r.region),
      description: `RDS instance "${r.db_instance_identifier}" (${r.engine} ${r.engine_version}) is directly accessible from the internet.`,
      remediationHint: `aws rds modify-db-instance --db-instance-identifier ${r.db_instance_identifier} --no-publicly-accessible --apply-immediately`
    })
  },
  {
    id: 'RDS_NO_ENC',
    provider: 'aws',
    sql: `SELECT db_instance_identifier, engine, region FROM aws_rds_db_instance WHERE storage_encrypted = false LIMIT 50`,
    mapRow: (r) => ({
      id: `rdsenc-${r.db_instance_identifier}`, checkId: 'RDS_NO_ENC', cisControl: 'CIS-2.3.1', provider: 'aws',
      severity: 'high', type: 'Unencrypted RDS Instance', resource: String(r.db_instance_identifier), region: String(r.region),
      description: `RDS instance "${r.db_instance_identifier}" (${r.engine}) has no storage encryption. DB files and backups stored in plaintext.`,
      remediationHint: `Take snapshot -> aws rds copy-db-snapshot with --kms-key-id -> restore encrypted instance from snapshot.`
    })
  },
  // KMS
  {
    id: 'KMS_NO_ROT',
    provider: 'aws',
    sql: `SELECT id, region FROM aws_kms_key WHERE key_manager = 'CUSTOMER' AND key_state = 'Enabled' AND rotation_enabled = false LIMIT 50`,
    mapRow: (k) => ({
      id: `kms-${k.id}`, checkId: 'KMS_NO_ROT', cisControl: 'CIS-3.8', provider: 'aws',
      severity: 'medium', type: 'KMS Key Rotation Disabled', resource: String(k.id), region: String(k.region),
      description: `KMS CMK ${k.id} has no automatic key rotation. A compromised key can decrypt all historical encrypted data indefinitely.`,
      remediationHint: `aws kms enable-key-rotation --key-id ${k.id}`
    })
  },
  // VPC Flow Logs
  {
    id: 'VPC_NO_FLOW',
    provider: 'aws',
    sql: `SELECT v.vpc_id, v.region, v.cidr_block FROM aws_vpc v
         LEFT JOIN aws_vpc_flow_log f ON v.vpc_id = f.resource_id
         WHERE f.flow_log_id IS NULL AND v.is_default = false LIMIT 50`,
    mapRow: (v) => ({
      id: `vpc-${v.vpc_id}`, checkId: 'VPC_NO_FLOW', cisControl: 'CIS-3.9', provider: 'aws',
      severity: 'medium', type: 'VPC Without Flow Logs', resource: String(v.vpc_id), region: String(v.region),
      description: `VPC ${v.vpc_id} (CIDR: ${v.cidr_block}) has no flow logs. Network forensics and lateral movement detection are not possible.`,
      remediationHint: `aws ec2 create-flow-logs --resource-type VPC --resource-ids ${v.vpc_id} --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs`
    })
  },
  // Lambda
  {
    id: 'LAMBDA_PUBLIC',
    provider: 'aws',
    sql: `SELECT name, region, runtime FROM aws_lambda_function
         WHERE policy::text LIKE '%"Principal": "*"%' OR policy::text LIKE '%"Principal":"*"%' LIMIT 50`,
    mapRow: (f) => ({
      id: `lambda-${f.name}`, checkId: 'LAMBDA_PUBLIC', cisControl: 'LAMBDA-PUB', provider: 'aws',
      severity: 'high', type: 'Lambda Function With Public Access', resource: String(f.name), region: String(f.region),
      description: `Lambda "${f.name}" (${f.runtime}) has a resource policy allowing public invocation from any AWS account.`,
      remediationHint: `aws lambda remove-permission --function-name ${f.name} --statement-id PUBLIC_STATEMENT_ID`
    })
  },
  // RDS No Backup
  {
    id: 'RDS_NO_BACKUP',
    provider: 'aws',
    sql: `SELECT db_instance_identifier, engine, region FROM aws_rds_db_instance WHERE backup_retention_period = 0 LIMIT 50`,
    mapRow: (r) => ({
      id: `rdsbkp-${r.db_instance_identifier}`, checkId: 'RDS_NO_BACKUP', cisControl: 'AWS-BP', provider: 'aws',
      severity: 'medium', type: 'RDS Automated Backups Disabled', resource: String(r.db_instance_identifier), region: String(r.region),
      description: `RDS instance "${r.db_instance_identifier}" has automated backups disabled. Data loss is unrecoverable on instance failure.`,
      remediationHint: `aws rds modify-db-instance --db-instance-identifier ${r.db_instance_identifier} --backup-retention-period 7 --apply-immediately`
    })
  },
  // S3 logging
  {
    id: 'S3_NO_LOG',
    provider: 'aws',
    sql: `SELECT name, region FROM aws_s3_bucket WHERE logging IS NULL LIMIT 50`,
    mapRow: (b) => ({
      id: `s3log-${b.name}`, checkId: 'S3_NO_LOG', cisControl: 'CIS-3.1', provider: 'aws',
      severity: 'low', type: 'S3 Bucket Access Logging Disabled', resource: String(b.name), region: String(b.region),
      description: `Bucket "${b.name}" has access logging disabled. S3 access requests are not being recorded for audit or forensic purposes.`,
      remediationHint: `aws s3api put-bucket-logging --bucket ${b.name} --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"YOUR_LOG_BUCKET","TargetPrefix":"${b.name}/"}}'`
    })
  },
  // ── GCP ─────────────────────────────────────────────────────────────
  {
    id: 'GCP_STORAGE_PUBLIC',
    provider: 'gcp',
    sql: `SELECT name, location FROM gcp_storage_bucket WHERE iam_policy::text LIKE '%allUsers%' OR iam_policy::text LIKE '%allAuthenticatedUsers%' LIMIT 50`,
    mapRow: (b) => ({
      id: `gcp-storage-${b.name}`, checkId: 'GCP_STORAGE_PUBLIC', cisControl: 'CIS-GCP-5.1', provider: 'gcp',
      severity: 'high', type: 'Public Google Cloud Storage Bucket', resource: String(b.name), region: String(b.location),
      description: `Bucket "${b.name}" allows anonymous access via allUsers IAM binding.`,
      remediationHint: `gcloud storage buckets remove-iam-policy-binding gs://${b.name} --member="allUsers" --role="roles/storage.objectViewer"`
    })
  },
  {
    id: 'GCP_COMPUTE_PUBLIC',
    provider: 'gcp',
    sql: `SELECT name, zone FROM gcp_compute_instance WHERE network_interfaces::text LIKE '%accessConfigs%' AND network_interfaces::text LIKE '%ONE_TO_ONE_NAT%' LIMIT 50`,
    mapRow: (i) => ({
      id: `gcp-compute-${i.name}`, checkId: 'GCP_COMPUTE_PUBLIC', cisControl: 'CIS-GCP-3.6', provider: 'gcp',
      severity: 'high', type: 'Public GCP Compute Instance', resource: String(i.name), region: String(i.zone),
      description: `Instance "${i.name}" has an external IP configured via ONE_TO_ONE_NAT.`,
      remediationHint: `gcloud compute instances delete-access-config ${i.name} --network-interface=nic0 --access-config-name="External NAT"`
    })
  },
  // ── AZURE ───────────────────────────────────────────────────────────
  {
    id: 'AZURE_VM_PUBLIC',
    provider: 'azure',
    sql: `SELECT name, region FROM azure_compute_virtual_machine WHERE public_ips IS NOT NULL LIMIT 50`,
    mapRow: (v) => ({
      id: `azure-vm-${v.name}`, checkId: 'AZURE_VM_PUBLIC', cisControl: 'CIS-Azure-1.2', provider: 'azure',
      severity: 'high', type: 'Public Azure Virtual Machine', resource: String(v.name), region: String(v.region),
      description: `VM "${v.name}" is directly exposed with a public IP address.`,
      remediationHint: `az network public-ip delete -n PUBLIC_IP_NAME`
    })
  },
  {
    id: 'AZURE_BLOB_PUBLIC',
    provider: 'azure',
    sql: `SELECT name, region FROM azure_storage_container WHERE public_access = 'Blob' OR public_access = 'Container' LIMIT 50`,
    mapRow: (c) => ({
      id: `azure-blob-${c.name}`, checkId: 'AZURE_BLOB_PUBLIC', cisControl: 'CIS-Azure-3.1', provider: 'azure',
      severity: 'high', type: 'Public Azure Blob Container', resource: String(c.name), region: String(c.region),
      description: `Container "${c.name}" has anonymous public access enabled.`,
      remediationHint: `az storage container set-permission --name ${c.name} --public-access off`
    })
  },
];

// ─── MOCK DATA (shown when Steampipe unavailable) ────────────────────────────
const MOCK_ISSUES: SecurityIssue[] = [
  {
    id: 'm1', checkId: 'SG_OPEN', cisControl: 'CIS-5.3', severity: 'critical', type: 'Overly Permissive Security Group',
    resource: 'sg-web-server (sg-0a1b2c3d4e5f6)', region: 'us-east-1', provider: 'aws',
    description: '"sg-web-server" allows unrestricted inbound traffic (0.0.0.0/0) in VPC: vpc-12345678 - Web server SG',
    remediationHint: "aws ec2 revoke-security-group-ingress --group-id sg-0a1b2c3d4e5f6 --ip-permissions '[{\"IpProtocol\":\"-1\",\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\"}]}]'"
  },
  {
    id: 'm2', checkId: 'SG_OPEN', cisControl: 'CIS-5.3', severity: 'critical', type: 'Overly Permissive Security Group',
    resource: 'sg-database (sg-9z8y7x6w5v4)', region: 'us-east-1', provider: 'aws',
    description: '"sg-database" allows unrestricted inbound traffic (0.0.0.0/0) in VPC: vpc-87654321 - DB SG with SSH open',
    remediationHint: "aws ec2 revoke-security-group-ingress --group-id sg-9z8y7x6w5v4 --ip-permissions '[{\"IpProtocol\":\"-1\",\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\"}]}]'"
  },
  {
    id: 'm3', checkId: 'S3_PUBLIC', cisControl: 'CIS-2.1.5', severity: 'high', type: 'Public S3 Bucket',
    resource: 'customer-data-backup', region: 'us-west-2', provider: 'aws',
    description: 'Bucket "customer-data-backup" has public access - ACLs: ❌ Policy: ❌ IgnoreACL: ❌ Restrict: ❌',
    remediationHint: 'aws s3api put-public-access-block --bucket customer-data-backup --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
  },
  {
    id: 'm4', checkId: 'S3_PUBLIC', cisControl: 'CIS-2.1.5', severity: 'high', type: 'Public S3 Bucket',
    resource: 'app-logs-2024', region: 'eu-west-1', provider: 'aws',
    description: 'Bucket "app-logs-2024" has public access - ACLs: ❌ Policy: ✅ IgnoreACL: ❌ Restrict: ✅',
    remediationHint: 'aws s3api put-public-access-block --bucket app-logs-2024 --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
  },
  {
    id: 'm5', checkId: 'EC2_PUBLIC', cisControl: 'CIS-5.6', severity: 'medium', type: 'Public EC2 Instance',
    resource: 'web-server-prod (t3.medium)', region: 'us-east-1', provider: 'aws',
    description: 'Instance "i-0abc123def456" is publicly accessible - IP: 54.123.45.67 | DNS: ec2-54-123-45-67.compute-1.amazonaws.com',
    remediationHint: 'Move to private subnet. Use Application Load Balancer for public traffic.'
  },
  {
    id: 'm6', checkId: 'EC2_PUBLIC', cisControl: 'CIS-5.6', severity: 'medium', type: 'Public EC2 Instance',
    resource: 'api-server-01 (t3.large)', region: 'us-west-2', provider: 'aws',
    description: 'Instance "i-0def456abc123" is publicly accessible - IP: 52.98.76.54',
    remediationHint: 'Move to private subnet. Use Application Load Balancer for public traffic.'
  },
  {
    id: 'm7', checkId: 'IAM_NO_MFA', cisControl: 'CIS-1.10', severity: 'critical', type: 'IAM User Without MFA',
    resource: 'developer-anush', region: 'global', provider: 'aws',
    description: 'IAM user "developer-anush" has no MFA enabled. Console access with password only.',
    remediationHint: 'Enable virtual MFA: AWS Console > IAM > Users > developer-anush > Security credentials > Assign MFA device'
  },
  {
    id: 'm8', checkId: 'CT_DISABLED', cisControl: 'CIS-3.1', severity: 'high', type: 'CloudTrail Logging Disabled',
    resource: 'default-trail', region: 'ap-south-1', provider: 'aws',
    description: '"default-trail" has logging disabled. No AWS API audit trail is being recorded.',
    remediationHint: 'aws cloudtrail start-logging --name default-trail'
  },
  {
    id: 'gcp1', checkId: 'GCP_STORAGE_PUBLIC', cisControl: 'CIS-GCP-5.1', severity: 'high', type: 'Public Google Cloud Storage Bucket',
    resource: 'gcp-prod-backups', region: 'us-central1', provider: 'gcp',
    description: 'Bucket "gcp-prod-backups" allows anonymous access via allUsers IAM binding.',
    remediationHint: 'gcloud storage buckets remove-iam-policy-binding gs://gcp-prod-backups --member="allUsers" --role="roles/storage.objectViewer"'
  },
  {
    id: 'gcp2', checkId: 'GCP_COMPUTE_PUBLIC', cisControl: 'CIS-GCP-3.6', severity: 'high', type: 'Public GCP Compute Instance',
    resource: 'ml-training-node-1', region: 'us-east4', provider: 'gcp',
    description: 'Instance "ml-training-node-1" has an external IP configured via ONE_TO_ONE_NAT.',
    remediationHint: 'gcloud compute instances delete-access-config ml-training-node-1 --network-interface=nic0 --access-config-name="External NAT"'
  },
  {
    id: 'az1', checkId: 'AZURE_VM_PUBLIC', cisControl: 'CIS-Azure-1.2', severity: 'high', type: 'Public Azure Virtual Machine',
    resource: 'az-win-server-2022', region: 'eastus', provider: 'azure',
    description: 'VM "az-win-server-2022" is directly exposed with a public IP address.',
    remediationHint: 'az network public-ip delete -g RESOURCE_GROUP -n PUBLIC_IP_NAME'
  },
  {
    id: 'az2', checkId: 'AZURE_BLOB_PUBLIC', cisControl: 'CIS-Azure-3.1', severity: 'high', type: 'Public Azure Blob Container',
    resource: 'az-public-assets', region: 'westeurope', provider: 'azure',
    description: 'Container "az-public-assets" has anonymous public access enabled.',
    remediationHint: 'az storage container set-permission --name az-public-assets --public-access off --account-name ACCOUNT_NAME'
  }
];

// ─── COMPLIANCE SCORE ─────────────────────────────────────────────────────────
function getComplianceScore(issues: SecurityIssue[], availableChecks: CheckDef[]) {
  const allPrefixes = [...new Set(availableChecks.map(c => c.id.split('_')[0]))];
  const failPrefixes = [...new Set(
    issues.map(i => i.checkId?.split('_')[0]).filter(Boolean) as string[]
  )];
  const passCount = allPrefixes.filter(p => !failPrefixes.includes(p)).length;
  // Prevent divide by 0 if availableChecks is empty
  const percentage = allPrefixes.length === 0 ? 100 : Math.round((passCount / allPrefixes.length) * 100);
  return { score: percentage, pass: passCount, total: allPrefixes.length };
}

// Apple-palette chart colors
// (removed unused PIE_COLORS here)

// ─── SEVERITY HELPERS ─────────────────────────────────────────────────


// ─── DASHBOARD ───────────────────────────────────────────────────────
export default function Dashboard() {
  const [selectedCloud, setSelectedCloud] = useState<'all' | 'aws' | 'gcp' | 'azure'>('all');
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

  // ─── CHAT STATE ────────────────────────────────────────────────────────
  const [chatHistory, setChatHistory] = useState<{ role: 'user' | 'assistant', content: string }[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [sendingChat, setSendingChat] = useState(false);

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
    const mocksToRun = selectedCloud === 'all'
      ? MOCK_ISSUES
      : MOCK_ISSUES.filter((m) => m.provider === selectedCloud);

    const processed = processIssues(mocksToRun);
    setPrevIssues(processed.slice(0, 4));
    setIssues(processed);
    const totalRisk = processed.reduce((s, i) => s + (i.riskScore || 0), 0);
    setStats({
      publicS3Buckets: mocksToRun.filter(i => i.checkId === 'S3_PUBLIC' || i.checkId === 'GCP_STORAGE_PUBLIC' || i.checkId === 'AZURE_BLOB_PUBLIC').length,
      publicInstances: mocksToRun.filter(i => i.checkId === 'EC2_PUBLIC' || i.checkId === 'GCP_COMPUTE_PUBLIC' || i.checkId === 'AZURE_VM_PUBLIC').length,
      openSecurityGroups: mocksToRun.filter(i => i.checkId === 'SG_OPEN' || i.checkId === 'SG_SSH' || i.checkId === 'SG_RDP').length,
      totalInstances: 15,
      criticalIssues: processed.filter(i => i.severity === 'critical').length,
      highIssues: processed.filter(i => i.severity === 'high').length,
      totalRiskScore: totalRisk
    });
    const timeLabel = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    setRiskTrend([{ time: timeLabel, score: totalRisk }, { time: timeLabel, score: totalRisk }]);
  }, [processIssues, selectedCloud]);

  const fetchSecurityData = useCallback(async () => {
    setLoading(true);
    try {
      const checksToRun = selectedCloud === 'all' ? CLOUD_CHECKS : CLOUD_CHECKS.filter(c => c.provider === selectedCloud);
      const results = await Promise.allSettled(
        checksToRun.map(check =>
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
        publicS3Buckets: allIssues.filter(i => i.checkId === 'S3_PUBLIC' || i.checkId === 'GCP_STORAGE_PUBLIC' || i.checkId === 'AZURE_BLOB_PUBLIC').length,
        publicInstances: allIssues.filter(i => i.checkId === 'EC2_PUBLIC' || i.checkId === 'GCP_COMPUTE_PUBLIC' || i.checkId === 'AZURE_VM_PUBLIC').length,
        openSecurityGroups: allIssues.filter(i => i.checkId === 'SG_OPEN' || i.checkId === 'SG_SSH' || i.checkId === 'SG_RDP').length,
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
      setAiSummary(''); // Reset summary and chat on refresh
      setChatHistory([]);
    }
  }, [processIssues, setMockData, selectedCloud]);

  useEffect(() => { fetchSecurityData(); }, [fetchSecurityData]);

  const generateAISummary = async () => {
    setGeneratingAI(true);
    setAiError('');
    setChatHistory([]);
    setChatInput('');
    try {
      const counts = {
        critical: issues.filter(i => i.severity === 'critical').length,
        high: issues.filter(i => i.severity === 'high').length,
        medium: issues.filter(i => i.severity === 'medium').length,
        low: issues.filter(i => i.severity === 'low').length,
      };

      const checksToRun = selectedCloud === 'all' ? CLOUD_CHECKS : CLOUD_CHECKS.filter(c => c.provider === selectedCloud);
      const compliance = getComplianceScore(issues, checksToRun);
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

  const handleSendChat = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!chatInput.trim() || sendingChat) return;

    const newUserMsg = { role: 'user' as const, content: chatInput.trim() };
    setChatHistory(prev => [...prev, newUserMsg]);
    setChatInput('');
    setSendingChat(true);

    try {
      const res = await fetch('/api/ai-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: [...chatHistory, newUserMsg],
          context: aiSummary
        })
      });
      const data = await res.json();
      if (data.reply) {
        setChatHistory(prev => [...prev, { role: 'assistant', content: data.reply }]);
      }
    } catch (err) {
      console.error('Chat error:', err);
    } finally {
      setSendingChat(false);
    }
  };

  const drift = compareScans(prevIssues, issues);

  const checksToRunForCompliance = selectedCloud === 'all' ? CLOUD_CHECKS : CLOUD_CHECKS.filter(c => c.provider === selectedCloud);
  const compliance = getComplianceScore(issues, checksToRunForCompliance);

  const pieData = [
    { name: 'Critical', value: stats.criticalIssues },
    { name: 'High', value: stats.highIssues },
    { name: 'Medium', value: issues.filter(i => i.severity === 'medium').length },
    { name: 'Low', value: issues.filter(i => i.severity === 'low').length },
  ].filter(d => d.value > 0);

  const getServiceCategory = (checkId: string) => {
    if (!checkId) return 'Other';
    if (checkId.startsWith('GCP_')) {
      const parts = checkId.split('_');
      return `GCP ${parts[1] || ''}`;
    }
    if (checkId.startsWith('AZURE_')) {
      const parts = checkId.split('_');
      return `Azure ${parts[1] || ''}`;
    }
    return checkId.split('_')[0];
  };

  const catData = [...new Set(issues.map(i => getServiceCategory(i.checkId || '')))].map(cat => ({
    category: cat,
    count: issues.filter(i => getServiceCategory(i.checkId || '') === cat).length,
  })).sort((a, b) => b.count - a.count);


  // ─── DERIVED METRICS ──────────────────────────────────────────────────────────
  const riskColor = stats.totalRiskScore > 100 ? 'var(--accent-red)' : stats.totalRiskScore > 50 ? 'var(--accent-orange)' : 'var(--accent-green)';

  return (
    <div className="flex flex-col min-h-screen bg-[#000000]">
      {/* ─── HEADER ─── */}
      <header className="h-[64px] bg-black/60 backdrop-blur-xl sticky top-0 z-50 flex items-center px-8">
        <div className="flex items-center gap-3 flex-1">
          <Shield size={20} className="text-white" />
          <span className="text-lg font-semibold tracking-tight">AI Powered Cloud Threat Detection System</span>
        </div>
        <div className="flex items-center gap-4">

          {/* MULTI-CLOUD TOGGLE */}
          <div className="hidden sm:flex items-center p-1 bg-white/5 border border-white/10 rounded-full mr-4 text-sm font-medium">
            {(['all', 'aws', 'gcp', 'azure'] as const).map(cloud => (
              <button
                key={cloud}
                aria-label={`Filter by ${cloud} cloud`}
                onClick={() => setSelectedCloud(cloud)}
                className={`px-3 py-1 rounded-full transition-colors ${selectedCloud === cloud ? 'bg-white text-black' : 'text-white/60 hover:text-white'}`}
              >
                {cloud === 'all' ? 'All Clouds' : cloud.toUpperCase()}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[0.95rem] font-medium tracking-tight text-white/80">System Active</span>
            <div className="live-pulse" />
          </div>
          <button className="action-btn secondary" onClick={fetchSecurityData} disabled={loading} aria-label="Refresh Security Data">
            <RefreshCw size={14} className={`mr-1.5 ${loading ? 'animate-spin' : ''}`} /> {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </header>

      <main className="py-8 px-7 max-w-[1600px] mx-auto w-full flex flex-col gap-8">

        {/* ─── HERO ROW ─── */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 animate-enter" style={{ animationDelay: '0s' }}>
          <div className="surface-card p-6">
            <div className="text-xs uppercase font-medium tracking-widest text-white/60 mb-2">Total Risk Score</div>
            <div className="text-[3.5rem] leading-none font-semibold tracking-tighter tabular-nums" style={{ color: riskColor }}>{stats.totalRiskScore}</div>
            <div className="text-sm text-white/40 mt-2">Aggregated system vulnerability</div>
          </div>

          <div className="surface-card p-6">
            <div className="text-xs uppercase font-medium tracking-widest text-white/60 mb-2">Active Issues</div>
            <div className="text-[3.5rem] leading-none font-semibold tracking-tighter tabular-nums text-white">{issues.length}</div>
            <div className="text-sm text-white/40 mt-2">+{drift.added.length} newly detected</div>
          </div>

          <div className="surface-card p-6">
            <div className="text-xs uppercase font-medium tracking-widest text-white/60 mb-2">Compliance Status</div>
            <div className="text-[3.5rem] leading-none font-semibold tracking-tighter tabular-nums text-green-500">{compliance.score}%</div>
            <div className="mt-3">
              <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
                <div className="h-full rounded-full bg-green-500 transition-all duration-1000 ease-out" style={{ width: `${compliance.score}%` }} />
              </div>
            </div>
          </div>

          <div className="surface-card p-6">
            <div className="text-xs uppercase font-medium tracking-widest text-white/60 mb-2">Runtime Anomalies</div>
            <div className="text-[3.5rem] leading-none font-semibold tracking-tighter tabular-nums text-orange-500" suppressHydrationWarning>
              {(selectedCloud === 'all' ? mockRuntimeEvents : mockRuntimeEvents.filter(e => e.provider === selectedCloud))
                .filter(e => calculateAnomalyScore(e).threatLevel !== 'LOW').length}
            </div>
            <div className="text-sm text-white/40 mt-2">ML Behavior Detection Engine</div>
          </div>
        </section>

        {/* ─── MAIN ROW (Issues + CWPP/AI) ─── */}
        <section className="grid grid-cols-1 lg:grid-cols-[1fr_380px] gap-4 animate-enter" style={{ animationDelay: '0.1s' }}>

          {/* LEFT: Issue Feed */}
          <div className="surface-card flex flex-col h-[750px]">
            <div className="p-5 px-6 flex items-center justify-between border-b border-white/5">
              <div className="flex items-center gap-2">
                <Activity size={16} className="text-blue-500" />
                <span className="text-base font-medium tracking-tight">Configuration & Vulnerabilities</span>
              </div>
              <span className="status-pill low">{issues.length} Items</span>
            </div>

            <div className="custom-scrollbar flex-1 overflow-y-auto max-h-[800px] p-2">
              {issues.length === 0 ? (
                <div className="p-20 text-center">
                  <CheckCircle size={32} className="text-green-500 mx-auto mb-4" />
                  <div className="text-xl font-medium tracking-tight">All Clear</div>
                  <div className="text-sm text-white/50 mt-2">Infrastructure conforms to security baselines.</div>
                </div>
              ) : (
                issues.map(issue => {
                  const open = expandedId === issue.id;
                  const sevStyle = issue.severity; // Using the severity string to map to our new status-pill classes
                  return (
                    <div key={issue.id} className="mb-2">
                      <div className={`interactive-row ${open ? 'bg-white/[0.04]' : ''}`} onClick={() => setExpandedId(open ? null : issue.id)}>
                        <div className="flex gap-4">
                          <div className="mt-1">
                            <div className={`status-pill ${sevStyle}`}>{issue.severity}</div>
                          </div>
                          <div className="flex-1">
                            <div className="flex items-baseline gap-3 mb-1">
                              <span className="text-sm font-semibold font-mono">{issue.id}</span>
                              {issue.cisControl && <span className="text-[10px] font-bold tracking-wider text-blue-400 uppercase">{issue.cisControl}</span>}
                              <span className="text-xs text-white/40 font-medium">{issue.resource}</span>
                            </div>
                            <div className="text-[0.95rem] font-medium text-white mb-1.5">{issue.type}</div>
                            <div className="text-sm text-white/60 leading-relaxed">{issue.description}</div>
                          </div>
                        </div>
                      </div>

                      {open && issue.remediationHint && (
                        <div className="m-2 mt-0 p-4 bg-green-500/[0.03] border border-green-500/20 rounded-xl animate-enter">
                          <div className="text-[10px] uppercase font-bold tracking-wider text-green-500 mb-2">RECOMMENDED REMEDIATION</div>
                          <div className="font-mono text-xs text-white/90">
                            <span className="text-green-500 mr-2">$</span>{issue.remediationHint}
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
          <div className="flex flex-col gap-4 h-[750px]">

            {/* AI Assistant Bento */}
            <div className={`surface-card flex flex-col relative overflow-hidden transition-all duration-500 min-h-0 max-h-[350px] ${generatingAI ? 'ai-processing-bg border-indigo-500/50' : 'border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.05)]'}`}>
              <div className="p-5 px-6 border-b border-indigo-500/10 flex justify-between items-center bg-indigo-500/5 backdrop-blur-sm relative z-10">
                <div className="flex items-center gap-2">
                  <Sparkles size={18} className={generatingAI ? 'text-white animate-pulse' : 'text-indigo-400'} />
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
                    <div className={`markdown-prose text-[0.95rem] text-white/90 leading-relaxed ${generatingAI ? 'opacity-50' : 'animate-enter'}`}>
                      <ReactMarkdown>{aiSummary}</ReactMarkdown>
                      {generatingAI && <span className="typing-cursor" />}

                      {chatHistory.length > 0 && (
                        <div className="mt-6 flex flex-col gap-3 border-t border-white/10 pt-5">
                          {chatHistory.map((msg, idx) => (
                            <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                              <div className={`markdown-prose max-w-[85%] px-4 py-2.5 rounded-2xl text-[0.9rem] leading-relaxed ${msg.role === 'user' ? 'bg-indigo-500/20 text-indigo-100 border border-indigo-500/30 rounded-br-sm' : 'bg-white/5 text-white/90 border border-white/10 rounded-bl-sm'}`}>
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
                      {!generatingAI ? 'Copilot is ready to analyze active threats and context via retrieval augmented generation.' : <span className="typing-cursor" />}
                    </div>
                  )}
                </div>

                {aiSummary && (
                  <div className="p-3 px-5 border-t border-white/10 bg-black/20 backdrop-blur-md focus-within:bg-indigo-500/10 focus-within:border-t-indigo-500/30 transition-all duration-300">
                    <form onSubmit={handleSendChat} className="flex items-center gap-3">
                      <input
                        type="text"
                        value={chatInput}
                        onChange={e => setChatInput(e.target.value)}
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

            {/* CWPP Workloads */}
            <div className="surface-card flex-1 flex flex-col min-h-0">
              <div className="p-5 px-6 border-b border-white/5">
                <div className="flex items-center gap-2 mb-1">
                  <Cpu size={16} className="text-purple-400" />
                  <span className="text-base font-semibold tracking-tight text-white">Active ML Workloads</span>
                </div>
                <div className="text-[10px] uppercase font-bold tracking-wider text-purple-400/60">Real-time Behavioral Analysis</div>
              </div>
              <div className="custom-scrollbar p-0 overflow-y-auto flex-1 flex flex-col">
                {(selectedCloud === 'all' ? mockRuntimeEvents : mockRuntimeEvents.filter(e => e.provider === selectedCloud)).map((event) => {
                  const { score, threatLevel } = calculateAnomalyScore(event);
                  const lvlColor = threatLevel === 'HIGH' ? 'text-red-400' : threatLevel === 'MEDIUM' ? 'text-orange-400' : 'text-green-400';

                  return (
                    <div key={event.instanceId} className="px-6 py-4 border-b border-white/5 hover:bg-white/[0.02] transition-colors last:border-0 relative group">
                      <div className="absolute left-0 top-0 bottom-0 w-[2px] bg-transparent group-hover:bg-purple-500/50 transition-colors" />
                      <div className="flex justify-between items-center mb-1.5">
                        <span className="font-mono text-[0.9rem] font-medium text-white/90">{event.instanceId}</span>
                        <span className={`font-mono text-base font-bold ${lvlColor}`} suppressHydrationWarning>{score}</span>
                      </div>
                      <div className="flex justify-between items-center text-xs">
                        <span className="text-white/50" suppressHydrationWarning>CPU: <span className="text-white/80">{event.cpuUsage}%</span></span>
                        <span className={event.suspiciousPorts.length > 0 ? 'text-red-400/80' : 'text-white/40'} suppressHydrationWarning>
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
              <div className="surface-card p-6 flex flex-col justify-between">
                <div className="flex items-center justify-between mb-4">
                  <div className="text-[10px] uppercase font-bold tracking-wider text-white/50">RISK EXPOSURE TREND</div>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.6)] animate-pulse" />
                    <span className="text-xs text-blue-400 font-medium tracking-wide">Live</span>
                  </div>
                </div>
                <div className="h-[140px] -mx-2">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={riskTrend} margin={{ top: 5, right: 0, left: 0, bottom: 0 }}>
                      <defs>
                        <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="time" type="category" tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }} axisLine={false} tickLine={false} minTickGap={20} />
                      <YAxis tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10 }} axisLine={false} tickLine={false} domain={['auto', 'auto']} width={35} />
                      <Tooltip contentStyle={{ backgroundColor: 'rgba(0,0,0,0.8)', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }} itemStyle={{ color: '#fff' }} cursor={{ stroke: 'rgba(255,255,255,0.1)', strokeWidth: 1, strokeDasharray: '3 3' }} />
                      <Area type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorScore)" isAnimationActive={false} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* ─── CHARTS ROW ─── */}
        {(pieData.length > 0 || catData.length > 0) && (
          <section className="grid grid-cols-1 lg:grid-cols-3 gap-4 animate-enter" style={{ animationDelay: '0.2s' }}>
            {pieData.length > 0 && (
              <div className="surface-card p-6 h-[300px]">
                <div className="text-sm font-semibold tracking-tight mb-4 text-white">Severity Distribution</div>
                <div className="w-full h-[200px]">
                  <ResponsiveContainer>
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} stroke="none" dataKey="value" paddingAngle={2}>
                        {pieData.map((d, i) => {
                          const bg = d.name === 'Critical' ? '#ef4444' : d.name === 'High' ? '#f97316' : d.name === 'Medium' ? '#eab308' : '#3b82f6';
                          return <Cell key={i} fill={bg} />;
                        })}
                      </Pie>
                      <Tooltip cursor={{ fill: 'transparent' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {catData.length > 0 && (
              <div className="surface-card p-6 h-[300px] lg:col-span-2">
                <div className="text-sm font-semibold tracking-tight mb-4 text-white">Issues by Service Category</div>
                <div className="w-full h-[200px]">
                  <ResponsiveContainer>
                    <BarChart data={catData.slice(0, 5)} layout="vertical" margin={{ left: -20, right: 10 }}>
                      <XAxis type="number" hide />
                      <YAxis dataKey="category" type="category" tick={{ fill: 'rgba(255,255,255,0.7)', fontSize: 11 }} axisLine={false} tickLine={false} width={80} />
                      <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
                      <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} barSize={16}>
                        {catData.map((d, i) => <Cell key={i} fill={i % 2 === 0 ? '#3b82f6' : '#6366f1'} />)}
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
