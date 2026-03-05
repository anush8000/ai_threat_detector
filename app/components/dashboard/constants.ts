import { CheckDef, SecurityIssue } from './types';

export const CLOUD_CHECKS: CheckDef[] = [
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

export const MOCK_ISSUES: SecurityIssue[] = [
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
