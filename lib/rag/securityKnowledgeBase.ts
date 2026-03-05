// lib/rag/securityKnowledgeBase.ts
// Pure TypeScript RAG engine — no external dependencies
// TF-IDF cosine similarity retrieves relevant CIS/NIST controls
// before the Groq LLM call, so AI cites real control IDs

export interface SecurityControl {
  id: string;
  framework: string;
  category: string;
  title: string;
  description: string;
  remediation: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cloudService: string;
  tags: string[];
}

export const SECURITY_CONTROLS: SecurityControl[] = [
  // ── S3 ──
  {
    id: 'CIS-2.1.5', framework: 'CIS AWS Foundations v2.0', category: 'S3', cloudService: 'S3',
    severity: 'HIGH', tags: ['s3', 'public', 'block', 'access', 'data-exposure', 'bucket'],
    title: 'Ensure S3 buckets are configured with Block Public Access',
    description: 'S3 Block Public Access overrides all public grants. Any bucket with a Block Public Access setting disabled can expose sensitive data to the internet — the leading cause of cloud data breaches.',
    remediation: 'aws s3api put-public-access-block --bucket BUCKET_NAME --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
  },
  {
    id: 'CIS-2.1.2', framework: 'CIS AWS Foundations v2.0', category: 'S3', cloudService: 'S3',
    severity: 'MEDIUM', tags: ['s3', 'encryption', 'sse', 'kms', 'data-at-rest'],
    title: 'Ensure S3 bucket server-side encryption is enabled',
    description: 'Unencrypted S3 buckets store data in plaintext. If storage is compromised or snapshots shared, data is exposed.',
    remediation: "aws s3api put-bucket-encryption --bucket BUCKET_NAME --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"
  },
  // ── EC2 / Security Groups ──
  {
    id: 'CIS-5.1', framework: 'CIS AWS Foundations v2.0', category: 'EC2', cloudService: 'EC2',
    severity: 'CRITICAL', tags: ['ec2', 'security-group', 'ssh', '22', 'unrestricted', 'network'],
    title: 'Ensure no security groups allow unrestricted SSH access (port 22)',
    description: 'Security groups allowing SSH from 0.0.0.0/0 expose instances to brute-force attacks from any internet IP. SSH should be restricted to known IP ranges or VPN.',
    remediation: 'aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0'
  },
  {
    id: 'CIS-5.2', framework: 'CIS AWS Foundations v2.0', category: 'EC2', cloudService: 'EC2',
    severity: 'CRITICAL', tags: ['security-group', 'rdp', '3389', 'unrestricted', 'windows', 'ransomware'],
    title: 'Ensure no security groups allow unrestricted RDP access (port 3389)',
    description: 'RDP exposed to 0.0.0.0/0 is the primary ransomware delivery vector. Windows instances must never have port 3389 open to the internet.',
    remediation: 'aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port 3389 --cidr 0.0.0.0/0'
  },
  {
    id: 'CIS-5.3', framework: 'CIS AWS Foundations v2.0', category: 'SecurityGroup', cloudService: 'EC2',
    severity: 'CRITICAL', tags: ['security-group', '0.0.0.0/0', 'unrestricted', 'inbound', 'overly-permissive', 'permissive'],
    title: 'Ensure security groups restrict all inbound traffic from 0.0.0.0/0',
    description: 'Security groups allowing ALL inbound traffic from 0.0.0.0/0 on any port eliminate all network-layer protection. This is the most exploited misconfiguration for initial access.',
    remediation: "aws ec2 revoke-security-group-ingress --group-id SG_ID --ip-permissions '[{\"IpProtocol\":\"-1\",\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\"}]}]'"
  },
  {
    id: 'CIS-5.6', framework: 'CIS AWS Foundations v2.0', category: 'EC2', cloudService: 'EC2',
    severity: 'MEDIUM', tags: ['ec2', 'public-ip', 'internet-facing', 'public', 'instance'],
    title: 'Ensure EC2 instances are not publicly accessible without justification',
    description: 'EC2 instances with public IPs are directly reachable from the internet, increasing attack surface. Private instances should use NAT gateways for outbound access.',
    remediation: 'Move instance to private subnet. Use Application Load Balancer or NAT Gateway for required internet connectivity.'
  },
  // ── IAM ──
  {
    id: 'CIS-1.10', framework: 'CIS AWS Foundations v2.0', category: 'IAM', cloudService: 'IAM',
    severity: 'CRITICAL', tags: ['iam', 'mfa', 'multi-factor', 'authentication', 'console', 'credential', 'no-mfa'],
    title: 'Ensure MFA is enabled for all IAM users with console access',
    description: 'Without MFA, compromised passwords grant full console access. Phishing, credential stuffing, and brute force attacks are the primary threat vectors against password-only IAM accounts.',
    remediation: 'aws iam enable-mfa-device --user-name USERNAME --serial-number arn:aws:iam::ACCOUNT:mfa/USERNAME --authentication-code1 CODE1 --authentication-code2 CODE2'
  },
  {
    id: 'CIS-1.4', framework: 'CIS AWS Foundations v2.0', category: 'IAM', cloudService: 'IAM',
    severity: 'CRITICAL', tags: ['iam', 'root', 'access-key', 'credential', 'privilege'],
    title: 'Ensure no root account access keys exist',
    description: 'Root account keys provide unrestricted access to all AWS services. If compromised, they enable complete account takeover with no recovery.',
    remediation: 'Delete root access keys: AWS Console > Security Credentials > Access keys > Delete. Use IAM users with least-privilege permissions instead.'
  },
  {
    id: 'NIST-AC-2', framework: 'NIST SP 800-53 Rev 5', category: 'IAM', cloudService: 'IAM',
    severity: 'MEDIUM', tags: ['iam', 'inactive', 'stale', 'old', 'key', 'access-key', 'rotation', '90-days'],
    title: 'Account Management — Rotate IAM access keys older than 90 days',
    description: 'NIST AC-2 requires disabling credentials no longer in use. Access keys older than 90 days represent persistent attack surfaces that are commonly compromised through data breaches.',
    remediation: 'aws iam create-access-key --user-name USERNAME (update apps) then aws iam delete-access-key --user-name USERNAME --access-key-id OLD_KEY_ID'
  },
  // ── CloudTrail ──
  {
    id: 'CIS-3.1', framework: 'CIS AWS Foundations v2.0', category: 'CloudTrail', cloudService: 'CloudTrail',
    severity: 'HIGH', tags: ['cloudtrail', 'logging', 'audit', 'monitoring', 'forensics', 'disabled', 'trail'],
    title: 'Ensure CloudTrail is enabled in all regions',
    description: 'CloudTrail records all AWS API calls. Without it, incident investigation after a breach is impossible — attackers can operate, exfiltrate data, and cover tracks undetected.',
    remediation: 'aws cloudtrail create-trail --name management-events --s3-bucket-name YOUR_BUCKET --is-multi-region-trail && aws cloudtrail start-logging --name management-events'
  },
  {
    id: 'CIS-3.2', framework: 'CIS AWS Foundations v2.0', category: 'CloudTrail', cloudService: 'CloudTrail',
    severity: 'MEDIUM', tags: ['cloudtrail', 'log-validation', 'integrity', 'tamper', 'validation'],
    title: 'Ensure CloudTrail log file validation is enabled',
    description: 'Log validation uses SHA-256 + RSA signing to detect if logs were modified after delivery. Without it, tampered logs may be used undetected during forensic investigations.',
    remediation: 'aws cloudtrail update-trail --name TRAIL_NAME --enable-log-file-validation'
  },
  // ── EBS ──
  {
    id: 'CIS-2.2.1', framework: 'CIS AWS Foundations v2.0', category: 'EBS', cloudService: 'EBS',
    severity: 'HIGH', tags: ['ebs', 'encryption', 'volume', 'data-at-rest', 'kms', 'unencrypted'],
    title: 'Ensure EBS volume encryption is enabled',
    description: 'Unencrypted EBS volumes store data in plaintext. Hardware decommissioned without sanitization, or snapshots inadvertently shared, expose all stored data.',
    remediation: 'aws ec2 enable-ebs-encryption-by-default --region REGION. For existing volumes: create snapshot → copy with --encrypted → create new encrypted volume → swap attachment.'
  },
  // ── RDS ──
  {
    id: 'CIS-2.3.2', framework: 'CIS AWS Foundations v2.0', category: 'RDS', cloudService: 'RDS',
    severity: 'CRITICAL', tags: ['rds', 'database', 'public', 'internet-facing', 'sql', 'mysql', 'postgres'],
    title: 'Ensure RDS instances are not publicly accessible',
    description: 'Public RDS instances allow direct database connections from the internet. A single exposed database port allows credential brute-force, injection attacks, and direct data theft.',
    remediation: 'aws rds modify-db-instance --db-instance-identifier DB_ID --no-publicly-accessible --apply-immediately'
  },
  {
    id: 'CIS-2.3.1', framework: 'CIS AWS Foundations v2.0', category: 'RDS', cloudService: 'RDS',
    severity: 'HIGH', tags: ['rds', 'encryption', 'database', 'storage', 'data-at-rest'],
    title: 'Ensure RDS instances have encryption at rest enabled',
    description: 'RDS encryption at rest protects database files, automated backups, read replicas, and snapshots. Without it, physical storage compromise exposes all data.',
    remediation: 'Snapshot DB → aws rds copy-db-snapshot with --kms-key-id → restore encrypted instance from snapshot.'
  },
  // ── KMS ──
  {
    id: 'CIS-3.8', framework: 'CIS AWS Foundations v2.0', category: 'KMS', cloudService: 'KMS',
    severity: 'MEDIUM', tags: ['kms', 'key-rotation', 'encryption', 'cmk', 'rotation', 'cryptographic'],
    title: 'Ensure AWS KMS CMK rotation is enabled',
    description: 'Without automatic key rotation, a single compromised CMK can decrypt all historical encrypted data indefinitely. Annual rotation limits the blast radius of key compromise.',
    remediation: 'aws kms enable-key-rotation --key-id KEY_ID'
  },
  // ── VPC ──
  {
    id: 'CIS-3.9', framework: 'CIS AWS Foundations v2.0', category: 'VPC', cloudService: 'VPC',
    severity: 'MEDIUM', tags: ['vpc', 'flow-logs', 'network', 'traffic', 'forensics', 'monitoring'],
    title: 'Ensure VPC flow logging is enabled in all VPCs',
    description: 'Without VPC flow logs, network-level attacks — port scanning, lateral movement, data exfiltration — cannot be detected or investigated after an incident.',
    remediation: 'aws ec2 create-flow-logs --resource-type VPC --resource-ids VPC_ID --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs'
  },
  // ── Lambda ──
  {
    id: 'LAMBDA-PUB', framework: 'AWS Security Best Practices', category: 'Lambda', cloudService: 'Lambda',
    severity: 'HIGH', tags: ['lambda', 'public', 'policy', 'function', 'invocation', 'serverless'],
    title: 'Ensure Lambda functions do not allow public invocation',
    description: 'Lambda resource policies with Principal:* allow any AWS account or internet user to invoke the function, enabling unauthorized execution and potential data access.',
    remediation: 'aws lambda remove-permission --function-name FUNCTION_NAME --statement-id PUBLIC_STATEMENT_ID'
  },
  // ── IMDSv2 ──
  {
    id: 'AWS-IMDSV2', framework: 'AWS Security Best Practices', category: 'EC2', cloudService: 'EC2',
    severity: 'HIGH', tags: ['ec2', 'imds', 'imdsv2', 'ssrf', 'metadata', 'credentials', 'tokens'],
    title: 'Enforce IMDSv2 on all EC2 instances',
    description: 'IMDSv1 is vulnerable to SSRF attacks that allow web application vulnerabilities to steal IAM credentials from the instance metadata service. IMDSv2 requires session-oriented tokens.',
    remediation: 'aws ec2 modify-instance-metadata-options --instance-id INSTANCE_ID --http-tokens required --http-put-response-hop-limit 1'
  },
  // ── GCP ──
  {
    id: 'CIS-GCP-5.1', framework: 'CIS Google Cloud Computing Foundations', category: 'Storage', cloudService: 'GCP Storage',
    severity: 'HIGH', tags: ['gcp', 'storage', 'bucket', 'public', 'allUsers', 'iam', 'exposure'],
    title: 'Ensure that Cloud Storage bucket is not anonymously or publicly accessible',
    description: 'Allowing anonymous access (allUsers) or public access (allAuthenticatedUsers) to Cloud Storage buckets exposes sensitive data to the internet.',
    remediation: 'gcloud storage buckets remove-iam-policy-binding gs://BUCKET_NAME --member="allUsers" --role="roles/storage.objectViewer"'
  },
  {
    id: 'CIS-GCP-3.6', framework: 'CIS Google Cloud Computing Foundations', category: 'Compute', cloudService: 'GCP Compute Engine',
    severity: 'HIGH', tags: ['gcp', 'compute', 'instance', 'public', 'ip', 'external'],
    title: 'Ensure that instances are not configured to use external IP addresses',
    description: 'Compute instances with external IPs are directly exposed to the internet. Access should be mediated via Cloud NAT or load balancers.',
    remediation: 'gcloud compute instances delete-access-config INSTANCE_NAME --network-interface=nic0 --access-config-name="External NAT"'
  },

  // ── Azure ──
  {
    id: 'CIS-Azure-3.1', framework: 'CIS Microsoft Azure Foundations', category: 'Storage', cloudService: 'Azure Blob Storage',
    severity: 'HIGH', tags: ['azure', 'storage', 'blob', 'public', 'container'],
    title: 'Ensure that "Public access level" is set to Private for blob containers',
    description: 'Anonymous, public read access to a container and its blobs can lead to sensitive data exposure and breaches.',
    remediation: 'az storage container set-permission --name CONTAINER_NAME --public-access off --account-name ACCOUNT_NAME'
  },
  {
    id: 'CIS-Azure-1.2', framework: 'CIS Microsoft Azure Foundations', category: 'Compute', cloudService: 'Azure Virtual Machines',
    severity: 'HIGH', tags: ['azure', 'vm', 'public', 'ip', 'external'],
    title: 'Ensure that Virtual Machines are not configured with public IP addresses',
    description: 'Azure VMs with public IPs bypass front-end security boundaries like Application Gateways and increase the attack surface.',
    remediation: 'az network public-ip delete -g RESOURCE_GROUP -n PUBLIC_IP_NAME'
  },
];

// ─── TF-IDF VECTOR ENGINE ─────────────────────────────────────────────────────
class TFIDFEngine {
  private vocabulary = new Map<string, number>();
  private idf = new Map<string, number>();
  private vectors: number[][] = [];
  private built = false;

  private tokenize(text: string): string[] {
    return text.toLowerCase().replace(/[^a-z0-9\s\-_.]/g, ' ').split(/\s+/).filter(t => t.length > 2);
  }

  build(controls: SecurityControl[]) {
    const docs = controls.map(c =>
      `${c.title} ${c.description} ${c.tags.join(' ')} ${c.cloudService} ${c.category} ${c.id}`
    );
    const docFreq = new Map<string, number>();
    docs.forEach(doc => {
      new Set(this.tokenize(doc)).forEach(term => {
        docFreq.set(term, (docFreq.get(term) || 0) + 1);
        if (!this.vocabulary.has(term)) this.vocabulary.set(term, this.vocabulary.size);
      });
    });
    const N = docs.length;
    docFreq.forEach((df, term) => this.idf.set(term, Math.log((N + 1) / (df + 1)) + 1));
    this.vectors = docs.map(d => this.toVector(d));
    this.built = true;
  }

  private toVector(text: string): number[] {
    const tokens = this.tokenize(text);
    const tf = new Map<string, number>();
    tokens.forEach(t => tf.set(t, (tf.get(t) || 0) + 1));
    const vec = new Array(this.vocabulary.size).fill(0);
    tf.forEach((count, term) => {
      const idx = this.vocabulary.get(term);
      if (idx !== undefined) vec[idx] = (count / tokens.length) * (this.idf.get(term) || 1);
    });
    return vec;
  }

  private cosine(a: number[], b: number[]): number {
    let dot = 0, na = 0, nb = 0;
    for (let i = 0; i < a.length; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
    const d = Math.sqrt(na) * Math.sqrt(nb);
    return d === 0 ? 0 : dot / d;
  }

  search(query: string, topK = 3): Array<{ control: SecurityControl; score: number }> {
    if (!this.built) throw new Error('Engine not built. Call build() first.');
    const qv = this.toVector(query);
    return this.vectors
      .map((vec, i) => ({ control: SECURITY_CONTROLS[i], score: this.cosine(qv, vec) }))
      .filter(s => s.score > 0.005)
      .sort((a, b) => b.score - a.score)
      .slice(0, topK);
  }
}

// Singleton — built once on first import
let _engine: TFIDFEngine | null = null;
function getEngine(): TFIDFEngine {
  if (!_engine) { _engine = new TFIDFEngine(); _engine.build(SECURITY_CONTROLS); }
  return _engine;
}

// ─── PUBLIC API ───────────────────────────────────────────────────────────────
export interface RAGContext {
  controls: SecurityControl[];
  contextBlock: string;
}

export function retrieveControls(query: string, topK = 3): RAGContext {
  const results = getEngine().search(query, topK);
  const controls = results.map(r => r.control);
  const contextBlock = controls.map((c, i) =>
    `[Control ${i + 1}] ${c.framework} — ${c.id}: ${c.title}\n` +
    `Severity: ${c.severity} | Cloud Service: ${c.cloudService}\n` +
    `Problem: ${c.description}\n` +
    `Fix: ${c.remediation}`
  ).join('\n\n');
  return { controls, contextBlock };
}

export function buildRAGPrompt(params: {
  riskScore: number;
  complianceScore: number;
  counts: { critical: number; high: number; medium: number; low: number };
  topIssues: Array<{ type: string; description: string; severity: string }>;
}): string {
  const { riskScore, complianceScore, counts, topIssues } = params;
  const issueQuery = topIssues.map(i => `${i.type} ${i.severity} ${i.description}`).join(' ');
  const { contextBlock } = retrieveControls(issueQuery, 4);

  return `You are a senior multi-cloud security engineer. Ground your analysis ONLY in the CIS/NIST controls retrieved below.

=== RETRIEVED SECURITY CONTROLS (Knowledge Base) ===
${contextBlock}

=== CURRENT CLOUD SECURITY SCAN FINDINGS ===
Overall Risk Score: ${riskScore}/100
Compliance Score: ${complianceScore}%
Critical: ${counts.critical} | High: ${counts.high} | Medium: ${counts.medium} | Low: ${counts.low}

Issues Detected:
${topIssues.map((i, n) => `${n + 1}. [${i.severity.toUpperCase()}] ${i.type}: ${i.description}`).join('\n')}

Return STRICTLY in this format:

SUMMARY:
<2 sentences citing specific control IDs e.g. "This violates CIS-5.3 and CIS-2.1.5">

RISK_LEVEL:
${riskScore > 80 ? 'CRITICAL' : riskScore > 60 ? 'HIGH' : riskScore > 30 ? 'MEDIUM' : 'LOW'}

ATTACK_VECTORS:
- <most likely attack path given these findings>
- <second attack path>
- <third attack path>

REMEDIATION:
- <Priority 1 with exact CLI command (aws, gcloud, or az) from the controls above>
- <Priority 2 with exact CLI command>
- <Priority 3 with exact CLI command>

COMPLIANCE_VIOLATIONS:
- <list violated CIS/NIST control IDs>`;
}
