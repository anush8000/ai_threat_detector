import { Issue } from './riskScore';

export function getThreatCategory(issue: Issue): string {
  const type = issue.type.toLowerCase();
  if (type.includes('s3')) return 'Data Exposure';
  if (type.includes('security group') || type.includes('sg_')) return 'Network Exposure';
  if (type.includes('ec2') || type.includes('instance')) return 'Attack Surface';
  return 'Misconfiguration Risk';
}
