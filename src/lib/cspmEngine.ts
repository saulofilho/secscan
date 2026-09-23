/**
 * Multi-Cloud CSPM Engine - Cloud Security Posture Management
 * Scans AWS, Azure, and GCP configurations against CIS Cloud Benchmarks,
 * identifying overly permissive IAM roles, public S3 buckets, exposed databases, and unencrypted volumes.
 */

export interface CspmFinding {
  id: string;
  provider: 'AWS' | 'AZURE' | 'GCP';
  resourceId: string;
  resourceType: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cisBenchmarkControl: string; // e.g., "CIS AWS 1.4 - 2.1.1"
  remediationCli: string;
  status: 'FAIL' | 'PASS';
}

export const SAMPLE_CSPM_FINDINGS: CspmFinding[] = [
  {
    id: 'cspm-aws-s3-public',
    provider: 'AWS',
    resourceId: 'arn:aws:s3:::prod-customer-data-backup',
    resourceType: 'AWS::S3::Bucket',
    title: 'S3 Bucket Public Access Block Not Configured',
    description: 'The S3 bucket allows public ACL or bucket policy, exposing customer backup data to anyone on the internet.',
    severity: 'CRITICAL',
    cisBenchmarkControl: 'CIS AWS 1.4 - 2.1.1',
    remediationCli: 'aws s3api put-public-access-block --bucket prod-customer-data-backup --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
    status: 'FAIL'
  },
  {
    id: 'cspm-aws-iam-root-mfa',
    provider: 'AWS',
    resourceId: 'arn:aws:iam::123456789012:root',
    resourceType: 'AWS::IAM::Root',
    title: 'Root Account Active Without Hardware/Virtual MFA',
    description: 'The AWS root account does not have Multi-Factor Authentication enabled.',
    severity: 'CRITICAL',
    cisBenchmarkControl: 'CIS AWS 1.4 - 1.5',
    remediationCli: 'aws iam create-virtual-mfa-device --virtual-mfa-device-name RootMfaDevice --outfile /root/QRCode.png',
    status: 'FAIL'
  },
  {
    id: 'cspm-azure-nsg-rdp',
    provider: 'AZURE',
    resourceId: '/subscriptions/sub-01/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-core',
    resourceType: 'Microsoft.Network/networkSecurityGroups',
    title: 'Network Security Group Allows Unrestricted Inbound RDP (Port 3389)',
    description: 'Inbound rule permits RDP access from 0.0.0.0/0, enabling brute-force and remote desktop exploit attempts.',
    severity: 'HIGH',
    cisBenchmarkControl: 'CIS Azure 2.0 - 6.1',
    remediationCli: 'az network nsg rule delete -g rg-prod --nsg-name nsg-core -n Allow-RDP-Any',
    status: 'FAIL'
  },
  {
    id: 'cspm-gcp-cloudsql-ssl',
    provider: 'GCP',
    resourceId: 'projects/corp-prod/instances/postgres-primary',
    resourceType: 'sqladmin.v1beta4.instance',
    title: 'Cloud SQL Database Allows Non-SSL Connections',
    description: 'The PostgreSQL instance accepts unencrypted plaintext connections without requiring SSL/TLS client certificates.',
    severity: 'HIGH',
    cisBenchmarkControl: 'CIS GCP 1.3 - 6.2',
    remediationCli: 'gcloud sql instances patch postgres-primary --require-ssl',
    status: 'FAIL'
  }
];
