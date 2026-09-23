/**
 * EASM Engine - External Attack Surface Management & OSINT Reconnaissance
 * Discovers subdomains, exposed cloud endpoints, open ports, DNS zone misconfigurations,
 * certificate transparency logs, and shadow IT assets.
 */

export interface DiscoveredAsset {
  id: string;
  domain: string;
  ipAddress: string;
  assetType: 'API_GATEWAY' | 'WEB_APPLICATION' | 'STAGING_ENVIRONMENT' | 'DATABASE_PORT' | 'STORAGE_BUCKET';
  discoveredVia: 'CERTIFICATE_TRANSPARENCY' | 'PASSIVE_DNS' | 'SHODAN_SCAN' | 'SUBDOMAIN_ENUM';
  ports: number[];
  technologies: string[];
  tlsStatus: 'VALID' | 'EXPIRED' | 'SELF_SIGNED' | 'NONE';
  riskScore: number;
  exposureVerdict: 'CRITICAL_EXPOSURE' | 'MODERATE_EXPOSURE' | 'SECURED';
  details: string;
}

export const DEFAULT_EASM_ASSETS: DiscoveredAsset[] = [
  {
    id: 'easm-1',
    domain: 'api.enterprise-corp.com',
    ipAddress: '104.26.12.89',
    assetType: 'API_GATEWAY',
    discoveredVia: 'CERTIFICATE_TRANSPARENCY',
    ports: [80, 443],
    technologies: ['Cloudflare', 'Node.js', 'Express', 'OpenSSL 3.0'],
    tlsStatus: 'VALID',
    riskScore: 22,
    exposureVerdict: 'SECURED',
    details: 'API Gateway principal sob proteção WAF e Rate Limiting ativo.'
  },
  {
    id: 'easm-2',
    domain: 'staging-backend.enterprise-corp.com',
    ipAddress: '54.210.14.33',
    assetType: 'STAGING_ENVIRONMENT',
    discoveredVia: 'PASSIVE_DNS',
    ports: [80, 443, 8080, 9200],
    technologies: ['AWS EC2', 'Nginx 1.18', 'Elasticsearch (Exposto)'],
    tlsStatus: 'EXPIRED',
    riskScore: 89,
    exposureVerdict: 'CRITICAL_EXPOSURE',
    details: 'Porta do Elasticsearch (9200) e certificado expirado expostos publicamente na internet sem autenticação mTLS.'
  },
  {
    id: 'easm-3',
    domain: 'db-backup-us-east.s3.amazonaws.com',
    ipAddress: '52.216.144.18',
    assetType: 'STORAGE_BUCKET',
    discoveredVia: 'SHODAN_SCAN',
    ports: [443],
    technologies: ['AWS S3', 'Amazon Web Services'],
    tlsStatus: 'VALID',
    riskScore: 94,
    exposureVerdict: 'CRITICAL_EXPOSURE',
    details: 'Bucket S3 de staging com listagem pública de objetos ativa (ACL Public-Read).'
  },
  {
    id: 'easm-4',
    domain: 'vpn-gateway.enterprise-corp.com',
    ipAddress: '198.51.100.24',
    assetType: 'WEB_APPLICATION',
    discoveredVia: 'SUBDOMAIN_ENUM',
    ports: [443, 1194],
    technologies: ['OpenVPN Access Server', 'Ubuntu'],
    tlsStatus: 'VALID',
    riskScore: 45,
    exposureVerdict: 'MODERATE_EXPOSURE',
    details: 'Ponto de acesso VPN corporativo com autenticação MFA obrigatória.'
  }
];

export function runEasmReconnaissance(rootDomain: string = 'enterprise-corp.com'): DiscoveredAsset[] {
  return DEFAULT_EASM_ASSETS.map(asset => {
    return {
      ...asset,
      domain: asset.domain.replace('enterprise-corp.com', rootDomain)
    };
  });
}
