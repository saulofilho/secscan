export type NgfwAction = 'ALLOW' | 'BLOCK' | 'DROP' | 'RESET' | 'QUARANTINE';

export type NgfwSecurityZone = 'UNTRUST' | 'DMZ' | 'INTERNAL_CORP' | 'CLOUD_VPC' | 'DATABASE_TIER';

export type NgfwThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export interface NgfwAppIdSignature {
  id: string;
  name: string;
  category: 'business-systems' | 'database' | 'collaboration' | 'infrastructure' | 'cloud-storage' | 'remote-access' | 'malicious';
  standardPorts: number[];
  riskLevel: 1 | 2 | 3 | 4 | 5; // 5 is highest
  description: string;
  sslDecrypted: boolean;
}

export interface NgfwPolicyRule {
  id: string;
  ruleName: string;
  priority: number;
  sourceZone: NgfwSecurityZone;
  destinationZone: NgfwSecurityZone;
  sourceIps: string[];
  destinationIps: string[];
  applications: string[]; // App-ID (e.g. 'postgresql', 'redis', 'ssh', 'stripe-api')
  servicePorts: string; // e.g. 'tcp/443, tcp/5432'
  action: NgfwAction;
  ipsProfileEnabled: boolean;
  sslInspectionEnabled: boolean;
  hitCount: number;
  lastHitTimestamp: string;
  status: 'ACTIVE' | 'DISABLED';
  description: string;
}

export interface NgfwIpsSignatureMatch {
  id: string;
  cve?: string;
  threatId: string;
  signatureName: string;
  severity: NgfwThreatSeverity;
  category: 'EXPLOIT' | 'BRUTE_FORCE' | 'COMMAND_INJECTION' | 'C2_BEACON' | 'DATA_EXFILTRATION';
  actionTaken: 'BLOCKED' | 'DROPPED_PACKET' | 'ALERTED';
  sourceIp: string;
  destinationIp: string;
  application: string;
  timestamp: string;
  payloadSnippet: string;
  mitigationRecommendation: string;
}

export interface NgfwSslInspectionSession {
  sessionId: string;
  flow: string; // e.g. "10.0.4.15:48210 -> api.stripe.com:443"
  sni: string;
  tlsVersion: string; // "TLSv1.3"
  cipherSuite: string;
  decryptionStatus: 'INSPECTED' | 'BYPASSED_FINANCIAL' | 'PINNED_CERT_ALERT';
  threatFound: boolean;
  threatDetails?: string;
  timestamp: string;
}

export interface NgfwMetrics {
  totalPacketsProcessed: number;
  throughputMbps: number;
  activeSessions: number;
  threatsBlockedToday: number;
  sslInspectedSessionsPct: number;
  cpuLoadPct: number;
  memoryUsagePct: number;
}
