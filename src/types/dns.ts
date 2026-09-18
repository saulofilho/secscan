export type DnsSecurityStatus = 'SAFE' | 'BLOCKED_SINKHOLE' | 'SUSPICIOUS_TUNNEL' | 'DGA_DETECTED' | 'MALICIOUS_C2';

export type DnssecValidationStatus = 'SECURE_VALIDATED' | 'INSECURE' | 'BOGUS_SIGNATURE_MISMATCH' | 'INDETERMINATE';

export interface DnsQueryLog {
  id: string;
  timestamp: string;
  queryDomain: string;
  queryType: 'A' | 'AAAA' | 'TXT' | 'CNAME' | 'MX' | 'NS' | 'PTR';
  clientIp: string;
  clientHostname: string;
  status: DnsSecurityStatus;
  dnssecStatus: DnssecValidationStatus;
  resolvedIp?: string;
  sinkholeRedirectIp?: string;
  entropyShannon: number; // Ex: 4.85
  category: 'C2_COMMUNICATION' | 'EXFILTRATION_TUNNEL' | 'DGA_ALGORITHM' | 'PHISHING_TYPOSQUATTING' | 'CLEAN';
  threatDescription: string;
  ttlSeconds: number;
}

export interface DnsSinkholeRule {
  id: string;
  domainPattern: string; // Ex: *.bad-c2-dropzone.ru
  targetRedirectIp: string; // Ex: 10.0.0.99 (Sinkhole Honeypot)
  threatCategory: string;
  enabled: boolean;
  totalInterceptions: number;
  lastInterceptedAt?: string;
}

export interface DgaDetectionModel {
  dgaDomain: string;
  calculatedEntropy: number;
  consonantVowelRatio: number;
  ngramScore: number;
  confidenceScore: number; // 0 - 100%
  predictedMalwareFamily: 'CobaltStrike' | 'Emotet' | 'LockBit' | 'AsyncRAT' | 'Unknown';
  actionTaken: 'SINKHOLE_ISOLATE' | 'ALERT_SOC';
}

export interface DnssecChainOfTrust {
  domain: string;
  rootAnchorKey: string; // DNSKEY KSK . (root)
  tldDsRecord: string; // DS record from root
  zoneDnsKey: string; // Zone DNSKEY ZSK
  rrsigStatus: 'VALID' | 'EXPIRED' | 'CORRUPTED';
  algorithm: 'ED25519 (Alg 15)' | 'ECDSA P-256 (Alg 13)' | 'RSA-SHA256 (Alg 8)';
  keyTag: number;
}

export interface DnsTunnelExfiltrationSession {
  sessionId: string;
  clientIp: string;
  apexDomain: string; // Ex: exfil.attacker-tunnel.net
  totalChunksCount: number;
  estimatedBytesLeaked: number;
  reassembledDataSample: string;
  status: 'ACTIVE_BLOCKING' | 'RECONSTRUCTED' | 'MITIGATED';
  detectedProtocol: 'BASE64_DNS_TUNNEL' | 'HEX_TXT_RECORD_CHANNEL';
}

export interface DnsSecurityOverview {
  resolverType: 'DoH (DNS over HTTPS) / DoT (DNS over TLS) Recurser';
  totalQueriesToday: number;
  blockedQueriesToday: number;
  activeSinkholeRules: number;
  dnssecValidationRate: number; // Ex: 99.4%
  tunnelExfiltrationsThwarted: number;
  threatFeedSyncStatus: 'SYNCHRONIZED (Quad9 + Cloudflare 1.1.1.2 + RPZ Feed)';
}
