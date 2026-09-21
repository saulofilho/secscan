import {
  DnsQueryLog,
  DnsSinkholeRule,
  DgaDetectionModel,
  DnssecChainOfTrust,
  DnsTunnelExfiltrationSession,
  DnsSecurityOverview
} from '../types/dns';

export const INITIAL_DNS_QUERIES: DnsQueryLog[] = [
  {
    id: 'dns-q-101',
    timestamp: 'Hoje, 08:44:10.120',
    queryDomain: '78a9f8b2c4e1.exfil.attacker-tunnel.net',
    queryType: 'TXT',
    clientIp: '10.0.4.15',
    clientHostname: 'prod-api-gateway-01',
    status: 'SUSPICIOUS_TUNNEL',
    dnssecStatus: 'INSECURE',
    sinkholeRedirectIp: '10.0.0.99',
    entropyShannon: 5.92,
    category: 'EXFILTRATION_TUNNEL',
    threatDescription: 'Tentativa de tunelamento DNS detectada: subdomínio de alta entropia contendo fragmentos de dados codificados em Base64.',
    ttlSeconds: 5
  },
  {
    id: 'dns-q-102',
    timestamp: 'Hoje, 08:41:05.441',
    queryDomain: 'xk92jqlpvnxmq81.biz',
    queryType: 'A',
    clientIp: '10.0.8.22',
    clientHostname: 'worker-node-k8s-pod-7',
    status: 'DGA_DETECTED',
    dnssecStatus: 'BOGUS_SIGNATURE_MISMATCH',
    sinkholeRedirectIp: '10.0.0.99',
    entropyShannon: 4.88,
    category: 'DGA_ALGORITHM',
    threatDescription: 'Domínio gerado algoritmicamente (DGA) característico de beacon C2 (Cobalt Strike / AsyncRAT).',
    ttlSeconds: 60
  },
  {
    id: 'dns-q-103',
    timestamp: 'Hoje, 08:35:12.809',
    queryDomain: 'paypa1-security-verification.top',
    queryType: 'A',
    clientIp: '192.168.1.104',
    clientHostname: 'workstation-financas-03',
    status: 'BLOCKED_SINKHOLE',
    dnssecStatus: 'INSECURE',
    sinkholeRedirectIp: '10.0.0.99',
    entropyShannon: 3.42,
    category: 'PHISHING_TYPOSQUATTING',
    threatDescription: 'Domínio malicioso de typosquatting e phishing bancário bloqueado via RPZ (Response Policy Zone).',
    ttlSeconds: 120
  },
  {
    id: 'dns-q-104',
    timestamp: 'Hoje, 08:30:22.010',
    queryDomain: 'api.stripe.com',
    queryType: 'A',
    clientIp: '10.0.4.15',
    clientHostname: 'prod-api-gateway-01',
    status: 'SAFE',
    dnssecStatus: 'SECURE_VALIDATED',
    resolvedIp: '54.187.128.99',
    entropyShannon: 2.10,
    category: 'CLEAN',
    threatDescription: 'Consulta legítima de API de gateway com validação estrita da cadeia de confiança DNSSEC (RRSIG).',
    ttlSeconds: 300
  },
  {
    id: 'dns-q-105',
    timestamp: 'Hoje, 08:15:00.910',
    queryDomain: 'github.com',
    queryType: 'A',
    clientIp: '10.0.4.15',
    clientHostname: 'prod-api-gateway-01',
    status: 'SAFE',
    dnssecStatus: 'SECURE_VALIDATED',
    resolvedIp: '140.82.121.4',
    entropyShannon: 2.35,
    category: 'CLEAN',
    threatDescription: 'Consulta legítima de repositório de código fonte com assinatura criptográfica verificada.',
    ttlSeconds: 600
  }
];

export const INITIAL_SINKHOLE_RULES: DnsSinkholeRule[] = [
  {
    id: 'sink-01',
    domainPattern: '*.attacker-tunnel.net',
    targetRedirectIp: '10.0.0.99 (Sinkhole Honeypot)',
    threatCategory: 'DNS Data Tunneling & Exfiltration',
    enabled: true,
    totalInterceptions: 142,
    lastInterceptedAt: 'Hoje, 08:44:10'
  },
  {
    id: 'sink-02',
    domainPattern: '*.bad-c2-dropzone.ru',
    targetRedirectIp: '10.0.0.99 (Sinkhole Honeypot)',
    threatCategory: 'Ransomware C2 Command & Control',
    enabled: true,
    totalInterceptions: 39,
    lastInterceptedAt: 'Hoje, 07:12:00'
  },
  {
    id: 'sink-03',
    domainPattern: '*paypa1*',
    targetRedirectIp: '10.0.0.99 (Sinkhole Honeypot)',
    threatCategory: 'Typosquatting & Credential Harvesting',
    enabled: true,
    totalInterceptions: 8,
    lastInterceptedAt: 'Hoje, 08:35:12'
  }
];

export const INITIAL_DGA_MODELS: DgaDetectionModel[] = [
  {
    dgaDomain: 'xk92jqlpvnxmq81.biz',
    calculatedEntropy: 4.88,
    consonantVowelRatio: 6.5,
    ngramScore: 0.12,
    confidenceScore: 97.8,
    predictedMalwareFamily: 'CobaltStrike',
    actionTaken: 'SINKHOLE_ISOLATE'
  },
  {
    dgaDomain: 'mzbqyrtplxwkv72.cc',
    calculatedEntropy: 5.12,
    consonantVowelRatio: 7.2,
    ngramScore: 0.08,
    confidenceScore: 99.1,
    predictedMalwareFamily: 'Emotet',
    actionTaken: 'SINKHOLE_ISOLATE'
  },
  {
    dgaDomain: 'cloud-aws-internal.net',
    calculatedEntropy: 2.85,
    consonantVowelRatio: 1.4,
    ngramScore: 0.88,
    confidenceScore: 4.2,
    predictedMalwareFamily: 'Unknown',
    actionTaken: 'ALERT_SOC'
  }
];

export const INITIAL_DNSSEC_CHAINS: DnssecChainOfTrust[] = [
  {
    domain: 'api.stripe.com',
    rootAnchorKey: 'Root KSK 20326 (SHA-256 Digest: e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d)',
    tldDsRecord: 'DS KeyTag 49201 (Digest: a5c8f18076de782f...) [Validated against .com]',
    zoneDnsKey: 'ZSK KeyTag 18290 (ECDSA P-256 Curve)',
    rrsigStatus: 'VALID',
    algorithm: 'ECDSA P-256 (Alg 13)',
    keyTag: 18290
  },
  {
    domain: 'xk92jqlpvnxmq81.biz',
    rootAnchorKey: 'Root KSK 20326 (SHA-256 Digest: e06d44b80b8f1d39...)',
    tldDsRecord: 'DS Record Ausente / Falha de Assinatura do Registro .biz',
    zoneDnsKey: 'Nenhuma chave pública DNSKEY válida encontrada',
    rrsigStatus: 'CORRUPTED',
    algorithm: 'RSA-SHA256 (Alg 8)',
    keyTag: 0
  }
];

export const INITIAL_TUNNEL_SESSIONS: DnsTunnelExfiltrationSession[] = [
  {
    sessionId: 'TUN-EXFIL-9481',
    clientIp: '10.0.4.15',
    apexDomain: 'exfil.attacker-tunnel.net',
    totalChunksCount: 48,
    estimatedBytesLeaked: 3072,
    reassembledDataSample: 'eyJhY2Nlc3Nfa2V5X2lkIjoiREVNT19BV1NfQUtJRF9TQU1QTEUiLCJzZWNyZXRfa2V5Ijoi...',
    status: 'ACTIVE_BLOCKING',
    detectedProtocol: 'BASE64_DNS_TUNNEL'
  }
];

export const INITIAL_DNS_OVERVIEW: DnsSecurityOverview = {
  resolverType: 'DoH (DNS over HTTPS) / DoT (DNS over TLS) Recurser',
  totalQueriesToday: 38492,
  blockedQueriesToday: 418,
  activeSinkholeRules: 3,
  dnssecValidationRate: 99.4,
  tunnelExfiltrationsThwarted: 14,
  threatFeedSyncStatus: 'SYNCHRONIZED (Quad9 + Cloudflare 1.1.1.2 + RPZ Feed)'
};
