import {
  NgfwPolicyRule,
  NgfwAppIdSignature,
  NgfwIpsSignatureMatch,
  NgfwSslInspectionSession,
  NgfwMetrics
} from '../types/ngfw';
import { ScanReport } from '../types';

export const INITIAL_APP_ID_CATALOG: NgfwAppIdSignature[] = [
  {
    id: 'app-stripe',
    name: 'Stripe-Payment-API',
    category: 'business-systems',
    standardPorts: [443],
    riskLevel: 2,
    description: 'Comunicação segura com endpoints da API financeira Stripe (charges, webhooks, refunds).',
    sslDecrypted: true
  },
  {
    id: 'app-postgres',
    name: 'PostgreSQL-Wire-Protocol',
    category: 'database',
    standardPorts: [5432],
    riskLevel: 4,
    description: 'Protocolo de comunicação direta binária com banco de dados PostgreSQL.',
    sslDecrypted: false
  },
  {
    id: 'app-redis',
    name: 'Redis-Serialization-Protocol (RESP)',
    category: 'database',
    standardPorts: [6379],
    riskLevel: 4,
    description: 'Protocolo de cache em memória e mensageria Redis em texto plano ou TLS.',
    sslDecrypted: false
  },
  {
    id: 'app-ssh',
    name: 'OpenSSH-Remote-Terminal',
    category: 'remote-access',
    standardPorts: [22],
    riskLevel: 3,
    description: 'Terminal interativo criptografado de administração de sistemas Linux.',
    sslDecrypted: false
  },
  {
    id: 'app-git-http',
    name: 'Git-Smart-HTTP',
    category: 'cloud-storage',
    standardPorts: [80, 443],
    riskLevel: 3,
    description: 'Operações de clone, fetch e push do protocolo Git sobre HTTP/S.',
    sslDecrypted: true
  },
  {
    id: 'app-c2-beacon',
    name: 'Cobalt-Strike-Malleable-C2',
    category: 'malicious',
    standardPorts: [8080, 8443, 443],
    riskLevel: 5,
    description: 'Tráfego camuflado de Command & Control utilizando cabeçalhos HTTP customizados e payloads criptografados.',
    sslDecrypted: true
  }
];

export const INITIAL_POLICY_RULES: NgfwPolicyRule[] = [
  {
    id: 'rule-01',
    ruleName: 'ISOLATE-DATABASE-FROM-UNTRUST',
    priority: 10,
    sourceZone: 'UNTRUST',
    destinationZone: 'DATABASE_TIER',
    sourceIps: ['any'],
    destinationIps: ['10.0.8.22', '10.0.8.0/24'],
    applications: ['PostgreSQL-Wire-Protocol', 'Redis-Serialization-Protocol (RESP)'],
    servicePorts: 'tcp/5432, tcp/6379',
    action: 'DROP',
    ipsProfileEnabled: true,
    sslInspectionEnabled: false,
    hitCount: 14208,
    lastHitTimestamp: 'Há 12 segundos',
    status: 'ACTIVE',
    description: 'Bloqueia sumariamente conexões diretas da Internet externa aos bancos de dados internos.'
  },
  {
    id: 'rule-02',
    ruleName: 'BLOCK-MALICIOUS-C2-BEACONS',
    priority: 20,
    sourceZone: 'INTERNAL_CORP',
    destinationZone: 'UNTRUST',
    sourceIps: ['10.0.0.0/16'],
    destinationIps: ['any'],
    applications: ['Cobalt-Strike-Malleable-C2'],
    servicePorts: 'any',
    action: 'RESET',
    ipsProfileEnabled: true,
    sslInspectionEnabled: true,
    hitCount: 39,
    lastHitTimestamp: 'Há 4 minutos',
    status: 'ACTIVE',
    description: 'Interrompe sessões TCP e quarentena endpoints com tráfego característico de malware e beacons C2.'
  },
  {
    id: 'rule-03',
    ruleName: 'ALLOW-GATEWAY-TO-STRIPE-PAYMENTS',
    priority: 50,
    sourceZone: 'DMZ',
    destinationZone: 'UNTRUST',
    sourceIps: ['10.0.4.15'],
    destinationIps: ['api.stripe.com'],
    applications: ['Stripe-Payment-API'],
    servicePorts: 'tcp/443',
    action: 'ALLOW',
    ipsProfileEnabled: true,
    sslInspectionEnabled: true,
    hitCount: 89450,
    lastHitTimestamp: 'Agora',
    status: 'ACTIVE',
    description: 'Permite checkout e pagamentos na Stripe com inspeção de vazamento de credenciais (DLP).'
  },
  {
    id: 'rule-04',
    ruleName: 'PROTECT-ADMIN-OVERRIDE-ENDPOINTS',
    priority: 80,
    sourceZone: 'UNTRUST',
    destinationZone: 'DMZ',
    sourceIps: ['any'],
    destinationIps: ['10.0.4.15'],
    applications: ['web-browsing', 'ssl'],
    servicePorts: 'tcp/3000, tcp/8080',
    action: 'BLOCK',
    ipsProfileEnabled: true,
    sslInspectionEnabled: true,
    hitCount: 521,
    lastHitTimestamp: 'Há 18 minutos',
    status: 'ACTIVE',
    description: 'Impede requisições diretas a /api/v1/admin/refunds/override sem VPN autenticada.'
  },
  {
    id: 'rule-05',
    ruleName: 'DEFAULT-DENY-ALL-CROSS-ZONE',
    priority: 999,
    sourceZone: 'UNTRUST',
    destinationZone: 'INTERNAL_CORP',
    sourceIps: ['any'],
    destinationIps: ['any'],
    applications: ['any'],
    servicePorts: 'any',
    action: 'DROP',
    ipsProfileEnabled: false,
    sslInspectionEnabled: false,
    hitCount: 928410,
    lastHitTimestamp: 'Agora',
    status: 'ACTIVE',
    description: 'Regra de ouro de firewall corporativo: negação implícita para qualquer tráfego não explicitamente autorizado.'
  }
];

export const INITIAL_IPS_MATCHES: NgfwIpsSignatureMatch[] = [
  {
    id: 'ips-01',
    cve: 'CVE-2023-45853',
    threatId: 'SID-49210',
    signatureName: 'HTTP: Admin Refund Route Bypass & Hardcoded Token Attack',
    severity: 'CRITICAL',
    category: 'COMMAND_INJECTION',
    actionTaken: 'BLOCKED',
    sourceIp: '198.51.100.44 (Rússia / Tor Exit)',
    destinationIp: '10.0.4.15:3000',
    application: 'Node.js Express /paymentController',
    timestamp: 'Hoje, 08:42:10',
    payloadSnippet: 'POST /api/v1/admin/refunds/override HTTP/1.1\\r\\nAuthorization: Bearer DEMO_JWT_ADMIN_TOKEN',
    mitigationRecommendation: 'Regra de IPS SID-49210 ativada com ação inline de drop imediato do pacote TCP RST.'
  },
  {
    id: 'ips-02',
    cve: 'CWE-538',
    threatId: 'SID-31084',
    signatureName: 'HTTP: Git Repository Metadata Extraction Attempt (/.git/HEAD)',
    severity: 'HIGH',
    category: 'EXPLOIT',
    actionTaken: 'BLOCKED',
    sourceIp: '203.0.113.88 (Scanner Automatizado)',
    destinationIp: '10.0.4.15:80',
    application: 'Git-Smart-HTTP',
    timestamp: 'Hoje, 08:35:19',
    payloadSnippet: 'GET /.git/config HTTP/1.1\\r\\nHost: 10.0.4.15\\r\\nUser-Agent: Nikto/2.5.0',
    mitigationRecommendation: 'Habilite WAF/IPS inline para responder com HTTP 403 Forbidden antes do web server.'
  },
  {
    id: 'ips-03',
    cve: 'CVE-2022-0543',
    threatId: 'SID-58911',
    signatureName: 'REDIS: Lua Sandbox Escape Remote Code Execution Probe',
    severity: 'CRITICAL',
    category: 'EXPLOIT',
    actionTaken: 'DROPPED_PACKET',
    sourceIp: '185.220.101.5',
    destinationIp: '10.0.8.22:6379',
    application: 'Redis-Serialization-Protocol (RESP)',
    timestamp: 'Hoje, 07:18:42',
    payloadSnippet: '*3\\r\\n$4\\r\\nEVAL\\r\\n$32\\r\\nlocal io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1-os.so"...',
    mitigationRecommendation: 'A porta 6379 deve ser imediatamente colocada na zona DATABASE_TIER sem rota pública.'
  }
];

export const INITIAL_SSL_SESSIONS: NgfwSslInspectionSession[] = [
  {
    sessionId: 'ssl-flow-901',
    flow: '10.0.4.15:44912 -> 54.187.128.99:443',
    sni: 'api.stripe.com',
    tlsVersion: 'TLSv1.3',
    cipherSuite: 'TLS_AES_256_GCM_SHA384',
    decryptionStatus: 'INSPECTED',
    threatFound: false,
    timestamp: '08:44:02'
  },
  {
    sessionId: 'ssl-flow-902',
    flow: '10.0.0.45:51280 -> 185.199.108.133:443',
    sni: 'raw.githubusercontent.com',
    tlsVersion: 'TLSv1.3',
    cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256',
    decryptionStatus: 'INSPECTED',
    threatFound: true,
    threatDetails: 'DLP Trigger: GITHUB_BACKUP_PAT detectado em trânsito dentro da payload HTTPS descriptografada.',
    timestamp: '08:41:29'
  },
  {
    sessionId: 'ssl-flow-903',
    flow: '10.0.8.10:39401 -> 140.82.114.4:443',
    sni: 'github.com',
    tlsVersion: 'TLSv1.3',
    cipherSuite: 'TLS_AES_128_GCM_SHA256',
    decryptionStatus: 'INSPECTED',
    threatFound: false,
    timestamp: '08:39:11'
  }
];

export const INITIAL_NGFW_METRICS: NgfwMetrics = {
  totalPacketsProcessed: 4892015,
  throughputMbps: 412.8,
  activeSessions: 1840,
  threatsBlockedToday: 147,
  sslInspectedSessionsPct: 91.4,
  cpuLoadPct: 34.2,
  memoryUsagePct: 58.1
};
