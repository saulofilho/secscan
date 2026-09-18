import {
  SnortSuricataRule,
  IdsLiveAlert,
  IdsAnomalyMetric,
  IdsSystemStatus
} from '../types/ids';

export const INITIAL_IDS_RULES: SnortSuricataRule[] = [
  {
    id: 'rule-sid-202401',
    sid: 202401,
    rev: 1,
    action: 'DROP',
    protocol: 'tcp',
    srcIp: '$EXTERNAL_NET',
    srcPort: 'any',
    direction: '->',
    dstIp: '$HOME_NET',
    dstPort: '3000',
    msg: 'ET WEB_SPECIFIC_APPS Node.js Admin Refund Token Bypass Attempt',
    contentMatches: ['POST /api/v1/admin/refunds/override', 'Bearer DEMO_JWT_ADMIN_TOKEN'],
    classtype: 'web-application-attack',
    cve: 'CVE-2023-45853',
    reference: 'url,owasp.org/Top10/A01_2021-Broken_Access_Control/',
    enabled: true,
    hitsCount: 18,
    rawRuleString: 'drop tcp $EXTERNAL_NET any -> $HOME_NET 3000 (msg:"ET WEB_SPECIFIC_APPS Node.js Admin Refund Token Bypass Attempt"; flow:to_server,established; content:"POST /api/v1/admin/refunds/override"; http_uri; content:"Bearer DEMO_JWT_ADMIN_TOKEN"; http_header; classtype:web-application-attack; sid:202401; rev:1;)'
  },
  {
    id: 'rule-sid-202402',
    sid: 202402,
    rev: 3,
    action: 'DROP',
    protocol: 'tcp',
    srcIp: '$EXTERNAL_NET',
    srcPort: 'any',
    direction: '->',
    dstIp: '$HOME_NET',
    dstPort: '80',
    msg: 'ET SCAN Git Repository Metadata Probing (/.git/HEAD)',
    contentMatches: ['GET /.git/HEAD', 'ref: refs/heads/'],
    classtype: 'attempted-recon',
    cve: 'CWE-538',
    enabled: true,
    hitsCount: 64,
    rawRuleString: 'drop tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"ET SCAN Git Repository Metadata Probing (/.git/HEAD)"; flow:to_server,established; content:"GET /.git/HEAD"; http_uri; classtype:attempted-recon; sid:202402; rev:3;)'
  },
  {
    id: 'rule-sid-202403',
    sid: 202403,
    rev: 2,
    action: 'REJECT',
    protocol: 'tcp',
    srcIp: '$EXTERNAL_NET',
    srcPort: 'any',
    direction: '->',
    dstIp: '$HOME_NET',
    dstPort: '6379',
    msg: 'ET EXPLOIT Redis EVAL Lua Sandbox Escape Attempt (CVE-2022-0543)',
    contentMatches: ['EVAL', 'package.loadlib'],
    classtype: 'trojan-activity',
    cve: 'CVE-2022-0543',
    enabled: true,
    hitsCount: 7,
    rawRuleString: 'reject tcp $EXTERNAL_NET any -> $HOME_NET 6379 (msg:"ET EXPLOIT Redis EVAL Lua Sandbox Escape Attempt (CVE-2022-0543)"; flow:to_server,established; content:"EVAL"; nocase; content:"package.loadlib"; nocase; classtype:trojan-activity; sid:202403; rev:2;)'
  },
  {
    id: 'rule-sid-202404',
    sid: 202404,
    rev: 1,
    action: 'ALERT',
    protocol: 'tcp',
    srcIp: '$HOME_NET',
    srcPort: 'any',
    direction: '->',
    dstIp: '$EXTERNAL_NET',
    dstPort: '443',
    msg: 'ET POLICY Cleartext Secret Exfiltration Pattern (AWS_ACCESS_KEY_ID in Body)',
    contentMatches: ['AKIA[0-9A-Z]{16}'],
    classtype: 'policy-violation',
    enabled: true,
    hitsCount: 3,
    rawRuleString: 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"ET POLICY Cleartext Secret Exfiltration Pattern (AWS_ACCESS_KEY_ID in Body)"; flow:to_server,established; pcre:"/AKIA[0-9A-Z]{16}/"; classtype:policy-violation; sid:202404; rev:1;)'
  },
  {
    id: 'rule-sid-202405',
    sid: 202405,
    rev: 4,
    action: 'DROP',
    protocol: 'icmp',
    srcIp: '$EXTERNAL_NET',
    srcPort: 'any',
    direction: '->',
    dstIp: '$HOME_NET',
    dstPort: 'any',
    msg: 'ET SCAN Nmap ICMP Ping Sweep / Echo Probe Burst',
    contentMatches: [],
    classtype: 'attempted-recon',
    enabled: true,
    hitsCount: 312,
    rawRuleString: 'drop icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nmap ICMP Ping Sweep / Echo Probe Burst"; itype:8; threshold:type both, track by_src, count 20, seconds 2; classtype:attempted-recon; sid:202405; rev:4;)'
  }
];

export const INITIAL_IDS_ALERTS: IdsLiveAlert[] = [
  {
    id: 'alt-9901',
    timestamp: 'Hoje, 08:44:12.419',
    sid: 202401,
    engine: 'SIGNATURE_SURICATA',
    severity: '1_HIGH',
    category: 'web-application-attack',
    signatureMsg: 'ET WEB_SPECIFIC_APPS Node.js Admin Refund Token Bypass Attempt',
    actionTaken: 'DROP',
    srcIp: '198.51.100.44',
    srcPort: 48912,
    dstIp: '10.0.4.15',
    dstPort: 3000,
    protocol: 'TCP',
    packetHexPayload: '50 4f 53 54 20 2f 61 70 69 2f 76 31 2f 61 64 6d 69 6e 2f 72 65 66 75 6e 64 73 2f 6f 76 65 72 72 69 64 65 20 48 54 54 50 2f 31 2e 31 0d 0a 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 3a 20 42 65 61 72 65 72 20 44 45 4d 4f 5f 4a 57 54 5f 41 44 4d 49 4e 5f 54 4f 4b 45 4e',
    packetAsciiPayload: 'POST /api/v1/admin/refunds/override HTTP/1.1\\r\\nAuthorization: Bearer DEMO_JWT_ADMIN_TOKEN',
    pcapPacketNo: 48190,
    interfaceName: 'eth0 (AF_PACKET inline)'
  },
  {
    id: 'alt-9902',
    timestamp: 'Hoje, 08:35:19.102',
    sid: 202402,
    engine: 'SIGNATURE_SURICATA',
    severity: '1_HIGH',
    category: 'attempted-recon',
    signatureMsg: 'ET SCAN Git Repository Metadata Probing (/.git/HEAD)',
    actionTaken: 'DROP',
    srcIp: '203.0.113.88',
    srcPort: 51208,
    dstIp: '10.0.4.15',
    dstPort: 80,
    protocol: 'TCP',
    packetHexPayload: '47 45 54 20 2f 2e 67 69 74 2f 48 45 41 44 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 31 30 2e 30 2e 34 2e 31 35',
    packetAsciiPayload: 'GET /.git/HEAD HTTP/1.1\\r\\nHost: 10.0.4.15\\r\\nUser-Agent: Nikto/2.5.0',
    pcapPacketNo: 47201,
    interfaceName: 'eth0 (AF_PACKET inline)'
  },
  {
    id: 'alt-9903',
    timestamp: 'Hoje, 07:18:42.880',
    sid: 202403,
    engine: 'SIGNATURE_SURICATA',
    severity: '1_HIGH',
    category: 'trojan-activity',
    signatureMsg: 'ET EXPLOIT Redis EVAL Lua Sandbox Escape Attempt (CVE-2022-0543)',
    actionTaken: 'REJECT',
    srcIp: '185.220.101.5',
    srcPort: 39120,
    dstIp: '10.0.8.22',
    dstPort: 6379,
    protocol: 'TCP',
    packetHexPayload: '2a 33 0d 0a 24 34 0d 0a 45 56 41 4c 0d 0a 24 33 32 0d 0a 70 61 63 6b 61 67 65 2e 6c 6f 61 64 6c 69 62',
    packetAsciiPayload: '*3\\r\\n$4\\r\\nEVAL\\r\\n$32\\r\\nlocal io_l = package.loadlib("/usr/lib/liblua.so"...',
    pcapPacketNo: 41920,
    interfaceName: 'eth1 (Intra-VPC)'
  },
  {
    id: 'alt-9904',
    timestamp: 'Hoje, 06:12:05.110',
    sid: 900101,
    engine: 'ANOMALY_HEURISTIC',
    severity: '2_MEDIUM',
    category: 'network-anomaly',
    signatureMsg: 'HEURISTIC: SYN Flood / Half-Open Connection Spike Exceeded Baseline',
    actionTaken: 'ALERT',
    srcIp: '45.142.212.0/24 (Múltiplas origens)',
    srcPort: 0,
    dstIp: '10.0.4.15',
    dstPort: 3000,
    protocol: 'TCP SYN',
    packetHexPayload: '00 00 00 00 [Burst de 4.200 pacotes SYN sem ACK de conclusão]',
    packetAsciiPayload: '[SYN Flood Detection Window = 5s, SYN/ACK Ratio = 0.08]',
    pcapPacketNo: 39401,
    interfaceName: 'eth0'
  }
];

export const INITIAL_ANOMALY_METRICS: IdsAnomalyMetric[] = [
  {
    metricName: 'Taxa de SYN Sem Resposta (Half-Open)',
    currentValue: 18.2,
    baselineThreshold: 45.0,
    status: 'NORMAL',
    unit: 'pkts/seg',
    description: 'Monitora taxa de pacotes TCP SYN sem conclusão de 3-way handshake para prevenir negação de serviço (DoS).'
  },
  {
    metricName: 'Entropia Média do Payload UDP/DNS',
    currentValue: 4.88,
    baselineThreshold: 6.50,
    status: 'NORMAL',
    unit: 'bits (Shannon)',
    description: 'Detecta tunelamento de dados e exfiltração secreta encapsulada em consultas DNS.'
  },
  {
    metricName: 'Proporção de Requisições HTTP 4xx/5xx',
    currentValue: 34.1,
    baselineThreshold: 20.0,
    status: 'ANOMALOUS',
    unit: '% do tráfego web',
    description: 'Pico anômalo de erros indicando scanners de vulnerabilidades ou brute-force de diretórios.'
  },
  {
    metricName: 'Taxa de Fragmentação IP Anômala',
    currentValue: 0.1,
    baselineThreshold: 5.0,
    status: 'NORMAL',
    unit: 'fragmentos/seg',
    description: 'Identifica tentativas de invasão através de sobreposição e fragmentação de pacotes (Teardrop / Fragroute).'
  }
];

export const INITIAL_IDS_STATUS: IdsSystemStatus = {
  mode: 'IPS_INLINE',
  afPacketThreads: 8,
  activeRulesCount: 5,
  packetsInspectedPerSec: 14850,
  droppedPacketsPerSec: 42,
  zeroCopyInterface: 'AF_PACKET (Kernel Bypass / zero-copy ring buffer)',
  memoryUsageMb: 384,
  reassembledTcpStreams: 1892
};
