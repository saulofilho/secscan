import { 
  NmapHostTarget, 
  NmapScanProfile, 
  NmapScriptResult, 
  NmapSuiteSession, 
  NmapPortService 
} from '../types/nmap';
import { ScanReport } from '../types';

export const NMAP_PRESET_PROFILES: NmapScanProfile[] = [
  {
    id: 'quick_syn',
    name: 'Quick SYN Scan (-sS -T4)',
    cliFlags: '-sS -T4 -F',
    description: 'Varredura rápida das 100 portas mais comuns usando pacotes TCP SYN stealth sem handshake completo.',
    timingTemplate: 'T4',
    technique: 'SYN_STEALTH',
    detectOS: false,
    detectServices: false,
    runScripts: false,
    portsRange: '100 portas comuns (Fast)'
  },
  {
    id: 'service_version',
    name: 'Service & Version Detection (-sV)',
    cliFlags: '-sV --version-intensity 7',
    description: 'Interroga portas abertas via sondas de protocolo para extrair banners, versões exatas de software e CPEs.',
    timingTemplate: 'T3',
    technique: 'VERSION_DETECTION',
    detectOS: false,
    detectServices: true,
    runScripts: false,
    portsRange: '1-1024, 3000, 3306, 5432, 6379, 8080, 8443'
  },
  {
    id: 'os_fingerprint',
    name: 'OS Fingerprinting (-O)',
    cliFlags: '-O --osscan-guess',
    description: 'Análise TCP/IP stack fingerprinting (janela TCP, TTL, opções de cabeçalho) para identificar o SO do host.',
    timingTemplate: 'T3',
    technique: 'OS_DETECTION',
    detectOS: true,
    detectServices: true,
    runScripts: false,
    portsRange: '1-1024'
  },
  {
    id: 'nse_vuln',
    name: 'NSE Vulnerability Audit (--script vuln)',
    cliFlags: '-sV --script vuln',
    description: 'Executa scripts Lua do Nmap Scripting Engine para correlacionar vulnerabilidades conhecidas e CVEs com serviços expostos.',
    timingTemplate: 'T3',
    technique: 'SCRIPT_NSE',
    detectOS: false,
    detectServices: true,
    runScripts: true,
    scriptArg: 'vuln',
    portsRange: '21, 22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443'
  },
  {
    id: 'aggressive_full',
    name: 'Aggressive Comprehensive (-A)',
    cliFlags: '-A -T4',
    description: 'Combina detecção de SO (-O), versão de serviços (-sV), scripts padrão (--script default) e Traceroute com resolução reversa.',
    timingTemplate: 'T4',
    technique: 'AGGRESSIVE',
    detectOS: true,
    detectServices: true,
    runScripts: true,
    scriptArg: 'default,discovery',
    portsRange: 'Top 1000 Ports'
  },
  {
    id: 'udp_discovery',
    name: 'UDP Services Discovery (-sU)',
    cliFlags: '-sU -T3 --top-ports 20',
    description: 'Envia datagramas UDP para detectar serviços cruciais frequentemente esquecidos (DNS, SNMP, NTP, DHCP).',
    timingTemplate: 'T3',
    technique: 'UDP',
    detectOS: false,
    detectServices: true,
    runScripts: false,
    portsRange: '53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 500'
  }
];

export const NSE_SCRIPT_DATABASE = [
  {
    id: 'ssl-heartbleed',
    name: 'ssl-heartbleed',
    category: 'vuln',
    cvss: 7.5,
    description: 'Verifica se o servidor TLS/SSL é vulnerável ao vazamento de memória OpenSSL Heartbleed (CVE-2014-0160).',
    recommendation: 'Atualize o OpenSSL para >= 1.0.1g e revogue certificados emitidos anteriormente.'
  },
  {
    id: 'http-git',
    name: 'http-git',
    category: 'discovery',
    cvss: 7.2,
    description: 'Procura por repositórios .git expostos publicamente via web server root que permitam download do código-fonte.',
    recommendation: 'Restrinja o acesso à pasta .git/ no Nginx/Apache ou remova artefatos do diretório público.'
  },
  {
    id: 'http-sql-injection',
    name: 'http-sql-injection',
    category: 'vuln',
    cvss: 9.8,
    description: 'Injeta payloads de teste em formulários e parâmetros de query detectando respostas anômalas de banco de dados.',
    recommendation: 'Utilize consultas parametrizadas (Prepared Statements) ou ORM com escape rigoroso.'
  },
  {
    id: 'redis-unprotected',
    name: 'redis-info',
    category: 'auth',
    cvss: 9.1,
    description: 'Identifica instâncias Redis escutando em interfaces públicas sem autenticação por senha (requirepass).',
    recommendation: 'Vincule o Redis a 127.0.0.1 ou rede privada interna e ative autenticação com senha forte e ACL.'
  },
  {
    id: 'ssh-auth-methods',
    name: 'ssh-auth-methods',
    category: 'default',
    cvss: 5.3,
    description: 'Enumera métodos de autenticação aceitos pelo daemon SSH (senha, chave pública, keyboard-interactive).',
    recommendation: 'Desative PasswordAuthentication no sshd_config permitindo apenas autenticação via chave ED25519/RSA.'
  },
  {
    id: 'http-headers',
    name: 'http-security-headers',
    category: 'discovery',
    cvss: 4.3,
    description: 'Avalia a presença de cabeçalhos de segurança HTTP (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).',
    recommendation: 'Configure cabeçalhos Strict-Transport-Security, Content-Security-Policy e X-Frame-Options nos proxies reversos.'
  }
];

/**
 * Generates initial realistic hosts discovered from code findings & environment endpoints
 */
export function generateDiscoveredHostsFromReport(report: ScanReport): NmapHostTarget[] {
  const hosts: NmapHostTarget[] = [
    {
      id: 'host-gateway-01',
      hostname: 'api.internal.finance.corp',
      ip: '10.0.4.15',
      macAddress: '00:50:56:A1:B2:C3',
      vendor: 'VMware Virtual NIC',
      latencyMs: 1.4,
      status: 'UP',
      osFingerprint: {
        name: 'Linux 5.15 LTS (Ubuntu 22.04 LTS)',
        family: 'Linux',
        accuracy: 98,
        cpe: 'cpe:/o:canonical:ubuntu_linux:22.04',
        deviceType: 'general purpose'
      },
      ports: [
        {
          port: 22,
          protocol: 'tcp',
          state: 'OPEN',
          service: 'ssh',
          version: 'OpenSSH 8.9p1 Ubuntu-3ubuntu0.6',
          product: 'OpenSSH',
          confidence: 10,
          bannerSnippet: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6',
          riskSeverity: 'LOW',
          remediation: 'Mantenha atualizado e desative autenticação por senha.'
        },
        {
          port: 80,
          protocol: 'tcp',
          state: 'OPEN',
          service: 'http',
          version: 'nginx 1.18.0 (Ubuntu)',
          product: 'nginx',
          confidence: 10,
          bannerSnippet: 'Server: nginx/1.18.0 (Ubuntu)',
          riskSeverity: 'INFO',
          remediation: 'Redirecione todo tráfego para HTTPS (porta 443).'
        },
        {
          port: 443,
          protocol: 'tcp',
          state: 'OPEN',
          service: 'ssl/https',
          version: 'nginx 1.18.0 + Node.js Express',
          product: 'nginx/Express',
          confidence: 9,
          bannerSnippet: 'TLSv1.3 / TLS_AES_256_GCM_SHA384 / Strict-Transport-Security',
          riskSeverity: 'LOW',
          remediation: 'Configuração TLS adequada.'
        },
        {
          port: 3000,
          protocol: 'tcp',
          state: 'OPEN',
          service: 'node-api',
          version: 'Node.js Express /paymentController',
          product: 'Express REST API',
          confidence: 9,
          riskSeverity: 'HIGH',
          cveMatches: ['CVE-2023-45853', 'CWE-312'],
          remediation: 'Remova rotas administrativas expostas (/api/v1/admin/refunds/override).'
        }
      ],
      scriptResults: [
        {
          id: 'script-1',
          name: 'http-security-headers',
          category: 'discovery',
          severity: 'MEDIUM',
          output: 'Content-Security-Policy: ausente;\nX-Frame-Options: SAMEORIGIN;\nStrict-Transport-Security: max-age=31536000',
          recommendation: 'Implemente Content-Security-Policy (CSP) estrito.'
        },
        {
          id: 'script-2',
          name: 'http-git',
          category: 'vuln',
          severity: 'CRITICAL',
          output: 'Diretório /.git/HEAD encontrado acessível via GET http://10.0.4.15/.git/config',
          recommendation: 'Bloqueie no nginx: location ~ /\\.git { deny all; }',
          cvss: 8.5
        }
      ],
      tracerouteHops: [
        { hop: 1, rttMs: 0.3, ip: '10.0.0.1', hostname: 'core-router.internal' },
        { hop: 2, rttMs: 0.8, ip: '10.0.4.1', hostname: 'vlan4-switch.internal' },
        { hop: 3, rttMs: 1.4, ip: '10.0.4.15', hostname: 'api.internal.finance.corp' }
      ]
    },
    {
      id: 'host-db-02',
      hostname: 'postgres-primary.corp.local',
      ip: '10.0.8.22',
      macAddress: '00:1A:4B:99:EE:11',
      vendor: 'Cisco Virtual Gateway',
      latencyMs: 2.1,
      status: 'UP',
      osFingerprint: {
        name: 'Linux 5.10 (Debian 11 bullseye)',
        family: 'Linux',
        accuracy: 95,
        cpe: 'cpe:/o:debian:debian_linux:11',
        deviceType: 'server'
      },
      ports: [
        {
          port: 5432,
          protocol: 'tcp',
          state: 'OPEN',
          service: 'postgresql',
          version: 'PostgreSQL DB 14.9 (Debian 14.9-1.pgdg110+1)',
          product: 'PostgreSQL',
          confidence: 10,
          bannerSnippet: 'PostgreSQL 14.9; SSL enabled; auth: md5/scram-sha-256',
          riskSeverity: 'CRITICAL',
          cveMatches: ['CWE-798', 'CWE-259'],
          remediation: 'Porta de banco de dados diretamente acessível! Feche para subredes públicas e restrinja a 127.0.0.1 ou VPC privada.'
        },
        {
          port: 6379,
          protocol: 'tcp',
          state: 'OPEN',
          service: 'redis',
          version: 'Redis key-value store 6.2.7',
          product: 'Redis',
          confidence: 9,
          bannerSnippet: 'Redis 6.2.7; unprotected-mode: no',
          riskSeverity: 'HIGH',
          cveMatches: ['CVE-2022-0543'],
          remediation: 'Ative requirepass com senha forte e restrinja o bind apenas a localhost.'
        }
      ],
      scriptResults: [
        {
          id: 'script-db-1',
          name: 'pgsql-databases',
          category: 'discovery',
          severity: 'HIGH',
          output: 'Bancos de dados detectados no catálogo: [finance_db, users_staging, template1]',
          recommendation: 'Restrinja pg_hba.conf para permitir conexão somente da máquina da aplicação.'
        }
      ],
      tracerouteHops: [
        { hop: 1, rttMs: 0.4, ip: '10.0.0.1', hostname: 'core-router.internal' },
        { hop: 2, rttMs: 1.1, ip: '10.0.8.1', hostname: 'db-dmz-firewall.internal' },
        { hop: 3, rttMs: 2.1, ip: '10.0.8.22', hostname: 'postgres-primary.corp.local' }
      ]
    },
    {
      id: 'host-auth-03',
      hostname: 'auth.empresa.com.br',
      ip: '192.168.10.45',
      macAddress: '08:00:27:54:12:9A',
      vendor: 'Oracle VirtualBox NIC',
      latencyMs: 4.8,
      status: 'UP',
      osFingerprint: {
        name: 'Linux 6.1 (Alpine Linux v3.18 / Container)',
        family: 'Linux',
        accuracy: 92,
        cpe: 'cpe:/o:alpinelinux:alpine_linux:3.18',
        deviceType: 'container'
      },
      ports: [
        {
          port: 8080,
          protocol: 'tcp',
          state: 'OPEN',
          service: 'http-proxy',
          version: 'Envoy Edge Proxy 1.26.1',
          product: 'Envoy',
          confidence: 9,
          bannerSnippet: 'server: envoy; x-envoy-upstream-service-time: 2',
          riskSeverity: 'MEDIUM',
          remediation: 'Desative cabeçalhos verbosos de proxy que exponham arquitetura interna.'
        },
        {
          port: 8443,
          protocol: 'tcp',
          state: 'OPEN',
          service: 'https-alt',
          version: 'OAuth2 / Keycloak Auth Server 21.1',
          product: 'Keycloak',
          confidence: 8,
          bannerSnippet: 'Keycloak OIDC Realm: Enterprise-SSO',
          riskSeverity: 'LOW',
          remediation: 'Assegure rotação periódica de chaves assimétricas RS256 e JWKS.'
        },
        {
          port: 9090,
          protocol: 'tcp',
          state: 'FILTERED',
          service: 'prometheus-metrics',
          version: 'Prometheus Node Exporter',
          product: 'Prometheus',
          confidence: 7,
          riskSeverity: 'INFO',
          remediation: 'Mantenha porta filtrada por firewall corporativo.'
        }
      ],
      scriptResults: [
        {
          id: 'script-auth-1',
          name: 'ssl-enum-ciphers',
          category: 'safe',
          severity: 'LOW',
          output: 'TLSv1.2 e TLSv1.3 suportados. Ciphers fortes identificados (ECDHE-RSA-AES256-GCM-SHA384).',
          recommendation: 'Nenhuma ação necessária para ciphers TLS.'
        }
      ],
      tracerouteHops: [
        { hop: 1, rttMs: 0.5, ip: '192.168.10.1', hostname: 'edge-gw.local' },
        { hop: 2, rttMs: 4.8, ip: '192.168.10.45', hostname: 'auth.empresa.com.br' }
      ]
    }
  ];

  return hosts;
}

/**
 * Simulates the execution of an Nmap command session with real-looking terminal logs
 */
export function simulateNmapScanExecution(
  targetIpOrCidr: string,
  profile: NmapScanProfile,
  customFlags: string,
  existingHosts: NmapHostTarget[]
): NmapSuiteSession {
  const flagsUsed = customFlags || profile.cliFlags;
  const commandExecuted = `nmap ${flagsUsed} ${targetIpOrCidr}`;
  const timestamp = new Date().toLocaleString();
  const startTime = new Date();

  // Pick or filter targets based on input
  let targets = [...existingHosts];
  if (targetIpOrCidr && targetIpOrCidr !== '10.0.0.0/24' && targetIpOrCidr !== 'all') {
    const matched = targets.filter(h => 
      h.ip.includes(targetIpOrCidr) || 
      h.hostname.toLowerCase().includes(targetIpOrCidr.toLowerCase())
    );
    if (matched.length > 0) {
      targets = matched;
    }
  }

  const hostsScanned = targets.length;
  const hostsUp = targets.filter(h => h.status === 'UP').length;
  const totalOpenPorts = targets.reduce((sum, h) => sum + h.ports.filter(p => p.state === 'OPEN').length, 0);
  const vulnerabilitiesDetected = targets.reduce((sum, h) => sum + h.scriptResults.filter(s => s.severity === 'CRITICAL' || s.severity === 'HIGH').length, 0);

  // Generate real Nmap formatted console output
  const lines: string[] = [];
  lines.push(`Starting Nmap 7.94 ( https://nmap.org ) at ${timestamp}`);
  lines.push(`Initiating ${profile.technique} against ${targetIpOrCidr} with timing ${profile.timingTemplate}`);
  lines.push(`Scanning ${hostsScanned} host(s) [${profile.portsRange}]`);
  lines.push(`Completed ${profile.technique} at ${new Date().toLocaleTimeString()}, duration: 2.14s`);
  lines.push('');

  targets.forEach((host) => {
    lines.push(`Nmap scan report for ${host.hostname} (${host.ip})`);
    lines.push(`Host is up (${host.latencyMs / 1000}s latency).`);
    if (host.macAddress) {
      lines.push(`MAC Address: ${host.macAddress} (${host.vendor || 'Unknown NIC Vendor'})`);
    }
    lines.push(`PORT     STATE SERVICE     VERSION`);

    host.ports.forEach((p) => {
      const pStr = `${p.port}/${p.protocol}`.padEnd(9);
      const sStr = p.state.toLowerCase().padEnd(9);
      const srvStr = p.service.padEnd(12);
      lines.push(`${pStr}${sStr}${srvStr}${p.version || ''}`);
    });

    if (profile.detectOS || profile.technique === 'AGGRESSIVE') {
      lines.push(`Device type: ${host.osFingerprint.deviceType}`);
      lines.push(`Running: ${host.osFingerprint.family}`);
      lines.push(`OS CPE: ${host.osFingerprint.cpe}`);
      lines.push(`OS details: ${host.osFingerprint.name} (${host.osFingerprint.accuracy}% accuracy)`);
    }

    if (host.scriptResults && host.scriptResults.length > 0 && (profile.runScripts || profile.technique === 'AGGRESSIVE')) {
      lines.push(`Host script results:`);
      host.scriptResults.forEach(script => {
        lines.push(`| ${script.name}: `);
        script.output.split('\n').forEach(outLine => {
          lines.push(`|_  ${outLine}`);
        });
      });
    }

    if (host.tracerouteHops && (profile.technique === 'AGGRESSIVE' || flagsUsed.includes('--traceroute'))) {
      lines.push(`TRACEROUTE (using port ${host.ports[0]?.port || 80}/tcp)`);
      lines.push(`HOP RTT    ADDRESS`);
      host.tracerouteHops.forEach(hop => {
        lines.push(`${hop.hop.toString().padStart(2)}  ${hop.rttMs.toFixed(2)} ms ${hop.ip} (${hop.hostname || 'unresolved'})`);
      });
    }

    lines.push('');
  });

  lines.push(`Nmap done: ${hostsScanned} IP addresses (${hostsUp} hosts up) scanned in 2.48 seconds`);

  return {
    sessionId: `nmap-session-${Date.now()}`,
    timestamp,
    commandExecuted,
    timingTemplate: profile.timingTemplate,
    durationSeconds: 2.48,
    hostsScanned,
    hostsUp,
    totalOpenPorts,
    vulnerabilitiesDetected,
    targets,
    rawConsoleOutput: lines.join('\n')
  };
}
