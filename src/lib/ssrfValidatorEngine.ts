import {
  SsrfCheckResult,
  SsrfRisk
} from '../types/securityTools';

export const SAMPLE_SSRF_PAYLOADS: { name: string; url: string; description: string }[] = [
  {
    name: 'AWS / Azure IMDSv1 Metadata (Exfiltração de Role IAM)',
    url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    description: 'Acessa o serviço de metadados de instância da AWS para roubar tokens temporários de autenticação.'
  },
  {
    name: 'GCP Compute Metadata (Token de Acesso)',
    url: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
    description: 'Requisita token de acesso OAuth2 da conta de serviço padrão do Google Cloud.'
  },
  {
    name: 'Bypass Decimal IP (127.0.0.1 Obfuscado)',
    url: 'http://2130706433:8080/admin/delete-database',
    description: 'Usa a representação inteira decimal (DWORD) de 127.0.0.1 para burlar filtros ingênuos baseados em string.'
  },
  {
    name: 'Bypass Hexadecimal (0x7F000001)',
    url: 'http://0x7f000001:9090/metrics',
    description: 'Usa notação hexadecimal para acessar serviços locais na máquina host.'
  },
  {
    name: 'Rede Local RFC 1918 (Kubernetes Pod / Database)',
    url: 'http://10.244.0.15:5432/internal-db',
    description: 'Aponta para um endereço privado interno de contêiner ou cluster Kubernetes.'
  },
  {
    name: 'Esquema de Arquivo Local (file://)',
    url: 'file:///etc/passwd',
    description: 'Tentativa de ler arquivos sensíveis do sistema de arquivos do servidor.'
  },
  {
    name: 'Webhook Seguro Externo (Permitido)',
    url: 'https://api.stripe.com/v1/webhook_callbacks',
    description: 'Destino legítimo HTTPS público com resolução de IP público e esquema seguro.'
  }
];

export function validateSsrfTarget(targetUrl: string): SsrfCheckResult {
  const clean = targetUrl.trim();

  let parsed: URL;
  try {
    parsed = new URL(clean);
  } catch (err) {
    // If lacks protocol, try prepend http://
    try {
      parsed = new URL(`http://${clean}`);
    } catch {
      return {
        url: clean,
        hostname: 'invalid-url',
        scheme: 'unknown',
        port: 80,
        isPrivateOrLoopback: false,
        isCloudMetadata: false,
        isDecimalOrHexBypass: false,
        riskLevel: 'BLOCKED_CRITICAL',
        classification: 'URL Malformada ou Inválida',
        attackTechnique: 'Entrada não parseável por RFC 3986',
        remediationAdvice: 'Rejeite a requisição imediatamente antes de qualquer chamada HTTP.',
        safeClientExample: generateSafeClientSnippet()
      };
    }
  }

  const hostname = parsed.hostname.toLowerCase();
  const scheme = parsed.protocol.replace(':', '').toLowerCase();
  const port = parsed.port ? parseInt(parsed.port, 10) : scheme === 'https' ? 443 : 80;

  // 1. Non-HTTP scheme check
  if (scheme !== 'http' && scheme !== 'https') {
    return {
      url: clean,
      hostname,
      scheme,
      port,
      isPrivateOrLoopback: false,
      isCloudMetadata: false,
      isDecimalOrHexBypass: false,
      riskLevel: 'BLOCKED_CRITICAL',
      classification: `Esquema Não Permitido (${scheme}://)`,
      attackTechnique: 'Arbitrary Scheme Injection (LFI / Protocol Smuggling)',
      remediationAdvice: 'Permita estritamente apenas os protocolos http e https. Rejeite file://, gopher://, dict://, ftp://.',
      safeClientExample: generateSafeClientSnippet()
    };
  }

  // 2. Cloud Metadata Check
  const isCloudMetadata = 
    hostname === '169.254.169.254' || 
    hostname === '169.254.169.253' ||
    hostname.includes('metadata.google.internal') ||
    hostname.includes('instance-data');

  if (isCloudMetadata) {
    return {
      url: clean,
      hostname,
      scheme,
      port,
      isPrivateOrLoopback: true,
      isCloudMetadata: true,
      isDecimalOrHexBypass: false,
      riskLevel: 'BLOCKED_CRITICAL',
      classification: 'Endpoint de Metadados de Nuvem (IMDSv1)',
      attackTechnique: 'MITRE ATT&CK T1552.005 (Cloud Instance Metadata API Exfiltration)',
      remediationAdvice: 'Bloqueie explicitamente a faixa 169.254.169.254 e exija IMDSv2 com token hop-limit=1 no provedor de nuvem.',
      safeClientExample: generateSafeClientSnippet()
    };
  }

  // 3. Decimal / Hex / Octal Bypass Check
  const isDecimal = /^\d+$/.test(hostname);
  const isHex = /^0x[0-9a-f]+$/i.test(hostname);
  const isOctal = /^0[0-7]+(\.0[0-7]+)*$/.test(hostname);
  const isDecimalOrHexBypass = isDecimal || isHex || isOctal;

  if (isDecimalOrHexBypass) {
    return {
      url: clean,
      hostname,
      scheme,
      port,
      isPrivateOrLoopback: true,
      isCloudMetadata: false,
      isDecimalOrHexBypass: true,
      riskLevel: 'BLOCKED_CRITICAL',
      classification: 'Ofuscação de IP (Bypass Decimal / Hex / Octal)',
      attackTechnique: 'CWE-918: Obfuscated IP Address SSRF Filter Bypass',
      remediationAdvice: 'Normalize todos os endereços resolvendo primeiro o IP canônico no DNS antes de checar as listas de bloqueio.',
      safeClientExample: generateSafeClientSnippet()
    };
  }

  // 4. Loopback and Private RFC 1918 Check
  const isLoopback = 
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '0.0.0.0' ||
    hostname === '::1' ||
    hostname.startsWith('127.');

  const isRfc1918 = 
    hostname.startsWith('10.') ||
    hostname.startsWith('192.168.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname) ||
    hostname.startsWith('169.254.'); // Link-local

  const isPrivateOrLoopback = isLoopback || isRfc1918;

  if (isPrivateOrLoopback) {
    return {
      url: clean,
      hostname,
      scheme,
      port,
      isPrivateOrLoopback: true,
      isCloudMetadata: false,
      isDecimalOrHexBypass: false,
      riskLevel: 'BLOCKED_PRIVATE',
      classification: isLoopback ? 'Interface Loopback (Localhost)' : 'Faixa de IP Privada RFC 1918',
      attackTechnique: 'CWE-918: Server-Side Request Forgery contra Rede Interna',
      remediationAdvice: 'Rejeite requisições para 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12 e 192.168.0.0/16.',
      safeClientExample: generateSafeClientSnippet()
    };
  }

  // Safe public destination
  return {
    url: clean,
    hostname,
    scheme,
    port,
    isPrivateOrLoopback: false,
    isCloudMetadata: false,
    isDecimalOrHexBypass: false,
    riskLevel: 'SAFE',
    classification: 'Destino Público Seguro',
    attackTechnique: 'Nenhum vetor de SSRF detectado',
    remediationAdvice: 'URL validada com sucesso. Certifique-se de configurar timeouts curtos e desabilitar redirects automáticos (maxRedirects: 0).',
    safeClientExample: generateSafeClientSnippet()
  };
}

export function generateSafeClientSnippet(): string {
  return `// Node.js (Axios) com Proteção Estrita contra SSRF e DNS Rebinding
import axios from 'axios';
import dns from 'dns';
import net from 'net';

function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    // 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
    if (parts[0] === 127 || parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 0) return true;
  }
  if (net.isIPv6(ip)) {
    if (ip === '::1' || ip.startsWith('fe80:')) return true;
  }
  return false;
}

export async function safeOutboundRequest(urlStr: string) {
  const parsed = new URL(urlStr);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Protocolo não permitido. Apenas HTTP/HTTPS');
  }

  // Resolução prévia de DNS para prevenir evasões
  const { address } = await dns.promises.lookup(parsed.hostname);
  if (isPrivateIp(address)) {
    throw new Error(\`SSRF Detectado! Endereço IP privado bloqueado: \${address}\`);
  }

  return axios.get(urlStr, {
    maxRedirects: 0, // CRÍTICO: Previne redirect para IP local
    timeout: 5000,
    headers: { 'User-Agent': 'SecScan-SafeClient/2.5' }
  });
}`;
}
