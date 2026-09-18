import {
  NiktoTargetProfile,
  NiktoScanOptions,
  NiktoScanSession,
  NiktoCheckItem,
  NiktoSecurityHeaderCheck,
  NiktoHttpMethodsAudit
} from '../types/nikto';
import { ScanReport } from '../types';

export const NIKTO_TUNING_DICTIONARY: { code: string; label: string; desc: string }[] = [
  { code: '1', label: 'Arquivos Interessantes / Logs', desc: 'Backups, arquivos temporários (.bak, .old, .swp) e logs de depuração.' },
  { code: '2', label: 'Erros de Configuração / Padrões', desc: 'Páginas padrão, manuais instalados, scripts de teste de fábrica.' },
  { code: '3', label: 'Vazamento de Informações', desc: 'phpinfo, banners verbosos, stack traces e endpoints de métricas.' },
  { code: '4', label: 'Injeção XSS / Scripting', desc: 'Parâmetros refletidos sem sanitização no cabeçalho ou payload HTML.' },
  { code: '7', label: 'Execução Remota de Código', desc: 'Tentativas de upload ou scripts CGI exploráveis.' },
  { code: '9', label: 'Injeção SQL (Web Application)', desc: 'Endpoints suscetíveis a testes de erro de sintaxe SQL.' },
  { code: 'b', label: 'Versão de Software / Banners', desc: 'Identificação de softwares desatualizados no cabeçalho Server ou X-Powered-By.' },
  { code: 'c', label: 'Cabeçalhos de Segurança (Headers & Cookies)', desc: 'Auditoria de HSTS, CSP, X-Frame-Options, SameSite e HttpOnly.' }
];

export function buildDefaultTargets(report: ScanReport): NiktoTargetProfile[] {
  return [
    {
      id: 'target-api-gateway',
      targetUrl: 'https://api.internal.finance.corp',
      host: 'api.internal.finance.corp',
      port: 443,
      useSsl: true,
      webServerBanner: 'nginx/1.18.0 (Ubuntu)',
      serverVersion: '1.18.0',
      ip: '10.0.4.15',
      responseTimeMs: 24,
      checksPassed: 38,
      checksFailed: 6,
      securityHeaders: [
        {
          headerName: 'Strict-Transport-Security (HSTS)',
          status: 'WEAK',
          expectedValue: 'max-age=31536000; includeSubDomains; preload',
          actualValue: 'max-age=86400',
          riskDescription: 'HSTS configurado com tempo muito curto (1 dia). Não oferece proteção permanente contra ataques SSL Strip.',
          remediationSnippet: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;'
        },
        {
          headerName: 'Content-Security-Policy (CSP)',
          status: 'MISSING',
          expectedValue: "default-src 'self'; script-src 'self'",
          actualValue: undefined,
          riskDescription: 'Ausência total de CSP permite injeção de scripts maliciosos (XSS) e carregamento de iframes não autorizados.',
          remediationSnippet: "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;"
        },
        {
          headerName: 'X-Frame-Options',
          status: 'VALID',
          expectedValue: 'DENY ou SAMEORIGIN',
          actualValue: 'SAMEORIGIN',
          riskDescription: 'Protegido contra Clickjacking básico dentro da mesma origem.',
          remediationSnippet: 'add_header X-Frame-Options "SAMEORIGIN" always;'
        },
        {
          headerName: 'X-Content-Type-Options',
          status: 'MISSING',
          expectedValue: 'nosniff',
          actualValue: undefined,
          riskDescription: 'Navegadores podem interpretar arquivos de mídia ou texto como JavaScript (MIME-type sniffing).',
          remediationSnippet: 'add_header X-Content-Type-Options "nosniff" always;'
        },
        {
          headerName: 'Server Header / Banner Disclosure',
          status: 'WEAK',
          expectedValue: 'Oculto (sem versão explícita)',
          actualValue: 'nginx/1.18.0 (Ubuntu)',
          riskDescription: 'Divulga publicamente a versão exata do Nginx e a distribuição Linux para atacantes automatizados.',
          remediationSnippet: 'server_tokens off;'
        }
      ],
      httpMethods: [
        { method: 'GET', allowed: true, isDangerous: false, statusResponse: 200 },
        { method: 'POST', allowed: true, isDangerous: false, statusResponse: 200 },
        { method: 'OPTIONS', allowed: true, isDangerous: false, statusResponse: 204 },
        { method: 'HEAD', allowed: true, isDangerous: false, statusResponse: 200 },
        { method: 'TRACE', allowed: true, isDangerous: true, statusResponse: 200, riskNote: 'Método TRACE habilitado! Permite ataques de Cross-Site Tracing (XST) para roubo de cookies HttpOnly.' },
        { method: 'PUT', allowed: false, isDangerous: false, statusResponse: 405 },
        { method: 'DELETE', allowed: false, isDangerous: false, statusResponse: 405 }
      ],
      findings: [
        {
          id: 'nikto-f-01',
          osvdb: 3233,
          uri: '/.git/HEAD',
          httpMethod: 'GET',
          tuningCode: '1',
          category: 'FILE_CHECK',
          severity: 'CRITICAL',
          description: 'Diretório Git exposto publicamente (/.git/HEAD). Possibilita reconstrução do código-fonte e histórico de commits da aplicação.',
          serverBannerSnippet: 'ref: refs/heads/main',
          recommendation: 'Bloqueie explicitamente o acesso a arquivos e diretórios ocultos no servidor web.',
          remediationSnippet: 'location ~ /\\.git { deny all; return 404; }',
          referenceUrl: 'https://cwe.mitre.org/data/definitions/538.html'
        },
        {
          id: 'nikto-f-02',
          osvdb: 3092,
          uri: '/api/v1/admin/refunds/override',
          httpMethod: 'POST',
          tuningCode: '2',
          category: 'MISCONFIG_DEFAULT',
          severity: 'HIGH',
          description: 'Endpoint administrativo sem autenticação prévia identificado via dicionário de rotas sensíveis.',
          recommendation: 'Restrinja endpoints privilegiados com middleware de autorização RBAC e VPN interna.',
          remediationSnippet: 'router.use("/api/v1/admin", authenticateAdminSession);'
        },
        {
          id: 'nikto-f-03',
          osvdb: 877,
          uri: '/trace-test',
          httpMethod: 'TRACE',
          tuningCode: 'c',
          category: 'SECURITY_HEADER',
          severity: 'MEDIUM',
          description: 'O servidor web respondeu a solicitações HTTP TRACE. Pode ser explorado por atacantes para refletir cabeçalhos e furtar tokens.',
          recommendation: 'Desative o método TRACE em sua configuração global do Nginx/Apache.',
          remediationSnippet: 'if ($request_method = TRACE) { return 405; }'
        },
        {
          id: 'nikto-f-04',
          osvdb: 637,
          uri: '/robots.txt',
          httpMethod: 'GET',
          tuningCode: '3',
          category: 'INFO_DISCLOSURE',
          severity: 'INFO',
          description: 'O arquivo robots.txt contém diretivas "Disallow" que revelam caminhos ocultos (/admin, /backup, /internal_docs).',
          recommendation: 'Não confie no robots.txt para proteger pastas secretas; aplique controle de acesso em nível de servidor.',
          remediationSnippet: '# Proteja caminhos via autenticação real e não apenas diretivas de indexador'
        },
        {
          id: 'nikto-f-05',
          osvdb: 12184,
          uri: '/package.json.bak',
          httpMethod: 'GET',
          tuningCode: '1',
          category: 'FILE_CHECK',
          severity: 'HIGH',
          description: 'Arquivo de backup de dependências encontrado no diretório estático. Revela versões de bibliotecas e scripts internos.',
          recommendation: 'Remova arquivos com extensão .bak, .old, .save da raiz estática de publicação.',
          remediationSnippet: 'find /var/www -name "*.bak" -type f -delete'
        }
      ]
    },
    {
      id: 'target-auth-service',
      targetUrl: 'https://auth.empresa.com.br:8443',
      host: 'auth.empresa.com.br',
      port: 8443,
      useSsl: true,
      webServerBanner: 'Keycloak OIDC / Envoy 1.26.1',
      serverVersion: 'Keycloak 21.1',
      ip: '192.168.10.45',
      responseTimeMs: 31,
      checksPassed: 42,
      checksFailed: 3,
      securityHeaders: [
        {
          headerName: 'Strict-Transport-Security (HSTS)',
          status: 'VALID',
          expectedValue: 'max-age=31536000; includeSubDomains',
          actualValue: 'max-age=31536000; includeSubDomains',
          riskDescription: 'HSTS ativo com expiração de 1 ano.',
          remediationSnippet: ''
        },
        {
          headerName: 'Content-Security-Policy (CSP)',
          status: 'VALID',
          expectedValue: "frame-ancestors 'none'",
          actualValue: "frame-ancestors 'none'; default-src 'self'",
          riskDescription: 'CSP estrito configurado.',
          remediationSnippet: ''
        },
        {
          headerName: 'X-Powered-By / Server Disclosure',
          status: 'WEAK',
          expectedValue: 'Oculto',
          actualValue: 'Envoy / Keycloak 21.1',
          riskDescription: 'Exposição de versão do servidor de autenticação.',
          remediationSnippet: 'hide_server_tokens: true'
        }
      ],
      httpMethods: [
        { method: 'GET', allowed: true, isDangerous: false, statusResponse: 200 },
        { method: 'POST', allowed: true, isDangerous: false, statusResponse: 200 },
        { method: 'OPTIONS', allowed: true, isDangerous: false, statusResponse: 204 },
        { method: 'TRACE', allowed: false, isDangerous: false, statusResponse: 405 },
        { method: 'PUT', allowed: false, isDangerous: false, statusResponse: 405 }
      ],
      findings: [
        {
          id: 'nikto-auth-01',
          osvdb: 3233,
          uri: '/auth/realms/master/.well-known/openid-configuration',
          httpMethod: 'GET',
          tuningCode: '3',
          category: 'INFO_DISCLOSURE',
          severity: 'INFO',
          description: 'Discovery endpoint público OIDC ativo, enumerando algoritmos criptográficos suportados (RS256, ES256).',
          recommendation: 'Comportamento esperado para OAuth2/OIDC, porém valide que o realm master está protegido.',
          remediationSnippet: '# Realm master deve ser desativado para contas de usuários finais'
        },
        {
          id: 'nikto-auth-02',
          osvdb: 981,
          uri: '/metrics',
          httpMethod: 'GET',
          tuningCode: '3',
          category: 'INFO_DISCLOSURE',
          severity: 'MEDIUM',
          description: 'Endpoint /metrics do Prometheus acessível publicamente sem autenticação mTLS ou token Bearer.',
          recommendation: 'Bloqueie o caminho /metrics para acessos externos no ingress controller.',
          remediationSnippet: 'ingress.annotations: nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8"'
        }
      ]
    }
  ];
}

/**
 * Simulates the execution of Nikto web server scanner command
 */
export function simulateNiktoScan(
  options: NiktoScanOptions,
  currentTargets: NiktoTargetProfile[]
): NiktoScanSession {
  const tuningStr = options.tuningCategories.join('');
  const sslFlag = options.useSsl ? ' -ssl' : '';
  const portFlag = options.port !== 80 && options.port !== 443 ? ` -p ${options.port}` : '';
  const cliCommand = `nikto -h ${options.targetUrl}${portFlag}${sslFlag} -Tuning ${tuningStr || 'all'} -C all`;
  const timestamp = new Date().toLocaleString();

  // Find or craft target profile
  let target = currentTargets.find(t => t.targetUrl === options.targetUrl) || currentTargets[0];
  if (!target) {
    target = buildDefaultTargets({} as ScanReport)[0];
  }

  // Generate realistic standard Nikto terminal output
  const lines: string[] = [];
  lines.push(`- Nikto v2.5.0`);
  lines.push(`---------------------------------------------------------------------------`);
  lines.push(`+ Target IP:          ${target.ip}`);
  lines.push(`+ Target Hostname:    ${target.host}`);
  lines.push(`+ Target Port:        ${target.port}`);
  lines.push(`+ SSL Info:           ${target.useSsl ? 'TLSv1.3 / Cipher: TLS_AES_256_GCM_SHA384' : 'Disabled (HTTP Plaintext)'}`);
  lines.push(`+ Start Time:         ${timestamp}`);
  lines.push(`---------------------------------------------------------------------------`);
  lines.push(`+ Server: ${target.webServerBanner}`);
  
  // Security headers output
  target.securityHeaders.forEach(h => {
    if (h.status === 'MISSING') {
      lines.push(`+ The anti-clickjacking/security header '${h.headerName}' is not present.`);
    } else if (h.status === 'WEAK') {
      lines.push(`+ The security header '${h.headerName}' has a weak value: '${h.actualValue}'.`);
    }
  });

  // HTTP Methods check
  const dangerousMethods = target.httpMethods.filter(m => m.allowed && m.isDangerous);
  if (dangerousMethods.length > 0) {
    lines.push(`+ Allowed HTTP Methods: ${target.httpMethods.filter(m => m.allowed).map(m => m.method).join(', ')}`);
    dangerousMethods.forEach(m => {
      lines.push(`+ OSVDB-877: HTTP method '${m.method}' is allowed: ${m.riskNote || 'Potential vulnerability'}`);
    });
  }

  // Findings list in Nikto syntax
  target.findings.forEach(f => {
    const osvdbStr = f.osvdb ? `+ OSVDB-${f.osvdb}: ` : `+ `;
    lines.push(`${osvdbStr}${f.uri}: ${f.description}`);
  });

  lines.push(`---------------------------------------------------------------------------`);
  lines.push(`+ 1 host(s) tested`);
  lines.push(`+ ${target.findings.length} item(s) reported on ${target.host}`);
  lines.push(`+ End Time:           ${new Date().toLocaleTimeString()} (Scan took 3.12 seconds)`);
  lines.push(`---------------------------------------------------------------------------`);

  return {
    sessionId: `nikto-session-${Date.now()}`,
    timestamp,
    cliCommand,
    durationSeconds: 3.12,
    target,
    rawConsoleOutput: lines.join('\n')
  };
}
