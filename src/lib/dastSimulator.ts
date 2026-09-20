export type AttackCategory = 
  | 'SQL_INJECTION' 
  | 'NOSQL_INJECTION' 
  | 'XSS' 
  | 'PATH_TRAVERSAL' 
  | 'SSRF' 
  | 'COMMAND_INJECTION';

export interface FuzzingPayload {
  id: string;
  category: AttackCategory;
  name: string;
  payload: string;
  targetParam: string;
  description: string;
  cwe: string;
}

export interface FuzzingTestResult {
  id: string;
  timestamp: string;
  endpoint: string;
  method: string;
  payload: FuzzingPayload;
  simulatedStatus: number;
  simulatedResponseTimeMs: number;
  responseSnippet: string;
  verdict: 'VULNERABLE' | 'BLOCKED_BY_WAF' | 'SANITIZED' | 'SAFE';
  analysis: string;
}

export interface SecurityHeaderCheck {
  header: string;
  status: 'PRESENT' | 'MISSING' | 'WEAK';
  currentValue?: string;
  recommendedValue: string;
  importance: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description: string;
  cwe: string;
}

export interface SecurityHeadersAudit {
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  score: number;
  headers: SecurityHeaderCheck[];
  recommendedMiddlewareCode: string;
}

export const BUILTIN_FUZZING_PAYLOADS: FuzzingPayload[] = [
  {
    id: 'pay-sqli-1',
    category: 'SQL_INJECTION',
    name: 'Boolean-based Blind SQLi',
    payload: "' OR '1'='1' --",
    targetParam: 'userId',
    description: 'Testa bypass de autenticação e retorno forçado de todos os registros.',
    cwe: 'CWE-89'
  },
  {
    id: 'pay-sqli-2',
    category: 'SQL_INJECTION',
    name: 'Union Based Query Extractor',
    payload: "1' UNION SELECT null, username, password FROM users --",
    targetParam: 'limit',
    description: 'Tenta exfiltrar colunas de banco via cláusula UNION em parâmetros paginados.',
    cwe: 'CWE-89'
  },
  {
    id: 'pay-nosql-1',
    category: 'NOSQL_INJECTION',
    name: 'MongoDB Operator Injection',
    payload: '{"$ne": null}',
    targetParam: 'customerEmail',
    description: 'Injeta operador $ne para burlar validação booleana em consultas Mongoose/MongoDB.',
    cwe: 'CWE-943'
  },
  {
    id: 'pay-xss-1',
    category: 'XSS',
    name: 'DOM / Reflected Script Injection',
    payload: '<script>alert(document.domain)</script>',
    targetParam: 'bioHtml',
    description: 'Verifica se a aplicação reflete tags <script> sem sanitização ou encoding HTML.',
    cwe: 'CWE-79'
  },
  {
    id: 'pay-xss-2',
    category: 'XSS',
    name: 'Event Handler Bypass Image Tag',
    payload: '"><img src=x onerror=alert(1)>',
    targetParam: 'query',
    description: 'Fecha o atributo de busca e dispara manipulador de erro onerror.',
    cwe: 'CWE-79'
  },
  {
    id: 'pay-traversal-1',
    category: 'PATH_TRAVERSAL',
    name: 'Linux /etc/passwd Extraction',
    payload: '../../../../../../etc/passwd',
    targetParam: 'filePath',
    description: 'Tenta escapar do diretório raiz para ler arquivos confidenciais do sistema operacional.',
    cwe: 'CWE-22'
  },
  {
    id: 'pay-ssrf-1',
    category: 'SSRF',
    name: 'AWS Cloud Metadata Instance API',
    payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    targetParam: 'webhookUrl',
    description: 'Tenta forçar o servidor a fazer requisição interna ao serviço de metadados da nuvem.',
    cwe: 'CWE-918'
  },
  {
    id: 'pay-cmd-1',
    category: 'COMMAND_INJECTION',
    name: 'Unix Command Concatenation',
    payload: '; cat /etc/hosts #',
    targetParam: 'format',
    description: 'Executa subcomandos no terminal bash caso o parâmetro seja concatenado em child_process.exec.',
    cwe: 'CWE-78'
  }
];

export function auditSecurityHeaders(rawHeaders: Record<string, string>): SecurityHeadersAudit {
  const checks: SecurityHeaderCheck[] = [
    {
      header: 'Content-Security-Policy',
      status: rawHeaders['content-security-policy'] ? 'PRESENT' : 'MISSING',
      currentValue: rawHeaders['content-security-policy'],
      recommendedValue: "default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none'; frame-ancestors 'none';",
      importance: 'CRITICAL',
      description: 'Mitiga ataques de Cross-Site Scripting (XSS) e injeção de dados controlando as origens permitidas de recursos.',
      cwe: 'CWE-79'
    },
    {
      header: 'Strict-Transport-Security (HSTS)',
      status: rawHeaders['strict-transport-security'] ? 'PRESENT' : 'MISSING',
      currentValue: rawHeaders['strict-transport-security'],
      recommendedValue: 'max-age=63072000; includeSubDomains; preload',
      importance: 'CRITICAL',
      description: 'Garante que os navegadores se comuniquem exclusivamente através de HTTPS protegido.',
      cwe: 'CWE-319'
    },
    {
      header: 'X-Frame-Options',
      status: rawHeaders['x-frame-options'] ? 'PRESENT' : 'MISSING',
      currentValue: rawHeaders['x-frame-options'],
      recommendedValue: 'DENY ou SAMEORIGIN',
      importance: 'HIGH',
      description: 'Protege os usuários contra ataques de Clickjacking impedindo que o site seja embutido em iframes não autorizados.',
      cwe: 'CWE-1021'
    },
    {
      header: 'X-Content-Type-Options',
      status: rawHeaders['x-content-type-options'] === 'nosniff' ? 'PRESENT' : 'MISSING',
      currentValue: rawHeaders['x-content-type-options'],
      recommendedValue: 'nosniff',
      importance: 'HIGH',
      description: 'Instrui os navegadores a não tentar adivinhar (sniff) o MIME type do conteúdo, mitigando execuções de arquivos forjados.',
      cwe: 'CWE-434'
    },
    {
      header: 'Referrer-Policy',
      status: rawHeaders['referrer-policy'] ? 'PRESENT' : 'MISSING',
      currentValue: rawHeaders['referrer-policy'],
      recommendedValue: 'strict-origin-when-cross-origin',
      importance: 'MEDIUM',
      description: 'Controla a quantidade de informações de rota passadas no cabeçalho Referer em requisições externas.',
      cwe: 'CWE-200'
    },
    {
      header: 'Permissions-Policy',
      status: rawHeaders['permissions-policy'] ? 'PRESENT' : 'MISSING',
      currentValue: rawHeaders['permissions-policy'],
      recommendedValue: 'geolocation=(), microphone=(), camera=()',
      importance: 'MEDIUM',
      description: 'Desabilita o acesso a recursos de hardware do dispositivo como microfone, câmera e geolocalização.',
      cwe: 'CWE-250'
    },
    {
      header: 'Access-Control-Allow-Origin',
      status: rawHeaders['access-control-allow-origin'] === '*' ? 'WEAK' : rawHeaders['access-control-allow-origin'] ? 'PRESENT' : 'MISSING',
      currentValue: rawHeaders['access-control-allow-origin'],
      recommendedValue: 'https://empresa.com.br (nunca curinga "*" com credenciais)',
      importance: 'HIGH',
      description: 'Configuração de CORS. Evita que qualquer domínio arbitrário na internet leia respostas autenticadas.',
      cwe: 'CWE-346'
    }
  ];

  let points = 100;
  checks.forEach(c => {
    if (c.status === 'MISSING') {
      points -= c.importance === 'CRITICAL' ? 22 : c.importance === 'HIGH' ? 14 : 8;
    } else if (c.status === 'WEAK') {
      points -= 12;
    }
  });

  const finalScore = Math.max(0, points);
  let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'F';
  if (finalScore >= 95) grade = 'A+';
  else if (finalScore >= 85) grade = 'A';
  else if (finalScore >= 70) grade = 'B';
  else if (finalScore >= 55) grade = 'C';
  else if (finalScore >= 40) grade = 'D';

  const recommendedMiddlewareCode = `// Middleware Helmet / Express para Nota A+ de Segurança
const helmet = require('helmet');

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 63072000,
      includeSubDomains: true,
      preload: true,
    },
    frameguard: { action: 'deny' },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  })
);`;

  return {
    grade,
    score: finalScore,
    headers: checks,
    recommendedMiddlewareCode
  };
}

/**
 * Simulates defensive dynamic fuzzing against an API endpoint
 */
export function simulateFuzzingTest(
  endpoint: string,
  method: string,
  payload: FuzzingPayload
): FuzzingTestResult {
  const isSensitiveOrUnprotected = endpoint.includes('admin') || endpoint.includes('refunds') || endpoint.includes('charge') || endpoint.includes('bioHtml');

  let verdict: 'VULNERABLE' | 'BLOCKED_BY_WAF' | 'SANITIZED' | 'SAFE' = 'SAFE';
  let status = 200;
  let responseSnippet = '';
  let analysis = '';

  if (payload.category === 'SQL_INJECTION') {
    if (endpoint.includes('audit-trail') || endpoint.includes('charge')) {
      verdict = 'VULNERABLE';
      status = 500;
      responseSnippet = `{"error": "QueryFailedError: syntax error at or near 'OR' at line 1", "query": "SELECT * FROM audit_logs WHERE user_id = '' OR '1'='1' --"}`;
      analysis = 'O endpoint concatenou o payload diretamente na query SQL sem parametrização. Vazamento de stack trace detectado (CWE-89).';
    } else {
      verdict = 'SANITIZED';
      status = 400;
      responseSnippet = `{"status": "error", "code": "INVALID_INPUT", "message": "Parâmetro contém caracteres proibidos."}`;
      analysis = 'Parâmetro rejeitado pelo validador de tipos.';
    }
  } else if (payload.category === 'XSS') {
    if (endpoint.includes('bioHtml') || endpoint.includes('users')) {
      verdict = 'VULNERABLE';
      status = 200;
      responseSnippet = `<div id="profile-container">${payload.payload}</div>`;
      analysis = 'A aplicação refletiu o payload HTML/JavaScript no corpo da resposta sem sanitização por DOMPurify (CWE-79).';
    } else {
      verdict = 'SANITIZED';
      status = 200;
      responseSnippet = `{"profile": "&lt;script&gt;alert(1)&lt;/script&gt;"}`;
      analysis = 'Payload encodado corretamente para HTML Entities.';
    }
  } else if (payload.category === 'SSRF') {
    verdict = 'VULNERABLE';
    status = 200;
    responseSnippet = `{"SecurityCredentials": {"AccessKeyId": "ASIA...", "SecretAccessKey": "..."}}`;
    analysis = 'O servidor executou requisição HTTP para o endpoint de metadados da AWS (169.254.169.254), expondo credenciais de instância (CWE-918).';
  } else {
    verdict = isSensitiveOrUnprotected ? 'VULNERABLE' : 'BLOCKED_BY_WAF';
    status = verdict === 'VULNERABLE' ? 500 : 403;
    responseSnippet = verdict === 'VULNERABLE'
      ? `{"status": "failure", "details": "Comando '${payload.payload}' executado com status 0"}`
      : `<html><head><title>403 Forbidden</title></head><body><h1>Request blocked by ModSecurity WAF Rule #941100</h1></body></html>`;
    analysis = verdict === 'VULNERABLE'
      ? 'Comando executado no sistema operacional do servidor (CWE-78).'
      : 'Requisição interceptada e bloqueada pelo Web Application Firewall (WAF).';
  }

  return {
    id: `fuzz-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
    timestamp: new Date().toLocaleTimeString(),
    endpoint,
    method,
    payload,
    simulatedStatus: status,
    simulatedResponseTimeMs: Math.floor(Math.random() * 120) + 15,
    responseSnippet,
    verdict,
    analysis
  };
}
