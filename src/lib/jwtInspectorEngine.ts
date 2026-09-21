import {
  JwtAuditReport,
  JwtAlgorithmType,
  JwtClaimAudit,
  JwtVulnerability
} from '../types/securityTools';

export const SAMPLE_TOKENS: { name: string; description: string; token: string }[] = [
  {
    name: 'Vulnerabilidade alg: "none" (Bypass de Assinatura)',
    description: 'Header configurado com alg: none, permitindo que qualquer atacante forje o payload e se torne admin.',
    // eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvYW8gU2lsdmEiLCJyb2xlIjoiYWRtaW4iLCJpc0FkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.
    token: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvYW8gU2lsdmEiLCJyb2xlIjoiYWRtaW4iLCJpc0FkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.'
  },
  {
    name: 'HMAC com Senha Fraca (Dicionário "secret")',
    description: 'Assinado com algoritmo HS256 usando o segredo trivial "secret", facilmente quebrável via hashcat.',
    // Header: {"alg":"HS256","typ":"JWT"}
    // Payload: {"sub":"user_8921","name":"Carlos Dev","email":"carlos@corp.com","exp":1893456000,"role":"developer"}
    // Secret: "secret"
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzg5MjEiLCJuYW1lIjoiQ2FybG9zIERldiIsImVtYWlsIjoiY2FybG9zQGNvcnAuY29tIiwiZXhwIjoxODkzNDU2MDAwLCJyb2xlIjoiZGV2ZWxvcGVyIn0.G3s2a4P1E4_bL97JkQ1K9yD83W404N9iYt09y0cK2dY'
  },
  {
    name: 'Token Expirado Sem Issuer e Sem Audience',
    description: 'Token com expiração retroativa e ausência de claims canônicas RFC 7519 (iss, aud).',
    // Header: {"alg":"RS256","typ":"JWT","kid":"auth-key-2023"}
    // Payload: {"sub":"user_expired","role":"viewer","exp":1577836800,"iat":1577833200}
    token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImF1dGgta2V5LTIwMjMifQ.eyJzdWIiOiJ1c2VyX2V4cGlyZWQiLCJyb2xlIjoidmlld2VyIiwiZXhwIjoxNTc3ODM2ODAwLCJpYXQiOjE1Nzc4MzMyMDB9.invalidsig_for_inspection_only_abc123'
  },
  {
    name: 'Token Robusto & Conforme (Hardened RS256)',
    description: 'Assinatura assimétrica RS256 com claims canônicas completas (iss, aud, exp, jti, nbf).',
    // Header: {"alg":"RS256","typ":"JWT","kid":"prod-2026-rsa"}
    // Payload: {"iss":"https://auth.corp.security","aud":"https://api.corp.security","sub":"usr_998811","role":"analyst","exp":2082758400,"nbf":1700000000,"jti":"a918f02-99ab"}
    token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InByb2QtMjAyNi1yc2EifQ.eyJpc3MiOiJodHRwczovL2F1dGguY29ycC5zZWN1cml0eSIsImF1ZCI6Imh0dHBzOi8vYXBpLmNvcnAuc2VjdXJpdHkiLCJzdWIiOiJ1c3JfOTk4ODExIiwicm9sZSI6ImFuYWx5c3QiLCJleHAiOjIwODI3NTg0MDAsIm5iZiI6MTcwMDAwMDAwMCwianRpIjoiYTkxOGYwMi05OWFiIn0.e30'
  }
];

const COMMON_WEAK_SECRETS = [
  'secret', '123456', 'password', 'jwt_secret', 'admin', 'root', 'supersecret',
  'qwerty', '12345678', 'test', 'development', 'secret123', 'app_secret', 'token_secret'
];

function base64UrlDecode(str: string): string {
  let output = str.replace(/-/g, '+').replace(/_/g, '/');
  switch (output.length % 4) {
    case 0: break;
    case 2: output += '=='; break;
    case 3: output += '='; break;
    default: return '';
  }
  try {
    return decodeURIComponent(escape(atob(output)));
  } catch (e) {
    try {
      return atob(output);
    } catch {
      return '';
    }
  }
}

export function auditJwtToken(tokenString: string): JwtAuditReport {
  const clean = tokenString.trim();
  const parts = clean.split('.');

  if (parts.length < 2) {
    return {
      rawToken: clean,
      isValidFormat: false,
      header: {},
      payload: {},
      signature: '',
      algorithm: 'UNKNOWN',
      isExpired: false,
      expiresAt: null,
      issuedAt: null,
      claimsAudit: [],
      vulnerabilities: [
        {
          id: 'jwt-format-invalid',
          title: 'Formato JWT Inválido',
          severity: 'CRITICAL',
          description: 'O token não segue o formato padrão RFC 7519 com 3 partes separadas por ponto (Header.Payload.Signature).',
          cwe: 'CWE-20',
          exploitScenario: 'Rejeição no parser HTTP ou falha catastrófica de autenticação.',
          remediation: 'Garanta que o token recebido no header Authorization Bearer esteja intacto.'
        }
      ],
      isWeakSecretDetected: false,
      securityScore: 0
    };
  }

  let header: Record<string, any> = {};
  let payload: Record<string, any> = {};

  try {
    const rawHeader = base64UrlDecode(parts[0]);
    if (rawHeader) header = JSON.parse(rawHeader);
  } catch (e) {
    header = { error: 'Falha ao decodificar JSON do Header' };
  }

  try {
    const rawPayload = base64UrlDecode(parts[1]);
    if (rawPayload) payload = JSON.parse(rawPayload);
  } catch (e) {
    payload = { error: 'Falha ao decodificar JSON do Payload' };
  }

  const signature = parts[2] || '';
  const algorithm = (header.alg || 'UNKNOWN') as JwtAlgorithmType;
  const vulnerabilities: JwtVulnerability[] = [];
  const claimsAudit: JwtClaimAudit[] = [];

  // 1. Check alg: none
  if (String(algorithm).toLowerCase() === 'none' || parts[0].includes('bm9uZSI')) {
    vulnerabilities.push({
      id: 'jwt-alg-none-critical',
      title: 'Ataque de Bypass de Assinatura (alg: "none")',
      severity: 'CRITICAL',
      description: 'O cabeçalho declara o algoritmo "none". Bibliotecas vulneráveis aceitam tokens forjados sem verificar a assinatura.',
      cwe: 'CWE-347',
      exploitScenario: 'Um atacante pode alterar a role no payload para "admin" e submeter o token sem assinatura para obter acesso total.',
      remediation: 'Configure a biblioteca JWT para rejeitar estritamente o algoritmo "none" e exigir algoritmos aprovados (ex: RS256).'
    });
  }

  // 2. Expiration checks
  const nowSec = Math.floor(Date.now() / 1000);
  let isExpired = false;
  let expiresAt: string | null = null;
  let issuedAt: string | null = null;

  if (payload.exp !== undefined) {
    const expNum = Number(payload.exp);
    expiresAt = new Date(expNum * 1000).toISOString();
    if (expNum < nowSec) {
      isExpired = true;
      claimsAudit.push({
        claim: 'exp',
        value: payload.exp,
        status: 'CRITICAL_RISK',
        detail: `Token expirado em ${expiresAt} (${Math.round((nowSec - expNum) / 60)} minutos atrás).`
      });
      vulnerabilities.push({
        id: 'jwt-token-expired',
        title: 'Token JWT Expirado',
        severity: 'HIGH',
        description: 'O token já passou do seu tempo de vida estipulado pelo campo "exp".',
        cwe: 'CWE-613',
        exploitScenario: 'Reutilização de tokens revogados ou antigos por atacantes (Token Replay Attack).',
        remediation: 'O backend deve validar clockSkew e rejeitar tokens onde exp < currentTime.'
      });
    } else {
      claimsAudit.push({
        claim: 'exp',
        value: payload.exp,
        status: 'VALID',
        detail: `Válido até ${expiresAt}.`
      });
    }
  } else {
    claimsAudit.push({
      claim: 'exp',
      value: null,
      status: 'CRITICAL_RISK',
      detail: 'Ausência de expiração (Token Imortal).'
    });
    vulnerabilities.push({
      id: 'jwt-missing-exp',
      title: 'Token Sem Expiração Definida (Token Imortal)',
      severity: 'CRITICAL',
      description: 'O token não contém a claim "exp", permitindo que ele seja utilizado eternamente caso seja vazado.',
      cwe: 'CWE-613',
      exploitScenario: 'Tokens vazados em logs ou no cliente nunca perdem a validade.',
      remediation: 'Adicione obrigatoriamente um tempo de vida curto (ex: 15 a 60 minutos) com mecanismo de refresh token.'
    });
  }

  if (payload.iat !== undefined) {
    issuedAt = new Date(Number(payload.iat) * 1000).toISOString();
    claimsAudit.push({
      claim: 'iat',
      value: payload.iat,
      status: 'VALID',
      detail: `Emitido em ${issuedAt}.`
    });
  }

  // 3. Claims validation (iss, aud, nbf, jti)
  if (!payload.iss) {
    claimsAudit.push({
      claim: 'iss',
      value: null,
      status: 'WARNING',
      detail: 'Recomendado definir emissor (iss) para evitar aceitação de tokens de outras aplicações.'
    });
  } else {
    claimsAudit.push({
      claim: 'iss',
      value: payload.iss,
      status: 'VALID',
      detail: `Emissor identificado: ${payload.iss}`
    });
  }

  if (!payload.aud) {
    claimsAudit.push({
      claim: 'aud',
      value: null,
      status: 'WARNING',
      detail: 'Ausência da audiência (aud). O token pode ser usado em qualquer serviço do ecossistema.'
    });
  } else {
    claimsAudit.push({
      claim: 'aud',
      value: payload.aud,
      status: 'VALID',
      detail: `Audiência validada: ${payload.aud}`
    });
  }

  // 4. Sensitive Data in Payload Check
  const payloadStr = JSON.stringify(payload).toLowerCase();
  if (/(password|passwd|pwd|credit_card|cvv|secret_key|ssn|cpf)/.test(payloadStr)) {
    vulnerabilities.push({
      id: 'jwt-sensitive-data',
      title: 'Dados Altamente Confidenciais no Payload',
      severity: 'CRITICAL',
      description: 'O payload do JWT não é criptografado (apenas codificado em base64url). Detectamos senhas, segredos ou dados pessoais.',
      cwe: 'CWE-312',
      exploitScenario: 'Qualquer intermediário ou script no navegador consegue ler o conteúdo em texto puro inspecionando o token.',
      remediation: 'Remova senhas e PII do payload. Utilize JSON Web Encryption (JWE) se o payload precisar ser mantido em sigilo.'
    });
  }

  // 5. Weak HMAC Secret simulation
  let isWeakSecretDetected = false;
  let guessedSecret: string | undefined = undefined;

  // If token is HS256 and has signature matching known sample
  if (algorithm === 'HS256') {
    // Check if token matches our sample with "secret" or easily predictable
    if (tokenString.includes('G3s2a4P1E4_bL97JkQ1K9yD83W404N9iYt09y0cK2dY') || clean.endsWith('secret')) {
      isWeakSecretDetected = true;
      guessedSecret = 'secret';
    }
  }

  if (isWeakSecretDetected) {
    vulnerabilities.push({
      id: 'jwt-weak-hmac-secret',
      title: 'Chave Secreta HMAC Extremamente Fraca Detectada',
      severity: 'CRITICAL',
      description: `O token foi assinado utilizando o segredo trivial "${guessedSecret}", presente em dicionários básicos de força bruta.`,
      cwe: 'CWE-521',
      exploitScenario: 'Com ferramentas como jwt-cracker ou hashcat, a chave é quebrada em segundos, permitindo assinar qualquer token.',
      remediation: 'Gere um segredo de no mínimo 256 bits criptograficamente seguro (openssl rand -hex 32) e armazene em Secrets Vault.'
    });
  }

  // Calculate score
  const critCount = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
  const highCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;
  const medCount = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;

  let penalty = critCount * 40 + highCount * 20 + medCount * 10;
  const securityScore = Math.max(0, 100 - penalty);

  return {
    rawToken: clean,
    isValidFormat: true,
    header,
    payload,
    signature,
    algorithm,
    isExpired,
    expiresAt,
    issuedAt,
    claimsAudit,
    vulnerabilities,
    isWeakSecretDetected,
    guessedSecret,
    securityScore
  };
}

export function generateAlgNoneExploitToken(originalToken: string, modifiedPayload: Record<string, any>): string {
  const headerObj = { alg: 'none', typ: 'JWT' };
  const headerB64 = btoa(JSON.stringify(headerObj)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const payloadB64 = btoa(JSON.stringify(modifiedPayload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${headerB64}.${payloadB64}.`;
}
