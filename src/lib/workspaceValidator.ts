/**
 * Workspace Validator & Pre-Flight Ingestion Guard
 * 
 * Validates files and raw code before they are added to the in-memory scanning workspace.
 * Prevents accidental inclusion of sensitive environment files (.env), private keys,
 * or raw live production credentials.
 */

export interface SensitivePatternFinding {
  patternId: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'WARNING';
  description: string;
  matchedPreview: string;
  line: number;
  remediation: string;
  securityImpact?: string;
}

export interface WorkspaceValidationResult {
  isValid: boolean;
  isForbiddenFile: boolean;
  fileName: string;
  blockedReason?: string;
  findings: SensitivePatternFinding[];
  hasBlockers: boolean;
  hasWarnings: boolean;
}

// Patterns that indicate forbidden files that must NEVER be added to the workspace
const FORBIDDEN_FILE_PATTERNS: Array<{ regex: RegExp; reason: string }> = [
  {
    regex: /^\.?env(\..+)?$/i,
    reason: 'Arquivos de variáveis de ambiente (.env) contêm segredos e não devem ser enviados ao workspace ou versionados.'
  },
  {
    regex: /\.(pem|key|pkcs12|pfx|keystore)$/i,
    reason: 'Arquivos de chave criptográfica privada (.pem, .key) não devem ser importados no navegador.'
  },
  {
    regex: /^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i,
    reason: 'Chaves de identidade SSH locais não devem ser expostas.'
  },
  {
    regex: /(credentials|service[-_]?account|google[-_]?services)\.json$/i,
    reason: 'Arquivos de credenciais de serviço em nuvem contêm chaves mestras e não podem ser adicionados.'
  }
];

// Patterns for detecting real, non-placeholder secrets in file content
const SENSITIVE_CONTENT_PATTERNS: Array<{
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'WARNING';
  regex: RegExp;
  description: string;
  remediation: string;
  securityImpact: string;
  isPlaceholder?: (match: string) => boolean;
}> = [
  {
    id: 'stripe-live-secret',
    name: 'Stripe Live Secret Key',
    severity: 'CRITICAL',
    regex: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,99}\b/g,
    description: 'Chave de API de produção do Stripe detectada.',
    remediation: 'Rotacione a chave no painel do Stripe imediatamente e utilize variáveis de ambiente no servidor.',
    securityImpact: 'Allows unauthorized API access & payment charge execution',
    isPlaceholder: (m) => /dummy|example|placeholder|test/i.test(m)
  },
  {
    id: 'stripe-webhook-secret',
    name: 'Stripe Webhook Signing Secret',
    severity: 'CRITICAL',
    regex: /\bwhsec_[0-9a-zA-Z]{32,99}\b/g,
    description: 'Assinatura secreta de Webhook do Stripe detectada.',
    remediation: 'Substitua por um placeholder antes de salvar o código.',
    securityImpact: 'Enables webhook signature forgery & balance spoofing',
    isPlaceholder: (m) => /dummy|example|placeholder|test|replace/i.test(m)
  },
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    severity: 'CRITICAL',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    description: 'Identificador de acesso da AWS exposto.',
    remediation: 'Invalide as credenciais no IAM da AWS e utilize IAM Roles.',
    securityImpact: 'Credentials exposure risk & cloud infrastructure takeover',
    isPlaceholder: (m) => /EXAMPLE/i.test(m)
  },
  {
    id: 'github-pat',
    name: 'GitHub Personal Access Token',
    severity: 'CRITICAL',
    regex: /\b(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b/g,
    description: 'Token de acesso pessoal do GitHub exposto.',
    remediation: 'Revogue o token no GitHub Settings > Developer settings > Personal access tokens.',
    securityImpact: 'Allows unauthorized repository & CI/CD pipeline access',
    isPlaceholder: (m) => /dummy|example|placeholder/i.test(m)
  },
  {
    id: 'private-rsa-key',
    name: 'Private RSA / OpenSSH Key Block',
    severity: 'CRITICAL',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    description: 'Bloco de chave privada assimétrica em texto simples.',
    remediation: 'Remova a chave privada do código e utilize gerenciador de segredos.',
    securityImpact: 'Credentials exposure risk & server decrypt/SSH compromise',
  },
  {
    id: 'slack-webhook',
    name: 'Slack Incoming Webhook URL',
    severity: 'HIGH',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z]{8,12}\/B[0-9A-Za-z]{8,12}\/[0-9A-Za-z]{24}/g,
    description: 'Webhook de canal do Slack exposto.',
    remediation: 'Regenere a URL do webhook no portal do Slack Apps.',
    securityImpact: 'Allows unauthorized internal messaging & channel phishing',
    isPlaceholder: (m) => /abcdefghijklmnopqrstuvwx/i.test(m)
  }
];

/**
 * Resolves the security impact explanation for any given sensitive pattern finding
 */
export function resolveSecurityImpact(finding: { patternId?: string; name?: string; severity?: string; securityImpact?: string }): string {
  if (finding.securityImpact && finding.securityImpact.trim().length > 0) {
    return finding.securityImpact;
  }

  const id = (finding.patternId || '').toLowerCase();
  const name = (finding.name || '').toLowerCase();

  if (id === 'stripe-live-secret' || name.includes('stripe live')) {
    return 'Allows unauthorized API access & payment charge execution';
  }
  if (id === 'stripe-webhook-secret' || name.includes('webhook')) {
    return 'Enables webhook signature forgery & balance spoofing';
  }
  if (id === 'aws-access-key' || id.includes('aws') || name.includes('aws')) {
    return 'Credentials exposure risk & cloud infrastructure takeover';
  }
  if (id === 'github-pat' || id.includes('github') || name.includes('github')) {
    return 'Allows unauthorized repository & CI/CD pipeline access';
  }
  if (id === 'private-rsa-key' || id.includes('rsa') || id.includes('ssh') || name.includes('private key')) {
    return 'Credentials exposure risk & server decrypt/SSH compromise';
  }
  if (id === 'slack-webhook' || id.includes('slack')) {
    return 'Allows unauthorized internal messaging & channel phishing';
  }
  if (id === 'forbidden-filename' || id.includes('env') || name.includes('bloqueado') || name.includes('forbidden')) {
    return 'Credentials exposure risk (Master environment keys & private certificates)';
  }

  // Common pattern categories
  if (id.includes('token') || name.includes('token') || id.includes('jwt')) {
    return 'Allows unauthorized API access & session hijacking';
  }
  if (id.includes('password') || name.includes('password') || id.includes('pass')) {
    return 'Credentials exposure risk & unauthorized authentication';
  }
  if (id.includes('db') || id.includes('database') || name.includes('database')) {
    return 'Credentials exposure risk & direct database compromise';
  }
  if (id.includes('key') || name.includes('key') || id.includes('secret')) {
    return 'Allows unauthorized API access & service impersonation';
  }

  return finding.severity === 'CRITICAL'
    ? 'Credentials exposure risk'
    : 'Allows unauthorized API access';
}

/**
 * Checks if a filename matches forbidden workspace file types (.env, keys, etc.)
 */
export function isForbiddenWorkspaceFile(fileName: string): { isForbidden: boolean; reason?: string } {
  const cleanName = fileName.trim().split(/[/\\]/).pop() || fileName.trim();

  for (const item of FORBIDDEN_FILE_PATTERNS) {
    if (item.regex.test(cleanName)) {
      return {
        isForbidden: true,
        reason: item.reason
      };
    }
  }

  return { isForbidden: false };
}

/**
 * Validates a file's name and its text content for sensitive patterns
 * before allowing it to be imported into the workspace.
 */
export function validateFileForSensitivePatterns(fileName: string, content: string): WorkspaceValidationResult {
  const forbiddenCheck = isForbiddenWorkspaceFile(fileName);

  if (forbiddenCheck.isForbidden) {
    return {
      isValid: false,
      isForbiddenFile: true,
      fileName,
      blockedReason: forbiddenCheck.reason,
      findings: [
        {
          patternId: 'forbidden-filename',
          name: 'Arquivo Bloqueado',
          severity: 'CRITICAL',
          description: forbiddenCheck.reason || 'Tipo de arquivo restrito.',
          matchedPreview: fileName,
          line: 1,
          remediation: 'Não envie arquivos de configuração de ambiente (.env) ou chaves privadas.',
          securityImpact: 'Credentials exposure risk (Master environment keys & private certificates)'
        }
      ],
      hasBlockers: true,
      hasWarnings: false
    };
  }

  const findings: SensitivePatternFinding[] = [];
  const lines = content.split('\n');

  for (const pattern of SENSITIVE_CONTENT_PATTERNS) {
    // Reset regex state
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.regex.exec(content)) !== null) {
      const matchedString = match[0];
      
      // Skip known dummy/placeholder markers
      if (pattern.isPlaceholder && pattern.isPlaceholder(matchedString)) {
        continue;
      }

      // Find line number
      const matchIndex = match.index;
      let charCount = 0;
      let lineNum = 1;

      for (let i = 0; i < lines.length; i++) {
        charCount += lines[i].length + 1;
        if (charCount > matchIndex) {
          lineNum = i + 1;
          break;
        }
      }

      // Obfuscate preview (show first 6 and last 4 characters)
      const preview = matchedString.length > 14
        ? `${matchedString.slice(0, 6)}...${matchedString.slice(-4)}`
        : `${matchedString.slice(0, 3)}***`;

      findings.push({
        patternId: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        matchedPreview: preview,
        line: lineNum,
        remediation: pattern.remediation,
        securityImpact: pattern.securityImpact || resolveSecurityImpact(pattern)
      });

      // Avoid infinite loop if regex is zero-width
      if (match.index === pattern.regex.lastIndex) {
        pattern.regex.lastIndex++;
      }
    }
  }

  const hasBlockers = findings.some(f => f.severity === 'CRITICAL');
  const hasWarnings = findings.length > 0;

  return {
    isValid: !hasBlockers,
    isForbiddenFile: false,
    fileName,
    findings,
    hasBlockers,
    hasWarnings
  };
}

/**
 * Replaces live secrets with safe dummy placeholders
 */
export function sanitizeSensitiveContent(content: string): string {
  let sanitized = content;

  sanitized = sanitized.replace(/\b(?:sk|rk)_live_[0-9a-zA-Z]{24,99}\b/g, 'PLACEHOLDER_STRIPE_SECRET_KEY');
  sanitized = sanitized.replace(/\bwhsec_[0-9a-zA-Z]{32,99}\b/g, 'DUMMY_WEBHOOK_SECRET_PLACEHOLDER');
  sanitized = sanitized.replace(/\bAKIA[0-9A-Z]{16}\b/g, 'DUMMY_AWS_ACCESS_KEY');
  sanitized = sanitized.replace(/\bghp_[0-9a-zA-Z]{36}\b/g, 'DUMMY_GITHUB_PAT_TOKEN');
  sanitized = sanitized.replace(/\bgithub_pat_[0-9a-zA-Z_]{82}\b/g, 'DUMMY_GITHUB_PAT_TOKEN');

  return sanitized;
}
