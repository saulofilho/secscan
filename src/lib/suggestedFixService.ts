import { ScanFinding, SuggestedFixResult } from '../types';

/**
 * Extracts lines of context surrounding the vulnerable line in a file
 */
export function extractSurroundingCode(fileContent: string, line: number, contextRadius: number = 4): string {
  if (!fileContent) return '';
  const lines = fileContent.split('\n');
  const startLine = Math.max(0, line - contextRadius - 1);
  const endLine = Math.min(lines.length, line + contextRadius);

  return lines
    .slice(startLine, endLine)
    .map((l, idx) => `${startLine + idx + 1}: ${l}`)
    .join('\n');
}

/**
 * Client-side fallback generator in case network or backend API is temporarily unavailable
 */
export function generateClientFallbackFix(finding: ScanFinding, surroundingCode?: string): SuggestedFixResult {
  const ruleId = (finding.ruleId || '').toLowerCase();
  const ruleName = (finding.ruleName || '').toLowerCase();
  const category = (finding.category || '').toUpperCase();
  const snippet = finding.snippet || finding.matchedSecret || '';
  const file = finding.file || '';

  let envVarName = 'SECRET_KEY';
  if (ruleId.includes('stripe') || ruleName.includes('stripe')) {
    envVarName = 'STRIPE_SECRET_KEY';
  } else if (ruleId.includes('aws') || ruleName.includes('aws')) {
    envVarName = ruleId.includes('secret') ? 'AWS_SECRET_ACCESS_KEY' : 'AWS_ACCESS_KEY_ID';
  } else if (ruleId.includes('google') || ruleName.includes('google')) {
    envVarName = 'GOOGLE_API_KEY';
  } else if (ruleId.includes('github') || ruleName.includes('github')) {
    envVarName = 'GITHUB_TOKEN';
  } else if (ruleId.includes('slack') || ruleName.includes('slack')) {
    envVarName = ruleId.includes('webhook') ? 'SLACK_WEBHOOK_URL' : 'SLACK_BOT_TOKEN';
  } else if (ruleId.includes('jwt') || ruleName.includes('jwt')) {
    envVarName = 'JWT_SECRET';
  } else if (category.includes('DATABASE') || ruleId.includes('postgres') || ruleId.includes('mongo')) {
    envVarName = 'DATABASE_URL';
  } else if (finding.ruleId) {
    envVarName = finding.ruleId.toUpperCase().replace(/[^A-Z0-9]/g, '_');
  }

  const isTaint = category.includes('TAINT') || ruleId.includes('eval') || snippet.includes('innerHTML');
  const isSql = category.includes('SQL') || ruleId.includes('sql') || snippet.toLowerCase().includes('select *');

  let securePattern = 'Runtime Environment Injection & Fail-Fast Guard';
  let cweOwaspReference = 'CWE-798: Use of Hardcoded Credentials / OWASP A07:2021';
  let vulnerabilityType = `Exposição de Credencial Estática (${finding.ruleName})`;
  let explanation = `Substituição da credencial estática por leitura de variável de ambiente '${envVarName}' com validação obrigatória em tempo de execução.`;
  let replacementSnippet = `// 1. Carregar chave com verificação em tempo de execução\nconst ${envVarName} = process.env.${envVarName};\nif (!${envVarName}) {\n  throw new Error("FATAL: '${envVarName}' deve ser configurada nas variáveis de ambiente");\n}`;
  let beforeSnippet = snippet || `const ${envVarName} = "${finding.maskedSecret || 'DUMMY_TOKEN_PLACEHOLDER'}";`;
  let envConfig: SuggestedFixResult['envConfig'] = {
    variableName: envVarName,
    exampleLine: `${envVarName}=${finding.matchedSecret || 'sua_credencial_aqui'}`,
    instructions: `Configure ${envVarName} no arquivo .env local e nas variáveis protegidas do CI/CD.`
  };
  let checklist = [
    'Revogar e rotacionar a chave no painel do provedor.',
    'Validar que o arquivo .env está listado no .gitignore.',
    'Testar o fluxo localmente com a variável de ambiente injetada.'
  ];

  if (isTaint) {
    securePattern = 'Context-Aware Output Sanitization (CWE-79)';
    cweOwaspReference = 'CWE-79 / OWASP A03:2021-Injection';
    vulnerabilityType = 'Manipulação Perigosa de DOM (DOM XSS)';
    explanation = 'Substitui inserção direta de marcação não higienizada por textContent seguro ou higienização via DOMPurify.';
    envConfig = undefined;
    replacementSnippet = `// Opção recomendada: uso de textContent nativo seguro\nelement.textContent = userControlledInput;\n// Ou com biblioteca de sanitização:\n// import DOMPurify from 'dompurify';\n// element.innerHTML = DOMPurify.sanitize(userControlledInput);`;
    checklist = [
      'Substituir innerHTML por textContent sempre que possível.',
      'Aplicar sanitização com DOMPurify para HTML dinâmico.',
      'Habilitar Content Security Policy (CSP) no servidor.'
    ];
  } else if (isSql) {
    securePattern = 'Parameterized Prepared Statements (CWE-89)';
    cweOwaspReference = 'CWE-89 / OWASP A03:2021-Injection';
    vulnerabilityType = 'Possível Injeção SQL em Concatenação Dinâmica';
    explanation = 'Substitui interpolação de strings por placeholders parametrizados gerenciados pelo client SQL.';
    envConfig = undefined;
    replacementSnippet = `const query = 'SELECT * FROM records WHERE id = $1 AND active = $2';\nconst result = await db.query(query, [recordId, true]);`;
    checklist = [
      'Utilizar parâmetros nomeados ou posicionais ($1, ?).',
      'Nunca concatenar entradas de usuário no comando SQL.',
      'Validar tipos com schema validation (Zod/Joi) antes da consulta.'
    ];
  }

  return {
    source: 'rule_engine',
    model: 'SecScan Deterministic AppSec Engine',
    timestamp: new Date().toISOString(),
    findingId: finding.id,
    ruleName: finding.ruleName,
    vulnerabilityType,
    cweOwaspReference,
    securePattern,
    replacementSnippet,
    beforeSnippet,
    explanation,
    envConfig,
    securityChecklist: checklist,
    diff: {
      removed: beforeSnippet.split('\n').filter(Boolean),
      added: replacementSnippet.split('\n').filter(Boolean)
    }
  };
}

/**
 * Calls the backend /api/suggested-fix endpoint (which queries Gemini AI with rule-engine fallback)
 */
export async function requestSuggestedFix(
  finding: ScanFinding,
  fileContent?: string
): Promise<SuggestedFixResult> {
  const surroundingCode = fileContent ? extractSurroundingCode(fileContent, finding.line, 5) : undefined;
  const fileExtension = finding.file.split('.').pop() || '';

  try {
    const response = await fetch('/api/suggested-fix', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        finding: {
          id: finding.id,
          ruleId: finding.ruleId,
          ruleName: finding.ruleName,
          category: finding.category,
          severity: finding.severity,
          file: finding.file,
          line: finding.line,
          column: finding.column,
          snippet: finding.snippet,
          matchedSecret: finding.matchedSecret,
          maskedSecret: finding.maskedSecret,
          remediation: finding.remediation,
          description: finding.description,
          riskScore: finding.riskScore,
          entropy: finding.entropy
        },
        context: {
          surroundingCode,
          fileExtension
        }
      })
    });

    if (!response.ok) {
      console.warn(`Servidor retornou status ${response.status} em /api/suggested-fix, usando contingência local.`);
      return generateClientFallbackFix(finding, surroundingCode);
    }

    const data = await response.json();
    if (!data.replacementSnippet) {
      return generateClientFallbackFix(finding, surroundingCode);
    }

    return data as SuggestedFixResult;
  } catch (err) {
    console.warn('Exceção ao requisitar /api/suggested-fix, usando motor local:', err);
    return generateClientFallbackFix(finding, surroundingCode);
  }
}
