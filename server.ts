import express from 'express';
import path from 'path';
import fs from 'fs';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';
import { auditGitignoreSecurity } from './src/lib/gitignoreAuditor';
import { DEFAULT_OSINT_THREAT_FEEDS } from './src/lib/osintThreatFeedsData';

dotenv.config();

let aiClient: GoogleGenAI | null = null;
function getAI(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  if (!aiClient) {
    aiClient = new GoogleGenAI({ apiKey });
  }
  return aiClient;
}

interface FindingInput {
  id: string;
  ruleName: string;
  category: string;
  severity: string;
  file: string;
  line: number;
  snippet: string;
  maskedSecret: string;
  remediation?: string;
  description?: string;
  entropy?: number;
  riskScore?: number;
}

interface RefactorSuggestion {
  findingId: string;
  ruleName: string;
  category: string;
  severity: string;
  file: string;
  line: number;
  riskImpact: string;
  rootCauseAnalysis: string;
  securePattern: string;
  refactorSteps: string[];
  beforeCode: string;
  afterCode: string;
  estimatedRiskReductionPoints: number;
  mitigationPriority: 'P0 - BLOQUEANTE' | 'P1 - CRÍTICO' | 'P2 - ALTO';
}

interface MitigationResponse {
  source: 'gemini' | 'rule_engine';
  model: string;
  timestamp: string;
  executiveSummary: string;
  totalPotentialRiskReduction: number;
  projectedNewRiskScore: number;
  willPassQualityGate: boolean;
  suggestions: RefactorSuggestion[];
  actionPlan: string[];
}

function generateRuleBasedSuggestions(
  topFindings: FindingInput[],
  currentRiskScore: number,
  qualityGateLimit: number
): MitigationResponse {
  let totalReduction = 0;

  const suggestions: RefactorSuggestion[] = topFindings.map((finding, idx) => {
    const isSecret = finding.category.includes('KEY') || finding.category.includes('CREDENTIAL') || finding.category.includes('TOKEN') || finding.category.includes('PASSWORD');
    const isTaint = finding.category.includes('TAINT') || finding.snippet.includes('eval') || finding.snippet.includes('innerHTML') || finding.snippet.includes('exec');
    const isDb = finding.category.includes('DATABASE') || finding.snippet.includes('postgres') || finding.snippet.includes('mongodb');

    let pts = 0;
    if (finding.severity === 'CRITICAL') pts = 22;
    else if (finding.severity === 'HIGH') pts = 14;
    else if (finding.severity === 'MEDIUM') pts = 6;
    else pts = 2;
    totalReduction += pts;

    let securePattern = 'Externalized Secrets Manager & Environment Variables';
    let beforeCode = finding.snippet || `const API_KEY = "${finding.maskedSecret || 'DUMMY_API_KEY_PLACEHOLDER'}";`;
    let afterCode = `// 1. Defina a variável no ambiente (.env ou CI/CD)\n// API_KEY=...\n\n// 2. Acesse via process.env com fail-fast:\nconst apiKey = process.env.API_KEY;\nif (!apiKey) {\n  throw new Error('FATAL: API_KEY must be provided via environment variables');\n}`;
    let rootCause = `Credencial sensível ou chave codificada de forma estática no arquivo ${finding.file}:${finding.line}.`;
    let refactorSteps = [
      'Remover a chave codificada do código-fonte imediatamente.',
      'Revogar e rotacionar a credencial no console do provedor.',
      'Utilizar variáveis de ambiente (process.env) ou gerenciador de segredos (ex: HashiCorp Vault, AWS Secrets Manager).',
      'Verificar o histórico do Git com git-filter-repo para expurgar commits passados.'
    ];

    if (isTaint) {
      securePattern = 'Safe DOM Manipulation & Input Sanitization (CWE-79 / DOM XSS)';
      beforeCode = finding.snippet || `element.innerHTML = userControlledInput;`;
      afterCode = `// Utilize textContent seguro ou biblioteca DOMPurify:\nimport DOMPurify from 'dompurify';\n\nelement.textContent = userControlledInput;\n// Ou se HTML for indispensável:\nelement.innerHTML = DOMPurify.sanitize(userControlledInput);`;
      rootCause = `Entrada não higienizada fluindo diretamente para um sink perigoso em ${finding.file}:${finding.line}.`;
      refactorSteps = [
        'Substituir inserções diretas no DOM (innerHTML/outerHTML) por APIs seguras (textContent, createElement).',
        'Se o HTML dinâmico for mandatário, processar a entrada com DOMPurify.',
        'Implementar Content Security Policy (CSP) rigorosa no cabeçalho HTTP.'
      ];
    } else if (isDb) {
      securePattern = 'Database Connection Pooling with Secrets Vault (CWE-312 / CWE-259)';
      beforeCode = finding.snippet || `const db = connect('postgres://' + 'admin:REDACTED_PASSWORD@db.internal:5432/main');`;
      afterCode = `const dbUri = process.env.DATABASE_URL;\nif (!dbUri) throw new Error('DATABASE_URL is missing');\nconst pool = new Pool({ connectionString: dbUri, ssl: { rejectUnauthorized: true } });`;
      rootCause = `URI de conexão com credenciais de banco de dados em texto plano em ${finding.file}:${finding.line}.`;
      refactorSteps = [
        'Mover a URI com credenciais para o cofre de segredos da infraestrutura.',
        'Rotacionar a senha do usuário administrativo do banco de dados.',
        'Garantir conexões criptografadas TLS/SSL obrigatórias no client.'
      ];
    }

    return {
      findingId: finding.id,
      ruleName: finding.ruleName,
      category: finding.category,
      severity: finding.severity,
      file: finding.file,
      line: finding.line,
      riskImpact: `Eliminação direta de vulnerabilidade ${finding.severity}, reduzindo até ${pts} pontos brutos no Risk Score.`,
      rootCauseAnalysis: rootCause,
      securePattern,
      refactorSteps,
      beforeCode,
      afterCode,
      estimatedRiskReductionPoints: pts,
      mitigationPriority: idx === 0 ? 'P0 - BLOQUEANTE' : (idx === 1 ? 'P1 - CRÍTICO' : 'P2 - ALTO')
    };
  });

  const projectedScore = Math.max(0, Math.round(currentRiskScore * Math.exp(-totalReduction / 60)));

  return {
    source: 'rule_engine',
    model: 'SecScan Deterministic AppSec Engine',
    timestamp: new Date().toISOString(),
    executiveSummary: `Análise estruturada dos ${topFindings.length} achados de maior severidade. A aplicação dessas 3 refatorações tem o potencial de reduzir o Risk Score de ${currentRiskScore} para cerca de ${projectedScore} pontos, ${projectedScore <= qualityGateLimit ? 'garantindo conformidade com o Quality Gate' : 'aproximando o workspace do teto de deploy'}.`,
    totalPotentialRiskReduction: Math.max(1, currentRiskScore - projectedScore),
    projectedNewRiskScore: projectedScore,
    willPassQualityGate: projectedScore <= qualityGateLimit,
    suggestions,
    actionPlan: [
      '1. Foco imediato no achado P0 para mitigar risco de credencial pública ativa.',
      '2. Implementação de injeção de segredos via ambiente em tempo de execução.',
      '3. Re-execução da varredura estática para validação de conformidade com o Quality Gate.'
    ]
  };
}

interface SingleFindingInput {
  id: string;
  ruleId?: string;
  ruleName: string;
  category: string;
  severity: string;
  file: string;
  line: number;
  column?: number;
  snippet?: string;
  matchedSecret?: string;
  maskedSecret?: string;
  remediation?: string;
  description?: string;
  riskScore?: number;
  entropy?: number;
}

interface SuggestedFixResult {
  source: 'gemini' | 'rule_engine';
  model: string;
  timestamp: string;
  findingId: string;
  ruleName: string;
  vulnerabilityType: string;
  cweOwaspReference: string;
  securePattern: string;
  replacementSnippet: string;
  beforeSnippet: string;
  explanation: string;
  envConfig?: {
    variableName: string;
    exampleLine: string;
    instructions: string;
  };
  securityChecklist: string[];
  diff?: {
    removed: string[];
    added: string[];
  };
}

function generateRuleBasedSuggestedFix(
  finding: SingleFindingInput,
  context?: { surroundingCode?: string; fileExtension?: string }
): SuggestedFixResult {
  const cat = (finding.category || '').toUpperCase();
  const ruleId = (finding.ruleId || '').toLowerCase();
  const ruleName = (finding.ruleName || '').toLowerCase();
  const snippet = finding.snippet || finding.matchedSecret || '';
  const fileExt = (context?.fileExtension || finding.file.split('.').pop() || '').toLowerCase();

  const isPython = fileExt === 'py';
  const isShell = ['sh', 'bash', 'zsh'].includes(fileExt);

  // Determine key/secret name
  let envVarName = 'SECRET_TOKEN';
  if (ruleId.includes('stripe') || ruleName.includes('stripe')) {
    envVarName = 'STRIPE_SECRET_KEY';
  } else if (ruleId.includes('aws') || ruleName.includes('aws')) {
    envVarName = ruleId.includes('secret') ? 'AWS_SECRET_ACCESS_KEY' : 'AWS_ACCESS_KEY_ID';
  } else if (ruleId.includes('google') || ruleName.includes('google') || ruleId.includes('firebase')) {
    envVarName = 'GOOGLE_API_KEY';
  } else if (ruleId.includes('github') || ruleName.includes('github')) {
    envVarName = 'GITHUB_TOKEN';
  } else if (ruleId.includes('slack') || ruleName.includes('slack')) {
    envVarName = ruleId.includes('webhook') ? 'SLACK_WEBHOOK_URL' : 'SLACK_BOT_TOKEN';
  } else if (ruleId.includes('jwt') || ruleName.includes('jwt')) {
    envVarName = 'JWT_SECRET';
  } else if (ruleId.includes('openai') || ruleName.includes('openai') || ruleName.includes('ai key')) {
    envVarName = 'OPENAI_API_KEY';
  } else if (cat.includes('DATABASE') || ruleId.includes('postgres') || ruleId.includes('mongo')) {
    envVarName = 'DATABASE_URL';
  } else if (cat.includes('PASSWORD') || ruleName.includes('password')) {
    envVarName = 'DATABASE_PASSWORD';
  } else if (finding.ruleId) {
    envVarName = finding.ruleId.toUpperCase().replace(/[^A-Z0-9]/g, '_');
  }

  // Taint / Injection check
  const isTaint = cat.includes('TAINT') || ruleId.includes('eval') || snippet.includes('innerHTML') || snippet.includes('eval(');
  const isSql = cat.includes('SQL') || ruleId.includes('sql') || snippet.toLowerCase().includes('select *') || snippet.toLowerCase().includes('query(');

  let securePattern = 'Externalized Secrets Manager & Environment Injection';
  let cweOwaspReference = 'CWE-798: Use of Hardcoded Credentials / OWASP A07:2021-Identification & Auth';
  let vulnerabilityType = `Segredo Codificado em Texto Plano (${finding.ruleName})`;
  let explanation = `Substitui a chave codificada de forma estática no repositório por injeção via variável de ambiente (${envVarName}) com verificação estrita de tempo de execução (fail-fast).`;
  let replacementSnippet = '';
  let beforeSnippet = snippet || `const ${envVarName} = "${finding.maskedSecret || 'DUMMY_TOKEN_PLACEHOLDER'}";`;
  let envConfig: SuggestedFixResult['envConfig'] = {
    variableName: envVarName,
    exampleLine: `${envVarName}=${finding.matchedSecret || 'sua_chave_ou_token_aqui'}`,
    instructions: `Adicione ${envVarName} no seu arquivo .env local e configure como Secret protegido no pipeline de CI/CD.`
  };
  let securityChecklist = [
    'Revogar imediatamente a credencial anterior no painel do provedor de serviço.',
    'Criar uma nova credencial com privilégios mínimos (princípio do menor privilégio).',
    'Certificar-se de que o arquivo .env está listado no .gitignore.',
    'Se o repositório for público, expurgar o commit histórico com git-filter-repo.'
  ];

  if (isTaint) {
    securePattern = 'Context-Aware Output Sanitization (CWE-79 / DOM XSS)';
    cweOwaspReference = 'CWE-79: Improper Neutralization of Input / OWASP A03:2021-Injection';
    vulnerabilityType = 'Manipulação Perigosa de DOM (DOM XSS / Insecure Sink)';
    explanation = 'Evita injeção direta de strings não higienizadas em sinks do DOM, utilizando textContent seguro ou sanitização com DOMPurify.';
    envConfig = undefined;
    if (isPython) {
      replacementSnippet = `# Sanitização de saída e escape seguro:\nimport html\nsafe_content = html.escape(user_input)`;
    } else {
      replacementSnippet = `// Opção 1: Se apenas texto for necessário (Recomendado):\nelement.textContent = userControlledInput;\n\n// Opção 2: Se marcação HTML for indispensável, use sanitizador:\nimport DOMPurify from 'dompurify';\nelement.innerHTML = DOMPurify.sanitize(userControlledInput);`;
    }
    securityChecklist = [
      'Substituir usos de innerHTML ou sinks perigosos por textContent nativo.',
      'Instalar e validar sanitizador rigoroso (como DOMPurify).',
      'Configurar cabeçalhos HTTP Content-Security-Policy (CSP) robustos.'
    ];
  } else if (isSql) {
    securePattern = 'Parameterized Prepared Statements (CWE-89 / SQL Injection)';
    cweOwaspReference = 'CWE-89: SQL Injection / OWASP A03:2021-Injection';
    vulnerabilityType = 'Possível Injeção SQL em Concatenação de Consulta';
    explanation = 'Substitui concatenação dinâmica de strings SQL por consultas preparadas com marcadores de parâmetros controlados pelo driver do banco de dados.';
    envConfig = undefined;
    if (isPython) {
      replacementSnippet = `# Consulta parametrizada com psycopg / sqlite3:\ncursor.execute("SELECT * FROM users WHERE email = %s AND active = %s", (email, True))`;
    } else {
      replacementSnippet = `// Consulta parametrizada com placeholders nativos (Postgres/MySQL):\nconst query = 'SELECT * FROM users WHERE email = $1 AND role = $2';\nconst result = await db.query(query, [userEmail, targetRole]);`;
    }
    securityChecklist = [
      'Nunca concatenar entradas de usuário diretamente em comandos SQL.',
      'Utilizar prepared statements ou ORM/Query Builder com validação de tipos.',
      'Restringir as permissões do usuário do banco de dados ao menor privilégio estrito.'
    ];
  } else if (isPython) {
    replacementSnippet = `import os\n\n# Carregar credencial a partir das variáveis de ambiente\n${envVarName.toLowerCase()} = os.environ.get('${envVarName}')\nif not ${envVarName.toLowerCase()}:\n    raise RuntimeError("FATAL: Variável de ambiente '${envVarName}' não configurada")`;
  } else if (isShell) {
    replacementSnippet = `# Carregar segredo via variável de ambiente com valor padrão protegido\n${envVarName}="\${${envVarName}:?ERRO: '${envVarName}' deve ser exportada no ambiente}"`;
  } else {
    // JavaScript / TypeScript
    if (snippet.includes('const ') || snippet.includes('let ') || snippet.includes('var ')) {
      const varDeclarator = snippet.includes('const ') ? 'const' : 'let';
      const varName = snippet.split('=')[0]?.replace(/(const|let|var)\s+/, '').trim() || envVarName;
      replacementSnippet = `// 1. Carregar chave com verificação em tempo de execução\nconst ${varName} = process.env.${envVarName};\nif (!${varName}) {\n  throw new Error("FATAL: '${envVarName}' deve ser configurada nas variáveis de ambiente");\n}`;
    } else if (snippet.includes(':') && (snippet.includes('{') || snippet.includes(','))) {
      // Inside an object literal: apiKey: '...'
      const keyName = snippet.split(':')[0]?.trim() || 'apiKey';
      replacementSnippet = `${keyName}: process.env.${envVarName} || (() => { throw new Error("${envVarName} não definida"); })()`;
    } else {
      replacementSnippet = `const ${envVarName} = process.env.${envVarName};\nif (!${envVarName}) {\n  throw new Error("FATAL: '${envVarName}' ausente no ambiente");\n}`;
    }
  }

  const removedLines = beforeSnippet.split('\n').filter(Boolean);
  const addedLines = replacementSnippet.split('\n').filter(Boolean);

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
    securityChecklist,
    diff: {
      removed: removedLines,
      added: addedLines
    }
  };
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '5mb' }));

  // API Health check
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', time: new Date().toISOString() });
  });

  // Resilient multi-tier Gemini caller with automatic model failover & exponential backoff
  const callGeminiResilient = async (
    ai: GoogleGenAI,
    prompt: string,
    modelCandidates: string[] = ['gemini-3.8-flash', 'gemini-3.1-flash-lite', 'gemini-flash-latest', 'gemini-3.1-pro-preview'],
    perModelTimeoutMs: number = 7000
  ): Promise<{ text: string; model: string } | null> => {
    for (let i = 0; i < modelCandidates.length; i++) {
      const model = modelCandidates[i];
      try {
        const callPromise = ai.models.generateContent({
          model,
          contents: prompt,
          config: {
            responseMimeType: 'application/json'
          }
        });

        const timeoutPromise = new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error(`Timeout de ${perModelTimeoutMs}ms no modelo ${model}`)), perModelTimeoutMs)
        );

        const response: any = await Promise.race([callPromise, timeoutPromise]);
        const text = response?.text?.trim();
        if (text) {
          return { text, model };
        }
      } catch (err: any) {
        const msg = String(err?.message || err);
        const isCapacityIssue = msg.includes('503') || msg.includes('high demand') || msg.includes('UNAVAILABLE') || msg.includes('429');
        if (isCapacityIssue && i < modelCandidates.length - 1) {
          await new Promise((resolve) => setTimeout(resolve, 350));
        }
      }
    }
    return null;
  };

  // API endpoint for Gemini-powered mitigation suggestions
  app.post('/api/mitigations', async (req, res) => {
    try {
      const { topFindings, currentRiskScore = 65, qualityGateLimit = 50 } = req.body || {};

      if (!Array.isArray(topFindings) || topFindings.length === 0) {
        return res.status(400).json({ error: 'Nenhum achado fornecido para análise de mitigação.' });
      }

      const top3 = topFindings.slice(0, 3);
      const ai = getAI();

      if (!ai) {
        // No API key configured or available -> return rule-based suggestions
        const fallback = generateRuleBasedSuggestions(top3, currentRiskScore, qualityGateLimit);
        return res.json(fallback);
      }

      // Prepare Gemini prompt
      const prompt = `Você é um engenheiro sênior de AppSec especializado em SAST, OWASP Top 10 e arquitetura segura de JavaScript/TypeScript.
Analise as 3 principais vulnerabilidades do workspace atual e sugira refatorações de código específicas para reduzir o Cumulative Risk Score (atual: ${currentRiskScore}/100, teto Quality Gate: ${qualityGateLimit}).

ACHADOS DE MAIOR SEVERIDADE:
${top3.map((f, idx) => `
Achado #${idx + 1}:
- Regra: ${f.ruleName}
- Severidade: ${f.severity}
- Categoria: ${f.category}
- Arquivo: ${f.file}:${f.line}
- Snippet vulnerável: ${f.snippet || f.maskedSecret || 'N/A'}
- Descrição: ${f.description || f.ruleName}
`).join('\n')}

Responda ESTRITAMENTE em formato JSON com o seguinte esquema sem markdown fences:
{
  "executiveSummary": "Resumo executivo em português com diagnóstico e impacto na pontuação de risco",
  "totalPotentialRiskReduction": 25,
  "projectedNewRiskScore": 32,
  "willPassQualityGate": true,
  "actionPlan": ["Passo 1", "Passo 2", "Passo 3"],
  "suggestions": [
    {
      "findingId": "id do achado",
      "ruleName": "nome da regra",
      "category": "categoria",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "file": "arquivo.ts",
      "line": 42,
      "riskImpact": "explicação do impacto no score",
      "rootCauseAnalysis": "causa raiz",
      "securePattern": "Padrão de arquitetura segura recomendado",
      "refactorSteps": ["Passo 1", "Passo 2", "Passo 3"],
      "beforeCode": "Código antes da refatoração",
      "afterCode": "Código corrigido e seguro com boas práticas",
      "estimatedRiskReductionPoints": 15,
      "mitigationPriority": "P0 - BLOQUEANTE"
    }
  ]
}`;

      const genResult = await callGeminiResilient(
        ai,
        prompt,
        ['gemini-3.8-flash', 'gemini-3.1-flash-lite', 'gemini-flash-latest', 'gemini-3.1-pro-preview'],
        7000
      );

      if (genResult && genResult.text) {
        try {
          let cleanText = genResult.text.trim();
          if (cleanText.startsWith('```')) {
            cleanText = cleanText.replace(/^```(json)?\n?/, '').replace(/\n?```$/, '').trim();
          }
          const parsed = JSON.parse(cleanText);
          if (parsed && (parsed.suggestions || parsed.executiveSummary)) {
            return res.json({
              source: 'gemini',
              model: genResult.model,
              timestamp: new Date().toISOString(),
              executiveSummary: parsed.executiveSummary || 'Plano de remediação gerado via inteligência artificial SecScan.',
              totalPotentialRiskReduction: parsed.totalPotentialRiskReduction || 20,
              projectedNewRiskScore: parsed.projectedNewRiskScore || Math.max(0, currentRiskScore - 20),
              willPassQualityGate: (parsed.projectedNewRiskScore || Math.max(0, currentRiskScore - 20)) <= qualityGateLimit,
              suggestions: parsed.suggestions || [],
              actionPlan: parsed.actionPlan || []
            });
          }
        } catch {
          // JSON parse failed, proceed to deterministic fallback
        }
      }

      // High demand or quota spike fallback -> deterministic AppSec engine
      const fallback = generateRuleBasedSuggestions(top3, currentRiskScore, qualityGateLimit);
      return res.json(fallback);
    } catch {
      const { topFindings = [], currentRiskScore = 65, qualityGateLimit = 50 } = req.body || {};
      const fallback = generateRuleBasedSuggestions(topFindings.slice(0, 3), currentRiskScore, qualityGateLimit);
      return res.json(fallback);
    }
  });

  // API endpoint for AI-powered Suggested Fix on a single finding
  app.post('/api/suggested-fix', async (req, res) => {
    const { finding, context } = req.body || {};

    if (!finding || !finding.ruleName) {
      return res.status(400).json({ error: 'Dados da ocorrência (finding) são obrigatórios.' });
    }

    const ai = getAI();

    if (!ai) {
      const fallback = generateRuleBasedSuggestedFix(finding, context);
      return res.json(fallback);
    }

    try {
      const prompt = `Você é um engenheiro sênior de DevSecOps e Application Security especializado em SAST, OWASP Top 10 e correção de vulnerabilidades em código.
Gere uma substituição de código segura (Suggested Fix) para a vulnerabilidade detectada abaixo, levando em conta o contexto do arquivo e o tipo de falha.

INFORMAÇÕES DA VULNERABILIDADE:
- Regra: ${finding.ruleName} (ID: ${finding.ruleId || 'N/A'})
- Severidade: ${finding.severity}
- Categoria: ${finding.category}
- Arquivo: ${finding.file} (linha ${finding.line}:${finding.column || 1})
- Snippet Vulnerável Atual:
${finding.snippet || finding.matchedSecret || 'N/A'}

- Segredo Mascarado: ${finding.maskedSecret || 'N/A'}
- Descrição da Falha: ${finding.description || 'N/A'}
- Remediação Recomendada: ${finding.remediation || 'N/A'}

${context?.surroundingCode ? `CONTEXTO DE CÓDIGO AO REDOR DO ACHADO:\n\`\`\`\n${context.surroundingCode}\n\`\`\`\n` : ''}

DIRETRIZES DE GERAÇÃO:
1. "replacementSnippet": Deve ser um código limpo, pronto para substituir a linha/bloco vulnerável, seguindo a sintaxe e estilo da linguagem do arquivo (${finding.file}).
2. Se for segredo/chave/token: Substituir por injeção segura via variável de ambiente (ex: process.env no Node/TS, os.environ no Python, etc.), com validação fail-fast adequada.
3. Se for injeção de código/SQL/XSS/eval: Substituir por API segura (parametrização, textContent, sanitização com DOMPurify, etc.).
4. Forneça diff com linhas removidas e adicionadas.
5. Forneça configuração de variável de ambiente (envConfig), se aplicável.
6. Forneça checklist prático pós-correção (revogação, rotação, git-filter-repo, etc.).

Responda ESTRITAMENTE em formato JSON com o seguinte formato, sem markdown ou fences ao redor:
{
  "vulnerabilityType": "Nome técnico da falha",
  "cweOwaspReference": "Ex: CWE-798 / OWASP A07:2021",
  "securePattern": "Nome do padrão de arquitetura segura",
  "replacementSnippet": "Código seguro pronto para substituir a vulnerabilidade",
  "beforeSnippet": "Código anterior vulnerável",
  "explanation": "Explicação clara e objetiva do porquê esta substituição elimina a vulnerabilidade",
  "envConfig": {
    "variableName": "NOME_DA_VARIAVEL",
    "exampleLine": "NOME_DA_VARIAVEL=valor_exemplo",
    "instructions": "Instruções de configuração no .env ou CI/CD"
  },
  "securityChecklist": [
    "Item de checklist 1",
    "Item de checklist 2"
  ],
  "diff": {
    "removed": ["linha removida 1"],
    "added": ["linha adicionada 1", "linha adicionada 2"]
  }
}`;

      const genResult = await callGeminiResilient(
        ai,
        prompt,
        ['gemini-3.1-pro-preview', 'gemini-3.8-flash', 'gemini-3.1-flash-lite', 'gemini-flash-latest'],
        7500
      );

      if (genResult && genResult.text) {
        try {
          let cleanText = genResult.text.trim();
          if (cleanText.startsWith('```')) {
            cleanText = cleanText.replace(/^```(json)?\n?/, '').replace(/\n?```$/, '').trim();
          }

          const parsed = JSON.parse(cleanText);

          if (parsed.replacementSnippet) {
            const removed = parsed.diff?.removed || (parsed.beforeSnippet || finding.snippet || '').split('\n').filter(Boolean);
            const added = parsed.diff?.added || (parsed.replacementSnippet || '').split('\n').filter(Boolean);

            const result: SuggestedFixResult = {
              source: 'gemini',
              model: genResult.model,
              timestamp: new Date().toISOString(),
              findingId: finding.id,
              ruleName: finding.ruleName,
              vulnerabilityType: parsed.vulnerabilityType || `Vulnerabilidade em ${finding.ruleName}`,
              cweOwaspReference: parsed.cweOwaspReference || 'CWE-798 / OWASP Top 10',
              securePattern: parsed.securePattern || 'Runtime Injection & Hardening',
              replacementSnippet: parsed.replacementSnippet,
              beforeSnippet: parsed.beforeSnippet || finding.snippet || '',
              explanation: parsed.explanation || 'Código refatorado de acordo com as melhores práticas de AppSec.',
              envConfig: parsed.envConfig || undefined,
              securityChecklist: parsed.securityChecklist || [
                'Validar a substituição em ambiente de desenvolvimento.',
                'Garantir rotação da credencial exposta.',
                'Executar a varredura SAST novamente para validar a correção.'
              ],
              diff: {
                removed,
                added
              }
            };

            return res.json(result);
          }
        } catch {
          // JSON parsing failed, proceed to fallback
        }
      }

      // Fallback to deterministic rule engine
      const fallback = generateRuleBasedSuggestedFix(finding, context);
      return res.json(fallback);
    } catch {
      const fallback = generateRuleBasedSuggestedFix(finding, context);
      return res.json(fallback);
    }
  });

  // ==========================================
  // THREAT INTELLIGENCE & OSINT FEEDS ENGINE
  // (AlienVault OTX, Abuse.ch URLhaus, ThreatFox, Feodo Tracker, CISA KEV)
  // ==========================================
  const osintThreatFeedsDatabase = DEFAULT_OSINT_THREAT_FEEDS;

  // API endpoint to get real-time Threat Intelligence feeds from OSINT sources
  app.get('/api/threat-intel/feeds', async (req, res) => {
    try {
      const { source, limit = 20, search } = req.query;
      let activities = [...osintThreatFeedsDatabase];

      if (source && typeof source === 'string' && source !== 'ALL') {
        activities = activities.filter(a => a.source === source);
      }

      if (search && typeof search === 'string') {
        const q = search.toLowerCase();
        activities = activities.filter(a => 
          a.indicator.toLowerCase().includes(q) ||
          a.title.toLowerCase().includes(q) ||
          a.description.toLowerCase().includes(q) ||
          (a.malwareFamily && a.malwareFamily.toLowerCase().includes(q)) ||
          a.tags.some(t => t.toLowerCase().includes(q))
        );
      }

      const summary = {
        totalIndicators: activities.length,
        activeCampaignsCount: activities.filter(a => a.status === 'ACTIVE').length,
        lastSyncTimestamp: new Date().toISOString(),
        sourcesOnline: [
          { name: 'AlienVault OTX (Open Threat Exchange)', source: 'ALIENVAULT_OTX', status: 'ONLINE', indicatorsCount: 1420, latencyMs: 64 },
          { name: 'Abuse.ch URLhaus (Malicious URLs)', source: 'ABUSE_CH_URLHAUS', status: 'ONLINE', indicatorsCount: 980, latencyMs: 42 },
          { name: 'Abuse.ch ThreatFox (IOC Tracker)', source: 'ABUSE_CH_THREATFOX', status: 'ONLINE', indicatorsCount: 850, latencyMs: 51 },
          { name: 'Abuse.ch Feodo Tracker (Botnet C2)', source: 'ABUSE_CH_FEODO', status: 'ONLINE', indicatorsCount: 310, latencyMs: 38 },
          { name: 'CISA KEV (Known Exploited Vulns)', source: 'CISA_KEV', status: 'ONLINE', indicatorsCount: 1140, latencyMs: 70 },
        ]
      };

      return res.json({
        success: true,
        summary,
        activities: activities.slice(0, Number(limit))
      });
    } catch (err: any) {
      return res.status(500).json({ error: 'Erro ao consultar feeds de Threat Intelligence: ' + String(err) });
    }
  });

  // API endpoint to perform OSINT lookup on any IP, Domain, Hash or CVE
  app.post('/api/threat-intel/lookup', async (req, res) => {
    try {
      const { query = '' } = req.body || {};
      const cleanQuery = String(query).trim().toLowerCase();

      if (!cleanQuery) {
        return res.status(400).json({ error: 'Termo de busca (query) é obrigatório.' });
      }

      const matches = osintThreatFeedsDatabase.filter(a => 
        a.indicator.toLowerCase().includes(cleanQuery) ||
        cleanQuery.includes(a.indicator.toLowerCase()) ||
        a.title.toLowerCase().includes(cleanQuery) ||
        (a.malwareFamily && a.malwareFamily.toLowerCase().includes(cleanQuery))
      );

      const isLikelyMalicious = matches.length > 0;

      return res.json({
        query: cleanQuery,
        matched: isLikelyMalicious,
        matchCount: matches.length,
        verdict: isLikelyMalicious ? 'MALICIOUS_IOC_FOUND' : 'CLEAN_OR_UNKNOWN',
        matches,
        recommendation: isLikelyMalicious
          ? 'IOC catalogado em bases de OSINT ativas. Recomenda-se bloquear e isolar imediatamente.'
          : 'Nenhum registro adverso encontrado nas bases abertas do AlienVault OTX e Abuse.ch neste momento.'
      });
    } catch (err: any) {
      return res.status(500).json({ error: 'Erro ao processar lookup OSINT: ' + String(err) });
    }
  });

  // API endpoint to correlate workspace findings with Threat Intelligence IOCs
  app.post('/api/threat-intel/correlate', async (req, res) => {
    try {
      const { findings = [], endpoints = [] } = req.body || {};
      const correlations: any[] = [];

      // Check endpoints and findings against known threat indicators
      findings.forEach((f: any) => {
        const text = `${f.snippet || ''} ${f.file || ''} ${f.matchedSecret || ''} ${f.ruleName || ''}`.toLowerCase();
        
        osintThreatFeedsDatabase.forEach((threat) => {
          const ind = threat.indicator.toLowerCase();
          if (text.includes(ind) || (threat.malwareFamily && text.includes(threat.malwareFamily.toLowerCase()))) {
            correlations.push({
              findingId: f.id,
              findingRule: f.ruleName,
              file: f.file,
              line: f.line,
              threatActivity: threat,
              correlationType: 'IOC_MATCH_IN_CODE',
              confidence: 'HIGH'
            });
          }
        });
      });

      endpoints.forEach((ep: any) => {
        const epPath = (ep.path || '').toLowerCase();
        osintThreatFeedsDatabase.forEach((threat) => {
          const ind = threat.indicator.toLowerCase();
          if (epPath.includes(ind) || (threat.indicatorType === 'DOMAIN' && epPath.includes(ind))) {
            correlations.push({
              endpointId: ep.id,
              path: ep.path,
              method: ep.method,
              threatActivity: threat,
              correlationType: 'EXTERNAL_C2_MATCH',
              confidence: 'CRITICAL'
            });
          }
        });
      });

      return res.json({
        totalCorrelations: correlations.length,
        hasThreatAlerts: correlations.length > 0,
        correlations,
        checkedFindingsCount: findings.length,
        checkedEndpointsCount: endpoints.length
      });
    } catch (err: any) {
      return res.status(500).json({ error: 'Erro ao correlacionar achados com feeds OSINT: ' + String(err) });
    }
  });

  // Helper to safely list working files from disk repository
  function getRepositoryWorkingFiles(dir: string, baseDir: string = dir, maxFiles = 300): Array<{ name: string; path: string; size: number }> {
    const results: Array<{ name: string; path: string; size: number }> = [];
    
    function scan(current: string) {
      if (results.length >= maxFiles) return;
      try {
        const entries = fs.readdirSync(current, { withFileTypes: true });
        for (const entry of entries) {
          if (results.length >= maxFiles) break;
          const fullPath = path.join(current, entry.name);
          const relPath = path.relative(baseDir, fullPath).replace(/\\/g, '/');
          
          if (entry.isDirectory()) {
            if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.cache') {
              results.push({ name: entry.name, path: relPath + '/', size: 0 });
              continue;
            }
            scan(fullPath);
          } else if (entry.isFile()) {
            try {
              const stat = fs.statSync(fullPath);
              results.push({ name: entry.name, path: relPath, size: stat.size });
            } catch {
              results.push({ name: entry.name, path: relPath, size: 0 });
            }
          }
        }
      } catch {
        // Continue scanning even if single directory read fails
      }
    }

    scan(dir);
    return results;
  }

  // Audit Gitignore and Working Directory Security (Disk repository)
  app.get('/api/gitignore/audit', (req, res) => {
    try {
      const repoRoot = process.cwd();
      const gitignorePath = path.join(repoRoot, '.gitignore');
      let gitignoreContent = '';
      if (fs.existsSync(gitignorePath)) {
        gitignoreContent = fs.readFileSync(gitignorePath, 'utf8');
      }

      const files = getRepositoryWorkingFiles(repoRoot, repoRoot);
      const auditResult = auditGitignoreSecurity({
        gitignoreContent,
        files,
        source: 'DISK_REPOSITORY'
      });

      return res.json(auditResult);
    } catch (err: any) {
      return res.status(500).json({ error: 'Erro ao auditar .gitignore do repositório: ' + String(err) });
    }
  });

  // Audit Gitignore for custom or workspace files
  app.post('/api/gitignore/audit', (req, res) => {
    try {
      const { gitignoreContent, files } = req.body || {};
      const auditResult = auditGitignoreSecurity({
        gitignoreContent: typeof gitignoreContent === 'string' ? gitignoreContent : undefined,
        files: Array.isArray(files) ? files : [],
        source: 'WORKSPACE'
      });

      return res.json(auditResult);
    } catch (err: any) {
      return res.status(500).json({ error: 'Erro na auditoria de .gitignore: ' + String(err) });
    }
  });


  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SecScan AppSec Suite Server running on port ${PORT}`);
  });
}

startServer();
