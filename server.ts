import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';

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
    let beforeCode = finding.snippet || `const API_KEY = "${finding.maskedSecret || 'sk_live_xxxx'}";`;
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
      beforeCode = finding.snippet || `const db = connect('postgres://admin:password123@db.prod:5432/main');`;
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

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '5mb' }));

  // API Health check
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', time: new Date().toISOString() });
  });

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

      // Call Gemini with a timeout promise to guarantee fast and resilient response
      const geminiCall = ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json'
        }
      });

      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Timeout de 3.5s atingido na consulta ao Gemini API')), 3500)
      );

      const response: any = await Promise.race([geminiCall, timeoutPromise]);
      const responseText = response.text?.trim();

      if (responseText) {
        try {
          const parsed = JSON.parse(responseText);
          return res.json({
            source: 'gemini',
            model: 'gemini-3.8-flash',
            timestamp: new Date().toISOString(),
            executiveSummary: parsed.executiveSummary || 'Plano de remediação gerado via Gemini 3.8 Flash.',
            totalPotentialRiskReduction: parsed.totalPotentialRiskReduction || 20,
            projectedNewRiskScore: parsed.projectedNewRiskScore || Math.max(0, currentRiskScore - 20),
            willPassQualityGate: (parsed.projectedNewRiskScore || Math.max(0, currentRiskScore - 20)) <= qualityGateLimit,
            suggestions: parsed.suggestions || [],
            actionPlan: parsed.actionPlan || []
          });
        } catch (parseErr) {
          console.warn('Falha no parse do JSON do Gemini, utilizando fallback:', parseErr);
        }
      }

      // Fallback if parsing failed
      const fallback = generateRuleBasedSuggestions(top3, currentRiskScore, qualityGateLimit);
      return res.json(fallback);
    } catch (err: any) {
      console.warn('Erro ao chamar Gemini API para mitigação, utilizando motor de contingência:', err?.message);
      const { topFindings = [], currentRiskScore = 65, qualityGateLimit = 50 } = req.body || {};
      const fallback = generateRuleBasedSuggestions(topFindings.slice(0, 3), currentRiskScore, qualityGateLimit);
      return res.json(fallback);
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
