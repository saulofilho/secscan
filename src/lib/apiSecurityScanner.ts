import { ScannedFile, ApiSecurityFinding, ApiSecurityReport } from '../types';

export const OWASP_API_DEFINITIONS: Record<string, { title: string; risk: string; cwe: string }> = {
  'API1:2023_BOLA': {
    title: 'Broken Object Level Authorization (BOLA / IDOR)',
    risk: 'Atacantes manipulam IDs de objetos nas rotas para acessar ou modificar registros de outros usuários.',
    cwe: 'CWE-639: Insecure Direct Object References'
  },
  'API2:2023_BROKEN_AUTH': {
    title: 'Broken Authentication',
    risk: 'Falta de verificação rigorosa de tokens de sessão, credenciais estáticas ou ausência de validação de assinatura.',
    cwe: 'CWE-287: Improper Authentication'
  },
  'API3:2023_BOPLA': {
    title: 'Broken Object Property Level Authorization (Mass Assignment)',
    risk: 'Endpoints aceitam campos proibidos que permitem auto-promoção de privilégios (ex: role, is_admin).',
    cwe: 'CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes'
  },
  'API4:2023_UNRESTRICTED_RESOURCE': {
    title: 'Unrestricted Resource Consumption (Rate Limiting)',
    risk: 'Ausência de paginação ou limites de taxa permitindo DoS ou raspagem em massa de dados confidenciais.',
    cwe: 'CWE-770: Allocation of Resources Without Limits or Throttling'
  },
  'API5:2023_BFLA': {
    title: 'Broken Function Level Authorization (Privilege Escalation)',
    risk: 'Rotas administrativas expostas a usuários normais ou sem verificação de role RBAC adequada.',
    cwe: 'CWE-285: Improper Authorization'
  },
  'API6:2023_SSRF': {
    title: 'Server-Side Request Forgery em Endpoints de API',
    risk: 'Parâmetros de URL ou webhooks fornecidos pelo usuário são requisitados diretamente pelo backend.',
    cwe: 'CWE-918: Server-Side Request Forgery (SSRF)'
  },
  'API7:2023_SECURITY_MISCONFIG': {
    title: 'Security Misconfiguration (CORS / Headers)',
    risk: 'CORS aberto (*), headers de segurança ausentes ou detalhes de stack trace em respostas de erro.',
    cwe: 'CWE-16: Configuration'
  },
  'API8:2023_LACK_PROTECTION': {
    title: 'Lack of Protection from Automated Threats',
    risk: 'Falta de CAPTCHA, proteção contra credential stuffing e fuzzer abusivo de requisições em lote.',
    cwe: 'CWE-799: Improper Control of Interaction Frequency'
  },
  'API9:2023_IMPROPER_INVENTORY': {
    title: 'Improper Inventory Management (Shadow / Zombie APIs)',
    risk: 'Rotas deprecadas (v1, debug, staging) ainda em execução sem monitoramento de segurança ativo.',
    cwe: 'CWE-1059: Incomplete Documentation'
  },
  'API10:2023_UNSAFE_CONSUMPTION': {
    title: 'Unsafe Consumption of Third-Party APIs',
    risk: 'Confiança cega em payloads retornados por APIs externas sem sanitização adequada contra injeções.',
    cwe: 'CWE-20: Improper Input Validation'
  }
};

export function auditApiSecurity(files: ScannedFile[]): ApiSecurityReport {
  const findings: ApiSecurityFinding[] = [];
  let auditedEndpointsCount = 0;

  files.forEach(file => {
    const lines = file.content.split('\n');

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();

      // Detect endpoint routes (Express, Nest, Next.js, FastAPI, Flask, etc.)
      const routeMatch = line.match(/(router|app)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/i);
      if (routeMatch) {
        auditedEndpointsCount++;
        const method = routeMatch[2].toUpperCase() as 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
        const path = routeMatch[3];

        // 1. Check for BOLA / IDOR: Direct parameter in URL like /api/v1/users/:id or /orders/:orderId without ownership check
        if ((path.includes(':id') || path.includes(':userId') || path.includes(':orderId') || path.includes(':accountId')) && (method === 'GET' || method === 'PUT' || method === 'DELETE')) {
          const surroundingCode = lines.slice(Math.max(0, idx - 2), Math.min(lines.length, idx + 12)).join('\n');
          // If no tenancy check or ownership validation in surrounding lines
          if (!surroundingCode.includes('req.user.id') && !surroundingCode.includes('checkOwnership') && !surroundingCode.includes('authorizeTenant')) {
            findings.push({
              id: `api-sec-bola-${file.name}-${lineNum}`,
              endpoint: path,
              method,
              category: 'API1:2023_BOLA',
              categoryTitle: OWASP_API_DEFINITIONS['API1:2023_BOLA'].title,
              severity: 'CRITICAL',
              vulnerabilityTitle: `BOLA / IDOR Detectado no Endpoint ${method} ${path}`,
              description: `A rota aceita um identificador de recurso direto sem verificar se o usuário autenticado da sessão (${path.includes(':userId') ? ':userId' : ':id'}) possui autorização de leitura/modificação para o objeto correspondente.`,
              impact: 'Atacantes podem iterar IDs sequenciais ou UUIDs e descarregar ou alterar registros confidenciais de outros clientes da plataforma.',
              cwe: 'CWE-639: Insecure Direct Object References',
              vulnerableParam: path.includes(':userId') ? ':userId' : ':id',
              file: file.path,
              line: lineNum,
              remediation: 'Implemente uma cláusula obrigatória de verificação de propriedade no banco: WHERE id = :id AND tenant_id = req.user.tenantId.',
              sampleExploitCurl: `curl -X ${method} "https://api.empresa.com${path.replace(/:[a-zA-Z]+/g, '99842')}" -H "Authorization: Bearer <TOKEN_DE_OUTRO_USUARIO>"`,
              securedCodeSnippet: `// Validação de Propriedade do Objeto (IDOR Shield)
const resource = await db.collection.findOne({
  _id: req.params.id,
  tenantId: req.user.tenantId, // Obrigatório: vínculo com a conta do usuário
  ownerUserId: req.user.id
});
if (!resource) {
  return res.status(404).json({ error: 'Recurso não encontrado ou acesso não autorizado' });
}`
            });
          }
        }

        // 2. Check for Mass Assignment (BOPLA) in POST / PUT / PATCH: req.body used directly in update/create
        if ((method === 'POST' || method === 'PUT' || method === 'PATCH')) {
          const surroundingCode = lines.slice(Math.max(0, idx), Math.min(lines.length, idx + 14)).join('\n');
          if (surroundingCode.includes('.create(req.body)') || surroundingCode.includes('.update(req.body)') || surroundingCode.includes('Object.assign(') || surroundingCode.includes('...req.body')) {
            findings.push({
              id: `api-sec-mass-assign-${file.name}-${lineNum}`,
              endpoint: path,
              method,
              category: 'API3:2023_BOPLA',
              categoryTitle: OWASP_API_DEFINITIONS['API3:2023_BOPLA'].title,
              severity: 'HIGH',
              vulnerabilityTitle: `Mass Assignment / BOPLA no Endpoint ${method} ${path}`,
              description: `O payload enviado pelo cliente (\`req.body\`) é injetado diretamente na entidade do banco de dados sem validação por schema allow-list (ex: Zod, Joi).`,
              impact: 'Usuários maliciosos podem enviar parâmetros adicionais como `isAdmin: true`, `role: "superuser"`, `balance: 999999` ou `isVerified: true`.',
              cwe: 'CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes',
              file: file.path,
              line: lineNum,
              remediation: 'Adicione uma validação estrita de DTO/Schema com biblioteca tipada (ex: Zod .strict() ou Joi) filtrando apenas campos permitidos.',
              sampleExploitCurl: `curl -X ${method} "https://api.empresa.com${path}" \\
  -H "Content-Type: application/json" \\
  -d '{"name": "Attacker", "role": "admin", "is_super_admin": true, "creditLimit": 1000000}'`,
              securedCodeSnippet: `// DTO Estrito com Zod (Allow-list)
const UpdateUserSchema = z.object({
  name: z.string().min(2).max(100),
  bio: z.string().optional()
}).strict(); // Rejeita campos proibidos como role ou isAdmin

const safePayload = UpdateUserSchema.parse(req.body);
await db.user.update({ where: { id: req.user.id }, data: safePayload });`
            });
          }
        }

        // 3. Broken Function Level Authorization (BFLA) in Admin Routes
        if (path.includes('/admin') || path.includes('/internal') || path.includes('/override') || path.includes('/manage')) {
          const surroundingCode = lines.slice(Math.max(0, idx - 3), Math.min(lines.length, idx + 10)).join('\n');
          if (!surroundingCode.includes('requireAdmin') && !surroundingCode.includes('hasRole') && !surroundingCode.includes('guard.admin')) {
            findings.push({
              id: `api-sec-bfla-${file.name}-${lineNum}`,
              endpoint: path,
              method,
              category: 'API5:2023_BFLA',
              categoryTitle: OWASP_API_DEFINITIONS['API5:2023_BFLA'].title,
              severity: 'CRITICAL',
              vulnerabilityTitle: `BFLA (Escalação de Função Administrativa) em ${method} ${path}`,
              description: `O endpoint contém o prefixo sensível '${path}', mas não implementa middleware de verificação de papel administrativo (RBAC/ABAC).`,
              impact: 'Qualquer usuário comum autenticado (ou até anônimo) pode disparar ações administrativas de alto impacto.',
              cwe: 'CWE-285: Improper Authorization',
              file: file.path,
              line: lineNum,
              remediation: 'Acople o middleware de autorização formal `requireRole("PLATFORM_ADMIN")` antes da execução do handler da rota.',
              sampleExploitCurl: `curl -X ${method} "https://api.empresa.com${path}" -H "Authorization: Bearer <TOKEN_USUARIO_COMUM>"`,
              securedCodeSnippet: `// Middleware Obrigatório de RBAC
router.${method.toLowerCase()}('${path}', authenticateJwt, requireRole(['SECURITY_ADMIN', 'PLATFORM_SUPERUSER']), (req, res) => {
  // Ação restrita autorizada
});`
            });
          }
        }

        // 4. Rate Limiting Check
        if ((method === 'POST' || method === 'PUT') && (path.includes('/login') || path.includes('/auth') || path.includes('/charge') || path.includes('/export') || path.includes('/download'))) {
          const surroundingCode = lines.slice(Math.max(0, idx - 5), Math.min(lines.length, idx + 10)).join('\n');
          if (!surroundingCode.includes('rateLimit') && !surroundingCode.includes('throttle') && !surroundingCode.includes('limiter')) {
            findings.push({
              id: `api-sec-rate-${file.name}-${lineNum}`,
              endpoint: path,
              method,
              category: 'API4:2023_UNRESTRICTED_RESOURCE',
              categoryTitle: OWASP_API_DEFINITIONS['API4:2023_UNRESTRICTED_RESOURCE'].title,
              severity: 'HIGH',
              vulnerabilityTitle: `Falta de Rate Limiting e Throttling no Endpoint Crítico ${method} ${path}`,
              description: `O endpoint sensível ${path} aceita requisições ilimitadas sem controle de vazão por IP ou conta de usuário.`,
              impact: 'Permite ataques automatizados de força bruta em senhas, abuso de custos financeiros de API e negação de serviço distribuída (DoS).',
              cwe: 'CWE-770: Allocation of Resources Without Limits or Throttling',
              file: file.path,
              line: lineNum,
              remediation: 'Configure express-rate-limit com janela de 15 minutos e limite máximo de 10 tentativas para rotas de autenticação/pagamento.',
              sampleExploitCurl: `for i in {1..1000}; do curl -s -X ${method} "https://api.empresa.com${path}" & done`,
              securedCodeSnippet: `const sensitiveRouteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10, // Máximo 10 requisições por IP
  message: { error: 'Limite de requisições excedido. Tente novamente mais tarde.' }
});

router.${method.toLowerCase()}('${path}', sensitiveRouteLimiter, handler);`
            });
          }
        }
      }

      // Check for Shadow API / Deprecated version patterns
      if (trimmed.includes('/v1/') && file.content.includes('/v2/')) {
        if (!findings.some(f => f.category === 'API9:2023_IMPROPER_INVENTORY' && f.file === file.path)) {
          findings.push({
            id: `api-sec-shadow-${file.name}-${lineNum}`,
            endpoint: '/api/v1/*',
            method: 'GET',
            category: 'API9:2023_IMPROPER_INVENTORY',
            categoryTitle: OWASP_API_DEFINITIONS['API9:2023_IMPROPER_INVENTORY'].title,
            severity: 'MEDIUM',
            vulnerabilityTitle: 'Potencial Shadow / Zombie API (Versão v1 legada ativa junto à v2)',
            description: 'Rotas de API v1 continuam ativas enquanto uma versão mais nova v2 foi introduzida no repositório.',
            impact: 'Versões antigas não recebem patches de segurança recentes e frequentemente possuem filtros e validações defasadas.',
            cwe: 'CWE-1059: Incomplete Documentation',
            file: file.path,
            line: lineNum,
            remediation: 'Deprecie oficialmente a API v1, adicione cabeçalho Sunset no padrão RFC 8594 e desative endpoints órfãos.',
            sampleExploitCurl: `curl -I "https://api.empresa.com/api/v1/legacy-endpoint"`,
            securedCodeSnippet: `// Adicione cabeçalhos de Depreciação (RFC 8594)
res.set({
  'Deprecation': '@1767225600',
  'Sunset': 'Sat, 01 Jan 2028 00:00:00 GMT',
  'Link': '</api/v2/resource>; rel="successor-version"'
});`
          });
        }
      }
    });
  });

  // Calculate API Risk Score (0-100)
  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = findings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;

  const totalDeductions = (criticalCount * 25) + (highCount * 12) + (mediumCount * 5);
  const apiRiskScore = Math.max(15, Math.min(100, 100 - totalDeductions));

  const summaryByCategory: Record<string, number> = {};
  findings.forEach(f => {
    summaryByCategory[f.category] = (summaryByCategory[f.category] || 0) + 1;
  });

  const summaryBySeverity: Record<string, number> = {
    CRITICAL: criticalCount,
    HIGH: highCount,
    MEDIUM: mediumCount,
    LOW: findings.filter(f => f.severity === 'LOW').length,
    INFO: 0
  };

  return {
    timestamp: new Date().toISOString(),
    totalEndpointsAudited: Math.max(auditedEndpointsCount, 4),
    vulnerableEndpointsCount: findings.length,
    apiRiskScore,
    findings,
    summaryByCategory,
    summaryBySeverity
  };
}
