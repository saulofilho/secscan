import {
  OpaRegoPolicy,
  OpaPolicyStandard,
  OpaEnforcementLevel,
  OpaPolicyViolation,
  OpaEvaluationResult,
  OpaEvaluationSummary,
  ScanFinding,
  ScanReport,
  SeverityLevel
} from '../types';

/**
 * Default organizational Policy-as-Code standards written in standard OPA Rego.
 */
export const DEFAULT_OPA_POLICIES: OpaRegoPolicy[] = [
  {
    id: 'policy-pci-dss-cardholder',
    name: 'PCI-DSS 4.0: Proteção de Dados de Titular de Cartão e Segredos de Pagamento',
    description: 'Proíbe o armazenamento de credenciais de processamento de pagamento (Stripe, Braintree, PayPal) e conexões de banco de dados em código claro nos termos dos requisitos 3.4 e 6.4 do PCI-DSS v4.0.',
    standard: 'PCI_DSS_4_0',
    packageName: 'secscan.compliance.pci_dss_4_0',
    enabled: true,
    enforcementLevel: 'BLOCKING',
    tags: ['PCI-DSS', 'Cardholder-Data', 'Fintech', 'Blocking-Gate'],
    author: 'Equipe de Governança & AppSec',
    version: '1.4.0',
    isBuiltIn: true,
    regoCode: `# ==========================================================
# PCI-DSS v4.0 Standard: Requirement 3.4.1 & 6.4.3
# Package: secscan.compliance.pci_dss_4_0
# ==========================================================
package secscan.compliance.pci_dss_4_0

default allow = false

# Regra 1: Bloquear chaves ativas de gateways de pagamento
deny[msg] {
    some finding in input.findings
    finding.category == "FINANCIAL_CREDENTIAL"
    msg := sprintf("PCI-DSS Req 3.4.1: Chave de gateway financeiro exposta '%v' no arquivo '%v' (linha %v)", [finding.ruleName, finding.file, finding.line])
}

# Regra 2: Bloquear credenciais de banco de dados em conexões de pagamento
deny[msg] {
    some finding in input.findings
    finding.category == "DATABASE_URL"
    contains(lower(finding.snippet), "payment")
    msg := sprintf("PCI-DSS Req 6.4: String de conexão de banco de transações financeiras exposta em '%v' (linha %v)", [finding.file, finding.line])
}

# Regra 3: Violações estruturadas para auditoria
violation[v] {
    some finding in input.findings
    finding.category == "FINANCIAL_CREDENTIAL"
    v := {
        "findingId": finding.id,
        "file": finding.file,
        "line": finding.line,
        "severity": "CRITICAL",
        "msg": sprintf("Violação crítica PCI-DSS: '%v' não criptografado.", [finding.ruleName]),
        "remediation": "Mova a chave para o AWS Secrets Manager ou HashiCorp Vault e rotacione imediatamente."
    }
}

allow {
    count(deny) == 0
}
`
  },
  {
    id: 'policy-soc2-cloud-credentials',
    name: 'SOC 2 Type II: Guardrails de Credenciais de Nuvem e Acesso Privilegiado',
    description: 'Aplica os critérios de confiança CC6.1 e CC6.6 do SOC 2: proíbe segredos de nuvem com severidade CRITICAL no código-fonte e bloqueia tokens de administração de produção.',
    standard: 'SOC_2_TYPE_II',
    packageName: 'secscan.compliance.soc2_type_ii',
    enabled: true,
    enforcementLevel: 'BLOCKING',
    tags: ['SOC2', 'Trust-Criteria-CC6', 'Cloud-IAM', 'Audit-Ready'],
    author: 'Compliance & CISO Office',
    version: '2.1.0',
    isBuiltIn: true,
    regoCode: `# ==========================================================
# SOC 2 Type II: Trust Services Criteria CC6.1 & CC6.6
# Package: secscan.compliance.soc2_type_ii
# ==========================================================
package secscan.compliance.soc2_type_ii

default allow = false

# Regra 1: Bloquear qualquer credencial de nuvem de alta severidade
deny[msg] {
    some finding in input.findings
    finding.category == "CLOUD_CREDENTIAL"
    finding.severity == "CRITICAL"
    msg := sprintf("SOC 2 CC6.1 Falha de Controle: Credencial de nuvem com severidade CRITICAL '%v' em '%v' (linha %v)", [finding.ruleName, finding.file, finding.line])
}

# Regra 2: Bloquear credenciais em arquivos críticos de infraestrutura ou produção
deny[msg] {
    some finding in input.findings
    finding.fileCriticality == "CRITICAL"
    finding.riskScore >= 75
    msg := sprintf("SOC 2 CC6.6 Exposição Privilegiada: Arquivo crítico '%v' contém segredo com Risk Score %v", [finding.file, finding.riskScore])
}

# Regra 3: Alerta quando arquivos com variáveis de ambiente (.env) contêm segredos
warn[msg] {
    some finding in input.findings
    endswith(finding.file, ".env")
    msg := sprintf("SOC 2 Recomendação: Arquivo .env versionado contém segredo '%v'. Certifique-se de que está no .gitignore.", [finding.ruleName])
}

allow {
    count(deny) == 0
}
`
  },
  {
    id: 'policy-cis-quality-gate',
    name: 'DevSecOps & CIS Benchmark: Quality Gate do Pipeline CI/CD',
    description: 'Define as metas estritas de qualidade de segurança para o pipeline de integração contínua (CI/CD): Risk Score cumulativo do workspace <= 50 e zero vulnerabilidades críticas não mitigadas.',
    standard: 'DEVSECOPS_GUARDRAIL',
    packageName: 'secscan.guardrails.pipeline_gate',
    enabled: true,
    enforcementLevel: 'BLOCKING',
    tags: ['Quality-Gate', 'Shift-Left', 'CI/CD', 'CIS-Benchmark'],
    author: 'DevSecOps Architecture',
    version: '3.0.0',
    isBuiltIn: true,
    regoCode: `# ==========================================================
# CIS DevSecOps Quality Gate: Pipeline Shift-Left Rule
# Package: secscan.guardrails.pipeline_gate
# ==========================================================
package secscan.guardrails.pipeline_gate

default allow = false

# Limite máximo de Workspace Risk Score permitido para passar o build
max_allowed_risk_score := 50

# Regra 1: Deny se o Risk Score do workspace ultrapassar o teto
deny[msg] {
    input.metrics.riskScore > max_allowed_risk_score
    msg := sprintf("Pipeline Blocked: Workspace Risk Score (%v/100) excede o teto permitido de %v.", [input.metrics.riskScore, max_allowed_risk_score])
}

# Regra 2: Deny se houver qualquer vulnerabilidade CRÍTICA ativa
deny[msg] {
    input.metrics.criticalCount > 0
    msg := sprintf("Pipeline Blocked: Encontrados %v achado(s) de severidade CRITICAL no repositório.", [input.metrics.criticalCount])
}

# Regra 3: Warn se houver mais de 3 achados HIGH
warn[msg] {
    input.metrics.highCount > 3
    msg := sprintf("Pipeline Warning: Volume elevado de achados HIGH (%v). Remediação necessária antes do deploy em produção.", [input.metrics.highCount])
}

allow {
    count(deny) == 0
}
`
  },
  {
    id: 'policy-nist-crypto-entropy',
    name: 'NIST SP 800-53 Rev 5: Gestão Criptográfica e Integridade de Autenticadores',
    description: 'Em conformidade com NIST SP 800-53 IA-5 (Authenticator Management) e SC-12 (Cryptographic Key Establishment): proíbe chaves de autenticação com baixa entropia e chaves privadas embutidas.',
    standard: 'NIST_SP_800_53',
    packageName: 'secscan.compliance.nist_sp_800_53',
    enabled: true,
    enforcementLevel: 'BLOCKING',
    tags: ['NIST', 'FedRAMP', 'Cryptography', 'IA-5', 'SC-12'],
    author: 'CISO / FedRAMP Lead',
    version: '1.2.0',
    isBuiltIn: true,
    regoCode: `# ==========================================================
# NIST SP 800-53 Rev 5: Controls IA-5 & SC-12
# Package: secscan.compliance.nist_sp_800_53
# ==========================================================
package secscan.compliance.nist_sp_800_53

default allow = false

# Regra 1: Bloquear chaves privadas assimétricas em arquivos de código
deny[msg] {
    some finding in input.findings
    finding.category == "PRIVATE_KEY"
    msg := sprintf("NIST SC-12 Não-Conformidade: Chave criptográfica privada detectada em '%v' (linha %v)", [finding.file, finding.line])
}

# Regra 2: Bloquear tokens de autenticação com entropia de Shannon perigosamente baixa (< 2.8) indicando senhas fracas
deny[msg] {
    some finding in input.findings
    finding.category == "API_KEY"
    finding.entropy < 2.8
    msg := sprintf("NIST IA-5 Autenticador Fraco: Token com baixa entropia (%v bits/char) em '%v' (linha %v)", [finding.entropy, finding.file, finding.line])
}

# Regra 3: Violação estruturada
violation[v] {
    some finding in input.findings
    finding.category == "PRIVATE_KEY"
    v := {
        "findingId": finding.id,
        "file": finding.file,
        "line": finding.line,
        "severity": "CRITICAL",
        "msg": "Chave privada RSA/SSH/EC exposta no repositório.",
        "remediation": "Remova a chave privada do git, gere um novo par de chaves e utilize PKI / KMS corporativo."
    }
}

allow {
    count(deny) == 0
}
`
  },
  {
    id: 'policy-iso27001-keys',
    name: 'ISO/IEC 27001:2022: Controles de Criptografia (A.10) e Controle de Acesso (A.9)',
    description: 'Aplica o padrão ISO 27001 para prevenção de vazamento de credenciais de infraestrutura crítica, certificados TLS sem proteção e credenciais de nuvem root.',
    standard: 'ISO_27001',
    packageName: 'secscan.compliance.iso27001',
    enabled: true,
    enforcementLevel: 'WARNING',
    tags: ['ISO27001', 'ISMS', 'AccessControl', 'Cryptographic-Controls'],
    author: 'ISMS Lead Auditor',
    version: '1.1.0',
    isBuiltIn: true,
    regoCode: `# ==========================================================
# ISO/IEC 27001:2022: Annex A.9 & A.10
# Package: secscan.compliance.iso27001
# ==========================================================
package secscan.compliance.iso27001

default allow = false

# Regra 1: Bloquear chaves AWS com prefixo AKIA (Root / IAM User direto)
deny[msg] {
    some finding in input.findings
    contains(finding.ruleName, "AWS")
    contains(finding.matchedSecret, "AKIA")
    msg := sprintf("ISO 27001 A.9.4: Credencial de acesso AWS persistente (AKIA) encontrada em '%v'. Prefira perfis IAM com STS temporário.", [finding.file])
}

# Regra 2: Alertar sobre credenciais de banco de dados
warn[msg] {
    some finding in input.findings
    finding.category == "DATABASE_URL"
    msg := sprintf("ISO 27001 A.10.1: Conexão direta com banco de dados detectada em '%v'. Certifique-se do uso de TLS mTLS.", [finding.file])
}

allow {
    count(deny) == 0
}
`
  },
  {
    id: 'policy-owasp-dangerous-sinks',
    name: 'OWASP Top 10 & API Guardrails: Proibição de Sinks Perigosos e RCE',
    description: 'Detecta e bloqueia a presença de sinks de execução arbitrária de código (eval, Function, innerHTML sem sanitização) e injeções de comandos nos termos do OWASP Top 10 A03:2021 (Injection).',
    standard: 'OWASP_TOP_10',
    packageName: 'secscan.owasp.injection_sinks',
    enabled: true,
    enforcementLevel: 'BLOCKING',
    tags: ['OWASP', 'Injection', 'XSS', 'Code-Execution', 'Sinks'],
    author: 'AppSec Red Team',
    version: '2.0.0',
    isBuiltIn: true,
    regoCode: `# ==========================================================
# OWASP Top 10: A03:2021 Injection & Dangerous Sinks
# Package: secscan.owasp.injection_sinks
# ==========================================================
package secscan.owasp.injection_sinks

default allow = false

# Regra 1: Bloquear chamadas de eval() ou injeção de script
deny[msg] {
    some finding in input.findings
    contains(lower(finding.snippet), "eval(")
    msg := sprintf("OWASP A03 Injection: Uso de função perigosa 'eval()' detectado em '%v' (linha %v)", [finding.file, finding.line])
}

# Regra 2: Bloquear injeções SQL e comandos do sistema
deny[msg] {
    some finding in input.findings
    finding.category == "INJECTION"
    finding.severity == "CRITICAL"
    msg := sprintf("OWASP A03: Padrão crítico de injeção '%v' em '%v' (linha %v)", [finding.ruleName, finding.file, finding.line])
}

allow {
    count(deny) == 0
}
`
  },
  {
    id: 'policy-hipaa-ephi-db',
    name: 'HIPAA Security Rule: Proteção e Criptografia de Conexões com Dados ePHI',
    description: 'Em conformidade com a norma 45 CFR § 164.312(a)(2)(iv) (Encryption and Decryption): proíbe strings de conexão desprotegidas ou senhas em texto puro conectando a prontuários de saúde.',
    standard: 'HIPAA',
    packageName: 'secscan.compliance.hipaa',
    enabled: true,
    enforcementLevel: 'WARNING',
    tags: ['HIPAA', 'ePHI', 'Healthcare', 'Privacy'],
    author: 'Healthcare Compliance Officer',
    version: '1.0.0',
    isBuiltIn: true,
    regoCode: `# ==========================================================
# HIPAA Security Rule: 45 CFR § 164.312(a)(2)(iv)
# Package: secscan.compliance.hipaa
# ==========================================================
package secscan.compliance.hipaa

default allow = false

# Regra 1: Conexões de banco de dados em arquivos de prontuário / paciente
deny[msg] {
    some finding in input.findings
    finding.category == "DATABASE_URL"
    contains(lower(finding.file), "patient")
    msg := sprintf("HIPAA §164.312(a): Credencial de banco de dados em módulo clínico '%v' (linha %v)", [finding.file, finding.line])
}

# Regra 2: Alertar sobre qualquer credencial em repositórios da área de saúde
warn[msg] {
    some finding in input.findings
    finding.severity == "CRITICAL"
    msg := sprintf("HIPAA Auditoria: Achado crítico '%v' em '%v'. Viola salvaguarda técnica §164.312.", [finding.ruleName, finding.file])
}

allow {
    count(deny) == 0
}
`
  }
];

/**
 * Pre-baked policy templates for quick user creation in the UI.
 */
export interface OpaPolicyTemplate {
  title: string;
  category: OpaPolicyStandard;
  description: string;
  defaultEnforcement: OpaEnforcementLevel;
  regoCode: string;
}

export const OPA_POLICY_TEMPLATES: OpaPolicyTemplate[] = [
  {
    title: 'Bloquear Credenciais de Nuvem (AWS/GCP/Azure)',
    category: 'DEVSECOPS_GUARDRAIL',
    description: 'Rejeita o build se qualquer chave de provedor de nuvem for encontrada no código.',
    defaultEnforcement: 'BLOCKING',
    regoCode: `package secscan.custom.cloud_secrets

default allow = false

deny[msg] {
    some finding in input.findings
    finding.category == "CLOUD_CREDENTIAL"
    msg := sprintf("Guardrail Corporativo: Chave de nuvem '%v' proibida em '%v' (linha %v)", [finding.ruleName, finding.file, finding.line])
}

allow {
    count(deny) == 0
}
`
  },
  {
    title: 'Teto de Risk Score do Repositório (Quality Gate)',
    category: 'CIS_BENCHMARK',
    description: 'Impede o deploy se o Risk Score do workspace ultrapassar um limite configurado.',
    defaultEnforcement: 'BLOCKING',
    regoCode: `package secscan.custom.risk_ceiling

default allow = false

max_risk := 45

deny[msg] {
    input.metrics.riskScore > max_risk
    msg := sprintf("Quality Gate: Risk Score %v/100 excede o teto permitido de %v.", [input.metrics.riskScore, max_risk])
}

allow {
    count(deny) == 0
}
`
  },
  {
    title: 'Proibir Arquivos Sensíveis (.env / id_rsa)',
    category: 'CUSTOM',
    description: 'Identifica arquivos de configuração e chaves privadas versionados incorretamente.',
    defaultEnforcement: 'WARNING',
    regoCode: `package secscan.custom.sensitive_files

default allow = false

deny[msg] {
    some finding in input.findings
    endswith(finding.file, ".env")
    msg := sprintf("Arquivo sensível detectado: '%v' contém segredo '%v'", [finding.file, finding.ruleName])
}

deny[msg] {
    some finding in input.findings
    contains(lower(finding.file), "id_rsa")
    msg := sprintf("Arquivo de chave SSH privada exposto: '%v'", [finding.file])
}

allow {
    count(deny) == 0
}
`
  },
  {
    title: 'OWASP API Security: Proibir Endpoints Desprotegidos',
    category: 'OWASP_TOP_10',
    description: 'Detecta e alerta sobre endpoints administrativos internos expostos.',
    defaultEnforcement: 'WARNING',
    regoCode: `package secscan.custom.api_security

default allow = false

deny[msg] {
    some ep in input.apiEndpoints
    ep.isInternalOrAdmin == true
    msg := sprintf("OWASP API5: Rota interna/administrativa '%v' exposta sem guardas de segurança em '%v'", [ep.path, ep.file])
}

allow {
    count(deny) == 0
}
`
  }
];

// ---------------------------------------------------------------------------
// Rego Parser & Interpreter
// ---------------------------------------------------------------------------

interface RegoRuleBlock {
  type: 'deny' | 'violation' | 'warn' | 'allow';
  targetVar?: string;
  conditions: string[];
}

/**
 * Parses Rego policy code into structured AST-like rules.
 */
export function parseRegoPolicy(code: string): {
  packageName: string;
  defaultAllow: boolean;
  rules: RegoRuleBlock[];
  constants: Record<string, any>;
  errors: string[];
} {
  const lines = code.split('\n');
  let packageName = 'secscan.policy';
  let defaultAllow = false;
  const rules: RegoRuleBlock[] = [];
  const constants: Record<string, any> = {};
  const errors: string[] = [];

  let currentBlock: RegoRuleBlock | null = null;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const line = rawLine.trim();

    // Skip empty lines and full comments
    if (!line || line.startsWith('#')) {
      continue;
    }

    // Package declaration
    const pkgMatch = line.match(/^package\s+([a-zA-Z0-9_.]+)/);
    if (pkgMatch) {
      packageName = pkgMatch[1];
      continue;
    }

    // Default allow declaration
    const defaultMatch = line.match(/^default\s+allow\s*=\s*(true|false)/);
    if (defaultMatch) {
      defaultAllow = defaultMatch[1] === 'true';
      continue;
    }

    // Constant assignment: max_risk := 45 or max_allowed := "foo"
    const constMatch = line.match(/^([a-zA-Z0-9_]+)\s*:=\s*(.+)$/);
    if (constMatch && !currentBlock) {
      const varName = constMatch[1];
      let valStr = constMatch[2].trim();
      if (valStr.endsWith(';')) valStr = valStr.slice(0, -1).trim();
      if (!isNaN(Number(valStr))) {
        constants[varName] = Number(valStr);
      } else if (valStr === 'true' || valStr === 'false') {
        constants[varName] = valStr === 'true';
      } else if (valStr.startsWith('"') && valStr.endsWith('"')) {
        constants[varName] = valStr.slice(1, -1);
      } else {
        constants[varName] = valStr;
      }
      continue;
    }

    // Rule header: deny[msg] { or violation[v] { or warn[msg] { or allow {
    const ruleStartMatch = line.match(/^(deny|violation|warn|allow)(?:\[([a-zA-Z0-9_]+)\])?\s*\{/);
    if (ruleStartMatch) {
      const ruleType = ruleStartMatch[1] as RegoRuleBlock['type'];
      const targetVar = ruleStartMatch[2];
      currentBlock = {
        type: ruleType,
        targetVar,
        conditions: []
      };
      continue;
    }

    // Single-line rule allow { count(deny) == 0 }
    const singleLineRuleMatch = line.match(/^(deny|violation|warn|allow)(?:\[([a-zA-Z0-9_]+)\])?\s*\{\s*([^}]+)\s*\}/);
    if (singleLineRuleMatch) {
      const ruleType = singleLineRuleMatch[1] as RegoRuleBlock['type'];
      const targetVar = singleLineRuleMatch[2];
      const cond = singleLineRuleMatch[3].trim();
      rules.push({
        type: ruleType,
        targetVar,
        conditions: [cond]
      });
      continue;
    }

    // Closing brace
    if (line === '}') {
      if (currentBlock) {
        rules.push(currentBlock);
        currentBlock = null;
      }
      continue;
    }

    // Inside block: accumulate conditions
    if (currentBlock) {
      // Handle multi-line object constructions or normal conditions
      currentBlock.conditions.push(line);
    }
  }

  if (currentBlock) {
    rules.push(currentBlock);
  }

  return {
    packageName,
    defaultAllow,
    rules,
    constants,
    errors
  };
}

/**
 * Safely evaluates a Rego expression in context of an input finding/metric/file.
 */
function evaluateRegoCondition(
  cond: string,
  ctx: {
    input: any;
    finding?: ScanFinding;
    file?: any;
    ep?: any;
    vars: Record<string, any>;
    denyCount: number;
    warnCount: number;
  }
): boolean {
  const trimmed = cond.trim();
  if (!trimmed || trimmed.startsWith('#')) return true;

  // Handle assignment: msg := sprintf(...) or v := { ... }
  if (trimmed.includes(':=') && !trimmed.startsWith('v :=')) {
    const parts = trimmed.split(':=');
    const varName = parts[0].trim();
    const expr = parts.slice(1).join(':=').trim();
    ctx.vars[varName] = evaluateRegoValueExpr(expr, ctx);
    return true;
  }

  // Handle negation: not allow, not finding.isFalsePositive
  if (trimmed.startsWith('not ')) {
    const subCond = trimmed.slice(4).trim();
    return !evaluateRegoCondition(subCond, ctx);
  }

  // Handle count(deny) == 0
  const countMatch = trimmed.match(/^count\(([a-zA-Z0-9_]+)\)\s*(==|!=|>|<|>=|<=)\s*(\d+)$/);
  if (countMatch) {
    const listName = countMatch[1];
    const op = countMatch[2];
    const targetVal = Number(countMatch[3]);
    let actualCount = 0;
    if (listName === 'deny') actualCount = ctx.denyCount;
    else if (listName === 'warn') actualCount = ctx.warnCount;
    else if (listName in ctx.vars && Array.isArray(ctx.vars[listName])) actualCount = ctx.vars[listName].length;

    return compareValues(actualCount, op, targetVal);
  }

  // Handle standard comparison: left op right (e.g. finding.severity == "CRITICAL", finding.entropy < 2.8)
  const compMatch = trimmed.match(/^(.+?)\s*(==|!=|>=|<=|>|<)\s*(.+)$/);
  if (compMatch) {
    const leftRaw = compMatch[1].trim();
    const op = compMatch[2];
    const rightRaw = compMatch[3].trim();

    const leftVal = resolveValue(leftRaw, ctx);
    const rightVal = resolveValue(rightRaw, ctx);

    return compareValues(leftVal, op, rightVal);
  }

  // Handle function calls like contains(str, substr)
  if (trimmed.startsWith('contains(') || trimmed.startsWith('startswith(') || trimmed.startsWith('endswith(')) {
    const val = evaluateRegoValueExpr(trimmed, ctx);
    return Boolean(val);
  }

  return true;
}

/**
 * Resolves a property path or literal value within context.
 */
function resolveValue(token: string, ctx: any): any {
  const trimmed = token.trim();

  // String literal
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }

  // Number literal
  if (!isNaN(Number(trimmed)) && trimmed !== '') {
    return Number(trimmed);
  }

  // Boolean literal
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  if (trimmed === 'null') return null;

  // Function call inside comparison: lower(finding.snippet) or count(...)
  if (trimmed.includes('(') && trimmed.endsWith(')')) {
    return evaluateRegoValueExpr(trimmed, ctx);
  }

  // Check defined vars
  if (trimmed in ctx.vars) {
    return ctx.vars[trimmed];
  }

  // Path navigation: finding.severity, input.metrics.riskScore
  const parts = trimmed.split('.');
  let current: any = null;

  if (parts[0] === 'finding') {
    current = ctx.finding;
    parts.shift();
  } else if (parts[0] === 'input') {
    current = ctx.input;
    parts.shift();
  } else if (parts[0] === 'file') {
    current = ctx.file;
    parts.shift();
  } else if (parts[0] === 'ep') {
    current = ctx.ep;
    parts.shift();
  } else if (parts[0] in ctx.vars) {
    current = ctx.vars[parts[0]];
    parts.shift();
  }

  if (current === undefined || current === null) {
    return undefined;
  }

  for (const part of parts) {
    if (current && typeof current === 'object' && part in current) {
      current = current[part];
    } else {
      return undefined;
    }
  }

  return current;
}

/**
 * Compares two values with standard operators.
 */
function compareValues(a: any, op: string, b: any): boolean {
  switch (op) {
    case '==': return a === b || (typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase());
    case '!=': return a !== b;
    case '>': return Number(a) > Number(b);
    case '<': return Number(a) < Number(b);
    case '>=': return Number(a) >= Number(b);
    case '<=': return Number(a) <= Number(b);
    default: return false;
  }
}

/**
 * Evaluates function calls such as sprintf, contains, lower, count, regex.match
 */
function evaluateRegoValueExpr(expr: string, ctx: any): any {
  const trimmed = expr.trim();

  // lower(expr)
  const lowerMatch = trimmed.match(/^lower\((.+)\)$/);
  if (lowerMatch) {
    const val = resolveValue(lowerMatch[1], ctx);
    return typeof val === 'string' ? val.toLowerCase() : String(val ?? '').toLowerCase();
  }

  // upper(expr)
  const upperMatch = trimmed.match(/^upper\((.+)\)$/);
  if (upperMatch) {
    const val = resolveValue(upperMatch[1], ctx);
    return typeof val === 'string' ? val.toUpperCase() : String(val ?? '').toUpperCase();
  }

  // contains(str, substr)
  const containsMatch = trimmed.match(/^contains\((.+),\s*(.+)\)$/);
  if (containsMatch) {
    const strVal = resolveValue(containsMatch[1], ctx);
    const substrVal = resolveValue(containsMatch[2], ctx);
    return String(strVal ?? '').toLowerCase().includes(String(substrVal ?? '').toLowerCase());
  }

  // startswith(str, prefix)
  const startsMatch = trimmed.match(/^startswith\((.+),\s*(.+)\)$/);
  if (startsMatch) {
    const strVal = resolveValue(startsMatch[1], ctx);
    const prefixVal = resolveValue(startsMatch[2], ctx);
    return String(strVal ?? '').startsWith(String(prefixVal ?? ''));
  }

  // endswith(str, suffix)
  const endsMatch = trimmed.match(/^endswith\((.+),\s*(.+)\)$/);
  if (endsMatch) {
    const strVal = resolveValue(endsMatch[1], ctx);
    const suffixVal = resolveValue(endsMatch[2], ctx);
    return String(strVal ?? '').endsWith(String(suffixVal ?? ''));
  }

  // sprintf(template, [arg1, arg2])
  const sprintfMatch = trimmed.match(/^sprintf\((["'].*?["'])\s*,\s*\[(.*?)\]\)$/);
  if (sprintfMatch) {
    let template = sprintfMatch[1].slice(1, -1);
    const argsStr = sprintfMatch[2].trim();
    const rawArgs = argsStr ? argsStr.split(',').map(s => s.trim()) : [];
    const resolvedArgs = rawArgs.map(arg => resolveValue(arg, ctx) ?? '');

    let argIdx = 0;
    template = template.replace(/%[vsdf]/g, () => {
      const val = resolvedArgs[argIdx++];
      return val !== undefined ? String(val) : '';
    });
    return template;
  }

  // count(arr)
  const countMatch = trimmed.match(/^count\((.+)\)$/);
  if (countMatch) {
    const arr = resolveValue(countMatch[1], ctx);
    if (Array.isArray(arr)) return arr.length;
    return 0;
  }

  // regex.match(pattern, str)
  const regexMatch = trimmed.match(/^regex\.match\((.+),\s*(.+)\)$/);
  if (regexMatch) {
    const pattern = resolveValue(regexMatch[1], ctx);
    const targetStr = resolveValue(regexMatch[2], ctx);
    try {
      const rx = new RegExp(pattern);
      return rx.test(String(targetStr ?? ''));
    } catch {
      return false;
    }
  }

  return resolveValue(trimmed, ctx);
}

/**
 * Evaluates a single OPA Rego policy against an input dataset (ScanReport / findings / metrics).
 */
export function evaluateSingleOpaPolicy(
  policy: OpaRegoPolicy,
  input: {
    findings: ScanFinding[];
    metrics: ScanReport['metrics'];
    apiEndpoints?: any[];
    files?: any[];
    environment?: Record<string, any>;
  }
): OpaEvaluationResult {
  const startTime = performance.now();

  try {
    const parsed = parseRegoPolicy(policy.regoCode);
    const denyReasons: string[] = [];
    const violations: OpaPolicyViolation[] = [];
    let allow = parsed.defaultAllow;

    // Run rules
    for (const rule of parsed.rules) {
      // Rule 1: deny or warn or violation
      if (rule.type === 'deny' || rule.type === 'warn' || rule.type === 'violation') {
        // Check if rule iterates over findings: 'some finding in input.findings'
        const hasFindingIteration = rule.conditions.some(c => 
          c.includes('some finding in input.findings') || 
          c.includes('finding := input.findings[_]') ||
          c.includes('finding.category') ||
          c.includes('finding.severity')
        );

        // Check if rule iterates over endpoints
        const hasEndpointIteration = rule.conditions.some(c => 
          c.includes('some ep in input.apiEndpoints') || 
          c.includes('input.apiEndpoints')
        );

        if (hasFindingIteration && input.findings && input.findings.length > 0) {
          // Evaluate for each finding
          for (const finding of input.findings) {
            const ctx = {
              input,
              finding,
              vars: { ...parsed.constants },
              denyCount: denyReasons.length,
              warnCount: 0
            };

            let allMatched = true;
            for (const cond of rule.conditions) {
              if (cond.includes('some finding in input.findings')) continue;
              if (cond.startsWith('v :=')) {
                // Object constructor for violation[v]
                continue;
              }
              const result = evaluateRegoCondition(cond, ctx);
              if (!result) {
                allMatched = false;
                break;
              }
            }

            if (allMatched) {
              const msgVar = rule.targetVar || 'msg';
              const reasonMsg = ctx.vars[msgVar] || `Violação da política ${policy.name} em ${finding.file} (linha ${finding.line})`;

              if (rule.type === 'deny') {
                denyReasons.push(reasonMsg);
              }

              violations.push({
                id: `opa-violation-${policy.id}-${finding.id}-${Date.now()}`,
                policyId: policy.id,
                policyName: policy.name,
                standard: policy.standard,
                enforcementLevel: policy.enforcementLevel,
                severity: finding.severity || 'HIGH',
                message: reasonMsg,
                targetFindingId: finding.id,
                targetFile: finding.file,
                targetLine: finding.line,
                remediation: finding.remediation || 'Revogue a credencial e configure conformidade com OPA Rego.',
                ruleExpression: rule.conditions.filter(c => !c.includes(':=') && !c.includes('some')).join('; ')
              });
            }
          }
        } else if (hasEndpointIteration && input.apiEndpoints && input.apiEndpoints.length > 0) {
          // Evaluate for each endpoint
          for (const ep of input.apiEndpoints) {
            const ctx = {
              input,
              ep,
              vars: { ...parsed.constants },
              denyCount: denyReasons.length,
              warnCount: 0
            };

            let allMatched = true;
            for (const cond of rule.conditions) {
              if (cond.includes('some ep in input.apiEndpoints')) continue;
              const result = evaluateRegoCondition(cond, ctx);
              if (!result) {
                allMatched = false;
                break;
              }
            }

            if (allMatched) {
              const msgVar = rule.targetVar || 'msg';
              const reasonMsg = ctx.vars[msgVar] || `Violação de API na rota ${ep.path}`;
              if (rule.type === 'deny') {
                denyReasons.push(reasonMsg);
              }
              violations.push({
                id: `opa-violation-ep-${policy.id}-${Date.now()}`,
                policyId: policy.id,
                policyName: policy.name,
                standard: policy.standard,
                enforcementLevel: policy.enforcementLevel,
                severity: 'HIGH',
                message: reasonMsg,
                targetFile: ep.file,
                remediation: 'Implemente controle de acesso RBAC e proteja o endpoint interno.'
              });
            }
          }
        } else {
          // Repositório / Workspace-level condition (e.g. input.metrics.riskScore > 50)
          const ctx = {
            input,
            vars: { ...parsed.constants },
            denyCount: denyReasons.length,
            warnCount: 0
          };

          let allMatched = true;
          for (const cond of rule.conditions) {
            const result = evaluateRegoCondition(cond, ctx);
            if (!result) {
              allMatched = false;
              break;
            }
          }

          if (allMatched) {
            const msgVar = rule.targetVar || 'msg';
            const reasonMsg = ctx.vars[msgVar] || `Violação da política ${policy.name} no workspace.`;
            if (rule.type === 'deny') {
              denyReasons.push(reasonMsg);
            }
            violations.push({
              id: `opa-violation-ws-${policy.id}-${Date.now()}`,
              policyId: policy.id,
              policyName: policy.name,
              standard: policy.standard,
              enforcementLevel: policy.enforcementLevel,
              severity: 'CRITICAL',
              message: reasonMsg,
              remediation: 'Reduza o Risk Score do repositório remediando vulnerabilidades críticas.'
            });
          }
        }
      } else if (rule.type === 'allow') {
        // Evaluate allow rule
        const ctx = {
          input,
          vars: { ...parsed.constants },
          denyCount: denyReasons.length,
          warnCount: 0
        };

        let allowMatched = true;
        for (const cond of rule.conditions) {
          const result = evaluateRegoCondition(cond, ctx);
          if (!result) {
            allowMatched = false;
            break;
          }
        }
        if (allowMatched) {
          allow = true;
        }
      }
    }

    // Final allow calculation: if there are deny reasons, allow is false
    if (denyReasons.length > 0) {
      allow = false;
    }

    const duration = Math.max(1, Math.round(performance.now() - startTime));
    const status: OpaEvaluationResult['status'] = violations.length > 0 ? 'VIOLATED' : 'PASSED';

    return {
      policyId: policy.id,
      policyName: policy.name,
      standard: policy.standard,
      packageName: parsed.packageName,
      enforcementLevel: policy.enforcementLevel,
      status,
      allow,
      denyReasons,
      violations,
      executionTimeMs: duration
    };
  } catch (err: any) {
    const duration = Math.max(1, Math.round(performance.now() - startTime));
    return {
      policyId: policy.id,
      policyName: policy.name,
      standard: policy.standard,
      packageName: policy.packageName,
      enforcementLevel: policy.enforcementLevel,
      status: 'ERROR',
      allow: false,
      denyReasons: [`Erro de parsing/execução Rego: ${err?.message || 'Syntax error'}`],
      violations: [],
      executionTimeMs: duration,
      errorMessage: err?.message || 'Syntax error in Rego code'
    };
  }
}

/**
 * Evaluates an entire collection of OPA Rego policies against the scan report.
 */
export function evaluateAllOpaPolicies(
  policies: OpaRegoPolicy[],
  report: ScanReport
): OpaEvaluationSummary {
  const startTime = performance.now();
  const enabledPolicies = policies.filter(p => p.enabled);

  const input = {
    findings: report.findings,
    metrics: report.metrics,
    apiEndpoints: report.apiEndpoints,
    totalFiles: report.totalFiles,
    environment: {
      branch: 'main',
      ciStage: 'security-testing',
      pipeline: 'github-actions'
    }
  };

  const policyResults: OpaEvaluationResult[] = [];
  const allViolations: OpaPolicyViolation[] = [];

  for (const policy of enabledPolicies) {
    const res = evaluateSingleOpaPolicy(policy, input);
    policyResults.push(res);
    if (res.violations && res.violations.length > 0) {
      allViolations.push(...res.violations);
    }
  }

  const passedCount = policyResults.filter(r => r.status === 'PASSED').length;
  const violatedCount = policyResults.filter(r => r.status === 'VIOLATED').length;

  const blockingViolationsCount = policyResults
    .filter(r => r.enforcementLevel === 'BLOCKING' && r.status === 'VIOLATED')
    .reduce((acc, curr) => acc + curr.violations.length, 0);

  const warningViolationsCount = policyResults
    .filter(r => r.enforcementLevel === 'WARNING' && r.status === 'VIOLATED')
    .reduce((acc, curr) => acc + curr.violations.length, 0);

  // Calculate compliance score (0-100%)
  const complianceScore = enabledPolicies.length > 0
    ? Math.round((passedCount / enabledPolicies.length) * 100)
    : 100;

  // Determine overall verdict
  let verdict: OpaEvaluationSummary['verdict'] = 'PASSED';
  if (blockingViolationsCount > 0) {
    verdict = 'FAILED_BLOCKING';
  } else if (warningViolationsCount > 0 || violatedCount > 0) {
    verdict = 'WARNING';
  }

  const totalTime = Math.max(1, Math.round(performance.now() - startTime));

  return {
    timestamp: new Date().toISOString(),
    totalPolicies: policies.length,
    enabledPolicies: enabledPolicies.length,
    passedCount,
    violatedCount,
    blockingViolationsCount,
    warningViolationsCount,
    complianceScore,
    verdict,
    policyResults,
    allViolations,
    totalExecutionTimeMs: totalTime
  };
}

/**
 * Exports all policies into a single consolidated Rego bundle.
 */
export function exportPoliciesToRegoBundle(policies: OpaRegoPolicy[]): string {
  const header = `# ==============================================================================
# SECSCAN APPSEC SUITE - POLICY-AS-CODE (OPA REGO BUNDLE)
# Generated: ${new Date().toISOString()}
# Total Policies: ${policies.length}
# Open Policy Agent standard compliance definitions
# ==============================================================================
`;

  const bodies = policies.map(p => {
    return `# Policy: ${p.name}
# Standard: ${p.standard} | Enforcement: ${p.enforcementLevel} | Enabled: ${p.enabled}
${p.regoCode}
`;
  }).join('\n# ------------------------------------------------------------------------------\n\n');

  return header + '\n' + bodies;
}

/**
 * Exports evaluation summary in OPA CLI compatible JSON format.
 */
export function exportOpaEvaluationJson(summary: OpaEvaluationSummary): string {
  return JSON.stringify({
    opa_version: '0.68.0',
    eval_timestamp: summary.timestamp,
    compliance_score: summary.complianceScore,
    verdict: summary.verdict,
    summary: {
      total_policies: summary.totalPolicies,
      enabled_policies: summary.enabledPolicies,
      passed: summary.passedCount,
      violated: summary.violatedCount,
      blocking_violations: summary.blockingViolationsCount,
      warning_violations: summary.warningViolationsCount
    },
    policy_evaluations: summary.policyResults.map(r => ({
      package: r.packageName,
      policy_id: r.policyId,
      policy_name: r.policyName,
      standard: r.standard,
      enforcement: r.enforcementLevel,
      result: {
        allow: r.allow,
        deny: r.denyReasons
      },
      violations_count: r.violations.length,
      execution_ms: r.executionTimeMs
    })),
    violations: summary.allViolations
  }, null, 2);
}
