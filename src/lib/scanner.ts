import {
  RegexRule,
  ScanFinding,
  ApiEndpointFinding,
  ScannedFile,
  ScanReport,
  AuditLogEvent,
  SeverityLevel,
  FileCriticalityLevel,
  FileCriticalityInfo,
  IgnorePatternItem,
  JsMinerResults,
  SourceMapFinding,
  CloudBucketFinding,
  JwtTokenFinding,
  BundledDependencyFinding,
  DangerousSinkFinding,
  DataFlowGraphData
} from '../types';
import { extractLinkFinderEndpoints } from './linkFinderEngine';
import { analyzeWithJsMiner } from './jsMinerEngine';
import { buildDataFlowGraph } from './dataFlowGraphEngine';

export const DEFAULT_GLOBAL_IGNORE_PATTERNS: IgnorePatternItem[] = [
  {
    id: 'ignore-node-modules',
    pattern: 'node_modules/*',
    enabled: true,
    description: 'Dependências de pacotes Node.js (npm / yarn / pnpm)',
    isBuiltIn: true,
    createdAt: '2026-01-01'
  },
  {
    id: 'ignore-vendor',
    pattern: 'vendor/*',
    enabled: true,
    description: 'Bibliotecas e módulos de terceiros (Composer, Go vendor)',
    isBuiltIn: true,
    createdAt: '2026-01-01'
  },
  {
    id: 'ignore-git',
    pattern: '.git/*',
    enabled: true,
    description: 'Objetos internos e metadados do repositório Git',
    isBuiltIn: true,
    createdAt: '2026-01-01'
  },
  {
    id: 'ignore-dist',
    pattern: 'dist/*',
    enabled: true,
    description: 'Artefatos compilados de distribuição e bundles',
    isBuiltIn: true,
    createdAt: '2026-01-01'
  },
  {
    id: 'ignore-build',
    pattern: 'build/*',
    enabled: true,
    description: 'Diretórios de compilação intermediária e packaging',
    isBuiltIn: true,
    createdAt: '2026-01-01'
  },
  {
    id: 'ignore-coverage',
    pattern: 'coverage/*',
    enabled: true,
    description: 'Relatórios de cobertura de testes automatizados (lcov/istanbul)',
    isBuiltIn: true,
    createdAt: '2026-01-01'
  },
  {
    id: 'ignore-tests',
    pattern: 'tests/*',
    enabled: false,
    description: 'Diretório de testes unitários e de integração (tests/*)',
    isBuiltIn: false,
    createdAt: '2026-01-01'
  },
  {
    id: 'ignore-test-files',
    pattern: '*.test.*',
    enabled: false,
    description: 'Arquivos de suíte de testes (*.test.js, *.test.ts)',
    isBuiltIn: false,
    createdAt: '2026-01-01'
  },
  {
    id: 'ignore-spec-files',
    pattern: '*.spec.*',
    enabled: false,
    description: 'Arquivos de especificação (*.spec.js, *.spec.ts)',
    isBuiltIn: false,
    createdAt: '2026-01-01'
  }
];

export const SEVERITY_BASE_WEIGHTS: Record<SeverityLevel, number> = {
  CRITICAL: 25,
  HIGH: 14,
  MEDIUM: 7,
  LOW: 3,
  INFO: 1
};

export const FILE_CRITICALITY_MULTIPLIERS: Record<FileCriticalityLevel, number> = {
  CRITICAL: 2.0,
  HIGH: 1.5,
  MEDIUM: 1.0,
  LOW: 0.5
};

/**
 * Evaluates file criticality based on filepath semantics, architectural exposure, and role.
 */
export function evaluateFileCriticality(filePath: string): FileCriticalityInfo {
  const normalized = filePath.replace(/\\/g, '/').toLowerCase();
  const fileName = normalized.split('/').pop() || '';

  // 1. CRITICAL TIER (2.0x): Infrastructure secrets, production config, database credentials, authentication cores
  if (
    normalized.includes('.env') ||
    normalized.includes('credentials') ||
    normalized.includes('secret') ||
    normalized.includes('id_rsa') ||
    fileName.endsWith('.pem') ||
    fileName.endsWith('.key') ||
    fileName.endsWith('.pfx') ||
    fileName.endsWith('.keystore') ||
    normalized.startsWith('config/') ||
    normalized.includes('/config/') ||
    fileName.includes('cloudconfig') ||
    fileName.includes('dbconfig') ||
    fileName.includes('database') ||
    fileName === 'dockerfile' ||
    fileName.startsWith('docker-compose') ||
    normalized.includes('k8s/') ||
    normalized.includes('kubernetes/') ||
    normalized.includes('helm/') ||
    fileName === 'server.ts' ||
    fileName === 'server.js'
  ) {
    return {
      level: 'CRITICAL',
      weight: 2.0,
      category: 'CONFIG_INFRA_SECRETS',
      reason: 'Arquivo crítico de infraestrutura, credenciais ou configurações de ambiente de produção'
    };
  }

  // 2. HIGH TIER (1.5x): Core backend controllers, API routing, authentication & authorization services, payment processors
  if (
    normalized.includes('/services/') ||
    normalized.includes('/controllers/') ||
    normalized.includes('/routes/') ||
    normalized.includes('/api/') ||
    normalized.includes('/handlers/') ||
    normalized.includes('/backend/') ||
    normalized.includes('/auth') ||
    normalized.includes('payment') ||
    normalized.includes('checkout') ||
    normalized.includes('webhook') ||
    fileName.includes('authservice') ||
    fileName.includes('paymentcontroller') ||
    normalized.includes('firebase.json') ||
    normalized.includes('cloudbuild') ||
    normalized.includes('terraform')
  ) {
    return {
      level: 'HIGH',
      weight: 1.5,
      category: 'BACKEND_API_SERVICE',
      reason: 'Camada de backend, controle de pagamentos ou serviços de autenticação com privilégios elevados'
    };
  }

  // 3. LOW TIER (0.5x): Test suites, mocks, documentation, static assets
  if (
    normalized.includes('/test/') ||
    normalized.includes('/tests/') ||
    normalized.includes('/__tests__/') ||
    normalized.includes('/mocks/') ||
    normalized.includes('/fixtures/') ||
    normalized.includes('/docs/') ||
    fileName.endsWith('.test.ts') ||
    fileName.endsWith('.test.js') ||
    fileName.endsWith('.spec.ts') ||
    fileName.endsWith('.spec.js') ||
    fileName.endsWith('.md') ||
    fileName.endsWith('.txt') ||
    fileName.endsWith('.css') ||
    fileName.endsWith('.svg')
  ) {
    return {
      level: 'LOW',
      weight: 0.5,
      category: 'TEST_DOC_FIXTURE',
      reason: 'Ambiente de testes, fixtures estáticas ou documentação sem execução em produção'
    };
  }

  // 4. MEDIUM TIER (1.0x): General application components, client interfaces, integration scripts
  return {
    level: 'MEDIUM',
    weight: 1.0,
    category: 'APPLICATION_CLIENT',
    reason: 'Código-fonte padrão de aplicação ou componentes clientes com exposição direta'
  };
}

export interface FindingRiskEvaluation {
  riskScore: number;
  assignedSeverity: SeverityLevel;
  baseRuleScore: number;
  categoryAdjustment: number;
  entropyAdjustment: number;
  contextMultiplier: number;
  factors: string[];
}

/**
 * Calculates a dedicated 'Risk Score' (0 - 100) and assigns an authoritative severity level
 * (Critical, High, Medium, Low) to each finding based on the matched rule, secret entropy,
 * and filepath architectural exposure.
 */
export function calculateFindingRiskScore(
  rule: RegexRule,
  matchedSecret: string,
  entropy: number,
  filePath: string
): FindingRiskEvaluation {
  const factors: string[] = [];

  // 1. Base Score from Rule Severity
  let baseRuleScore = 35;
  switch (rule.severity) {
    case 'CRITICAL':
      baseRuleScore = 75;
      factors.push('Regra de Severidade Crítica (+75)');
      break;
    case 'HIGH':
      baseRuleScore = 55;
      factors.push('Regra de Alta Severidade (+55)');
      break;
    case 'MEDIUM':
      baseRuleScore = 35;
      factors.push('Regra de Severidade Média (+35)');
      break;
    case 'LOW':
      baseRuleScore = 18;
      factors.push('Regra de Baixa Severidade (+18)');
      break;
    case 'INFO':
    default:
      baseRuleScore = 10;
      factors.push('Regra Informativa (+10)');
      break;
  }

  // 2. Category Adjustment
  let categoryAdjustment = 0;
  switch (rule.category) {
    case 'CLOUD_CREDENTIAL':
      categoryAdjustment = 15;
      factors.push('Credencial de Nuvem / IAM (+15)');
      break;
    case 'PRIVATE_KEY':
      categoryAdjustment = 15;
      factors.push('Chave Privada Criptográfica (+15)');
      break;
    case 'DATABASE_URI':
      categoryAdjustment = 12;
      factors.push('String de Conexão com DB (+12)');
      break;
    case 'AUTH_TOKEN':
      categoryAdjustment = 10;
      factors.push('Token de Autenticação / PAT (+10)');
      break;
    case 'PASSWORD':
      categoryAdjustment = 10;
      factors.push('Senha em Texto Plano (+10)');
      break;
    case 'API_KEY':
      categoryAdjustment = 8;
      factors.push('Chave de API Exposta (+8)');
      break;
    case 'CUSTOM_REGEX':
      categoryAdjustment = 4;
      factors.push('Regra Customizada (+4)');
      break;
    case 'API_PATH':
    default:
      categoryAdjustment = 2;
      break;
  }

  // 3. Shannon Entropy Modifier
  let entropyAdjustment = 0;
  if (entropy >= 4.5) {
    entropyAdjustment = 6;
    factors.push(`Alta Aleatoriedade Criptográfica (H=${entropy.toFixed(2)}: +6)`);
  } else if (entropy >= 4.0) {
    entropyAdjustment = 3;
    factors.push(`Entropia Elevada (H=${entropy.toFixed(2)}: +3)`);
  } else if (entropy < 2.8 && entropy > 0) {
    entropyAdjustment = -8;
    factors.push(`Baixa Entropia / Possível Mock (H=${entropy.toFixed(2)}: -8)`);
  }

  // 4. File Context Exposure Multiplier
  const fileCrit = evaluateFileCriticality(filePath);
  let contextMultiplier = 1.0;
  if (fileCrit.level === 'CRITICAL') {
    contextMultiplier = 1.25;
    factors.push('Exposição em Infraestrutura Crítica / .env (1.25x)');
  } else if (fileCrit.level === 'HIGH') {
    contextMultiplier = 1.10;
    factors.push('Exposição em Camada de Backend / API (1.10x)');
  } else if (fileCrit.level === 'LOW') {
    contextMultiplier = 0.70;
    factors.push('Ambiente de Testes / Documentação (0.70x)');
  } else {
    contextMultiplier = 1.00;
  }

  // 5. Final Score Calculation (Bounded 1 - 100)
  const rawScore = (baseRuleScore + categoryAdjustment + entropyAdjustment) * contextMultiplier;
  const riskScore = Math.min(100, Math.max(1, Math.round(rawScore)));

  // 6. Assign Dynamic Severity Level based on Matched Rule & Risk Score
  let assignedSeverity: SeverityLevel;
  if (riskScore >= 80) {
    assignedSeverity = 'CRITICAL';
  } else if (riskScore >= 60) {
    assignedSeverity = 'HIGH';
  } else if (riskScore >= 35) {
    assignedSeverity = 'MEDIUM';
  } else {
    assignedSeverity = 'LOW';
  }

  return {
    riskScore,
    assignedSeverity,
    baseRuleScore,
    categoryAdjustment,
    entropyAdjustment,
    contextMultiplier,
    factors
  };
}

/**
 * Calculates the bounded Security Impact Score (0 - 100) based on weighted finding severity and file criticality.
 * A score of 0 represents zero risk / nominal health.
 * A score of 100 represents catastrophic vulnerability exposure in critical infrastructure.
 */
export function calculateSecurityImpactScore(findings: ScanFinding[]): {
  score: number;
  totalWeightedRisk: number;
  impactLevel: 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'MODERATE' | 'LOW' | 'NOMINAL';
} {
  const activeFindings = findings.filter(f => !f.isFalsePositive);
  if (activeFindings.length === 0) {
    return {
      score: 0,
      totalWeightedRisk: 0,
      impactLevel: 'NOMINAL'
    };
  }

  const totalWeightedRisk = activeFindings.reduce((sum, f) => {
    const weight = f.weightedScore ?? ((SEVERITY_BASE_WEIGHTS[f.severity] || 5) * (f.fileCriticalityWeight || 1.0));
    return sum + weight;
  }, 0);

  // Asymptotic saturation curve mapping total risk to 0-100 bounded scale:
  // 1 - exp(-totalWeightedRisk / 55)
  const normalizedImpact = 100 * (1 - Math.exp(-totalWeightedRisk / 55));
  const score = Math.min(100, Math.max(1, Math.round(normalizedImpact)));

  let impactLevel: 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'MODERATE' | 'LOW' | 'NOMINAL';
  if (score >= 80) impactLevel = 'CRITICAL';
  else if (score >= 60) impactLevel = 'HIGH';
  else if (score >= 35) impactLevel = 'ELEVATED';
  else if (score >= 15) impactLevel = 'MODERATE';
  else if (score > 0) impactLevel = 'LOW';
  else impactLevel = 'NOMINAL';

  return {
    score,
    totalWeightedRisk: Number(totalWeightedRisk.toFixed(1)),
    impactLevel
  };
}

/**
 * Calculates Shannon Entropy of a string to detect high-randomness secrets (hashes, tokens, keys)
 */
export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

/**
 * Tests if a given relative file path matches an ignore glob or pattern
 * Supports:
 * - Folder wildcards: `tests/*`, `node_modules/*`, `vendor/**`, `tests/`
 * - Extensions: `*.test.*`, `*.test.js`, `*.spec.ts`, `*.log`
 * - Exact paths: `src/config/legacy.js`, `package-lock.json`
 * - Directory names: `tests`, `temp`, `.cache`
 */
export function matchesIgnorePattern(filePath: string, rawPattern: string): boolean {
  if (!rawPattern || !filePath) return false;
  const pattern = rawPattern.trim().replace(/\\/g, '/');
  if (!pattern || pattern.startsWith('#')) return false;

  const path = filePath.trim().replace(/\\/g, '/');
  const normalizedPath = path.toLowerCase().replace(/^\.?\//, '');
  const normalizedPattern = pattern.toLowerCase().replace(/^\.?\//, '');

  // 1. Exact path equality
  if (normalizedPath === normalizedPattern) return true;

  // 2. Folder wildcard or trailing slash: e.g., 'tests/*', 'tests/**', 'tests/'
  if (normalizedPattern.endsWith('/*') || normalizedPattern.endsWith('/**') || normalizedPattern.endsWith('/')) {
    const folderPrefix = normalizedPattern.replace(/(\/\*+|\/)$/, '');
    if (
      normalizedPath === folderPrefix ||
      normalizedPath.startsWith(folderPrefix + '/') ||
      normalizedPath.includes('/' + folderPrefix + '/')
    ) {
      return true;
    }
  }

  // 3. Simple directory name without wildcards or file dots: e.g., 'tests' or 'node_modules'
  if (!normalizedPattern.includes('*') && !normalizedPattern.includes('.')) {
    if (
      normalizedPath === normalizedPattern ||
      normalizedPath.startsWith(normalizedPattern + '/') ||
      normalizedPath.includes('/' + normalizedPattern + '/') ||
      normalizedPath.endsWith('/' + normalizedPattern)
    ) {
      return true;
    }
  }

  // 4. Extension wildcards: e.g. '*.test.*', '*.test.js', '*.log'
  if (normalizedPattern.startsWith('*.')) {
    const extOrSuffix = normalizedPattern.slice(1); // e.g. '.test.*' or '.test.js'
    if (extOrSuffix.endsWith('.*')) {
      const baseSub = extOrSuffix.slice(0, -2); // e.g. '.test'
      if (normalizedPath.includes(baseSub + '.') || normalizedPath.endsWith(baseSub)) return true;
    } else if (normalizedPath.endsWith(extOrSuffix)) {
      return true;
    }
  }

  // 5. Glob to Regex conversion for arbitrary patterns
  try {
    const escaped = normalizedPattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '.');

    const regexPattern = normalizedPattern.startsWith('/')
      ? `^${escaped}`
      : `(^|/)${escaped}`;
    const regex = new RegExp(regexPattern + '($|/)', 'i');
    if (regex.test(normalizedPath)) {
      return true;
    }
  } catch {
    if (normalizedPath.includes(normalizedPattern)) {
      return true;
    }
  }

  return false;
}

/**
 * Checks if a file path is a third-party dependency or generated artifact to be ignored
 */
export function isThirdPartyOrIgnored(
  filePath: string,
  customIgnorePatterns: string[] = []
): { isIgnored: boolean; reason?: string } {
  const normalized = filePath.replace(/\\/g, '/').toLowerCase();

  // 1. Custom user global ignore patterns take precedence
  for (const pattern of customIgnorePatterns) {
    if (matchesIgnorePattern(filePath, pattern)) {
      return { isIgnored: true, reason: `Global Ignore List (${pattern})` };
    }
  }

  // 2. Standard third-party dependency patterns
  if (normalized.includes('/node_modules/') || normalized.startsWith('node_modules/')) {
    return { isIgnored: true, reason: 'Dependência de terceiros (node_modules)' };
  }
  if (normalized.includes('/vendor/') || normalized.startsWith('vendor/')) {
    return { isIgnored: true, reason: 'Dependência de terceiros (vendor)' };
  }
  if (normalized.includes('/bower_components/')) {
    return { isIgnored: true, reason: 'Dependência de terceiros (bower_components)' };
  }
  if (normalized.includes('/.git/') || normalized.startsWith('.git/')) {
    return { isIgnored: true, reason: 'Diretório interno Git' };
  }
  if (
    normalized.includes('/dist/') ||
    normalized.startsWith('dist/') ||
    normalized.includes('/build/') ||
    normalized.startsWith('build/') ||
    normalized.includes('/out/')
  ) {
    return { isIgnored: true, reason: 'Artefato compilado de build' };
  }
  if (normalized.endsWith('.min.js') || normalized.endsWith('.bundle.js') || normalized.includes('.chunk.js')) {
    return { isIgnored: true, reason: 'Arquivo minificado de terceiro ou bundle' };
  }
  if (
    normalized.endsWith('package-lock.json') ||
    normalized.endsWith('yarn.lock') ||
    normalized.endsWith('pnpm-lock.yaml')
  ) {
    return { isIgnored: true, reason: 'Lockfile de gerenciador de pacotes' };
  }
  if (normalized.includes('/coverage/') || normalized.includes('/.cache/')) {
    return { isIgnored: true, reason: 'Arquivo temporário ou relatório de testes' };
  }

  return { isIgnored: false };
}

/**
 * Safely masks a discovered secret to prevent accidental leakage in reports/UI
 */
export function maskSecret(secret: string): string {
  if (!secret) return '';
  const clean = secret.trim().replace(/^['"]|['"]$/g, '');
  if (clean.length <= 8) {
    return '••••••••';
  }
  const prefix = clean.slice(0, 4);
  const suffix = clean.slice(-4);
  const asterisks = '•'.repeat(Math.min(16, Math.max(6, clean.length - 8)));
  return `${prefix}${asterisks}${suffix}`;
}

/**
 * Extracts line and column from file index
 */
function getLineAndColumn(content: string, index: number): { line: number; column: number; lineContent: string } {
  const upToIndex = content.substring(0, index);
  const lines = upToIndex.split('\n');
  const line = lines.length;
  const column = lines[lines.length - 1].length + 1;

  const allLines = content.split('\n');
  const lineContent = allLines[line - 1] || '';

  return { line, column, lineContent };
}

/**
 * Core scanning function that processes files against active regex rules
 */
export function scanSourceFiles(
  files: ScannedFile[],
  rules: RegexRule[],
  customIgnorePatterns: string[] = [],
  onLog?: (event: AuditLogEvent) => void
): ScanReport {
  const startTime = performance.now();
  const scanId = 'scan-' + Math.random().toString(36).substring(2, 9);
  const findings: ScanFinding[] = [];
  const apiEndpoints: ApiEndpointFinding[] = [];
  const allSourceMaps: SourceMapFinding[] = [];
  const allCloudBuckets: CloudBucketFinding[] = [];
  const allJwtTokens: JwtTokenFinding[] = [];
  const allDependencies: BundledDependencyFinding[] = [];
  const allDangerousSinks: DangerousSinkFinding[] = [];

  let scannedCount = 0;
  let ignoredCount = 0;

  onLog?.({
    id: `log-${Date.now()}-0`,
    timestamp: new Date().toLocaleTimeString(),
    type: 'SCAN_START',
    message: `Iniciando análise estática em ${files.length} arquivo(s)...`
  });

  const activeRules = rules.filter(r => r.enabled);

  for (const file of files) {
    const ignoreCheck = isThirdPartyOrIgnored(file.path, customIgnorePatterns);
    if (ignoreCheck.isIgnored) {
      ignoredCount++;
      file.isIgnored = true;
      file.ignoreReason = ignoreCheck.reason;
      onLog?.({
        id: `log-${Date.now()}-${file.name}`,
        timestamp: new Date().toLocaleTimeString(),
        type: 'DEP_IGNORED',
        message: `Ignorando dependência: ${file.path} (${ignoreCheck.reason})`
      });
      continue;
    }

    scannedCount++;
    file.isIgnored = false;
    file.findingsCount = 0;

    // Scan for secrets with regex rules
    for (const rule of activeRules) {
      let regex: RegExp;
      try {
        let pattern = rule.pattern;
        let flags = rule.flags || 'g';
        // Strip any PCRE-style inline (?i) prefix and add 'i' flag
        if (pattern.startsWith('(?i)')) {
          pattern = pattern.slice(4);
          if (!flags.includes('i')) flags += 'i';
        }
        // ensure global flag exists for matching all occurrences
        const effectiveFlags = flags.includes('g') ? flags : flags + 'g';
        regex = new RegExp(pattern, effectiveFlags);
      } catch (err) {
        console.warn(`Invalid regex pattern in rule ${rule.name}:`, err);
        continue;
      }

      let match: RegExpExecArray | null;
      while ((match = regex.exec(file.content)) !== null) {
        const fullMatch = match[0];
        if (!fullMatch) break;

        const entropy = calculateEntropy(fullMatch);
        if (rule.minEntropy && entropy < rule.minEntropy) {
          // Skip low-entropy false positives
          continue;
        }

        const { line, column, lineContent } = getLineAndColumn(file.content, match.index);
        const criticalityInfo = evaluateFileCriticality(file.path);
        
        // Calculate dynamic Risk Score (0-100) and assign authoritative severity level based on the matched rule
        const riskEval = calculateFindingRiskScore(rule, fullMatch, entropy, file.path);
        const baseSeverityWeight = SEVERITY_BASE_WEIGHTS[riskEval.assignedSeverity] || 5;
        const weightedScore = Number((baseSeverityWeight * criticalityInfo.weight).toFixed(1));

        const findingId = `finding-${findings.length + 1}`;
        const finding: ScanFinding = {
          id: findingId,
          ruleId: rule.id,
          ruleName: rule.name,
          category: rule.category,
          severity: riskEval.assignedSeverity,
          file: file.path,
          line,
          column,
          snippet: lineContent.trim(),
          matchedSecret: fullMatch,
          maskedSecret: maskSecret(fullMatch),
          entropy,
          description: rule.description,
          remediation: rule.remediation,
          timestamp: new Date().toISOString(),
          fileCriticality: criticalityInfo.level,
          fileCriticalityWeight: criticalityInfo.weight,
          weightedScore,
          riskScore: riskEval.riskScore,
          riskScoreDetails: {
            baseRuleScore: riskEval.baseRuleScore,
            categoryAdjustment: riskEval.categoryAdjustment,
            entropyAdjustment: riskEval.entropyAdjustment,
            contextMultiplier: riskEval.contextMultiplier,
            finalScore: riskEval.riskScore,
            assignedSeverity: riskEval.assignedSeverity,
            factors: riskEval.factors
          }
        };

        findings.push(finding);
        file.findingsCount = (file.findingsCount || 0) + 1;

        if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
          onLog?.({
            id: `log-${Date.now()}-${findingId}`,
            timestamp: new Date().toLocaleTimeString(),
            type: 'SECRET_DETECTED',
            severity: finding.severity,
            message: `[ALERTA ${finding.severity}] ${rule.name} detectado em ${file.path}:${line} (Risk Score: ${riskEval.riskScore}/100 • ${riskEval.assignedSeverity})`
          });
        }
      }
    }

    // 1. LinkFinder Engine: Deep reconnaissance of endpoints, parameters, methods, and full URLs
    const linkFinderEndpoints = extractLinkFinderEndpoints(file.path, file.content);
    for (const ep of linkFinderEndpoints) {
      const exists = apiEndpoints.some(
        existing => existing.file === ep.file && existing.path === ep.path && existing.method === ep.method
      );
      if (!exists) {
        apiEndpoints.push(ep);
      }
    }

    // 2. JS-Miner Engine: Source Maps, Cloud Storage Buckets, JWTs, Bundled Libraries & DOM Sinks
    const jsMinerRes = analyzeWithJsMiner(file.path, file.content);
    allSourceMaps.push(...jsMinerRes.sourceMaps);
    allCloudBuckets.push(...jsMinerRes.cloudBuckets);
    allJwtTokens.push(...jsMinerRes.jwtTokens);
    allDependencies.push(...jsMinerRes.dependencies);
    allDangerousSinks.push(...jsMinerRes.dangerousSinks);
  }

  // Construct JS Miner Results
  const jsMiner: JsMinerResults = {
    sourceMaps: allSourceMaps,
    cloudBuckets: allCloudBuckets,
    jwtTokens: allJwtTokens,
    dependencies: allDependencies,
    dangerousSinks: allDangerousSinks,
    totalAssetsCount:
      allSourceMaps.length +
      allCloudBuckets.length +
      allJwtTokens.length +
      allDependencies.length +
      allDangerousSinks.length
  };

  // 3. Data Flow Graph Engine: Map endpoints -> consumer functions -> dangerous sinks
  const dataFlowGraph = buildDataFlowGraph(files, apiEndpoints, allDangerousSinks);

  // Calculate Metrics
  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = findings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter(f => f.severity === 'LOW').length;
  const infoCount = findings.filter(f => f.severity === 'INFO').length;

  // Compliance score: base 100, deduction by severity
  const deduction = (criticalCount * 25) + (highCount * 12) + (mediumCount * 5) + (lowCount * 2);
  const securityScore = Math.max(0, Math.min(100, 100 - deduction));

  // Security Impact Score (0 - 100): Weighted risk scoring system based on finding severity & file criticality
  const { score: securityImpactScore, totalWeightedRisk, impactLevel } = calculateSecurityImpactScore(findings);

  // File Criticality Distribution across findings
  const fileCriticalityMap = new Map<string, FileCriticalityLevel>();
  for (const f of findings) {
    const crit = evaluateFileCriticality(f.file);
    fileCriticalityMap.set(f.file, crit.level);
  }
  const criticalityDistribution = {
    criticalFiles: Array.from(fileCriticalityMap.values()).filter(lvl => lvl === 'CRITICAL').length,
    highFiles: Array.from(fileCriticalityMap.values()).filter(lvl => lvl === 'HIGH').length,
    mediumFiles: Array.from(fileCriticalityMap.values()).filter(lvl => lvl === 'MEDIUM').length,
    lowFiles: Array.from(fileCriticalityMap.values()).filter(lvl => lvl === 'LOW').length,
  };

  const totalEntropy = findings.reduce((acc, curr) => acc + curr.entropy, 0);
  const averageEntropy = findings.length > 0 ? Number((totalEntropy / findings.length).toFixed(2)) : 0;

  const totalRiskScore = findings.reduce((acc, curr) => acc + (curr.riskScore ?? 0), 0);
  const averageRiskScore = findings.length > 0 ? Math.round(totalRiskScore / findings.length) : 0;
  const maxRiskScore = findings.reduce((max, curr) => Math.max(max, curr.riskScore ?? 0), 0);

  const durationMs = Math.max(1, Math.round(performance.now() - startTime));

  onLog?.({
    id: `log-${Date.now()}-end`,
    timestamp: new Date().toLocaleTimeString(),
    type: 'SCAN_COMPLETE',
    durationMs,
    message: `Scan concluído em ${durationMs}ms. Security Impact Score: ${securityImpactScore}/100 (${impactLevel}). Encontrados ${findings.length} segredo(s) em ${scannedCount} arquivo(s) analisado(s).`
  });

  return {
    id: scanId,
    timestamp: new Date().toISOString(),
    target: 'Workspace Repository',
    totalFiles: files.length,
    scannedFilesCount: scannedCount,
    ignoredFilesCount: ignoredCount,
    findings,
    apiEndpoints,
    jsMiner,
    dataFlowGraph,
    metrics: {
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      securityScore,
      securityImpactScore,
      impactLevel,
      totalWeightedRisk,
      criticalityDistribution,
      averageEntropy,
      averageRiskScore,
      maxRiskScore,
      linkFinderTotalEndpoints: apiEndpoints.length,
      jsMinerTotalAssets: jsMiner.totalAssetsCount,
      jsMinerCloudBucketsCount: jsMiner.cloudBuckets.length,
      jsMinerSourceMapsCount: jsMiner.sourceMaps.length,
      jsMinerDangerousSinksCount: jsMiner.dangerousSinks.length
    },
    durationMs
  };
}

/**
 * Exports report as structured JSON suitable for CI/CD integrations
 */
export function exportToJson(report: ScanReport, pretty = true): string {
  return JSON.stringify(report, null, pretty ? 2 : 0);
}

/**
 * Exports findings as CSV for compliance spreadsheets
 */
export function exportToCsv(report: ScanReport): string {
  const headers = ['ID', 'Severity', 'Rule Name', 'Category', 'File', 'Line', 'Column', 'Entropy', 'Masked Secret', 'Remediation'];
  const rows = report.findings.map(f => [
    f.id,
    f.severity,
    `"${f.ruleName.replace(/"/g, '""')}"`,
    f.category,
    `"${f.file.replace(/"/g, '""')}"`,
    f.line,
    f.column,
    f.entropy,
    `"${f.maskedSecret.replace(/"/g, '""')}"`,
    `"${f.remediation.replace(/"/g, '""')}"`
  ]);

  return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
}

/**
 * Exports report to SARIF 2.1.0 standard (OASIS standard consumed natively by GitHub Code Scanning)
 */
export function exportToSarif(report: ScanReport): string {
  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "SecScan",
            semanticVersion: "1.0.0",
            informationUri: "https://github.com/secscan/secscan",
            rules: Array.from(new Set(report.findings.map(f => f.ruleId))).map(ruleId => {
              const finding = report.findings.find(f => f.ruleId === ruleId)!;
              return {
                id: finding.ruleId,
                name: finding.ruleName,
                shortDescription: { text: finding.description },
                help: { text: finding.remediation },
                defaultConfiguration: {
                  level: finding.severity === 'CRITICAL' || finding.severity === 'HIGH' ? 'error' : 'warning'
                }
              };
            })
          }
        },
        results: report.findings.map(finding => ({
          ruleId: finding.ruleId,
          level: finding.severity === 'CRITICAL' || finding.severity === 'HIGH' ? 'error' : 'warning',
          message: {
            text: `Exposed secret detected: ${finding.ruleName}. Value: ${finding.maskedSecret}`
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: finding.file
                },
                region: {
                  startLine: finding.line,
                  startColumn: finding.column,
                  snippet: {
                    text: finding.snippet
                  }
                }
              }
            }
          ]
        }))
      }
    ]
  };

  return JSON.stringify(sarif, null, 2);
}

/**
 * Generates an executive Markdown audit report
 */
export function exportToMarkdown(report: ScanReport): string {
  return `# Relatório de Auditoria de Segurança - SecScan

**Data do Scan:** ${new Date(report.timestamp).toLocaleString('pt-BR')}
**Score de Conformidade:** ${report.metrics.securityScore}/100
**Arquivos Analisados:** ${report.scannedFilesCount} (Ignorados: ${report.ignoredFilesCount})
**Total de Vulnerabilidades:** ${report.findings.length}

---

## 📊 Sumário de Métricas

| Severidade | Quantidade |
|---|---|
| 🚨 CRITICAL | ${report.metrics.criticalCount} |
| ⚠️ HIGH | ${report.metrics.highCount} |
| 🟡 MEDIUM | ${report.metrics.mediumCount} |
| ℹ️ LOW / INFO | ${report.metrics.lowCount + report.metrics.infoCount} |

---

## 🔍 Segredos Detectados

${report.findings.length === 0 ? '_Nenhum segredo encontrado! Repositório seguro._' : report.findings.map(f => `
### [${f.severity}] ${f.ruleName}
- **Arquivo:** \`${f.file}\` (Linha ${f.line})
- **Valor Mascarado:** \`${f.maskedSecret}\`
- **Entropia de Shannon:** ${f.entropy}
- **Descrição:** ${f.description}
- **Remediação Recomendada:** ${f.remediation}
`).join('\n')}

---

## 🌐 Endpoints de API Mapeados (${report.apiEndpoints.length})
${report.apiEndpoints.map(e => `- \`${e.method || 'GET'}\` \`${e.path}\` em \`${e.file}:${e.line}\` ${e.isInternalOrAdmin ? '**(Sensível/Admin)**' : ''}`).join('\n')}

_Relatório gerado automaticamente por SecScan SAST Engine._
`;
}
