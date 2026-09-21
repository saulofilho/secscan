/**
 * Gitignore Security Auditor & Working Directory Inspector
 * 
 * Verifies if the current repository/workspace has a valid .gitignore file,
 * evaluates it against security best practices (OWASP, GitHub, GitGuardian guidelines),
 * and identifies files in the working directory that are or should be ignored to prevent
 * accidental leakage of sensitive secrets, keys, and build artifacts.
 */

export type GitignoreSecurityCategory = 
  | 'ENVIRONMENT' 
  | 'PRIVATE_KEY' 
  | 'SSH_KEY' 
  | 'CLOUD_CREDENTIAL' 
  | 'TOKEN_SECRET' 
  | 'LOCAL_DATABASE' 
  | 'LOG_ARTIFACT' 
  | 'BUILD_ARTIFACT' 
  | 'SYSTEM_CACHE';

export type GitignoreAuditStatus = 'VALID' | 'INCOMPLETE' | 'MISSING';

export interface BestPracticeRuleDefinition {
  id: string;
  category: GitignoreSecurityCategory;
  categoryTitle: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  securityReason: string;
  patterns: string[];
  exceptions?: string[];
  suggestedRuleSnippet: string;
}

export interface IgnoredFileAuditItem {
  id: string;
  fileName: string;
  filePath: string;
  category: GitignoreSecurityCategory;
  categoryTitle: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  securityImpact: string;
  isCoveredByGitignore: boolean;
  coveredByRule?: string;
  suggestedRule: string;
  status: 'UNPROTECTED_EXPOSED' | 'COVERED_BY_GITIGNORE';
  fileSize?: number;
}

export interface CategoryCoverageStatus {
  category: GitignoreSecurityCategory;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  isCovered: boolean;
  matchedRules: string[];
  suggestedPatterns: string[];
}

export interface GitignoreAuditResult {
  hasGitignore: boolean;
  isValid: boolean;
  status: GitignoreAuditStatus;
  statusLabel: string;
  summaryMessage: string;
  currentRulesCount: number;
  existingGitignoreContent: string;
  source: 'WORKSPACE' | 'DISK_REPOSITORY';
  
  // Categorized coverage
  categoriesCoverage: CategoryCoverageStatus[];
  missingCriticalCategories: CategoryCoverageStatus[];
  
  // Files in working directory that should be ignored
  ignoredFiles: IgnoredFileAuditItem[];
  unprotectedExposedFiles: IgnoredFileAuditItem[];
  coveredFiles: IgnoredFileAuditItem[];
  
  // Statistics
  stats: {
    totalWorkingFiles: number;
    sensitiveFilesCount: number;
    unprotectedExposedCount: number;
    properlyCoveredCount: number;
    securityScore: number; // 0 - 100
  };
  
  // Recommendations
  recommendedGitignore: string;
  missingRulesToAppend: string;
}

/**
 * Industry-standard security ignore definitions
 */
export const SECURITY_BEST_PRACTICE_RULES: BestPracticeRuleDefinition[] = [
  {
    id: 'sec-env',
    category: 'ENVIRONMENT',
    categoryTitle: 'Variáveis de Ambiente & Segredos (.env)',
    severity: 'CRITICAL',
    description: 'Arquivos com tokens de API, strings de conexão e senhas mestras de desenvolvimento.',
    securityReason: 'Arquivos .env contêm segredos em texto puro. Comitá-los expõe senhas, chaves de API e tokens de acesso a todos com leitura do repositório.',
    patterns: ['.env', '.env.*', '.env*.local', '*.env'],
    exceptions: ['!.env.example', '!.env.template'],
    suggestedRuleSnippet: `# Variáveis de ambiente & segredos locais\n.env\n.env.*\n.env*.local\n!.env.example\n!.env.template`
  },
  {
    id: 'sec-private-keys',
    category: 'PRIVATE_KEY',
    categoryTitle: 'Chaves Privadas & Certificados SSL/TLS',
    severity: 'CRITICAL',
    description: 'Chaves criptográficas privadas (.pem, .key, .pfx, .p12).',
    securityReason: 'Permite personificar servidores, descriptografar tráfego TLS/HTTPS em trânsito e comprometer assinaturas digitais.',
    patterns: ['*.pem', '*.key', '*.pkcs12', '*.pfx', '*.p12', '*.crt', '*.cer'],
    suggestedRuleSnippet: `# Chaves privadas e certificados criptográficos\n*.pem\n*.key\n*.pfx\n*.p12\n*.pkcs12\n*.crt\n*.cer`
  },
  {
    id: 'sec-ssh-keys',
    category: 'SSH_KEY',
    categoryTitle: 'Chaves de Identidade SSH',
    severity: 'CRITICAL',
    description: 'Chaves SSH locais de autenticação (id_rsa, id_ed25519, etc.).',
    securityReason: 'Concede acesso shell direto e não supervisionado a servidores, bastions e instâncias de nuvem.',
    patterns: ['id_rsa', 'id_rsa*', 'id_ecdsa*', 'id_ed25519*', 'id_dsa*'],
    suggestedRuleSnippet: `# Chaves de autenticação SSH\nid_rsa\nid_rsa*\nid_ecdsa*\nid_ed25519*\nid_dsa*`
  },
  {
    id: 'sec-cloud-credentials',
    category: 'CLOUD_CREDENTIAL',
    categoryTitle: 'Contas de Serviço & Credenciais de Nuvem',
    severity: 'CRITICAL',
    description: 'Arquivos JSON de contas de serviço da AWS, Google Cloud, Firebase ou Azure.',
    securityReason: 'Arquivos como serviceAccountKey.json concedem privilégios de administrador de nuvem sobre bancos de dados, clusters e buckets.',
    patterns: [
      '*credentials*.json', 
      '*serviceAccount*.json', 
      '*service[-_]?account*.json',
      '*client_secret*.json', 
      'google-services.json',
      'amplifyconfiguration*.json'
    ],
    suggestedRuleSnippet: `# Credenciais de Nuvem e Contas de Serviço\ncredentials.json\n*credentials*.json\nserviceAccountKey*.json\n*service[-_]?account*.json\nclient_secret*.json\ngoogle-services.json`
  },
  {
    id: 'sec-token-files',
    category: 'TOKEN_SECRET',
    categoryTitle: 'Pastas e Arquivos de Segredos Locais',
    severity: 'CRITICAL',
    description: 'Pastas dedicadas a segredos ou arquivos com extensões .secret ou .token.',
    securityReason: 'Muitos scripts salvam tokens de sessão e cookies em pastas locais como secrets/ ou .secrets/.',
    patterns: ['*.secret', '*.token', 'secrets/', '.secrets/'],
    suggestedRuleSnippet: `# Arquivos e diretórios de segredos\n*.secret\n*.token\nsecrets/\n.secrets/`
  },
  {
    id: 'sec-databases',
    category: 'LOCAL_DATABASE',
    categoryTitle: 'Bancos de Dados Locais & Dumps SQL',
    severity: 'HIGH',
    description: 'Arquivos SQLite (.db, .sqlite) e backups SQL exportados (.sql, .dump).',
    securityReason: 'Dumps de banco de dados podem conter tabelas com CPFs, emails, senhas criptografadas e dados confidenciais (LGPD/GDPR).',
    patterns: ['*.sqlite', '*.sqlite3', '*.db', '*.db3', '*.sql', '*.dump', 'dump.rdb'],
    suggestedRuleSnippet: `# Bancos de dados locais e backups\n*.sqlite\n*.sqlite3\n*.db\n*.db3\n*.dump\ndump.rdb`
  },
  {
    id: 'sec-logs',
    category: 'LOG_ARTIFACT',
    categoryTitle: 'Logs de Aplicação & Relatórios de Erro',
    severity: 'MEDIUM',
    description: 'Logs operacionais (.log) e relatórios de crash de pacotes.',
    securityReason: 'Logs de depuração frequentemente capturam requisições HTTP completas contendo cabeçalhos de autorização, senhas e tokens.',
    patterns: ['*.log', 'npm-debug.log*', 'yarn-debug.log*', 'yarn-error.log*', 'pnpm-debug.log*', 'core.*'],
    suggestedRuleSnippet: `# Logs e dumps de memória\n*.log\nnpm-debug.log*\nyarn-debug.log*\nyarn-error.log*\npnpm-debug.log*\ncore.*`
  },
  {
    id: 'sec-build-artifacts',
    category: 'BUILD_ARTIFACT',
    categoryTitle: 'Dependências & Artefatos de Build',
    severity: 'LOW',
    description: 'Diretórios de dependências (node_modules) e saídas de compilação (dist, build).',
    securityReason: 'Polui o controle de versão com centenas de megabytes e pode incluir pacotes com vulnerabilidades conhecidas.',
    patterns: ['node_modules/', 'dist/', 'build/', 'out/', '.next/', 'coverage/'],
    suggestedRuleSnippet: `# Dependências e builds compilados\nnode_modules/\ndist/\nbuild/\nout/\n.next/\ncoverage/`
  },
  {
    id: 'sec-system-cache',
    category: 'SYSTEM_CACHE',
    categoryTitle: 'Arquivos de Sistema Operacional & IDE',
    severity: 'LOW',
    description: 'Arquivos de índice do macOS (.DS_Store), Windows (Thumbs.db) ou configs de IDE.',
    securityReason: 'Pode vazar caminhos de arquivos absolutos locais e nomes de usuários do sistema operacional.',
    patterns: ['.DS_Store', 'Thumbs.db', '.idea/', '.vscode/*', '!.vscode/settings.json', '*.swp'],
    suggestedRuleSnippet: `# Sistema Operacional e IDEs\n.DS_Store\nThumbs.db\n.idea/\n.vscode/*\n!.vscode/settings.json\n*.swp`
  }
];

/**
 * Checks if a single string matches a glob-like pattern
 */
export function matchesGitignorePattern(filePath: string, rawPattern: string): boolean {
  const pattern = rawPattern.trim();
  if (!pattern || pattern.startsWith('#')) return false;

  const normalizedPath = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
  const fileName = normalizedPath.split('/').pop() || normalizedPath;

  // Exact file name match
  if (pattern === normalizedPath || pattern === fileName) {
    return true;
  }

  // Directory match (ends with /)
  if (pattern.endsWith('/')) {
    const dirPattern = pattern.slice(0, -1);
    if (normalizedPath === dirPattern || normalizedPath.startsWith(dirPattern + '/') || normalizedPath.includes('/' + dirPattern + '/')) {
      return true;
    }
    if (fileName === dirPattern) {
      return true;
    }
  }

  // Convert simple gitignore pattern to Regex
  // Escape regex special chars except * and ?
  let regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '.*')
    .replace(/(?<!\.)\*/g, '[^/]*')
    .replace(/\?/g, '[^/]');

  // If pattern does not contain slash, it matches in any directory or the filename directly
  if (!pattern.includes('/')) {
    try {
      const regex = new RegExp(`(^|/)${regexStr}$`, 'i');
      if (regex.test(normalizedPath) || regex.test(fileName)) {
        return true;
      }
    } catch {
      // Fallback simple substring
      if (pattern.startsWith('*.') && fileName.endsWith(pattern.slice(1))) return true;
    }
  } else {
    // Anchored or path pattern
    const anchored = pattern.startsWith('/') ? regexStr.slice(1) : regexStr;
    try {
      const regex = new RegExp(`^${anchored}$`, 'i');
      if (regex.test(normalizedPath)) {
        return true;
      }
    } catch {
      // Ignore invalid regex
    }
  }

  // Specific common cases
  if (pattern === '.env' && (fileName === '.env' || fileName.startsWith('.env.'))) return true;
  if (pattern === '.env*' && fileName.startsWith('.env')) return true;
  if (pattern === '*.pem' && fileName.endsWith('.pem')) return true;
  if (pattern === '*.key' && fileName.endsWith('.key')) return true;
  if (pattern === '*.p12' && fileName.endsWith('.p12')) return true;
  if (pattern === '*.pfx' && fileName.endsWith('.pfx')) return true;
  if (pattern === '*.log' && fileName.endsWith('.log')) return true;
  if (pattern === '*.sqlite' && (fileName.endsWith('.sqlite') || fileName.endsWith('.sqlite3'))) return true;
  if (pattern === '*.db' && fileName.endsWith('.db')) return true;
  if (pattern === 'node_modules/' && normalizedPath.includes('node_modules')) return true;

  return false;
}

/**
 * Evaluates whether a file is ignored according to a list of .gitignore rules
 */
export function isPathIgnoredByRules(filePath: string, rules: string[]): { isIgnored: boolean; matchedRule?: string } {
  let isIgnored = false;
  let matchedRule: string | undefined = undefined;

  for (const rawLine of rules) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    // Negation rule (e.g. !.env.example)
    if (line.startsWith('!')) {
      const unignorePattern = line.slice(1);
      if (matchesGitignorePattern(filePath, unignorePattern)) {
        isIgnored = false;
        matchedRule = undefined;
      }
      continue;
    }

    if (matchesGitignorePattern(filePath, line)) {
      isIgnored = true;
      matchedRule = line;
    }
  }

  return { isIgnored, matchedRule };
}

/**
 * Generates the complete, security-hardened standard .gitignore template
 */
export function generateRecommendedGitignore(): string {
  return `# ==============================================================================
# SECSCAN - .gitignore Padronizado por Boas Práticas de Segurança (OWASP / GitHub)
# Protege variáveis de ambiente, chaves privadas, dumps de banco e credenciais de nuvem.
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. VARIÁVEIS DE AMBIENTE & SEGREDOS (CRÍTICO)
# ------------------------------------------------------------------------------
.env
.env.*
.env*.local
!.env.example
!.env.template

# ------------------------------------------------------------------------------
# 2. CHAVES PRIVADAS, CERTIFICADOS & SSH (CRÍTICO)
# ------------------------------------------------------------------------------
*.pem
*.key
*.pfx
*.p12
*.pkcs12
*.crt
*.cer
id_rsa
id_rsa*
id_ecdsa*
id_ed25519*
id_dsa*

# ------------------------------------------------------------------------------
# 3. CONTAS DE SERVIÇO & CREDENCIAIS DE NUVEM (CRÍTICO)
# ------------------------------------------------------------------------------
credentials.json
*credentials*.json
serviceAccountKey*.json
*service[-_]?account*.json
client_secret*.json
google-services.json
amplifyconfiguration*.json
*.secret
*.token
secrets/
.secrets/

# ------------------------------------------------------------------------------
# 4. BANCOS DE DADOS LOCAIS & DUMPS SQL (ALTO)
# ------------------------------------------------------------------------------
*.sqlite
*.sqlite3
*.db
*.db3
*.dump
dump.rdb

# ------------------------------------------------------------------------------
# 5. LOGS OPERACIONAIS & DUMPS DE CRASH (MÉDIO)
# ------------------------------------------------------------------------------
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*
pnpm-debug.log*
core.*

# ------------------------------------------------------------------------------
# 6. DEPENDÊNCIAS & DIRETÓRIOS DE BUILD (BAIXO)
# ------------------------------------------------------------------------------
node_modules/
dist/
build/
out/
.next/
coverage/

# ------------------------------------------------------------------------------
# 7. METADADOS DE SISTEMA OPERACIONAL & IDES (BAIXO)
# ------------------------------------------------------------------------------
.DS_Store
Thumbs.db
.idea/
.vscode/*
!.vscode/settings.json
*.swp
`;
}

/**
 * Main utility function to audit gitignore and inspect working directory files.
 * Can be called with files from the workspace or from the filesystem.
 */
export function auditGitignoreSecurity(options: {
  gitignoreContent?: string;
  files: Array<{ name: string; path?: string; content?: string; size?: number }>;
  source?: 'WORKSPACE' | 'DISK_REPOSITORY';
}): GitignoreAuditResult {
  const source = options.source || 'WORKSPACE';
  const rawFiles = options.files || [];

  // 1. Locate .gitignore content
  let gitignoreContent = options.gitignoreContent;
  if (!gitignoreContent) {
    const gitignoreFile = rawFiles.find(f => {
      const n = (f.name || '').trim();
      const p = (f.path || '').trim();
      return n === '.gitignore' || p === '.gitignore' || p.endsWith('/.gitignore');
    });
    if (gitignoreFile && gitignoreFile.content) {
      gitignoreContent = gitignoreFile.content;
    }
  }

  const hasGitignore = Boolean(gitignoreContent && gitignoreContent.trim().length > 0);
  const existingGitignoreContent = gitignoreContent || '';

  // 2. Parse active rules from .gitignore
  const existingRules = existingGitignoreContent
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0 && !line.startsWith('#'));

  // 3. Evaluate Category Coverage
  const categoriesCoverage: CategoryCoverageStatus[] = SECURITY_BEST_PRACTICE_RULES.map(cat => {
    const matchedRules: string[] = [];
    
    // Check if any rule in the current gitignore addresses this category
    for (const rule of existingRules) {
      for (const pattern of cat.patterns) {
        if (rule === pattern || rule === pattern.replace(/\/$/, '') || rule.includes(pattern.replace(/\*/g, ''))) {
          matchedRules.push(rule);
          break;
        }
      }
    }

    return {
      category: cat.category,
      title: cat.categoryTitle,
      severity: cat.severity,
      isCovered: matchedRules.length > 0,
      matchedRules: Array.from(new Set(matchedRules)),
      suggestedPatterns: cat.patterns
    };
  });

  const missingCriticalCategories = categoriesCoverage.filter(
    c => !c.isCovered && (c.severity === 'CRITICAL' || c.severity === 'HIGH')
  );

  // 4. Scan Working Directory Files against Best Practices and Current Rules
  const ignoredFiles: IgnoredFileAuditItem[] = [];

  for (const file of rawFiles) {
    const filePath = file.path || file.name;
    const fileName = file.name || filePath.split('/').pop() || filePath;

    // Do not audit the .gitignore file itself
    if (fileName === '.gitignore') continue;

    // Check if the file is covered by the current .gitignore
    const checkResult = hasGitignore 
      ? isPathIgnoredByRules(filePath, existingRules)
      : { isIgnored: false, matchedRule: undefined };

    // Check if this file triggers any security best practice rule
    for (const ruleDef of SECURITY_BEST_PRACTICE_RULES) {
      // Check exceptions first (e.g. .env.example)
      let isException = false;
      if (ruleDef.exceptions) {
        for (const exc of ruleDef.exceptions) {
          const excPattern = exc.startsWith('!') ? exc.slice(1) : exc;
          if (matchesGitignorePattern(filePath, excPattern)) {
            isException = true;
            break;
          }
        }
      }

      if (isException) continue;

      let matchedPattern: string | undefined = undefined;
      for (const pattern of ruleDef.patterns) {
        if (matchesGitignorePattern(filePath, pattern)) {
          matchedPattern = pattern;
          break;
        }
      }

      if (matchedPattern) {
        const isCovered = checkResult.isIgnored;
        
        ignoredFiles.push({
          id: `audit-ign-${file.name}-${ruleDef.id}-${Date.now()}`,
          fileName,
          filePath,
          category: ruleDef.category,
          categoryTitle: ruleDef.categoryTitle,
          severity: ruleDef.severity,
          reason: ruleDef.securityReason,
          securityImpact: ruleDef.description,
          isCoveredByGitignore: isCovered,
          coveredByRule: checkResult.matchedRule,
          suggestedRule: matchedPattern,
          status: isCovered ? 'COVERED_BY_GITIGNORE' : 'UNPROTECTED_EXPOSED',
          fileSize: file.size
        });
        break; // Match first dominant category
      }
    }
  }

  const unprotectedExposedFiles = ignoredFiles.filter(f => !f.isCoveredByGitignore);
  const coveredFiles = ignoredFiles.filter(f => f.isCoveredByGitignore);

  // 5. Determine Overall Status & Hygiene Score
  let status: GitignoreAuditStatus = 'VALID';
  let statusLabel = 'Conforme';
  let summaryMessage = 'O repositório possui .gitignore configurado e cobre as principais regras de segurança.';

  if (!hasGitignore) {
    status = 'MISSING';
    statusLabel = 'Ausente';
    summaryMessage = 'Nenhum arquivo .gitignore foi detectado no repositório. Arquivos sensíveis podem ser commitados acidentalmente.';
  } else if (unprotectedExposedFiles.length > 0 || missingCriticalCategories.length > 0) {
    status = 'INCOMPLETE';
    statusLabel = 'Incompleto';
    if (unprotectedExposedFiles.length > 0) {
      summaryMessage = `Atenção: ${unprotectedExposedFiles.length} arquivo(s) sensível(is) no diretório de trabalho NÃO estão protegidos pelo .gitignore atual.`;
    } else {
      summaryMessage = `O .gitignore existe, mas faltam ${missingCriticalCategories.length} categoria(s) crítica(s) de proteção recomendadas por boas práticas.`;
    }
  }

  // Calculate score (0-100)
  let securityScore = 0;
  if (hasGitignore) securityScore += 30;
  
  // Category coverage contribution (up to 45 pts)
  const coveredCount = categoriesCoverage.filter(c => c.isCovered).length;
  securityScore += Math.round((coveredCount / Math.max(1, categoriesCoverage.length)) * 45);

  // Absence of unprotected files (up to 25 pts)
  if (unprotectedExposedFiles.length === 0) {
    securityScore += 25;
  } else {
    securityScore += Math.max(0, 25 - (unprotectedExposedFiles.length * 10));
  }
  securityScore = Math.min(100, Math.max(0, securityScore));

  // 6. Build missing rules snippet to append
  const missingRulesSnippets: string[] = [];
  for (const cat of missingCriticalCategories) {
    const def = SECURITY_BEST_PRACTICE_RULES.find(r => r.category === cat.category);
    if (def) {
      missingRulesSnippets.push(def.suggestedRuleSnippet);
    }
  }
  const missingRulesToAppend = missingRulesSnippets.join('\n\n');

  return {
    hasGitignore,
    isValid: hasGitignore && existingRules.length > 0,
    status,
    statusLabel,
    summaryMessage,
    currentRulesCount: existingRules.length,
    existingGitignoreContent,
    source,
    categoriesCoverage,
    missingCriticalCategories,
    ignoredFiles,
    unprotectedExposedFiles,
    coveredFiles,
    stats: {
      totalWorkingFiles: rawFiles.length,
      sensitiveFilesCount: ignoredFiles.length,
      unprotectedExposedCount: unprotectedExposedFiles.length,
      properlyCoveredCount: coveredFiles.length,
      securityScore
    },
    recommendedGitignore: generateRecommendedGitignore(),
    missingRulesToAppend
  };
}
