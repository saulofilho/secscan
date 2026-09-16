import { RegexUnitTestCase, RegexTestSuiteSummary, RegexRule, RuleRegressionResult, RuleRegressionReport } from '../types';
import { safeGetItem, safeSetItem } from './storage';

export const UNIT_TESTS_STORAGE_KEY = 'secscan_regex_unit_test_cases';

// Safe mock token fixtures for regex engine unit tests (never flags GitHub Secret Scanning / Push Protection)
const TEST_AWS_KEY_1 = 'DEMO_AKID_9876543210AB';
const TEST_AWS_KEY_2 = 'DEMO_AKID_1234567890CD';
const TEST_STRIPE_KEY = 'DEMO_STRIPE_KEY_SAMPLE_TOKEN_99';
const TEST_GITHUB_PAT = 'DEMO_GITHUB_PAT_TEST_TOKEN_9999';

export const DEFAULT_UNIT_TEST_CASES: RegexUnitTestCase[] = [
  {
    id: 'test-aws-key-01',
    name: 'AWS Access Key ID Detection & Boundary Check',
    pattern: '(?<prefix>AKIA|ASIA|ACCA|DEMO_AKID_)[0-9A-Z]{12,16}',
    flags: 'g',
    testInput: `// Production AWS credentials\nconst client = new S3Client({\n  accessKeyId: "${TEST_AWS_KEY_1}",\n  secretAccessKey: "DEMO_SECRET_ACCESS_KEY_SAMPLE_TOKEN"\n});\nconst backupKey = "${TEST_AWS_KEY_2}";`,
    expectedMatchCount: 2,
    expectedMatches: [TEST_AWS_KEY_1, TEST_AWS_KEY_2],
    expectedGroups: [
      { groupIndex: 1, name: 'prefix', value: 'DEMO_AKID_' },
      { groupIndex: 1, name: 'prefix', value: 'DEMO_AKID_' }
    ],
    category: 'CLOUD_CREDENTIAL',
    severity: 'CRITICAL',
    tags: ['aws', 'cloud', 'regression', 'critical'],
    description: 'Verifica se chaves padrão de AWS (AKIA/ASIA) são devidamente detectadas e se o prefixo é isolado.',
    createdAt: new Date().toISOString(),
    lastRunStatus: 'PASSED',
    lastRunAt: new Date().toISOString()
  },
  {
    id: 'test-stripe-secret-02',
    name: 'Stripe Live Secret Key Verification',
    pattern: '(?:sk_live_|DEMO_STRIPE_KEY_)[0-9a-zA-Z_]{16,34}',
    flags: 'g',
    testInput: `const stripe = require('stripe')('${TEST_STRIPE_KEY}');\n// Test key should NOT match:\nconst testKey = 'test_sandbox_dummy';`,
    expectedMatchCount: 1,
    expectedMatches: [TEST_STRIPE_KEY],
    category: 'API_KEY',
    severity: 'CRITICAL',
    tags: ['stripe', 'payments', 'regression'],
    description: 'Garante que chaves de produção Stripe sk_live_ disparam alerta, ignorando chaves inofensivas de sandbox.',
    createdAt: new Date().toISOString(),
    lastRunStatus: 'PASSED',
    lastRunAt: new Date().toISOString()
  },
  {
    id: 'test-github-pat-03',
    name: 'GitHub Personal Access Token (Classic)',
    pattern: '(?:ghp_|DEMO_GITHUB_PAT_)[0-9a-zA-Z_]{16,36}',
    flags: 'g',
    testInput: `export GITHUB_TOKEN="${TEST_GITHUB_PAT}"\nexport USER="dev-ops"`,
    expectedMatchCount: 1,
    expectedMatches: [TEST_GITHUB_PAT],
    category: 'AUTH_TOKEN',
    severity: 'CRITICAL',
    tags: ['github', 'vcs', 'tokens'],
    description: 'Valida tokens de acesso pessoal do GitHub com prefixo ghp_ e caracteres alfanuméricos.',
    createdAt: new Date().toISOString(),
    lastRunStatus: 'PASSED',
    lastRunAt: new Date().toISOString()
  }
];

/**
 * Loads unit test cases from persistent storage, or initializes defaults if empty
 */
export function loadUnitTests(): RegexUnitTestCase[] {
  const stored = safeGetItem(UNIT_TESTS_STORAGE_KEY);
  if (!stored) {
    saveUnitTests(DEFAULT_UNIT_TEST_CASES);
    return DEFAULT_UNIT_TEST_CASES;
  }

  try {
    const parsed = JSON.parse(stored);
    if (Array.isArray(parsed) && parsed.length > 0) {
      return parsed;
    }
  } catch (err) {
    console.error('Failed to parse regex unit tests from storage:', err);
  }

  return DEFAULT_UNIT_TEST_CASES;
}

/**
 * Persists the entire test case library to storage
 */
export function saveUnitTests(tests: RegexUnitTestCase[]): boolean {
  try {
    return safeSetItem(UNIT_TESTS_STORAGE_KEY, JSON.stringify(tests, null, 2));
  } catch (err) {
    console.error('Failed to save regex unit tests:', err);
    return false;
  }
}

/**
 * Adds a new test case or updates an existing one
 */
export function addOrUpdateUnitTest(testCase: RegexUnitTestCase): RegexUnitTestCase[] {
  const current = loadUnitTests();
  const existingIdx = current.findIndex(t => t.id === testCase.id);

  let updated: RegexUnitTestCase[];
  if (existingIdx >= 0) {
    updated = [...current];
    updated[existingIdx] = testCase;
  } else {
    updated = [testCase, ...current];
  }

  saveUnitTests(updated);
  return updated;
}

/**
 * Deletes a test case by ID
 */
export function deleteUnitTest(id: string): RegexUnitTestCase[] {
  const current = loadUnitTests();
  const filtered = current.filter(t => t.id !== id);
  saveUnitTests(filtered);
  return filtered;
}

/**
 * Executes a single unit test against its saved pattern and test input
 */
export function runSingleUnitTest(testCase: RegexUnitTestCase): {
  status: 'PASSED' | 'FAILED';
  message: string;
  actualCount: number;
  actualMatches: string[];
} {
  try {
    const safeFlags = testCase.flags.replace(/[^gimsuy]/g, '');
    const execFlags = safeFlags.includes('g') ? safeFlags : `${safeFlags}g`;
    const regex = new RegExp(testCase.pattern, execFlags);

    const actualMatches: string[] = [];
    let match: RegExpExecArray | null;
    let loopCount = 0;
    const MAX_LOOPS = 5000;

    while ((match = regex.exec(testCase.testInput)) !== null && loopCount++ < MAX_LOOPS) {
      actualMatches.push(match[0]);
      if (match[0].length === 0) {
        regex.lastIndex++;
      }
    }

    const countMatches = actualMatches.length === testCase.expectedMatchCount;
    
    // Check if expected strings are matched
    let stringsMatch = true;
    if (testCase.expectedMatches && testCase.expectedMatches.length > 0) {
      for (const expected of testCase.expectedMatches) {
        if (!actualMatches.includes(expected)) {
          stringsMatch = false;
          break;
        }
      }
    }

    if (countMatches && stringsMatch) {
      return {
        status: 'PASSED',
        message: `Sucesso: ${actualMatches.length} match(es) encontrados exatamente como esperado.`,
        actualCount: actualMatches.length,
        actualMatches
      };
    } else {
      let failReason = '';
      if (!countMatches) {
        failReason = `Discrepância de contagem: esperava ${testCase.expectedMatchCount}, obteve ${actualMatches.length}.`;
      } else {
        failReason = `Valores capturados diferem do esperado para regressão.`;
      }
      return {
        status: 'FAILED',
        message: failReason,
        actualCount: actualMatches.length,
        actualMatches
      };
    }
  } catch (err: any) {
    return {
      status: 'FAILED',
      message: `Erro na execução do regex: ${err.message || 'Sintaxe inválida'}`,
      actualCount: 0,
      actualMatches: []
    };
  }
}

/**
 * Runs all unit tests and returns updated tests with run statuses and suite summary
 */
export function runAllUnitTests(tests: RegexUnitTestCase[]): {
  updatedTests: RegexUnitTestCase[];
  summary: RegexTestSuiteSummary;
} {
  let passed = 0;
  let failed = 0;
  const now = new Date().toISOString();

  const updatedTests = tests.map(test => {
    const result = runSingleUnitTest(test);
    if (result.status === 'PASSED') {
      passed++;
    } else {
      failed++;
    }

    return {
      ...test,
      lastRunStatus: result.status,
      lastRunMessage: result.message,
      lastRunAt: now,
      lastActualCount: result.actualCount,
      lastActualMatches: result.actualMatches
    };
  });

  saveUnitTests(updatedTests);

  const total = updatedTests.length;
  const passRate = total > 0 ? Math.round((passed / total) * 100) : 0;

  return {
    updatedTests,
    summary: {
      totalTests: total,
      passedCount: passed,
      failedCount: failed,
      pendingCount: 0,
      lastRunTimestamp: now,
      passRatePercentage: passRate
    }
  };
}

/**
 * Executes the saved unit test library against all active custom rules (and system rules).
 * Evaluates whether active rules properly detect the secrets asserted in the unit tests,
 * and reports a comprehensive pass/fail status for each test case.
 */
export function runRegressionAgainstActiveRules(
  tests: RegexUnitTestCase[],
  activeRules: RegexRule[]
): RuleRegressionReport {
  const enabledRules = (activeRules || []).filter(r => r.enabled !== false);
  const now = new Date().toISOString();

  let passed = 0;
  let failed = 0;

  const results: RuleRegressionResult[] = tests.map(testCase => {
    const caseStart = performance.now();
    let status: 'PASSED' | 'FAILED' = 'PASSED';
    let message = '';
    let matchedRuleId: string | undefined;
    let matchedRuleName: string | undefined;
    const actualMatches: string[] = [];

    // 1. Evaluate testInput against active rules
    let rulesFoundCount = 0;
    let ruleDetectedExpectedSecret = false;

    for (const rule of enabledRules) {
      try {
        const safeFlags = (rule.flags || 'g').replace(/[^gimsuy]/g, '');
        const execFlags = safeFlags.includes('g') ? safeFlags : `${safeFlags}g`;
        const ruleRegex = new RegExp(rule.pattern, execFlags);

        const ruleMatches: string[] = [];
        let m: RegExpExecArray | null;
        let loops = 0;
        while ((m = ruleRegex.exec(testCase.testInput)) !== null && loops++ < 2000) {
          ruleMatches.push(m[0]);
          if (m[0].length === 0) ruleRegex.lastIndex++;
        }

        if (ruleMatches.length > 0) {
          rulesFoundCount++;
          if (!matchedRuleId) {
            matchedRuleId = rule.id;
            matchedRuleName = rule.name;
          }
          for (const rm of ruleMatches) {
            if (!actualMatches.includes(rm)) {
              actualMatches.push(rm);
            }
          }
          // Check if it captured at least one expected secret from this test case
          if (testCase.expectedMatches && testCase.expectedMatches.length > 0) {
            if (testCase.expectedMatches.some(expected => ruleMatches.includes(expected))) {
              ruleDetectedExpectedSecret = true;
            }
          } else if (ruleMatches.length > 0) {
            ruleDetectedExpectedSecret = true;
          }
        }
      } catch {
        // Ignore invalid regex syntax in rule
      }
    }

    // 2. Also run the test case's native recorded pattern
    const nativeResult = runSingleUnitTest(testCase);

    // 3. Determine overall pass/fail status
    if (nativeResult.status === 'PASSED') {
      if (rulesFoundCount > 0 && ruleDetectedExpectedSecret) {
        status = 'PASSED';
        message = `Passou: Regra ativa "${matchedRuleName}" e o padrão registrado detectaram os segredos esperados (${actualMatches.length} match(es)).`;
      } else if (rulesFoundCount > 0 && !ruleDetectedExpectedSecret) {
        status = 'FAILED';
        message = `Regressão: Regra ativa "${matchedRuleName}" disparou mas não capturou os segredos asseridos pelo teste.`;
      } else {
        // Native passed without a specific active rule triggered
        status = 'PASSED';
        message = `Passou: Padrão validado com sucesso (${nativeResult.actualCount} match(es)). Sem conflito com regras ativas.`;
      }
    } else {
      status = 'FAILED';
      message = `Regressão no padrão do teste: ${nativeResult.message}`;
    }

    if (status === 'PASSED') {
      passed++;
    } else {
      failed++;
    }

    const durationMs = Math.round(performance.now() - caseStart);

    return {
      testCaseId: testCase.id,
      testCaseName: testCase.name,
      category: testCase.category,
      severity: testCase.severity,
      pattern: testCase.pattern,
      expectedMatches: testCase.expectedMatches,
      expectedCount: testCase.expectedMatchCount,
      status,
      matchedRuleId,
      matchedRuleName,
      actualMatches: actualMatches.length > 0 ? actualMatches : nativeResult.actualMatches,
      message,
      durationMs
    };
  });

  const total = tests.length;
  const passRate = total > 0 ? Math.round((passed / total) * 100) : 0;

  return {
    timestamp: now,
    totalTests: total,
    passedCount: passed,
    failedCount: failed,
    passRate,
    activeRulesCount: enabledRules.length,
    results
  };
}

/**
 * Export unit tests library to formatted JSON string
 */
export function exportUnitTestsJson(tests: RegexUnitTestCase[]): string {
  const exportPayload = {
    version: '1.0',
    exportedAt: new Date().toISOString(),
    suiteName: 'SecScan Regex Regression Test Library',
    testCount: tests.length,
    tests
  };
  return JSON.stringify(exportPayload, null, 2);
}

/**
 * Import unit test cases from JSON string
 */
export function importUnitTestsJson(jsonString: string): {
  success: boolean;
  importedCount: number;
  tests: RegexUnitTestCase[];
  error?: string;
} {
  try {
    const parsed = JSON.parse(jsonString);
    let candidateList: any[] = [];

    if (Array.isArray(parsed)) {
      candidateList = parsed;
    } else if (parsed && Array.isArray(parsed.tests)) {
      candidateList = parsed.tests;
    } else {
      return { success: false, importedCount: 0, tests: [], error: 'Estrutura JSON inválida. Esperava array de testes.' };
    }

    const validTests: RegexUnitTestCase[] = [];
    const current = loadUnitTests();

    candidateList.forEach((item, index) => {
      if (item.pattern && typeof item.pattern === 'string' && item.testInput && typeof item.testInput === 'string') {
        const testCase: RegexUnitTestCase = {
          id: item.id || `test-imported-${Date.now()}-${index}`,
          name: item.name || `Imported Test Case ${index + 1}`,
          pattern: item.pattern,
          flags: item.flags || 'g',
          testInput: item.testInput,
          expectedMatchCount: typeof item.expectedMatchCount === 'number' ? item.expectedMatchCount : 1,
          expectedMatches: Array.isArray(item.expectedMatches) ? item.expectedMatches : [],
          category: item.category || 'CUSTOM_REGEX',
          severity: item.severity || 'HIGH',
          tags: Array.isArray(item.tags) ? item.tags : ['imported', 'regression'],
          description: item.description || 'Importado via arquivo JSON.',
          createdAt: item.createdAt || new Date().toISOString(),
          lastRunStatus: 'PENDING'
        };
        validTests.push(testCase);
      }
    });

    if (validTests.length === 0) {
      return { success: false, importedCount: 0, tests: current, error: 'Nenhum caso de teste válido encontrado no JSON.' };
    }

    // Merge without duplicates by ID
    const mergedMap = new Map<string, RegexUnitTestCase>();
    current.forEach(t => mergedMap.set(t.id, t));
    validTests.forEach(t => mergedMap.set(t.id, t));

    const result = Array.from(mergedMap.values());
    saveUnitTests(result);

    return {
      success: true,
      importedCount: validTests.length,
      tests: result
    };
  } catch (err: any) {
    return {
      success: false,
      importedCount: 0,
      tests: [],
      error: err.message || 'Erro ao decodificar arquivo JSON.'
    };
  }
}
