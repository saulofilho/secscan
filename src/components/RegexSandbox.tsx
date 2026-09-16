import React, { useState, useMemo, useRef } from 'react';
import { 
  Terminal, 
  Sparkles, 
  Check, 
  Copy, 
  Plus, 
  Play, 
  Layers, 
  AlertTriangle, 
  FileCode, 
  Maximize2,
  RefreshCw,
  Info,
  Sliders,
  ShieldAlert,
  FlaskConical,
  CheckCircle2,
  BookmarkCheck,
  Loader2,
  XCircle,
  X,
  RotateCcw,
  CheckSquare,
  ShieldCheck,
  Filter
} from 'lucide-react';
import { RegexRule, FindingCategory, SeverityLevel, RegexUnitTestCase, RuleRegressionReport, RuleRegressionResult } from '../types';
import { loadUnitTests, addOrUpdateUnitTest, runRegressionAgainstActiveRules } from '../lib/regexUnitTestManager';
import { RegexUnitTestLibrary } from './RegexUnitTestLibrary';

export interface MatchCapture {
  fullMatch: string;
  index: number;
  length: number;
  endIndex: number;
  line: number;
  column: number;
  groups: {
    groupIndex: number;
    name?: string;
    value: string;
    start: number;
    end: number;
  }[];
}

interface RegexSandboxProps {
  initialPattern?: string;
  initialFlags?: string;
  initialText?: string;
  activeRules?: RegexRule[];
  onSaveRule?: (rule: RegexRule) => void;
  onOpenManualModal?: (ruleParams: Partial<RegexRule>) => void;
}

// Safe mock strings for sandbox testing that do not trigger GitHub Push Protection
const SAMPLE_AWS_KEY = 'DEMO_AWS_AKID_EXAMPLE_KEY_01';
const SAMPLE_AWS_SECRET = 'DEMO_AWS_SECRET_KEY_SAMPLE_TEST_KEY_40';
const SAMPLE_STRIPE_SECRET = 'DEMO_STRIPE_SECRET_KEY_FOR_TESTS';
const SAMPLE_GITHUB_PAT = 'DEMO_GITHUB_PAT_TOKEN_SAMPLE_FOR_TESTS';
const SAMPLE_STRIPE_WEBHOOK = 'DEMO_STRIPE_WEBHOOK_SECRET_SAMPLE_TOKEN';
const SAMPLE_AWS_KEY_2 = 'DEMO_AWS_AKID_BACKUP_KEY_02';
const SAMPLE_GOOGLE_KEY = 'DEMO_GOOGLE_API_KEY_SAMPLE_TEST_99';
const SAMPLE_SLACK_TOKEN = 'DEMO_SLACK_BOT_TOKEN_SAMPLE_TEST';
const SAMPLE_DB_PASS_URI = 'postgres://app_admin:REDACTED_PASSWORD@db-prod.internal:5432/finance_db';
const SAMPLE_DB_URL = 'postgres://app_user:REDACTED_PASSWORD@10.0.0.12:5432/core_production';
const SAMPLE_REDIS_URL = 'redis://default:REDACTED_AUTH_TOKEN@cache.prod.internal:6379';
const SAMPLE_JWT_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vX3VzZXIifQ.DEMO_SIGNATURE_ONLY';

const SAMPLE_TEST_CASES = [
  {
    title: 'Cloud & API Keys Codeblock',
    text: `// Application Configuration & Service Connectors
const AWS_CONFIG = {
  accessKeyId: "${SAMPLE_AWS_KEY}",
  secretAccessKey: "${SAMPLE_AWS_SECRET}",
  region: "us-east-1"
};

const STRIPE_WEBHOOK_KEY = "${SAMPLE_STRIPE_WEBHOOK}";
const STRIPE_SECRET = "${SAMPLE_STRIPE_SECRET}";
const GITHUB_PAT = "${SAMPLE_GITHUB_PAT}";

function getDatabaseConnection() {
  const uri = "${SAMPLE_DB_PASS_URI}";
  return connect(uri);
}`
  },
  {
    title: 'Environment & Dotenv File',
    text: `# Production Credentials
DATABASE_URL=${SAMPLE_DB_URL}
REDIS_AUTH=${SAMPLE_REDIS_URL}
GOOGLE_GEMINI_KEY=${SAMPLE_GOOGLE_KEY}
SLACK_BOT_TOKEN=${SAMPLE_SLACK_TOKEN}
JWT_BEARER=Bearer ${SAMPLE_JWT_TOKEN}`
  },
  {
    title: 'JSON API Response Payload',
    text: `{
  "status": "success",
  "data": {
    "organizationId": "org_987234",
    "credentials": [
      {
        "provider": "aws",
        "keyId": "${SAMPLE_AWS_KEY_2}",
        "description": "Deployment bot"
      },
      {
        "provider": "custom_service",
        "token": "token_a1b2c3d4e5f678901234567890abcdef",
        "expiresIn": 3600
      }
    ]
  }
}`
  }
];

export const RegexSandbox: React.FC<RegexSandboxProps> = ({
  initialPattern = '(?<prefix>AKIA|ASIA|sk_live_|ghp_)(?<token>[0-9A-Za-z_]{16,40})',
  initialFlags = 'g',
  initialText,
  activeRules,
  onSaveRule,
  onOpenManualModal
}) => {
  const [pattern, setPattern] = useState(initialPattern);
  const [flags, setFlags] = useState(initialFlags);
  const [testText, setTestText] = useState(
    initialText || SAMPLE_TEST_CASES[0].text
  );

  // Configuration for quick-save as rule
  const [ruleName, setRuleName] = useState('Sandbox Verified Regex Rule');
  const [severity, setSeverity] = useState<SeverityLevel>('HIGH');
  const [category, setCategory] = useState<FindingCategory>('API_KEY');
  const [showSaveConfig, setShowSaveConfig] = useState(false);
  const [copiedPattern, setCopiedPattern] = useState(false);
  const [copiedMatch, setCopiedMatch] = useState<number | null>(null);
  const [selectedMatchIndex, setSelectedMatchIndex] = useState<number | null>(null);
  const [isWordWrap, setIsWordWrap] = useState(true);

  // Persistent Unit Tests State
  const [showSaveUnitTest, setShowSaveUnitTest] = useState(false);
  const [showUnitTestLibrary, setShowUnitTestLibrary] = useState(false);
  const [unitTestName, setUnitTestName] = useState('');
  const [unitTestDesc, setUnitTestDesc] = useState('');
  const [unitTestsCount, setUnitTestsCount] = useState<number>(0);
  const [unitTestToast, setUnitTestToast] = useState<string | null>(null);

  // Regression Testing Suite State
  const [isRunningRegression, setIsRunningRegression] = useState(false);
  const [regressionReport, setRegressionReport] = useState<RuleRegressionReport | null>(null);
  const [regressionFilter, setRegressionFilter] = useState<'ALL' | 'PASSED' | 'FAILED'>('ALL');

  // Initialize unit tests count
  React.useEffect(() => {
    const loaded = loadUnitTests();
    setUnitTestsCount(loaded.length);
  }, []);

  // Sync initialPattern changes if updated from parent builder
  React.useEffect(() => {
    if (initialPattern) setPattern(initialPattern);
  }, [initialPattern]);

  React.useEffect(() => {
    if (initialFlags) setFlags(initialFlags);
  }, [initialFlags]);

  // Execute regex and extract match details, index positions, and capture groups
  const parsingResult = useMemo(() => {
    if (!pattern.trim()) {
      return {
        isValid: false,
        error: 'Padrão regex não informado.',
        matches: [] as MatchCapture[],
        groupsList: [] as string[]
      };
    }

    try {
      // Validate flags
      const safeFlags = flags.replace(/[^gimsuy]/g, '');
      const hasGlobal = safeFlags.includes('g');
      const execFlags = hasGlobal ? safeFlags : `${safeFlags}g`;
      const regex = new RegExp(pattern, execFlags);

      const matches: MatchCapture[] = [];
      let match: RegExpExecArray | null;
      let loopCount = 0;
      const MAX_LOOPS = 5000; // Safeguard against infinite zero-length matches

      // Calculate line starts for line/column numbering
      const lines = testText.split('\n');
      const lineOffsets: number[] = [0];
      for (let i = 0; i < lines.length; i++) {
        lineOffsets.push(lineOffsets[i] + lines[i].length + 1); // +1 for \n
      }

      const getLineAndCol = (index: number) => {
        let line = 1;
        for (let i = 0; i < lineOffsets.length - 1; i++) {
          if (index >= lineOffsets[i] && index < lineOffsets[i + 1]) {
            line = i + 1;
            break;
          }
        }
        const col = index - lineOffsets[line - 1] + 1;
        return { line, col };
      };

      while ((match = regex.exec(testText)) !== null && loopCount++ < MAX_LOOPS) {
        const fullMatch = match[0];
        const matchIndex = match.index;
        const endIndex = matchIndex + fullMatch.length;
        const { line, col } = getLineAndCol(matchIndex);

        // Group extractions
        const groups: MatchCapture['groups'] = [];
        
        // Named groups if present in match.groups
        const namedGroups = match.groups || {};
        const namedGroupNames = Object.keys(namedGroups);

        // Numbered groups (starting at 1)
        for (let g = 1; g < match.length; g++) {
          const val = match[g];
          if (val !== undefined) {
            // Find name if any
            let gName: string | undefined = undefined;
            for (const n of namedGroupNames) {
              if (namedGroups[n] === val) {
                gName = n;
                break;
              }
            }

            // Approximate position of group inside the match
            const offsetInMatch = fullMatch.indexOf(val);
            const gStart = offsetInMatch >= 0 ? matchIndex + offsetInMatch : matchIndex;
            const gEnd = gStart + val.length;

            groups.push({
              groupIndex: g,
              name: gName,
              value: val,
              start: gStart,
              end: gEnd
            });
          }
        }

        matches.push({
          fullMatch,
          index: matchIndex,
          length: fullMatch.length,
          endIndex,
          line,
          column: col,
          groups
        });

        // Avoid infinite loop on zero-width match
        if (fullMatch.length === 0) {
          regex.lastIndex++;
        }
      }

      // Collect all unique group names across all matches
      const allGroupNamesSet = new Set<string>();
      matches.forEach(m => {
        m.groups.forEach(g => {
          allGroupNamesSet.add(g.name ? `${g.name} (#${g.groupIndex})` : `Grupo ${g.groupIndex}`);
        });
      });

      return {
        isValid: true,
        error: null,
        matches,
        groupsList: Array.from(allGroupNamesSet)
      };
    } catch (err: any) {
      return {
        isValid: false,
        error: err.message || 'Sintaxe de Regex Inválida',
        matches: [] as MatchCapture[],
        groupsList: [] as string[]
      };
    }
  }, [pattern, flags, testText]);

  // Build interactive styled segments for the live text display
  const highlightedSegments = useMemo(() => {
    if (!parsingResult.isValid || parsingResult.matches.length === 0) {
      return [{ text: testText, isMatch: false, matchIndex: -1 }];
    }

    const segments: {
      text: string;
      isMatch: boolean;
      matchIndex: number;
      matchData?: MatchCapture;
    }[] = [];

    let cursor = 0;
    parsingResult.matches.forEach((m, idx) => {
      // Unmatched leading text
      if (m.index > cursor) {
        segments.push({
          text: testText.substring(cursor, m.index),
          isMatch: false,
          matchIndex: -1
        });
      }

      // Matched segment
      segments.push({
        text: testText.substring(m.index, m.endIndex),
        isMatch: true,
        matchIndex: idx,
        matchData: m
      });

      cursor = m.endIndex;
    });

    // Unmatched trailing text
    if (cursor < testText.length) {
      segments.push({
        text: testText.substring(cursor),
        isMatch: false,
        matchIndex: -1
      });
    }

    return segments;
  }, [testText, parsingResult]);

  const handleCopyPattern = () => {
    navigator.clipboard.writeText(`/${pattern}/${flags}`);
    setCopiedPattern(true);
    setTimeout(() => setCopiedPattern(false), 2000);
  };

  const handleCopyMatchValue = (val: string, idx: number) => {
    navigator.clipboard.writeText(val);
    setCopiedMatch(idx);
    setTimeout(() => setCopiedMatch(null), 2000);
  };

  const handleSaveToActiveRules = () => {
    if (!pattern.trim() || !parsingResult.isValid) return;

    const newRule: RegexRule = {
      id: `sandbox-${Date.now()}`,
      name: ruleName.trim() || 'Custom Sandbox Rule',
      pattern: pattern.trim(),
      flags: flags.trim() || 'g',
      category,
      severity,
      description: `Regra regex validada e calibrada no Regex Sandbox com ${parsingResult.matches.length} correspondências registradas.`,
      remediation: 'Extraia os valores confidenciais para variáveis de ambiente protegidas e aplique rotação imediata de chaves.',
      enabled: true,
      isCustom: true,
      exampleMatch: parsingResult.matches[0]?.fullMatch || undefined,
      tags: ['sandbox', 'custom', category.toLowerCase()]
    };

    if (onSaveRule) {
      onSaveRule(newRule);
    }
    setShowSaveConfig(false);
  };

  const handleSaveToUnitTestLibrary = () => {
    if (!pattern.trim() || !parsingResult.isValid) return;

    const defaultTitle = `Teste de Regressão: /${pattern.length > 28 ? pattern.slice(0, 28) + '...' : pattern}/`;
    const finalName = unitTestName.trim() || defaultTitle;

    const newTestCase: RegexUnitTestCase = {
      id: `test-${Date.now()}`,
      name: finalName,
      pattern: pattern.trim(),
      flags: flags.trim() || 'g',
      testInput: testText,
      expectedMatchCount: parsingResult.matches.length,
      expectedMatches: parsingResult.matches.map(m => m.fullMatch),
      expectedGroups: parsingResult.matches.flatMap(m =>
        m.groups.map(g => ({
          groupIndex: g.groupIndex,
          name: g.name,
          value: g.value
        }))
      ),
      category,
      severity,
      tags: ['regression', 'unit-test', category.toLowerCase()],
      description: unitTestDesc.trim() || `Caso de regressão validado no Regex Sandbox com ${parsingResult.matches.length} match(es) asseridos.`,
      createdAt: new Date().toISOString(),
      lastRunStatus: 'PASSED',
      lastRunMessage: `Asserção gravada: ${parsingResult.matches.length} match(es) capturados em tempo real.`,
      lastRunAt: new Date().toISOString(),
      lastActualCount: parsingResult.matches.length,
      lastActualMatches: parsingResult.matches.map(m => m.fullMatch)
    };

    const updated = addOrUpdateUnitTest(newTestCase);
    setUnitTestsCount(updated.length);
    setShowSaveUnitTest(false);
    setUnitTestToast(`Caso de teste "${finalName}" salvo com sucesso na biblioteca JSON de testes unitários!`);
    setTimeout(() => setUnitTestToast(null), 4000);
  };

  const handleLoadTestCaseToSandbox = (testCase: RegexUnitTestCase) => {
    setPattern(testCase.pattern);
    setFlags(testCase.flags);
    setTestText(testCase.testInput);
    if (testCase.category) setCategory(testCase.category);
    if (testCase.severity) setSeverity(testCase.severity);
    setUnitTestName(testCase.name);
    setUnitTestToast(`Caso de teste "${testCase.name}" carregado no Sandbox para inspeção e teste!`);
    setTimeout(() => setUnitTestToast(null), 3500);
  };

  const handleRunAllRegressionTests = () => {
    setIsRunningRegression(true);
    setTimeout(() => {
      try {
        const tests = loadUnitTests();
        const effectiveRules = activeRules || [];
        const report = runRegressionAgainstActiveRules(tests, effectiveRules);
        setRegressionReport(report);
        setUnitTestToast(`Regressão concluída: ${report.passedCount}/${report.totalTests} casos passaram (${report.passRate}% taxa de sucesso).`);
      } catch (err: any) {
        setUnitTestToast(`Erro ao rodar regressão: ${err.message}`);
      } finally {
        setIsRunningRegression(false);
      }
    }, 120);
  };

  const toggleFlag = (flagLetter: string) => {
    if (flags.includes(flagLetter)) {
      setFlags(flags.replace(flagLetter, ''));
    } else {
      setFlags(flags + flagLetter);
    }
  };

  return (
    <div className="regex-sandbox-component bg-[#0A0A0A] border border-[#222] p-5 sm:p-7 space-y-6">
      {/* Toast Notification for Unit Tests / Actions */}
      {unitTestToast && (
        <div className="p-3 bg-[#00FF41]/10 border border-[#00FF41] text-[#00FF41] text-xs font-mono font-bold flex items-center justify-between animate-in fade-in duration-150">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-[#00FF41] shrink-0" />
            <span>{unitTestToast}</span>
          </div>
          <button 
            type="button" 
            onClick={() => setUnitTestToast(null)} 
            className="text-[#888] hover:text-white cursor-pointer ml-3 font-bold"
          >
            &times;
          </button>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#222]">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-none bg-[#00FF41] text-black flex items-center justify-center font-black text-xs">
              <Terminal className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-sm sm:text-base font-black uppercase tracking-[0.2em] text-white">
              Regex Sandbox & Live Match Inspector
            </h2>
            <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30 uppercase">
              Real-Time Highlighting & Captures
            </span>
          </div>
          <p className="text-xs font-mono text-[#888] max-w-3xl">
            Ambiente interativo de teste para suas expressões regulares. Visualize correspondências exatas em tempo real, posições de linha/coluna e grupos de captura delimitados antes de salvar como regra ativa.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={handleCopyPattern}
            className="px-3 py-2 bg-[#111] hover:bg-[#222] text-white border border-[#333] font-mono text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            {copiedPattern ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedPattern ? 'COPIADO!' : 'COPIAR REGEX'}</span>
          </button>

          {/* User Request: Save to Unit Tests button */}
          <button
            type="button"
            id="btn-save-unit-test"
            onClick={() => {
              setShowSaveUnitTest(!showSaveUnitTest);
              setShowSaveConfig(false);
            }}
            disabled={!parsingResult.isValid}
            className={`px-3.5 py-2 font-black uppercase text-[10px] tracking-[0.15em] flex items-center gap-1.5 transition-all cursor-pointer ${
              showSaveUnitTest
                ? 'bg-white text-black'
                : 'bg-[#181818] hover:bg-[#FF3E00] text-white border border-[#FF3E00]/60 shadow-[0_0_12px_rgba(255,62,0,0.2)]'
            } disabled:opacity-40`}
            title="Salvar regex validada e texto de entrada na biblioteca persistente JSON de testes unitários para testes de regressão"
          >
            <FlaskConical className="w-3.5 h-3.5 text-[#FF3E00] group-hover:text-white" />
            <span>Save to Unit Tests</span>
          </button>

          {/* User Request: Run All Regression Tests button */}
          <button
            type="button"
            id="btn-run-all-regression-tests"
            onClick={handleRunAllRegressionTests}
            disabled={isRunningRegression}
            className={`px-3.5 py-2 font-black uppercase text-[10px] tracking-[0.15em] flex items-center gap-1.5 transition-all cursor-pointer ${
              isRunningRegression
                ? 'bg-zinc-800 text-zinc-400 border border-zinc-700 cursor-wait'
                : 'bg-[#00FF41]/10 hover:bg-[#00FF41] text-[#00FF41] hover:text-black border border-[#00FF41]/60 shadow-[0_0_12px_rgba(0,255,65,0.15)]'
            }`}
            title="Executar toda a biblioteca persistente de testes unitários contra todas as regras ativas e gerar relatório de regressão"
          >
            {isRunningRegression ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5 fill-current" />
            )}
            <span>Run All Regression Tests</span>
          </button>

          {/* Toggle Persistent Unit Test Library */}
          <button
            type="button"
            id="btn-toggle-unit-tests"
            onClick={() => setShowUnitTestLibrary(!showUnitTestLibrary)}
            className={`px-3 py-2 border text-[10px] font-mono uppercase font-bold flex items-center gap-1.5 transition-colors cursor-pointer ${
              showUnitTestLibrary
                ? 'bg-[#FF3E00] text-white border-[#FF3E00]'
                : 'bg-[#111] text-zinc-300 border-[#333] hover:border-white hover:text-white'
            }`}
            title="Visualizar e gerenciar biblioteca persistente de regressão de testes unitários em JSON"
          >
            <BookmarkCheck className="w-3.5 h-3.5 text-[#FF3E00]" />
            <span>Suíte de Testes ({unitTestsCount})</span>
          </button>

          <button
            type="button"
            id="btn-save-sandbox-rule"
            onClick={() => {
              setShowSaveConfig(!showSaveConfig);
              setShowSaveUnitTest(false);
            }}
            disabled={!parsingResult.isValid}
            className={`px-4 py-2 font-black uppercase text-[10px] tracking-[0.15em] flex items-center gap-1.5 transition-all cursor-pointer ${
              showSaveConfig
                ? 'bg-white text-black'
                : 'bg-[#00FF41] hover:bg-white text-black shadow-[0_0_12px_rgba(0,255,65,0.25)]'
            } disabled:opacity-40`}
          >
            <Plus className="w-3.5 h-3.5 stroke-[3]" />
            <span>Salvar como Regra</span>
          </button>
        </div>
      </div>

      {/* Regression Tests Results Panel */}
      {regressionReport && (
        <div className="p-5 bg-[#0C0C0C] border-2 border-[#00FF41] space-y-4 animate-in fade-in duration-200">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#222]">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/40">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-xs sm:text-sm font-black uppercase tracking-wider text-white">
                    Relatório de Regressão de Regras Ativas
                  </h3>
                  <span className={`px-2 py-0.5 text-[9px] font-mono font-bold uppercase border ${
                    regressionReport.failedCount === 0
                      ? 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]'
                      : 'bg-red-500/10 text-red-400 border-red-500'
                  }`}>
                    {regressionReport.failedCount === 0 ? '100% REGRESSÃO PASSOU' : `${regressionReport.failedCount} FALHA(S) DETECTADA(S)`}
                  </span>
                </div>
                <p className="text-[10px] font-mono text-[#888] mt-0.5">
                  Executado em {new Date(regressionReport.timestamp).toLocaleTimeString()} • Avaliado contra {regressionReport.activeRulesCount} regra(s) ativas
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleRunAllRegressionTests}
                disabled={isRunningRegression}
                className="px-3 py-1.5 bg-[#181818] hover:bg-[#252525] text-zinc-200 border border-[#333] text-[10px] font-mono uppercase font-bold flex items-center gap-1 cursor-pointer"
                title="Executar novamente a suíte de regressão"
              >
                <RotateCcw className={`w-3 h-3 ${isRunningRegression ? 'animate-spin' : ''}`} />
                <span>Re-executar</span>
              </button>
              <button
                type="button"
                onClick={() => setRegressionReport(null)}
                className="px-2.5 py-1.5 bg-[#181818] hover:bg-red-950/40 text-zinc-400 hover:text-red-400 border border-[#333] hover:border-red-500/40 text-[10px] font-mono uppercase font-bold flex items-center gap-1 cursor-pointer"
                title="Fechar relatório de regressão"
              >
                <X className="w-3.5 h-3.5" />
                <span>Fechar</span>
              </button>
            </div>
          </div>

          {/* Metrics summary row */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
            <div className="p-3 bg-[#111] border border-[#222]">
              <span className="text-[9px] font-mono uppercase text-[#888] block">Total de Casos</span>
              <span className="text-base font-black font-mono text-white mt-0.5 block">{regressionReport.totalTests}</span>
            </div>
            <div className="p-3 bg-[#111] border border-emerald-900/40">
              <span className="text-[9px] font-mono uppercase text-emerald-400 block">Passaram</span>
              <span className="text-base font-black font-mono text-[#00FF41] mt-0.5 block">{regressionReport.passedCount}</span>
            </div>
            <div className="p-3 bg-[#111] border border-red-900/40">
              <span className="text-[9px] font-mono uppercase text-red-400 block">Falharam</span>
              <span className="text-base font-black font-mono text-red-400 mt-0.5 block">{regressionReport.failedCount}</span>
            </div>
            <div className="p-3 bg-[#111] border border-[#222]">
              <span className="text-[9px] font-mono uppercase text-[#888] block">Regras Ativas</span>
              <span className="text-base font-black font-mono text-cyan-400 mt-0.5 block">{regressionReport.activeRulesCount}</span>
            </div>
            <div className="p-3 bg-[#111] border border-[#222] col-span-2 sm:col-span-1">
              <span className="text-[9px] font-mono uppercase text-[#888] block">Taxa de Sucesso</span>
              <span className={`text-base font-black font-mono mt-0.5 block ${
                regressionReport.passRate === 100 ? 'text-[#00FF41]' : regressionReport.passRate >= 75 ? 'text-yellow-400' : 'text-red-400'
              }`}>
                {regressionReport.passRate}%
              </span>
            </div>
          </div>

          {/* Filter Bar */}
          <div className="flex items-center justify-between gap-2 pt-1">
            <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#888]">
              <Filter className="w-3 h-3 text-[#888]" />
              <span>Filtrar:</span>
              <div className="inline-flex border border-[#333] p-0.5 bg-[#111]">
                {(['ALL', 'PASSED', 'FAILED'] as const).map(flt => (
                  <button
                    key={flt}
                    type="button"
                    onClick={() => setRegressionFilter(flt)}
                    className={`px-2.5 py-1 text-[9px] font-mono font-bold uppercase transition-colors cursor-pointer ${
                      regressionFilter === flt
                        ? 'bg-white text-black'
                        : 'text-zinc-400 hover:text-white'
                    }`}
                  >
                    {flt === 'ALL' ? `Todos (${regressionReport.results.length})` : flt === 'PASSED' ? `Passaram (${regressionReport.passedCount})` : `Falharam (${regressionReport.failedCount})`}
                  </button>
                ))}
              </div>
            </div>
            <span className="text-[9px] font-mono text-zinc-500">
              Clique em &quot;Carregar no Sandbox&quot; para depurar qualquer padrão
            </span>
          </div>

          {/* Results List */}
          <div className="space-y-2 max-h-[380px] overflow-y-auto pr-1">
            {regressionReport.results
              .filter(r => regressionFilter === 'ALL' || r.status === regressionFilter)
              .map((res) => (
                <div
                  key={res.testCaseId}
                  className={`p-3 border transition-colors flex flex-col md:flex-row md:items-center justify-between gap-3 ${
                    res.status === 'PASSED'
                      ? 'bg-[#111]/80 border-emerald-900/50 hover:border-[#00FF41]/60'
                      : 'bg-[#1A0A0A] border-red-900/60 hover:border-red-500'
                  }`}
                >
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`px-2 py-0.5 text-[9px] font-mono font-bold uppercase flex items-center gap-1 ${
                        res.status === 'PASSED'
                          ? 'bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/40'
                          : 'bg-red-500/10 text-red-400 border border-red-500/40'
                      }`}>
                        {res.status === 'PASSED' ? (
                          <CheckCircle2 className="w-3 h-3 text-[#00FF41]" />
                        ) : (
                          <XCircle className="w-3 h-3 text-red-400" />
                        )}
                        <span>{res.status}</span>
                      </span>

                      <span className="text-xs font-mono font-bold text-white truncate">
                        {res.testCaseName}
                      </span>

                      {res.matchedRuleName && (
                        <span className="px-1.5 py-0.5 text-[9px] font-mono bg-cyan-950/40 text-cyan-300 border border-cyan-800/40">
                          Regra: {res.matchedRuleName}
                        </span>
                      )}

                      <span className="text-[9px] font-mono text-[#666]">
                        {res.durationMs}ms
                      </span>
                    </div>

                    <p className="text-[11px] font-mono text-zinc-300">
                      {res.message}
                    </p>

                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] font-mono text-[#888]">
                      <span>
                        Correspondências: <strong className="text-white">{res.actualMatches.length}</strong> (Esperado: <strong className="text-white">{res.expectedCount}</strong>)
                      </span>
                      {res.actualMatches.length > 0 && (
                        <span className="truncate max-w-md text-[#00FF41]">
                          Detectado: {res.actualMatches.slice(0, 2).map((s) => `"${s.length > 25 ? s.slice(0, 25) + '...' : s}"`).join(', ')}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="shrink-0 flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        const targetTest = loadUnitTests().find(t => t.id === res.testCaseId);
                        if (targetTest) {
                          handleLoadTestCaseToSandbox(targetTest);
                        }
                      }}
                      className="px-2.5 py-1.5 bg-[#1a1a1a] hover:bg-white text-zinc-300 hover:text-black border border-[#333] font-mono text-[9px] font-bold uppercase transition-colors cursor-pointer"
                      title="Carregar este caso de teste no Sandbox para visualização e edição"
                    >
                      Carregar no Sandbox
                    </button>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Save to Unit Tests Configuration Panel (Expandable) */}
      {showSaveUnitTest && (
        <div className="p-4 bg-[#0F0F0F] border border-[#FF3E00]/50 space-y-4 animate-in fade-in duration-200">
          <div className="flex items-center justify-between pb-2 border-b border-[#222]">
            <span className="text-xs font-black uppercase tracking-wider text-white flex items-center gap-2">
              <FlaskConical className="w-4 h-4 text-[#FF3E00]" />
              <span>Salvar Caso na Biblioteca JSON de Testes Unitários (Regressão)</span>
            </span>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-[#00FF41] bg-[#00FF41]/10 px-2 py-0.5 border border-[#00FF41]/30">
                STATUS: {parsingResult.matches.length} MATCH(ES) COMO ASSERÇÃO
              </span>
            </div>
          </div>

          <p className="text-xs font-mono text-[#888]">
            Grava este padrão regex e o texto de entrada em uma biblioteca persistente JSON. Em auditorias futuras, o motor executará este caso de teste para garantir que mudanças de sintaxe não causem regressões nem quebras de regras ativas.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-mono uppercase text-[#777] block mb-1">
                Nome do Caso de Teste Unitário
              </label>
              <input
                type="text"
                value={unitTestName}
                onChange={(e) => setUnitTestName(e.target.value)}
                placeholder="Ex: AWS Access Key ID Detection & Boundary Check"
                className="w-full px-3 py-1.5 text-xs bg-[#050505] border border-[#222] font-mono text-white focus:outline-none focus:border-[#FF3E00]"
              />
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase text-[#777] block mb-1">
                Padrão Regex & Modificadores Salvos
              </label>
              <div className="px-3 py-1.5 text-xs bg-[#000] border border-[#1A1A1A] font-mono text-[#00FF41] truncate">
                /{pattern}/{flags}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-[10px] font-mono uppercase text-[#777] block mb-1">
                Categoria do Finding
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as FindingCategory)}
                className="w-full px-3 py-1.5 text-xs bg-[#050505] border border-[#222] font-mono text-white focus:outline-none focus:border-[#FF3E00]"
              >
                <option value="API_KEY">API_KEY (Chave de API)</option>
                <option value="CLOUD_CREDENTIAL">CLOUD_CREDENTIAL (Nuvem)</option>
                <option value="AUTH_TOKEN">AUTH_TOKEN (Token de Acesso)</option>
                <option value="DATABASE_URI">DATABASE_URI (Banco de Dados)</option>
                <option value="PASSWORD">PASSWORD (Senha Hardcoded)</option>
                <option value="CUSTOM_REGEX">CUSTOM_REGEX (Customizado)</option>
              </select>
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase text-[#777] block mb-1">
                Severidade
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as SeverityLevel)}
                className="w-full px-3 py-1.5 text-xs bg-[#050505] border border-[#222] font-mono text-white focus:outline-none focus:border-[#FF3E00]"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase text-[#777] block mb-1">
                Asserção Esperada (Matches)
              </label>
              <div className="px-3 py-1.5 text-xs bg-[#050505] border border-[#222] font-mono text-white">
                <strong className="text-[#00FF41]">{parsingResult.matches.length}</strong> match(es) esperados
              </div>
            </div>
          </div>

          <div>
            <label className="text-[10px] font-mono uppercase text-[#777] block mb-1">
              Notas & Descrição da Regressão (Opcional)
            </label>
            <input
              type="text"
              value={unitTestDesc}
              onChange={(e) => setUnitTestDesc(e.target.value)}
              placeholder="Descreva o propósito da asserção ou casos de borda cobertos..."
              className="w-full px-3 py-1.5 text-xs bg-[#050505] border border-[#222] font-mono text-white focus:outline-none focus:border-[#FF3E00]"
            />
          </div>

          {/* Snapshot preview */}
          <div className="p-3 bg-[#050505] border border-[#1A1A1A] text-[11px] font-mono space-y-1">
            <div className="text-[#666] uppercase text-[9px]">Snapshot de Entrada (Test Input) Salvo:</div>
            <div className="text-zinc-400 truncate">
              {testText.slice(0, 140)}... ({testText.length} caracteres)
            </div>
            {parsingResult.matches.length > 0 && (
              <div className="text-[#00FF41] text-[10px] truncate pt-1 border-t border-[#111]">
                Matches capturados para regressão: {parsingResult.matches.map(m => m.fullMatch).slice(0, 3).join(', ')}
                {parsingResult.matches.length > 3 ? ` (+${parsingResult.matches.length - 3} mais)` : ''}
              </div>
            )}
          </div>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#222]">
            <button
              type="button"
              onClick={() => setShowSaveUnitTest(false)}
              className="px-3 py-1.5 text-[10px] font-mono uppercase text-[#888] hover:text-white border border-[#222] cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="button"
              id="btn-confirm-save-unit-test"
              onClick={handleSaveToUnitTestLibrary}
              className="px-4 py-1.5 text-[10px] font-black uppercase tracking-wider text-white bg-[#FF3E00] hover:bg-white hover:text-black transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <FlaskConical className="w-3.5 h-3.5" />
              <span>Salvar no JSON de Regressão</span>
            </button>
          </div>
        </div>
      )}

      {/* Persistent Unit Test Library Viewer (Expandable) */}
      {showUnitTestLibrary && (
        <div className="space-y-2">
          <RegexUnitTestLibrary
            onLoadTestCaseToSandbox={handleLoadTestCaseToSandbox}
            onClose={() => setShowUnitTestLibrary(false)}
          />
        </div>
      )}

      {/* Save Rule Quick-Config Panel (Expandable) */}
      {showSaveConfig && (
        <div className="p-4 bg-[#0F0F0F] border border-[#00FF41]/40 space-y-4 animate-in fade-in duration-200">
          <div className="flex items-center justify-between pb-2 border-b border-[#222]">
            <span className="text-xs font-black uppercase tracking-wider text-white flex items-center gap-2">
              <Sparkles className="w-3.5 h-3.5 text-[#00FF41]" />
              <span>Configurar Ativação de Regra Personalizada</span>
            </span>
            <span className="text-[10px] font-mono text-[#00FF41]">
              STATUS: {parsingResult.matches.length} CORRESPONDÊNCIA(S) CONFIRMADA(S)
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-[10px] font-mono uppercase text-[#777] block mb-1">
                Nome da Regra
              </label>
              <input
                type="text"
                value={ruleName}
                onChange={(e) => setRuleName(e.target.value)}
                placeholder="Ex: Token de Serviço Customizado"
                className="w-full px-3 py-1.5 text-xs bg-[#050505] border border-[#222] font-mono text-white focus:outline-none focus:border-[#00FF41]"
              />
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase text-[#777] block mb-1">
                Severidade
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as SeverityLevel)}
                className="w-full px-3 py-1.5 text-xs bg-[#050505] border border-[#222] font-mono text-white focus:outline-none focus:border-[#00FF41]"
              >
                <option value="CRITICAL">CRITICAL (Crítica)</option>
                <option value="HIGH">HIGH (Alta)</option>
                <option value="MEDIUM">MEDIUM (Média)</option>
                <option value="LOW">LOW (Baixa)</option>
              </select>
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase text-[#777] block mb-1">
                Categoria
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as FindingCategory)}
                className="w-full px-3 py-1.5 text-xs bg-[#050505] border border-[#222] font-mono text-white focus:outline-none focus:border-[#00FF41]"
              >
                <option value="API_KEY">API_KEY (Chave de API)</option>
                <option value="CLOUD_CREDENTIAL">CLOUD_CREDENTIAL (Nuvem)</option>
                <option value="AUTH_TOKEN">AUTH_TOKEN (Token de Acesso)</option>
                <option value="DATABASE_URI">DATABASE_URI (Banco de Dados)</option>
                <option value="PASSWORD">PASSWORD (Senha Hardcoded)</option>
                <option value="CUSTOM_REGEX">CUSTOM_REGEX (Padrão Customizado)</option>
              </select>
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#222]">
            <button
              type="button"
              onClick={() => setShowSaveConfig(false)}
              className="px-3 py-1.5 text-[10px] font-mono uppercase text-[#888] hover:text-white border border-[#222] cursor-pointer"
            >
              Cancelar
            </button>
            {onOpenManualModal && (
              <button
                type="button"
                onClick={() => {
                  setShowSaveConfig(false);
                  onOpenManualModal({
                    name: ruleName,
                    pattern,
                    flags,
                    severity,
                    category,
                    exampleMatch: parsingResult.matches[0]?.fullMatch
                  });
                }}
                className="px-3 py-1.5 text-[10px] font-mono uppercase text-white bg-[#1A1A1A] hover:bg-[#252525] border border-[#333] cursor-pointer"
              >
                Refinar Detalhes no Modal &rarr;
              </button>
            )}
            <button
              type="button"
              onClick={handleSaveToActiveRules}
              className="px-4 py-1.5 text-[10px] font-black uppercase tracking-wider text-black bg-[#00FF41] hover:bg-white transition-colors cursor-pointer"
            >
              Confirmar & Inserir nas Regras
            </button>
          </div>
        </div>
      )}

      {/* Regex Expression Bar & Flags */}
      <div className="p-4 bg-[#050505] border border-[#222] space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <label className="text-[10px] font-black uppercase tracking-[0.2em] text-[#888] flex items-center gap-1.5">
            <FileCode className="w-3.5 h-3.5 text-[#00FF41]" />
            <span>Padrão Regex & Modificadores</span>
          </label>

          {/* Regex Flags Toggles */}
          <div className="flex items-center gap-1.5">
            <span className="text-[9px] font-mono text-[#555] uppercase mr-1">Flags:</span>
            {[
              { flag: 'g', label: 'Global (/g)', title: 'Localiza todas as ocorrências' },
              { flag: 'i', label: 'Ignore Case (/i)', title: 'Não diferencia maiúsculas de minúsculas' },
              { flag: 'm', label: 'Multiline (/m)', title: '^ e $ ancoram no início e fim de cada linha' },
              { flag: 's', label: 'DotAll (/s)', title: 'O ponto (.) também captura quebras de linha' }
            ].map(({ flag, label, title }) => {
              const active = flags.includes(flag);
              return (
                <button
                  key={flag}
                  type="button"
                  onClick={() => toggleFlag(flag)}
                  title={title}
                  className={`px-2 py-0.5 text-[9px] font-mono uppercase font-bold border transition-colors cursor-pointer ${
                    active
                      ? 'bg-[#00FF41]/20 text-[#00FF41] border-[#00FF41]'
                      : 'bg-[#111] text-[#666] border-[#222] hover:text-white'
                  }`}
                >
                  {label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Input Bar */}
        <div className="flex items-center bg-[#000] border border-[#333] px-3 py-2 text-xs font-mono focus-within:border-[#00FF41] transition-colors">
          <span className="text-[#666] font-bold text-sm mr-1">/</span>
          <input
            type="text"
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
            placeholder="Digite a expressão regular (ex: (?<key>AKIA[0-9A-Z]{16}))"
            className="flex-1 bg-transparent text-[#00FF41] font-bold focus:outline-none placeholder-[#444]"
          />
          <span className="text-[#666] font-bold text-sm ml-1">/</span>
          <input
            type="text"
            value={flags}
            onChange={(e) => setFlags(e.target.value)}
            placeholder="flags"
            className="w-12 ml-1 bg-transparent text-white text-center focus:outline-none border-l border-[#222]"
          />
        </div>

        {/* Validation Status Message */}
        <div className="flex items-center justify-between text-[11px] font-mono">
          {parsingResult.error ? (
            <div className="text-[#FF3E00] flex items-center gap-1.5 font-bold">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>ERRO DE SINTAXE: {parsingResult.error}</span>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <span className="text-[#00FF41] flex items-center gap-1 font-bold">
                <Check className="w-3.5 h-3.5" />
                PADRÃO VÁLIDO
              </span>
              <span className="text-[#666]">|</span>
              <span className="text-white">
                {parsingResult.matches.length} correspondência(s) encontrada(s)
              </span>
              {parsingResult.groupsList.length > 0 && (
                <>
                  <span className="text-[#666]">|</span>
                  <span className="text-[#FF7A00]">
                    {parsingResult.groupsList.length} grupo(s) de captura identificados
                  </span>
                </>
              )}
            </div>
          )}

          {/* Quick preset selector */}
          <div className="hidden sm:flex items-center gap-1 text-[10px]">
            <span className="text-[#555]">Amostra:</span>
            {SAMPLE_TEST_CASES.map((sample, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => setTestText(sample.text)}
                className="text-[#888] hover:text-[#00FF41] underline px-1 cursor-pointer"
              >
                {sample.title.split(' ')[0]}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Interactive Dual-Pane: Live Textarea vs Real-Time Highlight Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column: Live Editable Textarea (6 cols) */}
        <div className="lg:col-span-6 space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-[10px] font-black uppercase tracking-[0.2em] text-[#888] flex items-center gap-2">
              <span className="w-4 h-4 bg-[#141414] border border-[#333] text-white flex items-center justify-center text-[10px] font-bold">1</span>
              <span>Área de Teste Editável (Input Textarea)</span>
            </label>
            <button
              type="button"
              onClick={() => setTestText('')}
              className="text-[9px] font-mono text-[#666] hover:text-white uppercase cursor-pointer"
            >
              Limpar Texto
            </button>
          </div>

          <div className="relative border border-[#222] bg-[#050505]">
            <textarea
              id="sandbox-test-textarea"
              rows={14}
              value={testText}
              onChange={(e) => setTestText(e.target.value)}
              placeholder="Cole aqui o código-fonte, arquivo .env ou payload que deseja auditar..."
              className={`w-full p-3.5 text-xs font-mono text-zinc-300 bg-transparent focus:outline-none focus:border-[#00FF41] resize-y ${
                isWordWrap ? 'whitespace-pre-wrap' : 'whitespace-pre overflow-x-auto'
              }`}
              spellCheck={false}
            />
            <div className="px-3 py-1.5 bg-[#0A0A0A] border-t border-[#1A1A1A] flex items-center justify-between text-[10px] font-mono text-[#666]">
              <span>{testText.length} caracteres | {testText.split('\n').length} linhas</span>
              <label className="flex items-center gap-1.5 cursor-pointer text-[#888] hover:text-white">
                <input
                  type="checkbox"
                  checked={isWordWrap}
                  onChange={(e) => setIsWordWrap(e.target.checked)}
                  className="accent-[#00FF41]"
                />
                <span>Quebra de linha</span>
              </label>
            </div>
          </div>
        </div>

        {/* Right Column: Instant Highlighting & Group Visualizer (6 cols) */}
        <div className="lg:col-span-6 space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-[10px] font-black uppercase tracking-[0.2em] text-[#888] flex items-center gap-2">
              <span className="w-4 h-4 bg-[#141414] border border-[#333] text-white flex items-center justify-center text-[10px] font-bold">2</span>
              <span>Realce Instantâneo & Capturas em Tempo Real</span>
            </label>
            <span className="text-[9px] font-mono text-[#00FF41]">
              LIVE_RENDER
            </span>
          </div>

          <div className="border border-[#222] bg-[#000] flex flex-col h-[385px]">
            {/* Scrollable highlighted render container */}
            <div 
              id="sandbox-highlight-container"
              className="flex-1 p-3.5 overflow-auto font-mono text-xs text-zinc-400 whitespace-pre-wrap leading-relaxed select-text"
            >
              {highlightedSegments.map((seg, i) => {
                if (!seg.isMatch) {
                  return <span key={i}>{seg.text}</span>;
                }

                const isSelected = selectedMatchIndex === seg.matchIndex;
                return (
                  <mark
                    key={i}
                    onClick={() => setSelectedMatchIndex(seg.matchIndex)}
                    className={`px-1 py-0.5 border font-bold cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-[#00FF41] text-black border-white shadow-[0_0_12px_rgba(0,255,65,0.6)]'
                        : 'bg-[#00FF41]/25 text-[#00FF41] border-[#00FF41]/60 hover:bg-[#00FF41]/40'
                    }`}
                    title={`Correspondência #${seg.matchIndex + 1} (Linha ${seg.matchData?.line}, Coluna ${seg.matchData?.column}) - Clique para inspecionar grupos`}
                  >
                    {seg.text}
                  </mark>
                );
              })}
            </div>

            {/* Quick legend bar */}
            <div className="px-3 py-1.5 bg-[#080808] border-t border-[#1A1A1A] flex items-center justify-between text-[10px] font-mono text-[#666]">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 bg-[#00FF41] inline-block" />
                <span className="text-zinc-300">Match Detectado</span>
                <span className="text-[#444]">•</span>
                <span className="text-[#888]">Clique na marcação para focar</span>
              </div>
              <span className="text-[#00FF41] font-bold">
                {parsingResult.matches.length} matches
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Step 3: Group Capture Visualization Table */}
      <div className="space-y-3 pt-2">
        <div className="flex items-center justify-between pb-2 border-b border-[#222]">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#FF7A00]" />
            <h3 className="text-xs font-black uppercase tracking-[0.2em] text-white">
              Visualização de Grupos de Captura (Capture Groups Breakdown)
            </h3>
          </div>
          <span className="text-[10px] font-mono text-[#888]">
            {parsingResult.matches.length === 0
              ? 'Nenhuma captura ativa'
              : `${parsingResult.matches.length} ocorrência(s) extraída(s)`}
          </span>
        </div>

        {parsingResult.matches.length === 0 ? (
          <div className="p-8 text-center bg-[#050505] border border-dashed border-[#222] space-y-2">
            <ShieldAlert className="w-8 h-8 text-[#444] mx-auto" />
            <p className="text-xs font-mono text-[#777]">
              Nenhuma correspondência capturada pelo padrão atual contra o texto informado.
            </p>
            <p className="text-[10px] font-mono text-[#555]">
              Ajuste o padrão regex acima ou selecione uma das amostras pré-carregadas.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="overflow-x-auto border border-[#1A1A1A]">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-[#111] text-[#777] uppercase text-[9px] tracking-wider border-b border-[#222]">
                  <tr>
                    <th className="p-2.5 w-12 text-center">#</th>
                    <th className="p-2.5 w-32">Posição</th>
                    <th className="p-2.5">Texto Completo Capturado (Match 0)</th>
                    <th className="p-2.5">Grupos Subjacentes / Named Groups</th>
                    <th className="p-2.5 w-24 text-right">Ação</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#141414] bg-[#070707]">
                  {parsingResult.matches.map((m, mIdx) => {
                    const isSelected = selectedMatchIndex === mIdx;
                    return (
                      <tr 
                        key={mIdx} 
                        className={`transition-colors ${
                          isSelected ? 'bg-[#141414] border-l-2 border-l-[#00FF41]' : 'hover:bg-[#0D0D0D]'
                        }`}
                      >
                        {/* Index badge */}
                        <td className="p-2.5 text-center font-bold text-[#888]">
                          <span className={`w-5 h-5 inline-flex items-center justify-center text-[10px] font-mono ${
                            isSelected ? 'bg-[#00FF41] text-black font-black' : 'bg-[#181818] text-white'
                          }`}>
                            {mIdx + 1}
                          </span>
                        </td>

                        {/* Location */}
                        <td className="p-2.5 text-[10px] text-[#888] whitespace-nowrap">
                          <div>Linha <span className="text-white font-bold">{m.line}</span>, Col <span className="text-white font-bold">{m.column}</span></div>
                          <div className="text-[#555] text-[9px]">Índice: {m.index}..{m.endIndex}</div>
                        </td>

                        {/* Full Match */}
                        <td className="p-2.5">
                          <div className="flex items-center gap-2">
                            <code className="bg-[#000] text-[#00FF41] px-2 py-1 border border-[#222] font-bold text-xs break-all max-w-md">
                              {m.fullMatch}
                            </code>
                            <button
                              type="button"
                              onClick={() => handleCopyMatchValue(m.fullMatch, mIdx)}
                              className="p-1 text-[#666] hover:text-white transition-colors cursor-pointer"
                              title="Copiar texto da captura"
                            >
                              {copiedMatch === mIdx ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                            </button>
                          </div>
                        </td>

                        {/* Subgroups visualization */}
                        <td className="p-2.5">
                          {m.groups.length === 0 ? (
                            <span className="text-[10px] text-[#555] italic">
                              Sem grupos de captura explícitos (Match completo único)
                            </span>
                          ) : (
                            <div className="flex flex-wrap gap-1.5">
                              {m.groups.map((grp, gIdx) => (
                                <div
                                  key={gIdx}
                                  className="inline-flex items-center gap-1.5 px-2 py-1 bg-[#000] border border-[#222] text-[10px]"
                                >
                                  <span className="text-[#FF7A00] font-bold">
                                    {grp.name ? `${grp.name}:` : `$${grp.groupIndex}:`}
                                  </span>
                                  <span className="text-white font-mono bg-[#141414] px-1.5 py-0.2">
                                    {grp.value}
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </td>

                        {/* Action buttons */}
                        <td className="p-2.5 text-right">
                          <button
                            type="button"
                            onClick={() => {
                              setSelectedMatchIndex(mIdx);
                              const elem = document.getElementById('sandbox-highlight-container');
                              if (elem) {
                                elem.scrollTop = Math.max(0, (m.line - 2) * 18);
                              }
                            }}
                            className="px-2.5 py-1 text-[9px] font-mono uppercase bg-[#141414] hover:bg-[#222] text-zinc-300 hover:text-white border border-[#333] cursor-pointer"
                          >
                            Inspecionar
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
