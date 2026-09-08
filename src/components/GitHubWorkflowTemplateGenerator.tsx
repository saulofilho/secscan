import React, { useState, useMemo } from 'react';
import {
  Download,
  Copy,
  Check,
  GitBranch,
  ShieldCheck,
  FileCode,
  SlidersHorizontal,
  FileJson,
  Sparkles,
  AlertTriangle,
  CheckCircle2,
  Info,
  Clock,
  Zap,
  ChevronDown,
  ChevronUp,
  FolderDown,
  Terminal,
  ShieldAlert,
  Key,
  Workflow
} from 'lucide-react';
import { RegexRule, IgnorePatternItem, SeverityLevel } from '../types';
import { safeCopyText } from '../lib/storage';

interface GitHubWorkflowTemplateGeneratorProps {
  rules?: RegexRule[];
  ignorePatterns?: IgnorePatternItem[];
  onOpenAdvancedModal?: () => void;
}

type WorkflowTemplatePreset = 'FULL_SAST' | 'PR_GUARD' | 'NIGHTLY_AUDIT' | 'CUSTOM';
type RulesIntegrationMode = 'FILE' | 'EMBEDDED_IDS' | 'SECRETS_VARS';

export const GitHubWorkflowTemplateGenerator: React.FC<GitHubWorkflowTemplateGeneratorProps> = ({
  rules = [],
  ignorePatterns = [],
  onOpenAdvancedModal
}) => {
  // Active rules filtered from current workspace
  const activeRules = useMemo(() => {
    return rules.filter(r => r.enabled);
  }, [rules]);

  // Derived metrics from active rules
  const activeStats = useMemo(() => {
    const critical = activeRules.filter(r => r.severity === 'CRITICAL').length;
    const high = activeRules.filter(r => r.severity === 'HIGH').length;
    const medium = activeRules.filter(r => r.severity === 'MEDIUM').length;
    const low = activeRules.filter(r => r.severity === 'LOW' || r.severity === 'INFO').length;

    // Minimum entropy among active rules that have minEntropy set
    const entropies = activeRules.map(r => r.minEntropy).filter((e): e is number => typeof e === 'number' && e > 0);
    const suggestedEntropy = entropies.length > 0 ? Math.min(...entropies).toFixed(1) : '3.2';

    // Categories
    const categories = Array.from(new Set(activeRules.map(r => r.category)));

    return {
      total: activeRules.length,
      critical,
      high,
      medium,
      low,
      suggestedEntropy,
      categories
    };
  }, [activeRules]);

  // Generator configuration states
  const [selectedPreset, setSelectedPreset] = useState<WorkflowTemplatePreset>('FULL_SAST');
  const [rulesMode, setRulesMode] = useState<RulesIntegrationMode>('FILE');
  const [branches, setBranches] = useState('main, master, develop');
  const [failOn, setFailOn] = useState<SeverityLevel>('CRITICAL');
  const [includeSarifUpload, setIncludeSarifUpload] = useState(true);
  const [includeSlackAlert, setIncludeSlackAlert] = useState(false);
  const [includeManualDispatch, setIncludeManualDispatch] = useState(true);
  const [includeNightlyCron, setIncludeNightlyCron] = useState(false);
  const [cronExpression, setCronExpression] = useState('0 3 * * *');
  const [minEntropy, setMinEntropy] = useState<string>(activeStats.suggestedEntropy);
  const [customIgnorePaths, setCustomIgnorePaths] = useState(() => {
    const activeIgnores = ignorePatterns.filter(p => p.enabled).map(p => p.pattern);
    return activeIgnores.length > 0
      ? activeIgnores.join(',')
      : 'node_modules,dist,build,vendor,**/*.test.js,**/*.spec.ts';
  });

  const [copiedType, setCopiedType] = useState<string | null>(null);
  const [isRulesListOpen, setIsRulesListOpen] = useState(false);
  const [activeCategoryFilter, setActiveCategoryFilter] = useState<string>('ALL');

  // Handle preset change
  const handleSelectPreset = (preset: WorkflowTemplatePreset) => {
    setSelectedPreset(preset);
    if (preset === 'FULL_SAST') {
      setBranches('main, master, develop');
      setFailOn('CRITICAL');
      setIncludeSarifUpload(true);
      setIncludeSlackAlert(false);
      setIncludeManualDispatch(true);
      setIncludeNightlyCron(false);
    } else if (preset === 'PR_GUARD') {
      setBranches('main, master');
      setFailOn('HIGH');
      setIncludeSarifUpload(false);
      setIncludeSlackAlert(false);
      setIncludeManualDispatch(false);
      setIncludeNightlyCron(false);
    } else if (preset === 'NIGHTLY_AUDIT') {
      setBranches('main');
      setFailOn('CRITICAL');
      setIncludeSarifUpload(true);
      setIncludeSlackAlert(true);
      setIncludeManualDispatch(true);
      setIncludeNightlyCron(true);
      setCronExpression('0 3 * * *');
    }
  };

  // Format branch list
  const formattedBranches = useMemo(() => {
    return branches
      .split(',')
      .map(b => b.trim())
      .filter(Boolean)
      .map(b => `"${b}"`)
      .join(', ');
  }, [branches]);

  // Active Rule IDs comma-separated
  const activeRuleIdsString = useMemo(() => {
    return activeRules.map(r => r.id).join(',');
  }, [activeRules]);

  // Clean JSON string of active rules
  const activeRulesJsonString = useMemo(() => {
    const simplified = activeRules.map(r => ({
      id: r.id,
      name: r.name,
      category: r.category,
      severity: r.severity,
      pattern: r.pattern,
      flags: r.flags || 'g',
      minEntropy: r.minEntropy || 3.0,
      enabled: true,
      description: r.description,
      remediation: r.remediation
    }));
    return JSON.stringify(simplified, null, 2);
  }, [activeRules]);

  // Generate the GitHub Actions Workflow YAML based on active rules
  const generatedWorkflowYaml = useMemo(() => {
    const rulesListComments = activeRules
      .map(r => `#   - [${r.severity}] ${r.id}: ${r.name}`)
      .join('\n');

    let rulesFlag = '';
    let rulesEnvBlock = '';

    if (rulesMode === 'FILE') {
      rulesEnvBlock = `      # Caminho do arquivo com as ${activeRules.length} regras ativas exportadas do SecScan
      SECSCAN_RULES_FILE: ".secscan-rules.json"`;
      rulesFlag = `            --rules-file "$SECSCAN_RULES_FILE" \\`;
    } else if (rulesMode === 'EMBEDDED_IDS') {
      rulesEnvBlock = `      # IDs das ${activeRules.length} regras ativas selecionadas no SecScan
      SECSCAN_ACTIVE_RULE_IDS: "${activeRuleIdsString}"`;
      rulesFlag = `            --active-rules "$SECSCAN_ACTIVE_RULE_IDS" \\`;
    } else {
      rulesEnvBlock = `      # Regras ativas injetadas via GitHub Secret / Repository Variable
      SECSCAN_CUSTOM_RULES: \${{ secrets.SECSCAN_CUSTOM_RULES || vars.SECSCAN_CUSTOM_RULES || '' }}`;
      rulesFlag = `            --custom-rules "$SECSCAN_CUSTOM_RULES" \\`;
    }

    return `# =========================================================================
# SecScan SAST Security Pipeline - GitHub Actions Workflow
# Arquivo: .github/workflows/secscan.yml
# Gerado via SecScan DevSecOps Suite
# Pré-configurado com base nas ${activeRules.length} Regras Ativas do Workspace
# =========================================================================
#
# REGRAS ATIVAS INCLUÍDAS NO PIPELINE (${activeRules.length}):
${rulesListComments || '#   (Nenhuma regra ativa selecionada - utilizando regras padrão)'}
#
# Severidades Ativas: ${activeStats.critical} Críticas, ${activeStats.high} Altas, ${activeStats.medium} Médias, ${activeStats.low} Baixas
# =========================================================================

name: SecScan Security Pipeline

on:
  push:
    branches: [ ${formattedBranches || '"main"'} ]
  pull_request:
    branches: [ ${formattedBranches || '"main"'} ]${includeManualDispatch ? '\n  workflow_dispatch: # Permite disparo manual sob demanda na UI do GitHub Actions' : ''}${includeNightlyCron ? `\n  schedule:\n    - cron: "${cronExpression}" # Auditoria noturna programada` : ''}

permissions:
  contents: read
  ${includeSarifUpload ? 'security-events: write # Permite envio de alertas SARIF para GitHub Security > Code Scanning' : 'security-events: none'}

jobs:
  secscan-security-audit:
    name: SecScan SAST Security Check
    runs-on: ubuntu-latest
    timeout-minutes: 15

    env:
      # Nível de Quality Gate para quebra de pipeline (${failOn.toUpperCase()})
      SECSCAN_FAIL_ON: \${{ vars.SECSCAN_FAIL_ON || '${failOn.toLowerCase()}' }}

      # Padrões globais de caminhos ignorados
      SECSCAN_IGNORE_PATTERNS: "${customIgnorePaths}"

      # Piso de Entropia de Shannon (calculado a partir das regras ativas)
      SECSCAN_MIN_ENTROPY: "${minEntropy}"

${rulesEnvBlock}

    steps:
      - name: 📥 Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Análise histórica profunda de commits e pull requests

      - name: ⚙️ Setup Node.js 22 LTS
        uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: 'npm'

      - name: 📦 Install Dependencies
        run: npm ci || npm install --prefer-offline

      - name: 🔍 Execute SecScan SAST (Regras Ativas: ${activeRules.length})
        run: |
          echo "::group::🚀 Executando SecScan com ${activeRules.length} Regras Ativas"
          node bin/secscan.js . \\
            --format sarif \\
            --output secscan-results.sarif \\
            --min-entropy "$SECSCAN_MIN_ENTROPY" \\
            --ignore "$SECSCAN_IGNORE_PATTERNS" \\
${rulesFlag}
          echo "::endgroup::"
${includeSarifUpload ? `
      - name: 🛡️ Upload SARIF to GitHub Security Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secscan-results.sarif
          category: secscan-active-rules
` : ''}
      - name: 🚦 Quality Gate Verification (Fail-On: ${failOn.toUpperCase()})
        run: |
          echo "Validando Quality Gate com severidade mínima: $SECSCAN_FAIL_ON"
          node bin/secscan.js . \\
            --fail-on "$SECSCAN_FAIL_ON" \\
            --ignore "$SECSCAN_IGNORE_PATTERNS" \\
${rulesFlag}
${includeSlackAlert ? `
      - name: 📢 Dispatch DevSecOps Webhook on Failure
        if: failure()
        env:
          DEVSECOPS_WEBHOOK: \${{ secrets.DEVSECOPS_WEBHOOK || secrets.SLACK_WEBHOOK }}
        run: |
          if [ -n "$DEVSECOPS_WEBHOOK" ]; then
            echo "Enviando alerta de falha de segurança para Webhook..."
            curl -s -X POST -H 'Content-type: application/json' \\
              --data "{\\"text\\":\\"🚨 *[SecScan SAST Alert]* Falha no Quality Gate de Segurança!\\\\n• Repositório: \`\${GITHUB_REPOSITORY}\`\\\\n• Branch: \`\${GITHUB_REF_NAME}\`\\\\n• Commit: \`\${GITHUB_SHA:0:8}\`\\\\n• Autor: \${GITHUB_ACTOR}\\\\n• Pipeline: \${GITHUB_SERVER_URL}/\${GITHUB_REPOSITORY}/actions/runs/\${GITHUB_RUN_ID}\\"}" \\
              "$DEVSECOPS_WEBHOOK" > /dev/null || true
          fi
` : ''}`;
  }, [
    activeRules,
    activeStats,
    rulesMode,
    formattedBranches,
    includeManualDispatch,
    includeNightlyCron,
    cronExpression,
    includeSarifUpload,
    failOn,
    customIgnorePaths,
    minEntropy,
    activeRuleIdsString,
    includeSlackAlert
  ]);

  // Download helper for a single text file
  const downloadFile = (filename: string, content: string, mimeType = 'text/yaml;charset=utf-8;') => {
    try {
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Falha ao baixar arquivo:', err);
    }
  };

  // Download both .yaml and .json files
  const handleDownloadBoth = () => {
    downloadFile('secscan.yml', generatedWorkflowYaml, 'text/yaml;charset=utf-8;');
    setTimeout(() => {
      downloadFile('.secscan-rules.json', activeRulesJsonString, 'application/json;charset=utf-8;');
    }, 400);
  };

  // Copy helper with feedback
  const handleCopy = async (text: string, type: string) => {
    await safeCopyText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  // Filtered active rules for visual inspection
  const displayedRules = useMemo(() => {
    if (activeCategoryFilter === 'ALL') return activeRules;
    return activeRules.filter(r => r.category === activeCategoryFilter);
  }, [activeRules, activeCategoryFilter]);

  return (
    <div id="github-workflow-template-generator" className="bg-[#0A0A0A] border-2 border-[#2B2B2B] overflow-hidden">
      {/* Top Banner Header */}
      <div className="p-5 sm:p-6 bg-[#0E0E0E] border-b border-[#222]">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5 min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 bg-[#00FF41]/15 border border-[#00FF41]/40 text-[#00FF41] font-mono text-[10.5px] font-black uppercase tracking-wider">
                <Workflow className="w-3.5 h-3.5" />
                GERADOR DE WORKFLOW GITHUB ACTIONS
              </span>
              <span className="text-[10px] font-mono bg-[#181818] text-white border border-[#333] px-2 py-0.5">
                .github/workflows/secscan.yml
              </span>
              <span className="inline-flex items-center gap-1 text-[10px] font-mono text-emerald-400 font-bold bg-emerald-950/40 border border-emerald-800/40 px-2 py-0.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#00FF41] animate-pulse inline-block" />
                {activeRules.length} REGRAS ATIVAS VINCULADAS
              </span>
            </div>

            <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2">
              <span>Template CI/CD Pré-Configurado</span>
              <span className="text-xs font-mono text-[#888] font-normal hidden sm:inline">
                // Sincronizado com as regras do SecScan
              </span>
            </h2>

            <p className="text-xs font-mono text-[#888] max-w-3xl leading-relaxed">
              Gere e baixe um arquivo <code className="text-white">.yaml</code> pronto para execução direta no GitHub Actions, pré-configurado com as <strong>{activeRules.length} regras de segurança ativas</strong> do seu workspace, Quality Gate automático e envio SARIF.
            </p>
          </div>

          {/* Download Action Buttons */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            {rulesMode === 'FILE' && (
              <button
                id="btn-download-both-bundle"
                type="button"
                onClick={handleDownloadBoth}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-mono font-black uppercase tracking-wider text-black bg-[#00FF41] hover:bg-[#00dd38] border border-[#00FF41] transition-all cursor-pointer shadow-md active:scale-95"
                title="Baixar ambos os arquivos: secscan.yml e .secscan-rules.json"
              >
                <FolderDown className="w-3.5 h-3.5" />
                <span>Baixar Pacote (.yml + .json)</span>
              </button>
            )}

            <button
              id="btn-download-workflow-yaml"
              type="button"
              onClick={() => downloadFile('secscan.yml', generatedWorkflowYaml)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-mono font-black uppercase tracking-wider text-white bg-[#1A1A1A] hover:bg-[#262626] border border-[#3A3A3A] hover:border-white transition-all cursor-pointer shadow-sm active:scale-95"
              title="Baixar arquivo secscan.yml pré-configurado com as regras ativas"
            >
              <Download className="w-3.5 h-3.5 text-[#00E5FF]" />
              <span>Baixar secscan.yml</span>
            </button>

            <button
              id="btn-copy-workflow-yaml-top"
              type="button"
              onClick={() => handleCopy(generatedWorkflowYaml, 'top-yaml')}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-mono font-bold uppercase tracking-wider text-[#CCC] bg-[#111] hover:bg-white hover:text-black border border-[#333] transition-colors cursor-pointer"
            >
              {copiedType === 'top-yaml' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-[#00FF41]" />
                  <span className="text-[#00FF41]">Copiado!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copiar YAML</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Active Rules Breakdown Pill Bar */}
        <div className="mt-4 pt-3 border-t border-[#1C1C1C] flex flex-wrap items-center justify-between gap-3 text-[11px] font-mono">
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-[#666]">Composição das regras ativas:</span>
            <span className="px-2 py-0.5 rounded bg-red-950/50 text-red-400 border border-red-800/40 font-bold">
              {activeStats.critical} Críticas
            </span>
            <span className="px-2 py-0.5 rounded bg-amber-950/50 text-amber-400 border border-amber-800/40 font-bold">
              {activeStats.high} Altas
            </span>
            <span className="px-2 py-0.5 rounded bg-blue-950/50 text-blue-400 border border-blue-800/40">
              {activeStats.medium} Médias
            </span>
            {activeStats.low > 0 && (
              <span className="px-2 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-800">
                {activeStats.low} Baixas
              </span>
            )}
            <span className="text-[#555]">|</span>
            <span className="text-zinc-400">
              Entropia sugerida: <strong className="text-white">{activeStats.suggestedEntropy}</strong>
            </span>
          </div>

          <button
            type="button"
            onClick={() => setIsRulesListOpen(prev => !prev)}
            className="text-[11px] text-[#00E5FF] hover:underline inline-flex items-center gap-1 cursor-pointer font-bold"
          >
            <span>{isRulesListOpen ? 'Ocultar regras incluídas' : `Inspecionar ${activeRules.length} regras ativas`}</span>
            {isRulesListOpen ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
        </div>

        {/* Collapsible Inspection of Active Rules */}
        {isRulesListOpen && (
          <div className="mt-4 p-3.5 bg-[#070707] border border-[#222] rounded space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1A1A1A] pb-2 text-[11px] font-mono">
              <span className="text-zinc-400">
                Regras ativas que serão executadas no runner do GitHub Actions:
              </span>

              {/* Category Filter Pills */}
              <div className="flex flex-wrap items-center gap-1">
                <button
                  type="button"
                  onClick={() => setActiveCategoryFilter('ALL')}
                  className={`px-2 py-0.5 rounded text-[10px] ${
                    activeCategoryFilter === 'ALL'
                      ? 'bg-white text-black font-bold'
                      : 'bg-[#141414] text-[#888] hover:text-white'
                  }`}
                >
                  Todas ({activeRules.length})
                </button>
                {activeStats.categories.map(cat => (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => setActiveCategoryFilter(cat)}
                    className={`px-2 py-0.5 rounded text-[10px] ${
                      activeCategoryFilter === cat
                        ? 'bg-[#00E5FF] text-black font-bold'
                        : 'bg-[#141414] text-[#888] hover:text-white'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            <div className="max-h-56 overflow-y-auto space-y-1.5 pr-1 font-mono text-[11px]">
              {displayedRules.map(rule => (
                <div
                  key={rule.id}
                  className="flex items-center justify-between p-2 bg-[#0C0C0C] hover:bg-[#121212] border border-[#1A1A1A] transition-colors gap-2"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span
                      className={`text-[9px] font-bold px-1.5 py-0.2 shrink-0 border ${
                        rule.severity === 'CRITICAL'
                          ? 'bg-red-950/80 text-red-400 border-red-800'
                          : rule.severity === 'HIGH'
                          ? 'bg-amber-950/80 text-amber-400 border-amber-800'
                          : 'bg-blue-950/80 text-blue-400 border-blue-800'
                      }`}
                    >
                      {rule.severity}
                    </span>
                    <span className="text-white font-semibold truncate">{rule.name}</span>
                    <code className="text-[10px] text-[#666] hidden md:inline">({rule.id})</code>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 text-[10px] text-[#888]">
                    <span className="hidden sm:inline px-1.5 py-0.2 bg-[#161616] text-[#AAA] border border-[#262626]">
                      {rule.category}
                    </span>
                    {rule.minEntropy && (
                      <span className="text-zinc-400">Entr: {rule.minEntropy}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {rulesMode === 'FILE' && (
              <div className="pt-2 flex items-center justify-between text-[11px] font-mono text-[#888] border-t border-[#1A1A1A]">
                <span>
                  O arquivo de regras <code className="text-white">.secscan-rules.json</code> contém todas as regras listadas acima.
                </span>
                <button
                  type="button"
                  onClick={() => downloadFile('.secscan-rules.json', activeRulesJsonString, 'application/json;charset=utf-8;')}
                  className="text-[#00FF41] hover:underline font-bold inline-flex items-center gap-1 cursor-pointer"
                >
                  <Download className="w-3 h-3" />
                  <span>Baixar apenas .secscan-rules.json</span>
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Preset Selector Bar */}
      <div className="p-4 bg-[#090909] border-b border-[#222]">
        <div className="text-[10px] font-mono text-[#888] uppercase tracking-wider mb-2 font-bold flex items-center gap-1.5">
          <Sparkles className="w-3.5 h-3.5 text-[#00E5FF]" />
          <span>Selecione um Arquétipo de Pipeline para GitHub Actions:</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {/* Preset 1: FULL SAST */}
          <button
            type="button"
            onClick={() => handleSelectPreset('FULL_SAST')}
            className={`p-3 text-left border transition-all cursor-pointer relative ${
              selectedPreset === 'FULL_SAST'
                ? 'bg-[#141414] border-[#00E5FF] text-white shadow-[0_0_15px_rgba(0,229,255,0.15)]'
                : 'bg-[#0E0E0E] border-[#222] text-[#888] hover:border-[#444] hover:text-[#CCC]'
            }`}
          >
            {selectedPreset === 'FULL_SAST' && (
              <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-[#00E5FF]" />
            )}
            <div className="flex items-center gap-1.5 text-xs font-mono font-black text-white uppercase">
              <ShieldCheck className="w-3.5 h-3.5 text-[#00E5FF]" />
              <span>Full SAST + SARIF</span>
            </div>
            <p className="text-[10px] font-mono text-[#777] mt-1 leading-snug">
              Push e Pull Request em branches principais com upload SARIF nativo e Quality Gate crítico.
            </p>
          </button>

          {/* Preset 2: PR GUARD */}
          <button
            type="button"
            onClick={() => handleSelectPreset('PR_GUARD')}
            className={`p-3 text-left border transition-all cursor-pointer relative ${
              selectedPreset === 'PR_GUARD'
                ? 'bg-[#141414] border-[#FF3E00] text-white shadow-[0_0_15px_rgba(255,62,0,0.15)]'
                : 'bg-[#0E0E0E] border-[#222] text-[#888] hover:border-[#444] hover:text-[#CCC]'
            }`}
          >
            {selectedPreset === 'PR_GUARD' && (
              <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-[#FF3E00]" />
            )}
            <div className="flex items-center gap-1.5 text-xs font-mono font-black text-white uppercase">
              <Zap className="w-3.5 h-3.5 text-[#FF3E00]" />
              <span>Fast PR Blocker</span>
            </div>
            <p className="text-[10px] font-mono text-[#777] mt-1 leading-snug">
              Quality Gate rigoroso (falha em HIGH ou CRITICAL) para impedir merges com segredos vazados.
            </p>
          </button>

          {/* Preset 3: NIGHTLY AUDIT */}
          <button
            type="button"
            onClick={() => handleSelectPreset('NIGHTLY_AUDIT')}
            className={`p-3 text-left border transition-all cursor-pointer relative ${
              selectedPreset === 'NIGHTLY_AUDIT'
                ? 'bg-[#141414] border-amber-400 text-white shadow-[0_0_15px_rgba(245,158,11,0.15)]'
                : 'bg-[#0E0E0E] border-[#222] text-[#888] hover:border-[#444] hover:text-[#CCC]'
            }`}
          >
            {selectedPreset === 'NIGHTLY_AUDIT' && (
              <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-amber-400" />
            )}
            <div className="flex items-center gap-1.5 text-xs font-mono font-black text-white uppercase">
              <Clock className="w-3.5 h-3.5 text-amber-400" />
              <span>Auditoria Noturna Cron</span>
            </div>
            <p className="text-[10px] font-mono text-[#777] mt-1 leading-snug">
              Execução programada às 03:00 UTC diariamente com notificação automática via Webhook em caso de falha.
            </p>
          </button>

          {/* Preset 4: CUSTOM */}
          <button
            type="button"
            onClick={() => handleSelectPreset('CUSTOM')}
            className={`p-3 text-left border transition-all cursor-pointer relative ${
              selectedPreset === 'CUSTOM'
                ? 'bg-[#141414] border-[#00FF41] text-white shadow-[0_0_15px_rgba(0,255,65,0.15)]'
                : 'bg-[#0E0E0E] border-[#222] text-[#888] hover:border-[#444] hover:text-[#CCC]'
            }`}
          >
            {selectedPreset === 'CUSTOM' && (
              <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-[#00FF41]" />
            )}
            <div className="flex items-center gap-1.5 text-xs font-mono font-black text-white uppercase">
              <SlidersHorizontal className="w-3.5 h-3.5 text-[#00FF41]" />
              <span>Personalizado</span>
            </div>
            <p className="text-[10px] font-mono text-[#777] mt-1 leading-snug">
              Ajuste fino manual de branches, modo de injeção de regras, limites e gatilhos de execução.
            </p>
          </button>
        </div>
      </div>

      {/* Configuration Controls Bar */}
      <div className="p-5 bg-[#0C0C0C] border-b border-[#222] grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
        {/* Col 1: Rules Integration Mode */}
        <div className="space-y-2">
          <label className="text-[10px] font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
            <Key className="w-3 h-3 text-[#00FF41]" />
            <span>Entrega das {activeRules.length} Regras Ativas:</span>
          </label>
          <div className="space-y-1.5">
            <button
              type="button"
              onClick={() => setRulesMode('FILE')}
              className={`w-full p-2 text-left border text-[11px] rounded transition-all cursor-pointer flex items-center justify-between ${
                rulesMode === 'FILE'
                  ? 'bg-[#161616] border-[#00FF41] text-white font-bold'
                  : 'bg-[#0E0E0E] border-[#222] text-zinc-400 hover:text-white'
              }`}
            >
              <span>1. Arquivo (.secscan-rules.json)</span>
              <span className="text-[9px] px-1 py-0.2 bg-[#222] text-zinc-300">Recomendado</span>
            </button>

            <button
              type="button"
              onClick={() => setRulesMode('EMBEDDED_IDS')}
              className={`w-full p-2 text-left border text-[11px] rounded transition-all cursor-pointer flex items-center justify-between ${
                rulesMode === 'EMBEDDED_IDS'
                  ? 'bg-[#161616] border-[#00E5FF] text-white font-bold'
                  : 'bg-[#0E0E0E] border-[#222] text-zinc-400 hover:text-white'
              }`}
            >
              <span>2. IDs Embutidos no YAML</span>
              <span className="text-[9px] px-1 py-0.2 bg-[#222] text-zinc-300">Zero Arquivo</span>
            </button>

            <button
              type="button"
              onClick={() => setRulesMode('SECRETS_VARS')}
              className={`w-full p-2 text-left border text-[11px] rounded transition-all cursor-pointer flex items-center justify-between ${
                rulesMode === 'SECRETS_VARS'
                  ? 'bg-[#161616] border-purple-400 text-white font-bold'
                  : 'bg-[#0E0E0E] border-[#222] text-zinc-400 hover:text-white'
              }`}
            >
              <span>3. GitHub Secrets / Variables</span>
              <span className="text-[9px] px-1 py-0.2 bg-[#222] text-zinc-300">Centralizado</span>
            </button>
          </div>
        </div>

        {/* Col 2: Quality Gate & Triggers */}
        <div className="space-y-3">
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-zinc-400 block mb-1">
              Quality Gate Fail-On:
            </label>
            <div className="grid grid-cols-3 gap-1.5">
              {(['CRITICAL', 'HIGH', 'MEDIUM'] as SeverityLevel[]).map(sev => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setFailOn(sev)}
                  className={`py-1.5 text-center text-[10.5px] font-bold border transition-colors cursor-pointer ${
                    failOn === sev
                      ? sev === 'CRITICAL'
                        ? 'bg-red-950/80 border-red-500 text-red-200'
                        : sev === 'HIGH'
                        ? 'bg-amber-950/80 border-amber-500 text-amber-200'
                        : 'bg-blue-950/80 border-blue-500 text-blue-200'
                      : 'bg-[#121212] border-[#222] text-[#777] hover:text-white'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-zinc-400 block mb-1">
              Branches Alvo (Push & PR):
            </label>
            <input
              type="text"
              value={branches}
              onChange={e => setBranches(e.target.value)}
              placeholder="main, master, develop"
              className="w-full px-2.5 py-1.5 bg-[#121212] border border-[#2B2B2B] text-white text-xs rounded focus:outline-none focus:border-[#00FF41]"
            />
          </div>
        </div>

        {/* Col 3: Pipeline Options Toggles */}
        <div className="space-y-2">
          <label className="text-[10px] font-bold uppercase tracking-wider text-zinc-400 block">
            Recursos do Workflow:
          </label>

          <label className="flex items-center gap-2 cursor-pointer text-[11px] text-zinc-300 hover:text-white">
            <input
              type="checkbox"
              checked={includeSarifUpload}
              onChange={e => setIncludeSarifUpload(e.target.checked)}
              className="accent-[#00FF41] rounded w-3.5 h-3.5"
            />
            <span>Upload SARIF para a aba Security</span>
          </label>

          <label className="flex items-center gap-2 cursor-pointer text-[11px] text-zinc-300 hover:text-white">
            <input
              type="checkbox"
              checked={includeManualDispatch}
              onChange={e => setIncludeManualDispatch(e.target.checked)}
              className="accent-[#00FF41] rounded w-3.5 h-3.5"
            />
            <span>Disparo manual (workflow_dispatch)</span>
          </label>

          <label className="flex items-center gap-2 cursor-pointer text-[11px] text-zinc-300 hover:text-white">
            <input
              type="checkbox"
              checked={includeNightlyCron}
              onChange={e => setIncludeNightlyCron(e.target.checked)}
              className="accent-[#00FF41] rounded w-3.5 h-3.5"
            />
            <span>Agendamento Noturno diário (Cron)</span>
          </label>

          <label className="flex items-center gap-2 cursor-pointer text-[11px] text-zinc-300 hover:text-white">
            <input
              type="checkbox"
              checked={includeSlackAlert}
              onChange={e => setIncludeSlackAlert(e.target.checked)}
              className="accent-[#00FF41] rounded w-3.5 h-3.5"
            />
            <span>Disparar Webhook em caso de falha</span>
          </label>
        </div>
      </div>

      {/* Code Preview Header */}
      <div className="p-3 bg-[#080808] border-b border-[#222] flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-2">
          <GitBranch className="w-3.5 h-3.5 text-[#FF3E00]" />
          <span className="text-white font-bold">.github/workflows/secscan.yml</span>
          <span className="text-[10px] px-2 py-0.2 bg-[#161616] text-[#888] border border-[#262626]">
            YAML // {generatedWorkflowYaml.split('\n').length} linhas
          </span>
        </div>

        <div className="flex items-center gap-2">
          {rulesMode === 'FILE' && (
            <button
              id="btn-download-rules-json"
              type="button"
              onClick={() => downloadFile('.secscan-rules.json', activeRulesJsonString, 'application/json;charset=utf-8;')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-bold text-[#00FF41] bg-[#141414] hover:bg-[#202020] border border-[#00FF41]/40 rounded transition-colors cursor-pointer"
              title="Baixar apenas o arquivo .secscan-rules.json com as regras ativas"
            >
              <Download className="w-3 h-3" />
              <span>.secscan-rules.json</span>
            </button>
          )}

          <button
            id="btn-download-secscan-yml-action"
            type="button"
            onClick={() => downloadFile('secscan.yml', generatedWorkflowYaml)}
            className="inline-flex items-center gap-1.5 px-3 py-1 text-[11px] font-black uppercase text-white bg-[#1E1E1E] hover:bg-white hover:text-black border border-[#3A3A3A] rounded transition-all cursor-pointer shadow-sm"
          >
            <Download className="w-3 h-3 text-[#00E5FF]" />
            <span>Baixar .yml</span>
          </button>

          <button
            id="btn-copy-workflow-yaml-code"
            type="button"
            onClick={() => handleCopy(generatedWorkflowYaml, 'code-yaml')}
            className="inline-flex items-center gap-1.5 px-3 py-1 text-[11px] font-bold uppercase text-[#CCC] bg-[#141414] hover:bg-white hover:text-black border border-[#2B2B2B] rounded transition-colors cursor-pointer"
          >
            {copiedType === 'code-yaml' ? (
              <>
                <Check className="w-3 h-3 text-[#00FF41]" />
                <span className="text-[#00FF41]">Copiado!</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span>Copiar</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Code Preview Body */}
      <div className="p-4 sm:p-5 bg-[#050505] text-[#D4D4D4] font-mono text-xs overflow-x-auto leading-relaxed max-h-[440px] border-b border-[#222]">
        <pre className="selection:bg-[#00FF41]/30 selection:text-white">
          {generatedWorkflowYaml}
        </pre>
      </div>

      {/* Bottom Info Bar & Quick Guide */}
      <div className="p-4 bg-[#080808] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono text-[#888]">
        <div className="flex items-center gap-2">
          <Info className="w-4 h-4 text-[#00E5FF] shrink-0" />
          <span>
            Coloque este arquivo em <code className="text-white bg-[#141414] px-1.5 py-0.5 border border-[#262626]">.github/workflows/secscan.yml</code> no seu repositório.
            {rulesMode === 'FILE' && (
              <> Coloque também o <code className="text-[#00FF41] bg-[#141414] px-1.5 py-0.5 border border-[#262626]">.secscan-rules.json</code> na raiz do projeto.</>
            )}
          </span>
        </div>

        {onOpenAdvancedModal && (
          <button
            type="button"
            onClick={onOpenAdvancedModal}
            className="text-[11px] font-bold text-[#00FF41] hover:underline uppercase tracking-wider cursor-pointer shrink-0"
          >
            Abrir Editor Avançado com Overrides &rarr;
          </button>
        )}
      </div>
    </div>
  );
};
