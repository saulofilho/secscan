import React, { useState, useEffect } from 'react';
import {
  X,
  Copy,
  Check,
  Download,
  GitBranch,
  ShieldCheck,
  SlidersHorizontal,
  FileCode,
  Key,
  Bell,
  Code,
  FileJson,
  Terminal,
  Layers,
  HelpCircle,
  ExternalLink,
  Workflow,
  FolderDown
} from 'lucide-react';
import { RegexRule, IgnorePatternItem } from '../types';

interface SecScanWorkflowModalProps {
  isOpen: boolean;
  onClose: () => void;
  rules?: RegexRule[];
  ignorePatterns?: IgnorePatternItem[];
}

export const SecScanWorkflowModal: React.FC<SecScanWorkflowModalProps> = ({
  isOpen,
  onClose,
  rules = [],
  ignorePatterns = []
}) => {
  const [activeTab, setActiveTab] = useState<'WORKFLOW' | 'ENV_DOCS' | 'JSON_SAMPLES'>('WORKFLOW');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const activeRules = rules.filter(r => r.enabled);

  // Workflow generation options
  const [branches, setBranches] = useState('main, master, develop');
  const [failOn, setFailOn] = useState<'critical' | 'high' | 'medium'>('critical');
  const [includeEnvCustomRules, setIncludeEnvCustomRules] = useState(true);
  const [includeEnvRuleOverrides, setIncludeEnvRuleOverrides] = useState(true);
  const [includeRulesFile, setIncludeRulesFile] = useState(true);
  const [rulesFilePath, setRulesFilePath] = useState('.secscan-rules.json');
  const [includeSarifUpload, setIncludeSarifUpload] = useState(true);
  const [includeSlackAlert, setIncludeSlackAlert] = useState(true);
  const [includeManualDispatch, setIncludeManualDispatch] = useState(true);
  const [includeNightlyCron, setIncludeNightlyCron] = useState(false);
  const [customIgnorePatterns, setCustomIgnorePatterns] = useState(() => {
    const active = ignorePatterns.filter(p => p.enabled).map(p => p.pattern);
    return active.length > 0 ? active.join(',') : 'node_modules,dist,build,vendor,**/*.test.js,**/*.spec.ts';
  });
  const [minEntropy, setMinEntropy] = useState('3.2');

  // Handle ESC key to close modal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleDownload = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'text/yaml;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Branch list array for yaml
  const parsedBranches = branches
    .split(',')
    .map(b => b.trim())
    .filter(Boolean)
    .map(b => `"${b}"`)
    .join(', ');

  // Generate .github/workflows/secscan.yml snippet dynamically based on user controls
  const generatedWorkflowYaml = `# =========================================================================
# SecScan SAST Security Pipeline
# Arquivo: .github/workflows/secscan.yml
# Gerado via SecScan DevSecOps Suite com suporte a Environment Rule Overrides
# =========================================================================

name: SecScan SAST Security Pipeline

on:
  push:
    branches: [ ${parsedBranches || '"main"'} ]
  pull_request:
    branches: [ ${parsedBranches || '"main"'} ]${includeManualDispatch ? '\n  workflow_dispatch: # Permite disparo manual via GitHub Actions UI' : ''}${includeNightlyCron ? '\n  schedule:\n    - cron: "0 3 * * *" # Execução noturna diária às 03:00 UTC' : ''}

permissions:
  contents: read
  ${includeSarifUpload ? 'security-events: write # Permite publicação de alertas SARIF na aba Security > Code scanning' : 'security-events: none'}

jobs:
  secscan-security-audit:
    name: SecScan SAST & Rule Overrides Pipeline
    runs-on: ubuntu-latest
    timeout-minutes: 15

    # =========================================================================
    # ⚙️ CONFIGURAÇÃO DE VARIÁVEIS DE AMBIENTE PARA SOBRESCRITA DE REGRAS
    # =========================================================================
    env:
      # Severidade mínima para quebrar o pipeline no Quality Gate (${failOn.toUpperCase()})
      SECSCAN_FAIL_ON: \${{ vars.SECSCAN_FAIL_ON || '${failOn}' }}
      
      # Padrões globais de exclusão no scanner SAST
      SECSCAN_IGNORE_PATTERNS: "${customIgnorePatterns}"
      
      # Piso de Entropia de Shannon (0.0 a 8.0) para heurística de chaves pseudo-aleatórias
      SECSCAN_MIN_ENTROPY: "${minEntropy}"${includeEnvCustomRules ? `
      
      # 🛡️ Regras personalizadas injetadas via GitHub Secret / Variable (JSON Array)
      # Permite adicionar novas chaves proprietárias sem alterar o código do repositório
      SECSCAN_CUSTOM_RULES: \${{ secrets.SECSCAN_CUSTOM_RULES || vars.SECSCAN_CUSTOM_RULES || '' }}` : ''}${includeEnvRuleOverrides ? `
      
      # ⚡ Sobrescrita de Regras Nativas (Rule Overrides em JSON Object)
      # Altere severidade (ex: promover HIGH para CRITICAL) ou refine o minEntropy
      SECSCAN_RULE_OVERRIDES: \${{ secrets.SECSCAN_RULE_OVERRIDES || vars.SECSCAN_RULE_OVERRIDES || '' }}` : ''}${includeRulesFile ? `
      
      # 📄 Caminho para arquivo de regras customizadas versionado localmente
      SECSCAN_CUSTOM_RULES_FILE: "${rulesFilePath}"` : ''}

    steps:
      - name: 📥 Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Análise histórica de commits e diffs de PR

      - name: ⚙️ Setup Node.js 22 LTS
        uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: 'npm'

      - name: 📦 Install Dependencies
        run: npm ci || npm install --prefer-offline

      - name: 🔍 Execute SecScan SAST with Custom Rule Overrides
        run: |
          echo "::group::🚀 Executing SecScan SAST Engine"
          node bin/secscan.js . \\
            --format sarif \\
            --output secscan-results.sarif \\
            --min-entropy "$SECSCAN_MIN_ENTROPY" \\
            --ignore "$SECSCAN_IGNORE_PATTERNS" \\${includeRulesFile ? `\n            --rules-file "$SECSCAN_CUSTOM_RULES_FILE" \\` : ''}${includeEnvCustomRules ? `\n            --custom-rules "$SECSCAN_CUSTOM_RULES" \\` : ''}${includeEnvRuleOverrides ? `\n            --rule-overrides "$SECSCAN_RULE_OVERRIDES"` : ''}
          echo "::endgroup::"
${includeSarifUpload ? `      - name: 🛡️ Upload SARIF Results to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secscan-results.sarif
          category: secscan-sast
` : ''}      - name: 🚦 Quality Gate Check (Bloquear PR em caso de violação)
        run: |
          echo "Verificando Quality Gate com severidade mínima: $SECSCAN_FAIL_ON"
          node bin/secscan.js . \\
            --fail-on "$SECSCAN_FAIL_ON" \\
            --ignore "$SECSCAN_IGNORE_PATTERNS" \\${includeEnvCustomRules ? `\n            --custom-rules "$SECSCAN_CUSTOM_RULES" \\` : ''}${includeEnvRuleOverrides ? `\n            --rule-overrides "$SECSCAN_RULE_OVERRIDES"` : ''}
${includeSlackAlert ? `      - name: 📢 Dispatch DevSecOps Alert on Failure
        if: failure()
        env:
          SLACK_WEBHOOK: \${{ secrets.SLACK_DEVSECOPS_WEBHOOK }}
        run: |
          if [ -n "$SLACK_WEBHOOK" ]; then
            echo "Enviando alerta para Webhook de Segurança..."
            curl -s -X POST -H 'Content-type: application/json' \\
              --data "{\\"text\\":\\"🚨 *[SecScan SAST Alert]* Falha no Quality Gate de Segurança!\\\\n• Repositório: \`\${GITHUB_REPOSITORY}\`\\\\n• Branch: \`\${GITHUB_REF_NAME}\`\\\\n• Commit: \`\${GITHUB_SHA:0:8}\`\\\\n• Autor: \${GITHUB_ACTOR}\\\\n• Pipeline: \${GITHUB_SERVER_URL}/\${GITHUB_REPOSITORY}/actions/runs/\${GITHUB_RUN_ID}\\"}" \\
              "$SLACK_WEBHOOK" > /dev/null || true
          fi
` : ''}`;

  // Sample JSON for SECSCAN_CUSTOM_RULES
  const sampleCustomRulesJson = `[
  {
    "id": "corp-internal-api-token",
    "name": "Corporate Internal API Token",
    "category": "API_KEY",
    "severity": "CRITICAL",
    "pattern": "(?i)corp[-_]token[-_]live[-_][a-z0-9]{32,48}",
    "minEntropy": 3.8,
    "description": "Token de acesso interno para microsserviços corporativos exposto.",
    "remediation": "Mova este token para o AWS Secrets Manager ou Vault e revogue a credencial.",
    "enabled": true
  },
  {
    "id": "acme-s3-private-bucket",
    "name": "ACME Internal S3 Storage Endpoint",
    "category": "CLOUD_CREDENTIAL",
    "severity": "HIGH",
    "pattern": "(?i)acme-(?:prod|staging)-[a-z0-9-]+\\\\.s3\\\\.amazonaws\\\\.com",
    "minEntropy": 2.5,
    "description": "Bucket privado S3 em ambiente produtivo referenciado diretamente.",
    "remediation": "Utilize IAM Roles for Service Accounts (IRSA) e acesse via CDN privada.",
    "enabled": true
  }
]`;

  // Sample JSON for SECSCAN_RULE_OVERRIDES
  const sampleRuleOverridesJson = `{
  "aws-access-key-id": {
    "severity": "CRITICAL",
    "minEntropy": 3.5,
    "description": "[POLICY OVERRIDE] Chaves AWS em qualquer repositório são tratadas com severidade máxima imediata.",
    "enabled": true
  },
  "generic-jwt-token": {
    "severity": "HIGH",
    "minEntropy": 4.2
  },
  "stripe-secret-key": {
    "severity": "CRITICAL"
  },
  "database-uri-credentials": {
    "severity": "CRITICAL",
    "remediation": "Substitua connection strings em texto puro por autenticação IAM ou Secret Manager."
  }
}`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/85 backdrop-blur-sm animate-in fade-in duration-150">
      <div
        id="secscan-workflow-modal-container"
        className="w-full max-w-5xl bg-[#0A0A0A] border-2 border-[#333] shadow-[0_0_50px_rgba(0,0,0,0.9)] max-h-[94vh] flex flex-col overflow-hidden text-white font-sans"
      >
        {/* Modal Top Header */}
        <div className="p-5 sm:p-6 bg-[#080808] border-b border-[#222] flex items-start justify-between gap-4 shrink-0">
          <div className="space-y-1.5 min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 bg-[#FF3E00]/15 border border-[#FF3E00]/40 text-[#FF3E00] font-mono text-[10px] font-black uppercase tracking-widest">
                <Workflow className="w-3 h-3" />
                GITHUB ACTIONS WORKFLOW
              </span>
              <span className="text-[10px] font-mono text-[#888]">
                // PRE-CONFIGURED PIPELINE TEMPLATE
              </span>
              <span className="text-[10px] font-mono bg-[#141414] text-[#00FF41] border border-[#00FF41]/30 px-2 py-0.5 font-bold">
                NODE 22 LTS
              </span>
              <span className="text-[10px] font-mono bg-[#141414] text-[#3366FF] border border-[#3366FF]/30 px-2 py-0.5 font-bold">
                RULE OVERRIDES READY
              </span>
              {activeRules.length > 0 && (
                <span className="text-[10px] font-mono bg-emerald-950/60 text-emerald-300 border border-emerald-700/50 px-2 py-0.5 font-bold inline-flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#00FF41] animate-pulse" />
                  {activeRules.length} REGRAS ATIVAS
                </span>
              )}
            </div>

            <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2">
              <span>Workflow Pré-Configurado</span>
              <code className="text-sm font-mono text-[#FF3E00] bg-[#141414] px-2 py-0.5 border border-[#333] lowercase font-normal">
                .github/workflows/secscan.yml
              </code>
            </h2>

            <p className="text-xs font-mono text-[#888] max-w-3xl leading-relaxed">
              Snippet pronto para cópia com suporte nativo a <strong>sobrescrita de regras via variáveis de ambiente</strong> (<code className="text-white">SECSCAN_CUSTOM_RULES</code> e <code className="text-white">SECSCAN_RULE_OVERRIDES</code>), Quality Gate de severidade e upload SARIF.
            </p>
          </div>

          <button
            id="btn-close-secscan-workflow-modal"
            onClick={onClose}
            className="w-9 h-9 bg-[#111] hover:bg-[#FF3E00] hover:text-white text-[#888] border border-[#333] flex items-center justify-center transition-colors shrink-0 cursor-pointer"
            title="Fechar (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Navigation Tabs & Action Bar */}
        <div className="px-5 sm:px-6 py-2.5 bg-[#0C0C0C] border-b border-[#222] flex flex-wrap items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-1 bg-[#141414] p-1 border border-[#222]">
            <button
              id="tab-btn-workflow-yaml"
              type="button"
              onClick={() => setActiveTab('WORKFLOW')}
              className={`px-3 py-1.5 text-xs font-mono font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'WORKFLOW'
                  ? 'bg-white text-black'
                  : 'text-[#888] hover:text-white'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Workflow YAML</span>
            </button>

            <button
              id="tab-btn-env-docs"
              type="button"
              onClick={() => setActiveTab('ENV_DOCS')}
              className={`px-3 py-1.5 text-xs font-mono font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'ENV_DOCS'
                  ? 'bg-white text-black'
                  : 'text-[#888] hover:text-white'
              }`}
            >
              <SlidersHorizontal className="w-3.5 h-3.5" />
              <span>Variáveis de Ambiente</span>
            </button>

            <button
              id="tab-btn-json-samples"
              type="button"
              onClick={() => setActiveTab('JSON_SAMPLES')}
              className={`px-3 py-1.5 text-xs font-mono font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'JSON_SAMPLES'
                  ? 'bg-white text-black'
                  : 'text-[#888] hover:text-white'
              }`}
            >
              <FileJson className="w-3.5 h-3.5" />
              <span>Exemplos de JSON (Overrides)</span>
            </button>
          </div>

          <div className="flex items-center gap-2">
            {/* Quick Path Copy */}
            <button
              type="button"
              onClick={() => handleCopy('.github/workflows/secscan.yml', 'file-path')}
              className="px-2.5 py-1.5 text-[11px] font-mono bg-[#141414] text-[#888] hover:text-white border border-[#262626] flex items-center gap-1.5 cursor-pointer transition-colors"
              title="Copiar caminho recomendado do arquivo"
            >
              {copiedKey === 'file-path' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
              <span>.github/workflows/secscan.yml</span>
            </button>

            {/* Download Rules JSON button */}
            {activeRules.length > 0 && (
              <button
                id="btn-download-secscan-rules-json-modal"
                type="button"
                onClick={() => {
                  const rulesJson = JSON.stringify(activeRules.map(r => ({
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
                  })), null, 2);
                  handleDownload('.secscan-rules.json', rulesJson);
                }}
                className="px-2.5 py-1.5 text-xs font-mono font-bold uppercase tracking-wider bg-[#141414] hover:bg-[#222] text-[#00FF41] border border-[#00FF41]/40 flex items-center gap-1.5 cursor-pointer transition-colors"
                title={`Baixar arquivo .secscan-rules.json com as ${activeRules.length} regras ativas`}
              >
                <Download className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Regras</span>
                <span>.json</span>
              </button>
            )}

            {/* Download YAML file button */}
            <button
              id="btn-download-secscan-yml"
              type="button"
              onClick={() => handleDownload('secscan.yml', generatedWorkflowYaml)}
              className="px-3 py-1.5 text-xs font-mono font-bold uppercase tracking-wider bg-[#141414] hover:bg-[#222] text-white border border-[#333] flex items-center gap-1.5 cursor-pointer transition-colors"
              title="Baixar arquivo secscan.yml pronto"
            >
              <Download className="w-3.5 h-3.5 text-[#3366FF]" />
              <span className="hidden sm:inline">Baixar</span>
              <span>.yml</span>
            </button>

            {/* Copy YAML Button */}
            <button
              id="btn-copy-secscan-workflow-yaml"
              type="button"
              onClick={() => handleCopy(generatedWorkflowYaml, 'workflow-yaml')}
              className="px-4 py-1.5 text-xs font-mono font-black uppercase tracking-wider bg-[#FF3E00] hover:bg-[#e03700] text-white border border-[#FF3E00] flex items-center gap-2 cursor-pointer transition-all shadow-md active:scale-95"
            >
              {copiedKey === 'workflow-yaml' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-white" />
                  <span>Copiado!</span>
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

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-5 sm:p-6 space-y-6">
          {activeTab === 'WORKFLOW' && (
            <div className="space-y-6">
              {/* Quick Interactive Customizer Panel */}
              <div className="bg-[#0D0D0D] border border-[#222] p-4 space-y-4">
                <div className="flex items-center justify-between border-b border-[#1A1A1A] pb-2.5">
                  <div className="flex items-center gap-2">
                    <SlidersHorizontal className="w-4 h-4 text-[#FF3E00]" />
                    <span className="text-xs font-black uppercase tracking-wider text-white">
                      Parâmetros Dinâmicos do Snippet
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-[#666]">
                    (O código YAML abaixo atualiza instantaneamente com base nas seleções)
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
                  {/* Target Branches */}
                  <div className="space-y-1">
                    <label className="text-[11px] text-[#888] flex items-center gap-1.5">
                      <GitBranch className="w-3 h-3 text-sky-400" />
                      <span>Branches Alvo:</span>
                    </label>
                    <input
                      type="text"
                      value={branches}
                      onChange={(e) => setBranches(e.target.value)}
                      placeholder="main, master, develop"
                      className="w-full px-2.5 py-1.5 bg-[#050505] border border-[#262626] text-white focus:border-[#FF3E00] focus:outline-none"
                    />
                  </div>

                  {/* Quality Gate Severity */}
                  <div className="space-y-1">
                    <label className="text-[11px] text-[#888] flex items-center gap-1.5">
                      <ShieldCheck className="w-3 h-3 text-[#00FF41]" />
                      <span>Quality Gate (Fail On):</span>
                    </label>
                    <select
                      value={failOn}
                      onChange={(e) => setFailOn(e.target.value as any)}
                      className="w-full px-2.5 py-1.5 bg-[#050505] border border-[#262626] text-white focus:border-[#FF3E00] focus:outline-none"
                    >
                      <option value="critical">CRITICAL (Apenas Segredos Críticos)</option>
                      <option value="high">HIGH (Críticos e Altos)</option>
                      <option value="medium">MEDIUM (Médios ou superiores)</option>
                    </select>
                  </div>

                  {/* Min Entropy */}
                  <div className="space-y-1">
                    <label className="text-[11px] text-[#888] flex items-center gap-1.5">
                      <Code className="w-3 h-3 text-amber-400" />
                      <span>Piso de Entropia (Shannon):</span>
                    </label>
                    <input
                      type="number"
                      step="0.1"
                      min="0.0"
                      max="8.0"
                      value={minEntropy}
                      onChange={(e) => setMinEntropy(e.target.value)}
                      className="w-full px-2.5 py-1.5 bg-[#050505] border border-[#262626] text-white focus:border-[#FF3E00] focus:outline-none"
                    />
                  </div>
                </div>

                {/* Checkboxes / Feature Toggles */}
                <div className="pt-2 border-t border-[#1A1A1A] grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 text-xs font-mono">
                  <label className="flex items-center gap-2 cursor-pointer text-zinc-300 hover:text-white">
                    <input
                      type="checkbox"
                      checked={includeEnvCustomRules}
                      onChange={(e) => setIncludeEnvCustomRules(e.target.checked)}
                      className="w-3.5 h-3.5 accent-[#FF3E00]"
                    />
                    <span className="truncate">Env <code className="text-[#00FF41] text-[11px]">SECSCAN_CUSTOM_RULES</code></span>
                  </label>

                  <label className="flex items-center gap-2 cursor-pointer text-zinc-300 hover:text-white">
                    <input
                      type="checkbox"
                      checked={includeEnvRuleOverrides}
                      onChange={(e) => setIncludeEnvRuleOverrides(e.target.checked)}
                      className="w-3.5 h-3.5 accent-[#FF3E00]"
                    />
                    <span className="truncate">Env <code className="text-[#3366FF] text-[11px]">SECSCAN_RULE_OVERRIDES</code></span>
                  </label>

                  <label className="flex items-center gap-2 cursor-pointer text-zinc-300 hover:text-white">
                    <input
                      type="checkbox"
                      checked={includeRulesFile}
                      onChange={(e) => setIncludeRulesFile(e.target.checked)}
                      className="w-3.5 h-3.5 accent-[#FF3E00]"
                    />
                    <span className="truncate">Arquivo de regras local (<code className="text-zinc-400 text-[10px]">{rulesFilePath}</code>)</span>
                  </label>

                  <label className="flex items-center gap-2 cursor-pointer text-zinc-300 hover:text-white">
                    <input
                      type="checkbox"
                      checked={includeSarifUpload}
                      onChange={(e) => setIncludeSarifUpload(e.target.checked)}
                      className="w-3.5 h-3.5 accent-[#FF3E00]"
                    />
                    <span>Upload SARIF (GitHub Code Scanning)</span>
                  </label>

                  <label className="flex items-center gap-2 cursor-pointer text-zinc-300 hover:text-white">
                    <input
                      type="checkbox"
                      checked={includeSlackAlert}
                      onChange={(e) => setIncludeSlackAlert(e.target.checked)}
                      className="w-3.5 h-3.5 accent-[#FF3E00]"
                    />
                    <span>Alerta Webhook no Fallback (Slack/Teams)</span>
                  </label>

                  <label className="flex items-center gap-2 cursor-pointer text-zinc-300 hover:text-white">
                    <input
                      type="checkbox"
                      checked={includeNightlyCron}
                      onChange={(e) => setIncludeNightlyCron(e.target.checked)}
                      className="w-3.5 h-3.5 accent-[#FF3E00]"
                    />
                    <span>Agendamento Cron Noturno (03:00 UTC)</span>
                  </label>
                </div>
              </div>

              {/* YAML Code Viewer */}
              <div className="border border-[#222] bg-[#050505] overflow-hidden">
                <div className="p-3 bg-[#080808] border-b border-[#222] flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center gap-2 text-[#888]">
                    <Terminal className="w-3.5 h-3.5 text-[#00FF41]" />
                    <span className="text-white font-bold">.github/workflows/secscan.yml</span>
                    <span className="text-[10px] text-[#555] hidden sm:inline">
                      ({generatedWorkflowYaml.split('\n').length} linhas)
                    </span>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleCopy(generatedWorkflowYaml, 'workflow-yaml')}
                    className="px-2.5 py-1 text-[11px] font-mono text-zinc-300 hover:text-white bg-[#141414] hover:bg-[#222] border border-[#333] flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    {copiedKey === 'workflow-yaml' ? (
                      <>
                        <Check className="w-3 h-3 text-[#00FF41]" />
                        <span>Copiado!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copiar Código</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="p-4 overflow-x-auto max-h-[460px] font-mono text-xs leading-relaxed text-zinc-300 scrollbar-thin">
                  <pre className="text-[11.5px] leading-5 font-mono">{generatedWorkflowYaml}</pre>
                </div>
              </div>

              {/* Step by step installation prompt */}
              <div className="bg-[#0A0A0A] border border-[#222] p-4 text-xs font-mono space-y-2">
                <div className="flex items-center gap-2 text-white font-bold uppercase tracking-wider">
                  <Key className="w-3.5 h-3.5 text-amber-400" />
                  <span>Como instalar no seu repositório em 3 passos:</span>
                </div>
                <ol className="list-decimal list-inside space-y-1 text-zinc-400 pl-1 text-[11.5px]">
                  <li>Crie a pasta <code className="text-white bg-[#141414] px-1.5 py-0.5 border border-[#262626]">.github/workflows/</code> no seu repositório.</li>
                  <li>Salve o snippet acima como <code className="text-white bg-[#141414] px-1.5 py-0.5 border border-[#262626]">.github/workflows/secscan.yml</code>.</li>
                  <li>(Opcional) Configure os segredos <code className="text-[#00FF41]">SECSCAN_CUSTOM_RULES</code> e <code className="text-[#3366FF]">SECSCAN_RULE_OVERRIDES</code> em <em>Settings &gt; Secrets and variables &gt; Actions</em> para sobrescrita dinâmica de regras!</li>
                </ol>
              </div>
            </div>
          )}

          {activeTab === 'ENV_DOCS' && (
            <div className="space-y-5 text-xs font-mono">
              <div className="bg-[#0A0A0A] border border-[#222] p-4 space-y-2">
                <div className="flex items-center gap-2">
                  <SlidersHorizontal className="w-4 h-4 text-[#FF3E00]" />
                  <h3 className="text-sm font-black uppercase text-white tracking-wider">
                    Variáveis de Ambiente & Sobrescrita de Regras (Rule Overrides)
                  </h3>
                </div>
                <p className="text-zinc-400 leading-relaxed text-[11.5px]">
                  O SecScan suporta injeção de regras e modificação de severidade em tempo de execução via <strong>Environment Variables</strong> do GitHub Actions. Isso permite que equipes de segurança apliquem políticas corporativas restritivas sem alterar o código dos desenvolvedores.
                </p>
              </div>

              {/* Table of Environment Variables */}
              <div className="border border-[#222] overflow-x-auto bg-[#080808]">
                <table className="w-full text-left border-collapse text-[11px]">
                  <thead>
                    <tr className="bg-[#111] text-zinc-400 border-b border-[#222] uppercase tracking-wider font-bold">
                      <th className="p-3">Variável de Ambiente</th>
                      <th className="p-3">Tipo / Origem</th>
                      <th className="p-3">Descrição & Finalidade</th>
                      <th className="p-3">Exemplo</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1A1A1A] text-zinc-300">
                    <tr className="hover:bg-white/5">
                      <td className="p-3 font-bold text-[#00FF41] whitespace-nowrap">SECSCAN_CUSTOM_RULES</td>
                      <td className="p-3 whitespace-nowrap text-zinc-400">Secret ou Var (JSON Array)</td>
                      <td className="p-3 text-zinc-300">
                        Injeta regras regex proprietárias dinamicamente. Ideal para detectar tokens de API internos de microsserviços da empresa.
                      </td>
                      <td className="p-3 text-zinc-400">
                        <code className="text-[10px] bg-black px-1.5 py-0.5 border border-[#222] text-amber-300">
                          [&#123;"id":"corp-key","pattern":"..."&#125;]
                        </code>
                      </td>
                    </tr>
                    <tr className="hover:bg-white/5">
                      <td className="p-3 font-bold text-[#3366FF] whitespace-nowrap">SECSCAN_RULE_OVERRIDES</td>
                      <td className="p-3 whitespace-nowrap text-zinc-400">Secret ou Var (JSON Object)</td>
                      <td className="p-3 text-zinc-300">
                        Sobrescreve configurações de regras nativas (ex: promover <code className="text-amber-400">HIGH</code> para <code className="text-rose-400">CRITICAL</code>, alterar <code className="text-sky-400">minEntropy</code> ou desativar falso positivo).
                      </td>
                      <td className="p-3 text-zinc-400">
                        <code className="text-[10px] bg-black px-1.5 py-0.5 border border-[#222] text-sky-300">
                          &#123;"aws-key":&#123;"severity":"CRITICAL"&#125;&#125;
                        </code>
                      </td>
                    </tr>
                    <tr className="hover:bg-white/5">
                      <td className="p-3 font-bold text-white whitespace-nowrap">SECSCAN_FAIL_ON</td>
                      <td className="p-3 whitespace-nowrap text-zinc-400">Action Variable (String)</td>
                      <td className="p-3 text-zinc-300">
                        Severidade mínima para quebrar o pipeline no Quality Gate (<code className="text-white">critical</code>, <code className="text-white">high</code>, <code className="text-white">medium</code>).
                      </td>
                      <td className="p-3 text-zinc-400">
                        <code className="text-[10px] bg-black px-1.5 py-0.5 border border-[#222] text-white">critical</code>
                      </td>
                    </tr>
                    <tr className="hover:bg-white/5">
                      <td className="p-3 font-bold text-white whitespace-nowrap">SECSCAN_CUSTOM_RULES_FILE</td>
                      <td className="p-3 whitespace-nowrap text-zinc-400">Path Local (String)</td>
                      <td className="p-3 text-zinc-300">
                        Arquivo local versionado no repositório com regras adicionais.
                      </td>
                      <td className="p-3 text-zinc-400">
                        <code className="text-[10px] bg-black px-1.5 py-0.5 border border-[#222] text-white">.secscan-rules.json</code>
                      </td>
                    </tr>
                    <tr className="hover:bg-white/5">
                      <td className="p-3 font-bold text-white whitespace-nowrap">SECSCAN_IGNORE_PATTERNS</td>
                      <td className="p-3 whitespace-nowrap text-zinc-400">String (Lista separada por vírgula)</td>
                      <td className="p-3 text-zinc-300">
                        Padrões de arquivos e pastas excluídos do escaneamento (ex: fixtures de teste, mocks, build).
                      </td>
                      <td className="p-3 text-zinc-400">
                        <code className="text-[10px] bg-black px-1.5 py-0.5 border border-[#222] text-zinc-400">node_modules,dist,**/*.test.js</code>
                      </td>
                    </tr>
                    <tr className="hover:bg-white/5">
                      <td className="p-3 font-bold text-white whitespace-nowrap">SLACK_DEVSECOPS_WEBHOOK</td>
                      <td className="p-3 whitespace-nowrap text-zinc-400">Repository Secret (URL)</td>
                      <td className="p-3 text-zinc-300">
                        URL de webhook do Slack ou Discord para notificação automática em caso de quebra do pipeline.
                      </td>
                      <td className="p-3 text-zinc-400">
                        <code className="text-[10px] bg-black px-1.5 py-0.5 border border-[#222] text-zinc-400">https://hooks.slack.com/...</code>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* GitHub Settings Instruction Callout */}
              <div className="bg-[#121212] border border-[#262626] p-4 flex items-start gap-3">
                <HelpCircle className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
                <div className="space-y-1 text-[11px] text-zinc-300">
                  <span className="font-bold text-white uppercase">Onde cadastrar no GitHub?</span>
                  <p>
                    Vá no seu repositório &gt; <strong>Settings</strong> &gt; <strong>Secrets and variables</strong> &gt; <strong>Actions</strong> &gt; <strong>New repository secret</strong> (ou <strong>Variables</strong>). Cole os dados no formato JSON especificado na aba <em>Exemplos de JSON (Overrides)</em>.
                  </p>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'JSON_SAMPLES' && (
            <div className="space-y-6 text-xs font-mono">
              {/* SECSCAN_CUSTOM_RULES JSON Snippet */}
              <div className="bg-[#0A0A0A] border border-[#222] overflow-hidden">
                <div className="p-3 bg-[#0E0E0E] border-b border-[#222] flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <FileJson className="w-4 h-4 text-[#00FF41]" />
                    <span className="text-xs font-bold text-white">Payload Exemplo: SECSCAN_CUSTOM_RULES</span>
                    <span className="text-[10px] px-2 py-0.5 bg-[#141414] text-[#00FF41] border border-[#00FF41]/30">
                      JSON ARRAY
                    </span>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleCopy(sampleCustomRulesJson, 'custom-rules-json')}
                    className="px-2.5 py-1 text-[11px] font-mono bg-[#141414] hover:bg-[#222] text-white border border-[#333] flex items-center gap-1.5 cursor-pointer transition-colors"
                  >
                    {copiedKey === 'custom-rules-json' ? (
                      <>
                        <Check className="w-3 h-3 text-[#00FF41]" />
                        <span>Copiado!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copiar JSON</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="p-4 bg-[#050505] overflow-x-auto text-[11.5px] leading-relaxed text-zinc-300">
                  <pre>{sampleCustomRulesJson}</pre>
                </div>

                <div className="p-2.5 bg-[#080808] border-t border-[#1F1F1F] text-[10.5px] text-zinc-500">
                  Cole este JSON no segredo <code className="text-[#00FF41]">SECSCAN_CUSTOM_RULES</code> no GitHub Actions para adicionar regras personalizadas sem modificar o projeto.
                </div>
              </div>

              {/* SECSCAN_RULE_OVERRIDES JSON Snippet */}
              <div className="bg-[#0A0A0A] border border-[#222] overflow-hidden">
                <div className="p-3 bg-[#0E0E0E] border-b border-[#222] flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <SlidersHorizontal className="w-4 h-4 text-[#3366FF]" />
                    <span className="text-xs font-bold text-white">Payload Exemplo: SECSCAN_RULE_OVERRIDES</span>
                    <span className="text-[10px] px-2 py-0.5 bg-[#141414] text-[#3366FF] border border-[#3366FF]/30">
                      JSON OBJECT
                    </span>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleCopy(sampleRuleOverridesJson, 'rule-overrides-json')}
                    className="px-2.5 py-1 text-[11px] font-mono bg-[#141414] hover:bg-[#222] text-white border border-[#333] flex items-center gap-1.5 cursor-pointer transition-colors"
                  >
                    {copiedKey === 'rule-overrides-json' ? (
                      <>
                        <Check className="w-3 h-3 text-[#00FF41]" />
                        <span>Copiado!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copiar JSON</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="p-4 bg-[#050505] overflow-x-auto text-[11.5px] leading-relaxed text-zinc-300">
                  <pre>{sampleRuleOverridesJson}</pre>
                </div>

                <div className="p-2.5 bg-[#080808] border-t border-[#1F1F1F] text-[10.5px] text-zinc-500">
                  Cole este JSON no segredo <code className="text-[#3366FF]">SECSCAN_RULE_OVERRIDES</code> no GitHub Actions para mudar severidades, entropias mínimas ou desativar regras.
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-[#080808] border-t border-[#222] flex flex-wrap items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-2 text-xs font-mono text-zinc-400">
            <ShieldCheck className="w-4 h-4 text-[#00FF41]" />
            <span>Compatível com GitHub Actions, SARIF CodeQL e SAST CI/CD Quality Gates.</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              id="btn-footer-close-secscan-modal"
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider text-zinc-400 hover:text-white bg-[#141414] hover:bg-[#222] border border-[#333] cursor-pointer transition-colors"
            >
              Fechar
            </button>

            <button
              id="btn-footer-copy-secscan-yaml"
              type="button"
              onClick={() => handleCopy(generatedWorkflowYaml, 'workflow-yaml')}
              className="px-5 py-2 text-xs font-mono font-black uppercase tracking-wider bg-[#FF3E00] hover:bg-[#e03700] text-white border border-[#FF3E00] flex items-center gap-2 cursor-pointer transition-all shadow-md active:scale-95"
            >
              {copiedKey === 'workflow-yaml' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-white" />
                  <span>Copiado!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copiar .github/workflows/secscan.yml</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
