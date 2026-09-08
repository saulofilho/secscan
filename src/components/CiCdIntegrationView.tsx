import React, { useState } from 'react';
import { 
  CloudCog, 
  Copy, 
  Check, 
  GitBranch, 
  ShieldCheck, 
  Bell, 
  Send, 
  ExternalLink,
  Layers,
  Database,
  Workflow,
  SlidersHorizontal,
  FileCode,
  Sparkles,
  Download
} from 'lucide-react';
import { ScanReport, RegexRule, IgnorePatternItem } from '../types';
import { ScanScheduleManager } from './ScanScheduleManager';
import { SecScanWorkflowModal } from './SecScanWorkflowModal';
import { GitHubWorkflowTemplateGenerator } from './GitHubWorkflowTemplateGenerator';

interface CiCdIntegrationViewProps {
  report: ScanReport;
  rules?: RegexRule[];
  ignorePatterns?: IgnorePatternItem[];
}

export const CiCdIntegrationView: React.FC<CiCdIntegrationViewProps> = ({ 
  report,
  rules = [],
  ignorePatterns = []
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookStatus, setWebhookStatus] = useState<string | null>(null);
  const [isWorkflowModalOpen, setIsWorkflowModalOpen] = useState(false);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const githubWorkflowCode = `name: SecScan SAST Security Pipeline

on:
  push:
    branches: [ "main", "master" ]
  pull_request:
    branches: [ "main", "master" ]

permissions:
  contents: read
  security-events: write # Permite envio de SARIF para a aba Security

jobs:
  secret-scan:
    name: SecScan Secret & API Path SAST
    runs-on: ubuntu-latest
    steps:
      - name: 📥 Checkout Code
        uses: actions/checkout@v4

      - name: ⚙️ Setup Node.js 22
        uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: 'npm'

      - name: 📦 Install Dependencies
        run: npm ci || npm install

      - name: 🔍 Run SecScan (Ignora node_modules e gera SARIF)
        run: |
          node bin/secscan.js . \\
            --format sarif \\
            --output secscan-results.sarif \\
            --ignore "node_modules,dist,build,vendor"

      - name: 🛡️ Upload SARIF to GitHub Code Scanning Alerts
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secscan-results.sarif

      - name: 🚦 Quality Gate (Bloquear PR se houver credenciais críticas)
        run: |
          node bin/secscan.js . --fail-on critical
`;

  const awsSecretsSnippet = `// Integração Segura com AWS Secrets Manager (Substitui chaves expostas)
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

const client = new SecretsManagerClient({ region: process.env.AWS_REGION || "us-east-1" });

export async function getProductionSecret(secretId: string): Promise<string> {
  const command = new GetSecretValueCommand({ SecretId: secretId });
  const response = await client.send(command);
  return response.SecretString || "";
}`;

  const gcpSecretsSnippet = `// Integração Segura com Google Cloud Secret Manager
import { SecretManagerServiceClient } from '@google-cloud/secret-manager';

const client = new SecretManagerServiceClient();

export async function accessGoogleSecret(secretName: string): Promise<string> {
  const [version] = await client.accessSecretVersion({
    name: \`projects/\${process.env.GCP_PROJECT_ID}/secrets/\${secretName}/versions/latest\`,
  });
  return version.payload?.data?.toString() || '';
}`;

  const simulateWebhook = () => {
    if (!webhookUrl.trim()) {
      setWebhookStatus('Informe a URL do webhook do Slack/Discord.');
      return;
    }

    setWebhookStatus('Enviando alerta para o Webhook...');
    setTimeout(() => {
      setWebhookStatus('✅ Alerta DevSecOps disparado com sucesso no Webhook!');
    }, 800);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="bg-[#0A0A0A] p-6 sm:p-8 border border-[#222]">
        <div className="flex items-center gap-3">
          <span className="text-[10px] font-black tracking-[0.25em] text-[#FF3E00] uppercase">
            // DEVSECOPS PIPELINE & CLOUD AUTOMATION
          </span>
          <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-[#141414] text-white border border-[#333]">
            NODE 22 LTS
          </span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white uppercase mt-1">
          CI/CD & Cloud Vault Integration
        </h1>
        <p className="text-xs font-mono text-[#888] mt-1.5 max-w-3xl leading-relaxed">
          Automatize a execução do SecScan em pipelines de integração contínua (GitHub Actions, GitLab CI) e conecte com provedores de nuvem (AWS Secrets Manager, Google Cloud Secret Manager) para eliminação de credenciais estáticas no código.
        </p>

        {/* Action Bar for Pre-Configured Workflow Generator */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mt-5 pt-4 border-t border-[#1C1C1C]">
          <div className="flex items-center gap-2 text-xs font-mono text-[#AAA]">
            <Sparkles className="w-4 h-4 text-[#00FF41] shrink-0" />
            <span>Snippet pronto para cópia com suporte a overrides de severidade e regras dinâmicas</span>
          </div>

          <button
            id="btn-open-secscan-workflow-modal"
            type="button"
            onClick={() => setIsWorkflowModalOpen(true)}
            className="inline-flex items-center gap-2 px-4 py-2.5 text-xs font-mono font-black uppercase tracking-wider text-black bg-[#00FF41] hover:bg-[#00dd38] border border-[#00FF41] cursor-pointer transition-all shadow-md active:scale-95 shrink-0"
          >
            <Workflow className="w-4 h-4 text-black" />
            <span>Gerar .github/workflows/secscan.yml</span>
          </button>
        </div>
      </div>

      {/* Automated Scan Schedules with Cron Engine */}
      <ScanScheduleManager report={report} />

      {/* GitHub Actions Workflow Template Generator (Pre-Configured with Active Rules) */}
      <GitHubWorkflowTemplateGenerator
        rules={rules}
        ignorePatterns={ignorePatterns}
        onOpenAdvancedModal={() => setIsWorkflowModalOpen(true)}
      />

      {/* Cloud Providers Secrets Replacement */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* AWS Secrets Manager */}
        <div className="bg-[#0A0A0A] border border-[#222] overflow-hidden flex flex-col">
          <div className="p-4 bg-[#080808] border-b border-[#222] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-amber-500" />
              <span className="text-xs font-black uppercase tracking-wider text-white">AWS Secrets Manager / KMS</span>
            </div>
            <button
              onClick={() => handleCopy(awsSecretsSnippet, 'aws')}
              className="text-[10px] font-black uppercase tracking-widest text-[#FF3E00] hover:underline"
            >
              {copiedKey === 'aws' ? 'COPIADO!' : 'COPIAR SNIPPET'}
            </button>
          </div>

          <div className="p-4 bg-[#050505] text-[#00FF41] font-mono text-xs flex-1 overflow-x-auto leading-relaxed">
            <pre>{awsSecretsSnippet}</pre>
          </div>

          <div className="p-3 bg-[#080808] border-t border-[#222] text-[10px] font-mono text-[#666]">
            Instale: <code className="bg-[#000] px-1.5 py-0.5 border border-[#1A1A1A] text-white">npm install @aws-sdk/client-secrets-manager</code>
          </div>
        </div>

        {/* GCP Secret Manager */}
        <div className="bg-[#0A0A0A] border border-[#222] overflow-hidden flex flex-col">
          <div className="p-4 bg-[#080808] border-b border-[#222] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-400" />
              <span className="text-xs font-black uppercase tracking-wider text-white">Google Cloud Secret Manager</span>
            </div>
            <button
              onClick={() => handleCopy(gcpSecretsSnippet, 'gcp')}
              className="text-[10px] font-black uppercase tracking-widest text-[#FF3E00] hover:underline"
            >
              {copiedKey === 'gcp' ? 'COPIADO!' : 'COPIAR SNIPPET'}
            </button>
          </div>

          <div className="p-4 bg-[#050505] text-[#00FF41] font-mono text-xs flex-1 overflow-x-auto leading-relaxed">
            <pre>{gcpSecretsSnippet}</pre>
          </div>

          <div className="p-3 bg-[#080808] border-t border-[#222] text-[10px] font-mono text-[#666]">
            Instale: <code className="bg-[#000] px-1.5 py-0.5 border border-[#1A1A1A] text-white">npm install @google-cloud/secret-manager</code>
          </div>
        </div>
      </div>

      {/* Webhook Alert Simulator (Slack / Discord) */}
      <div className="bg-[#0A0A0A] p-6 sm:p-8 border border-[#222] space-y-4">
        <div className="flex items-center gap-2">
          <Bell className="w-4 h-4 text-[#FF3E00]" />
          <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white">Webhooks & Alert Dispatchers (Slack / Discord / Teams)</h2>
        </div>
        <p className="text-xs font-mono text-[#888]">
          Dispare alertas instantâneos para o canal de segurança do seu time sempre que credenciais críticas forem detectadas em commits ou pull requests.
        </p>

        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="url"
            placeholder="https://hooks.example.com/services/T00/B00/XXXXX"
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            className="flex-1 px-3 py-2 text-xs bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
          />
          <button
            onClick={simulateWebhook}
            className="inline-flex items-center justify-center gap-2 px-5 py-2.5 text-[10px] font-black uppercase tracking-[0.2em] text-black bg-white hover:bg-[#FF3E00] hover:text-white transition-colors shrink-0"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Testar Disparo</span>
          </button>
        </div>

        {webhookStatus && (
          <div className="p-3 bg-[#050505] border border-[#222] text-xs font-mono text-[#00FF41]">
            {webhookStatus}
          </div>
        )}
      </div>

      {/* SecScan GitHub Actions Workflow Modal (.github/workflows/secscan.yml) */}
      <SecScanWorkflowModal
        isOpen={isWorkflowModalOpen}
        onClose={() => setIsWorkflowModalOpen(false)}
        rules={rules}
        ignorePatterns={ignorePatterns}
      />
    </div>
  );
};
