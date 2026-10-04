import React, { useState } from 'react';
import { 
  Download, 
  Copy, 
  Check, 
  FileJson, 
  FileSpreadsheet, 
  ShieldAlert, 
  FileText, 
  X, 
  FileDown, 
  ExternalLink,
  Code2,
  Workflow,
  Sparkles,
  CheckCircle2,
  Terminal
} from 'lucide-react';
import { ScanReport } from '../types';
import { exportToJson, exportToCsv, exportToSarif, exportToMarkdown } from '../lib/scanner';
import { downloadSecurityReportPdf } from '../lib/pdfReportGenerator';

/**
 * Translates internal severity levels (CRITICAL, HIGH, WARNING, MEDIUM, LOW, INFO)
 * to standard OASIS SARIF v2.1 'level' strings ('error', 'warning', 'note')
 * for accurate rendering in GitHub Advanced Security and third-party security platforms.
 */
export function mapSeverityToSarifLevel(severity: string): 'error' | 'warning' | 'note' {
  const normalized = (severity || '').toUpperCase().trim();
  switch (normalized) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'WARNING':
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
    case 'INFO':
    case 'NOTE':
    default:
      return 'note';
  }
}

interface ExportModalProps {
  report: ScanReport;
  onClose: () => void;
  initialFormat?: 'PDF' | 'JSON' | 'CSV' | 'SARIF' | 'MARKDOWN';
}

export const ExportModal: React.FC<ExportModalProps> = ({ report, onClose, initialFormat = 'PDF' }) => {
  const [selectedFormat, setSelectedFormat] = useState<'PDF' | 'JSON' | 'CSV' | 'SARIF' | 'MARKDOWN'>(initialFormat);
  const [sarifSubTab, setSarifSubTab] = useState<'payload' | 'github_actions'>('payload');
  const [includeSummaryMetadata, setIncludeSummaryMetadata] = useState<boolean>(true);
  const [copied, setCopied] = useState(false);
  const [copiedWorkflow, setCopiedWorkflow] = useState(false);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);

  // Generate GitHub Actions YAML for SARIF integration
  const gitHubActionsWorkflow = `# .github/workflows/secscan-sarif.yml
# GitHub Advanced Security & Code Scanning Pipeline
name: "SecScan AppSec - GitHub Code Scanning"

on:
  push:
    branches: [ "main", "master", "develop" ]
  pull_request:
    branches: [ "main", "master" ]
  schedule:
    - cron: '0 4 * * 1' # Runs every Monday at 04:00 UTC

jobs:
  secscan-analysis:
    name: "SecScan SAST & Secret Matrix"
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # Required for uploading SARIF to GitHub Security tab
      actions: read

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Node.js Environment
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install Dependencies
        run: npm ci --prefer-offline || npm install

      - name: Run SecScan Security Engine
        run: |
          npx secscan --output-format=sarif --output-file=secscan-results.sarif --fail-on=critical

      - name: Upload SARIF to GitHub Advanced Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secscan-results.sarif
          category: secscan-sast
`;

  let exportContent = '';
  let fileName = `secscan-report-${Date.now()}`;
  let mimeType = 'application/json';

  if (selectedFormat === 'PDF') {
    exportContent = `================================================================================
SECSCAN APPSEC SUITE — CONSOLIDATED SECURITY AUDIT & EXECUTIVE RISK ASSESSMENT (PDF)
================================================================================
Target Repository : ${report.target || 'Workspace Root'}
Timestamp         : ${new Date(report.timestamp).toLocaleString()}
Engine            : SecScan AppSec Suite v2.5 (Entropy + Deep Regex + Taint Analysis)

EXECUTIVE RISK SUMMARY:
--------------------------------------------------------------------------------
• Cumulative Risk Score  : ${report.metrics.riskScore ?? 0} / 100 [${report.metrics.riskLevel ?? 'MINIMAL'} RISK]
• Risk Scoring Formula   : ${report.metrics.workspaceRiskBreakdown?.formula || 'N/A'}
• Security Impact Score  : ${report.metrics.securityImpactScore ?? 0} / 100 [${report.metrics.impactLevel ?? 'NOMINAL'}]
• Compliance Health Score: ${report.metrics.securityScore}%
• Critical Vulnerabilities : ${report.metrics.criticalCount} (25 pts cada)
• High Risk Exposures    : ${report.metrics.highCount} (15 pts cada)
• Medium & Low Findings  : ${report.metrics.mediumCount + report.metrics.lowCount} (6 pts / 2 pts cada)
• Files Scanned / Ignored: ${report.scannedFilesCount} / ${report.ignoredFilesCount} (node_modules filter active)
• Quality Gate Status    : ${(report.metrics.riskScore ?? 0) >= 75 ? 'FAILED (CRITICAL RISK)' : (report.metrics.riskScore ?? 0) >= 50 ? 'WARNING (ELEVATED RISK)' : 'PASSED (COMPLIANT)'}

EXECUTIVE MITIGATION PHASES:
--------------------------------------------------------------------------------
[FASE 1] IMEDIATO (0-24h) : Rotação de chaves AWS, tokens Stripe e segredos em .env
[FASE 2] CURTO (1-3d)    : Expurgar histórico Git via git-filter-repo / BFG Repo-Cleaner
[FASE 3] MÉDIO (1 semana): Adotar Secrets Vault centralizado (Vault, AWS Secrets Mgr)
[FASE 4] CONTÍNUO        : Quality gates em CI/CD com bloqueio (--fail-on critical)

CONSOLIDATED FINDINGS INVENTORY:
--------------------------------------------------------------------------------
${report.findings.map((f, i) => `[#${i + 1}] [${f.severity}] ${f.ruleName} (${f.ruleId})
     File   : ${f.file}:${f.line}
     Entropy: ${f.entropy.toFixed(2)} bits/char | File Criticality: ${f.fileCriticality || 'MEDIUM'}
     Match  : ${f.maskedSecret || f.snippet}
     Action : ${f.remediation}
`).join('\n')}
================================================================================
* O arquivo PDF oficial contém formatação profissional A4, gráficos vetoriais,
  tabelas coloridas de severidade, matriz de endpoints e sumário executivo.
================================================================================`;
    fileName += '.pdf';
    mimeType = 'application/pdf';
  } else if (selectedFormat === 'JSON') {
    exportContent = exportToJson(report, true);
    fileName += '.json';
    mimeType = 'application/json';
  } else if (selectedFormat === 'CSV') {
    exportContent = exportToCsv(report);
    fileName += '.csv';
    mimeType = 'text/csv';
  } else if (selectedFormat === 'SARIF') {
    if (sarifSubTab === 'github_actions') {
      exportContent = gitHubActionsWorkflow;
      fileName = 'secscan-sarif-upload.yml';
      mimeType = 'text/yaml';
    } else {
      exportContent = exportToSarif(report, includeSummaryMetadata);
      fileName += '.sarif';
      mimeType = 'application/sarif+json';
    }
  } else {
    exportContent = exportToMarkdown(report);
    fileName += '.md';
    mimeType = 'text/markdown';
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(exportContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCopyWorkflow = () => {
    navigator.clipboard.writeText(gitHubActionsWorkflow);
    setCopiedWorkflow(true);
    setTimeout(() => setCopiedWorkflow(false), 2000);
  };

  const handleDownload = () => {
    if (selectedFormat === 'PDF') {
      setIsDownloadingPdf(true);
      try {
        downloadSecurityReportPdf(report);
      } finally {
        setTimeout(() => setIsDownloadingPdf(false), 800);
      }
      return;
    }

    const blob = new Blob([exportContent], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadWorkflowDirect = () => {
    const blob = new Blob([gitHubActionsWorkflow], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'secscan-github-actions.yml';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadSarifDirect = () => {
    const sarifRaw = exportToSarif(report, includeSummaryMetadata);
    const blob = new Blob([sarifRaw], { type: 'application/sarif+json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secscan-findings-${Date.now()}.sarif`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const uniqueRulesCount = Array.from(new Set(report.findings.map(f => f.ruleId))).length;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-4">
      <div className="bg-[#0A0A0C] max-w-3xl w-full p-5 sm:p-7 border border-zinc-800 shadow-[0_0_50px_rgba(0,0,0,0.8)] space-y-4 max-h-[92vh] flex flex-col rounded-lg">
        {/* Header */}
        <div className="flex items-start justify-between pb-3 border-b border-zinc-800">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-black tracking-[0.25em] text-[#FF3E00] uppercase font-mono">
                // ARTIFACT EXPORT ENGINE
              </span>
              <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-purple-500/15 text-purple-300 border border-purple-500/30 uppercase tracking-wider">
                SARIF 2.1.0 READY
              </span>
            </div>
            <h2 className="text-xl font-black uppercase tracking-tight text-white mt-1 flex items-center gap-2">
              <Download className="w-5 h-5 text-[#FF3E00]" />
              <span>Export SAST Security Report</span>
            </h2>
            <p className="text-xs font-mono text-zinc-400 mt-1">
              Escolha o formato adequado para auditoria, esteira de CI/CD ou integração nativa com GitHub Advanced Security
            </p>
          </div>
          <button 
            type="button"
            onClick={onClose} 
            className="text-zinc-500 hover:text-white p-1.5 rounded transition-colors cursor-pointer"
            title="Fechar"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Format Selector Tabs - 5 Formats */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          {/* PDF */}
          <button
            type="button"
            onClick={() => setSelectedFormat('PDF')}
            className={`p-2.5 sm:p-3 border text-center transition-all flex flex-col items-center gap-1.5 rounded cursor-pointer ${
              selectedFormat === 'PDF'
                ? 'border-[#FF3E00] bg-[#1A0A00] text-white shadow-[0_0_12px_rgba(255,62,0,0.2)]'
                : 'border-zinc-800/80 bg-[#0C0C0E] hover:border-zinc-700 text-zinc-400'
            }`}
          >
            <FileDown className={`w-5 h-5 ${selectedFormat === 'PDF' ? 'text-[#FF3E00]' : 'text-zinc-500'}`} />
            <span className="text-xs font-black uppercase tracking-wider">PDF EXECUTIVO</span>
            <span className="text-[9px] font-mono text-[#FF3E00]">A4 AUDIT REPORT</span>
          </button>

          {/* SARIF 2.1.0 */}
          <button
            type="button"
            id="btn-format-sarif"
            onClick={() => setSelectedFormat('SARIF')}
            className={`p-2.5 sm:p-3 border text-center transition-all flex flex-col items-center gap-1.5 rounded cursor-pointer relative ${
              selectedFormat === 'SARIF'
                ? 'border-purple-500 bg-[#160D24] text-white shadow-[0_0_15px_rgba(168,85,247,0.25)]'
                : 'border-zinc-800/80 bg-[#0C0C0E] hover:border-purple-500/50 text-zinc-400'
            }`}
          >
            <span className="absolute -top-1.5 -right-1 px-1.5 py-0.2 bg-purple-600 text-[8px] font-black font-mono text-white rounded uppercase tracking-tighter">
              ADVANCED
            </span>
            <ShieldAlert className={`w-5 h-5 ${selectedFormat === 'SARIF' ? 'text-purple-400' : 'text-zinc-500'}`} />
            <span className="text-xs font-black uppercase tracking-wider text-purple-200">SARIF 2.1.0</span>
            <span className="text-[9px] font-mono text-purple-400 font-bold">GITHUB SECURITY</span>
          </button>

          {/* JSON */}
          <button
            type="button"
            onClick={() => setSelectedFormat('JSON')}
            className={`p-2.5 sm:p-3 border text-center transition-all flex flex-col items-center gap-1.5 rounded cursor-pointer ${
              selectedFormat === 'JSON'
                ? 'border-[#FF3E00] bg-[#141418] text-white shadow-[0_0_12px_rgba(255,62,0,0.2)]'
                : 'border-zinc-800/80 bg-[#0C0C0E] hover:border-zinc-700 text-zinc-400'
            }`}
          >
            <FileJson className={`w-5 h-5 ${selectedFormat === 'JSON' ? 'text-[#FF3E00]' : 'text-zinc-500'}`} />
            <span className="text-xs font-black uppercase tracking-wider">JSON CI/CD</span>
            <span className="text-[9px] font-mono text-zinc-500">PIPELINE & API</span>
          </button>

          {/* CSV */}
          <button
            type="button"
            onClick={() => setSelectedFormat('CSV')}
            className={`p-2.5 sm:p-3 border text-center transition-all flex flex-col items-center gap-1.5 rounded cursor-pointer ${
              selectedFormat === 'CSV'
                ? 'border-[#00FF41] bg-[#0A1A0F] text-white shadow-[0_0_12px_rgba(0,255,65,0.2)]'
                : 'border-zinc-800/80 bg-[#0C0C0E] hover:border-zinc-700 text-zinc-400'
            }`}
          >
            <FileSpreadsheet className={`w-5 h-5 ${selectedFormat === 'CSV' ? 'text-[#00FF41]' : 'text-zinc-500'}`} />
            <span className="text-xs font-black uppercase tracking-wider">CSV / SHEETS</span>
            <span className="text-[9px] font-mono text-zinc-500">AUDIT & EXCEL</span>
          </button>

          {/* MARKDOWN */}
          <button
            type="button"
            onClick={() => setSelectedFormat('MARKDOWN')}
            className={`p-2.5 sm:p-3 border text-center transition-all flex flex-col items-center gap-1.5 rounded cursor-pointer ${
              selectedFormat === 'MARKDOWN'
                ? 'border-amber-500 bg-[#1A1408] text-white shadow-[0_0_12px_rgba(245,158,11,0.2)]'
                : 'border-zinc-800/80 bg-[#0C0C0E] hover:border-zinc-700 text-zinc-400'
            }`}
          >
            <FileText className={`w-5 h-5 ${selectedFormat === 'MARKDOWN' ? 'text-amber-400' : 'text-zinc-500'}`} />
            <span className="text-xs font-black uppercase tracking-wider">MARKDOWN</span>
            <span className="text-[9px] font-mono text-zinc-500">SUMMARY REPORT</span>
          </button>
        </div>

        {/* SARIF Special Information Banner */}
        {selectedFormat === 'SARIF' && (
          <div className="bg-[#120C1C] border border-purple-500/30 rounded p-3 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse" />
                <span className="font-bold text-purple-300 uppercase tracking-wide">
                  OASIS SARIF v2.1.0 Standard Consumed Natively
                </span>
              </div>
              <p className="text-[11px] text-zinc-400 leading-snug">
                Compatível com <strong className="text-purple-200">GitHub Advanced Security / Code Scanning</strong>, GitLab SAST, SonarQube, DefectDojo e Azure DevOps.
              </p>
            </div>

            <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
              <span className="px-2 py-1 bg-purple-950/60 border border-purple-500/40 rounded text-[10px] text-purple-300 font-bold">
                {report.findings.length} ACHADOS
              </span>
              <span className="px-2 py-1 bg-zinc-900 border border-zinc-700 rounded text-[10px] text-zinc-300">
                {uniqueRulesCount} REGRAS
              </span>
            </div>
          </div>
        )}

        {/* Sub-Tabs for SARIF: Payload vs GitHub Actions Workflow + Include Summary Metadata Checkbox */}
        {selectedFormat === 'SARIF' && (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 border-b border-zinc-800 pb-2.5">
            <div className="flex items-center gap-2 font-mono text-xs">
              <button
                type="button"
                id="btn-sarif-tab-payload"
                onClick={() => setSarifSubTab('payload')}
                className={`px-3 py-1.5 rounded flex items-center gap-2 transition-all cursor-pointer ${
                  sarifSubTab === 'payload'
                    ? 'bg-purple-900/40 text-purple-200 border border-purple-500/50 font-bold'
                    : 'text-zinc-400 hover:text-white hover:bg-zinc-800/40 border border-transparent'
                }`}
              >
                <Code2 className="w-3.5 h-3.5" />
                <span>SARIF 2.1.0 JSON ({fileName})</span>
              </button>

              <button
                type="button"
                id="btn-sarif-tab-workflow"
                onClick={() => setSarifSubTab('github_actions')}
                className={`px-3 py-1.5 rounded flex items-center gap-2 transition-all cursor-pointer ${
                  sarifSubTab === 'github_actions'
                    ? 'bg-purple-900/40 text-purple-200 border border-purple-500/50 font-bold'
                    : 'text-zinc-400 hover:text-white hover:bg-zinc-800/40 border border-transparent'
                }`}
              >
                <Workflow className="w-3.5 h-3.5 text-purple-400" />
                <span>GitHub Actions CI/CD (.yml)</span>
              </button>
            </div>

            {/* Checkbox: Include Summary Metadata */}
            <div className="flex items-center gap-2.5 pl-1 sm:pl-0">
              <label 
                htmlFor="checkbox-sarif-summary-metadata"
                className="inline-flex items-center gap-2 font-mono text-xs text-zinc-300 hover:text-white cursor-pointer select-none"
              >
                <input
                  type="checkbox"
                  id="checkbox-sarif-summary-metadata"
                  checked={includeSummaryMetadata}
                  onChange={(e) => setIncludeSummaryMetadata(e.target.checked)}
                  className="w-4 h-4 rounded border-zinc-700 bg-zinc-900 text-purple-600 focus:ring-purple-500 focus:ring-offset-zinc-950 cursor-pointer accent-purple-500"
                />
                <span className="font-semibold text-[11px] sm:text-xs">
                  Include Summary Metadata
                </span>
              </label>

              <span 
                className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-wider ${
                  includeSummaryMetadata 
                    ? 'bg-purple-950/50 text-purple-300 border-purple-500/40 font-bold' 
                    : 'bg-zinc-900 text-zinc-500 border-zinc-800'
                }`}
                title={includeSummaryMetadata ? 'Platform-wide scan summary & invocations included' : 'Minimalist mode: Only finding entries and rule definitions'}
              >
                {includeSummaryMetadata ? 'WITH SUMMARY' : 'FINDINGS ONLY'}
              </span>
            </div>
          </div>
        )}

        {/* Code Preview Screen */}
        <div className="relative flex-1 min-h-[220px] max-h-[300px] bg-[#050507] text-zinc-300 p-4 font-mono text-xs overflow-y-auto border border-zinc-800/80 rounded leading-relaxed select-text">
          <pre className="whitespace-pre">{exportContent}</pre>
        </div>

        {/* Footer Actions */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-zinc-800">
          <div className="flex items-center gap-2 text-xs text-zinc-400 font-mono">
            <span className="font-bold text-white">{report.findings.length}</span>
            <span>FINDINGS DETECTED</span>
            <span>•</span>
            <span className="font-bold text-white">{report.scannedFilesCount}</span>
            <span>FILES AUDITED</span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Quick action to download both or specific */}
            {selectedFormat === 'SARIF' && sarifSubTab === 'github_actions' && (
              <button
                type="button"
                onClick={handleDownloadSarifDirect}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-wider text-purple-300 bg-purple-950/40 hover:bg-purple-900/60 border border-purple-500/40 rounded transition-colors cursor-pointer"
                title="Baixar arquivo .sarif dos achados"
              >
                <ShieldAlert className="w-3 h-3 text-purple-400" />
                <span>Baixar .sarif</span>
              </button>
            )}

            {selectedFormat === 'SARIF' && sarifSubTab === 'payload' && (
              <button
                type="button"
                onClick={handleDownloadWorkflowDirect}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-wider text-zinc-300 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 rounded transition-colors cursor-pointer"
                title="Baixar workflow do GitHub Actions"
              >
                <Workflow className="w-3 h-3 text-purple-400" />
                <span>Workflow (.yml)</span>
              </button>
            )}

            <button
              type="button"
              id="btn-export-copy"
              onClick={handleCopy}
              className="inline-flex items-center gap-2 px-3.5 py-2.5 text-[10px] font-mono font-black uppercase tracking-[0.15em] text-white bg-zinc-900 hover:bg-white hover:text-black border border-zinc-700 rounded transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'COPIADO!' : 'COPIAR'}</span>
            </button>

            <button
              type="button"
              id="btn-export-download"
              onClick={handleDownload}
              disabled={isDownloadingPdf}
              className={`inline-flex items-center gap-2 px-4 py-2.5 text-[10px] font-mono font-black uppercase tracking-[0.15em] rounded transition-all cursor-pointer disabled:opacity-50 ${
                selectedFormat === 'SARIF'
                  ? 'text-black bg-purple-400 hover:bg-purple-300 shadow-[0_0_15px_rgba(168,85,247,0.3)]'
                  : 'text-black bg-white hover:bg-[#FF3E00] hover:text-white'
              }`}
            >
              <Download className={`w-3.5 h-3.5 ${isDownloadingPdf ? 'animate-bounce' : ''}`} />
              <span>
                {isDownloadingPdf 
                  ? 'GERANDO PDF...' 
                  : selectedFormat === 'SARIF' 
                  ? (sarifSubTab === 'payload' ? 'BAIXAR (SARIF 2.1.0)' : 'BAIXAR (WORKFLOW .YML)')
                  : `BAIXAR (${selectedFormat})`}
              </span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
