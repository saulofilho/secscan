import React, { useState } from 'react';
import { Download, Copy, Check, FileJson, FileSpreadsheet, ShieldAlert, FileText, X, FileDown } from 'lucide-react';
import { ScanReport } from '../types';
import { exportToJson, exportToCsv, exportToSarif, exportToMarkdown } from '../lib/scanner';
import { downloadSecurityReportPdf } from '../lib/pdfReportGenerator';

interface ExportModalProps {
  report: ScanReport;
  onClose: () => void;
  initialFormat?: 'PDF' | 'JSON' | 'CSV' | 'SARIF' | 'MARKDOWN';
}

export const ExportModal: React.FC<ExportModalProps> = ({ report, onClose, initialFormat = 'PDF' }) => {
  const [selectedFormat, setSelectedFormat] = useState<'PDF' | 'JSON' | 'CSV' | 'SARIF' | 'MARKDOWN'>(initialFormat);
  const [copied, setCopied] = useState(false);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);

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
    exportContent = exportToSarif(report);
    fileName += '.sarif';
    mimeType = 'application/json';
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

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0A0A0A] max-w-2xl w-full p-6 sm:p-8 border border-[#333] space-y-5 max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-start justify-between pb-3 border-b border-[#222]">
          <div>
            <span className="text-[10px] font-black tracking-[0.25em] text-[#FF3E00] uppercase">
              // ARTIFACT EXPORT ENGINE
            </span>
            <h2 className="text-xl font-black uppercase tracking-tight text-white mt-1 flex items-center gap-2">
              <Download className="w-5 h-5 text-[#FF3E00]" />
              <span>Export SAST Security Report</span>
            </h2>
            <p className="text-xs font-mono text-[#888] mt-1">
              Escolha o formato adequado para sua esteira de CI/CD ou auditoria de conformidade
            </p>
          </div>
          <button onClick={onClose} className="text-[#666] hover:text-white p-1 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Format Selector Tabs - 5 Formats */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
          <button
            onClick={() => setSelectedFormat('PDF')}
            className={`p-3 border text-center transition-all flex flex-col items-center gap-1.5 ${
              selectedFormat === 'PDF'
                ? 'border-[#FF3E00] bg-[#1A0A00] text-white'
                : 'border-[#222] bg-[#050505] hover:border-[#333] text-[#888]'
            }`}
          >
            <FileDown className={`w-5 h-5 ${selectedFormat === 'PDF' ? 'text-[#FF3E00]' : 'text-[#666]'}`} />
            <span className="text-xs font-black uppercase tracking-wider">PDF EXECUTIVO</span>
            <span className="text-[9px] font-mono text-[#FF3E00]">A4 AUDIT REPORT</span>
          </button>

          <button
            onClick={() => setSelectedFormat('JSON')}
            className={`p-3 border text-center transition-all flex flex-col items-center gap-1.5 ${
              selectedFormat === 'JSON'
                ? 'border-[#FF3E00] bg-[#141414] text-white'
                : 'border-[#222] bg-[#050505] hover:border-[#333] text-[#888]'
            }`}
          >
            <FileJson className={`w-5 h-5 ${selectedFormat === 'JSON' ? 'text-[#FF3E00]' : 'text-[#666]'}`} />
            <span className="text-xs font-black uppercase tracking-wider">JSON CI/CD</span>
            <span className="text-[9px] font-mono text-[#666]">PIPELINE & API</span>
          </button>

          <button
            onClick={() => setSelectedFormat('CSV')}
            className={`p-3 border text-center transition-all flex flex-col items-center gap-1.5 ${
              selectedFormat === 'CSV'
                ? 'border-[#FF3E00] bg-[#141414] text-white'
                : 'border-[#222] bg-[#050505] hover:border-[#333] text-[#888]'
            }`}
          >
            <FileSpreadsheet className={`w-5 h-5 ${selectedFormat === 'CSV' ? 'text-[#00FF41]' : 'text-[#666]'}`} />
            <span className="text-xs font-black uppercase tracking-wider">CSV / SHEETS</span>
            <span className="text-[9px] font-mono text-[#666]">AUDIT & EXCEL</span>
          </button>

          <button
            onClick={() => setSelectedFormat('SARIF')}
            className={`p-3 border text-center transition-all flex flex-col items-center gap-1.5 ${
              selectedFormat === 'SARIF'
                ? 'border-[#FF3E00] bg-[#141414] text-white'
                : 'border-[#222] bg-[#050505] hover:border-[#333] text-[#888]'
            }`}
          >
            <ShieldAlert className={`w-5 h-5 ${selectedFormat === 'SARIF' ? 'text-purple-400' : 'text-[#666]'}`} />
            <span className="text-xs font-black uppercase tracking-wider">SARIF 2.1.0</span>
            <span className="text-[9px] font-mono text-[#666]">GITHUB SECURITY</span>
          </button>

          <button
            onClick={() => setSelectedFormat('MARKDOWN')}
            className={`p-3 border text-center transition-all flex flex-col items-center gap-1.5 ${
              selectedFormat === 'MARKDOWN'
                ? 'border-[#FF3E00] bg-[#141414] text-white'
                : 'border-[#222] bg-[#050505] hover:border-[#333] text-[#888]'
            }`}
          >
            <FileText className={`w-5 h-5 ${selectedFormat === 'MARKDOWN' ? 'text-amber-400' : 'text-[#666]'}`} />
            <span className="text-xs font-black uppercase tracking-wider">MARKDOWN</span>
            <span className="text-[9px] font-mono text-[#666]">SUMMARY REPORT</span>
          </button>
        </div>

        {/* Preview Screen */}
        <div className="flex-1 min-h-[200px] max-h-[260px] bg-[#000] text-[#CCC] p-4 font-mono text-xs overflow-y-auto border border-[#1A1A1A] leading-relaxed">
          <pre>{exportContent}</pre>
        </div>

        {/* Footer Actions */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-[#222]">
          <span className="text-xs text-[#666] font-mono">
            {report.findings.length} FINDINGS • {report.scannedFilesCount} FILES ANALYZED
          </span>

          <div className="flex items-center gap-2.5">
            <button
              onClick={handleCopy}
              className="inline-flex items-center gap-2 px-3.5 py-2.5 text-[10px] font-black uppercase tracking-[0.2em] text-white bg-[#111] hover:bg-white hover:text-black border border-[#333] transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'COPIADO!' : 'COPIAR'}</span>
            </button>

            <button
              onClick={handleDownload}
              disabled={isDownloadingPdf}
              className="inline-flex items-center gap-2 px-4 py-2.5 text-[10px] font-black uppercase tracking-[0.2em] text-black bg-white hover:bg-[#FF3E00] hover:text-white transition-colors disabled:opacity-50"
            >
              <Download className={`w-3.5 h-3.5 ${isDownloadingPdf ? 'animate-bounce' : ''}`} />
              <span>{isDownloadingPdf ? 'GERANDO PDF...' : `BAIXAR (${selectedFormat})`}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
