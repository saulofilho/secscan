import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Scale,
  FileText,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Download,
  Copy,
  Check,
  Search,
  Layers,
  Lock,
  ChevronDown,
  ChevronUp,
  BookOpen,
  Award,
  AlertCircle,
  FileCode,
  Zap,
  Info
} from 'lucide-react';
import { ScanReport, ScanFinding, ComplianceFrameworkId, ComplianceControlStatus } from '../types';
import {
  COMPLIANCE_FRAMEWORKS_META,
  evaluateComplianceReadiness,
  generateComplianceMarkdownReport
} from '../lib/complianceEngine';

interface ComplianceReadinessPanelProps {
  report: ScanReport;
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToScanner?: () => void;
  onNavigateToFile?: (filePath: string) => void;
}

export const ComplianceReadinessPanel: React.FC<ComplianceReadinessPanelProps> = ({
  report,
  onSelectFinding,
  onNavigateToScanner,
  onNavigateToFile,
}) => {
  const [selectedFramework, setSelectedFramework] = useState<ComplianceFrameworkId | 'ALL'>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | ComplianceControlStatus>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedControlIds, setExpandedControlIds] = useState<Record<string, boolean>>({});
  const [copiedReport, setCopiedReport] = useState<boolean>(false);
  const [copiedFindingId, setCopiedFindingId] = useState<string | null>(null);

  // 1. Evaluate Compliance Posture
  const assessment = useMemo(() => {
    return evaluateComplianceReadiness(report.findings || []);
  }, [report.findings]);

  // Set default expanded controls to all that are AT_RISK initially
  const activeExpanded = useMemo(() => {
    if (Object.keys(expandedControlIds).length > 0) {
      return expandedControlIds;
    }
    const initial: Record<string, boolean> = {};
    assessment.evaluatedControls.forEach((ctrl) => {
      if (ctrl.status === 'AT_RISK') {
        initial[ctrl.id] = true;
      }
    });
    return initial;
  }, [expandedControlIds, assessment.evaluatedControls]);

  // Toggle control accordion
  const toggleControlExpanded = (id: string) => {
    setExpandedControlIds((prev) => ({
      ...prev,
      [id]: !(prev[id] ?? (assessment.evaluatedControls.find((c) => c.id === id)?.status === 'AT_RISK')),
    }));
  };

  // 2. Filter Controls based on framework, status, and search query
  const filteredControls = useMemo(() => {
    return assessment.evaluatedControls.filter((ctrl) => {
      if (selectedFramework !== 'ALL' && ctrl.framework !== selectedFramework) {
        return false;
      }
      if (statusFilter !== 'ALL' && ctrl.status !== statusFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchTitle = ctrl.title.toLowerCase().includes(query);
        const matchCode = ctrl.code.toLowerCase().includes(query);
        const matchCategory = ctrl.category.toLowerCase().includes(query);
        const matchFw = ctrl.frameworkName.toLowerCase().includes(query);
        const matchFinding = ctrl.matchingFindings.some(
          (f) => f.ruleName.toLowerCase().includes(query) || f.file.toLowerCase().includes(query)
        );
        if (!matchTitle && !matchCode && !matchCategory && !matchFw && !matchFinding) {
          return false;
        }
      }
      return true;
    });
  }, [assessment.evaluatedControls, selectedFramework, statusFilter, searchQuery]);

  // Copy Markdown Report
  const handleCopyMarkdownReport = () => {
    const md = generateComplianceMarkdownReport(assessment);
    navigator.clipboard.writeText(md);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2200);
  };

  // Download Markdown Report
  const handleDownloadMarkdownReport = () => {
    const md = generateComplianceMarkdownReport(assessment);
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `compliance-readiness-audit-${new Date().toISOString().split('T')[0]}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Copy Finding Details
  const handleCopyFinding = (finding: ScanFinding) => {
    const text = `[${finding.severity}] ${finding.ruleName} em ${finding.file}:${finding.line} | Segredo: ${finding.maskedSecret}`;
    navigator.clipboard.writeText(text);
    setCopiedFindingId(finding.id);
    setTimeout(() => setCopiedFindingId(null), 1800);
  };

  // Framework list for tabs
  const frameworkKeys: ComplianceFrameworkId[] = ['SOC2', 'HIPAA', 'OWASP_TOP_10', 'PCI_DSS', 'ISO_27001'];

  return (
    <div
      id="compliance-readiness-panel"
      className="bg-[#080808] border-2 border-[#2A2A2A] p-6 lg:p-8 space-y-6 relative overflow-hidden transition-all shadow-2xl"
    >
      {/* Subtle Background Cyber Grid */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-bl from-[#3366FF]/10 via-[#00F0FF]/5 to-transparent rounded-bl-full pointer-events-none" />

      {/* Header & Badges */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-[#1F1F1F] relative z-10">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono text-[#00F0FF] bg-[#00F0FF]/10 px-2.5 py-0.5 border border-[#00F0FF]/40 uppercase font-black tracking-widest flex items-center gap-1.5">
              <Scale className="w-3.5 h-3.5 text-[#00F0FF]" />
              COMPLIANCE READINESS // REGULATORY FRAMEWORK MAPPING
            </span>
            <span className="text-[10px] font-mono text-zinc-400 bg-[#121212] px-2 py-0.5 border border-[#333] uppercase font-bold">
              SOC 2 • HIPAA • OWASP TOP 10 • PCI-DSS • ISO 27001
            </span>
            {assessment.overallStatus === 'AT_RISK' ? (
              <span className="text-[10px] font-mono text-[#FF3E00] bg-[#FF3E00]/15 px-2 py-0.5 border border-[#FF3E00]/40 uppercase font-bold flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                {assessment.frameworksAtRiskCount} FRAMEWORKS EM RISCO
              </span>
            ) : assessment.overallStatus === 'DEGRADED' ? (
              <span className="text-[10px] font-mono text-amber-400 bg-amber-400/15 px-2 py-0.5 border border-amber-400/40 uppercase font-bold flex items-center gap-1">
                <AlertCircle className="w-3 h-3" />
                POSTURA DEGRADADA (ALERTA)
              </span>
            ) : (
              <span className="text-[10px] font-mono text-[#00FF41] bg-[#00FF41]/15 px-2 py-0.5 border border-[#00FF41]/40 uppercase font-bold flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" />
                100% EM CONFORMIDADE
              </span>
            )}
          </div>

          <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
            <Award className="w-6 h-6 text-[#3366FF]" />
            <span>Painel de Prontidão de Conformidade (Compliance Readiness)</span>
          </h2>
          <p className="text-xs font-mono text-[#888] max-w-4xl leading-relaxed">
            Mapeamento contínuo dos achados de SAST contra os principais frameworks e normas regulatórias de segurança da indústria. Identifique quais controles e padrões de <strong>SOC 2</strong>, <strong>HIPAA</strong>, <strong>OWASP Top 10</strong>, <strong>PCI-DSS</strong> e <strong>ISO 27001</strong> estão atualmente em risco antes de auditorias externas.
          </p>
        </div>

        {/* Action Buttons: Copy & Download Audit Report */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={handleCopyMarkdownReport}
            className="px-3.5 py-2 bg-[#121212] hover:bg-[#202020] border border-[#333] text-white text-xs font-mono uppercase tracking-wider transition-all flex items-center gap-1.5 cursor-pointer"
            title="Copiar relatório completo de conformidade em formato Markdown"
          >
            {copiedReport ? (
              <>
                <Check className="w-3.5 h-3.5 text-[#00FF41]" />
                <span className="text-[#00FF41] font-bold">Relatório Copiado!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-[#00F0FF]" />
                <span>Copiar Auditoria</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={handleDownloadMarkdownReport}
            className="px-3.5 py-2 bg-[#3366FF] hover:bg-white hover:text-black text-white text-xs font-mono uppercase tracking-wider font-bold transition-all flex items-center gap-1.5 cursor-pointer shadow-[0_0_15px_rgba(51,102,255,0.25)]"
            title="Baixar relatório de auditoria para evidências de compliance"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Baixar (.md)</span>
          </button>
        </div>
      </div>

      {/* 4 Executive Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Global Readiness */}
        <div className="p-4 bg-[#0D0D0D] border border-[#222] relative overflow-hidden">
          <div className="flex items-center justify-between text-[11px] font-mono text-[#888] uppercase">
            <span>Índice Global de Prontidão</span>
            <Scale className="w-3.5 h-3.5 text-[#3366FF]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-3xl font-black font-mono ${
              assessment.overallReadinessPercentage < 50
                ? 'text-[#FF3E00]'
                : assessment.overallReadinessPercentage < 80
                ? 'text-amber-400'
                : 'text-[#00FF41]'
            }`}>
              {assessment.overallReadinessPercentage}%
            </span>
            <span className="text-xs font-mono text-[#666]">de conformidade</span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[10px] font-mono pt-2 border-t border-[#1C1C1C]">
            <span className={assessment.overallStatus === 'AT_RISK' ? 'text-[#FF3E00] font-bold' : 'text-zinc-400'}>
              {assessment.overallStatus === 'AT_RISK' ? 'REPROVADO EM AUDITORIA' : 'APROVÁVEL'}
            </span>
            <span className="text-[#888]">{assessment.totalControlsEvaluated} controles auditados</span>
          </div>
        </div>

        {/* Metric 2: Frameworks in Risk */}
        <div className="p-4 bg-[#0D0D0D] border border-[#222] relative overflow-hidden">
          <div className="flex items-center justify-between text-[11px] font-mono text-[#888] uppercase">
            <span>Frameworks em Risco</span>
            <ShieldAlert className="w-3.5 h-3.5 text-[#FF3E00]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-[#FF3E00]">
              {assessment.frameworksAtRiskCount}
            </span>
            <span className="text-xs font-mono text-[#888]">
              / {assessment.totalFrameworksCount} frameworks
            </span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[10px] font-mono pt-2 border-t border-[#1C1C1C]">
            <span className="text-[#AAA]">Padrões Regulatórios</span>
            <span className="text-[#FF3E00] font-bold">
              {assessment.frameworksAtRiskCount > 0 ? 'Ação Imediata Exigida' : 'Todos Conformes'}
            </span>
          </div>
        </div>

        {/* Metric 3: Controls At Risk */}
        <div className="p-4 bg-[#0D0D0D] border border-[#222] relative overflow-hidden">
          <div className="flex items-center justify-between text-[11px] font-mono text-[#888] uppercase">
            <span>Controles Comprometidos</span>
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-white">
              {assessment.totalControlsAtRisk}
            </span>
            <span className="text-xs font-mono text-amber-400 font-bold">
              em risco crítico
            </span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[10px] font-mono pt-2 border-t border-[#1C1C1C]">
            <span className="text-[#888]">{assessment.totalControlsDegraded} degradados</span>
            <span className="text-[#00FF41]">{assessment.totalControlsCompliant} conformes</span>
          </div>
        </div>

        {/* Metric 4: Violating Findings Count */}
        <div 
          onClick={onNavigateToScanner}
          className="p-4 bg-[#0D0D0D] border border-[#222] hover:border-[#FF3E00] transition-all cursor-pointer relative overflow-hidden group"
          title="Clique para inspecionar todos os achados no Scanner SAST"
        >
          <div className="flex items-center justify-between text-[11px] font-mono text-[#888] uppercase">
            <span>Achados com Risco Regulatório</span>
            <FileCode className="w-3.5 h-3.5 text-[#FF3E00]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-white">
              {(report.findings || []).filter((f) => !f.isFalsePositive).length}
            </span>
            <span className="text-xs font-mono text-[#666]">achados ativos</span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[10px] font-mono pt-2 border-t border-[#1C1C1C]">
            <span className="text-[#888]">Violações de código</span>
            <span className="text-[#FF3E00] group-hover:underline flex items-center gap-0.5">
              Ver Scanner &rarr;
            </span>
          </div>
        </div>
      </div>

      {/* Frameworks Selector Grid */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono text-zinc-400 uppercase tracking-wider font-bold flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-[#00F0FF]" />
            Selecione o Framework para Análise Detalhada
          </span>
          {selectedFramework !== 'ALL' && (
            <button
              type="button"
              onClick={() => setSelectedFramework('ALL')}
              className="text-[11px] font-mono text-[#00F0FF] hover:underline cursor-pointer"
            >
              Ver Todos os Frameworks
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {frameworkKeys.map((fwKey) => {
            const summary = assessment.frameworkSummaries[fwKey];
            const isSelected = selectedFramework === fwKey;
            const isAtRisk = summary.status === 'AT_RISK';
            const isDegraded = summary.status === 'DEGRADED';

            return (
              <button
                key={fwKey}
                type="button"
                onClick={() => setSelectedFramework(isSelected ? 'ALL' : fwKey)}
                className={`p-3.5 text-left border transition-all cursor-pointer relative overflow-hidden ${
                  isSelected
                    ? 'bg-[#151515] border-[#3366FF] shadow-[0_0_15px_rgba(51,102,255,0.2)]'
                    : 'bg-[#0B0B0B] border-[#222] hover:border-[#444]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-[#888] font-bold uppercase">
                    {summary.badge}
                  </span>
                  <span
                    className={`text-[9px] font-mono px-1.5 py-0.5 font-bold uppercase ${
                      isAtRisk
                        ? 'bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40'
                        : isDegraded
                        ? 'bg-amber-400/20 text-amber-300 border border-amber-400/40'
                        : 'bg-[#00FF41]/20 text-[#00FF41] border border-[#00FF41]/40'
                    }`}
                  >
                    {isAtRisk ? 'EM RISCO' : isDegraded ? 'DEGRADADO' : 'CONFORME'}
                  </span>
                </div>

                <div className="text-xs font-bold text-white font-mono mt-2 truncate">
                  {summary.name}
                </div>

                {/* Mini Progress Bar */}
                <div className="mt-2 w-full bg-[#1C1C1C] h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all ${
                      summary.readinessPercentage < 50
                        ? 'bg-[#FF3E00]'
                        : summary.readinessPercentage < 80
                        ? 'bg-amber-400'
                        : 'bg-[#00FF41]'
                    }`}
                    style={{ width: `${summary.readinessPercentage}%` }}
                  />
                </div>

                <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-[#888]">
                  <span>{summary.readinessPercentage}% Pronto</span>
                  <span className={isAtRisk ? 'text-[#FF3E00] font-bold' : 'text-zinc-400'}>
                    {summary.atRiskControls} em risco
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3 bg-[#0D0D0D] border border-[#222] flex flex-col sm:flex-row items-center justify-between gap-3">
        {/* Status Filters */}
        <div className="flex flex-wrap items-center gap-1.5 w-full sm:w-auto">
          <span className="text-[10px] font-mono text-[#777] uppercase mr-1">Filtrar:</span>
          {(['ALL', 'AT_RISK', 'DEGRADED', 'COMPLIANT'] as const).map((st) => (
            <button
              key={st}
              type="button"
              onClick={() => setStatusFilter(st)}
              className={`px-2.5 py-1 text-[11px] font-mono font-bold uppercase transition-colors cursor-pointer border ${
                statusFilter === st
                  ? 'bg-white text-black border-white'
                  : 'bg-[#141414] text-[#888] border-[#2A2A2A] hover:text-white'
              }`}
            >
              {st === 'ALL'
                ? 'Todos os Status'
                : st === 'AT_RISK'
                ? '🔴 Em Risco'
                : st === 'DEGRADED'
                ? '🟡 Degradados'
                : '🟢 Conformes'}
            </button>
          ))}
        </div>

        {/* Search Field */}
        <div className="relative w-full sm:w-72">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-[#666]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Buscar controle, regra, código ou arquivo..."
            className="w-full bg-[#121212] border border-[#2E2E2E] focus:border-[#3366FF] pl-8 pr-3 py-1.5 text-xs font-mono text-white placeholder-[#555] outline-none"
          />
        </div>
      </div>

      {/* Active Filter Notice */}
      {(selectedFramework !== 'ALL' || statusFilter !== 'ALL' || searchQuery.trim()) && (
        <div className="flex items-center justify-between text-xs font-mono text-[#888] px-1">
          <span>
            Exibindo <strong>{filteredControls.length}</strong> de {assessment.totalControlsEvaluated} controles
            {selectedFramework !== 'ALL' && ` • Framework: ${selectedFramework}`}
            {statusFilter !== 'ALL' && ` • Status: ${statusFilter}`}
            {searchQuery && ` • Busca: "${searchQuery}"`}
          </span>
          <button
            type="button"
            onClick={() => {
              setSelectedFramework('ALL');
              setStatusFilter('ALL');
              setSearchQuery('');
            }}
            className="text-[#00F0FF] hover:underline cursor-pointer text-[11px]"
          >
            Limpar Filtros
          </button>
        </div>
      )}

      {/* Evaluated Controls List */}
      <div className="space-y-3">
        {filteredControls.length === 0 ? (
          <div className="p-8 bg-[#0B0B0B] border border-[#222] text-center space-y-2">
            <CheckCircle2 className="w-8 h-8 text-[#00FF41] mx-auto opacity-80" />
            <div className="text-sm font-bold text-white font-mono uppercase">
              Nenhum controle corresponde aos filtros ativos
            </div>
            <p className="text-xs font-mono text-[#888]">
              Tente selecionar outro framework ou redefinir a busca textual.
            </p>
          </div>
        ) : (
          filteredControls.map((ctrl) => {
            const isExpanded = activeExpanded[ctrl.id] ?? (ctrl.status === 'AT_RISK');
            const isAtRisk = ctrl.status === 'AT_RISK';
            const isDegraded = ctrl.status === 'DEGRADED';
            const isCompliant = ctrl.status === 'COMPLIANT';

            const fwMeta = COMPLIANCE_FRAMEWORKS_META[ctrl.framework];

            return (
              <div
                key={ctrl.id}
                className={`border transition-all ${
                  isAtRisk
                    ? 'bg-[#0B0B0B] border-[#FF3E00]/40'
                    : isDegraded
                    ? 'bg-[#0B0B0B] border-amber-500/40'
                    : 'bg-[#070707] border-[#1C1C1C]'
                }`}
              >
                {/* Control Header Bar */}
                <div
                  onClick={() => toggleControlExpanded(ctrl.id)}
                  className="p-4 sm:p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-3 cursor-pointer hover:bg-[#121212] transition-colors"
                >
                  <div className="flex items-start gap-3 min-w-0 flex-1">
                    {/* Status Icon */}
                    <div className="mt-0.5 shrink-0">
                      {isAtRisk ? (
                        <div className="w-7 h-7 rounded bg-[#FF3E00]/20 border border-[#FF3E00]/50 flex items-center justify-center text-[#FF3E00]">
                          <ShieldAlert className="w-4 h-4" />
                        </div>
                      ) : isDegraded ? (
                        <div className="w-7 h-7 rounded bg-amber-400/20 border border-amber-400/50 flex items-center justify-center text-amber-400">
                          <AlertTriangle className="w-4 h-4" />
                        </div>
                      ) : (
                        <div className="w-7 h-7 rounded bg-[#00FF41]/20 border border-[#00FF41]/50 flex items-center justify-center text-[#00FF41]">
                          <ShieldCheck className="w-4 h-4" />
                        </div>
                      )}
                    </div>

                    {/* Standard details */}
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        {/* Framework Tag */}
                        <span
                          className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 border"
                          style={{
                            borderColor: `${fwMeta.color}60`,
                            backgroundColor: `${fwMeta.color}15`,
                            color: fwMeta.color,
                          }}
                        >
                          {ctrl.frameworkName}
                        </span>

                        {/* Standard Code */}
                        <span className="text-xs font-mono font-black text-white px-2 py-0.5 bg-[#1C1C1C] border border-[#333]">
                          {ctrl.code}
                        </span>

                        {/* Status Badge */}
                        <span
                          className={`text-[10px] font-mono font-black uppercase px-2 py-0.5 border ${
                            isAtRisk
                              ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40'
                              : isDegraded
                              ? 'bg-amber-400/15 text-amber-300 border-amber-400/40'
                              : 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/40'
                          }`}
                        >
                          {isAtRisk ? 'EM RISCO' : isDegraded ? 'DEGRADADO' : 'CONFORME'}
                        </span>

                        <span className="text-[11px] font-mono text-[#888]">
                          • {ctrl.category}
                        </span>
                      </div>

                      <h3 className="text-sm font-bold text-white font-mono truncate">
                        {ctrl.title}
                      </h3>
                      <p className="text-xs font-mono text-[#888] line-clamp-1">
                        {ctrl.description}
                      </p>
                    </div>
                  </div>

                  {/* Right: Metrics & Collapse Arrow */}
                  <div className="flex items-center gap-3 shrink-0 lg:ml-4">
                    {ctrl.matchingFindings.length > 0 ? (
                      <div className="flex items-center gap-2">
                        <div className="px-2.5 py-1 bg-[#141414] border border-[#2A2A2A] text-right font-mono text-xs">
                          <span className="text-[#FF3E00] font-bold">
                            {ctrl.matchingFindings.length} achados
                          </span>
                          {ctrl.criticalCount > 0 && (
                            <span className="text-[10px] text-rose-400 block font-bold">
                              {ctrl.criticalCount} críticos
                            </span>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="px-2.5 py-1 bg-[#00FF41]/10 border border-[#00FF41]/30 font-mono text-[11px] text-[#00FF41] font-bold">
                        0 Violações Ativas
                      </div>
                    )}

                    <div className="text-[#888] p-1">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </div>
                  </div>
                </div>

                {/* Expanded Deep Dive Section */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-2 border-t border-[#1C1C1C] space-y-4 bg-[#050505]">
                    {/* Regulatory Context & Audit Implication */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                      <div className="p-3.5 bg-[#0C0C0C] border border-[#222] space-y-1">
                        <div className="flex items-center gap-1.5 text-xs font-bold font-mono text-amber-400 uppercase">
                          <AlertCircle className="w-3.5 h-3.5" />
                          <span>Impacto em Auditoria Externa</span>
                        </div>
                        <p className="text-xs font-mono text-[#AAA] leading-relaxed">
                          {ctrl.auditImplication}
                        </p>
                      </div>

                      <div className="p-3.5 bg-[#0C0C0C] border border-[#222] space-y-1">
                        <div className="flex items-center gap-1.5 text-xs font-bold font-mono text-[#00FF41] uppercase">
                          <Zap className="w-3.5 h-3.5" />
                          <span>Remediação para Conformidade</span>
                        </div>
                        <p className="text-xs font-mono text-[#AAA] leading-relaxed">
                          {ctrl.recommendedRemediation}
                        </p>
                      </div>
                    </div>

                    {/* Mapped Findings List */}
                    {ctrl.matchingFindings.length > 0 ? (
                      <div className="space-y-2 pt-1">
                        <div className="flex items-center justify-between text-xs font-mono">
                          <span className="font-bold text-white uppercase flex items-center gap-1.5">
                            <FileCode className="w-3.5 h-3.5 text-[#FF3E00]" />
                            Achados de SAST que Violam Este Controle ({ctrl.matchingFindings.length})
                          </span>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              onNavigateToScanner?.();
                            }}
                            className="text-[#3366FF] hover:underline flex items-center gap-1 text-[11px] cursor-pointer"
                          >
                            <span>Inspecionar no Scanner</span>
                            <ExternalLink className="w-3 h-3" />
                          </button>
                        </div>

                        <div className="space-y-2">
                          {ctrl.matchingFindings.map((finding) => (
                            <div
                              key={finding.id}
                              className="p-3 bg-[#0A0A0A] border border-[#222] hover:border-[#333] transition-colors flex flex-col md:flex-row md:items-center justify-between gap-2.5"
                            >
                              <div className="min-w-0 space-y-1">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className={`text-[10px] font-mono font-bold uppercase px-1.5 py-0.2 rounded border ${
                                    finding.severity === 'CRITICAL'
                                      ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                                      : finding.severity === 'HIGH'
                                      ? 'bg-orange-500/20 text-orange-300 border-orange-500/40'
                                      : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                                  }`}>
                                    {finding.severity}
                                  </span>
                                  <span className="text-xs font-bold text-white font-mono">
                                    {finding.ruleName}
                                  </span>
                                </div>

                                <div className="flex items-center gap-2 text-[11px] font-mono text-[#888]">
                                  <span
                                    className="text-zinc-300 hover:underline cursor-pointer truncate"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      onNavigateToFile?.(finding.file);
                                    }}
                                  >
                                    {finding.file}:{finding.line}
                                  </span>
                                  <span>•</span>
                                  <span className="text-[#666]">
                                    Segredo: <code className="text-rose-400 bg-black px-1">{finding.maskedSecret}</code>
                                  </span>
                                </div>
                              </div>

                              <div className="flex items-center gap-2 shrink-0">
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleCopyFinding(finding);
                                  }}
                                  className="p-1.5 bg-[#141414] hover:bg-[#222] border border-[#333] text-[#AAA] hover:text-white transition-colors cursor-pointer"
                                  title="Copiar referência do achado"
                                >
                                  {copiedFindingId === finding.id ? (
                                    <Check className="w-3.5 h-3.5 text-[#00FF41]" />
                                  ) : (
                                    <Copy className="w-3.5 h-3.5" />
                                  )}
                                </button>

                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    onSelectFinding?.(finding);
                                    onNavigateToScanner?.();
                                  }}
                                  className="px-2.5 py-1.5 bg-[#181818] hover:bg-[#FF3E00] hover:text-white border border-[#333] text-white text-[11px] font-mono uppercase tracking-wider transition-colors cursor-pointer flex items-center gap-1"
                                  title="Abrir detalhes no Scanner"
                                >
                                  <span>Abrir</span>
                                  <ExternalLink className="w-3 h-3" />
                                </button>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div className="p-3 bg-[#00FF41]/5 border border-[#00FF41]/20 text-xs font-mono text-[#00FF41] flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 shrink-0" />
                        <span>
                          Nenhum achado no código viola esta exigência atualmente. O controle atende aos requisitos de conformidade para {ctrl.frameworkName}.
                        </span>
                      </div>
                    )}

                    {/* Official Standard Documentation Link */}
                    {ctrl.docUrl && (
                      <div className="pt-1 flex items-center justify-between text-[11px] font-mono text-[#777]">
                        <span>
                          Referência Oficial: {ctrl.frameworkName} ({ctrl.code})
                        </span>
                        <a
                          href={ctrl.docUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[#3366FF] hover:underline flex items-center gap-1"
                        >
                          <span>Documentação da Norma</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
