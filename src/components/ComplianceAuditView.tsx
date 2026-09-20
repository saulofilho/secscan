import React, { useState, useMemo } from 'react';
import {
  Scale,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  FileText,
  Download,
  Copy,
  Check,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  FileCode2,
  Lock,
  Zap,
  Sparkles,
  Info,
  ArrowRight,
  TrendingUp,
  RotateCcw,
  BookOpen,
  Award,
  Filter
} from 'lucide-react';
import {
  ScanFinding,
  ComplianceFrameworkId,
  ComplianceControlStatus,
  EvaluatedComplianceControl,
  GlobalComplianceAssessment
} from '../types';
import {
  COMPLIANCE_FRAMEWORKS_META,
  evaluateComplianceReadiness,
  generateComplianceMarkdownReport
} from '../lib/complianceEngine';

interface ComplianceAuditViewProps {
  findings: ScanFinding[];
  onNavigateToFile?: (filePath: string, line?: number) => void;
  onSelectFinding?: (finding: ScanFinding) => void;
}

export const ComplianceAuditView: React.FC<ComplianceAuditViewProps> = ({
  findings,
  onNavigateToFile,
  onSelectFinding
}) => {
  const [selectedFramework, setSelectedFramework] = useState<ComplianceFrameworkId | 'ALL'>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | ComplianceControlStatus>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedControlIds, setExpandedControlIds] = useState<Record<string, boolean>>({});
  const [copiedReport, setCopiedReport] = useState<boolean>(false);
  const [copiedMemo, setCopiedMemo] = useState<boolean>(false);
  const [copiedFindingId, setCopiedFindingId] = useState<string | null>(null);

  // 1. Calculate Compliance Assessment across frameworks
  const assessment: GlobalComplianceAssessment = useMemo(() => {
    return evaluateComplianceReadiness(findings || []);
  }, [findings]);

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

  const toggleControlExpanded = (id: string) => {
    setExpandedControlIds((prev) => ({
      ...prev,
      [id]: !(prev[id] ?? (assessment.evaluatedControls.find((c) => c.id === id)?.status === 'AT_RISK'))
    }));
  };

  const expandAll = () => {
    const all: Record<string, boolean> = {};
    assessment.evaluatedControls.forEach((c) => (all[c.id] = true));
    setExpandedControlIds(all);
  };

  const collapseAll = () => {
    setExpandedControlIds({});
  };

  // 2. Filter Controls
  const filteredControls = useMemo(() => {
    return assessment.evaluatedControls.filter((ctrl) => {
      if (selectedFramework !== 'ALL' && ctrl.framework !== selectedFramework) {
        return false;
      }
      if (statusFilter !== 'ALL' && ctrl.status !== statusFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchTitle = ctrl.title.toLowerCase().includes(q);
        const matchCode = ctrl.code.toLowerCase().includes(q);
        const matchCategory = ctrl.category.toLowerCase().includes(q);
        const matchFw = ctrl.frameworkName.toLowerCase().includes(q);
        const matchFinding = ctrl.matchingFindings.some(
          (f) =>
            f.ruleName.toLowerCase().includes(q) ||
            f.file.toLowerCase().includes(q) ||
            f.description.toLowerCase().includes(q)
        );
        if (!matchTitle && !matchCode && !matchCategory && !matchFw && !matchFinding) {
          return false;
        }
      }
      return true;
    });
  }, [assessment.evaluatedControls, selectedFramework, statusFilter, searchQuery]);

  // Download Markdown Report
  const handleDownloadMarkdown = () => {
    const reportText = generateComplianceMarkdownReport(assessment);
    const blob = new Blob([reportText], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `secscan-compliance-audit-report-${Date.now()}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Download JSON Package
  const handleDownloadJson = () => {
    const data = {
      assessmentDate: new Date().toISOString(),
      overallReadinessPercentage: assessment.overallReadinessPercentage,
      overallStatus: assessment.overallStatus,
      frameworkSummaries: assessment.frameworkSummaries,
      evaluatedControls: assessment.evaluatedControls.map((c) => ({
        id: c.id,
        framework: c.framework,
        code: c.code,
        title: c.title,
        status: c.status,
        auditImplication: c.auditImplication,
        recommendedRemediation: c.recommendedRemediation,
        violatingFindingsCount: c.matchingFindings.length,
        violatingFindings: c.matchingFindings.map((f) => ({
          ruleName: f.ruleName,
          severity: f.severity,
          file: f.file,
          line: f.line,
          maskedSecret: f.maskedSecret
        }))
      }))
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `compliance-readiness-attestation-${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Copy Executive Memo
  const handleCopyMemo = () => {
    const dateStr = new Date().toLocaleDateString('pt-BR');
    const memo = `MEMORANDO DE PRONTIDÃO DE AUDITORIA & CONFORMIDADE (COMPLIANCE AUDIT)
Data: ${dateStr}
Status Geral: ${assessment.overallStatus === 'COMPLIANT' ? 'CONFORME (Pass)' : assessment.overallStatus === 'DEGRADED' ? 'ATENÇÃO (Degradado)' : 'EM RISCO (Falha Iminente)'}
Índice Global de Prontidão: ${assessment.overallReadinessPercentage}%

RESUMO POR FRAMEWORK:
- SOC 2 Type II: ${assessment.frameworkSummaries.SOC2.readinessPercentage}% (Status: ${assessment.frameworkSummaries.SOC2.status}, ${assessment.frameworkSummaries.SOC2.atRiskControls} controles em risco)
- ISO/IEC 27001:2022: ${assessment.frameworkSummaries.ISO_27001.readinessPercentage}% (Status: ${assessment.frameworkSummaries.ISO_27001.status}, ${assessment.frameworkSummaries.ISO_27001.atRiskControls} controles em risco)
- HIPAA Security Rule: ${assessment.frameworkSummaries.HIPAA.readinessPercentage}% (Status: ${assessment.frameworkSummaries.HIPAA.status}, ${assessment.frameworkSummaries.HIPAA.atRiskControls} controles em risco)
- PCI-DSS v4.0: ${assessment.frameworkSummaries.PCI_DSS?.readinessPercentage ?? 100}%
- OWASP Top 10: ${assessment.frameworkSummaries.OWASP_TOP_10?.readinessPercentage ?? 100}%

Total de Controles Auditados: ${assessment.totalControlsEvaluated}
Controles em Conformidade: ${assessment.totalControlsCompliant}
Controles com Apontamentos: ${assessment.totalControlsAtRisk + assessment.totalControlsDegraded}
Gerado automaticamente via SecScan AppSec Platform.`;

    navigator.clipboard.writeText(memo);
    setCopiedMemo(true);
    setTimeout(() => setCopiedMemo(false), 2000);
  };

  const handleCopyFindingEvidence = (f: ScanFinding) => {
    const text = `Evidência de Auditoria: [${f.severity}] ${f.ruleName} em ${f.file}:${f.line}\nSegredo/Valor Detectado: ${f.maskedSecret}\nDescrição: ${f.description}`;
    navigator.clipboard.writeText(text);
    setCopiedFindingId(f.id);
    setTimeout(() => setCopiedFindingId(null), 2000);
  };

  // Helper for Circular Progress Gauge
  const renderGaugeRing = (percentage: number, color: string) => {
    const radius = 38;
    const circumference = 2 * Math.PI * radius;
    const strokeDashoffset = circumference - (percentage / 100) * circumference;

    return (
      <div className="relative w-24 h-24 flex items-center justify-center shrink-0">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 96 96">
          <circle
            cx="48"
            cy="48"
            r={radius}
            stroke="#1A1A1A"
            strokeWidth="8"
            fill="transparent"
          />
          <circle
            cx="48"
            cy="48"
            r={radius}
            stroke={color}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-xl font-bold text-white tracking-tight">{percentage}%</span>
          <span className="text-[9px] text-zinc-400 uppercase font-mono">Score</span>
        </div>
      </div>
    );
  };

  // Get status badge styling
  const getStatusBadge = (status: ComplianceControlStatus) => {
    switch (status) {
      case 'COMPLIANT':
        return {
          label: 'Aprovado (Pass)',
          className: 'bg-emerald-950/70 text-emerald-300 border border-emerald-800/60',
          dot: 'bg-emerald-400'
        };
      case 'DEGRADED':
        return {
          label: 'Atenção (Review)',
          className: 'bg-amber-950/70 text-amber-300 border border-amber-800/60',
          dot: 'bg-amber-400'
        };
      case 'AT_RISK':
        return {
          label: 'Em Risco (Falha)',
          className: 'bg-rose-950/70 text-rose-300 border border-rose-800/60',
          dot: 'bg-rose-500'
        };
    }
  };

  // Primary Frameworks List (SOC2, ISO 27001, HIPAA)
  const primaryFrameworks: ComplianceFrameworkId[] = ['SOC2', 'ISO_27001', 'HIPAA'];
  const secondaryFrameworks: ComplianceFrameworkId[] = ['PCI_DSS', 'OWASP_TOP_10'];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 font-mono text-zinc-200">
      {/* 1. Header & Quick Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#222] pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/30">
              <Scale className="w-5 h-5" />
            </span>
            <h1 className="text-xl font-bold tracking-tight text-white uppercase">
              Auditoria de Conformidade (Compliance Audit View)
            </h1>
            <span className="text-[10px] px-2 py-0.5 rounded bg-blue-950/60 text-blue-300 border border-blue-800/60 font-bold">
              SOC 2 / ISO 27001 / HIPAA
            </span>
          </div>
          <p className="text-xs text-zinc-400 mt-1.5">
            Mapeamento formal de achados e segredos estáticos contra os critérios de auditoria SOC 2 Type II, ISO/IEC 27001:2022 e HIPAA Security Rule com cálculo determinístico de prontidão (Readiness Score).
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={handleCopyMemo}
            className="h-8 px-3 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs flex items-center gap-1.5 transition-colors cursor-pointer border border-[#333]"
            title="Copiar memorando executivo de auditoria"
          >
            {copiedMemo ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedMemo ? 'Copiado!' : 'Copiar Memorando'}</span>
          </button>

          <button
            onClick={handleDownloadJson}
            className="h-8 px-3 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs flex items-center gap-1.5 transition-colors cursor-pointer border border-[#333]"
            title="Exportar pacote JSON com todas as evidências e controles"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Pacote JSON</span>
          </button>

          <button
            onClick={handleDownloadMarkdown}
            className="h-8 px-3 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer shadow"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Relatório Auditoria (.md)</span>
          </button>
        </div>
      </div>

      {/* 2. Executive Scorecard Banner */}
      <div className="bg-[#0C0C0C] border border-[#222] rounded-xl p-5 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          {/* Overall Global Score */}
          <div className="flex items-center gap-5">
            {renderGaugeRing(
              assessment.overallReadinessPercentage,
              assessment.overallReadinessPercentage >= 80 ? '#10B981' : assessment.overallReadinessPercentage >= 60 ? '#F59E0B' : '#F43F5E'
            )}
            <div className="space-y-1">
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider block font-bold">
                Índice Global de Prontidão (Cross-Framework)
              </span>
              <div className="flex items-center gap-2">
                <span className="text-2xl font-bold text-white">
                  {assessment.overallReadinessPercentage}%
                </span>
                <span className={`text-[11px] px-2 py-0.5 rounded font-bold ${getStatusBadge(assessment.overallStatus).className}`}>
                  {getStatusBadge(assessment.overallStatus).label}
                </span>
              </div>
              <p className="text-xs text-zinc-400 max-w-md">
                {assessment.overallReadinessPercentage >= 85
                  ? 'Repositório com alta conformidade. Controles de proteção contra credenciais estáticas e injeção atendem aos requisitos principais.'
                  : assessment.overallReadinessPercentage >= 65
                  ? 'Conformidade moderada. Foram identificados segredos ou fluxos que geram apontamentos de deficiência em auditorias formais.'
                  : 'Risco crítico de reprovação em auditoria. Falhas diretas nos controles de salvaguarda de chaves, ePHI e fronteiras lógicas.'}
              </p>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs border-t lg:border-t-0 lg:border-l border-[#222] pt-4 lg:pt-0 lg:pl-6">
            <div className="p-3 bg-black/50 rounded-lg border border-[#1A1A1A]">
              <span className="text-[10px] text-zinc-500 uppercase block">Total Controles</span>
              <span className="text-lg font-bold text-white mt-0.5 block">{assessment.totalControlsEvaluated}</span>
              <span className="text-[10px] text-zinc-500">Mapeados</span>
            </div>
            <div className="p-3 bg-black/50 rounded-lg border border-[#1A1A1A]">
              <span className="text-[10px] text-emerald-400 uppercase block">Conformes</span>
              <span className="text-lg font-bold text-emerald-400 mt-0.5 block">{assessment.totalControlsCompliant}</span>
              <span className="text-[10px] text-zinc-500">Sem violações</span>
            </div>
            <div className="p-3 bg-black/50 rounded-lg border border-[#1A1A1A]">
              <span className="text-[10px] text-amber-400 uppercase block">Degradados</span>
              <span className="text-lg font-bold text-amber-400 mt-0.5 block">{assessment.totalControlsDegraded}</span>
              <span className="text-[10px] text-zinc-500">Requer revisão</span>
            </div>
            <div className="p-3 bg-black/50 rounded-lg border border-[#1A1A1A]">
              <span className="text-[10px] text-rose-400 uppercase block">Em Risco</span>
              <span className="text-lg font-bold text-rose-500 mt-0.5 block">{assessment.totalControlsAtRisk}</span>
              <span className="text-[10px] text-zinc-500">Falha de auditoria</span>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Major Frameworks Scorecards (SOC2, ISO 27001, HIPAA) */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold text-zinc-400 uppercase tracking-wider flex items-center gap-1.5">
            <Award className="w-4 h-4 text-blue-400" />
            Frameworks de Auditoria Principais
          </span>
          <span className="text-[11px] text-zinc-500">Clique em qualquer framework para filtrar seus controles</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {primaryFrameworks.map((fwKey) => {
            const summary = assessment.frameworkSummaries[fwKey];
            const meta = COMPLIANCE_FRAMEWORKS_META[fwKey];
            const isSelected = selectedFramework === fwKey;
            const badge = getStatusBadge(summary.status);

            return (
              <div
                key={fwKey}
                onClick={() => setSelectedFramework(isSelected ? 'ALL' : fwKey)}
                className={`p-5 rounded-xl border transition-all cursor-pointer relative ${
                  isSelected
                    ? 'bg-[#0E1526] border-blue-500 shadow-[0_0_20px_rgba(59,130,246,0.15)] ring-1 ring-blue-500'
                    : 'bg-[#0A0A0A] border-[#222] hover:border-[#333] hover:bg-[#0E0E0E]'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 font-bold">
                        {summary.badge}
                      </span>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${badge.className}`}>
                        {badge.label}
                      </span>
                    </div>
                    <h2 className="text-base font-bold text-white tracking-tight">{summary.name}</h2>
                    <p className="text-xs text-zinc-400 leading-relaxed">{summary.shortDescription}</p>
                  </div>

                  {renderGaugeRing(summary.readinessPercentage, meta.color)}
                </div>

                {/* Counter metrics */}
                <div className="mt-4 pt-3 border-t border-white/5 grid grid-cols-3 gap-2 text-[11px]">
                  <div>
                    <span className="text-zinc-500 block">Total</span>
                    <span className="font-bold text-white">{summary.totalControls} controles</span>
                  </div>
                  <div>
                    <span className="text-rose-400 block">Em Risco</span>
                    <span className="font-bold text-rose-400">{summary.atRiskControls}</span>
                  </div>
                  <div>
                    <span className="text-zinc-400 block">Achados SAST</span>
                    <span className="font-bold text-blue-400">{summary.violatingFindingsCount} violando</span>
                  </div>
                </div>

                {/* Selection state banner */}
                <div className="mt-3 flex items-center justify-between text-[11px] text-blue-400 font-bold">
                  <span>{isSelected ? '✓ Framework Selecionado' : 'Ver Controles & Evidências'}</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Secondary Frameworks Strip (PCI-DSS, OWASP Top 10) */}
      <div className="bg-[#0A0A0A] border border-[#222] p-4 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs">
          <span className="text-zinc-400 font-bold uppercase">Outros Padrões Suportados:</span>
          <span className="text-zinc-500">Mapeamento adicional disponível para auditorias setoriais.</span>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {secondaryFrameworks.map((fwKey) => {
            const summary = assessment.frameworkSummaries[fwKey];
            if (!summary) return null;
            const isSelected = selectedFramework === fwKey;
            return (
              <button
                key={fwKey}
                onClick={() => setSelectedFramework(isSelected ? 'ALL' : fwKey)}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer border flex items-center gap-2 ${
                  isSelected
                    ? 'bg-blue-600 text-white border-blue-500 shadow'
                    : 'bg-[#121212] text-zinc-300 border-[#2A2A2A] hover:text-white'
                }`}
              >
                <span>{summary.name}:</span>
                <span className="text-emerald-400">{summary.readinessPercentage}%</span>
                <span className="text-[10px] text-zinc-400">({summary.violatingFindingsCount} achados)</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* 4. Filter Toolbar & Search Bar */}
      <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          {/* Framework Tab Pills */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
            <button
              onClick={() => setSelectedFramework('ALL')}
              className={`px-3 py-1.5 rounded-lg font-bold border transition-colors cursor-pointer ${
                selectedFramework === 'ALL'
                  ? 'bg-blue-600 text-white border-blue-500 shadow'
                  : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
              }`}
            >
              Todos ({assessment.evaluatedControls.length})
            </button>
            {(['SOC2', 'ISO_27001', 'HIPAA', 'PCI_DSS', 'OWASP_TOP_10'] as ComplianceFrameworkId[]).map((fw) => {
              const meta = COMPLIANCE_FRAMEWORKS_META[fw];
              const summary = assessment.frameworkSummaries[fw];
              return (
                <button
                  key={fw}
                  onClick={() => setSelectedFramework(fw)}
                  className={`px-3 py-1.5 rounded-lg font-bold border transition-colors cursor-pointer whitespace-nowrap ${
                    selectedFramework === fw
                      ? 'bg-blue-950 text-blue-200 border-blue-600 shadow'
                      : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-blue-300'
                  }`}
                >
                  {meta.badge} ({summary?.readinessPercentage}%)
                </button>
              );
            })}
          </div>

          {/* Expand / Collapse buttons */}
          <div className="flex items-center gap-2 shrink-0 text-xs">
            <button
              onClick={expandAll}
              className="text-[11px] text-zinc-400 hover:text-white cursor-pointer"
            >
              Expandir Todos
            </button>
            <span className="text-zinc-600">|</span>
            <button
              onClick={collapseAll}
              className="text-[11px] text-zinc-400 hover:text-white cursor-pointer"
            >
              Recolher Todos
            </button>
          </div>
        </div>

        {/* Search & Status Filter Row */}
        <div className="flex flex-col sm:flex-row items-center gap-3 pt-2 border-t border-[#1C1C1C]">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
            <input
              type="text"
              placeholder="Buscar por código do controle (ex: CC6.1, A.8.28, § 164.312), título ou achado..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-black border border-[#222] pl-9 pr-4 py-2 rounded-lg text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1.5 w-full sm:w-auto overflow-x-auto text-xs">
            <button
              onClick={() => setStatusFilter('ALL')}
              className={`px-2.5 py-1.5 rounded text-xs transition-colors cursor-pointer ${
                statusFilter === 'ALL' ? 'bg-zinc-800 text-white font-bold' : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              Todos Status
            </button>
            <button
              onClick={() => setStatusFilter('AT_RISK')}
              className={`px-2.5 py-1.5 rounded text-xs transition-colors cursor-pointer ${
                statusFilter === 'AT_RISK' ? 'bg-rose-950 text-rose-300 font-bold border border-rose-800' : 'text-zinc-500 hover:text-rose-400'
              }`}
            >
              Em Risco ({assessment.totalControlsAtRisk})
            </button>
            <button
              onClick={() => setStatusFilter('DEGRADED')}
              className={`px-2.5 py-1.5 rounded text-xs transition-colors cursor-pointer ${
                statusFilter === 'DEGRADED' ? 'bg-amber-950 text-amber-300 font-bold border border-amber-800' : 'text-zinc-500 hover:text-amber-400'
              }`}
            >
              Degradados ({assessment.totalControlsDegraded})
            </button>
            <button
              onClick={() => setStatusFilter('COMPLIANT')}
              className={`px-2.5 py-1.5 rounded text-xs transition-colors cursor-pointer ${
                statusFilter === 'COMPLIANT' ? 'bg-emerald-950 text-emerald-300 font-bold border border-emerald-800' : 'text-zinc-500 hover:text-emerald-400'
              }`}
            >
              Conformes ({assessment.totalControlsCompliant})
            </button>
          </div>
        </div>
      </div>

      {/* 5. Detailed Controls List */}
      <div className="space-y-4">
        <div className="flex items-center justify-between text-xs text-zinc-400">
          <span>
            Exibindo <strong>{filteredControls.length}</strong> de {assessment.evaluatedControls.length} controles
          </span>
          {selectedFramework !== 'ALL' && (
            <button
              onClick={() => setSelectedFramework('ALL')}
              className="text-blue-400 hover:underline cursor-pointer"
            >
              Limpar filtro de framework
            </button>
          )}
        </div>

        {filteredControls.length === 0 ? (
          <div className="p-12 text-center bg-[#0C0C0C] border border-[#222] rounded-xl text-xs text-zinc-500 space-y-2">
            <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto" />
            <p className="font-bold text-zinc-300 text-sm">Nenhum controle corresponde aos filtros aplicados.</p>
            <p className="text-zinc-500">Tente limpar a pesquisa ou selecionar "Todos Status".</p>
          </div>
        ) : (
          filteredControls.map((ctrl) => {
            const isExpanded = activeExpanded[ctrl.id];
            const badge = getStatusBadge(ctrl.status);
            const hasViolations = ctrl.matchingFindings.length > 0;

            return (
              <div
                key={ctrl.id}
                className={`rounded-xl border transition-all ${
                  ctrl.status === 'AT_RISK'
                    ? 'bg-[#0D0A0A] border-rose-900/40 hover:border-rose-700/60'
                    : ctrl.status === 'DEGRADED'
                    ? 'bg-[#0D0B0A] border-amber-900/40 hover:border-amber-700/60'
                    : 'bg-[#070E0A] border-emerald-900/40 hover:border-emerald-700/60'
                }`}
              >
                {/* Control Header Bar */}
                <div
                  onClick={() => toggleControlExpanded(ctrl.id)}
                  className="p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer select-none"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                        {ctrl.frameworkName}
                      </span>
                      <span className="text-xs font-bold text-blue-400 font-mono">
                        {ctrl.code}
                      </span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-800">
                        {ctrl.category}
                      </span>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-bold flex items-center gap-1 ${badge.className}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${badge.dot}`} />
                        {badge.label}
                      </span>
                    </div>

                    <h3 className="font-bold text-sm text-white tracking-tight">{ctrl.title}</h3>
                    <p className="text-xs text-zinc-400 max-w-3xl leading-relaxed">{ctrl.description}</p>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 self-start sm:self-auto">
                    {hasViolations ? (
                      <span className="px-2.5 py-1 rounded-lg bg-rose-950 text-rose-300 border border-rose-800 text-xs font-bold">
                        {ctrl.matchingFindings.length} achado{ctrl.matchingFindings.length !== 1 ? 's' : ''} violando
                      </span>
                    ) : (
                      <span className="px-2.5 py-1 rounded-lg bg-emerald-950 text-emerald-300 border border-emerald-800 text-xs font-bold flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Conforme</span>
                      </span>
                    )}

                    <div className="p-1.5 rounded bg-zinc-800 text-zinc-400 hover:text-white">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </div>
                  </div>
                </div>

                {/* Expanded Details Accordion */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-1 space-y-4 border-t border-white/5">
                    {/* Auditor Implication Box */}
                    <div className="p-3.5 bg-zinc-900/70 border border-zinc-800 rounded-lg text-xs space-y-1">
                      <div className="flex items-center gap-1.5 text-rose-400 font-bold uppercase text-[10px] tracking-wider">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>Impacto na Auditoria Formal:</span>
                      </div>
                      <p className="text-zinc-300 leading-relaxed text-[11px]">{ctrl.auditImplication}</p>
                    </div>

                    {/* Remediation Requirements */}
                    <div className="p-3.5 bg-blue-950/20 border border-blue-900/40 rounded-lg text-xs space-y-1">
                      <div className="flex items-center gap-1.5 text-blue-400 font-bold uppercase text-[10px] tracking-wider">
                        <Sparkles className="w-3.5 h-3.5" />
                        <span>Recomendação de Remediação para Aprovação:</span>
                      </div>
                      <p className="text-zinc-300 leading-relaxed text-[11px]">{ctrl.recommendedRemediation}</p>
                    </div>

                    {/* Findings / Evidence List */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-bold text-zinc-400 uppercase tracking-wider">
                          Evidências SAST Coletadas do Workspace ({ctrl.matchingFindings.length}):
                        </span>
                        <span className="text-zinc-500">Mapeamento automatizado por regra e assinatura</span>
                      </div>

                      {ctrl.matchingFindings.length === 0 ? (
                        <div className="p-3 bg-emerald-950/20 border border-emerald-900/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                          <span>Nenhuma evidência violadora detectada no repositório. Controle tecnicamente resguardado.</span>
                        </div>
                      ) : (
                        <div className="space-y-2">
                          {ctrl.matchingFindings.map((finding) => (
                            <div
                              key={finding.id}
                              className="p-3 bg-black/60 border border-white/5 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                            >
                              <div className="space-y-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span
                                    className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                                      finding.severity === 'CRITICAL'
                                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                        : finding.severity === 'HIGH'
                                        ? 'bg-rose-900/50 text-rose-200'
                                        : 'bg-amber-950 text-amber-300'
                                    }`}
                                  >
                                    {finding.severity}
                                  </span>
                                  <span className="font-bold text-white truncate">{finding.ruleName}</span>
                                </div>

                                <div className="flex items-center gap-2 text-zinc-400 text-[11px]">
                                  <FileCode2 className="w-3.5 h-3.5 text-zinc-500" />
                                  <code className="text-zinc-300 font-mono">
                                    {finding.file}:{finding.line}
                                  </code>
                                  {finding.maskedSecret && (
                                    <span className="text-rose-400 font-mono text-[10px] bg-rose-950/40 px-1 rounded">
                                      {finding.maskedSecret}
                                    </span>
                                  )}
                                </div>
                              </div>

                              <div className="flex items-center gap-2 shrink-0">
                                <button
                                  onClick={() => handleCopyFindingEvidence(finding)}
                                  className="p-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs transition-colors cursor-pointer"
                                  title="Copiar texto de evidência"
                                >
                                  {copiedFindingId === finding.id ? (
                                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-3.5 h-3.5" />
                                  )}
                                </button>

                                {onNavigateToFile && (
                                  <button
                                    onClick={() => onNavigateToFile(finding.file, finding.line)}
                                    className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-blue-400 text-xs font-bold flex items-center gap-1 transition-colors cursor-pointer"
                                  >
                                    <span>Inspecionar</span>
                                    <ArrowRight className="w-3 h-3" />
                                  </button>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* 6. Official Framework Documentation References */}
      <div className="p-4 bg-[#0A0A0A] border border-[#222] rounded-xl text-xs space-y-2">
        <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider block">
          Documentações e Normas Regulatórias Oficiais:
        </span>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          <a
            href={COMPLIANCE_FRAMEWORKS_META.SOC2.docUrl}
            target="_blank"
            rel="noreferrer"
            className="p-2 rounded bg-black/40 border border-white/5 hover:border-blue-500/50 flex items-center justify-between text-zinc-400 hover:text-white transition-colors"
          >
            <span>AICPA SOC 2 Trust Services Criteria</span>
            <ExternalLink className="w-3.5 h-3.5 text-zinc-500" />
          </a>
          <a
            href={COMPLIANCE_FRAMEWORKS_META.ISO_27001.docUrl}
            target="_blank"
            rel="noreferrer"
            className="p-2 rounded bg-black/40 border border-white/5 hover:border-blue-500/50 flex items-center justify-between text-zinc-400 hover:text-white transition-colors"
          >
            <span>ISO/IEC 27001:2022 Information Security</span>
            <ExternalLink className="w-3.5 h-3.5 text-zinc-500" />
          </a>
          <a
            href={COMPLIANCE_FRAMEWORKS_META.HIPAA.docUrl}
            target="_blank"
            rel="noreferrer"
            className="p-2 rounded bg-black/40 border border-white/5 hover:border-blue-500/50 flex items-center justify-between text-zinc-400 hover:text-white transition-colors"
          >
            <span>HHS HIPAA Security Rule (45 CFR Part 164)</span>
            <ExternalLink className="w-3.5 h-3.5 text-zinc-500" />
          </a>
        </div>
      </div>
    </div>
  );
};
