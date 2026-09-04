import React, { useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Layers, 
  Terminal, 
  Activity, 
  Route, 
  CheckCircle2, 
  AlertOctagon, 
  Sparkles,
  ExternalLink,
  Ban,
  Compass,
  FileDown,
  FileText,
  Download,
  Check,
  Flame,
  ArrowRight,
  AlertTriangle,
  Sliders,
  Plus,
  Minus,
  RotateCcw,
  BellRing,
  Settings,
  FolderTree,
  BookOpen
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  Tooltip as RechartsTooltip, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis 
} from 'recharts';
import { ScanReport, AuditLogEvent, ScanFinding, IgnorePatternItem } from '../types';
import { VulnerabilityHeatmap } from './VulnerabilityHeatmap';
import { VulnerabilityTrendChart } from './VulnerabilityTrendChart';
import { SeverityDonutChart } from './SeverityDonutChart';
import { SecurityImpactPanel } from './SecurityImpactPanel';
import { downloadSecurityReportPdf } from '../lib/pdfReportGenerator';
import { SecurityGlossaryTooltip } from './SecurityGlossary';
import { SecurityGlossaryEntry } from '../lib/securityGlossary';
import { safeGetItem, safeSetItem } from '../lib/storage';

interface DashboardOverviewProps {
  report: ScanReport;
  auditLogs: AuditLogEvent[];
  onSelectFinding: (finding: ScanFinding) => void;
  onNavigateToTab: (tab: string) => void;
  onNavigateToFile?: (filePath: string) => void;
  onOpenTour?: () => void;
  onOpenExport?: () => void;
  ignorePatterns?: IgnorePatternItem[];
  onOpenIgnoreModal?: () => void;
  onToggleIgnorePattern?: (id: string) => void;
  onOpenGlossary?: (entry?: SecurityGlossaryEntry) => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#FF3E00', // Electric safety orange
  HIGH: '#FF7A00',
  MEDIUM: '#EAB308',
  LOW: '#3366FF',      // Terminal blue
  INFO: '#555555'
};

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  report,
  auditLogs,
  onSelectFinding,
  onNavigateToTab,
  onNavigateToFile,
  onOpenTour,
  onOpenExport,
  ignorePatterns = [],
  onOpenIgnoreModal,
  onToggleIgnorePattern,
  onOpenGlossary
}) => {
  const findings = report?.findings || [];
  const apiEndpoints = report?.apiEndpoints || [];
  const metrics: ScanReport['metrics'] = report?.metrics || {
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
    securityScore: 100,
    securityImpactScore: 0,
    impactLevel: 'NOMINAL',
    totalWeightedRisk: 0,
    criticalityDistribution: {
      criticalFiles: 0,
      highFiles: 0,
      mediumFiles: 0,
      lowFiles: 0
    },
    averageEntropy: 0
  };
  const safeIgnorePatterns = Array.isArray(ignorePatterns) ? ignorePatterns : [];
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [pdfSuccess, setPdfSuccess] = useState(false);

  // Critical Finding Threshold configuration state (persisted in safe storage)
  const DEFAULT_CRITICAL_THRESHOLD = 1;
  const [criticalThreshold, setCriticalThreshold] = useState<number>(() => {
    try {
      const saved = safeGetItem('secscan_critical_finding_threshold');
      if (saved !== null) {
        const parsed = parseInt(saved, 10);
        if (!isNaN(parsed) && parsed >= 0) return parsed;
      }
    } catch {
      // ignore storage error
    }
    return DEFAULT_CRITICAL_THRESHOLD;
  });

  const handleUpdateThreshold = (val: number) => {
    const sanitized = Math.max(0, Math.floor(val));
    setCriticalThreshold(sanitized);
    safeSetItem('secscan_critical_finding_threshold', sanitized.toString());
  };

  const highSeverityCount = metrics.highCount;
  const isThresholdExceeded = highSeverityCount > criticalThreshold;
  const highSeverityFindings = findings.filter(f => f.severity === 'HIGH');

  const handleExportPdf = () => {
    setIsGeneratingPdf(true);
    try {
      downloadSecurityReportPdf(report);
      setPdfSuccess(true);
      setTimeout(() => setPdfSuccess(false), 3500);
    } catch (err) {
      console.error('Failed to export PDF report:', err);
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  // Category distribution
  const categoryCounts: Record<string, number> = {};
  findings.forEach(f => {
    categoryCounts[f.category] = (categoryCounts[f.category] || 0) + 1;
  });

  const categoryLabels: Record<string, string> = {
    CLOUD_CREDENTIAL: 'Nuvem (AWS/GCP)',
    API_KEY: 'Chaves de API',
    AUTH_TOKEN: 'Tokens / JWT',
    DATABASE_URI: 'Banco de Dados',
    PRIVATE_KEY: 'Chaves Privadas',
    PASSWORD: 'Hardcoded Pass',
    API_PATH: 'Rotas de API',
    CUSTOM_REGEX: 'Regex Custom'
  };

  const categoryData = Object.entries(categoryCounts).map(([cat, count]) => ({
    name: categoryLabels[cat] || cat,
    count
  }));

  // Score rating letter
  const getGrade = (score: number) => {
    if (score >= 90) return { letter: 'A+', color: 'text-[#00FF41]', bg: 'bg-[#081f0e] border-[#00FF41]/40' };
    if (score >= 75) return { letter: 'B', color: 'text-[#3366FF]', bg: 'bg-[#001433] border-[#3366FF]/40' };
    if (score >= 50) return { letter: 'C', color: 'text-amber-400', bg: 'bg-amber-950/40 border-amber-500/40' };
    return { letter: 'F', color: 'text-[#FF3E00]', bg: 'bg-[#220700] border-[#FF3E00]/40' };
  };

  const grade = getGrade(metrics.securityScore);
  const criticalFindings = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 5);

  const impactScore = metrics.securityImpactScore ?? 0;
  const getImpactBadge = (val: number) => {
    if (val >= 80) return { text: 'text-[#FF3E00]', bg: 'bg-[#FF3E00]/15 border-[#FF3E00]/40', label: 'CRÍTICO' };
    if (val >= 60) return { text: 'text-[#FF7A00]', bg: 'bg-[#FF7A00]/15 border-[#FF7A00]/40', label: 'ALTO' };
    if (val >= 35) return { text: 'text-[#EAB308]', bg: 'bg-[#EAB308]/15 border-[#EAB308]/40', label: 'ELEVADO' };
    if (val >= 15) return { text: 'text-[#3366FF]', bg: 'bg-[#3366FF]/15 border-[#3366FF]/40', label: 'MODERADO' };
    if (val > 0) return { text: 'text-[#00FF41]', bg: 'bg-[#00FF41]/15 border-[#00FF41]/40', label: 'BAIXO' };
    return { text: 'text-[#00FF41]', bg: 'bg-[#00FF41]/15 border-[#00FF41]/30', label: 'NOMINAL' };
  };
  const impactBadge = getImpactBadge(impactScore);

  return (
    <div className="space-y-8 pb-12">
      {/* Persistent 'ACTION REQUIRED' Visual Warning Alert */}
      {isThresholdExceeded && (
        <div 
          id="persistent-action-required-alert"
          className="relative bg-[#140300] border-2 border-[#FF3E00] shadow-[0_0_35px_rgba(255,62,0,0.35)] overflow-hidden transition-all"
        >
          {/* Top urgency hazard strip */}
          <div className="h-1.5 w-full bg-gradient-to-r from-[#FF3E00] via-[#FF8533] to-[#FF3E00] animate-pulse" />

          <div className="p-6 sm:p-8 space-y-6">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-[#FF3E00]/30">
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="inline-flex items-center gap-2 px-3 py-1 bg-[#FF3E00] text-black font-black text-xs uppercase tracking-[0.25em] animate-pulse shadow-[0_0_15px_rgba(255,62,0,0.6)]">
                    <AlertTriangle className="w-4 h-4 text-black" />
                    ACTION REQUIRED
                  </span>
                  <span className="text-[10px] font-mono text-[#FF3E00] bg-[#FF3E00]/10 px-2.5 py-1 border border-[#FF3E00]/40 uppercase font-black tracking-widest">
                    CRITICAL FINDING THRESHOLD EXCEEDED
                  </span>
                  <span className="text-[10px] font-mono text-[#888] flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#FF3E00] animate-ping" />
                    ALERTA PERSISTENTE ATIVO
                  </span>
                </div>

                <div>
                  <h2 className="text-2xl sm:text-3xl font-black uppercase tracking-tight text-white flex items-center gap-3">
                    <span>Limite de Achados Críticos Ultrapassado</span>
                  </h2>
                  <p className="text-xs sm:text-sm font-mono text-[#DDD] mt-1 max-w-3xl leading-relaxed">
                    O volume de vulnerabilidades de <strong className="text-[#FF3E00]">Alta Severidade (HIGH)</strong> detectadas ({highSeverityCount}) excedeu o <strong className="text-white">Critical Finding Threshold ({criticalThreshold})</strong> configurado. Ações imediatas de contenção e rotação de credenciais são mandatórias.
                  </p>
                </div>
              </div>

              {/* Threshold Comparison Badge */}
              <div className="flex items-center gap-3 shrink-0 bg-[#0A0200] border border-[#FF3E00]/40 p-4 font-mono">
                <div className="text-center pr-4 border-r border-[#331108]">
                  <div className="text-[10px] text-[#888] uppercase tracking-wider">Alta Gravidade</div>
                  <div className="text-3xl font-black text-[#FF3E00]">{highSeverityCount}</div>
                  <div className="text-[9px] text-[#AAA]">Detectados</div>
                </div>
                <div className="text-center px-2">
                  <div className="text-xs font-black text-[#888]">&gt;</div>
                </div>
                <div className="text-center pl-4 border-l border-[#331108]">
                  <div className="text-[10px] text-[#888] uppercase tracking-wider">Threshold</div>
                  <div className="text-3xl font-black text-white">{criticalThreshold}</div>
                  <div className="text-[9px] text-[#AAA]">Limite Máx</div>
                </div>
                <div className="ml-3 pl-3 border-l border-[#FF3E00]/40 text-right">
                  <div className="text-[10px] text-[#FF3E00] uppercase font-bold">Excedido por</div>
                  <div className="text-xl font-black text-[#FF3E00]">+{highSeverityCount - criticalThreshold}</div>
                  <div className="text-[9px] text-[#888]">ocorrência(s)</div>
                </div>
              </div>
            </div>

            {/* List of High-Severity findings causing the alert */}
            {highSeverityFindings.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center justify-between text-[11px] font-mono">
                  <span className="text-[#AAA] uppercase font-bold flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-[#FF3E00]" />
                    Vulnerabilidades de Alta Severidade Detectadas ({highSeverityFindings.length}):
                  </span>
                  <span className="text-[10px] text-[#888]">
                    Clique em um achado para visualizar detalhes no código
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
                  {highSeverityFindings.slice(0, 6).map((finding) => (
                    <button
                      key={finding.id}
                      onClick={() => onSelectFinding(finding)}
                      className="p-3 bg-[#080200] border border-[#FF3E00]/30 hover:border-[#FF3E00] hover:bg-[#200500] text-left transition-all group relative"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[9px] font-mono bg-[#FF3E00]/20 text-[#FF3E00] px-1.5 py-0.5 border border-[#FF3E00]/40 font-bold uppercase">
                          HIGH SEVERITY
                        </span>
                        <span className="text-[9px] font-mono text-[#888] group-hover:text-white">
                          Linha {finding.line}
                        </span>
                      </div>
                      <div className="text-xs font-bold text-white uppercase truncate group-hover:text-[#FF3E00] transition-colors">
                        {finding.ruleName}
                      </div>
                      <div className="text-[10px] font-mono text-[#888] truncate mt-0.5">
                        {finding.file}
                      </div>
                      <div className="mt-1.5 pt-1.5 border-t border-[#220700] text-[9px] font-mono text-[#AAA] truncate">
                        Snippet: <span className="text-white">{finding.maskedSecret || finding.snippet.slice(0, 30)}</span>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Actions Bar */}
            <div className="flex flex-wrap items-center justify-between gap-4 pt-4 border-t border-[#FF3E00]/20">
              <div className="flex flex-wrap items-center gap-3">
                <button
                  onClick={() => onNavigateToTab('scanner')}
                  className="px-5 py-2.5 bg-[#FF3E00] hover:bg-white hover:text-black text-white font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center gap-2"
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Auditar Achados no Scanner</span>
                </button>

                <button
                  onClick={() => {
                    const el = document.getElementById('critical-threshold-config');
                    if (el) el.scrollIntoView({ behavior: 'smooth' });
                  }}
                  className="px-4 py-2.5 border border-[#FF3E00]/40 bg-[#0A0200] hover:bg-[#FF3E00]/20 text-white font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center gap-2"
                >
                  <Sliders className="w-3.5 h-3.5 text-[#FF3E00]" />
                  <span>Ajustar Limite ({criticalThreshold})</span>
                </button>

                <button
                  onClick={handleExportPdf}
                  disabled={isGeneratingPdf}
                  className="px-4 py-2.5 border border-[#333] bg-[#0A0A0A] hover:bg-white hover:text-black text-white font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center gap-2 disabled:opacity-50"
                >
                  <FileDown className="w-3.5 h-3.5 text-[#FF3E00]" />
                  <span>Baixar Relatório PDF</span>
                </button>
              </div>

              <div className="text-[10px] font-mono text-[#888] italic">
                * Este aviso é persistente e só deixará de ser exibido quando as vulnerabilidades forem corrigidas ou o limite for elevado.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Top Threat Matrix Hero Banner */}
      <div className="bg-[#080808] border border-[#222] p-8 relative overflow-hidden flex flex-col lg:flex-row lg:items-end justify-between gap-6">
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-[10px] font-black tracking-[0.25em] text-[#FF3E00] uppercase">
              // STATIC ANALYSIS SECURITY TESTING
            </span>
            <span className="text-[10px] font-mono text-[#00FF41] bg-[#00FF41]/10 px-2 py-0.5 border border-[#00FF41]/30 uppercase font-bold">
              REGEX_ENGINE_ACTIVE
            </span>
            <button
              onClick={() => {
                const el = document.getElementById('critical-threshold-config');
                if (el) el.scrollIntoView({ behavior: 'smooth' });
              }}
              className={`text-[10px] font-mono px-2 py-0.5 border font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                isThresholdExceeded
                  ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/50 hover:bg-[#FF3E00] hover:text-white'
                  : 'bg-[#111] text-[#AAA] border-[#333] hover:border-[#666]'
              }`}
              title="Clique para configurar o Critical Finding Threshold"
            >
              <Sliders className="w-3 h-3" />
              <span>THRESHOLD: {criticalThreshold} HIGH {isThresholdExceeded ? '⚠️ EXCEDIDO' : '✓ OK'}</span>
            </button>
          </div>
          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-black tracking-tighter text-white leading-none uppercase">
            THREAT <span className="text-[#333]">MATRIX</span>
          </h1>
          <p className="text-xs font-mono text-[#888] max-w-2xl leading-relaxed">
            Varredura automatizada em JavaScript/TypeScript com filtro estrito de dependências (<span className="text-[#00FF41]">node_modules/**/*</span>), cálculo de entropia e conformidade OWASP A07.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            id="btn-export-pdf-hero"
            onClick={handleExportPdf}
            disabled={isGeneratingPdf}
            className="px-5 py-3.5 border border-[#FF3E00] bg-[#FF3E00]/15 hover:bg-[#FF3E00] hover:text-white text-white font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center gap-2 shadow-[0_0_15px_rgba(255,62,0,0.15)] disabled:opacity-50"
            title="Gerar e baixar relatório executivo consolidado em PDF"
          >
            {pdfSuccess ? (
              <>
                <Check className="w-3.5 h-3.5 text-[#00FF41]" />
                <span className="text-[#00FF41]">PDF Baixado!</span>
              </>
            ) : (
              <>
                <FileDown className={`w-3.5 h-3.5 text-[#FF3E00] ${isGeneratingPdf ? 'animate-bounce' : ''}`} />
                <span>{isGeneratingPdf ? 'Gerando PDF...' : 'Relatório PDF'}</span>
              </>
            )}
          </button>
          <button
            id="btn-nav-threshold-hero"
            onClick={() => {
              const el = document.getElementById('critical-threshold-config');
              if (el) el.scrollIntoView({ behavior: 'smooth' });
            }}
            className={`px-4 py-3.5 border font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center gap-2 ${
              isThresholdExceeded
                ? 'border-[#FF3E00] bg-[#FF3E00]/20 text-[#FF3E00] hover:bg-[#FF3E00] hover:text-white'
                : 'border-[#333] bg-[#0A0A0A] hover:border-white text-white'
            }`}
            title="Ajustar Limite de Achados Críticos"
          >
            <Sliders className="w-3.5 h-3.5 text-[#FF3E00]" />
            <span>Limite ({criticalThreshold})</span>
          </button>
          {onOpenIgnoreModal && (
            <button
              id="btn-nav-ignore-hero"
              onClick={onOpenIgnoreModal}
              className="px-4 py-3.5 border border-[#333] hover:border-[#FF3E00] bg-[#0A0A0A] hover:bg-[#141414] text-white font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center gap-2 group"
              title="Gerenciar Lista Global de Exclusões (Global Ignore List)"
            >
              <Ban className="w-3.5 h-3.5 text-[#FF3E00] group-hover:rotate-12 transition-transform" />
              <span>Ignore List ({safeIgnorePatterns.filter(p => p && p.enabled).length})</span>
            </button>
          )}
          {onOpenTour && (
            <button
              onClick={onOpenTour}
              className="px-5 py-3.5 border border-[#FF3E00]/40 bg-[#FF3E00]/10 hover:bg-[#FF3E00] hover:text-white text-[#FF3E00] font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center gap-2"
            >
              <Compass className="w-3.5 h-3.5" />
              <span>Guia Rápido</span>
            </button>
          )}
          <button
            onClick={() => onNavigateToTab('cli')}
            className="px-5 py-3.5 border border-[#333] hover:border-white bg-[#0A0A0A] hover:bg-white hover:text-black text-white font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center gap-2"
          >
            <Terminal className="w-3.5 h-3.5 text-[#FF3E00]" />
            <span>Terminal CLI</span>
          </button>
          <button
            onClick={() => onNavigateToTab('cicd')}
            className="px-5 py-3.5 bg-white hover:bg-[#FF3E00] hover:text-white text-black font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center gap-2"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            <span>CI/CD Pipeline</span>
          </button>
        </div>
      </div>

      {/* Metrics Row - 6 High-Precision Cards with Security Impact Score */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {/* Metric 1: Security Impact Score (Weighted System) */}
        <div className="bg-[#0A0A0A] p-6 border border-[#2A2A2A] relative overflow-hidden flex flex-col justify-between">
          <div className="absolute top-0 right-0 w-20 h-20 bg-[#FF3E00]/5 rounded-bl-full pointer-events-none" />
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-[10px] font-black tracking-[0.2em] text-[#888] uppercase">
                Security Impact
              </span>
              <div className={`px-2 py-0.5 font-mono font-black text-[10px] border ${impactBadge.bg} ${impactBadge.text}`}>
                {impactBadge.label}
              </div>
            </div>
            <div className="flex items-baseline gap-1.5 mb-1">
              <span className={`text-5xl font-black tracking-tighter ${impactBadge.text}`}>
                {impactScore}
              </span>
              <span className="text-xs font-mono text-[#666] font-bold">/ 100</span>
            </div>
            <div className="text-[11px] font-mono text-[#888] uppercase tracking-wide">
              Weighted Risk Index
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[#1A1A1A] flex items-center justify-between text-[10px] font-mono text-[#AAA]">
            <span>Carga: {metrics.totalWeightedRisk ?? 0} pts</span>
            <span className={impactBadge.text}>{metrics.impactLevel ?? 'NOMINAL'}</span>
          </div>
        </div>

        {/* Metric 2: Compliance Health */}
        <div className="bg-[#0A0A0A] p-6 border border-[#222] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-[10px] font-black tracking-[0.2em] text-[#666] uppercase">System Health</span>
              <div className={`w-7 h-7 flex items-center justify-center font-black text-xs border ${grade.bg} ${grade.color}`}>
                {grade.letter}
              </div>
            </div>
            <div className="text-5xl font-black tracking-tighter text-white mb-1">
              {metrics.securityScore}%
            </div>
            <div className="text-[11px] font-mono text-[#666] uppercase tracking-wide">
              Compliance Score
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[#1A1A1A] text-[10px] font-mono text-[#888]">
            {metrics.criticalCount === 0 ? 'STATUS: NOMINAL / SECURE' : 'STATUS: REMEDIATION REQ'}
          </div>
        </div>

        {/* Metric 3: Scanned vs Ignored */}
        <div className="bg-[#0A0A0A] p-6 border border-[#222] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-[10px] font-black tracking-[0.2em] text-[#666] uppercase">Scanned Sources</span>
              <Layers className="w-4 h-4 text-[#888]" />
            </div>
            <div className="text-5xl font-black tracking-tighter text-white mb-1">
              {report.scannedFilesCount}
            </div>
            <div className="text-[11px] font-mono text-[#666] uppercase tracking-wide">
              Files Evaluated
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[#1A1A1A] text-[11px] font-mono text-[#00FF41] flex items-center gap-1.5">
            <Ban className="w-3.5 h-3.5" />
            <span>{report.ignoredFilesCount} Ignored Deps</span>
          </div>
        </div>

        {/* Metric 4: Total Secrets */}
        <div className="bg-[#0A0A0A] p-6 border border-[#222] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-[10px] font-black tracking-[0.2em] text-[#666] uppercase">Active Exposures</span>
              <ShieldAlert className="w-4 h-4 text-[#FF3E00]" />
            </div>
            <div className={`text-5xl font-black tracking-tighter mb-1 ${findings.length > 0 ? 'text-[#FF3E00]' : 'text-white'}`}>
              {findings.length}
            </div>
            <div className="text-[11px] font-mono text-[#666] uppercase tracking-wide">
              Secrets Exposed
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[#1A1A1A] flex items-center justify-between font-mono text-[10px]">
            <div className="flex items-center gap-1.5">
              <span className="bg-[#220700] text-[#FF3E00] px-1.5 py-0.5 border border-[#FF3E00]/30 font-bold">
                {metrics.criticalCount} CRIT
              </span>
              <span className={`px-1.5 py-0.5 border font-bold ${
                isThresholdExceeded
                  ? 'bg-[#FF3E00]/20 text-[#FF3E00] border-[#FF3E00]/50 animate-pulse'
                  : 'bg-[#1A1A1A] text-[#AAA] border-[#333]'
              }`}>
                {metrics.highCount} HIGH
              </span>
            </div>
            <button
              onClick={() => {
                const el = document.getElementById('critical-threshold-config');
                if (el) el.scrollIntoView({ behavior: 'smooth' });
              }}
              className={`text-[9px] font-mono px-1 py-0.5 border transition-colors ${
                isThresholdExceeded 
                  ? 'text-[#FF3E00] border-[#FF3E00]/40 bg-[#FF3E00]/10 hover:bg-[#FF3E00] hover:text-white' 
                  : 'text-[#888] border-[#333] hover:text-white'
              }`}
              title="Configurar Critical Finding Threshold"
            >
              Limite: {criticalThreshold} {isThresholdExceeded ? '⚠️' : '✓'}
            </button>
          </div>
        </div>

        {/* Metric 5: API Endpoints */}
        <div className="bg-[#0A0A0A] p-6 border border-[#222] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-[10px] font-black tracking-[0.2em] text-[#666] uppercase">Surface Endpoints</span>
              <Route className="w-4 h-4 text-[#3366FF]" />
            </div>
            <div className="text-5xl font-black tracking-tighter text-white mb-1">
              {apiEndpoints.length}
            </div>
            <div className="text-[11px] font-mono text-[#666] uppercase tracking-wide">
              REST Routes Mapped
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[#1A1A1A] text-[10px] font-mono text-[#AAA]">
            {apiEndpoints.filter(e => e.isInternalOrAdmin).length} Admin / Internal
          </div>
        </div>

        {/* Metric 6: Shannon Entropy */}
        <div className="bg-[#0A0A0A] p-6 border border-[#222] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-[10px] font-black tracking-[0.2em] text-[#666] uppercase">Entropy Index</span>
              <Sparkles className="w-4 h-4 text-[#00FF41]" />
            </div>
            <div className="text-5xl font-black tracking-tighter text-white mb-1">
              {metrics.averageEntropy}
            </div>
            <div className="text-[11px] font-mono text-[#666] uppercase tracking-wide">
              Shannon (Bits/Char)
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[#1A1A1A] text-[10px] font-mono text-[#00FF41]">
            CRYPTOGRAPHIC_RANDOMNESS
          </div>
        </div>
      </div>

      {/* Critical Finding Threshold Configuration Section */}
      <div 
        id="critical-threshold-config"
        className={`border p-6 lg:p-7 space-y-6 transition-all ${
          isThresholdExceeded 
            ? 'bg-[#0E0402] border-[#FF3E00]/60 shadow-[0_0_25px_rgba(255,62,0,0.12)]' 
            : 'bg-[#080808] border-[#222]'
        }`}
      >
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-[#1A1A1A]">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="text-[10px] font-black tracking-[0.25em] text-[#FF3E00] uppercase">
                // GOVERNANCE POLICY • THRESHOLD CONTROLS
              </span>
              <span className={`text-[9px] font-mono px-2 py-0.5 border font-bold uppercase ${
                isThresholdExceeded
                  ? 'bg-[#FF3E00]/20 text-[#FF3E00] border-[#FF3E00]/50 animate-pulse'
                  : 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/30'
              }`}>
                {isThresholdExceeded ? 'ACTION REQUIRED • LIMITE EXCEDIDO' : 'STATUS: CONFORME COM POLÍTICA'}
              </span>
            </div>
            <h3 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
              <Sliders className="w-5 h-5 text-[#FF3E00]" />
              <span>Configuração: Critical Finding Threshold</span>
            </h3>
            <p className="text-xs font-mono text-[#888] max-w-3xl leading-relaxed">
              Defina a quantidade máxima tolerada de vulnerabilidades de <strong className="text-white">Alta Severidade (HIGH)</strong>. Quando o total de achados ultrapassar este valor, o alerta visual persistente <strong className="text-[#FF3E00]">'ACTION REQUIRED'</strong> será disparado no topo do dashboard.
            </p>
          </div>

          {/* Current Status Capsule */}
          <div className="flex items-center gap-4 bg-[#0A0A0A] border border-[#222] px-4 py-3 shrink-0 font-mono text-xs">
            <div>
              <div className="text-[10px] text-[#777] uppercase">Vulnerabilidades HIGH</div>
              <div className="text-xl font-black text-white">{highSeverityCount} ativas</div>
            </div>
            <div className="h-8 w-px bg-[#222]" />
            <div>
              <div className="text-[10px] text-[#777] uppercase">Threshold Configurado</div>
              <div className="text-xl font-black text-[#FF3E00]">{criticalThreshold} máx</div>
            </div>
          </div>
        </div>

        {/* Interactive Controls & Stepper */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
          {/* Stepper + Input */}
          <div className="lg:col-span-5 space-y-2">
            <label htmlFor="input-critical-threshold" className="text-[10px] font-mono uppercase tracking-widest text-[#AAA] font-bold block">
              Ajuste do Limite (Número Inteiro ≥ 0):
            </label>
            <div className="flex items-center gap-2">
              <button
                id="btn-decrement-threshold"
                onClick={() => handleUpdateThreshold(criticalThreshold - 1)}
                disabled={criticalThreshold <= 0}
                className="w-11 h-11 bg-[#141414] hover:bg-[#FF3E00] hover:text-white text-white border border-[#333] flex items-center justify-center font-bold text-lg transition-all disabled:opacity-30 disabled:hover:bg-[#141414]"
                title="Diminuir limite em 1"
              >
                <Minus className="w-4 h-4" />
              </button>

              <div className="relative flex-1">
                <input
                  id="input-critical-threshold"
                  type="number"
                  min="0"
                  max="100"
                  value={criticalThreshold}
                  onChange={(e) => {
                    const parsed = parseInt(e.target.value, 10);
                    if (!isNaN(parsed)) handleUpdateThreshold(parsed);
                  }}
                  className="w-full h-11 bg-[#050505] border border-[#333] focus:border-[#FF3E00] text-center font-mono font-black text-xl text-white outline-none px-3 transition-colors"
                />
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] font-mono text-[#666] pointer-events-none">
                  VULNS
                </span>
              </div>

              <button
                id="btn-increment-threshold"
                onClick={() => handleUpdateThreshold(criticalThreshold + 1)}
                className="w-11 h-11 bg-[#141414] hover:bg-[#FF3E00] hover:text-white text-white border border-[#333] flex items-center justify-center font-bold text-lg transition-all"
                title="Aumentar limite em 1"
              >
                <Plus className="w-4 h-4" />
              </button>

              <button
                id="btn-reset-threshold"
                onClick={() => handleUpdateThreshold(DEFAULT_CRITICAL_THRESHOLD)}
                className="h-11 px-3 bg-[#111] hover:bg-[#222] border border-[#333] text-[#AAA] hover:text-white flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider transition-all"
                title="Restaurar valor padrão (1)"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Padrão</span>
              </button>
            </div>
          </div>

          {/* Preset Buttons */}
          <div className="lg:col-span-7 space-y-2">
            <label className="text-[10px] font-mono uppercase tracking-widest text-[#AAA] font-bold block">
              Predefinições Rápidas de Política de Risco:
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
              {[
                { val: 0, label: '0', sub: 'Tolerância Zero' },
                { val: 1, label: '1', sub: 'Rígido (Default)' },
                { val: 2, label: '2', sub: 'Padrão SecOps' },
                { val: 3, label: '3', sub: 'Moderado' },
                { val: 5, label: '5', sub: 'Permissivo' }
              ].map((preset) => {
                const isSelected = criticalThreshold === preset.val;
                return (
                  <button
                    key={preset.val}
                    onClick={() => handleUpdateThreshold(preset.val)}
                    className={`p-2.5 border text-center transition-all flex flex-col items-center justify-center ${
                      isSelected
                        ? 'border-[#FF3E00] bg-[#FF3E00]/15 text-white shadow-[0_0_10px_rgba(255,62,0,0.2)]'
                        : 'border-[#222] bg-[#0A0A0A] hover:border-[#444] text-[#888] hover:text-white'
                    }`}
                  >
                    <span className={`text-xs font-black font-mono ${isSelected ? 'text-[#FF3E00]' : 'text-white'}`}>
                      {preset.label}
                    </span>
                    <span className="text-[8.5px] font-mono text-[#777] uppercase truncate max-w-full">
                      {preset.sub}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Diagnostic Status Box */}
        <div className={`p-4 border font-mono text-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${
          isThresholdExceeded
            ? 'bg-[#180300] border-[#FF3E00]/40 text-[#FF8533]'
            : 'bg-[#001405] border-[#00FF41]/30 text-[#00FF41]'
        }`}>
          <div className="flex items-center gap-2.5">
            {isThresholdExceeded ? (
              <AlertTriangle className="w-4 h-4 text-[#FF3E00] shrink-0 animate-pulse" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-[#00FF41] shrink-0" />
            )}
            <div>
              {isThresholdExceeded ? (
                <span>
                  <strong className="text-[#FF3E00]">ALERTA 'ACTION REQUIRED' ATIVO:</strong> Existem <strong className="text-white">{highSeverityCount}</strong> vulnerabilidades de alta severidade, ultrapassando o threshold de <strong className="text-white">{criticalThreshold}</strong> (excesso de <strong className="text-[#FF3E00]">+{highSeverityCount - criticalThreshold}</strong>).
                </span>
              ) : (
                <span>
                  <strong>POLÍTICA CONFORME:</strong> O volume de vulnerabilidades de alta severidade ({highSeverityCount}) está dentro do threshold configurado ({criticalThreshold}).
                </span>
              )}
            </div>
          </div>
          <span className="text-[10px] uppercase tracking-wider text-[#777] shrink-0">
            Armazenamento: LocalStorage • Automático
          </span>
        </div>
      </div>

      {/* Global Ignore List & Exclusions Governance Panel */}
      <div id="global-ignore-governance-panel" className="bg-[#0A0A0A] border-2 border-[#2A2A2A] p-6 lg:p-8 space-y-6 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-[#222]">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[10px] font-mono text-[#FF3E00] bg-[#FF3E00]/10 px-2.5 py-0.5 border border-[#FF3E00]/40 uppercase font-black tracking-widest flex items-center gap-1.5">
                <Ban className="w-3 h-3" />
                GLOBAL IGNORE LIST // EXCLUSÕES DE SAST
              </span>
              <span className="text-[10px] font-mono text-[#888]">
                POLÍTICA DE ESCOPO GLOBAL
              </span>
              <span className="text-[10px] font-mono bg-[#141414] text-[#00FF41] border border-[#00FF41]/30 px-2 py-0.5 font-bold">
                {safeIgnorePatterns.filter(p => p && p.enabled).length} PADRÕES ATIVOS
              </span>
              <span className="text-[10px] font-mono bg-[#141414] text-[#AAA] border border-[#333] px-2 py-0.5">
                {report?.ignoredFilesCount ?? 0} ARQUIVOS IGNORADOS
              </span>
            </div>

            <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
              <span>Lista Global de Exclusão de Arquivos</span>
            </h2>
            <p className="text-xs font-mono text-[#888] max-w-3xl leading-relaxed">
              Define caminhos, diretórios ou padrões globais (<code className="text-white bg-[#141414] px-1 py-0.5">tests/*</code>, <code className="text-white bg-[#141414] px-1 py-0.5">node_modules/*</code>, <code className="text-white bg-[#141414] px-1 py-0.5">*.test.*</code>) excluídos de todos os escaneamentos futuros para eliminar ruídos e falsos-positivos em suítes de teste.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {onOpenIgnoreModal && (
              <button
                id="btn-open-ignore-modal-governance"
                onClick={onOpenIgnoreModal}
                className="px-5 py-3 bg-[#FF3E00] hover:bg-white hover:text-black text-white font-black text-xs uppercase tracking-[0.15em] transition-all flex items-center gap-2 shadow-[0_0_20px_rgba(255,62,0,0.2)]"
              >
                <Ban className="w-4 h-4" />
                <span>Gerenciar Padrões Globais</span>
              </button>
            )}
          </div>
        </div>

        {/* Quick-Toggle Grid for Key Global Patterns */}
        <div className="space-y-3">
          <div className="flex items-center justify-between text-[11px] font-mono">
            <span className="text-[#AAA] uppercase font-bold flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-[#FF3E00]" />
              Padrões Principais de Exclusão (Clique para Ativar/Desativar):
            </span>
            <span className="text-[10px] text-[#666]">
              {safeIgnorePatterns.length} regras configuradas • Persistidas em LocalStorage
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {safeIgnorePatterns.slice(0, 8).map((item) => {
              const isEnabled = item.enabled;
              return (
                <div
                  key={item.id}
                  className={`p-3.5 border transition-all text-left flex flex-col justify-between gap-3 ${
                    isEnabled
                      ? 'bg-[#0E0502] border-[#FF3E00]/40 shadow-[0_0_10px_rgba(255,62,0,0.05)]'
                      : 'bg-[#080808] border-[#222] opacity-60'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className={`font-mono font-black text-xs px-2 py-0.5 border ${
                        isEnabled
                          ? 'bg-[#180804] text-white border-[#FF3E00]/50'
                          : 'bg-[#111] text-[#666] border-[#333]'
                      }`}>
                        {item.pattern}
                      </span>

                      <button
                        type="button"
                        onClick={() => onToggleIgnorePattern && onToggleIgnorePattern(item.id)}
                        className={`w-9 h-5 flex items-center px-0.5 transition-colors cursor-pointer ${
                          isEnabled ? 'bg-[#FF3E00] justify-end' : 'bg-[#222] justify-start'
                        }`}
                        title={isEnabled ? 'Desativar padrão' : 'Ativar padrão'}
                      >
                        <span className="w-4 h-4 bg-white block shadow-sm" />
                      </button>
                    </div>

                    <p className="text-[10px] font-mono text-[#888] line-clamp-2 mt-1">
                      {item.description || 'Padrão global de exclusão'}
                    </p>
                  </div>

                  <div className="flex items-center justify-between text-[9px] font-mono pt-2 border-t border-[#1C1C1C]">
                    <span className={isEnabled ? 'text-[#00FF41] font-bold' : 'text-[#666]'}>
                      {isEnabled ? '● ATIVO NO SAST' : '○ DESATIVADO'}
                    </span>
                    {item.isBuiltIn && (
                      <span className="text-[#666]">PADRÃO CORE</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Global Ignore Status Footer */}
        <div className="p-4 bg-[#080808] border border-[#222] font-mono text-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-[#AAA]">
          <div className="flex items-center gap-2">
            <FolderTree className="w-4 h-4 text-[#FF3E00] shrink-0" />
            <span>
              Arquivos correspondentes às regras ativas são automaticamente marcados como <strong>IGNORED</strong> e não contabilizam para o cálculo de métricas ou para o <strong>Critical Finding Threshold</strong>.
            </span>
          </div>
          {onOpenIgnoreModal && (
            <button
              onClick={onOpenIgnoreModal}
              className="text-[#FF3E00] hover:text-white font-bold text-xs uppercase tracking-wider underline shrink-0 cursor-pointer"
            >
              + Adicionar Padrão Customizado
            </button>
          )}
        </div>
      </div>

      {/* Weighted Risk Scoring Engine & Impact Breakdown Panel */}
      <SecurityImpactPanel 
        report={report} 
        onNavigateToFile={onNavigateToFile}
        onNavigateToTab={onNavigateToTab}
      />

      {/* Consolidated Executive Risk Summary & Mitigation Action Card */}
      <div className="bg-[#080808] border border-[#2A2A2A] p-6 lg:p-8 space-y-6 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-40 h-40 bg-[#FF3E00]/5 rounded-bl-full pointer-events-none" />
        
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-[#1A1A1A]">
          <div className="space-y-2">
            <div className="flex items-center gap-2.5">
              <span className="text-[10px] font-black tracking-[0.25em] text-[#FF3E00] uppercase">
                // EXECUTIVE GOVERNANCE & COMPLIANCE
              </span>
              <span className="text-[10px] font-mono text-[#00FF41] bg-[#00FF41]/10 px-2 py-0.5 border border-[#00FF41]/30 uppercase font-bold">
                AUDIT_READY • A4 PDF
              </span>
            </div>
            <h2 className="text-2xl sm:text-3xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
              <FileText className="w-6 h-6 text-[#FF3E00]" />
              <span>Sumário Executivo & Plano de Mitigação</span>
            </h2>
            <p className="text-xs font-mono text-[#888] max-w-3xl leading-relaxed">
              Consolidação de risco para comitês de segurança, CISO e compliance regulatório (<strong className="text-white">OWASP A07</strong>, <strong className="text-white">LGPD</strong> e <strong className="text-white">PCI-DSS v4.0</strong>), com exportação instantânea em PDF estruturado.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              id="btn-export-pdf-summary"
              onClick={handleExportPdf}
              disabled={isGeneratingPdf}
              className="px-6 py-4 bg-[#FF3E00] hover:bg-white hover:text-black text-white font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center gap-2.5 shadow-[0_0_25px_rgba(255,62,0,0.3)] active:scale-95 disabled:opacity-50"
            >
              {pdfSuccess ? (
                <>
                  <Check className="w-4 h-4 text-[#00FF41]" />
                  <span>Relatório PDF Baixado!</span>
                </>
              ) : (
                <>
                  <FileDown className={`w-4 h-4 ${isGeneratingPdf ? 'animate-bounce' : ''}`} />
                  <span>{isGeneratingPdf ? 'Compilando Documento A4...' : 'Exportar Relatório PDF'}</span>
                </>
              )}
            </button>

            {onOpenExport && (
              <button
                onClick={onOpenExport}
                className="px-5 py-4 border border-[#333] hover:border-white bg-[#0A0A0A] hover:bg-white hover:text-black text-white font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center gap-2"
                title="Abrir modal com JSON, CSV, SARIF e Markdown"
              >
                <Download className="w-4 h-4 text-[#AAA]" />
                <span>Outros Formatos</span>
              </button>
            )}
          </div>
        </div>

        {/* Diagnostic Statement Box */}
        <div className="bg-[#0D0D0D] border border-[#222] p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <span className="text-[10px] font-black tracking-[0.2em] text-[#AAA] uppercase">
              Diagnóstico de Exposição Forense
            </span>
            <p className="text-xs font-mono text-[#DDD] leading-relaxed">
              {metrics.criticalCount > 0 ? (
                <span>
                  <strong className="text-[#FF3E00]">{metrics.criticalCount} vulnerabilidade(s) crítica(s)</strong> e <strong className="text-[#FF7A00]">{metrics.highCount} de alta severidade</strong> detectadas. Credenciais e chaves ativas encontradas em arquivos de alta criticidade requerem rotação imediata.
                </span>
              ) : (
                <span className="text-[#00FF41]">
                  Repositório sem vulnerabilidades críticas ativas. Conformidade com filtros de segredos validada em {report.scannedFilesCount} arquivos.
                </span>
              )}
            </p>
          </div>
          <div className="flex items-center gap-4 shrink-0 font-mono text-xs text-[#888]">
            <div className="text-right">
              <div className="text-white font-bold">{report.findings.length} Achados</div>
              <div className="text-[10px]">{report.scannedFilesCount} Arquivos</div>
            </div>
            <div className="text-right border-l border-[#222] pl-4">
              <div className="text-[#FF3E00] font-bold">{impactScore}/100 Impacto</div>
              <div className="text-[10px]">{metrics.securityScore}% Conforme</div>
            </div>
          </div>
        </div>

        {/* 4 Mitigation Phases Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div className="p-4 bg-[#0A0A0A] border border-[#222] space-y-2 relative overflow-hidden">
            <div className="w-1 h-full bg-[#FF3E00] absolute left-0 top-0" />
            <div className="flex items-center justify-between pl-1">
              <span className="text-[10px] font-mono font-bold text-[#FF3E00] uppercase">Fase 1 • Imediato</span>
              <span className="text-[9px] font-mono px-1.5 py-0.5 bg-[#FF3E00]/10 text-[#FF3E00] border border-[#FF3E00]/30 font-bold">0-24h</span>
            </div>
            <h4 className="text-xs font-bold text-white uppercase pl-1">Rotação de Credenciais</h4>
            <p className="text-[11px] font-mono text-[#777] leading-relaxed pl-1">
              Revogar imediatamente chaves AWS, tokens Stripe e segredos detectados em provedores de nuvem.
            </p>
          </div>

          <div className="p-4 bg-[#0A0A0A] border border-[#222] space-y-2 relative overflow-hidden">
            <div className="w-1 h-full bg-[#FF7A00] absolute left-0 top-0" />
            <div className="flex items-center justify-between pl-1">
              <span className="text-[10px] font-mono font-bold text-[#FF7A00] uppercase">Fase 2 • Curto Prazo</span>
              <span className="text-[9px] font-mono px-1.5 py-0.5 bg-[#FF7A00]/10 text-[#FF7A00] border border-[#FF7A00]/30 font-bold">1-3 dias</span>
            </div>
            <h4 className="text-xs font-bold text-white uppercase pl-1">Expurgo de Histórico Git</h4>
            <p className="text-[11px] font-mono text-[#777] leading-relaxed pl-1">
              Sanitizar commits com git-filter-repo ou BFG e assegurar que arquivos sensíveis estejam no .gitignore.
            </p>
          </div>

          <div className="p-4 bg-[#0A0A0A] border border-[#222] space-y-2 relative overflow-hidden">
            <div className="w-1 h-full bg-[#EAB308] absolute left-0 top-0" />
            <div className="flex items-center justify-between pl-1">
              <span className="text-[10px] font-mono font-bold text-[#EAB308] uppercase">Fase 3 • Estrutural</span>
              <span className="text-[9px] font-mono px-1.5 py-0.5 bg-[#EAB308]/10 text-[#EAB308] border border-[#EAB308]/30 font-bold">1 semana</span>
            </div>
            <h4 className="text-xs font-bold text-white uppercase pl-1">Vault Centralizado</h4>
            <p className="text-[11px] font-mono text-[#777] leading-relaxed pl-1">
              Migrar variáveis estáticas para AWS Secrets Manager, HashiCorp Vault ou Doppler com injeção em runtime.
            </p>
          </div>

          <div className="p-4 bg-[#0A0A0A] border border-[#222] space-y-2 relative overflow-hidden">
            <div className="w-1 h-full bg-[#3366FF] absolute left-0 top-0" />
            <div className="flex items-center justify-between pl-1">
              <span className="text-[10px] font-mono font-bold text-[#3366FF] uppercase">Fase 4 • Prevenção</span>
              <span className="text-[9px] font-mono px-1.5 py-0.5 bg-[#3366FF]/10 text-[#3366FF] border border-[#3366FF]/30 font-bold">Contínuo</span>
            </div>
            <h4 className="text-xs font-bold text-white uppercase pl-1">Quality Gate em CI/CD</h4>
            <p className="text-[11px] font-mono text-[#777] leading-relaxed pl-1">
              Bloquear merges automaticamente em GitHub Actions / GitLab CI com flag estrita --fail-on critical.
            </p>
          </div>
        </div>
      </div>

      {/* Visual Analytics & Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Donut Chart using Recharts */}
        <SeverityDonutChart 
          report={report} 
          onSelectSeverity={() => onNavigateToTab('scanner')} 
        />

        {/* Categories Bar Chart */}
        <div className="bg-[#080808] p-6 border border-[#222] lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-[11px] font-black tracking-[0.2em] text-white uppercase flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-[#00FF41]" />
                <span>Credential Categories Distribution</span>
              </h2>
              <p className="text-[10px] font-mono text-[#666] uppercase mt-0.5">Identified pattern signatures in repository</p>
            </div>
            <button
              onClick={() => onNavigateToTab('scanner')}
              className="text-[11px] font-black uppercase tracking-[0.15em] text-[#FF3E00] hover:underline"
            >
              Inspect Code &rarr;
            </button>
          </div>

          <div className="h-56 mt-4">
            {categoryData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categoryData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                  <XAxis 
                    dataKey="name" 
                    tick={{ fontSize: 10, fill: '#666', fontFamily: 'monospace' }} 
                    angle={-15} 
                    textAnchor="end" 
                    interval={0}
                  />
                  <YAxis tick={{ fontSize: 10, fill: '#666', fontFamily: 'monospace' }} allowDecimals={false} />
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#111', borderColor: '#333', color: '#fff', fontSize: '11px', fontFamily: 'monospace' }}
                    formatter={(val) => [`${val} ocorrência(s)`, 'Detecções']}
                  />
                  <Bar dataKey="count" fill="#FF3E00" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-[#666] font-mono text-xs">
                NO_CATEGORIZED_VULNERABILITIES
              </div>
            )}
          </div>
        </div>
      </div>

      {/* D3 Vulnerability Density Heatmap */}
      <VulnerabilityHeatmap
        findings={findings}
        onSelectFinding={onSelectFinding}
        onNavigateToScanner={() => onNavigateToTab('scanner')}
      />

      {/* D3 30-Day Historical Vulnerability Trend Line Chart */}
      <VulnerabilityTrendChart report={report} />

      {/* Critical Findings Quick Feed & Real-Time Audit Log */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Critical Alerts Feed */}
        <div className="bg-[#080808] p-6 border border-[#222] flex flex-col justify-between">
          <div>
            <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
              <div>
                <h2 className="text-[11px] font-black tracking-[0.2em] text-white uppercase flex items-center gap-2">
                  <AlertOctagon className="w-4 h-4 text-[#FF3E00]" />
                  <span>Immediate Threat Vectors</span>
                </h2>
                <p className="text-[10px] font-mono text-[#666] uppercase mt-0.5">High-entropy secrets requiring immediate revocation</p>
              </div>
              <div className="flex items-center gap-2">
                {onOpenGlossary && (
                  <button
                    type="button"
                    onClick={() => onOpenGlossary()}
                    className="text-[10px] font-mono px-2.5 py-1 bg-[#111] hover:bg-[#200500] text-[#AAA] hover:text-white border border-[#333] hover:border-[#FF3E00] flex items-center gap-1.5 transition-colors cursor-pointer"
                    title="Consultar Glossário de Segurança"
                  >
                    <BookOpen className="w-3 h-3 text-[#FF3E00]" />
                    <span className="hidden sm:inline">Glossário</span>
                  </button>
                )}
                <span className="text-[10px] font-mono font-bold text-[#FF3E00] bg-[#220700] px-2.5 py-1 border border-[#FF3E00]/40">
                  {findings.length} TOTAL
                </span>
              </div>
            </div>

            <div className="space-y-3">
              {criticalFindings.length === 0 ? (
                <div className="p-8 text-center bg-[#050505] border border-dashed border-[#222]">
                  <CheckCircle2 className="w-8 h-8 text-[#00FF41] mx-auto mb-2" />
                  <p className="text-xs font-mono text-[#AAA]">Nenhum alerta crítico ativo no repositório.</p>
                  <p className="text-[10px] font-mono text-[#666] mt-1">STATUS: ALL CLEAR</p>
                </div>
              ) : (
                criticalFindings.map((finding) => (
                  <div
                    key={finding.id}
                    onClick={() => onSelectFinding(finding)}
                    className="p-4 bg-[#0A0A0A] border border-[#222] hover:border-[#FF3E00] cursor-pointer transition-all group"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`text-[10px] font-mono font-black px-2 py-0.5 uppercase tracking-wider ${
                          finding.severity === 'CRITICAL' 
                            ? 'bg-[#FF3E00] text-white' 
                            : 'bg-[#FF7A00] text-black font-bold'
                        }`}>
                          {finding.severity}
                        </span>
                        <span className="text-xs font-bold text-white group-hover:text-[#FF3E00] transition-colors">
                          {finding.ruleName}
                        </span>
                        
                        {/* Context-aware Glossary Tooltip */}
                        <div onClick={(e) => e.stopPropagation()}>
                          <SecurityGlossaryTooltip 
                            finding={finding} 
                            onOpenFullGlossary={onOpenGlossary}
                          />
                        </div>
                      </div>
                      <span className="text-[11px] text-[#888] font-mono">
                        {finding.file.split('/').pop()}:{finding.line}
                      </span>
                    </div>

                    <div className="mt-2.5 bg-[#000] text-zinc-300 px-3 py-2 border border-[#1A1A1A] text-xs font-mono flex items-center justify-between overflow-x-auto">
                      <span className="text-[#FF3E00] font-bold truncate">{finding.maskedSecret}</span>
                      <span className="text-[10px] text-[#888] shrink-0 ml-3">H={finding.entropy}</span>
                    </div>

                    <p className="mt-2 text-[11px] font-mono text-[#AAA] line-clamp-1">
                      &gt; REMEDIATION: {finding.remediation}
                    </p>
                  </div>
                ))
              )}
            </div>
          </div>

          {findings.length > 5 && (
            <button
              onClick={() => onNavigateToTab('scanner')}
              className="mt-4 w-full py-3 text-center text-xs font-black uppercase tracking-[0.2em] text-white bg-[#111] hover:bg-white hover:text-black border border-[#222] transition-colors"
            >
              Exibir todos os {findings.length} achados &rarr;
            </button>
          )}
        </div>

        {/* Real-time Logs & Events - Live Terminal Stream */}
        <div className="bg-[#080808] border border-[#222] p-6 flex flex-col h-full">
          <div className="flex items-center justify-between pb-3 border-b border-[#222]">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-[#00FF41] animate-pulse" />
              <h2 className="text-[11px] font-black tracking-[0.2em] text-white uppercase">Live Event Stream</h2>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-[#FF3E00]"></div>
              <div className="w-2 h-2 rounded-full bg-[#00FF41]"></div>
              <span className="text-[10px] font-mono text-[#666] uppercase">REALTIME</span>
            </div>
          </div>

          {/* Console Stream */}
          <div className="mt-4 flex-1 overflow-y-auto font-mono text-xs space-y-3 pr-1 max-h-[380px] select-text">
            {auditLogs.length === 0 ? (
              <div className="text-[#666] py-12 text-center font-mono italic text-xs">
                [WAITING_FOR_SCAN_EXECUTION]
              </div>
            ) : (
              auditLogs.map((log) => {
                const isAlert = log.type === 'SECRET_DETECTED';
                const isIgnored = log.type === 'DEP_IGNORED';
                return (
                  <div 
                    key={log.id} 
                    className="flex gap-3 border-b border-[#141414] pb-2 text-[11px] leading-relaxed"
                  >
                    <span className="text-[#444] shrink-0">[{log.timestamp}]</span>
                    <span className={`shrink-0 font-bold ${
                      isAlert ? 'text-[#FF3E00]' : isIgnored ? 'text-[#00FF41]' : 'text-[#3366FF]'
                    }`}>
                      {isAlert ? 'ALERT' : isIgnored ? 'PASS' : 'INFO'}
                    </span>
                    <span className="text-[#AAA] break-all">{log.message}</span>
                  </div>
                );
              })
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-[#1A1A1A] flex items-center justify-between text-[10px] font-mono text-[#666]">
            <span>SYSTEM_AUDIT_LOG_STREAM</span>
            <span>{auditLogs.length} EVENTS RECORDED</span>
          </div>
        </div>
      </div>
    </div>
  );
};
