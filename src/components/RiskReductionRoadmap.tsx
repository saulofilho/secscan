import React, { useState, useMemo } from 'react';
import {
  ResponsiveContainer,
  ComposedChart,
  Area,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ReferenceLine,
  BarChart,
  Bar,
  Cell
} from 'recharts';
import {
  TrendingDown,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Flame,
  KeyRound,
  RotateCcw,
  Sparkles,
  ExternalLink,
  Code2,
  Copy,
  Check,
  Clock,
  Sliders,
  ChevronRight,
  Download,
  Layers,
  FileCode,
  Lock,
  Zap,
  Target
} from 'lucide-react';
import { ScanReport, ScanFinding, SeverityLevel } from '../types';
import { calculateCumulativeWorkspaceRiskScore } from '../lib/scanner';

interface RiskReductionRoadmapProps {
  report: ScanReport;
  qualityGateLimit?: number;
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToFinding?: (findingId: string) => void;
  onNavigateToScanner?: () => void;
  onNavigateToFile?: (filePath: string) => void;
  onNavigateToQualityGate?: () => void;
}

const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

const SEVERITY_BADGE_STYLE: Record<SeverityLevel, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'bg-[#FF3E00]/15', text: 'text-[#FF3E00]', border: 'border-[#FF3E00]/40' },
  HIGH: { bg: 'bg-orange-500/15', text: 'text-orange-400', border: 'border-orange-500/40' },
  MEDIUM: { bg: 'bg-amber-500/15', text: 'text-amber-300', border: 'border-amber-500/40' },
  LOW: { bg: 'bg-sky-500/15', text: 'text-sky-300', border: 'border-sky-500/40' },
  INFO: { bg: 'bg-zinc-800', text: 'text-zinc-400', border: 'border-zinc-700' },
};

export interface RoadmapStep {
  stepIndex: number;
  id: string;
  stageName: string;
  stageSubtitle: string;
  finding?: ScanFinding;
  riskScore: number;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'MINIMAL';
  scoreReduction: number;
  cumulativeReduction: number;
  percentReduction: number;
  passesQualityGate: boolean;
  activeFindingsRemaining: number;
  estimatedEffortMinutes: number;
  remediationTitle: string;
  remediationSnippetBefore?: string;
  remediationSnippetAfter?: string;
  remediationAction: string;
}

export const RiskReductionRoadmap: React.FC<RiskReductionRoadmapProps> = ({
  report,
  qualityGateLimit = 50,
  onSelectFinding,
  onNavigateToFinding,
  onNavigateToScanner,
  onNavigateToFile,
  onNavigateToQualityGate,
}) => {
  const [activeStepIndex, setActiveStepIndex] = useState<number>(3);
  const [chartViewMode, setChartViewMode] = useState<'AREA' | 'BAR'>('AREA');
  const [appliedSteps, setAppliedSteps] = useState<Record<number, boolean>>({
    1: true,
    2: true,
    3: true,
  });
  const [copiedCodeKey, setCopiedCodeKey] = useState<string | null>(null);

  // 1. Identify Top-3 Highest Severity Findings (same order as Mitigation Engine)
  const topFindings = useMemo(() => {
    const activeFindings = (report.findings || []).filter((f) => !f.isFalsePositive);
    return [...activeFindings]
      .sort((a, b) => {
        const sevDiff = (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0);
        if (sevDiff !== 0) return sevDiff;
        const scoreB = b.weightedScore || b.riskScore || 0;
        const scoreA = a.weightedScore || a.riskScore || 0;
        return scoreB - scoreA;
      })
      .slice(0, 3);
  }, [report.findings]);

  // 2. Compute the exact sequential projection steps using calculateCumulativeWorkspaceRiskScore
  const roadmapSteps = useMemo<RoadmapStep[]>(() => {
    const activeFindings = (report.findings || []).filter((f) => !f.isFalsePositive);
    
    // Baseline Counts
    let currentCounts = {
      criticalCount: activeFindings.filter((f) => f.severity === 'CRITICAL').length,
      highCount: activeFindings.filter((f) => f.severity === 'HIGH').length,
      mediumCount: activeFindings.filter((f) => f.severity === 'MEDIUM').length,
      lowCount: activeFindings.filter((f) => f.severity === 'LOW').length,
      infoCount: activeFindings.filter((f) => f.severity === 'INFO').length,
    };

    const baselineCalc = calculateCumulativeWorkspaceRiskScore(currentCounts);
    const baselineScore = baselineCalc.riskScore;

    const steps: RoadmapStep[] = [
      {
        stepIndex: 0,
        id: 'step-0-baseline',
        stageName: 'Baseline Atual',
        stageSubtitle: 'Estado atual sem mitigações',
        riskScore: baselineScore,
        riskLevel: baselineCalc.riskLevel,
        scoreReduction: 0,
        cumulativeReduction: 0,
        percentReduction: 0,
        passesQualityGate: baselineScore <= qualityGateLimit,
        activeFindingsRemaining: activeFindings.length,
        estimatedEffortMinutes: 0,
        remediationTitle: 'Ponto de Partida',
        remediationAction: 'Executar análise estática e priorizar vulnerabilidades críticas.',
      },
    ];

    let previousScore = baselineScore;
    let remainingFindingsCount = activeFindings.length;

    topFindings.forEach((finding, idx) => {
      const stepNumber = idx + 1;
      
      // Decrement the severity count for this finding
      if (finding.severity === 'CRITICAL') currentCounts.criticalCount = Math.max(0, currentCounts.criticalCount - 1);
      else if (finding.severity === 'HIGH') currentCounts.highCount = Math.max(0, currentCounts.highCount - 1);
      else if (finding.severity === 'MEDIUM') currentCounts.mediumCount = Math.max(0, currentCounts.mediumCount - 1);
      else if (finding.severity === 'LOW') currentCounts.lowCount = Math.max(0, currentCounts.lowCount - 1);
      else if (finding.severity === 'INFO') currentCounts.infoCount = Math.max(0, (currentCounts.infoCount || 0) - 1);

      const stepCalc = calculateCumulativeWorkspaceRiskScore(currentCounts);
      const newScore = stepCalc.riskScore;
      const scoreReduction = Math.max(0, Number((previousScore - newScore).toFixed(1)));
      const cumulativeReduction = Math.max(0, Number((baselineScore - newScore).toFixed(1)));
      const percentReduction = baselineScore > 0 ? Number(((cumulativeReduction / baselineScore) * 100).toFixed(1)) : 0;
      remainingFindingsCount = Math.max(0, remainingFindingsCount - 1);

      // Construct realistic effort & code snippets
      const effortMinutes = finding.severity === 'CRITICAL' ? 20 : finding.severity === 'HIGH' ? 15 : 10;
      const cleanRuleKey = finding.ruleName.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase();

      steps.push({
        stepIndex: stepNumber,
        id: `step-${stepNumber}-${finding.id}`,
        stageName: `Remediação #${stepNumber}`,
        stageSubtitle: `${finding.ruleName} (${finding.severity})`,
        finding,
        riskScore: newScore,
        riskLevel: stepCalc.riskLevel,
        scoreReduction,
        cumulativeReduction,
        percentReduction,
        passesQualityGate: newScore <= qualityGateLimit,
        activeFindingsRemaining: remainingFindingsCount,
        estimatedEffortMinutes: effortMinutes,
        remediationTitle: finding.ruleName,
        remediationSnippetBefore: finding.snippet || `const key = "${finding.maskedSecret}";`,
        remediationSnippetAfter: `// Carregar de variáveis de ambiente seguras (ex: Secret Manager / .env)\nconst key = process.env.${cleanRuleKey};\nif (!key) {\n  throw new Error('Configuração obrigatória não encontrada: ${cleanRuleKey}');\n}`,
        remediationAction: finding.remediation || 'Remover credencial exposta e utilizar Secret Manager.',
      });

      previousScore = newScore;
    });

    return steps;
  }, [report.findings, topFindings, qualityGateLimit]);

  // 3. Current active simulated score based on user-toggled checkboxes
  const simulatedProjection = useMemo(() => {
    const activeFindings = (report.findings || []).filter((f) => !f.isFalsePositive);
    let counts = {
      criticalCount: activeFindings.filter((f) => f.severity === 'CRITICAL').length,
      highCount: activeFindings.filter((f) => f.severity === 'HIGH').length,
      mediumCount: activeFindings.filter((f) => f.severity === 'MEDIUM').length,
      lowCount: activeFindings.filter((f) => f.severity === 'LOW').length,
      infoCount: activeFindings.filter((f) => f.severity === 'INFO').length,
    };

    const baselineScore = calculateCumulativeWorkspaceRiskScore(counts).riskScore;

    // Apply only checked steps
    topFindings.forEach((finding, idx) => {
      const stepNum = idx + 1;
      if (appliedSteps[stepNum]) {
        if (finding.severity === 'CRITICAL') counts.criticalCount = Math.max(0, counts.criticalCount - 1);
        else if (finding.severity === 'HIGH') counts.highCount = Math.max(0, counts.highCount - 1);
        else if (finding.severity === 'MEDIUM') counts.mediumCount = Math.max(0, counts.mediumCount - 1);
        else if (finding.severity === 'LOW') counts.lowCount = Math.max(0, counts.lowCount - 1);
        else if (finding.severity === 'INFO') counts.infoCount = Math.max(0, (counts.infoCount || 0) - 1);
      }
    });

    const simCalc = calculateCumulativeWorkspaceRiskScore(counts);
    const simScore = simCalc.riskScore;
    const diff = Math.max(0, Number((baselineScore - simScore).toFixed(1)));
    const percent = baselineScore > 0 ? Number(((diff / baselineScore) * 100).toFixed(1)) : 0;
    const appliedCount = Object.values(appliedSteps).filter(Boolean).length;

    return {
      baselineScore,
      projectedScore: simScore,
      projectedLevel: simCalc.riskLevel,
      pointsReduced: diff,
      percentReduced: percent,
      passesGate: simScore <= qualityGateLimit,
      appliedCount,
    };
  }, [report.findings, topFindings, appliedSteps, qualityGateLimit]);

  // 4. Data formatted for Recharts
  const chartData = useMemo(() => {
    return roadmapSteps.map((step) => ({
      name: step.stageName,
      shortName: step.stepIndex === 0 ? 'Baseline' : `Top #${step.stepIndex}`,
      fullName: step.stageSubtitle,
      riskScore: step.riskScore,
      qualityGate: qualityGateLimit,
      pointsDeducted: step.scoreReduction,
      cumulativeDrop: step.cumulativeReduction,
      percentReduction: step.percentReduction,
      passesGate: step.passesQualityGate,
      stepIndex: step.stepIndex,
      finding: step.finding,
      remediationAction: step.remediationAction,
    }));
  }, [roadmapSteps, qualityGateLimit]);

  const baselineStep = roadmapSteps[0];
  const finalFullStep = roadmapSteps[roadmapSteps.length - 1];
  const currentInspectStep = roadmapSteps.find((s) => s.stepIndex === activeStepIndex) || finalFullStep;

  const handleCopyCode = (code: string, key: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCodeKey(key);
    setTimeout(() => setCopiedCodeKey(null), 2000);
  };

  const toggleAllSteps = (enable: boolean) => {
    setAppliedSteps({
      1: enable,
      2: enable,
      3: enable,
    });
  };

  if (topFindings.length === 0) {
    return (
      <div 
        id="risk-reduction-roadmap-panel"
        className="bg-[#080808] border border-[#222] p-6 lg:p-8 space-y-4"
      >
        <div className="flex items-center gap-2 text-[#00FF41]">
          <ShieldCheck className="w-5 h-5" />
          <h3 className="text-sm font-black uppercase tracking-wider font-mono">
            Roteiro de Redução de Risco // Nenhum Achado Crítico Ativo
          </h3>
        </div>
        <p className="text-xs font-mono text-[#888]">
          Não há vulnerabilidades críticas ou de alta severidade pendentes de mitigação no workspace. O Risk Score atual é mínimo e atende a todos os Quality Gates.
        </p>
      </div>
    );
  }

  return (
    <div
      id="risk-reduction-roadmap-panel"
      className="bg-[#080808] border-2 border-[#2A2A2A] p-6 lg:p-8 space-y-6 relative overflow-hidden transition-all shadow-2xl"
    >
      {/* Background Cyber Accent Glow */}
      <div className="absolute top-0 right-0 w-80 h-80 bg-gradient-to-bl from-[#FF3E00]/10 via-[#3366FF]/5 to-transparent rounded-bl-full pointer-events-none" />

      {/* Header & Badges */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-[#1F1F1F] relative z-10">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono text-[#FF3E00] bg-[#FF3E00]/10 px-2.5 py-0.5 border border-[#FF3E00]/40 uppercase font-black tracking-widest flex items-center gap-1.5">
              <TrendingDown className="w-3.5 h-3.5" />
              PROJEÇÃO APSEC // RISK REDUCTION ROADMAP
            </span>
            <span className="text-[10px] font-mono text-[#00F0FF] bg-[#00F0FF]/10 px-2 py-0.5 border border-[#00F0FF]/30 uppercase font-bold">
              TOP-3 VULNERABILIDADES
            </span>
            {simulatedProjection.passesGate ? (
              <span className="text-[10px] font-mono text-[#00FF41] bg-[#00FF41]/15 px-2 py-0.5 border border-[#00FF41]/40 uppercase font-bold flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" />
                QUALITY GATE: ATINGÍVEL
              </span>
            ) : (
              <span className="text-[10px] font-mono text-[#FF3E00] bg-[#FF3E00]/15 px-2 py-0.5 border border-[#FF3E00]/40 uppercase font-bold flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                GATE EXIGE MITIGAÇÃO ADICIONAL
              </span>
            )}
          </div>

          <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
            <Target className="w-6 h-6 text-[#FF3E00]" />
            <span>Roteiro de Redução de Risco (Risk Reduction Roadmap)</span>
          </h2>
          <p className="text-xs font-mono text-[#888] max-w-4xl leading-relaxed">
            Projeção dinâmica da redução do <strong>Cumulative Workspace Risk Score</strong> conforme as recomendações de mitigação das <strong>Top-3 vulnerabilidades mais críticas</strong> são implementadas. Simule cada etapa para visualizar o impacto imediato na conformidade dos Quality Gates de CI/CD.
          </p>
        </div>

        {/* View mode toggle & simulation shortcuts */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <div className="flex bg-[#111] border border-[#2A2A2A] p-0.5">
            <button
              type="button"
              onClick={() => setChartViewMode('AREA')}
              className={`px-3 py-1.5 text-xs font-mono font-bold uppercase tracking-wider transition-colors cursor-pointer ${
                chartViewMode === 'AREA' ? 'bg-[#FF3E00] text-white' : 'text-[#888] hover:text-white'
              }`}
              title="Exibir trajetória em gráfico de área contínua"
            >
              Curva de Risco
            </button>
            <button
              type="button"
              onClick={() => setChartViewMode('BAR')}
              className={`px-3 py-1.5 text-xs font-mono font-bold uppercase tracking-wider transition-colors cursor-pointer ${
                chartViewMode === 'BAR' ? 'bg-[#FF3E00] text-white' : 'text-[#888] hover:text-white'
              }`}
              title="Exibir comparação de impacto por etapa em barras"
            >
              Comparativo
            </button>
          </div>

          <button
            type="button"
            onClick={() => toggleAllSteps(true)}
            className="px-3 py-1.5 bg-[#141414] hover:bg-[#222] border border-[#333] text-white text-xs font-mono uppercase tracking-wider transition-all flex items-center gap-1.5 cursor-pointer"
            title="Simular a aplicação das 3 mitigações simultaneamente"
          >
            <Sparkles className="w-3.5 h-3.5 text-[#00FF41]" />
            <span>Simular Todas (3/3)</span>
          </button>

          <button
            type="button"
            onClick={() => toggleAllSteps(false)}
            className="px-2.5 py-1.5 bg-[#141414] hover:bg-[#222] border border-[#333] text-[#888] hover:text-white text-xs font-mono uppercase transition-all cursor-pointer"
            title="Restaurar visualização para o Baseline atual"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 4 Executive Roadmap KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Baseline */}
        <div className="p-4 bg-[#0D0D0D] border border-[#222] relative overflow-hidden">
          <div className="flex items-center justify-between text-[11px] font-mono text-[#888] uppercase">
            <span>Score Atual (Baseline)</span>
            <ShieldAlert className="w-3.5 h-3.5 text-[#FF3E00]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-white">
              {baselineStep.riskScore}
            </span>
            <span className="text-xs font-mono text-[#666]">/ 100</span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[10px] font-mono pt-2 border-t border-[#1C1C1C]">
            <span className="text-rose-400 font-bold uppercase">{baselineStep.riskLevel}</span>
            <span className="text-[#666]">{baselineStep.activeFindingsRemaining} achados ativos</span>
          </div>
        </div>

        {/* Metric 2: Total Projected Drop */}
        <div className="p-4 bg-[#0D0D0D] border border-[#222] relative overflow-hidden">
          <div className="flex items-center justify-between text-[11px] font-mono text-[#888] uppercase">
            <span>Redução Projetada Total</span>
            <TrendingDown className="w-3.5 h-3.5 text-[#00FF41]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-[#00FF41]">
              -{finalFullStep.cumulativeReduction}
            </span>
            <span className="text-xs font-mono text-[#00FF41]">
              pts ({finalFullStep.percentReduction}%)
            </span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[10px] font-mono pt-2 border-t border-[#1C1C1C]">
            <span className="text-[#AAA]">3 correções aplicadas</span>
            <span className="text-[#00FF41] font-bold">↓ {finalFullStep.percentReduction}% de queda</span>
          </div>
        </div>

        {/* Metric 3: Final Projected Score */}
        <div className="p-4 bg-[#0D0D0D] border border-[#222] relative overflow-hidden">
          <div className="flex items-center justify-between text-[11px] font-mono text-[#888] uppercase">
            <span>Score Final Estimado</span>
            <Target className="w-3.5 h-3.5 text-[#00F0FF]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-white">
              {finalFullStep.riskScore}
            </span>
            <span className="text-xs font-mono text-[#666]">/ 100</span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[10px] font-mono pt-2 border-t border-[#1C1C1C]">
            <span className="text-emerald-400 font-bold uppercase">{finalFullStep.riskLevel}</span>
            <span className="text-[#666]">Meta atingível</span>
          </div>
        </div>

        {/* Metric 4: Quality Gate Compliance */}
        <div 
          onClick={onNavigateToQualityGate}
          className="p-4 bg-[#0D0D0D] border border-[#222] hover:border-[#3366FF] transition-all cursor-pointer relative overflow-hidden group"
          title="Clique para inspecionar os Quality Gates de CI/CD"
        >
          <div className="flex items-center justify-between text-[11px] font-mono text-[#888] uppercase">
            <span>Quality Gate (CI/CD)</span>
            <ShieldCheck className="w-3.5 h-3.5 text-[#3366FF]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-xl sm:text-2xl font-black font-mono ${
              finalFullStep.passesQualityGate ? 'text-[#00FF41]' : 'text-amber-400'
            }`}>
              {finalFullStep.passesQualityGate ? 'APROVADO' : 'EXCEDIDO'}
            </span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[10px] font-mono pt-2 border-t border-[#1C1C1C]">
            <span className="text-[#888]">Limite: {qualityGateLimit} pts</span>
            <span className="text-[#3366FF] group-hover:underline flex items-center gap-0.5">
              Detalhes &rarr;
            </span>
          </div>
        </div>
      </div>

      {/* Main Chart Plot Section */}
      <div className="bg-[#0D0D0D] border border-[#222] p-5 lg:p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1A1A1A]">
          <div>
            <h3 className="text-sm font-black font-mono uppercase text-white tracking-wider flex items-center gap-2">
              <TrendingDown className="w-4 h-4 text-[#FF3E00]" />
              <span>Trajetória da Pontuação de Risco (Risk Score Trajectory)</span>
            </h3>
            <span className="text-[11px] font-mono text-[#777]">
              Evolução passo-a-passo: do baseline atual à mitigação dos top 3 achados
            </span>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono">
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-0.5 bg-[#FF3E00]" />
              <span className="text-zinc-300">Risk Score Projetado</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-0.5 bg-amber-400 border-dashed" />
              <span className="text-amber-400">Quality Gate ({qualityGateLimit})</span>
            </div>
          </div>
        </div>

        {/* Recharts Container */}
        <div className="h-[280px] w-full pt-2">
          <ResponsiveContainer width="100%" height="100%">
            {chartViewMode === 'AREA' ? (
              <ComposedChart data={chartData} margin={{ top: 20, right: 30, left: -15, bottom: 10 }}>
                <defs>
                  <linearGradient id="roadmapRiskGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF3E00" stopOpacity={0.4} />
                    <stop offset="60%" stopColor="#FF3E00" stopOpacity={0.1} />
                    <stop offset="95%" stopColor="#00FF41" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#1F1F1F" strokeDasharray="3 3" vertical={false} />
                <XAxis 
                  dataKey="shortName" 
                  stroke="#666" 
                  tick={{ fill: '#AAA', fontSize: 11, fontFamily: 'monospace' }}
                  tickLine={{ stroke: '#333' }}
                />
                <YAxis 
                  domain={[0, 100]} 
                  stroke="#666" 
                  tick={{ fill: '#888', fontSize: 10, fontFamily: 'monospace' }}
                  tickLine={{ stroke: '#333' }}
                />
                <RechartsTooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      return (
                        <div className="bg-[#050505] border border-[#333] p-3 shadow-2xl text-xs font-mono space-y-1.5 max-w-xs">
                          <div className="flex items-center justify-between gap-2 border-b border-[#222] pb-1">
                            <span className="font-bold text-white uppercase">{data.name}</span>
                            <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                              data.riskScore <= qualityGateLimit 
                                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' 
                                : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            }`}>
                              {data.riskScore <= qualityGateLimit ? 'PASS' : 'FAIL'}
                            </span>
                          </div>
                          <div className="text-[#AAA] text-[11px]">{data.fullName}</div>
                          <div className="flex items-center justify-between text-xs pt-1">
                            <span className="text-[#888]">Risk Score:</span>
                            <span className="font-bold text-[#FF3E00] text-sm">{data.riskScore}/100</span>
                          </div>
                          {data.pointsDeducted > 0 && (
                            <div className="flex items-center justify-between text-[11px] text-[#00FF41]">
                              <span>Queda nesta etapa:</span>
                              <span className="font-bold">-{data.pointsDeducted} pts</span>
                            </div>
                          )}
                          {data.cumulativeDrop > 0 && (
                            <div className="flex items-center justify-between text-[11px] text-[#00F0FF]">
                              <span>Queda acumulada:</span>
                              <span className="font-bold">-{data.cumulativeDrop} pts (-{data.percentReduction}%)</span>
                            </div>
                          )}
                          {data.remediationAction && (
                            <p className="text-[10px] text-zinc-400 pt-1 border-t border-[#222] italic line-clamp-2">
                              {data.remediationAction}
                            </p>
                          )}
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <ReferenceLine 
                  y={qualityGateLimit} 
                  stroke="#F59E0B" 
                  strokeDasharray="4 4" 
                  label={{
                    value: `Quality Gate Limit (${qualityGateLimit})`,
                    position: 'insideTopRight',
                    fill: '#F59E0B',
                    fontSize: 10,
                    fontFamily: 'monospace'
                  }}
                />
                <Area 
                  type="monotone" 
                  dataKey="riskScore" 
                  stroke="#FF3E00" 
                  strokeWidth={3} 
                  fill="url(#roadmapRiskGradient)"
                  activeDot={{ r: 6, fill: '#00FF41', stroke: '#000', strokeWidth: 2 }}
                />
                <Line 
                  type="monotone" 
                  dataKey="riskScore" 
                  stroke="#FF3E00" 
                  strokeWidth={3}
                  dot={{ r: 5, fill: '#111', stroke: '#FF3E00', strokeWidth: 2 }}
                />
              </ComposedChart>
            ) : (
              <BarChart data={chartData} margin={{ top: 20, right: 30, left: -15, bottom: 10 }}>
                <CartesianGrid stroke="#1F1F1F" strokeDasharray="3 3" vertical={false} />
                <XAxis 
                  dataKey="shortName" 
                  stroke="#666" 
                  tick={{ fill: '#AAA', fontSize: 11, fontFamily: 'monospace' }}
                  tickLine={{ stroke: '#333' }}
                />
                <YAxis 
                  domain={[0, 100]} 
                  stroke="#666" 
                  tick={{ fill: '#888', fontSize: 10, fontFamily: 'monospace' }}
                  tickLine={{ stroke: '#333' }}
                />
                <RechartsTooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      return (
                        <div className="bg-[#050505] border border-[#333] p-3 shadow-2xl text-xs font-mono space-y-1.5 max-w-xs">
                          <div className="font-bold text-white uppercase">{data.name}</div>
                          <div className="text-zinc-400">{data.fullName}</div>
                          <div className="flex items-center justify-between text-xs pt-1">
                            <span className="text-[#888]">Risk Score:</span>
                            <span className="font-bold text-[#FF3E00]">{data.riskScore}/100</span>
                          </div>
                          {data.cumulativeDrop > 0 && (
                            <div className="text-[11px] text-[#00FF41] font-bold">
                              Queda Acumulada: -{data.cumulativeDrop} pts (-{data.percentReduction}%)
                            </div>
                          )}
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <ReferenceLine 
                  y={qualityGateLimit} 
                  stroke="#F59E0B" 
                  strokeDasharray="4 4" 
                  label={{
                    value: `Quality Gate (${qualityGateLimit})`,
                    position: 'insideTopRight',
                    fill: '#F59E0B',
                    fontSize: 10,
                    fontFamily: 'monospace'
                  }}
                />
                <Bar dataKey="riskScore" radius={[4, 4, 0, 0]}>
                  {chartData.map((entry, index) => {
                    const color = 
                      entry.riskScore > qualityGateLimit 
                        ? '#FF3E00' 
                        : entry.riskScore > 30 
                        ? '#3366FF' 
                        : '#00FF41';
                    return <Cell key={`cell-${index}`} fill={color} />;
                  })}
                </Bar>
              </BarChart>
            )}
          </ResponsiveContainer>
        </div>

        {/* Milestone Stage Selector Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 pt-2 border-t border-[#1C1C1C]">
          {roadmapSteps.map((step) => {
            const isSelected = activeStepIndex === step.stepIndex;
            return (
              <button
                key={step.id}
                type="button"
                onClick={() => setActiveStepIndex(step.stepIndex)}
                className={`p-3 text-left border transition-all cursor-pointer relative ${
                  isSelected
                    ? 'bg-[#141414] border-[#FF3E00] shadow-[0_0_12px_rgba(255,62,0,0.2)]'
                    : 'bg-[#0A0A0A] border-[#1C1C1C] hover:border-[#333]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-[#777]">
                    {step.stepIndex === 0 ? 'Ponto Inicial' : `Etapa 0${step.stepIndex}`}
                  </span>
                  <span className={`text-[10px] font-mono font-bold ${
                    step.riskScore <= qualityGateLimit ? 'text-[#00FF41]' : 'text-[#FF3E00]'
                  }`}>
                    {step.riskScore} pts
                  </span>
                </div>
                <div className="font-bold text-xs text-white truncate mt-1">
                  {step.stageName}
                </div>
                <div className="text-[10px] font-mono text-[#AAA] truncate mt-0.5">
                  {step.stepIndex === 0 ? 'Baseline' : `-${step.scoreReduction} pts (${step.finding?.severity})`}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Interactive Top-3 Remediation Steps List */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-black font-mono uppercase text-white tracking-wider flex items-center gap-2">
              <Layers className="w-4 h-4 text-[#00F0FF]" />
              <span>Ações do Roteiro & Simulação de Remediação (Top-3)</span>
            </h3>
            <span className="text-[11px] font-mono text-[#777]">
              Marque ou desmarque cada correção para simular o resultado em tempo real
            </span>
          </div>

          <div className="text-[11px] font-mono text-[#AAA] flex items-center gap-2">
            <span>Status simulado:</span>
            <span className="font-bold text-[#00FF41]">
              {simulatedProjection.appliedCount} de 3 correções marcadas (-{simulatedProjection.pointsReduced} pts)
            </span>
          </div>
        </div>

        {/* Steps Grid */}
        <div className="grid grid-cols-1 gap-3">
          {topFindings.map((finding, idx) => {
            const stepNum = idx + 1;
            const isApplied = appliedSteps[stepNum] ?? true;
            const stepData = roadmapSteps.find((s) => s.stepIndex === stepNum);
            const isInspecting = activeStepIndex === stepNum;

            return (
              <div
                key={finding.id}
                className={`p-4 sm:p-5 border transition-all ${
                  isApplied
                    ? 'bg-[#0B0B0B] border-[#2A2A2A]'
                    : 'bg-[#060606] border-[#181818] opacity-75'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  {/* Left: Checkbox + Priority Badge + Title + File */}
                  <div className="flex items-start gap-3 min-w-0 flex-1">
                    <button
                      type="button"
                      onClick={() =>
                        setAppliedSteps((prev) => ({
                          ...prev,
                          [stepNum]: !prev[stepNum],
                        }))
                      }
                      className={`mt-0.5 w-5 h-5 rounded border flex items-center justify-center transition-colors cursor-pointer shrink-0 ${
                        isApplied
                          ? 'bg-[#00FF41] border-[#00FF41] text-black font-black'
                          : 'bg-[#181818] border-[#444] text-transparent hover:border-[#666]'
                      }`}
                      title={isApplied ? 'Desmarcar da simulação' : 'Incluir na simulação'}
                    >
                      <Check className="w-3.5 h-3.5 stroke-[3]" />
                    </button>

                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[10px] font-mono font-black uppercase px-2 py-0.5 bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/30">
                          {idx === 0 ? 'P0 • BLOQUEANTE' : idx === 1 ? 'P1 • CRÍTICO' : 'P2 • ALTO'}
                        </span>
                        
                        <span className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 border ${
                          SEVERITY_BADGE_STYLE[finding.severity]?.bg || 'bg-zinc-800'
                        } ${SEVERITY_BADGE_STYLE[finding.severity]?.text || 'text-zinc-300'} ${
                          SEVERITY_BADGE_STYLE[finding.severity]?.border || 'border-zinc-700'
                        }`}>
                          {finding.severity}
                        </span>

                        <span className="text-xs font-bold text-white font-mono">
                          {finding.ruleName}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 text-[11px] font-mono text-[#888]">
                        <FileCode className="w-3 h-3 text-[#FF3E00]" />
                        <span className="text-zinc-300 hover:underline cursor-pointer truncate" onClick={() => onNavigateToFile?.(finding.file)}>
                          {finding.file}:{finding.line}
                        </span>
                        <span>•</span>
                        <span className="text-[#666]">Tempo estimado: ~{stepData?.estimatedEffortMinutes || 15} min</span>
                      </div>
                    </div>
                  </div>

                  {/* Right: Reduction Score Pill & Action Buttons */}
                  <div className="flex items-center gap-2.5 shrink-0 sm:ml-auto">
                    <div className="px-3 py-1.5 bg-[#141414] border border-[#222] text-right font-mono">
                      <span className="text-[9px] text-[#888] block uppercase">Impacto da Etapa</span>
                      <span className="text-xs font-bold text-[#00FF41]">
                        -{stepData?.scoreReduction || 15} pts
                      </span>
                    </div>

                    <button
                      type="button"
                      onClick={() => {
                        setActiveStepIndex(stepNum);
                      }}
                      className={`px-3 py-1.5 border text-xs font-mono uppercase tracking-wider transition-colors cursor-pointer ${
                        isInspecting
                          ? 'bg-[#FF3E00] text-white border-[#FF3E00]'
                          : 'bg-[#141414] hover:bg-[#222] text-[#AAA] hover:text-white border-[#333]'
                      }`}
                      title="Examinar plano detalhado de correção"
                    >
                      {isInspecting ? 'Inspecionando' : 'Detalhes'}
                    </button>

                    <button
                      type="button"
                      onClick={() => {
                        onSelectFinding?.(finding);
                        onNavigateToScanner?.();
                      }}
                      className="p-1.5 bg-[#141414] hover:bg-[#222] border border-[#333] text-[#AAA] hover:text-white transition-colors cursor-pointer"
                      title="Abrir achado completo no Scanner SAST"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Remediation Summary Snippet Preview */}
                <div className="mt-3 pt-3 border-t border-[#1C1C1C] flex flex-col md:flex-row md:items-center justify-between gap-2 text-xs font-mono text-[#AAA]">
                  <div className="flex items-center gap-2">
                    <Zap className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                    <span>
                      <strong>Recomendação:</strong> {finding.remediation || 'Remover credencial exposta e utilizar Secret Manager.'}
                    </span>
                  </div>
                  <span className="text-[10px] text-[#666] shrink-0">
                    Hash Segredo: {finding.maskedSecret}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected Step Deep Dive Card */}
      {currentInspectStep.finding && (
        <div className="bg-[#0C0C0C] border border-[#2A2A2A] p-5 lg:p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1E1E1E]">
            <div className="flex items-center gap-2.5">
              <Code2 className="w-4 h-4 text-[#FF3E00]" />
              <h4 className="text-xs font-bold text-white uppercase font-mono tracking-wider">
                Plano de Refatoração Recomendado • {currentInspectStep.stageName}: {currentInspectStep.remediationTitle}
              </h4>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  if (currentInspectStep.finding) {
                    onSelectFinding?.(currentInspectStep.finding);
                    onNavigateToScanner?.();
                  }
                }}
                className="px-3 py-1 bg-[#1A1A1A] hover:bg-[#2A2A2A] border border-[#333] text-white text-xs font-mono uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <ExternalLink className="w-3 h-3 text-[#FF3E00]" />
                <span>Ver no Scanner SAST</span>
              </button>

              <button
                type="button"
                onClick={() =>
                  handleCopyCode(
                    currentInspectStep.remediationSnippetAfter || '',
                    `step-${currentInspectStep.stepIndex}`
                  )
                }
                className="px-3 py-1 bg-[#1A1A1A] hover:bg-[#FF3E00] hover:text-white border border-[#333] text-white text-xs font-mono uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                {copiedCodeKey === `step-${currentInspectStep.stepIndex}` ? (
                  <>
                    <Check className="w-3 h-3 text-[#00FF41]" />
                    <span>Copiado!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copiar Fix Seguro</span>
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Before (Vulnerável) */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[11px] font-mono text-rose-400">
                <span className="font-bold flex items-center gap-1">
                  <ShieldAlert className="w-3 h-3" />
                  Código Vulnerável (Hardcoded Secret)
                </span>
                <span className="text-[#666]">{currentInspectStep.finding.file.split('/').pop()}</span>
              </div>
              <pre className="p-3 bg-[#060606] border border-rose-950/60 rounded text-[11px] font-mono text-rose-300 overflow-x-auto whitespace-pre leading-relaxed">
                <code>{currentInspectStep.remediationSnippetBefore}</code>
              </pre>
            </div>

            {/* After (Seguro) */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[11px] font-mono text-emerald-400">
                <span className="font-bold flex items-center gap-1">
                  <ShieldCheck className="w-3 h-3" />
                  Padrão Seguro Recomendado (Env Injection)
                </span>
                <span className="text-[#666]">Produção Seguro</span>
              </div>
              <pre className="p-3 bg-[#060606] border border-emerald-950/60 rounded text-[11px] font-mono text-emerald-300 overflow-x-auto whitespace-pre leading-relaxed">
                <code>{currentInspectStep.remediationSnippetAfter}</code>
              </pre>
            </div>
          </div>

          <div className="p-3 bg-[#111] border border-[#222] text-xs font-mono text-[#AAA] flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Lock className="w-3.5 h-3.5 text-[#00FF41] shrink-0" />
              <span>
                <strong>Instrução Adicional:</strong> Após refatorar o código, revogue a credencial no console do provedor e re-execute a varredura para atualizar as métricas.
              </span>
            </div>
            <span className="text-[#666] text-[10px] shrink-0">
              Score: {currentInspectStep.riskScore} pts (-{currentInspectStep.scoreReduction} pts)
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
