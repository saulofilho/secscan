import React, { useState, useEffect, useMemo } from 'react';
import {
  ResponsiveContainer,
  ComposedChart,
  AreaChart,
  Area,
  BarChart,
  Bar,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  ReferenceLine
} from 'recharts';
import {
  History,
  TrendingDown,
  TrendingUp,
  ShieldCheck,
  ShieldAlert,
  AlertOctagon,
  CheckCircle2,
  RotateCcw,
  ArrowUpRight,
  ArrowDownRight,
  Sliders,
  Target,
  Sparkles,
  BarChart3,
  LineChart as LineChartIcon,
  Activity,
  Calendar,
  Layers,
  Info,
  Clock,
  Timer
} from 'lucide-react';
import { ScanReport } from '../types';
import { safeGetItem, safeSetItem } from '../lib/storage';
import { 
  RecentScanRecord, 
  RECENT_SCANS_STORAGE_KEY, 
  generateBaselineRecentScans,
  getRelativeTime 
} from './RecentScansHistory';

export interface ScanHistoryChartProps {
  report: ScanReport;
  onNavigateToScanner?: () => void;
  onSelectScanIndex?: (scanIndex: number) => void;
}

export type ScanHistoryViewMode = 'AREA_TOTAL' | 'STACKED_SEVERITY' | 'TREND_TARGET';

export interface TenScanDataPoint {
  id: string;
  scanNumber: number; // 1 to 10
  scanIndex: number;
  label: string; // e.g. "Scan #1"
  shortLabel: string; // e.g. "#1"
  fullLabel: string;
  dateStr: string;
  relativeTime: string;
  timestamp: string;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  securityScore: number;
  durationMs: number;
  durationSec: number;
  durationPerFindingMs: number;
  totalFiles: number;
  deltaFromPrev: number;
  deltaFromBaseline: number;
  remediationPercent: number;
  isCurrent: boolean;
  status: 'CLEAN' | 'ALERT' | 'CRITICAL';
}

// Calculate Pearson Correlation Coefficient between two series
function calculatePearsonCorrelation(x: number[], y: number[]): number {
  const n = x.length;
  if (n < 2) return 0;
  const sumX = x.reduce((a, b) => a + b, 0);
  const sumY = y.reduce((a, b) => a + b, 0);
  const sumXY = x.reduce((acc, curr, i) => acc + curr * y[i], 0);
  const sumX2 = x.reduce((acc, curr) => acc + curr * curr, 0);
  const sumY2 = y.reduce((acc, curr) => acc + curr * curr, 0);
  const numerator = n * sumXY - sumX * sumY;
  const denominator = Math.sqrt((n * sumX2 - sumX * sumX) * (n * sumY2 - sumY * sumY));
  if (denominator === 0) return 0;
  return Number((numerator / denominator).toFixed(2));
}

export const ScanHistoryChart: React.FC<ScanHistoryChartProps> = ({
  report,
  onNavigateToScanner,
  onSelectScanIndex
}) => {
  // Load or sync 10 recent scans
  const [scans, setScans] = useState<RecentScanRecord[]>(() => {
    const saved = safeGetItem(RECENT_SCANS_STORAGE_KEY);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed.slice(0, 10);
        }
      } catch (e) {
        console.error('Failed to parse scan history in ScanHistoryChart:', e);
      }
    }
    return generateBaselineRecentScans(report);
  });

  const [viewMode, setViewMode] = useState<ScanHistoryViewMode>('AREA_TOTAL');
  const [showTargetLine, setShowTargetLine] = useState<boolean>(true);
  const [showAverageLine, setShowAverageLine] = useState<boolean>(true);
  const [showDurationLine, setShowDurationLine] = useState<boolean>(true);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);

  // Sync with localStorage or report updates
  useEffect(() => {
    if (!report) return;

    const syncFromStorage = () => {
      const saved = safeGetItem(RECENT_SCANS_STORAGE_KEY);
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          if (Array.isArray(parsed) && parsed.length > 0) {
            setScans(parsed.slice(0, 10));
            return;
          }
        } catch {
          // fallback
        }
      }
      setScans(generateBaselineRecentScans(report));
    };

    syncFromStorage();
    window.addEventListener('storage', syncFromStorage);
    return () => window.removeEventListener('storage', syncFromStorage);
  }, [report.id, report.findings.length, report.durationMs, report.timestamp]);

  // Transform 10 scans into chronological sequence (Scan #1 on left, Scan #10 on right)
  const chartData = useMemo<TenScanDataPoint[]>(() => {
    // scans in storage has index 0 as newest, index 9 as oldest.
    // Chronological order: reverse so oldest is first.
    const chronological = [...scans].reverse();

    // Ensure we have exactly up to 10 entries
    const sliced = chronological.slice(-10);
    const baselineFindings = sliced[0]?.findingsCount ?? (report.findings?.length ?? 6);

    return sliced.map((rec, idx) => {
      const scanNumber = idx + 1;
      const isCurrent = idx === sliced.length - 1;
      const prevFindings = idx > 0 ? sliced[idx - 1].findingsCount : rec.findingsCount;
      const deltaFromPrev = rec.findingsCount - prevFindings;
      const deltaFromBaseline = rec.findingsCount - baselineFindings;
      const remediationPercent = baselineFindings > 0 
        ? Math.round(((baselineFindings - rec.findingsCount) / baselineFindings) * 100)
        : 0;
      
      const durationSec = Number((rec.durationMs / 1000).toFixed(2));
      const durationPerFindingMs = rec.findingsCount > 0
        ? Math.round(rec.durationMs / rec.findingsCount)
        : rec.durationMs;

      return {
        id: rec.id,
        scanNumber,
        scanIndex: rec.scanIndex,
        label: isCurrent ? `Scan #${scanNumber} (Atual)` : `Scan #${scanNumber}`,
        shortLabel: `#${scanNumber}`,
        fullLabel: `${rec.formattedDate || rec.timestamp}`,
        dateStr: rec.formattedDate || '',
        relativeTime: rec.relativeTime || getRelativeTime(rec.timestamp),
        timestamp: rec.timestamp,
        totalFindings: rec.findingsCount,
        criticalCount: rec.criticalCount,
        highCount: rec.highCount,
        mediumCount: rec.mediumCount,
        lowCount: rec.lowCount,
        securityScore: rec.securityScore,
        durationMs: rec.durationMs,
        durationSec,
        durationPerFindingMs,
        totalFiles: rec.totalFiles,
        deltaFromPrev,
        deltaFromBaseline,
        remediationPercent,
        isCurrent,
        status: rec.status
      };
    });
  }, [scans, report.findings?.length]);

  // Overall Remediation & Duration Correlation Metrics across the 10 scans
  const remediationMetrics = useMemo(() => {
    if (chartData.length === 0) {
      return {
        baselineTotal: 0,
        currentTotal: 0,
        netDelta: 0,
        netPercent: 0,
        averageFindings: 0,
        peakFindings: 0,
        lowestFindings: 0,
        criticalRemediated: 0,
        isImproving: true,
        remediationVelocity: '0.0',
        averageDurationSec: 0,
        peakDurationSec: 0,
        lowestDurationSec: 0,
        currentDurationSec: 0,
        correlationR: 0,
        correlationLabel: 'Sem dados',
        correlationDesc: ''
      };
    }

    const baseline = chartData[0];
    const current = chartData[chartData.length - 1];
    const baselineTotal = baseline.totalFindings;
    const currentTotal = current.totalFindings;
    const netDelta = currentTotal - baselineTotal; // negative means reduction/improvement!
    const netPercent = baselineTotal > 0
      ? Math.round(((baselineTotal - currentTotal) / baselineTotal) * 100)
      : 0;

    const allTotals = chartData.map(d => d.totalFindings);
    const sumTotals = allTotals.reduce((a, b) => a + b, 0);
    const averageFindings = Number((sumTotals / chartData.length).toFixed(1));
    const peakFindings = Math.max(...allTotals);
    const lowestFindings = Math.min(...allTotals);

    // Duration analytics
    const allDurationsSec = chartData.map(d => d.durationSec);
    const sumDurations = allDurationsSec.reduce((a, b) => a + b, 0);
    const averageDurationSec = Number((sumDurations / chartData.length).toFixed(2));
    const peakDurationSec = Math.max(...allDurationsSec);
    const lowestDurationSec = Math.min(...allDurationsSec);
    const currentDurationSec = current.durationSec;

    // Pearson correlation between findings and scan duration
    const correlationR = calculatePearsonCorrelation(allTotals, allDurationsSec);
    let correlationLabel = 'Neutro';
    let correlationDesc = '';
    if (correlationR >= 0.5) {
      correlationLabel = 'Alta Correlação (+)';
      correlationDesc = 'Varreduras com mais achados demandam proporcionalmente mais tempo de inspeção e validação.';
    } else if (correlationR > 0.15) {
      correlationLabel = 'Moderada (+)';
      correlationDesc = 'O tempo de varredura tende a crescer suavemente conforme o volume de vulnerabilidades detectadas.';
    } else if (correlationR >= -0.15) {
      correlationLabel = 'Tempo Estável';
      correlationDesc = 'A duração da varredura permanece constante independente da contagem de achados.';
    } else {
      correlationLabel = 'Correlação Inversa (-)';
      correlationDesc = 'Otimizações do motor AST reduziram o tempo mesmo em ciclos com achados.';
    }

    const baselineCritical = baseline.criticalCount;
    const currentCritical = current.criticalCount;
    const criticalRemediated = Math.max(0, baselineCritical - currentCritical);

    const isImproving = netDelta <= 0;
    const stepCount = Math.max(1, chartData.length - 1);
    const velocityPerCycle = (Math.abs(netDelta) / stepCount).toFixed(1);

    return {
      baselineTotal,
      currentTotal,
      netDelta,
      netPercent,
      averageFindings,
      peakFindings,
      lowestFindings,
      criticalRemediated,
      isImproving,
      remediationVelocity: `${isImproving ? '-' : '+'}${velocityPerCycle}`,
      averageDurationSec,
      peakDurationSec,
      lowestDurationSec,
      currentDurationSec,
      correlationR,
      correlationLabel,
      correlationDesc
    };
  }, [chartData]);

  // Selected scan detail
  const selectedScan = useMemo(() => {
    if (!selectedScanId) return chartData[chartData.length - 1] || null;
    return chartData.find(d => d.id === selectedScanId) || chartData[chartData.length - 1] || null;
  }, [chartData, selectedScanId]);

  // Reset to default baseline
  const handleReset = () => {
    const fresh = generateBaselineRecentScans(report);
    setScans(fresh);
    safeSetItem(RECENT_SCANS_STORAGE_KEY, JSON.stringify(fresh));
    setSelectedScanId(null);
  };

  return (
    <div
      id="dashboard-scan-history-chart-card"
      className="bg-[#0A0A0A] border-2 border-[#1F1F1F] hover:border-[#2A2A2A] transition-colors p-5 sm:p-6 space-y-6 relative overflow-hidden"
    >
      {/* Decorative cyber corner accents */}
      <div className="absolute top-0 right-0 w-8 h-8 pointer-events-none overflow-hidden">
        <div className="absolute transform rotate-45 bg-[#FF3E00]/20 w-12 h-2 -top-1 -right-3" />
      </div>

      {/* Header & Main Telemetry */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#1A1A1A] pb-5">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="p-1.5 bg-[#FF3E00]/10 text-[#FF3E00] border border-[#FF3E00]/30 rounded">
              <History className="w-4 h-4" />
            </span>
            <h2 className="text-sm sm:text-base font-black tracking-wider text-white uppercase font-mono flex items-center gap-2">
              <span>Scan History</span>
              <span className="text-[#666] font-normal">/</span>
              <span className="text-zinc-400 font-bold">Últimos 10 Scans</span>
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#161616] text-[#00FF41] border border-[#00FF41]/30 font-bold uppercase tracking-wider">
              {chartData.length} Varreduras Registradas
            </span>
            {remediationMetrics.isImproving ? (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30 font-bold uppercase flex items-center gap-1">
                <TrendingDown className="w-3 h-3" />
                Remediação Ativa ({remediationMetrics.netPercent}%)
              </span>
            ) : (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#FF7A00]/10 text-[#FF7A00] border border-[#FF7A00]/30 font-bold uppercase flex items-center gap-1">
                <TrendingUp className="w-3 h-3" />
                Atenção: Novos Achados (+{Math.abs(remediationMetrics.netDelta)})
              </span>
            )}
          </div>
          <p className="text-xs font-mono text-[#888]">
            Acompanhamento temporal do backlog de vulnerabilidades e velocidade de remediação ao longo dos últimos 10 ciclos de auditoria SAST.
          </p>
        </div>

        {/* Top Controls & Navigation */}
        <div className="flex flex-wrap items-center gap-2 self-start lg:self-auto">
          {/* Quality Target Toggle */}
          <button
            id="btn-toggle-scan-history-target"
            type="button"
            onClick={() => setShowTargetLine(prev => !prev)}
            className={`h-8 px-2.5 rounded font-mono text-[11px] font-bold uppercase tracking-wider border transition-all flex items-center gap-1.5 cursor-pointer ${
              showTargetLine
                ? 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/40'
                : 'bg-[#111] text-[#666] border-[#262626] hover:text-white'
            }`}
            title="Exibir linha de meta de qualidade zero / limiar"
          >
            <Target className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Meta</span>
          </button>

          {/* Average Line Toggle */}
          <button
            id="btn-toggle-scan-history-average"
            type="button"
            onClick={() => setShowAverageLine(prev => !prev)}
            className={`h-8 px-2.5 rounded font-mono text-[11px] font-bold uppercase tracking-wider border transition-all flex items-center gap-1.5 cursor-pointer ${
              showAverageLine
                ? 'bg-[#3366FF]/15 text-[#3366FF] border-[#3366FF]/40'
                : 'bg-[#111] text-[#666] border-[#262626] hover:text-white'
            }`}
            title="Exibir média móvel dos 10 scans"
          >
            <Activity className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Média</span>
          </button>

          {/* Duration Secondary Axis Toggle */}
          <button
            id="btn-toggle-scan-history-duration"
            type="button"
            onClick={() => setShowDurationLine(prev => !prev)}
            className={`h-8 px-2.5 rounded font-mono text-[11px] font-bold uppercase tracking-wider border transition-all flex items-center gap-1.5 cursor-pointer ${
              showDurationLine
                ? 'bg-[#00E5FF]/15 text-[#00E5FF] border-[#00E5FF]/40 shadow-xs'
                : 'bg-[#111] text-[#666] border-[#262626] hover:text-white'
            }`}
            title="Alternar eixo secundário com tempo de duração da varredura em segundos"
          >
            <Clock className="w-3.5 h-3.5 text-[#00E5FF]" />
            <span className="hidden sm:inline">Duração (s)</span>
          </button>

          {/* Reset Baseline */}
          <button
            id="btn-reset-scan-history"
            type="button"
            onClick={handleReset}
            className="h-8 px-2.5 rounded font-mono text-[11px] font-bold uppercase tracking-wider bg-[#111] hover:bg-[#1A1A1A] text-[#888] hover:text-white border border-[#262626] transition-all flex items-center gap-1.5 cursor-pointer"
            title="Restaurar histórico simulado de 10 varreduras"
          >
            <RotateCcw className="w-3 h-3" />
            <span className="hidden sm:inline">Resetar</span>
          </button>

          {/* Navigate to Scanner Tab */}
          {onNavigateToScanner && (
            <button
              id="btn-scan-history-go-scanner"
              type="button"
              onClick={onNavigateToScanner}
              className="h-8 px-3 rounded font-mono text-[11px] font-bold uppercase tracking-wider bg-[#FF3E00]/15 hover:bg-[#FF3E00] text-[#FF3E00] hover:text-white border border-[#FF3E00]/40 transition-all flex items-center gap-1.5 cursor-pointer shadow-xs"
            >
              <span>Ver no Scanner</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* KPI Cards Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {/* Current Scan Findings & Duration */}
        <div className="p-3.5 bg-[#0D0D0D] border border-[#222] rounded flex flex-col justify-between">
          <div className="flex items-center justify-between text-[10px] font-mono text-[#888] uppercase font-bold">
            <span>Scan Atual (#10)</span>
            <span className="w-2 h-2 rounded-full bg-[#00FF41] animate-pulse" />
          </div>
          <div className="my-2 flex items-baseline justify-between gap-2">
            <div className="flex items-baseline gap-1.5">
              <span className="text-2xl sm:text-3xl font-black font-mono text-white">
                {remediationMetrics.currentTotal}
              </span>
              <span className="text-xs font-mono text-zinc-400">achados</span>
            </div>
            <div className="flex items-center gap-1 text-[11px] font-mono font-bold text-[#00E5FF] bg-[#00E5FF]/10 px-1.5 py-0.5 rounded border border-[#00E5FF]/20">
              <Clock className="w-3 h-3" />
              <span>{remediationMetrics.currentDurationSec}s</span>
            </div>
          </div>
          <div className="text-[10px] font-mono text-[#777] flex items-center justify-between pt-1.5 border-t border-[#1C1C1C]">
            <div className="flex items-center gap-1.5">
              <span className="text-[#FF3E00] font-bold">{chartData[chartData.length - 1]?.criticalCount ?? 0} críticos</span>
              <span>•</span>
              <span className="text-[#FF7A00] font-bold">{chartData[chartData.length - 1]?.highCount ?? 0} altos</span>
            </div>
            <span className="text-zinc-500">{chartData[chartData.length - 1]?.totalFiles ?? 8} arqs</span>
          </div>
        </div>

        {/* Net Remediation Progress */}
        <div className="p-3.5 bg-[#0D0D0D] border border-[#222] rounded flex flex-col justify-between">
          <div className="flex items-center justify-between text-[10px] font-mono text-[#888] uppercase font-bold">
            <span>Progresso de Remediação</span>
            {remediationMetrics.isImproving ? (
              <TrendingDown className="w-3.5 h-3.5 text-[#00FF41]" />
            ) : (
              <TrendingUp className="w-3.5 h-3.5 text-[#FF7A00]" />
            )}
          </div>
          <div className="my-2 flex items-baseline gap-2">
            <span className={`text-2xl sm:text-3xl font-black font-mono ${
              remediationMetrics.isImproving ? 'text-[#00FF41]' : 'text-[#FF7A00]'
            }`}>
              {remediationMetrics.netDelta <= 0 ? `${remediationMetrics.netDelta}` : `+${remediationMetrics.netDelta}`}
            </span>
            <span className="text-xs font-mono font-bold text-[#AAA]">
              ({remediationMetrics.netPercent > 0 ? `-${remediationMetrics.netPercent}%` : `${remediationMetrics.netPercent}%`})
            </span>
          </div>
          <div className="text-[10px] font-mono text-[#777] pt-1.5 border-t border-[#1C1C1C]">
            vs Scan #1 ({remediationMetrics.baselineTotal} achados no início)
          </div>
        </div>

        {/* 10-Scan Average Findings & Duration */}
        <div className="p-3.5 bg-[#0D0D0D] border border-[#222] rounded flex flex-col justify-between">
          <div className="flex items-center justify-between text-[10px] font-mono text-[#888] uppercase font-bold">
            <span>Médias (Achados / Tempo)</span>
            <Activity className="w-3.5 h-3.5 text-[#3366FF]" />
          </div>
          <div className="my-2 flex items-baseline justify-between gap-2">
            <div className="flex items-baseline gap-1.5">
              <span className="text-2xl sm:text-3xl font-black font-mono text-white">
                {remediationMetrics.averageFindings}
              </span>
              <span className="text-xs font-mono text-[#888]">achados</span>
            </div>
            <div className="flex items-center gap-1 text-[11px] font-mono text-[#00E5FF]">
              <span>~{remediationMetrics.averageDurationSec}s</span>
            </div>
          </div>
          <div className="text-[10px] font-mono text-[#777] pt-1.5 border-t border-[#1C1C1C] flex items-center justify-between">
            <span>Pico: {remediationMetrics.peakFindings} achados</span>
            <span className="text-zinc-500">Pico: {remediationMetrics.peakDurationSec}s</span>
          </div>
        </div>

        {/* Correlation: Scan Time vs Findings */}
        <div className="p-3.5 bg-[#0D0D0D] border border-[#222] rounded flex flex-col justify-between">
          <div className="flex items-center justify-between text-[10px] font-mono text-[#888] uppercase font-bold">
            <span>Correlação Tempo vs Achados</span>
            <Timer className="w-3.5 h-3.5 text-[#00E5FF]" />
          </div>
          <div className="my-2 flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-black font-mono text-[#00E5FF]">
              {remediationMetrics.correlationR >= 0 ? `+${remediationMetrics.correlationR}` : remediationMetrics.correlationR}
            </span>
            <span className="text-xs font-mono text-zinc-400 font-bold">
              (Pearson r)
            </span>
          </div>
          <div className="text-[10px] font-mono text-[#777] pt-1.5 border-t border-[#1C1C1C] flex items-center justify-between">
            <span className="text-[#00E5FF] font-bold truncate max-w-[130px]">{remediationMetrics.correlationLabel}</span>
            <span className="text-zinc-500 shrink-0">Vel: {remediationMetrics.remediationVelocity}/scan</span>
          </div>
        </div>
      </div>

      {/* Duration & Correlation Insight Strip */}
      {showDurationLine && (
        <div className="flex flex-wrap items-center justify-between gap-2.5 px-3.5 py-2.5 bg-[#00E5FF]/5 border border-[#00E5FF]/20 rounded text-[11px] font-mono">
          <div className="flex items-center gap-2 text-zinc-300">
            <span className="p-1 rounded bg-[#00E5FF]/10 text-[#00E5FF] border border-[#00E5FF]/30">
              <Clock className="w-3.5 h-3.5" />
            </span>
            <span>
              <strong className="text-[#00E5FF]">Eixo Secundário Ativo (Duração):</strong> Linha ciano tracejada exibe a duração de cada varredura em segundos para correlação com o volume de achados.
            </span>
            <span className="hidden md:inline text-zinc-400">
              • {remediationMetrics.correlationDesc}
            </span>
          </div>
          <div className="flex items-center gap-3 text-[10px] text-zinc-400 font-mono">
            <span>Duração Média: <strong className="text-white">{remediationMetrics.averageDurationSec}s</strong></span>
            <span>Pico: <strong className="text-white">{remediationMetrics.peakDurationSec}s</strong></span>
            <span>Pearson r: <strong className="text-[#00E5FF]">{remediationMetrics.correlationR >= 0 ? `+${remediationMetrics.correlationR}` : remediationMetrics.correlationR}</strong></span>
          </div>
        </div>
      )}

      {/* Mode View Switcher Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-2.5 bg-[#121212] border border-[#222] rounded">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] font-mono text-[#777] uppercase font-bold mr-1 flex items-center gap-1">
            <Sliders className="w-3 h-3 text-[#FF3E00]" />
            Modo de Visualização:
          </span>

          <button
            id="btn-scan-history-mode-area"
            type="button"
            onClick={() => setViewMode('AREA_TOTAL')}
            className={`px-3 py-1 text-[11px] font-mono font-bold uppercase tracking-wider rounded transition-all cursor-pointer flex items-center gap-1.5 ${
              viewMode === 'AREA_TOTAL'
                ? 'bg-[#FF3E00] text-white shadow-xs'
                : 'bg-[#181818] text-[#888] hover:text-white border border-[#262626]'
            }`}
          >
            <LineChartIcon className="w-3 h-3" />
            <span>Total de Achados (Área)</span>
          </button>

          <button
            id="btn-scan-history-mode-stacked"
            type="button"
            onClick={() => setViewMode('STACKED_SEVERITY')}
            className={`px-3 py-1 text-[11px] font-mono font-bold uppercase tracking-wider rounded transition-all cursor-pointer flex items-center gap-1.5 ${
              viewMode === 'STACKED_SEVERITY'
                ? 'bg-[#3366FF] text-white shadow-xs'
                : 'bg-[#181818] text-[#888] hover:text-white border border-[#262626]'
            }`}
          >
            <BarChart3 className="w-3 h-3" />
            <span>Composição por Severidade</span>
          </button>

          <button
            id="btn-scan-history-mode-trend"
            type="button"
            onClick={() => setViewMode('TREND_TARGET')}
            className={`px-3 py-1 text-[11px] font-mono font-bold uppercase tracking-wider rounded transition-all cursor-pointer flex items-center gap-1.5 ${
              viewMode === 'TREND_TARGET'
                ? 'bg-[#00FF41] text-black shadow-xs font-black'
                : 'bg-[#181818] text-[#888] hover:text-white border border-[#262626]'
            }`}
          >
            <TrendingDown className="w-3 h-3" />
            <span>Trajetória & Meta</span>
          </button>
        </div>

        {/* Legend pills */}
        <div className="flex flex-wrap items-center gap-2.5 text-[10px] font-mono">
          <span className="flex items-center gap-1 text-[#888]">
            <span className="w-2 h-2 rounded-full bg-[#FF3E00]" />
            Crítico
          </span>
          <span className="flex items-center gap-1 text-[#888]">
            <span className="w-2 h-2 rounded-full bg-[#FF7A00]" />
            Alto
          </span>
          <span className="flex items-center gap-1 text-[#888]">
            <span className="w-2 h-2 rounded-full bg-[#EAB308]" />
            Médio
          </span>
          <span className="flex items-center gap-1 text-[#888]">
            <span className="w-2 h-2 rounded-full bg-[#3366FF]" />
            Baixo
          </span>
          {showDurationLine && (
            <span className="flex items-center gap-1.5 text-[#00E5FF] font-bold bg-[#00E5FF]/10 px-1.5 py-0.5 rounded border border-[#00E5FF]/20">
              <span className="w-3 h-0.5 bg-[#00E5FF]" />
              Duração (s) [Eixo Direito]
            </span>
          )}
        </div>
      </div>

      {/* Main Recharts Canvas */}
      <div className="bg-[#0D0D0D] border border-[#222] p-4 sm:p-5 rounded relative">
        <div className="h-72 sm:h-80 w-full">
          <ResponsiveContainer width="100%" height="100%">
            {viewMode === 'STACKED_SEVERITY' ? (
              <ComposedChart
                data={chartData}
                margin={{ top: 15, right: showDurationLine ? 25 : 15, left: -10, bottom: 5 }}
                onClick={(data: any) => {
                  const payload = data?.activePayload?.[0]?.payload;
                  if (payload) {
                    setSelectedScanId(payload.id);
                    if (onSelectScanIndex) {
                      onSelectScanIndex(payload.scanIndex);
                    }
                  }
                }}
              >
                <CartesianGrid stroke="#1F1F1F" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="shortLabel"
                  stroke="#555"
                  tick={{ fill: '#888', fontSize: 11, fontFamily: 'monospace' }}
                  tickLine={{ stroke: '#333' }}
                  axisLine={{ stroke: '#333' }}
                />
                <YAxis
                  yAxisId="findings"
                  stroke="#555"
                  tick={{ fill: '#888', fontSize: 11, fontFamily: 'monospace' }}
                  tickLine={{ stroke: '#333' }}
                  axisLine={{ stroke: '#333' }}
                  allowDecimals={false}
                />
                {showDurationLine && (
                  <YAxis
                    yAxisId="duration"
                    orientation="right"
                    stroke="#555"
                    tick={{ fill: '#00E5FF', fontSize: 11, fontFamily: 'monospace' }}
                    tickLine={{ stroke: '#333' }}
                    axisLine={{ stroke: '#333' }}
                    tickFormatter={(v: number) => `${v}s`}
                    allowDecimals={true}
                    domain={[0, (dataMax: number) => Number((Math.max(0.2, dataMax) * 1.25).toFixed(1))]}
                  />
                )}
                <RechartsTooltip content={<CustomTooltip />} />
                <Bar yAxisId="findings" dataKey="criticalCount" stackId="a" fill="#FF3E00" name="Crítico" radius={[0, 0, 0, 0]} />
                <Bar yAxisId="findings" dataKey="highCount" stackId="a" fill="#FF7A00" name="Alto" radius={[0, 0, 0, 0]} />
                <Bar yAxisId="findings" dataKey="mediumCount" stackId="a" fill="#EAB308" name="Médio" radius={[0, 0, 0, 0]} />
                <Bar yAxisId="findings" dataKey="lowCount" stackId="a" fill="#3366FF" name="Baixo" radius={[2, 2, 0, 0]} />
                <Line
                  yAxisId="findings"
                  type="monotone"
                  dataKey="totalFindings"
                  stroke="#FFFFFF"
                  strokeWidth={2}
                  name="Total de Achados"
                  dot={{ r: 4, fill: '#FFFFFF', stroke: '#000', strokeWidth: 1.5 }}
                  activeDot={{ r: 6, fill: '#00FF41', stroke: '#FFF', strokeWidth: 2 }}
                />
                {showDurationLine && (
                  <Line
                    yAxisId="duration"
                    type="monotone"
                    dataKey="durationSec"
                    stroke="#00E5FF"
                    strokeWidth={2}
                    strokeDasharray="4 3"
                    name="Duração (s)"
                    dot={{ r: 3.5, fill: '#00E5FF', stroke: '#0D0D0D', strokeWidth: 1.5 }}
                    activeDot={{ r: 6, fill: '#00E5FF', stroke: '#FFFFFF', strokeWidth: 2 }}
                  />
                )}
                {showAverageLine && (
                  <ReferenceLine
                    yAxisId="findings"
                    y={remediationMetrics.averageFindings}
                    stroke="#3366FF"
                    strokeDasharray="4 4"
                    label={{
                      value: `Média: ${remediationMetrics.averageFindings}`,
                      fill: '#3366FF',
                      fontSize: 10,
                      fontFamily: 'monospace',
                      position: 'insideTopRight'
                    }}
                  />
                )}
              </ComposedChart>
            ) : viewMode === 'TREND_TARGET' ? (
              <ComposedChart
                data={chartData}
                margin={{ top: 15, right: showDurationLine ? 25 : 15, left: -10, bottom: 5 }}
                onClick={(data: any) => {
                  const payload = data?.activePayload?.[0]?.payload;
                  if (payload) {
                    setSelectedScanId(payload.id);
                    if (onSelectScanIndex) {
                      onSelectScanIndex(payload.scanIndex);
                    }
                  }
                }}
              >
                <defs>
                  <linearGradient id="scanHistoryTrendGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00FF41" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#00FF41" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#1F1F1F" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="shortLabel"
                  stroke="#555"
                  tick={{ fill: '#888', fontSize: 11, fontFamily: 'monospace' }}
                  tickLine={{ stroke: '#333' }}
                  axisLine={{ stroke: '#333' }}
                />
                <YAxis
                  yAxisId="findings"
                  stroke="#555"
                  tick={{ fill: '#888', fontSize: 11, fontFamily: 'monospace' }}
                  tickLine={{ stroke: '#333' }}
                  axisLine={{ stroke: '#333' }}
                  allowDecimals={false}
                />
                {showDurationLine && (
                  <YAxis
                    yAxisId="duration"
                    orientation="right"
                    stroke="#555"
                    tick={{ fill: '#00E5FF', fontSize: 11, fontFamily: 'monospace' }}
                    tickLine={{ stroke: '#333' }}
                    axisLine={{ stroke: '#333' }}
                    tickFormatter={(v: number) => `${v}s`}
                    allowDecimals={true}
                    domain={[0, (dataMax: number) => Number((Math.max(0.2, dataMax) * 1.25).toFixed(1))]}
                  />
                )}
                <RechartsTooltip content={<CustomTooltip />} />
                <Area
                  yAxisId="findings"
                  type="monotone"
                  dataKey="totalFindings"
                  stroke="#00FF41"
                  strokeWidth={2.5}
                  fill="url(#scanHistoryTrendGradient)"
                  name="Total de Achados"
                  dot={<CustomDot />}
                  activeDot={{ r: 7, fill: '#00FF41', stroke: '#FFFFFF', strokeWidth: 2 }}
                />
                {showDurationLine && (
                  <Line
                    yAxisId="duration"
                    type="monotone"
                    dataKey="durationSec"
                    stroke="#00E5FF"
                    strokeWidth={2}
                    strokeDasharray="4 3"
                    name="Duração (s)"
                    dot={{ r: 3.5, fill: '#00E5FF', stroke: '#0D0D0D', strokeWidth: 1.5 }}
                    activeDot={{ r: 6, fill: '#00E5FF', stroke: '#FFFFFF', strokeWidth: 2 }}
                  />
                )}
                {showTargetLine && (
                  <ReferenceLine
                    yAxisId="findings"
                    y={2}
                    stroke="#00FF41"
                    strokeDasharray="5 3"
                    label={{
                      value: 'Meta de Qualidade (≤ 2)',
                      fill: '#00FF41',
                      fontSize: 10,
                      fontFamily: 'monospace',
                      position: 'insideBottomRight'
                    }}
                  />
                )}
                {showAverageLine && (
                  <ReferenceLine
                    yAxisId="findings"
                    y={remediationMetrics.averageFindings}
                    stroke="#EAB308"
                    strokeDasharray="3 3"
                    label={{
                      value: `Média: ${remediationMetrics.averageFindings}`,
                      fill: '#EAB308',
                      fontSize: 10,
                      fontFamily: 'monospace',
                      position: 'insideTopRight'
                    }}
                  />
                )}
              </ComposedChart>
            ) : (
              <ComposedChart
                data={chartData}
                margin={{ top: 15, right: showDurationLine ? 25 : 15, left: -10, bottom: 5 }}
                onClick={(data: any) => {
                  const payload = data?.activePayload?.[0]?.payload;
                  if (payload) {
                    setSelectedScanId(payload.id);
                    if (onSelectScanIndex) {
                      onSelectScanIndex(payload.scanIndex);
                    }
                  }
                }}
              >
                <defs>
                  <linearGradient id="scanHistoryAreaGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF3E00" stopOpacity={0.35} />
                    <stop offset="50%" stopColor="#FF7A00" stopOpacity={0.15} />
                    <stop offset="95%" stopColor="#FF3E00" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#1F1F1F" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="shortLabel"
                  stroke="#555"
                  tick={{ fill: '#888', fontSize: 11, fontFamily: 'monospace' }}
                  tickLine={{ stroke: '#333' }}
                  axisLine={{ stroke: '#333' }}
                />
                <YAxis
                  yAxisId="findings"
                  stroke="#555"
                  tick={{ fill: '#888', fontSize: 11, fontFamily: 'monospace' }}
                  tickLine={{ stroke: '#333' }}
                  axisLine={{ stroke: '#333' }}
                  allowDecimals={false}
                />
                {showDurationLine && (
                  <YAxis
                    yAxisId="duration"
                    orientation="right"
                    stroke="#555"
                    tick={{ fill: '#00E5FF', fontSize: 11, fontFamily: 'monospace' }}
                    tickLine={{ stroke: '#333' }}
                    axisLine={{ stroke: '#333' }}
                    tickFormatter={(v: number) => `${v}s`}
                    allowDecimals={true}
                    domain={[0, (dataMax: number) => Number((Math.max(0.2, dataMax) * 1.25).toFixed(1))]}
                  />
                )}
                <RechartsTooltip content={<CustomTooltip />} />
                <Area
                  yAxisId="findings"
                  type="monotone"
                  dataKey="totalFindings"
                  stroke="#FF3E00"
                  strokeWidth={2.5}
                  fill="url(#scanHistoryAreaGradient)"
                  name="Total de Achados"
                  dot={<CustomDot />}
                  activeDot={{ r: 7, fill: '#FF3E00', stroke: '#FFFFFF', strokeWidth: 2 }}
                />
                {showDurationLine && (
                  <Line
                    yAxisId="duration"
                    type="monotone"
                    dataKey="durationSec"
                    stroke="#00E5FF"
                    strokeWidth={2}
                    strokeDasharray="4 3"
                    name="Duração (s)"
                    dot={{ r: 3.5, fill: '#00E5FF', stroke: '#0D0D0D', strokeWidth: 1.5 }}
                    activeDot={{ r: 6, fill: '#00E5FF', stroke: '#FFFFFF', strokeWidth: 2 }}
                  />
                )}
                {showTargetLine && (
                  <ReferenceLine
                    yAxisId="findings"
                    y={2}
                    stroke="#00FF41"
                    strokeDasharray="5 3"
                    label={{
                      value: 'Meta de Qualidade (≤ 2)',
                      fill: '#00FF41',
                      fontSize: 10,
                      fontFamily: 'monospace',
                      position: 'insideBottomRight'
                    }}
                  />
                )}
                {showAverageLine && (
                  <ReferenceLine
                    yAxisId="findings"
                    y={remediationMetrics.averageFindings}
                    stroke="#3366FF"
                    strokeDasharray="3 3"
                    label={{
                      value: `Média: ${remediationMetrics.averageFindings}`,
                      fill: '#3366FF',
                      fontSize: 10,
                      fontFamily: 'monospace',
                      position: 'insideTopRight'
                    }}
                  />
                )}
              </ComposedChart>
            )}
          </ResponsiveContainer>
        </div>
      </div>

      {/* 10-Scan Interactive Sequence Ribbon */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs font-mono text-[#888]">
          <span className="uppercase font-bold flex items-center gap-1.5">
            <Calendar className="w-3.5 h-3.5 text-[#FF3E00]" />
            Sequência Cronológica dos 10 Ciclos:
          </span>
          <span className="text-[11px] text-[#666]">
            Clique em qualquer ciclo para inspecionar
          </span>
        </div>

        <div className="grid grid-cols-5 sm:grid-cols-10 gap-1.5">
          {chartData.map((pt) => {
            const isSelected = selectedScan?.id === pt.id;
            return (
              <button
                key={pt.id}
                type="button"
                onClick={() => {
                  setSelectedScanId(pt.id);
                  if (onSelectScanIndex) {
                    onSelectScanIndex(pt.scanIndex);
                  }
                }}
                className={`p-2 rounded flex flex-col items-center justify-between border transition-all cursor-pointer font-mono text-center ${
                  isSelected
                    ? 'bg-[#FF3E00]/15 border-[#FF3E00] shadow-sm'
                    : pt.isCurrent
                    ? 'bg-[#151515] border-[#00FF41]/40 hover:border-[#00FF41]'
                    : 'bg-[#111] border-[#222] hover:bg-[#181818] hover:border-[#333]'
                }`}
              >
                <div className="flex items-center justify-between w-full text-[9px] text-[#777]">
                  <span>#{pt.scanNumber}</span>
                  {pt.isCurrent && (
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00FF41]" title="Atual" />
                  )}
                </div>

                <div className="my-1">
                  <span className={`text-base font-black ${
                    pt.totalFindings === 0
                      ? 'text-[#00FF41]'
                      : pt.criticalCount > 0
                      ? 'text-[#FF3E00]'
                      : 'text-white'
                  }`}>
                    {pt.totalFindings}
                  </span>
                  <div className="text-[9px] text-[#00E5FF] font-mono font-medium">
                    {pt.durationSec}s
                  </div>
                </div>

                <div className="text-[8.5px] text-[#888] truncate w-full">
                  {pt.relativeTime.replace(' (Última)', '')}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Selected Scan Snapshot Card */}
      {selectedScan && (
        <div
          id="scan-history-selected-snapshot"
          className="p-3.5 bg-[#0D0D0D] border border-[#242424] rounded flex flex-col md:flex-row items-start md:items-center justify-between gap-3 font-mono text-xs"
        >
          <div className="flex items-center gap-3">
            <div className={`w-8 h-8 rounded flex items-center justify-center font-bold text-sm ${
              selectedScan.isCurrent
                ? 'bg-[#00FF41]/20 text-[#00FF41] border border-[#00FF41]/40'
                : 'bg-[#1E1E1E] text-white border border-[#333]'
            }`}>
              #{selectedScan.scanNumber}
            </div>
            <div>
              <div className="text-white font-bold flex items-center gap-2">
                <span>{selectedScan.label}</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#1C1C1C] text-zinc-400 border border-[#333]">
                  {selectedScan.dateStr || selectedScan.relativeTime}
                </span>
                {selectedScan.isCurrent && (
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#00FF41]/20 text-[#00FF41] font-bold">
                    Scan Mais Recente
                  </span>
                )}
              </div>
              <div className="text-[11px] text-[#888] mt-0.5 flex flex-wrap items-center gap-2">
                <span>{selectedScan.totalFiles} arquivos analisados</span>
                <span>•</span>
                <span className="text-[#00E5FF] font-bold flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  Duração: {selectedScan.durationSec}s ({selectedScan.durationMs}ms)
                </span>
                <span>•</span>
                <span>Score: <strong className="text-white">{selectedScan.securityScore}/100</strong></span>
                <span>•</span>
                <span>Taxa: <strong className="text-zinc-300">{selectedScan.durationPerFindingMs}ms/achado</strong></span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <div className="flex items-center gap-1.5 bg-[#141414] px-2.5 py-1.5 rounded border border-[#222]">
              <span className="text-[10px] text-[#888] uppercase">Achados:</span>
              <span className="font-bold text-white text-sm">{selectedScan.totalFindings}</span>
              <span className="text-[10px] text-[#FF3E00]">({selectedScan.criticalCount}C / {selectedScan.highCount}A / {selectedScan.mediumCount}M)</span>
            </div>

            {selectedScan.deltaFromPrev !== 0 && (
              <div className={`flex items-center gap-1 px-2 py-1.5 rounded border text-[10px] font-bold ${
                selectedScan.deltaFromPrev < 0
                  ? 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/30'
                  : 'bg-[#FF7A00]/10 text-[#FF7A00] border-[#FF7A00]/30'
              }`}>
                {selectedScan.deltaFromPrev < 0 ? (
                  <>
                    <ArrowDownRight className="w-3 h-3" />
                    <span>{selectedScan.deltaFromPrev} vs anterior</span>
                  </>
                ) : (
                  <>
                    <ArrowUpRight className="w-3 h-3" />
                    <span>+{selectedScan.deltaFromPrev} vs anterior</span>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

// Custom SVG Dot for chart points
const CustomDot = (props: any) => {
  const { cx, cy, payload } = props;
  if (!cx || !cy) return null;

  const isCurrent = payload?.isCurrent;
  const total = payload?.totalFindings ?? 0;
  const isZero = total === 0;

  if (isCurrent) {
    return (
      <g>
        <circle cx={cx} cy={cy} r={7} fill="#00FF41" fillOpacity={0.3} className="animate-ping" />
        <circle cx={cx} cy={cy} r={5} fill="#00FF41" stroke="#FFFFFF" strokeWidth={2} />
      </g>
    );
  }

  return (
    <circle
      cx={cx}
      cy={cy}
      r={3.5}
      fill={isZero ? '#00FF41' : '#FF3E00'}
      stroke="#111"
      strokeWidth={1.5}
    />
  );
};

// Custom Recharts Tooltip
const CustomTooltip = ({ active, payload }: any) => {
  if (!active || !payload || !payload.length) return null;

  const data: TenScanDataPoint = payload[0]?.payload;
  if (!data) return null;

  return (
    <div className="bg-[#0D0D0D]/95 border border-[#333] shadow-2xl p-3.5 rounded max-w-xs font-mono text-xs backdrop-blur-xs">
      <div className="flex items-center justify-between border-b border-[#222] pb-2 mb-2">
        <div className="font-bold text-white flex items-center gap-1.5">
          <span>{data.label}</span>
          {data.isCurrent && (
            <span className="text-[9px] px-1 py-0.2 rounded bg-[#00FF41]/20 text-[#00FF41] font-bold">
              ATUAL
            </span>
          )}
        </div>
        <span className="text-[10px] text-[#888]">{data.relativeTime}</span>
      </div>

      <div className="space-y-1.5">
        <div className="flex items-baseline justify-between">
          <span className="text-zinc-400">Total de Achados:</span>
          <span className="text-base font-black text-white">{data.totalFindings}</span>
        </div>

        {/* Delta from previous */}
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-zinc-500">Variação vs Anterior:</span>
          <span className={`font-bold ${
            data.deltaFromPrev < 0
              ? 'text-[#00FF41]'
              : data.deltaFromPrev > 0
              ? 'text-[#FF7A00]'
              : 'text-[#888]'
          }`}>
            {data.deltaFromPrev < 0
              ? `${data.deltaFromPrev} achados remediados`
              : data.deltaFromPrev > 0
              ? `+${data.deltaFromPrev} novos achados`
              : 'Sem variação'}
          </span>
        </div>

        {/* Breakdown by severity */}
        <div className="pt-2 mt-2 border-t border-[#1F1F1F] grid grid-cols-2 gap-1.5 text-[10px]">
          <div className="flex items-center justify-between">
            <span className="text-[#FF3E00] flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#FF3E00]" />
              Crítico:
            </span>
            <span className="font-bold text-white">{data.criticalCount}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-[#FF7A00] flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#FF7A00]" />
              Alto:
            </span>
            <span className="font-bold text-white">{data.highCount}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-[#EAB308] flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#EAB308]" />
              Médio:
            </span>
            <span className="font-bold text-white">{data.mediumCount}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-[#3366FF] flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#3366FF]" />
              Baixo:
            </span>
            <span className="font-bold text-white">{data.lowCount}</span>
          </div>
        </div>

        {/* Security Score */}
        <div className="pt-2 mt-2 border-t border-[#1F1F1F] flex items-center justify-between text-[10px] text-[#888]">
          <span>Security Score:</span>
          <span className="font-bold text-[#00FF41]">{data.securityScore}/100</span>
        </div>

        {/* Scan Duration & Inspection Rate */}
        <div className="pt-2 mt-2 border-t border-[#1F1F1F] space-y-1">
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-zinc-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#00E5FF]" />
              Duração da Varredura:
            </span>
            <span className="font-bold text-[#00E5FF]">{data.durationSec}s ({data.durationMs}ms)</span>
          </div>
          <div className="flex items-center justify-between text-[10px] text-zinc-500">
            <span>Taxa de Inspeção:</span>
            <span className="text-zinc-300 font-medium">
              {data.durationPerFindingMs > 0 ? `${data.durationPerFindingMs}ms/achado` : 'Nenhum achado'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
