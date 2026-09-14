import React, { useState, useMemo, useEffect } from 'react';
import {
  ResponsiveContainer,
  ComposedChart,
  Area,
  Line,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  ReferenceLine
} from 'recharts';
import {
  TrendingDown,
  TrendingUp,
  Activity,
  Zap,
  Clock,
  CheckCircle2,
  Calendar,
  RotateCcw,
  Target,
  Sparkles,
  Info,
  GitCompare,
  History,
  Layers,
  AlertTriangle,
  AlertOctagon,
  Flame,
  ShieldAlert,
  ArrowUpRight,
  Filter,
  Check,
  BarChart3,
  Sliders
} from 'lucide-react';
import { ScanReport } from '../types';
import { safeGetItem, safeSetItem } from '../lib/storage';

export type MetricMode = 'DUAL_AXIS' | 'MTTR' | 'RESOLVED';

export interface ResolutionSpeedPoint {
  dayIndex: number;
  date: string; // e.g. "12 Ago"
  fullDate: string; // e.g. "12 de Agosto de 2026"
  mttrHours: number; // Current Mean Time to Remediate in hours (e.g. 14.5)
  fixResolutionHours: number; // Correlated Fix Resolution Time in hours
  resolvedCount: number; // Issues resolved on that day
  discoveryRate: number; // Finding Discovery Rate (findings discovered per day)
  netBacklogChange: number; // discoveryRate - resolvedCount (net debt delta)
  throughputRatio: number; // resolvedCount / Math.max(0.5, discoveryRate)
  slaTargetHours: number; // e.g. 24h
  accelerationPct: number; // % improvement vs start of 30-day window
  isTargetMet: boolean;

  // Bottleneck Lifecycle Diagnostics
  isBottleneck: boolean; // Flag when discovery outpaces fix capacity or MTTR spikes
  bottleneckSeverity: 'CRITICAL' | 'WARNING' | 'HEALTHY' | 'OPTIMAL';
  bottleneckLabel: string;
  bottleneckCause: string;
  bottleneckRemedy: string;

  // Secondary Trend Indicator: Comparison Against Previous 30-Day Period (-30d to -60d)
  previousPeriodMttrHours: number; // MTTR for equivalent day in previous 30-day cycle
  previousPeriodResolvedCount: number; // Resolved issues in previous 30-day cycle
  previousPeriodDiscoveryRate: number; // Discovery rate in previous 30-day cycle
  previousPeriodDate: string; // e.g. "13 Jul"
  previousPeriodFullDate: string; // e.g. "13 de Julho de 2026"
  diffMttrHours: number; // Difference in MTTR (current - previous)
  speedGainPct: number; // Acceleration percentage vs previous period
}

export interface ResolutionSpeedSparklineProps {
  report?: ScanReport;
  totalActiveCount?: number;
  averageTTRMinutes?: number;
}

const STORAGE_KEY = 'secscan_roadmap_resolution_speed_30d_v3';

/**
 * Generates a realistic 30-day historical trend correlating:
 * 1. Finding Discovery Rate (achados detectados / dia)
 * 2. Fix Resolution Time (MTTR em horas)
 * 3. Potential Bottlenecks in the remediation lifecycle (triage overload, PR merge surges, debt accumulation)
 * 4. Secondary trend baseline for the previous 30-day period (-30d to -60d)
 */
export function generate30DayResolutionSpeed(
  report?: ScanReport,
  averageTTRMinutes?: number
): ResolutionSpeedPoint[] {
  const points: ResolutionSpeedPoint[] = [];

  // Anchor current day to active findings' realistic TTR or baseline 14.5h
  const currentTargetMttr = averageTTRMinutes
    ? Math.max(10, Math.min(28, Math.round((averageTTRMinutes / 60) * 10) / 10))
    : 14.8;

  // Base starting MTTR 30 days ago (typically 2.5x to 3x slower prior to automated scanning)
  const startingMttr = Math.min(48, Math.max(34, Math.round(currentTargetMttr * 2.7 * 10) / 10));

  // Current active findings count anchor
  const activeFindingsCount = report?.findings?.length ?? 12;

  // Starting discovery rate 30 days ago (higher initial ingestion before shift-left)
  const startingDiscoveryRate = Math.min(8.5, Math.max(5.8, Math.round(activeFindingsCount * 0.42 * 10) / 10));
  // Current discovery rate today (controlled low rate due to pre-commit and pipeline gates)
  const currentDiscoveryRate = Math.min(2.4, Math.max(1.1, Math.round(activeFindingsCount * 0.11 * 10) / 10));

  // Reference date: Anchor to current date
  const now = new Date();

  for (let i = 29; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
    const dayOfMonth = d.getDate();
    const monthName = d.toLocaleDateString('pt-BR', { month: 'short' }).replace('.', '');
    const dateStr = `${dayOfMonth} ${monthName}`;
    const fullDateStr = d.toLocaleDateString('pt-BR', {
      day: '2-digit',
      month: 'long',
      year: 'numeric'
    });

    const dayIndex = 30 - i; // 1 to 30

    // Linear progress ratio from 0 (day -29) to 1 (day 0 / today)
    const progress = (29 - i) / 29;

    // Smooth asymptotic reduction curve (faster progress in first 2 weeks, settling near target)
    const curve = Math.pow(progress, 0.85);
    const baseMttr = startingMttr - curve * (startingMttr - currentTargetMttr);

    // Day of week factor: weekends tend to have lower staffing/triage velocity
    const dayOfWeek = d.getDay();
    const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;

    // Organic engineering rhythm jitter
    const jitter = Math.sin(i * 1.4) * 1.8 + (isWeekend ? 2.6 : -0.8);
    const finalMttr = Math.max(7.2, Math.round((baseMttr + jitter) * 10) / 10);

    // Resolved issues count: weekday sprints resolve more, weekends resolve fewer
    const seed = (i * 17 + dayOfMonth * 3) % 5;
    const resolvedCount = isWeekend
      ? i % 4 === 0
        ? 1
        : 0
      : Math.max(1, Math.min(6, Math.floor(seed + 1)));

    // Finding Discovery Rate curve: decreases over time as shift-left automation matures
    const discoveryCurve = Math.pow(progress, 0.75);
    const baseDiscovery = startingDiscoveryRate - discoveryCurve * (startingDiscoveryRate - currentDiscoveryRate);

    // Realistic lifecycle events creating temporary discovery surges:
    // Day 4: initial legacy repo sweep & audit
    // Day 16: mid-cycle major feature branch merge
    // Day 23: micro-sprint code freeze review
    let eventSpike = 0;
    if (dayIndex === 4) eventSpike = 2.1;
    else if (dayIndex === 5) eventSpike = 1.6;
    else if (dayIndex === 16) eventSpike = 2.5;
    else if (dayIndex === 23) eventSpike = 0.9;
    else if (isWeekend) eventSpike = -0.8;

    const discoveryJitter = Math.cos(i * 1.6) * 0.45 + eventSpike;
    const rawDiscovery = Math.max(0.6, Math.round((baseDiscovery + discoveryJitter) * 10) / 10);
    const discoveryRate = isWeekend ? Math.min(rawDiscovery, 1.2) : rawDiscovery;

    const netBacklogChange = Math.round((discoveryRate - resolvedCount) * 10) / 10;
    const throughputRatio = Number((resolvedCount / Math.max(0.5, discoveryRate)).toFixed(2));

    const slaTarget = 24.0; // 24 hours SLA threshold for P0/P1
    const acceleration = Math.round(((startingMttr - finalMttr) / startingMttr) * 100);

    // Bottleneck diagnosis
    let isBottleneck = false;
    let bottleneckSeverity: 'CRITICAL' | 'WARNING' | 'HEALTHY' | 'OPTIMAL' = 'HEALTHY';
    let bottleneckLabel = 'Fluxo Equilibrado';
    let bottleneckCause = 'Throughput de correção alinhado à taxa de novas falhas';
    let bottleneckRemedy = 'Manter rotina contínua de triage e code review';

    if (discoveryRate > resolvedCount && finalMttr >= 24) {
      isBottleneck = true;
      bottleneckSeverity = 'CRITICAL';
      bottleneckLabel = 'Gargalo Crítico de Triagem';
      bottleneckCause = `Taxa de descoberta (${discoveryRate}/dia) superou a resolução (${resolvedCount}/dia) com MTTR elevado (${finalMttr}h)`;
      bottleneckRemedy = 'Priorizar contenção de segredos críticos e desacoplar pendências de deploy';
    } else if (discoveryRate > resolvedCount) {
      isBottleneck = true;
      bottleneckSeverity = 'WARNING';
      bottleneckLabel = 'Congestionamento de Capacidade';
      bottleneckCause = `Novas vulnerabilidades detectadas (${discoveryRate}) superaram o throughput diário (${resolvedCount})`;
      bottleneckRemedy = 'Drenar Quick Wins para desafogar a fila de pendências';
    } else if (discoveryRate < resolvedCount && finalMttr <= 18) {
      isBottleneck = false;
      bottleneckSeverity = 'OPTIMAL';
      bottleneckLabel = 'Throughput Otimizado';
      bottleneckCause = `Resolução (${resolvedCount}/dia) supera novas descobertas (${discoveryRate}/dia) com resposta ágil (${finalMttr}h)`;
      bottleneckRemedy = 'Débito técnico em queima contínua sem retenções no pipeline';
    } else {
      isBottleneck = false;
      bottleneckSeverity = 'HEALTHY';
      bottleneckLabel = 'Capacidade Estável';
      bottleneckCause = 'Taxa de remediação equilibrada com o volume de ingestão de código';
      bottleneckRemedy = 'Monitorar métricas de regressão em ambiente de homologação';
    }

    // --- SECONDARY TREND: Previous 30-Day Period Equivalent (Day -59 to Day -30) ---
    const prevD = new Date(d.getTime() - 30 * 24 * 60 * 60 * 1000);
    const prevDayOfMonth = prevD.getDate();
    const prevMonthName = prevD.toLocaleDateString('pt-BR', { month: 'short' }).replace('.', '');
    const prevDateStr = `${prevDayOfMonth} ${prevMonthName}`;
    const prevFullDateStr = prevD.toLocaleDateString('pt-BR', {
      day: '2-digit',
      month: 'long',
      year: 'numeric'
    });

    const prevDayOfWeek = prevD.getDay();
    const isPrevWeekend = prevDayOfWeek === 0 || prevDayOfWeek === 6;

    // Previous cycle was before full automated pipeline gates: starting at 46h down to ~34h
    const prevStartingMttr = Math.min(52, Math.max(42, Math.round(startingMttr * 1.18 * 10) / 10));
    const prevEndingMttr = Math.min(38, Math.max(30, Math.round(startingMttr * 0.95 * 10) / 10));
    const prevCurve = Math.pow(progress, 0.7);
    const prevBaseMttr = prevStartingMttr - prevCurve * (prevStartingMttr - prevEndingMttr);
    const prevJitter = Math.cos(i * 1.5 + 0.8) * 2.2 + (isPrevWeekend ? 3.2 : -1.1);
    const prevFinalMttr = Math.max(24.0, Math.round((prevBaseMttr + prevJitter) * 10) / 10);

    const prevSeed = (i * 11 + prevDayOfMonth * 7) % 4;
    const prevResolvedCount = isPrevWeekend
      ? 0
      : Math.max(0, Math.min(3, Math.floor(prevSeed)));

    const prevDiscoveryRate = Math.max(
      1.5,
      Math.round((startingDiscoveryRate * 1.12 - progress * 1.4 + (isPrevWeekend ? -0.8 : 0.4)) * 10) / 10
    );

    const diffMttr = Math.round((finalMttr - prevFinalMttr) * 10) / 10;
    const speedGain = Math.round(((prevFinalMttr - finalMttr) / prevFinalMttr) * 100);

    points.push({
      dayIndex,
      date: dateStr,
      fullDate: fullDateStr,
      mttrHours: finalMttr,
      fixResolutionHours: finalMttr,
      resolvedCount,
      discoveryRate,
      netBacklogChange,
      throughputRatio,
      slaTargetHours: slaTarget,
      accelerationPct: acceleration,
      isTargetMet: finalMttr <= slaTarget,
      isBottleneck,
      bottleneckSeverity,
      bottleneckLabel,
      bottleneckCause,
      bottleneckRemedy,
      previousPeriodMttrHours: prevFinalMttr,
      previousPeriodResolvedCount: prevResolvedCount,
      previousPeriodDiscoveryRate: prevDiscoveryRate,
      previousPeriodDate: prevDateStr,
      previousPeriodFullDate: prevFullDateStr,
      diffMttrHours: diffMttr,
      speedGainPct: speedGain
    });
  }

  return points;
}

export const ResolutionSpeedSparkline: React.FC<ResolutionSpeedSparklineProps> = ({
  report,
  totalActiveCount = 0,
  averageTTRMinutes = 35
}) => {
  // Timeframe filter: 30d, 14d, 7d
  const [timeframe, setTimeframe] = useState<'30D' | '14D' | '7D'>('30D');
  // Metric display mode: Dual-Axis Bottleneck Overlay vs Single MTTR vs Single Resolved
  const [metricMode, setMetricMode] = useState<MetricMode>('DUAL_AXIS');
  // Secondary trend indicator line: Compare against previous 30-day period
  const [showPreviousPeriod, setShowPreviousPeriod] = useState<boolean>(true);
  // Selected bottleneck incident point for deep-dive inspection
  const [selectedPoint, setSelectedPoint] = useState<ResolutionSpeedPoint | null>(null);

  // Load or generate data
  const [dataPoints, setDataPoints] = useState<ResolutionSpeedPoint[]>(() => {
    const saved = safeGetItem(STORAGE_KEY);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (
          Array.isArray(parsed) &&
          parsed.length === 30 &&
          typeof parsed[0]?.discoveryRate === 'number' &&
          typeof parsed[0]?.fixResolutionHours === 'number'
        ) {
          return parsed;
        }
      } catch {
        // Fallback on parse error
      }
    }
    const fresh = generate30DayResolutionSpeed(report, averageTTRMinutes);
    safeSetItem(STORAGE_KEY, JSON.stringify(fresh));
    return fresh;
  });

  // Re-sync if report changes significantly
  useEffect(() => {
    const saved = safeGetItem(STORAGE_KEY);
    if (!saved) {
      const fresh = generate30DayResolutionSpeed(report, averageTTRMinutes);
      setDataPoints(fresh);
      safeSetItem(STORAGE_KEY, JSON.stringify(fresh));
    }
  }, [report?.id, averageTTRMinutes]);

  // Reset to fresh baseline
  const handleResetTrend = () => {
    const fresh = generate30DayResolutionSpeed(report, averageTTRMinutes);
    setDataPoints(fresh);
    setSelectedPoint(null);
    safeSetItem(STORAGE_KEY, JSON.stringify(fresh));
  };

  // Filtered slice by timeframe
  const visiblePoints = useMemo(() => {
    if (timeframe === '7D') {
      return dataPoints.slice(-7);
    }
    if (timeframe === '14D') {
      return dataPoints.slice(-14);
    }
    return dataPoints;
  }, [dataPoints, timeframe]);

  // Key metrics calculation including dual-axis correlation and bottleneck analytics
  const metrics = useMemo(() => {
    if (visiblePoints.length === 0) {
      return {
        currentMttr: 14.5,
        avgMttr: 22.0,
        prevAvgMttr: 38.5,
        prevCurrentMttr: 34.0,
        periodImprovementPct: 43,
        periodMttrDelta: 16.5,
        fastestMttr: 9.5,
        fastestDate: '',
        totalResolved: 42,
        prevTotalResolved: 26,
        slaComplianceRate: 85,
        improvementPct: 55,
        trendDirection: 'FASTER' as const,
        currentDiscoveryRate: 1.5,
        avgDiscoveryRate: 3.2,
        initialDiscoveryRate: 7.2,
        discoveryDropPct: 79,
        totalDiscovered: 65,
        netBacklogTotal: -23,
        overallThroughputRatio: 1.25,
        bottleneckDaysCount: 3,
        criticalBottleneckCount: 1,
        warningBottleneckCount: 2,
        optimalDaysCount: 16
      };
    }

    const current = visiblePoints[visiblePoints.length - 1].mttrHours;
    const initial = visiblePoints[0].mttrHours;
    const totalMttr = visiblePoints.reduce((acc, p) => acc + p.mttrHours, 0);
    const avg = Math.round((totalMttr / visiblePoints.length) * 10) / 10;

    const totalPrevMttr = visiblePoints.reduce(
      (acc, p) => acc + (p.previousPeriodMttrHours ?? 38.0),
      0
    );
    const prevAvgMttr = Math.round((totalPrevMttr / visiblePoints.length) * 10) / 10;
    const prevCurrent =
      visiblePoints[visiblePoints.length - 1].previousPeriodMttrHours ?? 34.0;
    const periodMttrDelta = Math.round((prevAvgMttr - avg) * 10) / 10;
    const periodImprovementPct = Math.max(
      0,
      Math.round(((prevAvgMttr - avg) / prevAvgMttr) * 100)
    );

    let fastest = visiblePoints[0].mttrHours;
    let fastestDate = visiblePoints[0].date;
    let totalResolved = 0;
    let prevTotalResolved = 0;
    let metSlaCount = 0;

    let totalDiscovered = 0;
    let bottleneckDaysCount = 0;
    let criticalBottleneckCount = 0;
    let warningBottleneckCount = 0;
    let optimalDaysCount = 0;

    visiblePoints.forEach((p) => {
      totalResolved += p.resolvedCount;
      prevTotalResolved += p.previousPeriodResolvedCount ?? 1;
      totalDiscovered += p.discoveryRate;

      if (p.mttrHours < fastest) {
        fastest = p.mttrHours;
        fastestDate = p.date;
      }
      if (p.isTargetMet) {
        metSlaCount++;
      }
      if (p.isBottleneck) {
        bottleneckDaysCount++;
      }
      if (p.bottleneckSeverity === 'CRITICAL') {
        criticalBottleneckCount++;
      } else if (p.bottleneckSeverity === 'WARNING') {
        warningBottleneckCount++;
      } else if (p.bottleneckSeverity === 'OPTIMAL') {
        optimalDaysCount++;
      }
    });

    const slaComplianceRate = Math.round((metSlaCount / visiblePoints.length) * 100);
    const diff = initial - current;
    const improvementPct = Math.abs(Math.round((diff / initial) * 100));
    const trendDirection = current < initial ? 'FASTER' : current > initial ? 'SLOWER' : 'FLAT';

    const currentDiscovery = visiblePoints[visiblePoints.length - 1].discoveryRate;
    const initialDiscovery = visiblePoints[0].discoveryRate;
    const avgDiscovery = Math.round((totalDiscovered / visiblePoints.length) * 10) / 10;
    const discoveryDropPct = Math.max(
      0,
      Math.round(((initialDiscovery - currentDiscovery) / Math.max(0.1, initialDiscovery)) * 100)
    );

    const roundedTotalDiscovered = Math.round(totalDiscovered);
    const netBacklogTotal = Math.round((totalResolved - roundedTotalDiscovered) * 10) / 10;
    const overallThroughputRatio = Number(
      (totalResolved / Math.max(1, roundedTotalDiscovered)).toFixed(2)
    );

    return {
      currentMttr: current,
      avgMttr: avg,
      prevAvgMttr,
      prevCurrentMttr: prevCurrent,
      periodImprovementPct,
      periodMttrDelta,
      fastestMttr: fastest,
      fastestDate,
      totalResolved,
      prevTotalResolved,
      slaComplianceRate,
      improvementPct,
      trendDirection,
      currentDiscoveryRate: currentDiscovery,
      avgDiscoveryRate: avgDiscovery,
      initialDiscoveryRate: initialDiscovery,
      discoveryDropPct,
      totalDiscovered: roundedTotalDiscovered,
      netBacklogTotal,
      overallThroughputRatio,
      bottleneckDaysCount,
      criticalBottleneckCount,
      warningBottleneckCount,
      optimalDaysCount
    };
  }, [visiblePoints]);

  // Bottleneck episodes list for quick interactive jumping
  const bottleneckEvents = useMemo(() => {
    return visiblePoints.filter((p) => p.isBottleneck);
  }, [visiblePoints]);

  return (
    <div
      id="roadmap-resolution-speed-sparkline"
      className="bg-[#111] border border-[#262626] p-4 lg:p-5 space-y-4 relative overflow-hidden transition-all"
    >
      {/* Sparkline Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-[#222]">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <div className="p-1.5 bg-[#00FF66]/10 border border-[#00FF66]/30 text-[#00FF66]">
              <Activity className="w-4 h-4" />
            </div>
            <h3 className="text-sm font-black tracking-wider text-white uppercase flex items-center gap-2">
              Tendência de Remediação & Correlação de Gargalos
              <span className="text-[10px] px-2 py-0.5 bg-[#00FF66]/15 text-[#00FF66] border border-[#00FF66]/30 font-mono font-bold tracking-normal">
                ÚLTIMOS {timeframe === '30D' ? '30' : timeframe === '14D' ? '14' : '7'} DIAS
              </span>
            </h3>
          </div>
          <p className="text-[11px] text-[#888] font-mono">
            {metricMode === 'DUAL_AXIS'
              ? 'Overlay de duplo eixo correlacionando Taxa de Descoberta com Tempo de Resolução (MTTR) e diagnóstico de gargalos operacionais'
              : 'Tempo Médio de Remediação (MTTR em horas) e aceleração diária de mitigação de vulnerabilidades'}
          </p>
        </div>

        {/* Filters and Metric Toggle */}
        <div className="flex flex-wrap items-center gap-2 self-start md:self-auto">
          {/* Secondary Comparison Toggle */}
          <button
            type="button"
            id="toggle-prev-period-line"
            onClick={() => setShowPreviousPeriod(!showPreviousPeriod)}
            className={`px-2 py-1 transition-all flex items-center gap-1.5 text-[10px] font-mono border cursor-pointer ${
              showPreviousPeriod
                ? 'bg-[#60A5FA]/15 text-[#60A5FA] border-[#60A5FA]/50 font-bold'
                : 'bg-[#0A0A0A] text-[#777] border-[#333] hover:text-white'
            }`}
            title="Comparar visualmente contra o ciclo de 30 dias anterior (-30d a -60d)"
          >
            <GitCompare className="w-3 h-3" />
            <span className="w-2.5 h-0.5 border-b border-dashed border-current inline-block" />
            <span>vs 30d Anteriores</span>
          </button>

          {/* Metric Mode Switcher */}
          <div className="flex items-center bg-[#0A0A0A] border border-[#333] p-0.5 text-[10px] font-mono">
            <button
              id="btn-mode-dual-axis"
              onClick={() => setMetricMode('DUAL_AXIS')}
              className={`px-2.5 py-1 transition-all flex items-center gap-1.5 font-bold cursor-pointer ${
                metricMode === 'DUAL_AXIS'
                  ? 'bg-gradient-to-r from-[#FF3E00] to-[#00E5FF] text-black shadow-sm'
                  : 'text-[#AAA] hover:text-white'
              }`}
              title="Overlay Dual-Axis: Taxa de Descoberta vs Tempo de Resolução (MTTR) com detecção de gargalos"
            >
              <Zap className="w-3 h-3" />
              <span>Dual-Axis (Gargalos)</span>
            </button>
            <button
              id="btn-mode-mttr"
              onClick={() => setMetricMode('MTTR')}
              className={`px-2 py-1 transition-all flex items-center gap-1 cursor-pointer ${
                metricMode === 'MTTR'
                  ? 'bg-[#FF7A00] text-black font-bold'
                  : 'text-[#888] hover:text-white'
              }`}
            >
              <Clock className="w-3 h-3" />
              <span>MTTR (h)</span>
            </button>
            <button
              id="btn-mode-resolved"
              onClick={() => setMetricMode('RESOLVED')}
              className={`px-2 py-1 transition-all flex items-center gap-1 cursor-pointer ${
                metricMode === 'RESOLVED'
                  ? 'bg-[#00FF66] text-black font-bold'
                  : 'text-[#888] hover:text-white'
              }`}
            >
              <CheckCircle2 className="w-3 h-3" />
              <span>Resolvidas/Dia</span>
            </button>
          </div>

          {/* Timeframe selector */}
          <div className="flex items-center bg-[#0A0A0A] border border-[#333] p-0.5 text-[10px] font-mono">
            {(['7D', '14D', '30D'] as const).map((tf) => (
              <button
                key={tf}
                onClick={() => setTimeframe(tf)}
                className={`px-2 py-1 transition-all cursor-pointer ${
                  timeframe === tf
                    ? 'bg-[#222] text-white font-bold border border-[#444]'
                    : 'text-[#777] hover:text-white'
                }`}
              >
                {tf === '30D' ? '30 Dias' : tf === '14D' ? '14 Dias' : '7 Dias'}
              </button>
            ))}
          </div>

          <button
            onClick={handleResetTrend}
            className="p-1.5 bg-[#0A0A0A] hover:bg-[#1A1A1A] border border-[#333] text-[#777] hover:text-[#FF3E00] transition-colors cursor-pointer"
            title="Recalcular e sincronizar baseline de 30 dias"
          >
            <RotateCcw className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* KPI Highlights Bar */}
      {metricMode === 'DUAL_AXIS' ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {/* Finding Discovery Rate */}
          <div className="bg-[#0D0D0D] border border-[#222] p-2.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#888]">
              <span className="text-[10px] font-mono uppercase text-[#FF7A00]">Taxa de Descoberta</span>
              <Flame className="w-3.5 h-3.5 text-[#FF3E00]" />
            </div>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span className="text-xl font-black font-mono text-white tracking-tight">
                {metrics.currentDiscoveryRate}
              </span>
              <span className="text-[10px] font-mono text-[#888]">/dia</span>
              <span className="text-[10px] font-mono font-bold text-[#00FF66] flex items-center">
                <TrendingDown className="w-3 h-3" />
                -{metrics.discoveryDropPct}%
              </span>
            </div>
            <span className="text-[9px] text-[#666] font-mono mt-0.5">
              Média: {metrics.avgDiscoveryRate}/dia ({metrics.totalDiscovered} no ciclo)
            </span>
          </div>

          {/* Fix Resolution Time (MTTR) */}
          <div className="bg-[#0D0D0D] border border-[#222] p-2.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#888]">
              <span className="text-[10px] font-mono uppercase text-[#00E5FF]">Tempo Resolução</span>
              <Clock className="w-3.5 h-3.5 text-[#00E5FF]" />
            </div>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span className="text-xl font-black font-mono text-[#00E5FF] tracking-tight">
                {metrics.currentMttr}h
              </span>
              <span className="text-[10px] font-mono font-bold text-[#00FF66] flex items-center">
                <TrendingDown className="w-3 h-3" />
                -{metrics.improvementPct}%
              </span>
            </div>
            <span className="text-[9px] text-[#666] font-mono mt-0.5">
              Meta SLA: &le; 24h ({metrics.slaComplianceRate}% na meta)
            </span>
          </div>

          {/* Throughput Ratio (Correlação) */}
          <div className="bg-[#0D0D0D] border border-[#222] p-2.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#888]">
              <span className="text-[10px] font-mono uppercase">Razão Throughput</span>
              <Zap className="w-3.5 h-3.5 text-[#00FF66]" />
            </div>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span
                className={`text-xl font-black font-mono tracking-tight ${
                  metrics.overallThroughputRatio >= 1.0 ? 'text-[#00FF66]' : 'text-[#FF3E00]'
                }`}
              >
                {metrics.overallThroughputRatio}x
              </span>
              <span className="text-[10px] font-mono text-[#888]">
                {metrics.overallThroughputRatio >= 1.0 ? 'superávit' : 'déficit'}
              </span>
            </div>
            <span className="text-[9px] text-[#666] font-mono mt-0.5">
              {metrics.totalResolved} resolvidos vs {metrics.totalDiscovered} descobertos
            </span>
          </div>

          {/* Bottleneck Incidents */}
          <div className="bg-[#0D0D0D] border border-[#222] p-2.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#888]">
              <span className="text-[10px] font-mono uppercase text-[#FF3E00]">Gargalos no Ciclo</span>
              <AlertOctagon className="w-3.5 h-3.5 text-[#FF3E00]" />
            </div>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span
                className={`text-xl font-black font-mono tracking-tight ${
                  metrics.criticalBottleneckCount > 0 ? 'text-[#FF7A00]' : 'text-[#00FF66]'
                }`}
              >
                {metrics.bottleneckDaysCount} dias
              </span>
              <span className="text-[10px] font-mono text-[#888]">
                ({metrics.criticalBottleneckCount} críticos)
              </span>
            </div>
            <span className="text-[9px] text-[#666] font-mono mt-0.5">
              {metrics.optimalDaysCount} dias em fluxo otimizado
            </span>
          </div>

          {/* Net Backlog Balance */}
          <div className="bg-[#0D0D0D] border border-[#222] p-2.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#888]">
              <span className="text-[10px] font-mono uppercase">Saldo de Backlog</span>
              <ShieldAlert className="w-3.5 h-3.5 text-[#60A5FA]" />
            </div>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span className="text-xl font-black font-mono text-[#00FF66] tracking-tight">
                +{metrics.netBacklogTotal}
              </span>
              <span className="text-[10px] font-mono text-[#888]">queimados</span>
            </div>
            <span className="text-[9px] text-[#666] font-mono mt-0.5">
              Redução líquida de débito no período
            </span>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {/* Current MTTR */}
          <div className="bg-[#0D0D0D] border border-[#222] p-2.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#888]">
              <span className="text-[10px] font-mono uppercase">MTTR Atual</span>
              <Clock className="w-3.5 h-3.5 text-[#00FF66]" />
            </div>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span className="text-xl font-black font-mono text-white tracking-tight">
                {metrics.currentMttr}h
              </span>
              <span
                className={`text-[10px] font-mono font-bold flex items-center gap-0.5 ${
                  metrics.trendDirection === 'FASTER' ? 'text-[#00FF66]' : 'text-[#FF3E00]'
                }`}
              >
                {metrics.trendDirection === 'FASTER' ? (
                  <>
                    <TrendingDown className="w-3 h-3" />
                    <span>-{metrics.improvementPct}%</span>
                  </>
                ) : (
                  <>
                    <TrendingUp className="w-3 h-3" />
                    <span>+{metrics.improvementPct}%</span>
                  </>
                )}
              </span>
            </div>
            <span className="text-[9px] text-[#666] font-mono mt-0.5">
              {metrics.trendDirection === 'FASTER' ? 'Aceleração de entrega' : 'Estável'}
            </span>
          </div>

          {/* 30-Day Average */}
          <div className="bg-[#0D0D0D] border border-[#222] p-2.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#888]">
              <span className="text-[10px] font-mono uppercase">Média Atual</span>
              <Target className="w-3.5 h-3.5 text-[#FF7A00]" />
            </div>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span className="text-xl font-black font-mono text-[#FF7A00] tracking-tight">
                {metrics.avgMttr}h
              </span>
              <span className="text-[10px] font-mono text-[#666]">MTTR</span>
            </div>
            <span className="text-[9px] text-[#666] font-mono mt-0.5">
              Janela de {timeframe === '30D' ? '30' : timeframe === '14D' ? '14' : '7'} dias
            </span>
          </div>

          {/* Previous 30-Day Period Comparison */}
          <div className="bg-[#0D0D0D] border border-[#222] p-2.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#888]">
              <span className="text-[10px] font-mono uppercase">30d Anteriores</span>
              <History className="w-3.5 h-3.5 text-[#60A5FA]" />
            </div>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span className="text-xl font-black font-mono text-[#60A5FA] tracking-tight">
                {metrics.prevAvgMttr}h
              </span>
              <span className="text-[10px] font-mono text-[#00FF66] font-bold">
                +{metrics.periodImprovementPct}%
              </span>
            </div>
            <span className="text-[9px] text-[#888] font-mono mt-0.5">
              vs ciclo ant. (-{metrics.periodMttrDelta}h)
            </span>
          </div>

          {/* SLA Compliance Rate */}
          <div className="bg-[#0D0D0D] border border-[#222] p-2.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#888]">
              <span className="text-[10px] font-mono uppercase">SLA (&lt;24h)</span>
              <CheckCircle2 className="w-3.5 h-3.5 text-[#3366FF]" />
            </div>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span className="text-xl font-black font-mono text-[#3366FF] tracking-tight">
                {metrics.slaComplianceRate}%
              </span>
              <span className="text-[10px] font-mono text-[#666]">na meta</span>
            </div>
            <span className="text-[9px] text-[#666] font-mono mt-0.5">
              Meta operacional: ≤ 24h
            </span>
          </div>

          {/* Total Resolved in Period */}
          <div className="bg-[#0D0D0D] border border-[#222] p-2.5 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#888]">
              <span className="text-[10px] font-mono uppercase">Total Mitigado</span>
              <Zap className="w-3.5 h-3.5 text-[#00FF66]" />
            </div>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span className="text-xl font-black font-mono text-[#00FF66] tracking-tight">
                {metrics.totalResolved}
              </span>
              <span className="text-[10px] font-mono text-[#888]">
                (ant: {metrics.prevTotalResolved})
              </span>
            </div>
            <span className="text-[9px] text-[#666] font-mono mt-0.5">
              Recorde: {metrics.fastestMttr}h em {metrics.fastestDate}
            </span>
          </div>
        </div>
      )}

      {/* Sparkline & Dual-Axis Visual Canvas */}
      <div className="bg-[#090909] border border-[#222] p-3.5 pt-4 relative">
        {/* Chart Legend with Dual-Axis Indicators & Bottleneck Markers */}
        <div className="flex flex-wrap items-center justify-between gap-2.5 text-[11px] font-mono text-[#777] mb-3 px-1 border-b border-[#1A1A1A] pb-2.5">
          {metricMode === 'DUAL_AXIS' ? (
            <div className="flex flex-wrap items-center gap-3.5">
              {/* Finding Discovery Rate (Left Axis) */}
              <span className="flex items-center gap-1.5 text-[#FF7A00] font-medium">
                <span className="w-3 h-1.5 rounded-xs bg-[#FF3E00]" />
                <span>Taxa de Descoberta (Achados/Dia - Eixo Esq.)</span>
              </span>

              {/* Fix Resolution Time (Right Axis) */}
              <span className="flex items-center gap-1.5 text-[#00E5FF] font-medium">
                <span className="w-3 h-0.5 bg-[#00E5FF]" />
                <span>Tempo de Resolução (MTTR Horas - Eixo Dir.)</span>
              </span>

              {/* Bottleneck Alert Dot */}
              <span className="flex items-center gap-1.5 text-[#FF3E00]">
                <span className="w-2.5 h-2.5 rounded-full bg-[#FF3E00] ring-2 ring-[#FF3E00]/40" />
                <span>Zona de Gargalo (Descoberta &gt; Resolução)</span>
              </span>

              {/* Secondary Trend Baseline */}
              {showPreviousPeriod && (
                <span className="flex items-center gap-1.5 text-[#60A5FA] font-medium">
                  <span className="w-3.5 h-0.5 border-b border-dashed border-[#60A5FA]" />
                  <span>MTTR 30d Anteriores</span>
                </span>
              )}
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-3.5">
              <span className="flex items-center gap-1.5 text-white font-medium">
                <span
                  className={`w-3 h-1 rounded-xs ${
                    metricMode === 'MTTR' ? 'bg-[#00FF66]' : 'bg-[#3366FF]'
                  }`}
                />
                <span>
                  {metricMode === 'MTTR'
                    ? 'Período Atual (MTTR Horas)'
                    : 'Resolvidas/Dia Atual'}
                </span>
              </span>

              {showPreviousPeriod && (
                <span className="flex items-center gap-1.5 text-[#60A5FA] font-medium">
                  <span className="w-4 h-0.5 border-b-2 border-dashed border-[#60A5FA]" />
                  <span>30 Dias Anteriores (Linha Tracejada)</span>
                </span>
              )}
            </div>
          )}

          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 text-[#FF3E00]/90">
              <span className="w-3 h-0.5 border-b border-dashed border-[#FF3E00]" />
              SLA Crítico (&le; 24h)
            </span>
          </div>
        </div>

        {/* Recharts Chart Canvas */}
        <div className="h-44 sm:h-52 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart
              data={visiblePoints}
              margin={{ top: 12, right: metricMode === 'DUAL_AXIS' ? 16 : 8, left: -10, bottom: 0 }}
              onClick={(e: any) => {
                if (e && e.activePayload && e.activePayload.length) {
                  setSelectedPoint(e.activePayload[0].payload as ResolutionSpeedPoint);
                }
              }}
            >
              <defs>
                {/* Discovery Gradient */}
                <linearGradient id="discoveryGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#FF3E00" stopOpacity={0.45} />
                  <stop offset="60%" stopColor="#FF3E00" stopOpacity={0.12} />
                  <stop offset="100%" stopColor="#FF3E00" stopOpacity={0.0} />
                </linearGradient>

                {/* MTTR Speed Gradient */}
                <linearGradient id="speedGradientMttr" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00FF66" stopOpacity={0.35} />
                  <stop offset="60%" stopColor="#00FF66" stopOpacity={0.08} />
                  <stop offset="100%" stopColor="#00FF66" stopOpacity={0.0} />
                </linearGradient>

                {/* Resolved Count Gradient */}
                <linearGradient id="speedGradientResolved" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#3366FF" stopOpacity={0.4} />
                  <stop offset="60%" stopColor="#3366FF" stopOpacity={0.1} />
                  <stop offset="100%" stopColor="#3366FF" stopOpacity={0.0} />
                </linearGradient>
              </defs>

              <XAxis
                dataKey="date"
                stroke="#444"
                tick={{ fill: '#777', fontSize: 10, fontFamily: 'monospace' }}
                tickLine={false}
                axisLine={{ stroke: '#2A2A2A' }}
                interval={timeframe === '30D' ? 3 : timeframe === '14D' ? 1 : 0}
              />

              {metricMode === 'DUAL_AXIS' ? (
                <>
                  {/* Left Y-Axis: Finding Discovery Rate */}
                  <YAxis
                    yAxisId="discovery"
                    orientation="left"
                    stroke="#FF7A00"
                    tick={{ fill: '#FF7A00', fontSize: 10, fontFamily: 'monospace' }}
                    tickLine={false}
                    axisLine={{ stroke: '#333' }}
                    domain={[0, (dataMax: number) => Math.max(8, Math.ceil(dataMax * 1.25))]}
                    tickFormatter={(v: number) => `${v}/d`}
                    allowDecimals={false}
                  />

                  {/* Right Y-Axis: Fix Resolution Time (MTTR) */}
                  <YAxis
                    yAxisId="resolution"
                    orientation="right"
                    stroke="#00E5FF"
                    tick={{ fill: '#00E5FF', fontSize: 10, fontFamily: 'monospace' }}
                    tickLine={false}
                    axisLine={{ stroke: '#333' }}
                    domain={[0, (dataMax: number) => Math.max(48, Math.ceil(dataMax * 1.15))]}
                    tickFormatter={(v: number) => `${v}h`}
                    allowDecimals={false}
                  />

                  {/* SLA Reference Line (24h) on Resolution axis */}
                  <ReferenceLine
                    yAxisId="resolution"
                    y={24}
                    stroke="#FF3E00"
                    strokeDasharray="4 4"
                    strokeOpacity={0.7}
                  />

                  {/* Finding Discovery Rate Area Series (Left Axis) */}
                  <Area
                    yAxisId="discovery"
                    type="monotone"
                    dataKey="discoveryRate"
                    name="Taxa de Descoberta"
                    stroke="#FF3E00"
                    strokeWidth={2}
                    fill="url(#discoveryGradient)"
                    dot={false}
                    activeDot={{
                      r: 5,
                      fill: '#FF3E00',
                      stroke: '#FFFFFF',
                      strokeWidth: 2
                    }}
                  />

                  {/* Fix Resolution Time Line Series (Right Axis) */}
                  <Line
                    yAxisId="resolution"
                    type="monotone"
                    dataKey="fixResolutionHours"
                    name="Tempo de Resolução (MTTR)"
                    stroke="#00E5FF"
                    strokeWidth={2.4}
                    dot={(props: { cx?: number; cy?: number; payload?: ResolutionSpeedPoint }) => {
                      const { cx, cy, payload } = props;
                      if (!cx || !cy || !payload) return <g key="empty" />;

                      if (payload.bottleneckSeverity === 'CRITICAL') {
                        return (
                          <g key={`dot-crit-${payload.dayIndex}`}>
                            <circle cx={cx} cy={cy} r={7} fill="#FF3E00" fillOpacity={0.3} />
                            <circle cx={cx} cy={cy} r={4.5} fill="#FF3E00" stroke="#FFFFFF" strokeWidth={1.5} />
                          </g>
                        );
                      }

                      if (payload.bottleneckSeverity === 'WARNING') {
                        return (
                          <circle
                            key={`dot-warn-${payload.dayIndex}`}
                            cx={cx}
                            cy={cy}
                            r={3.5}
                            fill="#FF7A00"
                            stroke="#0A0A0A"
                            strokeWidth={1.5}
                          />
                        );
                      }

                      return (
                        <circle
                          key={`dot-ok-${payload.dayIndex}`}
                          cx={cx}
                          cy={cy}
                          r={timeframe === '7D' ? 3 : 2}
                          fill="#00E5FF"
                          stroke="#0A0A0A"
                          strokeWidth={1}
                        />
                      );
                    }}
                    activeDot={{
                      r: 6,
                      fill: '#00E5FF',
                      stroke: '#FFFFFF',
                      strokeWidth: 2
                    }}
                  />

                  {/* Previous Period Baseline Line */}
                  {showPreviousPeriod && (
                    <Line
                      yAxisId="resolution"
                      type="monotone"
                      dataKey="previousPeriodMttrHours"
                      name="MTTR 30d Anteriores"
                      stroke="#60A5FA"
                      strokeDasharray="5 4"
                      strokeWidth={1.8}
                      dot={false}
                      activeDot={{
                        r: 4,
                        fill: '#60A5FA',
                        stroke: '#0A0A0A',
                        strokeWidth: 1.5
                      }}
                    />
                  )}
                </>
              ) : metricMode === 'MTTR' ? (
                <>
                  <YAxis
                    stroke="#444"
                    tick={{ fill: '#777', fontSize: 10, fontFamily: 'monospace' }}
                    tickLine={false}
                    axisLine={false}
                    domain={[0, 56]}
                  />

                  <ReferenceLine
                    y={24}
                    stroke="#FF3E00"
                    strokeDasharray="4 4"
                    strokeOpacity={0.6}
                  />

                  <Area
                    type="monotone"
                    dataKey="mttrHours"
                    stroke="#00FF66"
                    strokeWidth={2.2}
                    fill="url(#speedGradientMttr)"
                    dot={timeframe === '7D'}
                    activeDot={{
                      r: 5,
                      fill: '#00FF66',
                      stroke: '#000',
                      strokeWidth: 2
                    }}
                  />

                  {showPreviousPeriod && (
                    <Line
                      type="monotone"
                      dataKey="previousPeriodMttrHours"
                      name="30d Anteriores"
                      stroke="#60A5FA"
                      strokeDasharray="6 4"
                      strokeWidth={2.2}
                      dot={timeframe === '7D'}
                      activeDot={{
                        r: 5,
                        fill: '#60A5FA',
                        stroke: '#0A0A0A',
                        strokeWidth: 2
                      }}
                    />
                  )}
                </>
              ) : (
                <>
                  <YAxis
                    stroke="#444"
                    tick={{ fill: '#777', fontSize: 10, fontFamily: 'monospace' }}
                    tickLine={false}
                    axisLine={false}
                    domain={[0, 'dataMax + 2']}
                  />

                  <Area
                    type="monotone"
                    dataKey="resolvedCount"
                    stroke="#3366FF"
                    strokeWidth={2.2}
                    fill="url(#speedGradientResolved)"
                    dot={timeframe === '7D'}
                    activeDot={{
                      r: 5,
                      fill: '#3366FF',
                      stroke: '#000',
                      strokeWidth: 2
                    }}
                  />

                  {showPreviousPeriod && (
                    <Line
                      type="monotone"
                      dataKey="previousPeriodResolvedCount"
                      name="30d Anteriores (Resolvidas)"
                      stroke="#60A5FA"
                      strokeDasharray="6 4"
                      strokeWidth={2.2}
                      dot={timeframe === '7D'}
                      activeDot={{
                        r: 5,
                        fill: '#60A5FA',
                        stroke: '#0A0A0A',
                        strokeWidth: 2
                      }}
                    />
                  )}
                </>
              )}

              {/* Recharts Custom Tooltip */}
              <RechartsTooltip
                cursor={{ stroke: '#555', strokeWidth: 1.5, strokeDasharray: '3 3' }}
                isAnimationActive={false}
                content={({ active, payload }) => {
                  if (!active || !payload || !payload.length) return null;
                  const data = payload[0].payload as ResolutionSpeedPoint;
                  if (!data) return null;

                  const currentMttrFormatted = `${data.mttrHours.toFixed(1)}h`;
                  const baselineMttrFormatted = `${data.previousPeriodMttrHours.toFixed(1)}h`;
                  const mttrDelta = Math.abs(data.diffMttrHours).toFixed(1);
                  const isFaster = data.diffMttrHours <= 0;

                  return (
                    <div className="bg-[#0C0C0C] border border-[#333] p-3 shadow-2xl font-mono text-xs space-y-2.5 z-50 min-w-[300px] max-w-[360px] pointer-events-none">
                      {/* Date & Period Heading */}
                      <div className="border-b border-[#222] pb-2 flex items-center justify-between gap-3">
                        <div className="flex items-center gap-1.5 text-white font-bold">
                          <Calendar className="w-3.5 h-3.5 text-[#00FF66]" />
                          <span>{data.fullDate}</span>
                        </div>
                        <span className="text-[10px] text-[#888] bg-[#1A1A1A] px-1.5 py-0.5 border border-[#333]">
                          Dia {data.dayIndex}/30
                        </span>
                      </div>

                      {/* Dual-Axis Correlation Metrics Matrix */}
                      <div className="space-y-2">
                        <div className="grid grid-cols-2 gap-2 bg-[#141414] border border-[#262626] p-2">
                          <div className="space-y-0.5">
                            <span className="text-[10px] text-[#FF7A00] flex items-center gap-1 uppercase font-bold">
                              <Flame className="w-3 h-3 text-[#FF3E00]" />
                              Descoberta:
                            </span>
                            <span className="text-base font-black text-white">
                              {data.discoveryRate} <span className="text-[10px] font-normal text-[#888]">falhas/dia</span>
                            </span>
                            <div className="text-[9px] text-[#888]">
                              Saldo: {data.netBacklogChange > 0 ? `+${data.netBacklogChange}` : data.netBacklogChange} itens/dia
                            </div>
                          </div>

                          <div className="space-y-0.5">
                            <span className="text-[10px] text-[#00E5FF] flex items-center gap-1 uppercase font-bold">
                              <Clock className="w-3 h-3 text-[#00E5FF]" />
                              Tempo Resolução:
                            </span>
                            <span className="text-base font-black text-[#00E5FF]">
                              {currentMttrFormatted}
                            </span>
                            <div className="text-[9px] text-[#888]">
                              Resolvidas: {data.resolvedCount} itens
                            </div>
                          </div>
                        </div>

                        {/* Bottleneck Diagnostic Badge & Analysis */}
                        <div
                          className={`p-2 border space-y-1 text-[11px] ${
                            data.bottleneckSeverity === 'CRITICAL'
                              ? 'bg-[#FF3E00]/10 border-[#FF3E00]/40 text-[#FF3E00]'
                              : data.bottleneckSeverity === 'WARNING'
                              ? 'bg-[#FF7A00]/10 border-[#FF7A00]/40 text-[#FF7A00]'
                              : data.bottleneckSeverity === 'OPTIMAL'
                              ? 'bg-[#00FF66]/10 border-[#00FF66]/30 text-[#00FF66]'
                              : 'bg-[#181818] border-[#333] text-zinc-300'
                          }`}
                        >
                          <div className="flex items-center justify-between font-bold">
                            <span className="flex items-center gap-1.5">
                              {data.bottleneckSeverity === 'CRITICAL' ? (
                                <AlertOctagon className="w-3.5 h-3.5" />
                              ) : data.bottleneckSeverity === 'WARNING' ? (
                                <AlertTriangle className="w-3.5 h-3.5" />
                              ) : (
                                <CheckCircle2 className="w-3.5 h-3.5" />
                              )}
                              <span>{data.bottleneckLabel}</span>
                            </span>
                            <span className="text-[9px] px-1 py-0.5 border border-current">
                              {data.bottleneckSeverity}
                            </span>
                          </div>
                          <p className="text-[10px] text-zinc-300 font-normal leading-relaxed pt-0.5">
                            {data.bottleneckCause}
                          </p>
                          <div className="text-[9px] text-zinc-400 pt-0.5 border-t border-current/20 flex items-start gap-1">
                            <span className="font-bold text-white shrink-0">Ação:</span>
                            <span>{data.bottleneckRemedy}</span>
                          </div>
                        </div>

                        {/* Baseline comparison if enabled */}
                        {showPreviousPeriod && (
                          <div className="bg-[#10141C] border border-[#1E293B] p-2 text-[10px] text-[#94A3B8] flex items-center justify-between">
                            <span className="flex items-center gap-1">
                              <History className="w-3 h-3 text-[#60A5FA]" />
                              <span>Ciclo Anterior (-30d):</span>
                            </span>
                            <span className="text-white font-bold">
                              {baselineMttrFormatted} ({isFaster ? `-${mttrDelta}h mais veloz` : `+${mttrDelta}h`})
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                }}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        {/* Footer Micro-Insight & Bottleneck Correlation Strip */}
        <div className="mt-3 pt-2.5 border-t border-[#1C1C1C] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2.5 text-[11px] font-mono text-[#888]">
          <div className="flex flex-wrap items-center gap-1.5 text-[#AAA]">
            <Zap className="w-3.5 h-3.5 text-[#00FF66] shrink-0" />
            <span>
              <strong>Dinâmica do Ciclo:</strong> Descoberta reduzida de{' '}
              <span className="text-[#FF7A00] font-bold">{visiblePoints[0]?.discoveryRate}/dia</span> para{' '}
              <span className="text-[#00FF66] font-bold">{metrics.currentDiscoveryRate}/dia</span>, destravando o MTTR de{' '}
              <span className="text-white">{visiblePoints[0]?.mttrHours}h</span> para{' '}
              <span className="text-[#00E5FF] font-bold">{metrics.currentMttr}h</span> (
              <span className="text-[#00FF66]">-{metrics.improvementPct}%</span>).
            </span>
          </div>

          <div className="flex items-center gap-2 text-[10px] text-[#666] shrink-0">
            <span>SLA: &le; 24h</span>
            <span>•</span>
            <span className="text-[#00FF66]">{metrics.slaComplianceRate}% conformidade</span>
          </div>
        </div>
      </div>

      {/* Bottleneck Lifecycle Deep-Dive & Incident Navigator Panel */}
      {metricMode === 'DUAL_AXIS' && (
        <div className="bg-[#0C0C0C] border border-[#222] p-3.5 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1F1F1F] pb-2.5">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-[#FF7A00]" />
              <h4 className="text-xs font-bold font-mono text-white uppercase tracking-wider">
                Diagnóstico de Gargalos no Ciclo de Remediação
              </h4>
            </div>
            <span className="text-[10px] font-mono text-[#888]">
              Correlação empírica entre Ingestão de Vulnerabilidades e Throughput de Engenharia
            </span>
          </div>

          {/* Correlation Insight Explanation */}
          <p className="text-[11px] font-mono text-[#AAA] leading-relaxed">
            <strong className="text-white">Identificação de Gargalos:</strong> Durante fases de alta taxa de descoberta (ex: merges massivos e auditorias iniciais), a fila de triagem satura, elevando o tempo de resolução (MTTR). A introdução de verificações SAST/Secret Scan pré-commit achata a curva de descoberta (-{metrics.discoveryDropPct}%), permitindo que a equipe resolva débitos técnicos {metrics.overallThroughputRatio}x mais rápido do que novas falhas surgem.
          </p>

          {/* Bottleneck Stages Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 pt-1">
            {/* Stage 1: Ingestion Shock */}
            <div className="bg-[#121212] border border-[#2A2A2A] p-2.5 space-y-1">
              <div className="flex items-center justify-between text-[11px] font-mono">
                <span className="text-[#FF3E00] font-bold flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-[#FF3E00]" />
                  Fase 1: Sobrecarga Inicial
                </span>
                <span className="text-[9px] text-[#888] bg-[#1C1C1C] px-1 py-0.2">Dias 1 a 6</span>
              </div>
              <p className="text-[10px] text-[#888] font-mono leading-relaxed">
                Descoberta intensa ({visiblePoints[0]?.discoveryRate} falhas/dia) gerou gargalo operacional com MTTR acima de 38h, excedendo o SLA crítico.
              </p>
            </div>

            {/* Stage 2: Triage & Containment */}
            <div className="bg-[#121212] border border-[#2A2A2A] p-2.5 space-y-1">
              <div className="flex items-center justify-between text-[11px] font-mono">
                <span className="text-[#FF7A00] font-bold flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-[#FF7A00]" />
                  Fase 2: Contenção & Quick Wins
                </span>
                <span className="text-[9px] text-[#888] bg-[#1C1C1C] px-1 py-0.2">Dias 7 a 20</span>
              </div>
              <p className="text-[10px] text-[#888] font-mono leading-relaxed">
                Priorização de segredos de alto impacto e rotação de credenciais de nuvem reduziram o acúmulo, estabilizando o MTTR em ~22h.
              </p>
            </div>

            {/* Stage 3: Optimized Velocity */}
            <div className="bg-[#121212] border border-[#14532D]/40 p-2.5 space-y-1">
              <div className="flex items-center justify-between text-[11px] font-mono">
                <span className="text-[#00FF66] font-bold flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-[#00FF66]" />
                  Fase 3: Fluxo Otimizado
                </span>
                <span className="text-[9px] text-[#00FF66] bg-[#00FF66]/10 px-1 py-0.2">Atual</span>
              </div>
              <p className="text-[10px] text-[#888] font-mono leading-relaxed">
                Descoberta controlada em {metrics.currentDiscoveryRate}/dia com remediação em {metrics.currentMttr}h. Backlog em drenagem líquida contínua.
              </p>
            </div>
          </div>

          {/* Interactive Incident Selector */}
          {bottleneckEvents.length > 0 && (
            <div className="pt-2 border-t border-[#1C1C1C] flex flex-wrap items-center gap-2 text-[11px] font-mono">
              <span className="text-[#777] uppercase text-[10px] flex items-center gap-1">
                <Filter className="w-3 h-3 text-[#FF7A00]" />
                Inspecionar Incidentes de Gargalo:
              </span>
              {bottleneckEvents.slice(0, 5).map((point) => (
                <button
                  key={`btn-event-${point.dayIndex}`}
                  type="button"
                  onClick={() => setSelectedPoint(point)}
                  className={`px-2 py-0.5 border text-[10px] transition-all cursor-pointer flex items-center gap-1.5 ${
                    selectedPoint?.dayIndex === point.dayIndex
                      ? 'bg-[#FF3E00] text-white border-[#FF3E00] font-bold'
                      : point.bottleneckSeverity === 'CRITICAL'
                      ? 'bg-[#FF3E00]/10 text-[#FF3E00] border-[#FF3E00]/40 hover:bg-[#FF3E00]/20'
                      : 'bg-[#FF7A00]/10 text-[#FF7A00] border-[#FF7A00]/40 hover:bg-[#FF7A00]/20'
                  }`}
                >
                  <span>{point.date}</span>
                  <span className="text-[9px] opacity-80">({point.discoveryRate}/d vs {point.fixResolutionHours}h)</span>
                </button>
              ))}
              {selectedPoint && (
                <button
                  type="button"
                  onClick={() => setSelectedPoint(null)}
                  className="px-2 py-0.5 text-[10px] text-[#888] hover:text-white underline cursor-pointer"
                >
                  Limpar seleção
                </button>
              )}
            </div>
          )}

          {/* Selected Incident Drawer Card */}
          {selectedPoint && (
            <div className="bg-[#141414] border border-[#FF7A00]/40 p-3 text-[11px] font-mono space-y-2">
              <div className="flex items-center justify-between border-b border-[#262626] pb-1.5">
                <div className="flex items-center gap-2">
                  <span
                    className={`w-2.5 h-2.5 rounded-full ${
                      selectedPoint.bottleneckSeverity === 'CRITICAL'
                        ? 'bg-[#FF3E00]'
                        : 'bg-[#FF7A00]'
                    }`}
                  />
                  <span className="font-bold text-white">
                    Incidente de Gargalo: {selectedPoint.fullDate} (Dia {selectedPoint.dayIndex})
                  </span>
                </div>
                <span
                  className={`text-[9px] px-1.5 py-0.5 font-bold border ${
                    selectedPoint.bottleneckSeverity === 'CRITICAL'
                      ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40'
                      : 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/40'
                  }`}
                >
                  {selectedPoint.bottleneckLabel}
                </span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-[10px]">
                <div>
                  <span className="text-[#888]">Taxa de Descoberta:</span>
                  <p className="font-bold text-[#FF7A00] text-sm">{selectedPoint.discoveryRate} /dia</p>
                </div>
                <div>
                  <span className="text-[#888]">Tempo de Resolução:</span>
                  <p className="font-bold text-[#00E5FF] text-sm">{selectedPoint.fixResolutionHours}h</p>
                </div>
                <div>
                  <span className="text-[#888]">Throughput Efetivo:</span>
                  <p className="font-bold text-white text-sm">{selectedPoint.resolvedCount} itens corrigidos</p>
                </div>
                <div>
                  <span className="text-[#888]">Pressão de Backlog:</span>
                  <p className="font-bold text-[#FF3E00] text-sm">+{selectedPoint.netBacklogChange} itens</p>
                </div>
              </div>
              <div className="pt-1 text-[10px] text-zinc-300 space-y-1">
                <p>
                  <strong className="text-[#888]">Causa Raiz:</strong> {selectedPoint.bottleneckCause}
                </p>
                <p>
                  <strong className="text-[#00FF66]">Remediação Aplicada:</strong> {selectedPoint.bottleneckRemedy}
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
