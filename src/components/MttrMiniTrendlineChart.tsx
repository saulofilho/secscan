import React, { useState, useMemo } from 'react';
import {
  AreaChart,
  Area,
  Line,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  ReferenceLine,
  YAxis,
  XAxis
} from 'recharts';
import {
  Clock,
  TrendingDown,
  TrendingUp,
  Minus,
  Sliders,
  GitCompare,
  Layers,
  History,
  ChevronDown
} from 'lucide-react';
import { SecScanGlobalConfig } from '../types';
import { ValidationSeverityDistribution } from './ValidationSeverityDonutChart';
import { safeGetItem, safeSetItem } from '../lib/storage';

export interface MttrScanHistoryPoint {
  scanIndex: number;
  scanLabel: string;
  timeLabel: string;
  timestamp: string;
  criticalCount: number;
  highCount: number;
  warningCount: number;
  totalFindings: number;
  averageMttrHours: number;      // Average MTTR in hours per finding
  totalBacklogHours: number;     // Total estimated remediation hours for the backlog
  criticalMttrHours: number;     // Total hours for critical findings
  highMttrHours: number;         // Total hours for high findings
  warningMttrHours: number;      // Total hours for warning findings
  criticalUnitHours: number;     // Unit MTTR per critical finding
  highUnitHours: number;         // Unit MTTR per high finding
  warningUnitHours: number;      // Unit MTTR per warning finding
  isCurrent?: boolean;
}

export type MttrTrendViewMode = 'AVERAGE' | 'TOTAL';
export type MttrTimeRange = '5' | '10' | 'all';

interface MttrMiniTrendlineChartProps {
  distribution: ValidationSeverityDistribution;
  config: SecScanGlobalConfig;
  fileSetKey?: string;
  onOpenMttrConfig?: () => void;
  onSelectScan?: (point: MttrScanHistoryPoint) => void;
}

const MTTR_HISTORY_STORAGE_KEY = 'secscan_mttr_history_v1';
const MTTR_TIMERANGE_STORAGE_KEY = 'secscan_mttr_timerange_v1';

/**
 * Extracts average hours from a remediation string (e.g. "1.5h – 2h" -> 1.75, "30m – 1h" -> 0.75, "12h – 24h" -> 18)
 */
export function parseRemediationHours(remediationStr?: string, fallbackHours: number = 2.0): number {
  if (!remediationStr) return fallbackHours;
  const matches = Array.from(remediationStr.matchAll(/([\d.]+)\s*(h|m|d)?/gi));
  if (matches.length === 0) return fallbackHours;

  const values: number[] = [];
  for (const match of matches) {
    const num = parseFloat(match[1]);
    const unit = (match[2] || 'h').toLowerCase();
    if (isNaN(num)) continue;
    if (unit === 'm') values.push(num / 60);
    else if (unit === 'd') values.push(num * 24);
    else values.push(num);
  }

  if (values.length === 0) return fallbackHours;
  const sum = values.reduce((acc, curr) => acc + curr, 0);
  return Number((sum / values.length).toFixed(2));
}

/**
 * Generates sequential baseline scan runs showing realistic resolution over time
 */
function generateBaselineMttrRuns(
  distribution: ValidationSeverityDistribution,
  config: SecScanGlobalConfig,
  totalCount: number = 12
): MttrScanHistoryPoint[] {
  const critHours = parseRemediationHours(
    config.severityConfig?.CRITICAL?.remediationTime || config.remediationTime?.CRITICAL,
    1.75
  );
  const highHours = parseRemediationHours(
    config.severityConfig?.HIGH?.remediationTime || config.remediationTime?.HIGH,
    5.0
  );
  const warnHours = parseRemediationHours(
    config.severityConfig?.WARNING?.remediationTime || config.remediationTime?.WARNING,
    18.0
  );

  const timesAgo = [
    'Há 4h', 'Há 3h15m', 'Há 2h30m', 'Há 1h50m', 'Há 1h20m',
    'Há 55m', 'Há 40m', 'Há 25m', 'Há 15m', 'Há 8m', 'Há 3m', 'Agora'
  ];

  // Progressive finding offsets from earliest to latest
  const offsets = [
    { crit: 5, high: 6, warn: 8 },
    { crit: 4, high: 6, warn: 7 },
    { crit: 4, high: 5, warn: 6 },
    { crit: 3, high: 5, warn: 5 },
    { crit: 3, high: 4, warn: 5 },
    { crit: 2, high: 4, warn: 4 },
    { crit: 2, high: 3, warn: 4 },
    { crit: 2, high: 2, warn: 3 },
    { crit: 1, high: 2, warn: 2 },
    { crit: 1, high: 1, warn: 1 },
    { crit: 0, high: 1, warn: 1 },
    { crit: 0, high: 0, warn: 0 },
  ];

  const startIndex = Math.max(0, offsets.length - totalCount);
  const selectedOffsets = offsets.slice(startIndex);
  const selectedTimes = timesAgo.slice(startIndex);

  return selectedOffsets.map((counts, idx) => {
    const isCurrent = idx === selectedOffsets.length - 1;
    const critCount = distribution.critical + counts.crit;
    const highCount = distribution.high + counts.high;
    const warnCount = distribution.warning + counts.warn;
    const total = critCount + highCount + warnCount;
    const critTotal = critCount * critHours;
    const highTotal = highCount * highHours;
    const warnTotal = warnCount * warnHours;
    const totalHours = critTotal + highTotal + warnTotal;
    const avgHours = total > 0 ? totalHours / total : 0;
    const scanNum = idx + 1;

    return {
      scanIndex: scanNum,
      scanLabel: isCurrent ? `Varredura #${scanNum} (Atual)` : `Varredura #${scanNum}`,
      timeLabel: selectedTimes[idx] || 'Passado',
      timestamp: new Date(Date.now() - (selectedOffsets.length - 1 - idx) * 18 * 60 * 1000).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit'
      }),
      criticalCount: critCount,
      highCount: highCount,
      warningCount: warnCount,
      totalFindings: total,
      averageMttrHours: Number(avgHours.toFixed(1)),
      totalBacklogHours: Number(totalHours.toFixed(1)),
      criticalMttrHours: Number(critTotal.toFixed(1)),
      highMttrHours: Number(highTotal.toFixed(1)),
      warningMttrHours: Number(warnTotal.toFixed(1)),
      criticalUnitHours: Number(critHours.toFixed(1)),
      highUnitHours: Number(highHours.toFixed(1)),
      warningUnitHours: Number(warnHours.toFixed(1)),
      isCurrent
    };
  });
}

export const MttrMiniTrendlineChart: React.FC<MttrMiniTrendlineChartProps> = ({
  distribution,
  config,
  fileSetKey,
  onOpenMttrConfig,
  onSelectScan
}) => {
  const [viewMode, setViewMode] = useState<MttrTrendViewMode>('AVERAGE');
  const [compareBySeverity, setCompareBySeverity] = useState<boolean>(false);
  const [timeRange, setTimeRange] = useState<MttrTimeRange>(() => {
    const saved = safeGetItem(MTTR_TIMERANGE_STORAGE_KEY);
    return saved === '5' || saved === '10' || saved === 'all' ? saved : '5';
  });

  // Parse unit remediation parameters from SecScan global config
  const unitCritHours = useMemo(() => {
    return parseRemediationHours(
      config.severityConfig?.CRITICAL?.remediationTime || config.remediationTime?.CRITICAL,
      1.75
    );
  }, [config]);

  const unitHighHours = useMemo(() => {
    return parseRemediationHours(
      config.severityConfig?.HIGH?.remediationTime || config.remediationTime?.HIGH,
      5.0
    );
  }, [config]);

  const unitWarnHours = useMemo(() => {
    return parseRemediationHours(
      config.severityConfig?.WARNING?.remediationTime || config.remediationTime?.WARNING,
      18.0
    );
  }, [config]);

  // Compute or synchronize historical timeline of scans (up to 25 scans)
  const fullTimelineData: MttrScanHistoryPoint[] = useMemo(() => {
    const raw = safeGetItem(MTTR_HISTORY_STORAGE_KEY);
    let history: MttrScanHistoryPoint[] = [];

    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed) && parsed.length > 0) {
          history = parsed;
        }
      } catch {
        // Fallback to generator
      }
    }

    if (history.length < 10) {
      history = generateBaselineMttrRuns(distribution, config, 12);
    } else {
      // Keep previous runs (up to 24) and update/append the current scan
      const past = history.slice(-24);
      const curCritTotal = distribution.critical * unitCritHours;
      const curHighTotal = distribution.high * unitHighHours;
      const curWarnTotal = distribution.warning * unitWarnHours;
      const curTotalHours = curCritTotal + curHighTotal + curWarnTotal;
      const curTotalFindings = distribution.total;
      const curAvg = curTotalFindings > 0 ? curTotalHours / curTotalFindings : 0;
      const currentScanNum = past.length + 1;

      const currentPoint: MttrScanHistoryPoint = {
        scanIndex: currentScanNum,
        scanLabel: `Varredura #${currentScanNum} (Atual)`,
        timeLabel: 'Agora',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        criticalCount: distribution.critical,
        highCount: distribution.high,
        warningCount: distribution.warning,
        totalFindings: curTotalFindings,
        averageMttrHours: Number(curAvg.toFixed(1)),
        totalBacklogHours: Number(curTotalHours.toFixed(1)),
        criticalMttrHours: Number(curCritTotal.toFixed(1)),
        highMttrHours: Number(curHighTotal.toFixed(1)),
        warningMttrHours: Number(curWarnTotal.toFixed(1)),
        criticalUnitHours: Number(unitCritHours.toFixed(1)),
        highUnitHours: Number(unitHighHours.toFixed(1)),
        warningUnitHours: Number(unitWarnHours.toFixed(1)),
        isCurrent: true
      };

      // Unmark any previous current flags in history
      const cleanPast = past.map(pt => ({ ...pt, isCurrent: false }));
      history = [...cleanPast, currentPoint];
    }

    // Persist up to 25 scans
    safeSetItem(MTTR_HISTORY_STORAGE_KEY, JSON.stringify(history.slice(-25)));
    return history;
  }, [distribution, config, unitCritHours, unitHighHours, unitWarnHours, fileSetKey]);

  // Filter timeline according to selected timeRange dropdown (Last 5, Last 10, All time)
  const displayData: MttrScanHistoryPoint[] = useMemo(() => {
    if (timeRange === '5') {
      return fullTimelineData.slice(-5);
    }
    if (timeRange === '10') {
      return fullTimelineData.slice(-10);
    }
    return fullTimelineData;
  }, [fullTimelineData, timeRange]);

  // Formatted chart points adapting to single view or 3-severity comparison
  const chartData = useMemo(() => {
    return displayData.map(pt => ({
      ...pt,
      primaryValue: viewMode === 'AVERAGE' ? pt.averageMttrHours : pt.totalBacklogHours,
      criticalValue: viewMode === 'AVERAGE' ? pt.criticalUnitHours : pt.criticalMttrHours,
      highValue: viewMode === 'AVERAGE' ? pt.highUnitHours : pt.highMttrHours,
      warningValue: viewMode === 'AVERAGE' ? pt.warningUnitHours : pt.warningMttrHours,
    }));
  }, [displayData, viewMode]);

  // Historical trend comparison across the active time window
  const initialPoint = displayData[0] || fullTimelineData[0];
  const currentPoint = displayData[displayData.length - 1] || fullTimelineData[fullTimelineData.length - 1];

  const initialMetric =
    viewMode === 'AVERAGE'
      ? initialPoint?.averageMttrHours ?? 0
      : initialPoint?.totalBacklogHours ?? 0;

  const currentMetric =
    viewMode === 'AVERAGE'
      ? currentPoint?.averageMttrHours ?? 0
      : currentPoint?.totalBacklogHours ?? 0;

  const delta = currentMetric - initialMetric;
  const percentDelta =
    initialMetric > 0
      ? Math.round(((currentMetric - initialMetric) / initialMetric) * 100)
      : currentMetric > 0
      ? 100
      : 0;

  const isImproved = delta < 0;
  const isRegressed = delta > 0;

  // Chart theme colors
  const primaryColor =
    distribution.total === 0
      ? '#10B981' // emerald-500
      : distribution.critical > 0
      ? '#F43F5E' // rose-500
      : distribution.high > 0
      ? '#F59E0B' // amber-500
      : '#38BDF8'; // sky-400

  // SLA Target line
  const slaTargetLimit = viewMode === 'AVERAGE' ? 4.0 : 15.0;

  // Dynamic subtitle based on active timeRange
  const timeRangeSubtitle =
    timeRange === '5'
      ? '(Últimas 5 Varreduras)'
      : timeRange === '10'
      ? '(Últimas 10 Varreduras)'
      : `(Histórico Completo • ${displayData.length} Varreduras)`;

  return (
    <div
      id="workspace-mttr-mini-trendline"
      className="mt-2 p-2.5 rounded-lg bg-black/50 border border-white/10 font-mono text-[10px] space-y-2 select-none"
    >
      {/* Top Header: Title, Telemetry, Dropdown Toggle & View Mode */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 min-w-0">
          <Clock className="w-3.5 h-3.5 text-sky-400 shrink-0" />
          <span className="font-bold text-white uppercase tracking-wider text-[9.5px]">
            Evolução Histórica do MTTR
          </span>
          <span className="text-zinc-500 text-[8.5px] hidden sm:inline">
            {timeRangeSubtitle}
          </span>
        </div>

        {/* Action Controls & Badges */}
        <div className="flex flex-wrap items-center gap-1.5">
          {/* Current MTTR Value Badge */}
          <div
            id="badge-current-mttr"
            className="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-white font-bold text-[9.5px] inline-flex items-center gap-1"
            title="Tempo Médio de Remediação calculado para a varredura atual"
          >
            <span className="text-zinc-400">Atual:</span>
            <span className="text-emerald-400 font-mono">
              {viewMode === 'AVERAGE'
                ? `${currentPoint?.averageMttrHours ?? 0}h`
                : `${currentPoint?.totalBacklogHours ?? 0}h tot`}
            </span>
          </div>

          {/* Trend Delta Pill */}
          <div
            id="badge-mttr-trend-delta"
            className={`px-1.5 py-0.5 rounded text-[9px] font-bold border inline-flex items-center gap-0.5 ${
              isImproved
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                : isRegressed
                ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                : 'bg-zinc-800 text-zinc-300 border-zinc-700'
            }`}
            title={`Variação do MTTR no período selecionado: ${
              isImproved ? 'Tempo de resolução otimizado' : isRegressed ? 'Aumento no tempo estimado' : 'Tempo estável'
            }`}
          >
            {isImproved && <TrendingDown className="w-2.5 h-2.5 text-emerald-400" />}
            {isRegressed && <TrendingUp className="w-2.5 h-2.5 text-rose-400" />}
            {!isImproved && !isRegressed && <Minus className="w-2.5 h-2.5 text-zinc-400" />}
            <span>
              {isImproved
                ? `${percentDelta}% MTTR`
                : isRegressed
                ? `+${percentDelta}% MTTR`
                : 'Estável'}
            </span>
          </div>

          {/* Small Time-Range Dropdown (Historical Scan Depth Selector) */}
          <div
            className="relative inline-flex items-center text-[9px] font-mono"
            title="Selecionar profundidade temporal das varreduras: Últimas 5, Últimas 10 ou Histórico completo"
          >
            <History className="w-2.5 h-2.5 text-sky-400 absolute left-1.5 pointer-events-none z-10" />
            <select
              id="select-mttr-time-range"
              value={timeRange}
              onChange={(e) => {
                const val = e.target.value as MttrTimeRange;
                setTimeRange(val);
                safeSetItem(MTTR_TIMERANGE_STORAGE_KEY, val);
              }}
              className="pl-5 pr-4 py-0.5 rounded bg-black/70 hover:bg-black/90 border border-white/10 hover:border-sky-400/40 text-zinc-300 hover:text-white text-[9px] font-mono font-semibold transition-all appearance-none cursor-pointer focus:outline-none focus:ring-1 focus:ring-sky-400/50 shadow-xs"
              aria-label="Selecionar profundidade temporal do histórico de MTTR"
            >
              <option value="5" className="bg-[#111116] text-zinc-200">
                Last 5 scans (5 varreduras)
              </option>
              <option value="10" className="bg-[#111116] text-zinc-200">
                Last 10 scans (10 varreduras)
              </option>
              <option value="all" className="bg-[#111116] text-zinc-200">
                All time (Histórico completo)
              </option>
            </select>
            <ChevronDown className="w-2.5 h-2.5 text-zinc-400 absolute right-1 pointer-events-none" />
          </div>

          {/* Toggle "Comparar por severidade" button */}
          <button
            id="btn-toggle-compare-severity"
            type="button"
            onClick={() => setCompareBySeverity(prev => !prev)}
            className={`px-2 py-0.5 rounded text-[9px] font-mono font-semibold tracking-wide transition-all border cursor-pointer inline-flex items-center gap-1.5 ${
              compareBySeverity
                ? 'bg-sky-500/25 text-sky-200 border-sky-400/50 shadow-xs'
                : 'bg-white/5 text-zinc-400 border-white/10 hover:text-white hover:bg-white/10'
            }`}
            title="Sobrepor 3 linhas coloridas diferentes no mesmo gráfico: Crítico (Vermelho), Alto (Laranja) e Aviso (Amarelo)"
            aria-pressed={compareBySeverity}
          >
            <GitCompare className={`w-3 h-3 ${compareBySeverity ? 'text-sky-300' : 'text-zinc-400'}`} />
            <span>Comparar</span>
            <span
              className={`w-1.5 h-1.5 rounded-full transition-all ${
                compareBySeverity ? 'bg-sky-400 ring-2 ring-sky-400/30 animate-pulse' : 'bg-zinc-600'
              }`}
            />
          </button>

          {/* View Mode Switcher */}
          <div className="hidden xs:flex items-center rounded bg-black/60 border border-white/10 p-0.5 text-[8.5px]">
            <button
              id="btn-mttr-view-avg"
              type="button"
              onClick={() => setViewMode('AVERAGE')}
              className={`px-1.5 py-0.5 rounded transition-all cursor-pointer ${
                viewMode === 'AVERAGE'
                  ? 'bg-sky-500/20 text-sky-300 font-bold border border-sky-500/40'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
              title="Exibir Tempo Médio de Remediação por Achado (MTTR)"
            >
              MTTR Médio
            </button>
            <button
              id="btn-mttr-view-total"
              type="button"
              onClick={() => setViewMode('TOTAL')}
              className={`px-1.5 py-0.5 rounded transition-all cursor-pointer ${
                viewMode === 'TOTAL'
                  ? 'bg-sky-500/20 text-sky-300 font-bold border border-sky-500/40'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
              title="Exibir Total de Horas de Backlog"
            >
              Backlog Total
            </button>
          </div>

          {/* Quick config modal button */}
          {onOpenMttrConfig && (
            <button
              id="btn-mttr-quick-tune"
              type="button"
              onClick={onOpenMttrConfig}
              className="p-1 rounded text-zinc-400 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-colors cursor-pointer"
              title="Ajustar parâmetros de remediationTime (MTTR) do SecScan"
            >
              <Sliders className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* Multi-Severity Overlay Legend when Comparison is Active */}
      {compareBySeverity && (
        <div 
          id="mttr-compare-severity-legend"
          className="flex flex-wrap items-center justify-between gap-2 px-2 py-1 rounded bg-black/40 border border-white/5 text-[8.5px]"
        >
          <div className="flex items-center gap-1 text-zinc-400">
            <Layers className="w-3 h-3 text-sky-400" />
            <span className="font-semibold uppercase tracking-wider text-[8px]">Camadas Sobrepostas:</span>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            {/* Critical Line Legend */}
            <div className="flex items-center gap-1.5 text-rose-300">
              <span className="w-2 h-0.5 bg-rose-500 rounded-full" />
              <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shadow-sm" />
              <span className="font-bold">Crítico</span>
              <span className="text-zinc-500 text-[8px]">
                ({viewMode === 'AVERAGE' ? `${currentPoint?.criticalUnitHours ?? 0}h/achado` : `${currentPoint?.criticalMttrHours ?? 0}h tot`})
              </span>
            </div>

            {/* High Line Legend */}
            <div className="flex items-center gap-1.5 text-amber-300">
              <span className="w-2 h-0.5 bg-amber-500 rounded-full" />
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500 shadow-sm" />
              <span className="font-bold">Alto</span>
              <span className="text-zinc-500 text-[8px]">
                ({viewMode === 'AVERAGE' ? `${currentPoint?.highUnitHours ?? 0}h/achado` : `${currentPoint?.highMttrHours ?? 0}h tot`})
              </span>
            </div>

            {/* Warning Line Legend */}
            <div className="flex items-center gap-1.5 text-yellow-300">
              <span className="w-2 h-0.5 bg-yellow-400 rounded-full" />
              <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 shadow-sm" />
              <span className="font-bold">Aviso</span>
              <span className="text-zinc-500 text-[8px]">
                ({viewMode === 'AVERAGE' ? `${currentPoint?.warningUnitHours ?? 0}h/achado` : `${currentPoint?.warningMttrHours ?? 0}h tot`})
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Mini Trendline Sparkline Chart Container */}
      <div 
        id="mttr-trendline-chart-stage"
        className={`w-full ${compareBySeverity ? 'h-18 sm:h-20' : 'h-14'} bg-black/40 rounded border border-white/5 relative overflow-hidden pt-1 transition-all duration-200`}
      >
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={chartData}
            margin={{ top: 4, right: 8, left: 8, bottom: 0 }}
            onClick={(state: any) => {
              if (state && state.activePayload && state.activePayload.length > 0) {
                const pt = state.activePayload[0].payload as MttrScanHistoryPoint;
                if (onSelectScan) onSelectScan(pt);
              }
            }}
          >
            <defs>
              <linearGradient id="mttrGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={primaryColor} stopOpacity={0.38} />
                <stop offset="95%" stopColor={primaryColor} stopOpacity={0.02} />
              </linearGradient>
            </defs>

            <YAxis hide domain={[0, 'dataMax + 1.5']} />
            <XAxis dataKey="scanIndex" hide />

            {/* SLA Target Reference Line */}
            <ReferenceLine
              y={slaTargetLimit}
              stroke="#F59E0B"
              strokeDasharray="2 2"
              strokeWidth={1}
              strokeOpacity={0.45}
            />

            <RechartsTooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length > 0) {
                  const pt = payload[0].payload as any;
                  return (
                    <div className="bg-[#0f0f13] border border-white/20 px-2.5 py-1.5 rounded shadow-2xl font-mono text-[9px] text-zinc-200 z-50 min-w-[185px] space-y-1.5">
                      <div className="flex items-center justify-between border-b border-white/10 pb-1 font-bold text-white">
                        <span className="flex items-center gap-1">
                          {pt.isCurrent && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />}
                          {pt.scanLabel}
                        </span>
                        <span className="text-zinc-400 font-normal">{pt.timeLabel}</span>
                      </div>

                      {compareBySeverity ? (
                        /* Multi-Severity Breakdown in Tooltip */
                        <div className="space-y-1 py-0.5">
                          <div className="flex items-center justify-between text-rose-300">
                            <span className="flex items-center gap-1">
                              <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                              <span>Crítico:</span>
                            </span>
                            <span className="font-bold font-mono">
                              {pt.criticalValue}h
                              <span className="text-zinc-500 text-[8px] font-normal ml-1">
                                ({pt.criticalCount} achados)
                              </span>
                            </span>
                          </div>

                          <div className="flex items-center justify-between text-amber-300">
                            <span className="flex items-center gap-1">
                              <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                              <span>Alto:</span>
                            </span>
                            <span className="font-bold font-mono">
                              {pt.highValue}h
                              <span className="text-zinc-500 text-[8px] font-normal ml-1">
                                ({pt.highCount} achados)
                              </span>
                            </span>
                          </div>

                          <div className="flex items-center justify-between text-yellow-300">
                            <span className="flex items-center gap-1">
                              <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
                              <span>Aviso:</span>
                            </span>
                            <span className="font-bold font-mono">
                              {pt.warningValue}h
                              <span className="text-zinc-500 text-[8px] font-normal ml-1">
                                ({pt.warningCount} achados)
                              </span>
                            </span>
                          </div>
                        </div>
                      ) : (
                        /* Single Metric View in Tooltip */
                        <div className="space-y-1">
                          <div className="flex items-center justify-between pt-0.5">
                            <span className="text-zinc-400">MTTR Médio:</span>
                            <span className="font-bold text-white text-[10.5px]">
                              {pt.averageMttrHours}h / achado
                            </span>
                          </div>

                          <div className="flex items-center justify-between text-zinc-400">
                            <span>Horas Totais de Backlog:</span>
                            <span className="font-semibold text-zinc-200">{pt.totalBacklogHours}h</span>
                          </div>
                        </div>
                      )}

                      <div className="flex items-center justify-between pt-1 border-t border-white/10 text-[8px] text-zinc-400">
                        <span>Total: {pt.totalFindings} achados</span>
                        <span>MTTR Geral: {pt.averageMttrHours}h</span>
                      </div>
                    </div>
                  );
                }
                return null;
              }}
            />

            {compareBySeverity ? (
              /* 3 Superimposed Colored Lines for Critical, High, and Warning */
              <>
                {/* 1. Critical Line (Red / Rose) */}
                <Line
                  type="monotone"
                  dataKey="criticalValue"
                  name="Crítico"
                  stroke="#F43F5E"
                  strokeWidth={2.2}
                  dot={{ r: 2.2, fill: '#141419', stroke: '#F43F5E', strokeWidth: 1.5 }}
                  activeDot={{ r: 4.5, fill: '#F43F5E', stroke: '#FFFFFF', strokeWidth: 2 }}
                />

                {/* 2. High Line (Orange / Amber) */}
                <Line
                  type="monotone"
                  dataKey="highValue"
                  name="Alto"
                  stroke="#F59E0B"
                  strokeWidth={2.2}
                  dot={{ r: 2.2, fill: '#141419', stroke: '#F59E0B', strokeWidth: 1.5 }}
                  activeDot={{ r: 4.5, fill: '#F59E0B', stroke: '#FFFFFF', strokeWidth: 2 }}
                />

                {/* 3. Warning Line (Yellow) */}
                <Line
                  type="monotone"
                  dataKey="warningValue"
                  name="Aviso"
                  stroke="#EAB308"
                  strokeWidth={2.2}
                  dot={{ r: 2.2, fill: '#141419', stroke: '#EAB308', strokeWidth: 1.5 }}
                  activeDot={{ r: 4.5, fill: '#EAB308', stroke: '#FFFFFF', strokeWidth: 2 }}
                />
              </>
            ) : (
              /* Single Area/Trendline */
              <Area
                type="monotone"
                dataKey="primaryValue"
                stroke={primaryColor}
                strokeWidth={2}
                fill="url(#mttrGradient)"
                dot={{ r: 2.2, fill: '#0e0e11', stroke: primaryColor, strokeWidth: 1.5 }}
                activeDot={{ r: 4.5, fill: primaryColor, stroke: '#FFFFFF', strokeWidth: 2 }}
              />
            )}
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Historical Scan Point Ticks Legend */}
      <div 
        id="mttr-trendline-scans-legend"
        className={`grid ${
          displayData.length <= 5
            ? 'grid-cols-5'
            : displayData.length <= 10
            ? 'grid-cols-5 sm:grid-cols-10'
            : 'grid-cols-4 sm:grid-cols-6 md:grid-cols-12'
        } gap-1 pt-0.5 border-t border-white/5 text-center text-[8.5px]`}
      >
        {displayData.map((pt, idx) => {
          const val =
            compareBySeverity
              ? `${pt.criticalCount}C • ${pt.highCount}A • ${pt.warningCount}W`
              : viewMode === 'AVERAGE'
              ? `${pt.averageMttrHours}h`
              : `${pt.totalBacklogHours}h`;

          return (
            <div
              key={`scan-node-${pt.scanIndex}-${idx}`}
              className={`p-1 rounded transition-colors cursor-pointer ${
                pt.isCurrent
                  ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 font-bold'
                  : 'text-zinc-400 hover:bg-white/5 hover:text-zinc-200'
              }`}
              onClick={() => onSelectScan && onSelectScan(pt)}
              title={`${pt.scanLabel} (${pt.timeLabel}) — ${pt.totalFindings} achados, MTTR: ${pt.averageMttrHours}h`}
            >
              <div className="text-[7.5px] uppercase opacity-75 truncate">
                {pt.isCurrent ? 'Atual' : `#${idx + 1}`}
              </div>
              <div className="font-mono text-[9px] font-semibold">{val}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
