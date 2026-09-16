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
  ChevronDown,
  Calendar,
  CheckCircle2,
  AlertTriangle,
  Search,
  X,
  Download,
  Check
} from 'lucide-react';
import { SecScanGlobalConfig } from '../types';
import { ValidationSeverityDistribution } from './ValidationSeverityDonutChart';
import { safeGetItem, safeSetItem } from '../lib/storage';

export interface MttrScanHistoryPoint {
  scanIndex: number;
  scanLabel: string;
  timeLabel: string;
  timestamp: string;
  fullDateLabel?: string;
  isoDate?: string;
  timestampMs?: number;
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
export type MttrSeverityKey = 'critical' | 'high' | 'warning';

export interface MttrChartDataPoint extends MttrScanHistoryPoint {
  primaryValue: number;
  criticalValue: number;
  highValue: number;
  warningValue: number;
}

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
 * Safely extracts timestamp in milliseconds from a scan point
 */
export function getScanTimestampMs(pt: MttrScanHistoryPoint): number {
  if (pt.timestampMs && !isNaN(pt.timestampMs)) return pt.timestampMs;
  if (pt.isoDate) {
    const t = new Date(pt.isoDate).getTime();
    if (!isNaN(t)) return t;
  }
  if (pt.fullDateLabel) {
    const match = pt.fullDateLabel.match(/(\d{1,2})\/(\d{1,2})/);
    if (match) {
      const d = parseInt(match[1], 10);
      const m = parseInt(match[2], 10) - 1;
      const y = new Date().getFullYear();
      const dt = new Date(y, m, d);
      if (!isNaN(dt.getTime())) return dt.getTime();
    }
  }
  return 0;
}

/**
 * Helper to parse various user date or time inputs:
 * - DD/MM/YYYY or DD/MM
 * - YYYY-MM-DD
 * - HH:mm
 */
function parseDateOrTimeBoundary(input: string, isEndOfRange: boolean = false): { timeMs?: number; timeMinutes?: number } | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  // HH:mm (e.g., 11:30 or 09:45)
  const timeMatch = trimmed.match(/^(\d{1,2}):(\d{2})$/);
  if (timeMatch) {
    const hh = parseInt(timeMatch[1], 10);
    const mm = parseInt(timeMatch[2], 10);
    if (hh >= 0 && hh <= 23 && mm >= 0 && mm <= 59) {
      return { timeMinutes: hh * 60 + mm };
    }
  }

  // YYYY-MM-DD
  const isoMatch = trimmed.match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$/);
  if (isoMatch) {
    const y = parseInt(isoMatch[1], 10);
    const m = parseInt(isoMatch[2], 10) - 1;
    const d = parseInt(isoMatch[3], 10);
    const dt = isEndOfRange
      ? new Date(y, m, d, 23, 59, 59, 999)
      : new Date(y, m, d, 0, 0, 0, 0);
    if (!isNaN(dt.getTime())) return { timeMs: dt.getTime() };
  }

  // DD/MM/YYYY
  const dmyMatch = trimmed.match(/^(\d{1,2})[-/](\d{1,2})[-/](\d{4})$/);
  if (dmyMatch) {
    const d = parseInt(dmyMatch[1], 10);
    const m = parseInt(dmyMatch[2], 10) - 1;
    const y = parseInt(dmyMatch[3], 10);
    const dt = isEndOfRange
      ? new Date(y, m, d, 23, 59, 59, 999)
      : new Date(y, m, d, 0, 0, 0, 0);
    if (!isNaN(dt.getTime())) return { timeMs: dt.getTime() };
  }

  // DD/MM (assume current reference year)
  const dmMatch = trimmed.match(/^(\d{1,2})[-/](\d{1,2})$/);
  if (dmMatch) {
    const d = parseInt(dmMatch[1], 10);
    const m = parseInt(dmMatch[2], 10) - 1;
    const y = new Date().getFullYear();
    const dt = isEndOfRange
      ? new Date(y, m, d, 23, 59, 59, 999)
      : new Date(y, m, d, 0, 0, 0, 0);
    if (!isNaN(dt.getTime())) return { timeMs: dt.getTime() };
  }

  return null;
}

/**
 * Filter timeline points based on query string:
 * - Date/time ranges: "15/09 - 16/09", "15/09 a 16/09", "10:00 - 14:00"
 * - Specific single date: "16/09"
 * - Substring searches: "11:42", "Há 4h", "#3", "Hoje", "Ontem"
 */
export function filterScansByDateQuery(scans: MttrScanHistoryPoint[], query: string): MttrScanHistoryPoint[] {
  const q = query.trim().toLowerCase();
  if (!q) return scans;

  // Check for range splitters
  const rangeSplitters = [' - ', ' a ', ' até ', ' to ', '..'];
  let isRangeQuery = false;
  let partA = '';
  let partB = '';

  for (const sep of rangeSplitters) {
    if (q.includes(sep)) {
      const parts = q.split(sep);
      if (parts.length === 2 && parts[0].trim() && parts[1].trim()) {
        isRangeQuery = true;
        partA = parts[0].trim();
        partB = parts[1].trim();
        break;
      }
    }
  }

  if (isRangeQuery) {
    const boundA = parseDateOrTimeBoundary(partA, false);
    const boundB = parseDateOrTimeBoundary(partB, true);

    // Range in dates (timestamp milliseconds)
    if (boundA?.timeMs !== undefined && boundB?.timeMs !== undefined) {
      let minMs = boundA.timeMs;
      let maxMs = boundB.timeMs;
      if (minMs > maxMs) {
        const tmp = minMs;
        minMs = maxMs;
        maxMs = tmp;
      }
      return scans.filter(pt => {
        const ptMs = getScanTimestampMs(pt);
        return ptMs >= minMs && ptMs <= maxMs;
      });
    }

    // Range in clock times (minutes from midnight)
    if (boundA?.timeMinutes !== undefined && boundB?.timeMinutes !== undefined) {
      let minMin = boundA.timeMinutes;
      let maxMin = boundB.timeMinutes;
      if (minMin > maxMin) {
        const tmp = minMin;
        minMin = maxMin;
        maxMin = tmp;
      }
      return scans.filter(pt => {
        const match = pt.timestamp.match(/^(\d{1,2}):(\d{2})$/);
        if (!match) return false;
        const ptMin = parseInt(match[1], 10) * 60 + parseInt(match[2], 10);
        return ptMin >= minMin && ptMin <= maxMin;
      });
    }
  }

  // Single date boundary match (whole day)
  const singleBound = parseDateOrTimeBoundary(q, false);
  if (singleBound?.timeMs !== undefined) {
    const startMs = singleBound.timeMs;
    const endMs = startMs + 24 * 60 * 60 * 1000 - 1;
    const dateMatches = scans.filter(pt => {
      const ptMs = getScanTimestampMs(pt);
      return ptMs >= startMs && ptMs <= endMs;
    });
    if (dateMatches.length > 0) return dateMatches;
  }

  // Aliases for "hoje" (today) or "ontem" (yesterday)
  if (q === 'hoje' || q === 'today') {
    const now = new Date();
    const todayStr = now.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
    return scans.filter(pt => (pt.fullDateLabel || '').includes(todayStr) || pt.isCurrent);
  }

  if (q === 'ontem' || q === 'yesterday') {
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const yStr = yesterday.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
    return scans.filter(pt => (pt.fullDateLabel || '').includes(yStr));
  }

  // Textual fuzzy substring match
  return scans.filter(pt => {
    const fullDate = (pt.fullDateLabel || '').toLowerCase();
    const ts = (pt.timestamp || '').toLowerCase();
    const timeLbl = (pt.timeLabel || '').toLowerCase();
    const scanLbl = (pt.scanLabel || '').toLowerCase();
    const iso = (pt.isoDate || '').toLowerCase();
    const idxStr = `#${pt.scanIndex}`;

    return (
      fullDate.includes(q) ||
      ts.includes(q) ||
      timeLbl.includes(q) ||
      scanLbl.includes(q) ||
      iso.includes(q) ||
      idxStr === q ||
      String(pt.scanIndex) === q
    );
  });
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

    const scanDate = new Date(Date.now() - (selectedOffsets.length - 1 - idx) * 18 * 60 * 1000);
    const dateStr = scanDate.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
    const timeStr = scanDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const isoDateStr = scanDate.toISOString().slice(0, 10);
    const timeMs = scanDate.getTime();

    return {
      scanIndex: scanNum,
      scanLabel: isCurrent ? `Varredura #${scanNum} (Atual)` : `Varredura #${scanNum}`,
      timeLabel: selectedTimes[idx] || 'Passado',
      timestamp: timeStr,
      fullDateLabel: `${dateStr} às ${timeStr}`,
      isoDate: isoDateStr,
      timestampMs: timeMs,
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
  const [hoveredSeverity, setHoveredSeverity] = useState<MttrSeverityKey | null>(null);
  const [dateSearchQuery, setDateSearchQuery] = useState<string>('');
  const [exportSuccess, setExportSuccess] = useState<boolean>(false);
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

      const now = new Date();
      const dateStr = now.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
      const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const isoDateStr = now.toISOString().slice(0, 10);
      const timeMs = now.getTime();

      const currentPoint: MttrScanHistoryPoint = {
        scanIndex: currentScanNum,
        scanLabel: `Varredura #${currentScanNum} (Atual)`,
        timeLabel: 'Agora',
        timestamp: timeStr,
        fullDateLabel: `${dateStr} às ${timeStr}`,
        isoDate: isoDateStr,
        timestampMs: timeMs,
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

  // Filter timeline according to search query or selected timeRange dropdown (Last 5, Last 10, All time)
  const displayData: MttrScanHistoryPoint[] = useMemo(() => {
    if (dateSearchQuery.trim()) {
      return filterScansByDateQuery(fullTimelineData, dateSearchQuery);
    }
    if (timeRange === '5') {
      return fullTimelineData.slice(-5);
    }
    if (timeRange === '10') {
      return fullTimelineData.slice(-10);
    }
    return fullTimelineData;
  }, [fullTimelineData, timeRange, dateSearchQuery]);

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
  const initialPoint = displayData.length > 0 ? displayData[0] : null;
  const currentPoint = displayData.length > 0 ? displayData[displayData.length - 1] : null;

  const initialMetric = initialPoint
    ? (viewMode === 'AVERAGE' ? initialPoint.averageMttrHours : initialPoint.totalBacklogHours)
    : 0;

  const currentMetric = currentPoint
    ? (viewMode === 'AVERAGE' ? currentPoint.averageMttrHours : currentPoint.totalBacklogHours)
    : 0;

  const delta = currentPoint && initialPoint ? currentMetric - initialMetric : 0;
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

  // Dynamic subtitle based on active timeRange or search query
  const timeRangeSubtitle = dateSearchQuery.trim()
    ? `(Filtro: "${dateSearchQuery.trim()}" • ${displayData.length} de ${fullTimelineData.length} Varreduras)`
    : timeRange === '5'
    ? '(Últimas 5 Varreduras)'
    : timeRange === '10'
    ? '(Últimas 10 Varreduras)'
    : `(Histórico Completo • ${displayData.length} Varreduras)`;

  /**
   * Custom interactive SVG dot for each individual line with expanded hit target
   */
  const renderSeverityDot = (severityKey: MttrSeverityKey, color: string) => {
    return (props: any) => {
      const { cx, cy, payload } = props;
      if (cx == null || cy == null) return null;
      const isHovered = hoveredSeverity === severityKey;
      return (
        <g
          key={`dot-${severityKey}-${payload?.scanIndex}`}
          className="cursor-pointer"
          onMouseEnter={(e) => {
            e.stopPropagation();
            setHoveredSeverity(severityKey);
          }}
          onClick={(e) => {
            e.stopPropagation();
            setHoveredSeverity(prev => (prev === severityKey ? null : severityKey));
          }}
        >
          {/* Expanded transparent hit target (20px diameter) for easy aiming */}
          <circle cx={cx} cy={cy} r={10} fill="transparent" />
          {/* Main visual dot */}
          <circle
            cx={cx}
            cy={cy}
            r={isHovered ? 4.5 : 2.5}
            fill={isHovered ? color : '#141419'}
            stroke={color}
            strokeWidth={isHovered ? 2.5 : 1.5}
          />
          {isHovered && (
            <circle
              cx={cx}
              cy={cy}
              r={7}
              fill="none"
              stroke={color}
              strokeWidth={1.2}
              strokeDasharray="2 2"
              opacity={0.85}
            />
          )}
        </g>
      );
    };
  };

  /**
   * Exports the currently displayed historical MTTR chart data to a structured CSV file
   */
  const handleExportCsv = () => {
    if (!displayData || displayData.length === 0) return;

    const headers = [
      'ID_Varredura',
      'Rotulo',
      'Data_Hora',
      'Horario',
      'Data_ISO',
      'Tempo_Relativo',
      'Criticos_P0',
      'Altos_P1',
      'Aviso_P2',
      'Total_Achados',
      'MTTR_Medio_Horas',
      'Backlog_Total_Horas',
      'MTTR_Critico_Horas_Total',
      'MTTR_Alto_Horas_Total',
      'MTTR_Aviso_Horas_Total',
      'Tempo_Unitario_Critico_Horas',
      'Tempo_Unitario_Alto_Horas',
      'Tempo_Unitario_Aviso_Horas',
      'Varredura_Atual'
    ];

    const escapeCsv = (val: any) => {
      const str = String(val ?? '');
      if (str.includes(',') || str.includes('"') || str.includes('\n')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    };

    const rows = displayData.map(pt => [
      pt.scanIndex,
      escapeCsv(pt.scanLabel),
      escapeCsv(pt.fullDateLabel || `${pt.isoDate || ''} ${pt.timestamp || ''}`),
      escapeCsv(pt.timestamp),
      escapeCsv(pt.isoDate || ''),
      escapeCsv(pt.timeLabel),
      pt.criticalCount,
      pt.highCount,
      pt.warningCount,
      pt.totalFindings,
      pt.averageMttrHours,
      pt.totalBacklogHours,
      pt.criticalMttrHours,
      pt.highMttrHours,
      pt.warningMttrHours,
      pt.criticalUnitHours,
      pt.highUnitHours,
      pt.warningUnitHours,
      pt.isCurrent ? 'Sim' : 'Nao'
    ].join(','));

    // Prepend UTF-8 BOM (\uFEFF) for universal spreadsheet software compatibility (Excel, LibreOffice, etc.)
    const csvContent = '\uFEFF' + [headers.join(','), ...rows].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    const dateStamp = new Date().toISOString().slice(0, 10);
    link.download = `secscan-mttr-historico-${dateStamp}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setExportSuccess(true);
    setTimeout(() => {
      setExportSuccess(false);
    }, 2500);
  };

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
            onClick={() => {
              setCompareBySeverity(prev => !prev);
              setHoveredSeverity(null);
            }}
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

          {/* Export Chart Data Button (CSV) */}
          <button
            id="btn-export-mttr-csv"
            type="button"
            onClick={handleExportCsv}
            disabled={displayData.length === 0}
            className={`flex items-center gap-1.5 px-2 py-0.5 rounded border transition-all cursor-pointer font-bold text-[9px] ${
              exportSuccess
                ? 'bg-emerald-500/25 text-emerald-300 border-emerald-500/50 shadow-xs'
                : 'bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 hover:text-emerald-200 border-emerald-500/30 hover:border-emerald-500/50'
            } disabled:opacity-40 disabled:cursor-not-allowed`}
            title="Exportar dados históricos de MTTR exibidos atualmente no gráfico em formato CSV"
          >
            {exportSuccess ? (
              <>
                <Check className="w-3 h-3 text-emerald-300" />
                <span>Dados Exportados!</span>
              </>
            ) : (
              <>
                <Download className="w-3 h-3 text-emerald-400" />
                <span>Exportar Dados do Gráfico</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Date Search & Range Filter Bar */}
      <div 
        id="mttr-date-search-bar"
        className="flex flex-wrap items-center gap-1.5 p-1 rounded bg-black/40 border border-white/5"
      >
        <div className="relative flex-1 min-w-[200px]">
          <Search className="w-3 h-3 text-sky-400 absolute left-2 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            id="input-mttr-date-search"
            type="text"
            value={dateSearchQuery}
            onChange={(e) => setDateSearchQuery(e.target.value)}
            placeholder="Buscar por data (ex: 16/09, 11:30) ou intervalo (ex: 15/09 - 16/09, #3)..."
            className="w-full pl-6.5 pr-6 py-1 rounded bg-black/60 hover:bg-black/80 focus:bg-black/90 border border-white/10 focus:border-sky-400/60 text-zinc-200 placeholder-zinc-500 text-[9px] font-mono transition-all outline-none focus:ring-1 focus:ring-sky-400/40"
            aria-label="Filtrar histórico por data ou intervalo específico"
          />
          {dateSearchQuery && (
            <button
              id="btn-clear-mttr-date-search"
              type="button"
              onClick={() => setDateSearchQuery('')}
              className="absolute right-1.5 top-1/2 -translate-y-1/2 p-0.5 text-zinc-400 hover:text-white rounded hover:bg-white/10 cursor-pointer transition-colors"
              title="Limpar busca de data"
            >
              <X className="w-2.5 h-2.5" />
            </button>
          )}
        </div>

        {/* Search status badge / Quick suggestions */}
        {dateSearchQuery.trim() ? (
          <div className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-sky-500/15 border border-sky-500/30 text-sky-300 text-[8.5px]">
            <Calendar className="w-2.5 h-2.5 shrink-0" />
            <span className="font-semibold">
              {displayData.length} de {fullTimelineData.length} {displayData.length === 1 ? 'varredura' : 'varreduras'}
            </span>
            <button
              type="button"
              onClick={() => setDateSearchQuery('')}
              className="ml-1 text-zinc-400 hover:text-white underline cursor-pointer"
            >
              Limpar
            </button>
          </div>
        ) : (
          <div className="hidden sm:flex items-center gap-1 text-[8px] text-zinc-500">
            <span className="text-zinc-600">Sugestões:</span>
            <button
              type="button"
              onClick={() => {
                const today = new Date().toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
                setDateSearchQuery(today);
              }}
              className="px-1.5 py-0.5 rounded bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-zinc-200 cursor-pointer transition-colors"
              title="Filtrar varreduras da data de hoje"
            >
              Hoje
            </button>
            <button
              type="button"
              onClick={() => {
                const now = new Date();
                const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                const yStr = yesterday.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
                const tStr = now.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
                setDateSearchQuery(`${yStr} - ${tStr}`);
              }}
              className="px-1.5 py-0.5 rounded bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-zinc-200 cursor-pointer transition-colors"
              title="Filtrar intervalo entre ontem e hoje"
            >
              Intervalo 24h
            </button>
          </div>
        )}
      </div>

      {/* Multi-Severity Interactive Overlay Legend */}
      {compareBySeverity && (
        <div 
          id="mttr-compare-severity-legend"
          className="flex flex-wrap items-center justify-between gap-2 px-2 py-1 rounded bg-black/40 border border-white/5 text-[8.5px]"
        >
          <div className="flex items-center gap-1 text-zinc-400">
            <Layers className="w-3 h-3 text-sky-400" />
            <span className="font-semibold uppercase tracking-wider text-[8px]">
              {hoveredSeverity ? 'Severidade em Destaque:' : 'Camadas Sobrepostas:'}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {/* Critical Line Legend Button */}
            <button
              type="button"
              onClick={() => setHoveredSeverity(prev => (prev === 'critical' ? null : 'critical'))}
              onMouseEnter={() => setHoveredSeverity('critical')}
              className={`flex items-center gap-1.5 px-1.5 py-0.5 rounded transition-all cursor-pointer border ${
                hoveredSeverity === 'critical'
                  ? 'bg-rose-500/25 text-rose-200 border-rose-500/50 shadow-xs'
                  : 'bg-transparent text-rose-300 border-transparent hover:bg-rose-500/15'
              }`}
              title="Clique ou passe o mouse para focar na linha Crítica (P0)"
            >
              <span className="w-2 h-0.5 bg-rose-500 rounded-full" />
              <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shadow-sm" />
              <span className="font-bold">Crítico</span>
              <span className="text-zinc-500 text-[8px]">
                ({viewMode === 'AVERAGE' ? `${currentPoint?.criticalUnitHours ?? 0}h/achado` : `${currentPoint?.criticalMttrHours ?? 0}h tot`})
              </span>
            </button>

            {/* High Line Legend Button */}
            <button
              type="button"
              onClick={() => setHoveredSeverity(prev => (prev === 'high' ? null : 'high'))}
              onMouseEnter={() => setHoveredSeverity('high')}
              className={`flex items-center gap-1.5 px-1.5 py-0.5 rounded transition-all cursor-pointer border ${
                hoveredSeverity === 'high'
                  ? 'bg-amber-500/25 text-amber-200 border-amber-500/50 shadow-xs'
                  : 'bg-transparent text-amber-300 border-transparent hover:bg-amber-500/15'
              }`}
              title="Clique ou passe o mouse para focar na linha Alta (P1)"
            >
              <span className="w-2 h-0.5 bg-amber-500 rounded-full" />
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500 shadow-sm" />
              <span className="font-bold">Alto</span>
              <span className="text-zinc-500 text-[8px]">
                ({viewMode === 'AVERAGE' ? `${currentPoint?.highUnitHours ?? 0}h/achado` : `${currentPoint?.highMttrHours ?? 0}h tot`})
              </span>
            </button>

            {/* Warning Line Legend Button */}
            <button
              type="button"
              onClick={() => setHoveredSeverity(prev => (prev === 'warning' ? null : 'warning'))}
              onMouseEnter={() => setHoveredSeverity('warning')}
              className={`flex items-center gap-1.5 px-1.5 py-0.5 rounded transition-all cursor-pointer border ${
                hoveredSeverity === 'warning'
                  ? 'bg-yellow-400/25 text-yellow-200 border-yellow-400/50 shadow-xs'
                  : 'bg-transparent text-yellow-300 border-transparent hover:bg-yellow-400/15'
              }`}
              title="Clique ou passe o mouse para focar na linha de Aviso (P2)"
            >
              <span className="w-2 h-0.5 bg-yellow-400 rounded-full" />
              <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 shadow-sm" />
              <span className="font-bold">Aviso</span>
              <span className="text-zinc-500 text-[8px]">
                ({viewMode === 'AVERAGE' ? `${currentPoint?.warningUnitHours ?? 0}h/achado` : `${currentPoint?.warningMttrHours ?? 0}h tot`})
              </span>
            </button>
          </div>
        </div>
      )}

      {/* Mini Trendline Sparkline Chart Container */}
      <div 
        id="mttr-trendline-chart-stage"
        onMouseLeave={() => setHoveredSeverity(null)}
        className={`w-full ${compareBySeverity ? 'h-18 sm:h-20' : 'h-14'} bg-black/40 rounded border border-white/5 relative overflow-hidden pt-1 transition-all duration-200`}
      >
        {displayData.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center p-2 space-y-1 text-zinc-400">
            <div className="flex items-center gap-1.5 text-amber-400 font-semibold text-[9px]">
              <AlertTriangle className="w-3 h-3 shrink-0" />
              <span>Nenhuma varredura encontrada para "{dateSearchQuery}"</span>
            </div>
            <div className="flex items-center gap-2 text-[8px] text-zinc-500">
              <span>Tente buscar por data (ex: 16/09), horário (ex: 11:30) ou intervalo (ex: 15/09 - 16/09)</span>
              <button
                type="button"
                onClick={() => setDateSearchQuery('')}
                className="px-1.5 py-0.5 rounded bg-white/10 hover:bg-white/20 text-zinc-200 hover:text-white border border-white/10 text-[8px] cursor-pointer transition-colors"
              >
                Limpar filtro
              </button>
            </div>
          </div>
        ) : (
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
                if (!active || !payload || payload.length === 0) return null;
                const pt = payload[0].payload as MttrChartDataPoint;

                if (compareBySeverity) {
                  if (hoveredSeverity) {
                    /* Individual Line / Severity Custom Focused Tooltip */
                    const isCrit = hoveredSeverity === 'critical';
                    const isHigh = hoveredSeverity === 'high';
                    const isWarn = hoveredSeverity === 'warning';

                    const title = isCrit ? 'Severidade: Crítico (P0)' : isHigh ? 'Severidade: Alto (P1)' : 'Severidade: Aviso (P2)';
                    const badgeColor = isCrit ? 'text-rose-300' : isHigh ? 'text-amber-300' : 'text-yellow-300';
                    const bgColor = isCrit ? 'bg-rose-500/15 border-rose-500/30' : isHigh ? 'bg-amber-500/15 border-amber-500/30' : 'bg-yellow-400/15 border-yellow-400/30';
                    const dotBg = isCrit ? 'bg-rose-500' : isHigh ? 'bg-amber-500' : 'bg-yellow-400';
                    const mttrVal = isCrit
                      ? (viewMode === 'AVERAGE' ? pt.criticalUnitHours : pt.criticalMttrHours)
                      : isHigh
                      ? (viewMode === 'AVERAGE' ? pt.highUnitHours : pt.highMttrHours)
                      : (viewMode === 'AVERAGE' ? pt.warningUnitHours : pt.warningMttrHours);
                    const count = isCrit ? pt.criticalCount : isHigh ? pt.highCount : pt.warningCount;
                    const slaLimit = isCrit ? 2.0 : isHigh ? 6.0 : 24.0;
                    const unitVal = isCrit ? pt.criticalUnitHours : isHigh ? pt.highUnitHours : pt.warningUnitHours;
                    const withinSla = unitVal <= slaLimit;

                    return (
                      <div
                        id="tooltip-individual-severity"
                        className="bg-[#0f0f13] border border-white/20 px-3 py-2 rounded shadow-2xl font-mono text-[9px] text-zinc-200 z-50 min-w-[210px] space-y-1.5 backdrop-blur-md"
                      >
                        {/* Header: Severity Identification and Scan Label */}
                        <div className="flex items-center justify-between border-b border-white/10 pb-1">
                          <div className="flex items-center gap-1.5">
                            <span className={`w-2 h-2 rounded-full ${dotBg} shadow-sm animate-pulse`} />
                            <span className={`font-bold ${badgeColor} text-[10px] uppercase tracking-wide`}>
                              {title}
                            </span>
                          </div>
                          <span className="text-zinc-400 text-[8px] font-semibold">
                            {pt.scanLabel}
                          </span>
                        </div>

                        {/* Exact Date & Time */}
                        <div className="flex items-center justify-between text-zinc-300 text-[8.5px]">
                          <span className="text-zinc-400 flex items-center gap-1">
                            <Calendar className="w-2.5 h-2.5 text-sky-400" />
                            Data específica:
                          </span>
                          <span className="font-semibold text-white">
                            {pt.fullDateLabel || `${pt.timestamp} (${pt.timeLabel})`}
                          </span>
                        </div>

                        {/* MTTR on this specific date highlight box */}
                        <div className={`p-2 rounded ${bgColor} border flex items-center justify-between`}>
                          <div>
                            <div className={`text-[8px] uppercase tracking-wider font-bold ${badgeColor}`}>
                              {viewMode === 'AVERAGE' ? 'MTTR nesta data:' : 'Backlog nesta data:'}
                            </div>
                            <div className={`text-[14px] font-extrabold font-mono ${badgeColor}`}>
                              {mttrVal}h
                              <span className="text-[8.5px] font-normal text-zinc-400 ml-1">
                                {viewMode === 'AVERAGE' ? '/ achado' : 'totais'}
                              </span>
                            </div>
                          </div>
                          <div className="text-right">
                            <div className="text-[7.5px] text-zinc-400 uppercase">Achados nesta data</div>
                            <div className={`text-[12px] font-bold font-mono ${badgeColor}`}>
                              {count} {count === 1 ? 'item' : 'itens'}
                            </div>
                          </div>
                        </div>

                        {/* SLA Compliance Status */}
                        <div className="flex items-center justify-between text-[8px] pt-0.5 text-zinc-400 border-t border-white/5">
                          <span>Meta SLA: &le; {slaLimit}h</span>
                          <span className={`font-semibold flex items-center gap-1 ${withinSla ? 'text-emerald-400' : 'text-amber-400'}`}>
                            {withinSla ? (
                              <>
                                <CheckCircle2 className="w-2.5 h-2.5" />
                                Dentro do SLA
                              </>
                            ) : (
                              <>
                                <AlertTriangle className="w-2.5 h-2.5" />
                                Acima do SLA
                              </>
                            )}
                          </span>
                        </div>

                        {/* Interactive Severity Switcher */}
                        <div className="flex items-center justify-between pt-1 border-t border-white/10 text-[7.5px]">
                          <span className="text-zinc-500">Alternar severidade:</span>
                          <div className="flex gap-1">
                            <button
                              type="button"
                              onMouseEnter={() => setHoveredSeverity('critical')}
                              className={`px-1 py-0.2 rounded transition-colors cursor-pointer ${
                                isCrit ? 'bg-rose-500/30 text-rose-200 font-bold border border-rose-500/40' : 'text-zinc-400 hover:text-white'
                              }`}
                            >
                              Crítico
                            </button>
                            <button
                              type="button"
                              onMouseEnter={() => setHoveredSeverity('high')}
                              className={`px-1 py-0.2 rounded transition-colors cursor-pointer ${
                                isHigh ? 'bg-amber-500/30 text-amber-200 font-bold border border-amber-500/40' : 'text-zinc-400 hover:text-white'
                              }`}
                            >
                              Alto
                            </button>
                            <button
                              type="button"
                              onMouseEnter={() => setHoveredSeverity('warning')}
                              className={`px-1 py-0.2 rounded transition-colors cursor-pointer ${
                                isWarn ? 'bg-yellow-400/30 text-yellow-200 font-bold border border-yellow-400/40' : 'text-zinc-400 hover:text-white'
                              }`}
                            >
                              Aviso
                            </button>
                          </div>
                        </div>
                      </div>
                    );
                  }

                  /* Multi-Severity Overview in Tooltip */
                  return (
                    <div
                      id="tooltip-all-severities"
                      className="bg-[#0f0f13] border border-white/20 px-2.5 py-1.5 rounded shadow-2xl font-mono text-[9px] text-zinc-200 z-50 min-w-[210px] space-y-1.5 backdrop-blur-md"
                    >
                      <div className="flex items-center justify-between border-b border-white/10 pb-1 font-bold text-white">
                        <span className="flex items-center gap-1">
                          {pt.isCurrent && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />}
                          {pt.scanLabel}
                        </span>
                        <span className="text-zinc-400 font-normal text-[8px]">
                          {pt.fullDateLabel || `${pt.timestamp} (${pt.timeLabel})`}
                        </span>
                      </div>

                      <div className="space-y-1 py-0.5">
                        {/* Critical Row */}
                        <div
                          className="flex items-center justify-between p-1 rounded hover:bg-rose-500/10 cursor-pointer transition-colors text-rose-300"
                          onMouseEnter={() => setHoveredSeverity('critical')}
                        >
                          <span className="flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                            <span className="font-semibold">Crítico (P0):</span>
                          </span>
                          <span className="font-bold font-mono">
                            {pt.criticalValue}h
                            <span className="text-zinc-500 text-[8px] font-normal ml-1">
                              ({pt.criticalCount} {pt.criticalCount === 1 ? 'achado' : 'achados'})
                            </span>
                          </span>
                        </div>

                        {/* High Row */}
                        <div
                          className="flex items-center justify-between p-1 rounded hover:bg-amber-500/10 cursor-pointer transition-colors text-amber-300"
                          onMouseEnter={() => setHoveredSeverity('high')}
                        >
                          <span className="flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                            <span className="font-semibold">Alto (P1):</span>
                          </span>
                          <span className="font-bold font-mono">
                            {pt.highValue}h
                            <span className="text-zinc-500 text-[8px] font-normal ml-1">
                              ({pt.highCount} {pt.highCount === 1 ? 'achado' : 'achados'})
                            </span>
                          </span>
                        </div>

                        {/* Warning Row */}
                        <div
                          className="flex items-center justify-between p-1 rounded hover:bg-yellow-400/10 cursor-pointer transition-colors text-yellow-300"
                          onMouseEnter={() => setHoveredSeverity('warning')}
                        >
                          <span className="flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
                            <span className="font-semibold">Aviso (P2):</span>
                          </span>
                          <span className="font-bold font-mono">
                            {pt.warningValue}h
                            <span className="text-zinc-500 text-[8px] font-normal ml-1">
                              ({pt.warningCount} {pt.warningCount === 1 ? 'achado' : 'achados'})
                            </span>
                          </span>
                        </div>
                      </div>

                      <div className="flex items-center justify-between pt-1 border-t border-white/10 text-[7.5px] text-zinc-400">
                        <span>💡 Passe o mouse sobre uma linha para isolar</span>
                        <span className="text-zinc-300 font-semibold">{pt.totalFindings} achados tot</span>
                      </div>
                    </div>
                  );
                }

                /* Single Trendline Mode Tooltip */
                return (
                  <div className="bg-[#0f0f13] border border-white/20 px-2.5 py-1.5 rounded shadow-2xl font-mono text-[9px] text-zinc-200 z-50 min-w-[185px] space-y-1.5">
                    <div className="flex items-center justify-between border-b border-white/10 pb-1 font-bold text-white">
                      <span className="flex items-center gap-1">
                        {pt.isCurrent && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />}
                        {pt.scanLabel}
                      </span>
                      <span className="text-zinc-400 font-normal text-[8px]">
                        {pt.fullDateLabel || `${pt.timestamp} (${pt.timeLabel})`}
                      </span>
                    </div>

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

                    <div className="flex items-center justify-between pt-1 border-t border-white/10 text-[8px] text-zinc-400">
                      <span>Total: {pt.totalFindings} achados</span>
                      <span>MTTR Geral: {pt.averageMttrHours}h</span>
                    </div>
                  </div>
                );
              }}
            />

            {compareBySeverity ? (
              /* 3 Superimposed Colored Lines with Individual Hover and Dot Handlers */
              <>
                {/* 1. Critical Line (Red / Rose) */}
                <Line
                  type="monotone"
                  dataKey="criticalValue"
                  name="Crítico (P0)"
                  stroke="#F43F5E"
                  strokeWidth={hoveredSeverity === 'critical' ? 3.5 : hoveredSeverity ? 1.4 : 2.2}
                  strokeOpacity={hoveredSeverity && hoveredSeverity !== 'critical' ? 0.3 : 1}
                  onMouseEnter={() => setHoveredSeverity('critical')}
                  dot={renderSeverityDot('critical', '#F43F5E')}
                  activeDot={{
                    r: 6,
                    fill: '#F43F5E',
                    stroke: '#FFFFFF',
                    strokeWidth: 2,
                    onMouseEnter: () => setHoveredSeverity('critical'),
                  }}
                />

                {/* 2. High Line (Orange / Amber) */}
                <Line
                  type="monotone"
                  dataKey="highValue"
                  name="Alto (P1)"
                  stroke="#F59E0B"
                  strokeWidth={hoveredSeverity === 'high' ? 3.5 : hoveredSeverity ? 1.4 : 2.2}
                  strokeOpacity={hoveredSeverity && hoveredSeverity !== 'high' ? 0.3 : 1}
                  onMouseEnter={() => setHoveredSeverity('high')}
                  dot={renderSeverityDot('high', '#F59E0B')}
                  activeDot={{
                    r: 6,
                    fill: '#F59E0B',
                    stroke: '#FFFFFF',
                    strokeWidth: 2,
                    onMouseEnter: () => setHoveredSeverity('high'),
                  }}
                />

                {/* 3. Warning Line (Yellow) */}
                <Line
                  type="monotone"
                  dataKey="warningValue"
                  name="Aviso (P2)"
                  stroke="#EAB308"
                  strokeWidth={hoveredSeverity === 'warning' ? 3.5 : hoveredSeverity ? 1.4 : 2.2}
                  strokeOpacity={hoveredSeverity && hoveredSeverity !== 'warning' ? 0.3 : 1}
                  onMouseEnter={() => setHoveredSeverity('warning')}
                  dot={renderSeverityDot('warning', '#EAB308')}
                  activeDot={{
                    r: 6,
                    fill: '#EAB308',
                    stroke: '#FFFFFF',
                    strokeWidth: 2,
                    onMouseEnter: () => setHoveredSeverity('warning'),
                  }}
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
        )}
      </div>

      {/* Historical Scan Point Ticks Legend */}
      {displayData.length > 0 && (
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
                title={`${pt.scanLabel} (${pt.fullDateLabel || pt.timeLabel}) — ${pt.totalFindings} achados, MTTR: ${pt.averageMttrHours}h`}
              >
                <div className="text-[7.5px] uppercase opacity-75 truncate">
                  {pt.isCurrent ? 'Atual' : `#${idx + 1}`}
                </div>
                <div className="font-mono text-[9px] font-semibold">{val}</div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
