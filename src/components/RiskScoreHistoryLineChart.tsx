import React, { useState, useMemo, useEffect } from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  ReferenceLine
} from 'recharts';
import {
  TrendingDown,
  TrendingUp,
  ShieldCheck,
  ShieldAlert,
  Activity,
  RotateCcw,
  PlusCircle,
  Download,
  Calendar,
  Layers,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  AlertTriangle,
  Sliders,
  History,
  FileSpreadsheet,
  FileCode
} from 'lucide-react';
import { ScanReport } from '../types';
import { safeGetItem, safeSetItem } from '../lib/storage';
import { calculateCumulativeWorkspaceRiskScore } from '../lib/scanner';

export interface HistoricalRiskRecord {
  id: string;
  scanIndex: number;
  label: string;
  shortLabel: string;
  timestamp: string; // ISO string
  formattedDate: string;
  relativeTime: string;
  riskScore: number; // 0 - 100
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'MINIMAL';
  postureScore: number; // 0 - 100 (100 - riskScore)
  rawPoints: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  totalFindings: number;
  qualityGateLimit: number;
  passedQualityGate: boolean;
  deltaFromPrev: number;
  trigger: 'AUTO' | 'SNAPSHOT' | 'SIMULATION';
}

interface RiskScoreHistoryLineChartProps {
  report: ScanReport;
  qualityGateLimit?: number;
  onNavigateToScanner?: () => void;
  onNavigateToQualityGate?: () => void;
}

export type RiskHistoryViewMode = 'RISK_SCORE' | 'POSTURE' | 'DUAL';

const STORAGE_KEY = 'secscan_historical_risk_score_timeline_v2';

function getRelativeTimeString(timestamp: string): string {
  try {
    const diffMs = Date.now() - new Date(timestamp).getTime();
    if (isNaN(diffMs)) return 'Recente';
    const seconds = Math.floor(diffMs / 1000);
    if (seconds < 60) return 'Agora mesmo';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `Há ${minutes}m`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `Há ${hours}h`;
    const days = Math.floor(hours / 24);
    return `Há ${days}d`;
  } catch {
    return 'Recente';
  }
}

/**
 * Generates a realistic baseline sequence of past scans leading up to the current scan
 */
function generateBaselineHistory(
  currentReport: ScanReport,
  gateLimit: number = 50
): HistoricalRiskRecord[] {
  const curCrit = currentReport.metrics.criticalCount;
  const curHigh = currentReport.metrics.highCount;
  const curMed = currentReport.metrics.mediumCount;
  const curLow = currentReport.metrics.lowCount;
  const curInfo = currentReport.metrics.infoCount;

  const now = Date.now();
  const ONE_DAY = 24 * 60 * 60 * 1000;
  const ONE_HOUR = 60 * 60 * 1000;

  // 8 sequential scans showing progressive vulnerability remediation & occasional regressions
  const progression = [
    { critOffset: 3, highOffset: 4, medOffset: 3, lowOffset: 2, timeOffset: 6 * ONE_DAY, label: 'Scan #1 (Baseline Inicial)' },
    { critOffset: 2, highOffset: 3, medOffset: 2, lowOffset: 2, timeOffset: 4 * ONE_DAY + 8 * ONE_HOUR, label: 'Scan #2 (Remediação de Chaves)' },
    { critOffset: 2, highOffset: 2, medOffset: 3, lowOffset: 1, timeOffset: 3 * ONE_DAY + 2 * ONE_HOUR, label: 'Scan #3 (Sprint 42 Release)' },
    { critOffset: 1, highOffset: 2, medOffset: 1, lowOffset: 2, timeOffset: 2 * ONE_DAY, label: 'Scan #4 (Auditoria AWS Secrets)' },
    { critOffset: 1, highOffset: 1, medOffset: 2, lowOffset: 1, timeOffset: 1 * ONE_DAY + 6 * ONE_HOUR, label: 'Scan #5 (Sanitização de CI/CD)' },
    { critOffset: 0, highOffset: 1, medOffset: 1, lowOffset: 0, timeOffset: 14 * ONE_HOUR, label: 'Scan #6 (Revisão Pré-Merge)' },
    { critOffset: 0, highOffset: 0, medOffset: 1, lowOffset: 0, timeOffset: 3 * ONE_HOUR, label: 'Scan #7 (Varredura Automática)' },
    { critOffset: 0, highOffset: 0, medOffset: 0, lowOffset: 0, timeOffset: 0, label: 'Scan #8 (Varredura Atual)' }
  ];

  let prevScore = 0;

  return progression.map((step, idx) => {
    const isCurrent = idx === progression.length - 1;
    const crit = Math.max(0, curCrit + (isCurrent ? 0 : step.critOffset));
    const high = Math.max(0, curHigh + (isCurrent ? 0 : step.highOffset));
    const med = Math.max(0, curMed + (isCurrent ? 0 : step.medOffset));
    const low = Math.max(0, curLow + (isCurrent ? 0 : step.lowOffset));
    const info = curInfo;

    const riskCalc = calculateCumulativeWorkspaceRiskScore({
      criticalCount: crit,
      highCount: high,
      mediumCount: med,
      lowCount: low,
      infoCount: info
    });

    const calculatedRiskScore = isCurrent ? (currentReport.metrics.riskScore ?? riskCalc.riskScore) : riskCalc.riskScore;
    const calculatedRiskLevel = isCurrent ? (currentReport.metrics.riskLevel ?? riskCalc.riskLevel) : riskCalc.riskLevel;
    const calculatedRawPoints = isCurrent ? (currentReport.metrics.workspaceRiskBreakdown?.rawPoints ?? riskCalc.rawPoints) : riskCalc.rawPoints;
    const postureScore = Math.max(0, Math.min(100, 100 - calculatedRiskScore));

    const scanDate = new Date(now - step.timeOffset);
    const formattedDate = `${scanDate.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' })} ${scanDate.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}`;
    const relativeTime = getRelativeTimeString(scanDate.toISOString());

    const deltaFromPrev = idx === 0 ? 0 : calculatedRiskScore - prevScore;
    prevScore = calculatedRiskScore;

    return {
      id: `hist-scan-${idx + 1}-${scanDate.getTime()}`,
      scanIndex: idx + 1,
      label: step.label,
      shortLabel: `#${idx + 1}`,
      timestamp: scanDate.toISOString(),
      formattedDate,
      relativeTime,
      riskScore: calculatedRiskScore,
      riskLevel: calculatedRiskLevel,
      postureScore,
      rawPoints: calculatedRawPoints,
      criticalCount: crit,
      highCount: high,
      mediumCount: med,
      lowCount: low,
      infoCount: info,
      totalFindings: crit + high + med + low + info,
      qualityGateLimit: gateLimit,
      passedQualityGate: calculatedRiskScore <= gateLimit,
      deltaFromPrev,
      trigger: isCurrent ? 'AUTO' : 'SNAPSHOT'
    };
  });
}

export const RiskScoreHistoryLineChart: React.FC<RiskScoreHistoryLineChartProps> = ({
  report,
  qualityGateLimit = 50,
  onNavigateToScanner,
  onNavigateToQualityGate
}) => {
  const [viewMode, setViewMode] = useState<RiskHistoryViewMode>('RISK_SCORE');
  const [timeRange, setTimeRange] = useState<'ALL' | 'LAST_5' | 'LAST_10'>('ALL');
  const [showDataTable, setShowDataTable] = useState<boolean>(false);
  const [history, setHistory] = useState<HistoricalRiskRecord[]>(() => {
    const saved = safeGetItem(STORAGE_KEY);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed;
        }
      } catch {
        // Fall through to baseline
      }
    }
    return generateBaselineHistory(report, qualityGateLimit);
  });

  // Sync the latest scan point when the current report changes
  useEffect(() => {
    setHistory((prev) => {
      if (prev.length === 0) {
        return generateBaselineHistory(report, qualityGateLimit);
      }
      const updated = [...prev];
      const lastIdx = updated.length - 1;
      const last = { ...updated[lastIdx] };

      const curCrit = report.metrics.criticalCount;
      const curHigh = report.metrics.highCount;
      const curMed = report.metrics.mediumCount;
      const curLow = report.metrics.lowCount;
      const curInfo = report.metrics.infoCount;

      const riskCalc = calculateCumulativeWorkspaceRiskScore({
        criticalCount: curCrit,
        highCount: curHigh,
        mediumCount: curMed,
        lowCount: curLow,
        infoCount: curInfo
      });

      const currentRiskScore = report.metrics.riskScore ?? riskCalc.riskScore;
      const currentRiskLevel = report.metrics.riskLevel ?? riskCalc.riskLevel;
      const currentRawPoints = report.metrics.workspaceRiskBreakdown?.rawPoints ?? riskCalc.rawPoints;
      const postureScore = Math.max(0, Math.min(100, 100 - currentRiskScore));

      const prevScore = lastIdx > 0 ? updated[lastIdx - 1].riskScore : currentRiskScore;
      const deltaFromPrev = currentRiskScore - prevScore;

      last.criticalCount = curCrit;
      last.highCount = curHigh;
      last.mediumCount = curMed;
      last.lowCount = curLow;
      last.infoCount = curInfo;
      last.totalFindings = report.findings.length;
      last.riskScore = currentRiskScore;
      last.riskLevel = currentRiskLevel;
      last.postureScore = postureScore;
      last.rawPoints = currentRawPoints;
      last.qualityGateLimit = qualityGateLimit;
      last.passedQualityGate = currentRiskScore <= qualityGateLimit;
      last.deltaFromPrev = deltaFromPrev;
      last.label = `Scan #${updated.length} (Varredura Atual)`;

      updated[lastIdx] = last;
      safeSetItem(STORAGE_KEY, JSON.stringify(updated.slice(-20)));
      return updated;
    });
  }, [report, qualityGateLimit]);

  // Filtered dataset for rendering based on timeRange
  const displayedHistory = useMemo(() => {
    if (timeRange === 'LAST_5') return history.slice(-5);
    if (timeRange === 'LAST_10') return history.slice(-10);
    return history;
  }, [history, timeRange]);

  // Aggregate KPI metrics
  const kpis = useMemo(() => {
    if (history.length === 0) {
      return {
        currentScore: report.metrics.riskScore,
        currentLevel: report.metrics.riskLevel,
        currentPosture: 100 - report.metrics.riskScore,
        baselineScore: report.metrics.riskScore,
        totalDelta: 0,
        isImprovement: true,
        maxScore: report.metrics.riskScore,
        maxScoreLabel: 'Scan Atual',
        minScore: report.metrics.riskScore,
        gatePassCount: 0,
        gateTotalCount: 0,
        gateComplianceRate: 100
      };
    }

    const baseline = history[0];
    const current = history[history.length - 1];
    const totalDelta = current.riskScore - baseline.riskScore;
    const isImprovement = totalDelta <= 0; // negative delta means risk decreased!

    let maxScore = -1;
    let maxLabel = '';
    let minScore = 999;
    let gatePassCount = 0;

    history.forEach((rec) => {
      if (rec.riskScore > maxScore) {
        maxScore = rec.riskScore;
        maxLabel = rec.shortLabel;
      }
      if (rec.riskScore < minScore) {
        minScore = rec.riskScore;
      }
      if (rec.riskScore <= qualityGateLimit) {
        gatePassCount++;
      }
    });

    const gateComplianceRate = Math.round((gatePassCount / history.length) * 100);

    return {
      currentScore: current.riskScore,
      currentLevel: current.riskLevel,
      currentPosture: current.postureScore,
      baselineScore: baseline.riskScore,
      totalDelta,
      isImprovement,
      maxScore,
      maxScoreLabel: maxLabel,
      minScore,
      gatePassCount,
      gateTotalCount: history.length,
      gateComplianceRate
    };
  }, [history, report.metrics.riskScore, report.metrics.riskLevel, qualityGateLimit]);

  // Record a dedicated new snapshot in history
  const handleRecordSnapshot = () => {
    setHistory((prev) => {
      const nextIndex = prev.length + 1;
      const now = new Date();
      const last = prev[prev.length - 1];

      const curCrit = report.metrics.criticalCount;
      const curHigh = report.metrics.highCount;
      const curMed = report.metrics.mediumCount;
      const curLow = report.metrics.lowCount;
      const curInfo = report.metrics.infoCount;

      const riskCalc = calculateCumulativeWorkspaceRiskScore({
        criticalCount: curCrit,
        highCount: curHigh,
        mediumCount: curMed,
        lowCount: curLow,
        infoCount: curInfo
      });

      const currentRiskScore = report.metrics.riskScore ?? riskCalc.riskScore;
      const currentRiskLevel = report.metrics.riskLevel ?? riskCalc.riskLevel;
      const currentRawPoints = report.metrics.workspaceRiskBreakdown?.rawPoints ?? riskCalc.rawPoints;
      const postureScore = Math.max(0, Math.min(100, 100 - currentRiskScore));
      const deltaFromPrev = last ? currentRiskScore - last.riskScore : 0;

      const newRecord: HistoricalRiskRecord = {
        id: `hist-scan-${nextIndex}-${now.getTime()}`,
        scanIndex: nextIndex,
        label: `Scan #${nextIndex} (Snapshot Salvo)`,
        shortLabel: `#${nextIndex}`,
        timestamp: now.toISOString(),
        formattedDate: `${now.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' })} ${now.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}`,
        relativeTime: 'Agora mesmo',
        riskScore: currentRiskScore,
        riskLevel: currentRiskLevel,
        postureScore,
        rawPoints: currentRawPoints,
        criticalCount: curCrit,
        highCount: curHigh,
        mediumCount: curMed,
        lowCount: curLow,
        infoCount: curInfo,
        totalFindings: report.findings.length,
        qualityGateLimit,
        passedQualityGate: currentRiskScore <= qualityGateLimit,
        deltaFromPrev,
        trigger: 'SNAPSHOT'
      };

      const updated = [...prev, newRecord].slice(-20);
      safeSetItem(STORAGE_KEY, JSON.stringify(updated));
      return updated;
    });
  };

  // Simulate a hardened scan (remediation progress)
  const handleSimulateMitigationScan = () => {
    setHistory((prev) => {
      const nextIndex = prev.length + 1;
      const now = new Date();
      const last = prev[prev.length - 1];

      // Progressive mitigation: reduce critical or high
      const nextCrit = Math.max(0, last.criticalCount - (Math.random() > 0.35 ? 1 : 0));
      const nextHigh = Math.max(0, last.highCount - (Math.random() > 0.45 ? 1 : 0));
      const nextMed = Math.max(0, last.mediumCount - (Math.random() > 0.6 ? 1 : 0));
      const nextLow = last.lowCount;
      const nextInfo = last.infoCount;

      const riskCalc = calculateCumulativeWorkspaceRiskScore({
        criticalCount: nextCrit,
        highCount: nextHigh,
        mediumCount: nextMed,
        lowCount: nextLow,
        infoCount: nextInfo
      });

      const postureScore = Math.max(0, Math.min(100, 100 - riskCalc.riskScore));
      const deltaFromPrev = riskCalc.riskScore - last.riskScore;

      const newRecord: HistoricalRiskRecord = {
        id: `hist-scan-${nextIndex}-${now.getTime()}`,
        scanIndex: nextIndex,
        label: `Scan #${nextIndex} (Mitigação Simulada)`,
        shortLabel: `#${nextIndex}`,
        timestamp: now.toISOString(),
        formattedDate: `${now.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' })} ${now.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}`,
        relativeTime: 'Agora mesmo',
        riskScore: riskCalc.riskScore,
        riskLevel: riskCalc.riskLevel,
        postureScore,
        rawPoints: riskCalc.rawPoints,
        criticalCount: nextCrit,
        highCount: nextHigh,
        mediumCount: nextMed,
        lowCount: nextLow,
        infoCount: nextInfo,
        totalFindings: nextCrit + nextHigh + nextMed + nextLow + nextInfo,
        qualityGateLimit,
        passedQualityGate: riskCalc.riskScore <= qualityGateLimit,
        deltaFromPrev,
        trigger: 'SIMULATION'
      };

      const updated = [...prev, newRecord].slice(-20);
      safeSetItem(STORAGE_KEY, JSON.stringify(updated));
      return updated;
    });
  };

  // Reset to default baseline
  const handleResetHistory = () => {
    const baseline = generateBaselineHistory(report, qualityGateLimit);
    setHistory(baseline);
    safeSetItem(STORAGE_KEY, JSON.stringify(baseline));
  };

  // Export history to CSV
  const handleExportCsv = () => {
    const headers = ['Scan_Index', 'Label', 'Timestamp', 'Risk_Score', 'Risk_Level', 'Posture_Score', 'Raw_Points', 'Critical', 'High', 'Medium', 'Low', 'Total_Findings', 'Quality_Gate_Limit', 'Quality_Gate_Passed'];
    const rows = history.map(r => [
      r.scanIndex,
      `"${r.label}"`,
      r.timestamp,
      r.riskScore,
      r.riskLevel,
      r.postureScore,
      r.rawPoints,
      r.criticalCount,
      r.highCount,
      r.mediumCount,
      r.lowCount,
      r.totalFindings,
      r.qualityGateLimit,
      r.passedQualityGate ? 'PASS' : 'FAIL'
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `secscan-risk-score-history-${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Export history to JSON
  const handleExportJson = () => {
    const jsonContent = JSON.stringify(history, null, 2);
    const blob = new Blob([jsonContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `secscan-risk-score-history-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Custom high-precision Recharts tooltip
  const CustomTooltip = ({ active, payload }: any) => {
    if (!active || !payload || !payload.length) return null;
    const data: HistoricalRiskRecord = payload[0].payload;
    if (!data) return null;

    const isGatePassed = data.riskScore <= (data.qualityGateLimit || qualityGateLimit);
    const delta = data.deltaFromPrev;

    const levelBadgeColor = 
      data.riskLevel === 'CRITICAL' ? 'bg-[#FF3E00] text-white' :
      data.riskLevel === 'HIGH' ? 'bg-[#FF7A00] text-black font-bold' :
      data.riskLevel === 'MEDIUM' ? 'bg-[#EAB308] text-black font-bold' :
      'bg-[#00FF41] text-black font-bold';

    return (
      <div className="bg-[#050505] border border-[#333] p-4 shadow-2xl font-mono text-xs space-y-3 min-w-[280px]">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[#222] pb-2">
          <div>
            <div className="text-white font-black text-sm">{data.label}</div>
            <div className="text-[10px] text-[#888]">{data.formattedDate}</div>
          </div>
          <span className={`text-[9px] font-mono px-2 py-0.5 uppercase tracking-wider ${levelBadgeColor}`}>
            {data.riskLevel}
          </span>
        </div>

        {/* Primary Scores */}
        <div className="grid grid-cols-2 gap-2 bg-[#0E0E0E] p-2.5 border border-[#1C1C1C]">
          <div>
            <span className="text-[10px] text-[#777] uppercase block">Risk Score</span>
            <div className="flex items-baseline gap-1.5 mt-0.5">
              <span className="text-2xl font-black text-white">{data.riskScore}</span>
              <span className="text-[10px] text-[#666]">/100</span>
            </div>
          </div>
          <div>
            <span className="text-[10px] text-[#777] uppercase block">Postura de Segurança</span>
            <div className="flex items-baseline gap-1.5 mt-0.5">
              <span className="text-2xl font-black text-[#00FF41]">{data.postureScore}%</span>
            </div>
          </div>
        </div>

        {/* Delta vs Previous */}
        {delta !== 0 && (
          <div className="flex items-center justify-between text-[11px] px-1">
            <span className="text-[#888]">Evolução vs Scan Anterior:</span>
            <span className={`font-bold flex items-center gap-1 ${
              delta < 0 ? 'text-[#00FF41]' : 'text-[#FF3E00]'
            }`}>
              {delta < 0 ? <TrendingDown className="w-3.5 h-3.5" /> : <TrendingUp className="w-3.5 h-3.5" />}
              {delta < 0 ? `${delta} pts (Risco Reduzido)` : `+${delta} pts (Risco Aumentado)`}
            </span>
          </div>
        )}

        {/* Breakdown of findings */}
        <div className="space-y-1 pt-2 border-t border-[#1C1C1C] text-[10px]">
          <div className="flex items-center justify-between text-[#AAA]">
            <span>Achados por Severidade:</span>
            <span className="text-white font-bold">{data.totalFindings} total</span>
          </div>
          <div className="grid grid-cols-4 gap-1 text-center pt-1">
            <div className="bg-[#220700] text-[#FF3E00] border border-[#FF3E00]/30 py-1">
              <div className="font-black">{data.criticalCount}</div>
              <div className="text-[8px] text-[#888]">CRIT</div>
            </div>
            <div className="bg-[#1F1200] text-[#FF7A00] border border-[#FF7A00]/30 py-1">
              <div className="font-black">{data.highCount}</div>
              <div className="text-[8px] text-[#888]">HIGH</div>
            </div>
            <div className="bg-[#1C1700] text-[#EAB308] border border-[#EAB308]/30 py-1">
              <div className="font-black">{data.mediumCount}</div>
              <div className="text-[8px] text-[#888]">MED</div>
            </div>
            <div className="bg-[#00142A] text-[#3366FF] border border-[#3366FF]/30 py-1">
              <div className="font-black">{data.lowCount}</div>
              <div className="text-[8px] text-[#888]">LOW</div>
            </div>
          </div>
        </div>

        {/* Quality Gate Status */}
        <div className="pt-2 border-t border-[#1C1C1C] flex items-center justify-between text-[10px]">
          <span className="text-[#888]">Quality Gate (Max: {data.qualityGateLimit ?? qualityGateLimit}):</span>
          <span className={`px-2 py-0.5 border font-bold ${
            isGatePassed
              ? 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/40'
              : 'bg-[#FF3E00]/20 text-[#FF3E00] border-[#FF3E00]/50'
          }`}>
            {isGatePassed ? '✓ APROVADO' : '✕ VIOLAÇÃO'}
          </span>
        </div>
      </div>
    );
  };

  return (
    <div id="risk-score-history-chart-section" className="bg-[#0A0A0A] border-2 border-[#2A2A2A] p-6 lg:p-8 space-y-6 relative overflow-hidden">
      {/* Decorative subtle background corner glow */}
      <div className="absolute top-0 right-0 w-64 h-64 bg-[#FF3E00]/5 rounded-bl-full pointer-events-none" />

      {/* Header & Subtitle */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-[#222]">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="text-[10px] font-mono text-[#FF3E00] bg-[#FF3E00]/10 px-2.5 py-0.5 border border-[#FF3E00]/40 uppercase font-black tracking-widest flex items-center gap-1.5">
              <History className="w-3 h-3" />
              TIMELINE & AUDITORIA // LINHA HISTÓRICA
            </span>
            <span className="text-[10px] font-mono bg-[#141414] text-[#00FF41] border border-[#00FF41]/30 px-2 py-0.5 font-bold">
              {history.length} VARREDURAS REGISTRADAS
            </span>
            <span className="text-[10px] font-mono bg-[#141414] text-[#AAA] border border-[#333] px-2 py-0.5">
              TOLERÂNCIA CI/CD: &le; {qualityGateLimit} PTS
            </span>
          </div>

          <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
            <Activity className="w-6 h-6 text-[#FF3E00]" />
            <span>Evolução Histórica do Risk Score & Postura de Segurança</span>
          </h2>
          <p className="text-xs font-mono text-[#888] max-w-3xl leading-relaxed">
            Acompanhe o registro cronológico do <strong className="text-white">Workspace Risk Score (0–100)</strong> ao longo de varreduras passadas. Visualize a eficácia de remediações de segredos, a redução da superfície de ataque e o cumprimento dos limites de Quality Gate corporativos.
          </p>
        </div>

        {/* Action Buttons Top */}
        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            id="btn-record-current-risk-snapshot"
            onClick={handleRecordSnapshot}
            className="px-3.5 py-2 bg-[#FF3E00] hover:bg-white hover:text-black text-white font-mono font-bold text-xs uppercase tracking-wider transition-all flex items-center gap-1.5 shadow-[0_0_15px_rgba(255,62,0,0.2)] cursor-pointer"
            title="Registrar estado da varredura atual como um novo ponto no histórico"
          >
            <PlusCircle className="w-4 h-4" />
            <span>Registrar Snapshot</span>
          </button>

          <button
            id="btn-simulate-mitigation-scan"
            onClick={handleSimulateMitigationScan}
            className="px-3 py-2 bg-[#141414] hover:bg-[#222] border border-[#333] hover:border-[#555] text-white font-mono text-xs uppercase tracking-wider transition-colors flex items-center gap-1.5 cursor-pointer"
            title="Simular ciclo de mitigação com redução de vulnerabilidades críticas"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-[#00FF41]" />
            <span>Simular Mitigação</span>
          </button>

          <button
            id="btn-reset-risk-history"
            onClick={handleResetHistory}
            className="p-2 bg-[#141414] hover:bg-[#222] border border-[#333] text-[#888] hover:text-white transition-colors cursor-pointer"
            title="Restaurar histórico inicial de 8 varreduras"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono">
        {/* Card 1: Score Atual */}
        <div className="bg-[#050505] border border-[#222] p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[10px] text-[#777] uppercase font-bold">
              <span>Risk Score Atual</span>
              <Activity className="w-3.5 h-3.5 text-[#FF3E00]" />
            </div>
            <div className="flex items-baseline gap-2 mt-2">
              <span className={`text-3xl font-black ${
                kpis.currentScore >= 75 ? 'text-[#FF3E00]' :
                kpis.currentScore >= 50 ? 'text-[#FF7A00]' :
                kpis.currentScore >= 25 ? 'text-[#EAB308]' :
                'text-[#00FF41]'
              }`}>
                {kpis.currentScore}
              </span>
              <span className="text-xs text-[#666]">/ 100</span>
            </div>
          </div>
          <div className="mt-3 pt-2.5 border-t border-[#181818] flex items-center justify-between text-[10px]">
            <span className="text-[#888]">Nível:</span>
            <span className={`font-bold px-1.5 py-0.5 border text-[9px] ${
              kpis.currentScore >= 75 ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40' :
              kpis.currentScore >= 50 ? 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/40' :
              kpis.currentScore >= 25 ? 'bg-[#EAB308]/15 text-[#EAB308] border-[#EAB308]/40' :
              'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/40'
            }`}>
              {kpis.currentLevel}
            </span>
          </div>
        </div>

        {/* Card 2: Evolução Histórica (Delta Total) */}
        <div className="bg-[#050505] border border-[#222] p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[10px] text-[#777] uppercase font-bold">
              <span>Evolução Histórica</span>
              {kpis.isImprovement ? (
                <TrendingDown className="w-3.5 h-3.5 text-[#00FF41]" />
              ) : (
                <TrendingUp className="w-3.5 h-3.5 text-[#FF3E00]" />
              )}
            </div>
            <div className="flex items-baseline gap-2 mt-2">
              <span className={`text-3xl font-black ${
                kpis.isImprovement ? 'text-[#00FF41]' : 'text-[#FF3E00]'
              }`}>
                {kpis.totalDelta > 0 ? `+${kpis.totalDelta}` : kpis.totalDelta}
              </span>
              <span className="text-xs text-[#666]">pts</span>
            </div>
          </div>
          <div className="mt-3 pt-2.5 border-t border-[#181818] flex items-center justify-between text-[10px]">
            <span className="text-[#888]">Desde o Scan #1 ({kpis.baselineScore} pts):</span>
            <span className={kpis.isImprovement ? 'text-[#00FF41] font-bold' : 'text-[#FF3E00] font-bold'}>
              {kpis.isImprovement ? 'MELHORIA DE POSTURA' : 'REGRESSÃO DE RISCO'}
            </span>
          </div>
        </div>

        {/* Card 3: Postura de Segurança Atual */}
        <div className="bg-[#050505] border border-[#222] p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[10px] text-[#777] uppercase font-bold">
              <span>Postura de Segurança</span>
              <ShieldCheck className="w-3.5 h-3.5 text-[#00FF41]" />
            </div>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-black text-white">
                {kpis.currentPosture}%
              </span>
              <span className="text-xs text-[#666]">conforme</span>
            </div>
          </div>
          <div className="mt-3 pt-2.5 border-t border-[#181818] flex items-center justify-between text-[10px]">
            <span className="text-[#888]">Inverso do Risk Score:</span>
            <span className="text-[#00FF41] font-bold">
              100 - {kpis.currentScore} pts
            </span>
          </div>
        </div>

        {/* Card 4: Conformidade Quality Gate */}
        <div className="bg-[#050505] border border-[#222] p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[10px] text-[#777] uppercase font-bold">
              <span>Conformidade Quality Gate</span>
              <Sliders className="w-3.5 h-3.5 text-[#3366FF]" />
            </div>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-3xl font-black text-white">
                {kpis.gateComplianceRate}%
              </span>
              <span className="text-xs text-[#666]">({kpis.gatePassCount}/{kpis.gateTotalCount} scans)</span>
            </div>
          </div>
          <div className="mt-3 pt-2.5 border-t border-[#181818] flex items-center justify-between text-[10px]">
            <span className="text-[#888]">Teto Tolerado:</span>
            <span className="text-white font-bold">&le; {qualityGateLimit} pts</span>
          </div>
        </div>
      </div>

      {/* Control Toolbar: View Modes, Time Filters, and Export */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-[#080808] border border-[#222] p-3">
        {/* Left: View Mode Selectors */}
        <div className="flex items-center gap-1.5 text-xs font-mono">
          <span className="text-[10px] text-[#777] uppercase mr-2 hidden sm:inline">Visualização:</span>
          
          <button
            type="button"
            onClick={() => setViewMode('RISK_SCORE')}
            className={`px-3 py-1.5 border text-xs font-bold transition-all cursor-pointer ${
              viewMode === 'RISK_SCORE'
                ? 'bg-[#FF3E00] text-white border-[#FF3E00]'
                : 'bg-[#121212] text-[#AAA] border-[#333] hover:text-white'
            }`}
          >
            Risk Score (0–100)
          </button>

          <button
            type="button"
            onClick={() => setViewMode('POSTURE')}
            className={`px-3 py-1.5 border text-xs font-bold transition-all cursor-pointer ${
              viewMode === 'POSTURE'
                ? 'bg-[#00FF41] text-black border-[#00FF41]'
                : 'bg-[#121212] text-[#AAA] border-[#333] hover:text-white'
            }`}
          >
            Postura de Segurança (%)
          </button>

          <button
            type="button"
            onClick={() => setViewMode('DUAL')}
            className={`px-3 py-1.5 border text-xs font-bold transition-all cursor-pointer ${
              viewMode === 'DUAL'
                ? 'bg-white text-black border-white'
                : 'bg-[#121212] text-[#AAA] border-[#333] hover:text-white'
            }`}
          >
            Curva Dupla (Risco vs Postura)
          </button>
        </div>

        {/* Right: Time Range & Export Options */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <div className="flex items-center border border-[#333] bg-[#121212] p-0.5">
            <button
              onClick={() => setTimeRange('ALL')}
              className={`px-2 py-1 text-[10px] font-bold transition-colors cursor-pointer ${
                timeRange === 'ALL' ? 'bg-[#262626] text-white' : 'text-[#888] hover:text-white'
              }`}
            >
              Todos ({history.length})
            </button>
            <button
              onClick={() => setTimeRange('LAST_10')}
              className={`px-2 py-1 text-[10px] font-bold transition-colors cursor-pointer ${
                timeRange === 'LAST_10' ? 'bg-[#262626] text-white' : 'text-[#888] hover:text-white'
              }`}
            >
              Últimos 10
            </button>
            <button
              onClick={() => setTimeRange('LAST_5')}
              className={`px-2 py-1 text-[10px] font-bold transition-colors cursor-pointer ${
                timeRange === 'LAST_5' ? 'bg-[#262626] text-white' : 'text-[#888] hover:text-white'
              }`}
            >
              Últimos 5
            </button>
          </div>

          <div className="h-4 w-px bg-[#333]" />

          <button
            onClick={handleExportCsv}
            className="px-2.5 py-1.5 bg-[#121212] hover:bg-[#202020] border border-[#333] text-[#AAA] hover:text-white text-[10px] font-bold flex items-center gap-1 transition-colors cursor-pointer"
            title="Exportar dados históricos como CSV"
          >
            <FileSpreadsheet className="w-3 h-3 text-[#00FF41]" />
            <span>CSV</span>
          </button>

          <button
            onClick={handleExportJson}
            className="px-2.5 py-1.5 bg-[#121212] hover:bg-[#202020] border border-[#333] text-[#AAA] hover:text-white text-[10px] font-bold flex items-center gap-1 transition-colors cursor-pointer"
            title="Exportar dados históricos como JSON estruturado"
          >
            <FileCode className="w-3 h-3 text-[#3366FF]" />
            <span>JSON</span>
          </button>

          <button
            onClick={() => setShowDataTable(!showDataTable)}
            className="px-2.5 py-1.5 bg-[#121212] hover:bg-[#202020] border border-[#333] text-[#AAA] hover:text-white text-[10px] font-bold flex items-center gap-1 transition-colors cursor-pointer"
            title={showDataTable ? 'Ocultar tabela de varreduras' : 'Exibir tabela de varreduras detalhada'}
          >
            {showDataTable ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            <span>Tabela</span>
          </button>
        </div>
      </div>

      {/* Main Historical Recharts Line Chart */}
      <div className="bg-[#050505] border border-[#222] p-4 lg:p-6 space-y-4">
        {/* Chart Legend & Zone Badges */}
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono pb-2 border-b border-[#181818]">
          <div className="flex flex-wrap items-center gap-4">
            <span className="text-[#AAA] font-bold flex items-center gap-1.5">
              <span className="w-3 h-0.5 bg-[#FF3E00]" />
              <span>Risk Score (0–100)</span>
            </span>

            {(viewMode === 'POSTURE' || viewMode === 'DUAL') && (
              <span className="text-[#AAA] font-bold flex items-center gap-1.5">
                <span className="w-3 h-0.5 bg-[#00FF41]" />
                <span>Postura de Segurança (%)</span>
              </span>
            )}

            <span className="text-[#888] flex items-center gap-1.5">
              <span className="w-3 border-b-2 border-dashed border-white" />
              <span>Tolerância Quality Gate ({qualityGateLimit} pts)</span>
            </span>
          </div>

          {/* Risk Zone Indicators */}
          <div className="hidden xl:flex items-center gap-2 text-[9px]">
            <span className="px-1.5 py-0.5 bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30">0-24 MÍNIMO</span>
            <span className="px-1.5 py-0.5 bg-[#EAB308]/10 text-[#EAB308] border border-[#EAB308]/30">25-49 MÉDIO</span>
            <span className="px-1.5 py-0.5 bg-[#FF7A00]/10 text-[#FF7A00] border border-[#FF7A00]/30">50-74 ALTO</span>
            <span className="px-1.5 py-0.5 bg-[#FF3E00]/10 text-[#FF3E00] border border-[#FF3E00]/30">&ge;75 CRÍTICO</span>
          </div>
        </div>

        {/* Recharts Canvas */}
        <div className="h-80 sm:h-96 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={displayedHistory}
              margin={{ top: 20, right: 30, left: 10, bottom: 25 }}
            >
              <defs>
                <linearGradient id="riskScoreGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#FF3E00" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#FF3E00" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="postureGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00FF41" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#00FF41" stopOpacity={0.0} />
                </linearGradient>
              </defs>

              <CartesianGrid stroke="#1F1F1F" strokeDasharray="3 3" vertical={false} />

              <XAxis
                dataKey="shortLabel"
                stroke="#666"
                tick={{ fill: '#888', fontSize: 11, fontFamily: 'monospace' }}
                dy={10}
              />

              <YAxis
                domain={[0, 100]}
                stroke="#666"
                tick={{ fill: '#888', fontSize: 11, fontFamily: 'monospace' }}
                ticks={[0, 25, 50, 75, 100]}
                dx={-5}
              />

              <RechartsTooltip content={<CustomTooltip />} />

              {/* Quality Gate Benchmark Reference Line */}
              <ReferenceLine
                y={qualityGateLimit}
                stroke="#FFFFFF"
                strokeDasharray="4 4"
                strokeWidth={1.5}
                label={{
                  value: `GATE: ${qualityGateLimit} PTS`,
                  fill: '#FFFFFF',
                  fontSize: 10,
                  fontFamily: 'monospace',
                  position: 'insideTopRight'
                }}
              />

              {/* Risk Level Boundary Lines */}
              <ReferenceLine y={75} stroke="#FF3E00" strokeOpacity={0.3} strokeDasharray="2 2" />
              <ReferenceLine y={50} stroke="#FF7A00" strokeOpacity={0.2} strokeDasharray="2 2" />
              <ReferenceLine y={25} stroke="#EAB308" strokeOpacity={0.2} strokeDasharray="2 2" />

              {/* Primary Line: Risk Score */}
              {(viewMode === 'RISK_SCORE' || viewMode === 'DUAL') && (
                <Line
                  type="monotone"
                  dataKey="riskScore"
                  name="Risk Score"
                  stroke="#FF3E00"
                  strokeWidth={3}
                  dot={{ r: 5, fill: '#050505', stroke: '#FF3E00', strokeWidth: 2 }}
                  activeDot={{ r: 8, fill: '#FF3E00', stroke: '#FFFFFF', strokeWidth: 2 }}
                  animationDuration={1200}
                />
              )}

              {/* Secondary Line: Security Posture */}
              {(viewMode === 'POSTURE' || viewMode === 'DUAL') && (
                <Line
                  type="monotone"
                  dataKey="postureScore"
                  name="Postura de Segurança"
                  stroke="#00FF41"
                  strokeWidth={viewMode === 'POSTURE' ? 3 : 2}
                  strokeDasharray={viewMode === 'DUAL' ? '4 4' : undefined}
                  dot={{ r: 5, fill: '#050505', stroke: '#00FF41', strokeWidth: 2 }}
                  activeDot={{ r: 8, fill: '#00FF41', stroke: '#FFFFFF', strokeWidth: 2 }}
                  animationDuration={1200}
                />
              )}
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Bottom Chart Footer Diagnosis */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono text-[#888] pt-3 border-t border-[#181818]">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#00FF41]" />
            <span>
              Trajetória consolidada: {history.length} varreduras processadas pelo motor <strong>calculateCumulativeWorkspaceRiskScore</strong>.
            </span>
          </div>
          {onNavigateToQualityGate && (
            <button
              onClick={onNavigateToQualityGate}
              className="text-[#FF3E00] hover:text-white underline font-bold uppercase tracking-wider text-[11px] cursor-pointer"
            >
              Ajustar Tolerância de Quality Gate &rarr;
            </button>
          )}
        </div>
      </div>

      {/* Collapsible Detailed Scan Records Table */}
      {showDataTable && (
        <div className="bg-[#050505] border border-[#222] p-4 lg:p-6 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#181818]">
            <div className="flex items-center gap-2">
              <History className="w-4 h-4 text-[#FF3E00]" />
              <span className="text-xs font-bold text-white uppercase tracking-wider">
                Registro Histórico Detalhado de Varreduras
              </span>
            </div>
            <span className="text-[10px] font-mono text-[#666]">
              Exibindo {displayedHistory.length} de {history.length} registros
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#222] text-[10px] text-[#777] uppercase">
                  <th className="py-2.5 px-3">Scan</th>
                  <th className="py-2.5 px-3">Data e Hora</th>
                  <th className="py-2.5 px-3 text-center">Risk Score</th>
                  <th className="py-2.5 px-3 text-center">Nível</th>
                  <th className="py-2.5 px-3 text-center">Postura (%)</th>
                  <th className="py-2.5 px-3 text-center">Crítico</th>
                  <th className="py-2.5 px-3 text-center">Alto</th>
                  <th className="py-2.5 px-3 text-center">Médio / Baixo</th>
                  <th className="py-2.5 px-3 text-center">Quality Gate</th>
                  <th className="py-2.5 px-3 text-right">Evolução</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#141414]">
                {displayedHistory.slice().reverse().map((rec) => {
                  const isCurrent = rec.scanIndex === history.length;
                  const isPassed = rec.riskScore <= qualityGateLimit;

                  return (
                    <tr
                      key={rec.id}
                      className={`hover:bg-[#0E0E0E] transition-colors ${
                        isCurrent ? 'bg-[#FF3E00]/5 font-bold' : ''
                      }`}
                    >
                      <td className="py-3 px-3 text-white flex items-center gap-2">
                        <span>{rec.shortLabel}</span>
                        {isCurrent && (
                          <span className="px-1.5 py-0.2 bg-[#FF3E00] text-white text-[9px]">ATUAL</span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-[#AAA]">
                        {rec.formattedDate}
                        <span className="text-[10px] text-[#666] ml-2">({rec.relativeTime})</span>
                      </td>
                      <td className="py-3 px-3 text-center font-bold text-white">
                        <span className={`px-2 py-0.5 ${
                          rec.riskScore >= 75 ? 'text-[#FF3E00]' :
                          rec.riskScore >= 50 ? 'text-[#FF7A00]' :
                          rec.riskScore >= 25 ? 'text-[#EAB308]' :
                          'text-[#00FF41]'
                        }`}>
                          {rec.riskScore}/100
                        </span>
                      </td>
                      <td className="py-3 px-3 text-center">
                        <span className={`text-[9px] px-2 py-0.5 border font-bold uppercase ${
                          rec.riskLevel === 'CRITICAL' ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40' :
                          rec.riskLevel === 'HIGH' ? 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/40' :
                          rec.riskLevel === 'MEDIUM' ? 'bg-[#EAB308]/15 text-[#EAB308] border-[#EAB308]/40' :
                          'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/40'
                        }`}>
                          {rec.riskLevel}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-center text-[#00FF41] font-bold">
                        {rec.postureScore}%
                      </td>
                      <td className="py-3 px-3 text-center">
                        <span className={rec.criticalCount > 0 ? 'text-[#FF3E00] font-bold' : 'text-[#666]'}>
                          {rec.criticalCount}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-center">
                        <span className={rec.highCount > 0 ? 'text-[#FF7A00] font-bold' : 'text-[#666]'}>
                          {rec.highCount}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-center text-[#888]">
                        {rec.mediumCount} / {rec.lowCount}
                      </td>
                      <td className="py-3 px-3 text-center">
                        <span className={`text-[9px] px-2 py-0.5 border font-bold ${
                          isPassed
                            ? 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/40'
                            : 'bg-[#FF3E00]/20 text-[#FF3E00] border-[#FF3E00]/50'
                        }`}>
                          {isPassed ? 'PASS' : 'VIOLATION'}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-right">
                        {rec.deltaFromPrev === 0 ? (
                          <span className="text-[#666]">—</span>
                        ) : rec.deltaFromPrev < 0 ? (
                          <span className="text-[#00FF41] font-bold flex items-center justify-end gap-1">
                            <TrendingDown className="w-3 h-3" />
                            <span>{rec.deltaFromPrev} pts</span>
                          </span>
                        ) : (
                          <span className="text-[#FF3E00] font-bold flex items-center justify-end gap-1">
                            <TrendingUp className="w-3 h-3" />
                            <span>+{rec.deltaFromPrev} pts</span>
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
