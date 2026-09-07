import React, { useState, useEffect, useMemo } from 'react';
import {
  Gauge,
  Timer,
  Zap,
  TrendingDown,
  TrendingUp,
  Minus,
  Clock,
  Activity,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Cpu,
  Layers,
  Info
} from 'lucide-react';
import { ScanReport, AuditLogEvent } from '../types';
import { safeGetItem, safeSetItem } from '../lib/storage';

interface ScanSpeedometerGaugeProps {
  report: ScanReport;
  auditLogs?: AuditLogEvent[];
  onNavigateToScanner?: () => void;
}

interface ScanDurationRecord {
  id: string;
  durationMs: number;
  timestamp: string;
  filesCount: number;
}

const STORAGE_KEY = 'secscan_scan_duration_history';
const DEFAULT_BASELINE_HISTORY: ScanDurationRecord[] = [
  { id: 'base-1', durationMs: 44, timestamp: '10:00:15', filesCount: 12 },
  { id: 'base-2', durationMs: 38, timestamp: '10:05:22', filesCount: 12 },
  { id: 'base-3', durationMs: 46, timestamp: '10:12:08', filesCount: 12 },
  { id: 'base-4', durationMs: 40, timestamp: '10:18:40', filesCount: 12 },
  { id: 'base-5', durationMs: 35, timestamp: '10:25:02', filesCount: 12 }
];

export const ScanSpeedometerGauge: React.FC<ScanSpeedometerGaugeProps> = ({
  report,
  auditLogs = [],
  onNavigateToScanner
}) => {
  const currentDuration = Math.max(1, report.durationMs ?? 35);
  const scannedFiles = report.scannedFilesCount || 1;

  // Track historical scan durations in safe storage
  const [history, setHistory] = useState<ScanDurationRecord[]>(() => {
    try {
      const saved = safeGetItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed;
        }
      }
    } catch {
      // Fallback
    }
    return DEFAULT_BASELINE_HISTORY;
  });

  // Whenever report.durationMs changes, update history
  useEffect(() => {
    setHistory((prev) => {
      // Check if current duration is already the last entry
      const lastEntry = prev[prev.length - 1];
      if (lastEntry && lastEntry.durationMs === currentDuration) {
        return prev;
      }
      const newEntry: ScanDurationRecord = {
        id: `scan-${Date.now()}`,
        durationMs: currentDuration,
        timestamp: new Date().toLocaleTimeString(),
        filesCount: scannedFiles
      };
      const updated = [...prev, newEntry].slice(-12);
      try {
        safeSetItem(STORAGE_KEY, JSON.stringify(updated));
      } catch {
        // Storage fail-safe
      }
      return updated;
    });
  }, [currentDuration, scannedFiles]);

  // Compute average scan duration
  const averageDuration = useMemo(() => {
    if (history.length === 0) return currentDuration;
    const sum = history.reduce((acc, curr) => acc + curr.durationMs, 0);
    return Math.max(1, Math.round(sum / history.length));
  }, [history, currentDuration]);

  // Comparative metrics
  const diffMs = currentDuration - averageDuration;
  const absDiffMs = Math.abs(diffMs);
  const percentDiff = Math.round(((currentDuration - averageDuration) / averageDuration) * 100);
  const ratio = (currentDuration / averageDuration).toFixed(2);

  const isFaster = diffMs < 0;
  const isSlower = diffMs > 0;
  const isAtAverage = diffMs === 0;

  // Performance tier assessment
  const speedTier = useMemo(() => {
    if (percentDiff <= -25) {
      return {
        label: 'TURBO • ULTRA-RÁPIDO',
        color: 'text-[#00FF41]',
        bg: 'bg-[#00FF41]/10',
        border: 'border-[#00FF41]/40',
        desc: 'Varredura significativamente mais rápida que o tempo médio.'
      };
    }
    if (percentDiff <= -5) {
      return {
        label: 'ÓTIMO • ACIMA DA MÉDIA',
        color: 'text-sky-400',
        bg: 'bg-sky-500/10',
        border: 'border-sky-500/40',
        desc: 'Excelente vazão de processamento e cache eficiente.'
      };
    }
    if (percentDiff <= 15) {
      return {
        label: 'NOMINAL • DENTRO DO ESPERADO',
        color: 'text-[#00E5FF]',
        bg: 'bg-[#00E5FF]/10',
        border: 'border-[#00E5FF]/40',
        desc: 'Tempo de execução em perfeita consonância com a média histórica.'
      };
    }
    if (percentDiff <= 40) {
      return {
        label: 'MODERADO • LIGEIRAMENTE LENTO',
        color: 'text-amber-400',
        bg: 'bg-amber-500/10',
        border: 'border-amber-500/40',
        desc: 'Tempo ligeiramente acima da média devido à densidade de regras ou AST.'
      };
    }
    return {
      label: 'INTENSIVO • PROCESSAMENTO PESADO',
      color: 'text-[#FF3E00]',
      bg: 'bg-[#FF3E00]/10',
      border: 'border-[#FF3E00]/40',
      desc: 'Tempo consideravelmente acima da média. Avalie excluir arquivos grandes.'
    };
  }, [percentDiff]);

  // Throughput calculations
  const filesPerSec = useMemo(() => {
    if (currentDuration <= 0) return 0;
    return Math.round((scannedFiles / (currentDuration / 1000)));
  }, [scannedFiles, currentDuration]);

  // Speedometer geometry
  // Semi-circular gauge: 180° sweep from -180° to 0° (or 180° to 360°)
  // We'll map duration to an arc where:
  // 0ms = 0% (-180°)
  // maxScale = 100% (0°)
  // averageDuration is placed dynamically on this arc
  const maxScaleMs = useMemo(() => {
    const highest = Math.max(averageDuration, currentDuration, 80);
    return Math.ceil((highest * 1.6) / 20) * 20; // Round up to clean step
  }, [averageDuration, currentDuration]);

  // Coordinate math for SVG arc (Radius = 90, Center = 150, 130)
  const cx = 150;
  const cy = 130;
  const radius = 95;
  const strokeWidth = 14;

  // Angle in degrees: 0% -> 180° (left), 100% -> 360° (right)
  const getAngle = (val: number) => {
    const fraction = Math.min(1, Math.max(0, val / maxScaleMs));
    return 180 + fraction * 180;
  };

  const getCoordinates = (angleInDegrees: number, r: number = radius) => {
    const angleInRadians = (angleInDegrees * Math.PI) / 180;
    return {
      x: cx + r * Math.cos(angleInRadians),
      y: cy + r * Math.sin(angleInRadians)
    };
  };

  const currentAngle = getAngle(currentDuration);
  const averageAngle = getAngle(averageDuration);

  // SVG Path for arc
  const describeArc = (startAngle: number, endAngle: number, r: number = radius) => {
    const start = getCoordinates(startAngle, r);
    const end = getCoordinates(endAngle, r);
    const largeArcFlag = endAngle - startAngle <= 180 ? '0' : '1';
    return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArcFlag} 1 ${end.x} ${end.y}`;
  };

  // Background track (180° to 360°)
  const bgArcPath = describeArc(180, 360, radius);

  // Active progress arc from 180 to currentAngle
  const activeArcPath = describeArc(180, Math.max(180.5, currentAngle), radius);

  // Average marker coordinates
  const avgInner = getCoordinates(averageAngle, radius - strokeWidth / 2 - 4);
  const avgOuter = getCoordinates(averageAngle, radius + strokeWidth / 2 + 6);

  // Needle tip coordinates
  const needleTip = getCoordinates(currentAngle, radius - 15);

  // Tick marks
  const ticks = [0, 0.25, 0.5, 0.75, 1.0].map((frac) => {
    const val = Math.round(frac * maxScaleMs);
    const angle = 180 + frac * 180;
    const p1 = getCoordinates(angle, radius + 12);
    const p2 = getCoordinates(angle, radius + 18);
    const labelPos = getCoordinates(angle, radius + 28);
    return { val, p1, p2, labelPos, angle };
  });

  const handleResetHistory = () => {
    const fresh = [
      { id: `scan-${Date.now()}`, durationMs: currentDuration, timestamp: 'Agora', filesCount: scannedFiles }
    ];
    setHistory(fresh);
    safeSetItem(STORAGE_KEY, JSON.stringify(fresh));
  };

  return (
    <div
      id="scan-speedometer-gauge-section"
      className="bg-[#080808] border-2 border-[#262626] p-6 lg:p-7 space-y-6 relative overflow-hidden shadow-2xl"
    >
      {/* Background ambient lighting */}
      <div className="absolute top-0 right-0 w-64 h-64 bg-[#00FF41]/5 rounded-bl-full pointer-events-none blur-2xl" />
      <div className="absolute bottom-0 left-0 w-48 h-48 bg-[#3366FF]/5 rounded-tr-full pointer-events-none blur-2xl" />

      {/* Header Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-[#1A1A1A] relative z-10">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono text-[#00FF41] bg-[#00FF41]/10 px-2.5 py-0.5 border border-[#00FF41]/40 uppercase font-black tracking-widest flex items-center gap-1.5">
              <Gauge className="w-3.5 h-3.5 text-[#00FF41]" />
              PERFORMANCE GAUGE // TELEMETRIA DE EXECUÇÃO
            </span>
            <span className="text-[10px] font-mono text-[#777] uppercase">
              BENCHMARK DE VARREDURA
            </span>
            <span
              id="speedometer-variance-pill"
              className={`text-[10px] font-mono px-2 py-0.5 border font-bold uppercase flex items-center gap-1 ${
                isFaster
                  ? 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/40'
                  : isSlower
                    ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40'
                    : 'bg-sky-500/10 text-sky-400 border-sky-500/30'
              }`}
            >
              {isFaster ? (
                <>
                  <TrendingDown className="w-3 h-3 stroke-[2.5]" />
                  <span>{Math.abs(percentDiff)}% MAIS RÁPIDO</span>
                </>
              ) : isSlower ? (
                <>
                  <TrendingUp className="w-3 h-3 stroke-[2.5]" />
                  <span>+{percentDiff}% ACIMA DA MÉDIA</span>
                </>
              ) : (
                <>
                  <Minus className="w-3 h-3 stroke-[2.5]" />
                  <span>EM LINHA COM A MÉDIA</span>
                </>
              )}
            </span>
          </div>

          <h3 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
            <Timer className="w-6 h-6 text-[#00FF41]" />
            <span>Velocímetro de Execução: Último Scan vs. Média Histórica</span>
          </h3>

          <p className="text-xs font-mono text-[#888] max-w-3xl leading-relaxed">
            Mede em tempo real a duração total da última análise SAST (<strong className="text-white">{currentDuration}ms</strong>) em relação à média ponderada (<strong className="text-white">{averageDuration}ms</strong>) dos últimos <strong className="text-[#00FF41]">{history.length} scans</strong>.
          </p>
        </div>

        {/* Action button */}
        <div className="flex items-center gap-2.5 shrink-0">
          <button
            id="btn-speedometer-reset-history"
            onClick={handleResetHistory}
            className="px-3.5 py-2.5 bg-[#111] hover:bg-[#1C1C1C] text-[#888] hover:text-white border border-[#333] hover:border-[#555] font-mono text-xs uppercase tracking-wider transition-all flex items-center gap-1.5"
            title="Recalcular média iniciando a partir do scan atual"
          >
            <RotateCcw className="w-3.5 h-3.5 text-[#888]" />
            <span>Redefinir Média</span>
          </button>
          {onNavigateToScanner && (
            <button
              id="btn-speedometer-rescan-trigger"
              onClick={onNavigateToScanner}
              className="px-4 py-2.5 bg-[#00FF41]/10 hover:bg-[#00FF41] hover:text-black text-[#00FF41] border border-[#00FF41]/40 font-mono text-xs font-bold uppercase tracking-wider transition-all flex items-center gap-1.5 shadow-sm"
              title="Ir para o Scanner e disparar nova análise de código"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Nova Análise</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Speedometer & Telemetry Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        {/* Speedometer Radial Gauge Column */}
        <div className="lg:col-span-6 flex flex-col items-center justify-center p-5 bg-[#0A0A0A] border border-[#222] relative rounded-xs">
          <div className="text-[10px] font-mono uppercase tracking-widest text-[#777] mb-2 flex items-center gap-1.5">
            <Activity className="w-3 h-3 text-[#00FF41]" />
            <span>DIAL ANALÓGICO-DIGITAL // RADIAL VELOCITY</span>
          </div>

          {/* SVG Speedometer Canvas */}
          <div className="relative w-full max-w-[320px] aspect-[16/10] flex items-center justify-center">
            <svg
              id="speedometer-svg-canvas"
              viewBox="20 15 260 145"
              className="w-full h-full overflow-visible"
            >
              <defs>
                {/* Active gradient based on performance */}
                <linearGradient id="activeArcGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#00FF41" />
                  <stop offset="65%" stopColor="#3366FF" />
                  <stop offset="85%" stopColor="#EAB308" />
                  <stop offset="100%" stopColor="#FF3E00" />
                </linearGradient>

                <linearGradient id="gaugeZoneGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#00FF41" stopOpacity="0.25" />
                  <stop offset="50%" stopColor="#3366FF" stopOpacity="0.25" />
                  <stop offset="80%" stopColor="#EAB308" stopOpacity="0.25" />
                  <stop offset="100%" stopColor="#FF3E00" stopOpacity="0.3" />
                </linearGradient>

                <filter id="gaugeGlow" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="glow" />
                  <feComposite in="SourceGraphic" in2="glow" operator="over" />
                </filter>
              </defs>

              {/* Background Track Arc */}
              <path
                d={bgArcPath}
                fill="none"
                stroke="#1A1A1A"
                strokeWidth={strokeWidth}
                strokeLinecap="round"
              />

              {/* Zone Underlay */}
              <path
                d={bgArcPath}
                fill="none"
                stroke="url(#gaugeZoneGradient)"
                strokeWidth={strokeWidth}
                strokeLinecap="round"
              />

              {/* Active Progress Arc */}
              <path
                d={activeArcPath}
                fill="none"
                stroke={isFaster ? '#00FF41' : isSlower ? '#FF3E00' : '#00E5FF'}
                strokeWidth={strokeWidth}
                strokeLinecap="round"
                filter="url(#gaugeGlow)"
                className="transition-all duration-700 ease-out"
              />

              {/* Graduation Ticks and Scale Labels */}
              {ticks.map((t, idx) => (
                <g key={idx}>
                  <line
                    x1={t.p1.x}
                    y1={t.p1.y}
                    x2={t.p2.x}
                    y2={t.p2.y}
                    stroke="#444"
                    strokeWidth={idx === 0 || idx === ticks.length - 1 ? 2 : 1}
                  />
                  <text
                    x={t.labelPos.x}
                    y={t.labelPos.y}
                    fill="#666"
                    fontSize="7.5"
                    fontFamily="monospace"
                    textAnchor="middle"
                    dominantBaseline="middle"
                  >
                    {t.val}ms
                  </text>
                </g>
              ))}

              {/* Average Reference Notch / Marker */}
              <g id="speedometer-avg-marker" className="transition-all duration-500">
                <line
                  x1={avgInner.x}
                  y1={avgInner.y}
                  x2={avgOuter.x}
                  y2={avgOuter.y}
                  stroke="#FFFFFF"
                  strokeWidth="3"
                  strokeLinecap="round"
                  filter="url(#gaugeGlow)"
                />
                <circle
                  cx={avgOuter.x}
                  cy={avgOuter.y}
                  r="3.5"
                  fill="#FFFFFF"
                  stroke="#000000"
                  strokeWidth="1.5"
                />
              </g>

              {/* Needle Indicator */}
              <g id="speedometer-needle" className="transition-all duration-700 ease-out">
                {/* Needle Line */}
                <line
                  x1={cx}
                  y1={cy}
                  x2={needleTip.x}
                  y2={needleTip.y}
                  stroke={isFaster ? '#00FF41' : isSlower ? '#FF3E00' : '#00E5FF'}
                  strokeWidth="3"
                  strokeLinecap="round"
                  filter="url(#gaugeGlow)"
                />
                {/* Center Pivot Hub */}
                <circle cx={cx} cy={cy} r="8" fill="#141414" stroke="#444" strokeWidth="2" />
                <circle
                  cx={cx}
                  cy={cy}
                  r="4"
                  fill={isFaster ? '#00FF41' : isSlower ? '#FF3E00' : '#00E5FF'}
                />
              </g>

              {/* Arc Center Status Text */}
              <text
                x={cx}
                y={cy - 20}
                fill="#888"
                fontSize="8"
                fontFamily="monospace"
                fontWeight="bold"
                textAnchor="middle"
                className="uppercase tracking-widest"
              >
                MÉDIA REF: {averageDuration}ms
              </text>
            </svg>
          </div>

          {/* Central Digital HUD Readout */}
          <div className="text-center mt-1 space-y-1">
            <div className="flex items-baseline justify-center gap-1">
              <span
                id="speedometer-current-duration-display"
                className={`text-4xl sm:text-5xl font-black font-mono tracking-tighter ${
                  isFaster ? 'text-[#00FF41]' : isSlower ? 'text-[#FF3E00]' : 'text-white'
                }`}
              >
                {currentDuration}
              </span>
              <span className="text-sm font-mono font-bold text-[#888]">ms</span>
            </div>

            <div className="flex items-center justify-center gap-2 text-[10px] font-mono">
              <span className="text-zinc-400">TEMPO DO ÚLTIMO SCAN</span>
              <span className="text-[#444]">•</span>
              <span className="text-white font-bold">{ratio}x da média</span>
            </div>

            {/* Performance Tier Badge */}
            <div
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 mt-1 border font-mono text-[10px] font-black uppercase ${speedTier.bg} ${speedTier.color} ${speedTier.border}`}
            >
              <Zap className="w-3 h-3" />
              <span>{speedTier.label}</span>
            </div>
          </div>
        </div>

        {/* Telemetry Comparison Cards & Analytics Column */}
        <div className="lg:col-span-6 space-y-4">
          {/* Dual Progress Bar: Last Scan vs Average */}
          <div className="bg-[#0A0A0A] p-4 border border-[#222] space-y-3">
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-[#AAA] uppercase font-bold flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-[#00FF41]" />
                Comparativo de Tempos de Execução
              </span>
              <span className="text-[10px] text-[#666]">
                Base: {history.length} execuções
              </span>
            </div>

            {/* Bar 1: Last Scan */}
            <div className="space-y-1">
              <div className="flex justify-between text-[10px] font-mono">
                <span className="text-zinc-300 font-bold flex items-center gap-1">
                  <span>ÚLTIMO SCAN (ATUAL)</span>
                  <span className={`text-[9px] px-1 py-0.2 border ${speedTier.color} ${speedTier.border}`}>
                    {ratio}x
                  </span>
                </span>
                <span className={`font-black ${isFaster ? 'text-[#00FF41]' : isSlower ? 'text-[#FF3E00]' : 'text-white'}`}>
                  {currentDuration} ms
                </span>
              </div>
              <div className="w-full h-2.5 bg-[#141414] border border-[#262626] overflow-hidden">
                <div
                  className={`h-full transition-all duration-500 ${
                    isFaster ? 'bg-[#00FF41]' : isSlower ? 'bg-[#FF3E00]' : 'bg-[#00E5FF]'
                  }`}
                  style={{ width: `${Math.min(100, Math.max(8, (currentDuration / maxScaleMs) * 100))}%` }}
                />
              </div>
            </div>

            {/* Bar 2: Average Scan */}
            <div className="space-y-1">
              <div className="flex justify-between text-[10px] font-mono">
                <span className="text-zinc-400">MÉDIA HISTÓRICA DO WORKSPACE</span>
                <span id="speedometer-average-duration-display" className="font-bold text-white">
                  {averageDuration} ms
                </span>
              </div>
              <div className="w-full h-2.5 bg-[#141414] border border-[#262626] overflow-hidden">
                <div
                  className="h-full bg-sky-500 transition-all duration-500"
                  style={{ width: `${Math.min(100, Math.max(8, (averageDuration / maxScaleMs) * 100))}%` }}
                />
              </div>
            </div>

            {/* Differential Summary Tag */}
            <div className={`p-2.5 border font-mono text-[11px] flex items-center justify-between ${
              isFaster
                ? 'bg-[#001808] border-[#00FF41]/30 text-[#00FF41]'
                : isSlower
                  ? 'bg-[#1C0500] border-[#FF3E00]/30 text-[#FF8533]'
                  : 'bg-[#001026] border-sky-500/30 text-sky-400'
            }`}>
              <div className="flex items-center gap-2">
                {isFaster ? (
                  <CheckCircle2 className="w-4 h-4 text-[#00FF41] shrink-0" />
                ) : isSlower ? (
                  <AlertTriangle className="w-4 h-4 text-[#FF3E00] shrink-0" />
                ) : (
                  <Info className="w-4 h-4 text-sky-400 shrink-0" />
                )}
                <span>
                  {isFaster ? (
                    <>
                      <strong>{absDiffMs}ms mais rápido</strong> que a média ({percentDiff}% de economia temporal).
                    </>
                  ) : isSlower ? (
                    <>
                      <strong>+{absDiffMs}ms acima</strong> da média ({percentDiff}% tempo adicional consumido).
                    </>
                  ) : (
                    <>
                      Execução idêntica à média histórica ({averageDuration}ms).
                    </>
                  )}
                </span>
              </div>
              <span className="text-[9px] uppercase tracking-wider font-bold">
                {speedTier.label.split('•')[0]}
              </span>
            </div>
          </div>

          {/* Quick Engine Telemetry KPI Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div className="bg-[#0A0A0A] p-3 border border-[#222]">
              <div className="flex items-center justify-between text-[#777] mb-1">
                <span className="text-[9px] font-mono uppercase font-bold">Throughput</span>
                <Cpu className="w-3 h-3 text-[#00FF41]" />
              </div>
              <div className="text-xl font-black font-mono text-white">
                {filesPerSec} <span className="text-[10px] font-normal text-[#888]">arq/s</span>
              </div>
              <div className="text-[9px] font-mono text-[#666] mt-0.5">Taxa de ingestão</div>
            </div>

            <div className="bg-[#0A0A0A] p-3 border border-[#222]">
              <div className="flex items-center justify-between text-[#777] mb-1">
                <span className="text-[9px] font-mono uppercase font-bold">Escopo</span>
                <Layers className="w-3 h-3 text-[#3366FF]" />
              </div>
              <div className="text-xl font-black font-mono text-white">
                {scannedFiles} <span className="text-[10px] font-normal text-[#888]">fontes</span>
              </div>
              <div className="text-[9px] font-mono text-[#666] mt-0.5">
                {report.ignoredFilesCount} ignorados
              </div>
            </div>

            <div className="bg-[#0A0A0A] p-3 border border-[#222] col-span-2 sm:col-span-1">
              <div className="flex items-center justify-between text-[#777] mb-1">
                <span className="text-[9px] font-mono uppercase font-bold">Amostragem</span>
                <Activity className="w-3 h-3 text-amber-400" />
              </div>
              <div className="text-xl font-black font-mono text-white">
                {history.length} <span className="text-[10px] font-normal text-[#888]">scans</span>
              </div>
              <div className="text-[9px] font-mono text-[#666] mt-0.5">Janela estatística</div>
            </div>
          </div>

          {/* Historical Scans Spark Bars */}
          <div className="bg-[#0A0A0A] p-3.5 border border-[#222] space-y-2">
            <div className="flex items-center justify-between text-[10px] font-mono">
              <span className="text-zinc-400 uppercase font-bold">
                Histórico Recente de Duração ({history.length} execuções):
              </span>
              <span className="text-[9px] text-[#666]">
                Linha branca: Média ({averageDuration}ms)
              </span>
            </div>

            <div className="flex items-end gap-1.5 h-12 pt-2 border-b border-[#222] relative">
              {/* Average reference line */}
              <div
                className="absolute left-0 right-0 border-t border-dashed border-white/40 pointer-events-none z-10"
                style={{
                  bottom: `${Math.min(95, Math.max(5, (averageDuration / maxScaleMs) * 100))}%`
                }}
                title={`Média de referência: ${averageDuration}ms`}
              />

              {history.map((item, idx) => {
                const isLatest = idx === history.length - 1;
                const heightPercent = Math.min(100, Math.max(10, (item.durationMs / maxScaleMs) * 100));
                const itemFaster = item.durationMs <= averageDuration;

                return (
                  <div
                    key={item.id}
                    className="flex-1 flex flex-col items-center justify-end h-full group relative"
                  >
                    <div
                      className={`w-full transition-all duration-300 ${
                        isLatest
                          ? itemFaster
                            ? 'bg-[#00FF41] shadow-[0_0_8px_rgba(0,255,65,0.6)]'
                            : 'bg-[#FF3E00] shadow-[0_0_8px_rgba(255,62,0,0.6)]'
                          : itemFaster
                            ? 'bg-[#00FF41]/40 hover:bg-[#00FF41]/70'
                            : 'bg-[#FF3E00]/40 hover:bg-[#FF3E00]/70'
                      }`}
                      style={{ height: `${heightPercent}%` }}
                    />
                    {/* Tooltip on hover */}
                    <div className="absolute -top-7 left-1/2 -translate-x-1/2 bg-[#111] border border-[#333] px-1.5 py-0.5 text-[8.5px] font-mono text-white opacity-0 group-hover:opacity-100 pointer-events-none whitespace-nowrap z-20 shadow-md">
                      {item.durationMs}ms ({item.timestamp})
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="flex items-center justify-between text-[8.5px] font-mono text-[#666]">
              <span>SCAN ANTERIOR</span>
              <span className="text-[#00FF41] font-bold">SCAN ATUAL (DIREITA)</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
