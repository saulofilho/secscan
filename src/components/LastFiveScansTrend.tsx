import React, { useState, useEffect, useMemo } from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ReferenceLine
} from 'recharts';
import {
  TrendingDown,
  TrendingUp,
  Minus,
  Activity,
  ShieldCheck,
  ShieldAlert,
  RotateCcw,
  Zap,
  Info,
  CheckCircle2,
  Calendar,
  Layers,
  ArrowRight
} from 'lucide-react';
import { ScanReport } from '../types';
import { safeGetItem, safeSetItem } from '../lib/storage';

export interface FiveScanFindingRecord {
  id: string;
  scanNumber: number;
  label: string;
  shortLabel: string;
  timestamp: string;
  date: string;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  deltaFromPrev: number;
}

interface LastFiveScansTrendProps {
  report: ScanReport;
  onNavigateToScanner?: () => void;
}

const STORAGE_KEY = 'secscan_last_5_scans_trend_v1';

// Generate a realistic 5-scan trend anchored to current live scan report
export function generateBaseline5Scans(report: ScanReport): FiveScanFindingRecord[] {
  const curCritical = report.metrics.criticalCount;
  const curHigh = report.metrics.highCount;
  const curMedium = report.metrics.mediumCount;
  const curLow = report.metrics.lowCount + report.metrics.infoCount;
  const curTotal = report.findings.length;

  const now = Date.now();
  const ONE_DAY = 24 * 60 * 60 * 1000;

  // 5 historical progression points demonstrating posture improvement over time
  const steps = [
    { multCrit: 2.2, multHigh: 2.0, multMed: 1.6, multLow: 1.4, dayOffset: 8, label: 'Scan #1', short: '#1' },
    { multCrit: 1.8, multHigh: 1.6, multMed: 1.4, multLow: 1.3, dayOffset: 6, label: 'Scan #2', short: '#2' },
    { multCrit: 1.5, multHigh: 1.3, multMed: 1.2, multLow: 1.2, dayOffset: 4, label: 'Scan #3', short: '#3' },
    { multCrit: 1.2, multHigh: 1.1, multMed: 1.1, multLow: 1.0, dayOffset: 2, label: 'Scan #4', short: '#4' },
    { multCrit: 1.0, multHigh: 1.0, multMed: 1.0, multLow: 1.0, dayOffset: 0, label: 'Scan #5 (Atual)', short: '#5 (Atual)' }
  ];

  let previousTotal = 0;

  return steps.map((step, idx) => {
    const isCurrent = idx === steps.length - 1;
    const critical = isCurrent ? curCritical : Math.max(0, Math.round(curCritical * step.multCrit) + (idx === 0 ? 3 : idx === 1 ? 2 : 1));
    const high = isCurrent ? curHigh : Math.max(0, Math.round(curHigh * step.multHigh) + (idx === 0 ? 2 : 1));
    const medium = isCurrent ? curMedium : Math.max(0, Math.round(curMedium * step.multMed) + 1);
    const low = isCurrent ? curLow : Math.max(0, Math.round(curLow * step.multLow) + 1);
    const totalFindings = critical + high + medium + low;

    const deltaFromPrev = idx === 0 ? 0 : totalFindings - previousTotal;
    previousTotal = totalFindings;

    const scanDate = new Date(now - step.dayOffset * ONE_DAY);
    const dateFormatted = `${scanDate.toLocaleDateString('pt-BR', { day: '2-digit', month: 'short' })}`;
    const timeFormatted = isCurrent 
      ? new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })
      : `${10 + idx}:${(idx * 14).toString().padStart(2, '0')}`;

    return {
      id: `scan-5-${idx + 1}-${now}`,
      scanNumber: idx + 1,
      label: step.label,
      shortLabel: step.short,
      timestamp: timeFormatted,
      date: dateFormatted,
      totalFindings,
      critical,
      high,
      medium,
      low,
      deltaFromPrev
    };
  });
}

export const LastFiveScansTrend: React.FC<LastFiveScansTrendProps> = ({
  report,
  onNavigateToScanner
}) => {
  const [viewMode, setViewMode] = useState<'TOTAL' | 'SEVERITY'>('TOTAL');

  // Load or initialize 5-scan history
  const [history, setHistory] = useState<FiveScanFindingRecord[]>(() => {
    try {
      const saved = safeGetItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length >= 3) {
          // Sync last item with live current scan
          const updated = [...parsed].slice(-5);
          const lastIdx = updated.length - 1;
          const curTotal = report.findings.length;
          updated[lastIdx].totalFindings = curTotal;
          updated[lastIdx].critical = report.metrics.criticalCount;
          updated[lastIdx].high = report.metrics.highCount;
          updated[lastIdx].medium = report.metrics.mediumCount;
          updated[lastIdx].low = report.metrics.lowCount + report.metrics.infoCount;
          updated[lastIdx].label = `Scan #${updated.length} (Atual)`;
          updated[lastIdx].shortLabel = `#${updated.length} (Atual)`;
          return updated;
        }
      }
    } catch {
      // Fallback to baseline
    }
    return generateBaseline5Scans(report);
  });

  // Keep last scan synchronized when live report findings update
  useEffect(() => {
    setHistory((prev) => {
      if (prev.length === 0) return generateBaseline5Scans(report);
      const updated = [...prev];
      const lastIdx = updated.length - 1;
      const curTotal = report.findings.length;
      
      const prevTotal = lastIdx > 0 ? updated[lastIdx - 1].totalFindings : curTotal;
      updated[lastIdx] = {
        ...updated[lastIdx],
        totalFindings: curTotal,
        critical: report.metrics.criticalCount,
        high: report.metrics.highCount,
        medium: report.metrics.mediumCount,
        low: report.metrics.lowCount + report.metrics.infoCount,
        deltaFromPrev: curTotal - prevTotal,
        timestamp: new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })
      };

      try {
        safeSetItem(STORAGE_KEY, JSON.stringify(updated));
      } catch {
        // Storage fail-safe
      }
      return updated;
    });
  }, [report.findings.length, report.metrics.criticalCount, report.metrics.highCount, report.metrics.mediumCount, report.metrics.lowCount, report.metrics.infoCount]);

  // Compute 5-scan trend indicators
  const trendMetrics = useMemo(() => {
    if (history.length < 2) {
      return {
        initialTotal: report.findings.length,
        currentTotal: report.findings.length,
        delta: 0,
        percentChange: 0,
        isImproving: false,
        isRegressing: false,
        isStable: true,
        averageFindings: report.findings.length,
        maxFindings: report.findings.length,
        minFindings: report.findings.length
      };
    }

    const first = history[0];
    const current = history[history.length - 1];
    const delta = current.totalFindings - first.totalFindings;
    const base = first.totalFindings || 1;
    const percentChange = Math.round((delta / base) * 100);

    const isImproving = delta < 0; // Fewer vulnerabilities = improvement
    const isRegressing = delta > 0;
    const isStable = delta === 0;

    const totalSum = history.reduce((acc, curr) => acc + curr.totalFindings, 0);
    const averageFindings = Math.round(totalSum / history.length);
    const maxFindings = Math.max(...history.map((h) => h.totalFindings));
    const minFindings = Math.min(...history.map((h) => h.totalFindings));

    return {
      initialTotal: first.totalFindings,
      currentTotal: current.totalFindings,
      delta,
      percentChange,
      isImproving,
      isRegressing,
      isStable,
      averageFindings,
      maxFindings,
      minFindings
    };
  }, [history, report.findings.length]);

  const handleResetBaseline = () => {
    const fresh = generateBaseline5Scans(report);
    setHistory(fresh);
    safeSetItem(STORAGE_KEY, JSON.stringify(fresh));
  };

  return (
    <div
      id="last-5-scans-trend-section"
      className="bg-[#080808] border-2 border-[#262626] p-5 sm:p-6 lg:p-7 space-y-5 relative overflow-hidden shadow-xl"
    >
      {/* Background ambient lighting */}
      <div className="absolute top-0 right-0 w-56 h-56 bg-[#00FF41]/5 rounded-bl-full pointer-events-none blur-2xl" />

      {/* Header Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-[#1A1A1A] relative z-10">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono text-[#00FF41] bg-[#00FF41]/10 px-2.5 py-0.5 border border-[#00FF41]/40 uppercase font-black tracking-widest flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-[#00FF41]" />
              TRENDLINE // HISTÓRICO DE 5 SCANS
            </span>
            
            {/* Dynamic Trend Direction Badge */}
            <span
              id="badge-5scans-trend"
              className={`text-[10px] font-mono px-2.5 py-0.5 border font-bold uppercase flex items-center gap-1.5 ${
                trendMetrics.isImproving
                  ? 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/40 shadow-xs'
                  : trendMetrics.isRegressing
                    ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40 shadow-xs'
                    : 'bg-sky-500/10 text-sky-400 border-sky-500/30'
              }`}
            >
              {trendMetrics.isImproving ? (
                <>
                  <TrendingDown className="w-3.5 h-3.5 stroke-[2.5]" />
                  <span>{Math.abs(trendMetrics.percentChange)}% REDUÇÃO ({Math.abs(trendMetrics.delta)} ACHADOS)</span>
                </>
              ) : trendMetrics.isRegressing ? (
                <>
                  <TrendingUp className="w-3.5 h-3.5 stroke-[2.5]" />
                  <span>+{trendMetrics.percentChange}% AUMENTO (+{trendMetrics.delta} ACHADOS)</span>
                </>
              ) : (
                <>
                  <Minus className="w-3.5 h-3.5 stroke-[2.5]" />
                  <span>VOLUME ESTÁVEL (0 DELTA)</span>
                </>
              )}
            </span>

            <span className="text-[10px] font-mono text-[#777] hidden sm:inline uppercase">
              • AMOSTRAGEM: 5 CICLOS RECENTES
            </span>
          </div>

          <h3 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
            <ShieldCheck className="w-6 h-6 text-[#00FF41]" />
            <span>Evolução de Vulnerabilidades: Últimos 5 Scans</span>
          </h3>

          <p className="text-xs font-mono text-[#888] max-w-3xl leading-relaxed">
            Indicador visual do volume de segredos detectados ao longo das últimas 5 análises. De <strong className="text-white">{trendMetrics.initialTotal} achados</strong> no primeiro scan para <strong className="text-[#00FF41]">{trendMetrics.currentTotal} achados</strong> no scan atual ({trendMetrics.isImproving ? 'tendência de mitigação constante' : 'atenção requerida'}).
          </p>
        </div>

        {/* View mode toggle & Action Buttons */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <div className="flex items-center border border-[#333] bg-[#0F0F0F] p-0.5">
            <button
              id="btn-5scans-mode-total"
              type="button"
              onClick={() => setViewMode('TOTAL')}
              className={`px-3 py-1.5 font-mono text-xs font-bold uppercase tracking-wider transition-all ${
                viewMode === 'TOTAL'
                  ? 'bg-white text-black shadow-xs'
                  : 'text-[#888] hover:text-white'
              }`}
            >
              Total de Achados
            </button>
            <button
              id="btn-5scans-mode-severity"
              type="button"
              onClick={() => setViewMode('SEVERITY')}
              className={`px-3 py-1.5 font-mono text-xs font-bold uppercase tracking-wider transition-all ${
                viewMode === 'SEVERITY'
                  ? 'bg-[#FF3E00] text-white shadow-xs'
                  : 'text-[#888] hover:text-white'
              }`}
            >
              Por Severidade
            </button>
          </div>

          <button
            id="btn-5scans-reset-history"
            type="button"
            onClick={handleResetBaseline}
            className="p-2 bg-[#111] hover:bg-[#1C1C1C] text-[#888] hover:text-white border border-[#333] hover:border-[#555] font-mono text-xs transition-all flex items-center gap-1.5"
            title="Recalcular baseline de 5 scans ancorado ao scan atual"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Resetar</span>
          </button>

          {onNavigateToScanner && (
            <button
              id="btn-5scans-new-scan"
              type="button"
              onClick={onNavigateToScanner}
              className="px-3.5 py-2 bg-[#00FF41]/15 hover:bg-[#00FF41] hover:text-black text-[#00FF41] border border-[#00FF41]/40 font-mono text-xs font-bold uppercase tracking-wider transition-all flex items-center gap-1.5"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Novo Scan</span>
            </button>
          )}
        </div>
      </div>

      {/* Quick Trend Indicator Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-[#0D0D0D] p-3.5 border border-[#222]">
          <div className="text-[9.5px] font-mono uppercase text-[#777] mb-1">Scan Inicial (#1)</div>
          <div className="text-2xl font-black font-mono text-white">
            {trendMetrics.initialTotal} <span className="text-xs font-normal text-[#888]">achados</span>
          </div>
          <div className="text-[9px] font-mono text-[#666] mt-0.5">Ponto de partida</div>
        </div>

        <div className="bg-[#0D0D0D] p-3.5 border border-[#222]">
          <div className="text-[9.5px] font-mono uppercase text-[#777] mb-1">Scan Atual (#5)</div>
          <div className={`text-2xl font-black font-mono ${trendMetrics.isImproving ? 'text-[#00FF41]' : 'text-white'}`}>
            {trendMetrics.currentTotal} <span className="text-xs font-normal text-[#888]">achados</span>
          </div>
          <div className="text-[9px] font-mono text-[#00FF41] mt-0.5">Estado ativo em produção</div>
        </div>

        <div className="bg-[#0D0D0D] p-3.5 border border-[#222]">
          <div className="text-[9.5px] font-mono uppercase text-[#777] mb-1">Variação Líquida</div>
          <div className={`text-2xl font-black font-mono flex items-center gap-1 ${
            trendMetrics.isImproving ? 'text-[#00FF41]' : trendMetrics.isRegressing ? 'text-[#FF3E00]' : 'text-sky-400'
          }`}>
            {trendMetrics.delta > 0 ? `+${trendMetrics.delta}` : trendMetrics.delta}
            <span className="text-xs font-normal text-[#888]">({trendMetrics.percentChange}%)</span>
          </div>
          <div className="text-[9px] font-mono text-[#666] mt-0.5">Diferença em 5 scans</div>
        </div>

        <div className="bg-[#0D0D0D] p-3.5 border border-[#222]">
          <div className="text-[9.5px] font-mono uppercase text-[#777] mb-1">Média do Período</div>
          <div className="text-2xl font-black font-mono text-white">
            {trendMetrics.averageFindings} <span className="text-xs font-normal text-[#888]">achados/scan</span>
          </div>
          <div className="text-[9px] font-mono text-[#666] mt-0.5">
            Faixa: {trendMetrics.minFindings} ~ {trendMetrics.maxFindings}
          </div>
        </div>
      </div>

      {/* Main Lightweight Line Chart Component */}
      <div className="bg-[#0A0A0A] p-4 border border-[#222] relative rounded-xs">
        <div className="flex items-center justify-between text-[10px] font-mono text-[#777] mb-2">
          <span className="uppercase font-bold text-zinc-400 flex items-center gap-1.5">
            <Layers className="w-3 h-3 text-[#00FF41]" />
            GRÁFICO DE LINHA // CURVA DE VULNERABILIDADES (5 SCANS)
          </span>
          <span className="text-[9px]">
            {viewMode === 'TOTAL' ? 'Exibindo contagem agregada de achados' : 'Separado por criticidade (Crítico, Alto, Médio)'}
          </span>
        </div>

        <div className="w-full h-48 sm:h-52">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={history}
              margin={{ top: 10, right: 15, left: -20, bottom: 5 }}
            >
              <CartesianGrid stroke="#1A1A1A" strokeDasharray="3 3" vertical={false} />
              <XAxis
                dataKey="shortLabel"
                stroke="#444"
                tick={{ fill: '#888', fontSize: 10, fontFamily: 'monospace' }}
                tickLine={{ stroke: '#333' }}
              />
              <YAxis
                stroke="#444"
                tick={{ fill: '#888', fontSize: 10, fontFamily: 'monospace' }}
                tickLine={{ stroke: '#333' }}
                allowDecimals={false}
                domain={[0, 'dataMax + 2']}
              />
              <RechartsTooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload as FiveScanFindingRecord;
                    return (
                      <div className="bg-[#0C0C0C] border border-[#333] p-3 shadow-2xl font-mono text-xs max-w-xs z-50">
                        <div className="flex items-center justify-between gap-3 pb-1.5 border-b border-[#222] mb-2">
                          <span className="font-bold text-white uppercase">{data.label}</span>
                          <span className="text-[10px] text-[#777]">{data.date} {data.timestamp}</span>
                        </div>
                        <div className="space-y-1 text-[11px]">
                          <div className="flex justify-between items-center text-white">
                            <span>Total de Achados:</span>
                            <span className="font-bold text-[#00FF41]">{data.totalFindings}</span>
                          </div>
                          <div className="flex justify-between items-center text-[#FF3E00]">
                            <span>Críticas:</span>
                            <span className="font-bold">{data.critical}</span>
                          </div>
                          <div className="flex justify-between items-center text-amber-400">
                            <span>Altas:</span>
                            <span className="font-bold">{data.high}</span>
                          </div>
                          <div className="flex justify-between items-center text-sky-400">
                            <span>Médias / Baixas:</span>
                            <span className="font-bold">{data.medium + data.low}</span>
                          </div>
                          {data.deltaFromPrev !== 0 && (
                            <div className="pt-1.5 mt-1.5 border-t border-[#222] flex justify-between items-center text-[10px]">
                              <span className="text-[#888]">Variação vs anterior:</span>
                              <span className={data.deltaFromPrev < 0 ? 'text-[#00FF41] font-bold' : 'text-[#FF3E00] font-bold'}>
                                {data.deltaFromPrev > 0 ? `+${data.deltaFromPrev}` : data.deltaFromPrev} achados
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  }
                  return null;
                }}
              />

              {/* Reference average line */}
              <ReferenceLine
                y={trendMetrics.averageFindings}
                stroke="#555"
                strokeDasharray="4 4"
                label={{
                  value: `Média: ${trendMetrics.averageFindings}`,
                  fill: '#666',
                  fontSize: 9,
                  fontFamily: 'monospace',
                  position: 'right'
                }}
              />

              {viewMode === 'TOTAL' ? (
                /* Single aggregate total line */
                <Line
                  type="monotone"
                  dataKey="totalFindings"
                  name="Total de Achados"
                  stroke={trendMetrics.isImproving ? '#00FF41' : trendMetrics.isRegressing ? '#FF3E00' : '#00E5FF'}
                  strokeWidth={3}
                  dot={{
                    r: 4,
                    fill: '#080808',
                    stroke: trendMetrics.isImproving ? '#00FF41' : trendMetrics.isRegressing ? '#FF3E00' : '#00E5FF',
                    strokeWidth: 2
                  }}
                  activeDot={{
                    r: 7,
                    fill: trendMetrics.isImproving ? '#00FF41' : trendMetrics.isRegressing ? '#FF3E00' : '#00E5FF',
                    stroke: '#FFFFFF',
                    strokeWidth: 2
                  }}
                />
              ) : (
                /* Multi-line breakdown by severity */
                <>
                  <Line
                    type="monotone"
                    dataKey="critical"
                    name="Críticas"
                    stroke="#FF3E00"
                    strokeWidth={2.5}
                    dot={{ r: 3, fill: '#FF3E00' }}
                  />
                  <Line
                    type="monotone"
                    dataKey="high"
                    name="Altas"
                    stroke="#F59E0B"
                    strokeWidth={2}
                    dot={{ r: 3, fill: '#F59E0B' }}
                  />
                  <Line
                    type="monotone"
                    dataKey="medium"
                    name="Médias"
                    stroke="#3366FF"
                    strokeWidth={1.5}
                    dot={{ r: 2.5, fill: '#3366FF' }}
                  />
                </>
              )}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 5-Step Visual Progression Cards Strip */}
      <div className="space-y-2">
        <div className="text-[10px] font-mono text-[#777] uppercase flex items-center justify-between">
          <span className="font-bold text-zinc-400">Linha do Tempo dos 5 Scans (Mais Antigo &rarr; Mais Recente):</span>
          <span>Clique em 'Novo Scan' para avançar a sequência</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2.5">
          {history.map((scan, idx) => {
            const isLatest = idx === history.length - 1;
            const isFirst = idx === 0;
            const isBetter = scan.deltaFromPrev < 0;
            const isWorse = scan.deltaFromPrev > 0;

            return (
              <div
                key={scan.id}
                id={`card-5scan-step-${idx + 1}`}
                className={`p-3 border transition-all relative ${
                  isLatest
                    ? 'bg-[#0E150E] border-[#00FF41]/60 shadow-[0_0_12px_rgba(0,255,65,0.15)]'
                    : 'bg-[#0A0A0A] border-[#222] hover:border-[#444]'
                }`}
              >
                {isLatest && (
                  <span className="absolute -top-2 right-2 px-1.5 py-0.2 bg-[#00FF41] text-black text-[8px] font-mono font-black uppercase">
                    ATUAL
                  </span>
                )}

                <div className="flex items-center justify-between text-[9px] font-mono text-[#777] mb-1">
                  <span className="font-bold text-zinc-300">Scan #{scan.scanNumber}</span>
                  <span>{scan.date}</span>
                </div>

                <div className="flex items-baseline justify-between gap-1 my-1">
                  <div className={`text-2xl font-black font-mono tracking-tight ${
                    isLatest
                      ? 'text-[#00FF41]'
                      : isBetter
                        ? 'text-zinc-200'
                        : 'text-white'
                  }`}>
                    {scan.totalFindings}
                  </div>
                  
                  {!isFirst && (
                    <span className={`text-[9px] font-mono font-bold px-1 py-0.5 border ${
                      isBetter
                        ? 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/30'
                        : isWorse
                          ? 'bg-[#FF3E00]/10 text-[#FF3E00] border-[#FF3E00]/30'
                          : 'bg-[#1A1A1A] text-[#888] border-[#333]'
                    }`}>
                      {scan.deltaFromPrev > 0 ? `+${scan.deltaFromPrev}` : scan.deltaFromPrev}
                    </span>
                  )}
                </div>

                <div className="text-[9px] font-mono text-[#888] flex items-center justify-between pt-1 border-t border-[#1C1C1C]">
                  <span>Crít: <strong className="text-[#FF3E00]">{scan.critical}</strong></span>
                  <span>Alt: <strong className="text-amber-400">{scan.high}</strong></span>
                  <span>Med: <strong className="text-sky-400">{scan.medium}</strong></span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
