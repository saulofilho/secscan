import React from 'react';
import { PieChart, Pie, Cell, Tooltip as RechartsTooltip } from 'recharts';
import { AlertOctagon, ShieldAlert, AlertTriangle, CheckCircle2 } from 'lucide-react';

export interface ValidationSeverityDistribution {
  critical: number;
  high: number;
  warning: number;
  total: number;
}

interface ValidationSeverityDonutChartProps {
  distribution: ValidationSeverityDistribution;
  onSelectSeverity?: (severity: 'CRITICAL' | 'HIGH' | 'WARNING') => void;
  activeFilters?: {
    CRITICAL: boolean;
    HIGH: boolean;
    WARNING: boolean;
  };
}

interface DonutSlice {
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'WARNING' | 'COMPLIANT';
  value: number;
  percentage: number;
  color: string;
}

export const ValidationSeverityDonutChart: React.FC<ValidationSeverityDonutChartProps> = ({
  distribution,
  onSelectSeverity,
  activeFilters
}) => {
  const { critical, high, warning, total } = distribution;

  // Build chart slices based on counts
  const chartData: DonutSlice[] = React.useMemo(() => {
    if (total === 0) {
      return [
        {
          name: 'Conforme',
          severity: 'COMPLIANT',
          value: 1,
          percentage: 100,
          color: '#10B981' // emerald-500
        }
      ];
    }

    const slices: DonutSlice[] = [];

    if (critical > 0) {
      slices.push({
        name: 'Crítico',
        severity: 'CRITICAL',
        value: critical,
        percentage: Math.round((critical / total) * 100),
        color: '#F43F5E' // rose-500
      });
    }

    if (high > 0) {
      slices.push({
        name: 'Alto',
        severity: 'HIGH',
        value: high,
        percentage: Math.round((high / total) * 100),
        color: '#F59E0B' // amber-500
      });
    }

    if (warning > 0) {
      slices.push({
        name: 'Aviso',
        severity: 'WARNING',
        value: warning,
        percentage: Math.round((warning / total) * 100),
        color: '#EAB308' // yellow-500
      });
    }

    return slices;
  }, [critical, high, warning, total]);

  const hasMultipleSlices = chartData.length > 1;

  return (
    <div 
      id="validation-severity-progress-bar"
      className="p-2.5 rounded bg-black/50 border border-white/10 font-mono text-[10px] shadow-sm transition-all"
    >
      <div className="flex flex-col sm:flex-row items-center sm:items-start justify-between gap-3">
        {/* Left Side: Compact Donut Chart HUD */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="relative w-[84px] h-[84px] shrink-0 flex items-center justify-center">
            <PieChart width={84} height={84}>
              <Pie
                data={chartData}
                dataKey="value"
                nameKey="name"
                cx={42}
                cy={42}
                innerRadius={24}
                outerRadius={38}
                paddingAngle={hasMultipleSlices ? 3 : 0}
                stroke="#0A0A0A"
                strokeWidth={1.5}
                isAnimationActive={true}
                animationDuration={400}
                onClick={(entry: any) => {
                  const slice = (entry?.payload || entry) as DonutSlice | undefined;
                  if (slice && slice.severity && slice.severity !== 'COMPLIANT' && onSelectSeverity) {
                    onSelectSeverity(slice.severity as 'CRITICAL' | 'HIGH' | 'WARNING');
                  }
                }}
                className="cursor-pointer"
              >
                {chartData.map((slice, index) => (
                  <Cell 
                    key={`slice-${index}`} 
                    fill={slice.color}
                    className="hover:opacity-85 transition-opacity"
                  />
                ))}
              </Pie>
              <RechartsTooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload as DonutSlice;
                    return (
                      <div className="bg-[#111] border border-white/20 p-2 rounded shadow-xl font-mono text-[10px] text-white z-50">
                        <div className="flex items-center gap-1.5 font-bold mb-1">
                          <span 
                            className="w-2 h-2 rounded-full" 
                            style={{ backgroundColor: data.color }} 
                          />
                          <span>{data.name}</span>
                        </div>
                        <div className="text-white/80">
                          {data.severity === 'COMPLIANT' ? (
                            <span className="text-emerald-400">100% Validado</span>
                          ) : (
                            <span>{data.value} achado(s) ({data.percentage}%)</span>
                          )}
                        </div>
                      </div>
                    );
                  }
                  return null;
                }}
              />
            </PieChart>

            {/* Center HUD Count */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className={`font-mono text-xs font-black leading-none ${
                total === 0 ? 'text-emerald-400' : 'text-white'
              }`}>
                {total}
              </span>
              <span className="text-[7.5px] font-mono text-white/50 uppercase tracking-tighter leading-none mt-0.5">
                {total === 0 ? 'OK' : 'TOTAL'}
              </span>
            </div>
          </div>

          {/* Quick Context Summary next to donut */}
          <div className="space-y-1 text-[10px]">
            <div className="flex items-center gap-1.5 font-bold text-white uppercase tracking-wider">
              <span>Distribuição de Severidade</span>
              <span className="text-white/40 font-normal">({total} achados)</span>
            </div>
            <p className="text-white/60 text-[9.5px] max-w-xs leading-tight">
              {total === 0 
                ? 'Nenhuma violação de severidade detectada nesta ingestão de código.'
                : 'Proporção entre ameaças Críticas, Altas e Avisos mapeados.'}
            </p>
          </div>
        </div>

        {/* Right Side: Interactive Breakdown Badges & Legend */}
        <div className="flex flex-wrap sm:flex-col items-end sm:items-end gap-1.5 w-full sm:w-auto">
          {/* Critical Slice */}
          <button
            type="button"
            onClick={() => onSelectSeverity && onSelectSeverity('CRITICAL')}
            className={`px-2 py-1 rounded inline-flex items-center justify-between gap-2 text-[10px] font-mono border transition-all cursor-pointer w-full sm:w-auto ${
              critical > 0
                ? activeFilters?.CRITICAL !== false
                  ? 'bg-rose-500/20 text-rose-200 border-rose-500/40 hover:bg-rose-500/30'
                  : 'bg-black/30 text-zinc-500 border-white/10 opacity-60'
                : 'bg-black/20 text-white/40 border-white/5 cursor-default'
            }`}
            title="Alternar filtro de achados Críticos"
          >
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-rose-500 shrink-0" />
              <span className="font-bold uppercase tracking-wider">Crítico</span>
            </div>
            <div className="flex items-center gap-1.5 font-bold">
              <span className="text-white">{critical}</span>
              <span className="text-[8.5px] text-white/50">
                ({total > 0 ? Math.round((critical / total) * 100) : 0}%)
              </span>
            </div>
          </button>

          {/* High Slice */}
          <button
            type="button"
            onClick={() => onSelectSeverity && onSelectSeverity('HIGH')}
            className={`px-2 py-1 rounded inline-flex items-center justify-between gap-2 text-[10px] font-mono border transition-all cursor-pointer w-full sm:w-auto ${
              high > 0
                ? activeFilters?.HIGH !== false
                  ? 'bg-amber-500/20 text-amber-200 border-amber-500/40 hover:bg-amber-500/30'
                  : 'bg-black/30 text-zinc-500 border-white/10 opacity-60'
                : 'bg-black/20 text-white/40 border-white/5 cursor-default'
            }`}
            title="Alternar filtro de achados Altos"
          >
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-amber-500 shrink-0" />
              <span className="font-bold uppercase tracking-wider">Alto</span>
            </div>
            <div className="flex items-center gap-1.5 font-bold">
              <span className="text-white">{high}</span>
              <span className="text-[8.5px] text-white/50">
                ({total > 0 ? Math.round((high / total) * 100) : 0}%)
              </span>
            </div>
          </button>

          {/* Warning Slice */}
          <button
            type="button"
            onClick={() => onSelectSeverity && onSelectSeverity('WARNING')}
            className={`px-2 py-1 rounded inline-flex items-center justify-between gap-2 text-[10px] font-mono border transition-all cursor-pointer w-full sm:w-auto ${
              warning > 0
                ? activeFilters?.WARNING !== false
                  ? 'bg-yellow-500/20 text-yellow-200 border-yellow-500/40 hover:bg-yellow-500/30'
                  : 'bg-black/30 text-zinc-500 border-white/10 opacity-60'
                : 'bg-black/20 text-white/40 border-white/5 cursor-default'
            }`}
            title="Alternar filtro de achados de Aviso"
          >
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-yellow-400 shrink-0" />
              <span className="font-bold uppercase tracking-wider">Aviso</span>
            </div>
            <div className="flex items-center gap-1.5 font-bold">
              <span className="text-white">{warning}</span>
              <span className="text-[8.5px] text-white/50">
                ({total > 0 ? Math.round((warning / total) * 100) : 0}%)
              </span>
            </div>
          </button>

          {/* Compliant Indicator if 0 */}
          {total === 0 && (
            <div className="px-2 py-1 rounded inline-flex items-center gap-1.5 text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
              <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
              <span>Conforme (0 violações)</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
