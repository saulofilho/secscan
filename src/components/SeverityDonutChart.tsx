import React, { useState } from 'react';
import { 
  PieChart, 
  Pie, 
  Cell, 
  ResponsiveContainer, 
  Tooltip as RechartsTooltip 
} from 'recharts';
import { AlertOctagon, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { ScanReport, SeverityLevel } from '../types';

interface SeverityDonutChartProps {
  report: ScanReport;
  onSelectSeverity?: (severity: SeverityLevel) => void;
}

interface SeveritySlice {
  name: 'Critical' | 'High' | 'Medium' | 'Low';
  severity: SeverityLevel;
  value: number;
  percentage: number;
  color: string;
  badgeBg: string;
  badgeBorder: string;
}

const SEVERITY_CONFIG: Record<'Critical' | 'High' | 'Medium' | 'Low', {
  severity: SeverityLevel;
  color: string;
  badgeBg: string;
  badgeBorder: string;
}> = {
  Critical: {
    severity: 'CRITICAL',
    color: '#FF3E00',
    badgeBg: 'bg-[#220700]',
    badgeBorder: 'border-[#FF3E00]/40'
  },
  High: {
    severity: 'HIGH',
    color: '#FF7A00',
    badgeBg: 'bg-[#261200]',
    badgeBorder: 'border-[#FF7A00]/40'
  },
  Medium: {
    severity: 'MEDIUM',
    color: '#EAB308',
    badgeBg: 'bg-[#241C02]',
    badgeBorder: 'border-[#EAB308]/40'
  },
  Low: {
    severity: 'LOW',
    color: '#3366FF',
    badgeBg: 'bg-[#05112E]',
    badgeBorder: 'border-[#3366FF]/40'
  }
};

export const SeverityDonutChart: React.FC<SeverityDonutChartProps> = ({
  report,
  onSelectSeverity
}) => {
  const [activeIndex, setActiveIndex] = useState<number | null>(null);

  const { metrics, findings } = report;
  const totalFindings = findings.length;

  const severityItems: SeveritySlice[] = [
    {
      name: 'Critical',
      severity: SEVERITY_CONFIG.Critical.severity,
      value: metrics.criticalCount,
      percentage: totalFindings > 0 ? Math.round((metrics.criticalCount / totalFindings) * 100) : 0,
      color: SEVERITY_CONFIG.Critical.color,
      badgeBg: SEVERITY_CONFIG.Critical.badgeBg,
      badgeBorder: SEVERITY_CONFIG.Critical.badgeBorder
    },
    {
      name: 'High',
      severity: SEVERITY_CONFIG.High.severity,
      value: metrics.highCount,
      percentage: totalFindings > 0 ? Math.round((metrics.highCount / totalFindings) * 100) : 0,
      color: SEVERITY_CONFIG.High.color,
      badgeBg: SEVERITY_CONFIG.High.badgeBg,
      badgeBorder: SEVERITY_CONFIG.High.badgeBorder
    },
    {
      name: 'Medium',
      severity: SEVERITY_CONFIG.Medium.severity,
      value: metrics.mediumCount,
      percentage: totalFindings > 0 ? Math.round((metrics.mediumCount / totalFindings) * 100) : 0,
      color: SEVERITY_CONFIG.Medium.color,
      badgeBg: SEVERITY_CONFIG.Medium.badgeBg,
      badgeBorder: SEVERITY_CONFIG.Medium.badgeBorder
    },
    {
      name: 'Low',
      severity: SEVERITY_CONFIG.Low.severity,
      value: metrics.lowCount + metrics.infoCount,
      percentage: totalFindings > 0 ? Math.round(((metrics.lowCount + metrics.infoCount) / totalFindings) * 100) : 0,
      color: SEVERITY_CONFIG.Low.color,
      badgeBg: SEVERITY_CONFIG.Low.badgeBg,
      badgeBorder: SEVERITY_CONFIG.Low.badgeBorder
    }
  ];

  // Chart data filter: non-zero slices for rendering the donut pie
  const chartData = severityItems.filter(item => item.value > 0);

  const activeItem = activeIndex !== null && chartData[activeIndex] 
    ? chartData[activeIndex] 
    : null;

  return (
    <div className="bg-[#080808] p-6 border border-[#222] flex flex-col justify-between">
      {/* Header */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-[11px] font-black tracking-[0.2em] text-white uppercase flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-[#FF3E00]" />
            <span>Severity Distribution</span>
          </h2>
          <span className="text-[10px] font-mono px-2 py-0.5 bg-[#111] text-[#888] border border-[#262626] uppercase">
            {totalFindings} {totalFindings === 1 ? 'finding' : 'findings'}
          </span>
        </div>
        <p className="text-[10px] font-mono text-[#666] leading-relaxed mb-2">
          Proportional breakdown of discovered vulnerabilities by severity classification (Critical, High, Medium, Low).
        </p>
      </div>

      {/* Donut Chart Canvas with Center Stat */}
      <div className="relative h-60 w-full flex items-center justify-center my-2">
        {totalFindings > 0 ? (
          <>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={62}
                  outerRadius={88}
                  paddingAngle={chartData.length > 1 ? 4 : 0}
                  dataKey="value"
                  stroke="#080808"
                  strokeWidth={2}
                  onMouseEnter={(_, index) => setActiveIndex(index)}
                  onMouseLeave={() => setActiveIndex(null)}
                  onClick={(entry: any) => {
                    const item = entry?.payload as SeveritySlice | undefined;
                    if (item && onSelectSeverity) {
                      onSelectSeverity(item.severity);
                    }
                  }}
                  cursor="pointer"
                >
                  {chartData.map((entry, index) => (
                    <Cell 
                      key={`cell-${index}`} 
                      fill={entry.color} 
                      opacity={activeIndex === null || activeIndex === index ? 1 : 0.4}
                      style={{
                        transition: 'opacity 0.2s ease, transform 0.2s ease',
                        outline: 'none'
                      }}
                    />
                  ))}
                </Pie>
                <RechartsTooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload as SeveritySlice;
                      return (
                        <div className="bg-[#0D0D0D] border border-[#333] shadow-2xl p-3 font-mono text-xs space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="w-2.5 h-2.5 inline-block" style={{ backgroundColor: data.color }} />
                            <span className="font-bold text-white uppercase">{data.name}</span>
                          </div>
                          <div className="text-[#AAA] flex items-center justify-between gap-4 pt-1 border-t border-[#222]">
                            <span>Contagem:</span>
                            <span className="font-bold text-white">{data.value}</span>
                          </div>
                          <div className="text-[#AAA] flex items-center justify-between gap-4">
                            <span>Participação:</span>
                            <span className="font-bold" style={{ color: data.color }}>{data.percentage}%</span>
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
              </PieChart>
            </ResponsiveContainer>

            {/* Center Donut Label */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center select-none">
              {activeItem ? (
                <div className="space-y-0.5 animate-in fade-in duration-150">
                  <span 
                    className="text-[10px] font-black uppercase tracking-wider block font-mono"
                    style={{ color: activeItem.color }}
                  >
                    {activeItem.name}
                  </span>
                  <div className="text-2xl font-black text-white font-mono tracking-tight">
                    {activeItem.value}
                  </div>
                  <span className="text-[9px] font-mono text-[#888] block">
                    {activeItem.percentage}% of total
                  </span>
                </div>
              ) : (
                <div className="space-y-0.5">
                  <span className="text-[9px] font-black uppercase tracking-[0.2em] text-[#666] block font-mono">
                    TOTAL
                  </span>
                  <div className="text-2xl font-black text-white font-mono tracking-tight">
                    {totalFindings}
                  </div>
                  <span className="text-[9px] font-mono text-[#888] block uppercase">
                    Findings
                  </span>
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="text-center text-[#666] font-mono text-xs py-10">
            <CheckCircle2 className="w-9 h-9 text-[#00FF41] mx-auto mb-2" />
            <span className="font-bold text-white block">ZERO_FINDINGS</span>
            <span className="text-[10px] text-[#666]">Nenhuma vulnerabilidade detectada</span>
          </div>
        )}
      </div>

      {/* 4 Severity Level Cards / Legend (Critical, High, Medium, Low) */}
      <div className="grid grid-cols-2 gap-2 pt-4 border-t border-[#1A1A1A] font-mono text-xs">
        {severityItems.map((item) => (
          <div 
            key={item.name}
            onClick={() => onSelectSeverity && onSelectSeverity(item.severity)}
            className={`p-2.5 border transition-all cursor-pointer ${
              activeItem?.name === item.name 
                ? 'border-white bg-[#141414]' 
                : 'border-[#1E1E1E] bg-[#0A0A0A] hover:border-[#333]'
            }`}
          >
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-none" style={{ backgroundColor: item.color }} />
                <span className="text-[11px] font-bold text-white tracking-wide uppercase">
                  {item.name}
                </span>
              </div>
              <span className="text-[9px] text-[#666] font-bold">
                {item.percentage}%
              </span>
            </div>
            <div className="flex items-baseline justify-between">
              <span className="text-base font-black text-white">
                {item.value}
              </span>
              <span className="text-[9px] text-[#555] uppercase">
                {item.value === 1 ? 'achado' : 'achados'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
