import React, { useState, useMemo, useEffect } from 'react';
import {
  ResponsiveContainer,
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ReferenceLine,
  ReferenceArea,
  Cell
} from 'recharts';
import {
  ShieldAlert,
  AlertOctagon,
  Flame,
  AlertTriangle,
  ShieldCheck,
  Filter,
  Sliders,
  Search,
  Download,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  RefreshCw,
  Tag,
  Info,
  Layers,
  ArrowUpDown
} from 'lucide-react';
import { ScanFinding, SeverityLevel } from '../types';
import { safeGetItem, safeSetItem } from '../lib/storage';

export type RiskQuadrantId = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type UserRiskStatus = 
  | 'PENDING'
  | 'PRIORITY_FIX'
  | 'IN_MITIGATION'
  | 'RISK_ACCEPTED'
  | 'FALSE_POSITIVE';

export interface FindingRiskPoint {
  id: string;
  finding: ScanFinding;
  ruleName: string;
  ruleId: string;
  file: string;
  line: number;
  category: string;
  severity: SeverityLevel;
  entropy: number;
  impact: number;        // 0.0 - 10.0
  likelihood: number;    // 0.0 - 10.0
  quadrant: RiskQuadrantId;
  userStatus: UserRiskStatus;
  statusLabel: string;
  riskScore: number;
  zWeight: number;
}

interface RiskMatrix2x2Props {
  findings: ScanFinding[];
  onSelectFinding: (finding: ScanFinding) => void;
  onNavigateToScanner?: () => void;
  onNavigateToFile?: (filePath: string) => void;
}

const STORAGE_STATUS_KEY = 'secscan_user_risk_categorization_v1';
const STORAGE_THRESHOLD_KEY = 'secscan_risk_matrix_threshold_v1';

const QUADRANT_CONFIG: Record<RiskQuadrantId, {
  label: string;
  subLabel: string;
  color: string;
  bgLight: string;
  borderColor: string;
  badgeBg: string;
  description: string;
  recommendation: string;
  icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }>;
}> = {
  CRITICAL: {
    label: 'Risco Crítico',
    subLabel: 'Alto Impacto · Alta Probabilidade',
    color: '#FF3E00',
    bgLight: 'rgba(255, 62, 0, 0.07)',
    borderColor: 'rgba(255, 62, 0, 0.4)',
    badgeBg: 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40',
    description: 'Vulnerabilidades altamente exploráveis com potencial de dano catastrófico a credenciais essenciais ou infraestrutura.',
    recommendation: 'Mitigação imediata mandatória. Revogar e rotacionar segredo em produção nas próximas 2 horas.',
    icon: AlertOctagon
  },
  HIGH: {
    label: 'Risco Alto',
    subLabel: 'Alto Impacto · Baixa Probabilidade',
    color: '#FF7A00',
    bgLight: 'rgba(255, 122, 0, 0.05)',
    borderColor: 'rgba(255, 122, 0, 0.35)',
    badgeBg: 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/40',
    description: 'Dano substancial em caso de vazamento, porém requer pré-condições complexas ou acesso a arquivos confidenciais.',
    recommendation: 'Ação prioritária. Aplicar controle de acesso restrito e agendar correção na sprint atual.',
    icon: Flame
  },
  MEDIUM: {
    label: 'Risco Moderado',
    subLabel: 'Baixo Impacto · Alta Probabilidade',
    color: '#EAB308',
    bgLight: 'rgba(234, 179, 8, 0.05)',
    borderColor: 'rgba(234, 179, 8, 0.35)',
    badgeBg: 'bg-[#EAB308]/15 text-[#EAB308] border-[#EAB308]/40',
    description: 'Fácil detecção ou exposição frequente (ex: rotas de API, tokens expirados), porém com raio de impacto contido.',
    recommendation: 'Higiene operacional de código. Sanitizar e remover menções em logs ou repositórios públicos.',
    icon: AlertTriangle
  },
  LOW: {
    label: 'Risco Baixo',
    subLabel: 'Baixo Impacto · Baixa Probabilidade',
    color: '#38BDF8',
    bgLight: 'rgba(56, 189, 248, 0.04)',
    borderColor: 'rgba(56, 189, 248, 0.3)',
    badgeBg: 'bg-[#38BDF8]/15 text-[#38BDF8] border-[#38BDF8]/40',
    description: 'Achados informativos ou credenciais secundárias de ambiente local/teste com exposição e dano mínimos.',
    recommendation: 'Monitoramento contínuo. Aceitação formal de risco residual ou refatoração durante refatorações periódicas.',
    icon: ShieldCheck
  }
};

const USER_STATUS_OPTIONS: { value: UserRiskStatus; label: string; badgeClass: string }[] = [
  { value: 'PENDING', label: 'Pendente', badgeClass: 'bg-zinc-800 text-zinc-300 border-zinc-700' },
  { value: 'PRIORITY_FIX', label: 'Correção Prioritária', badgeClass: 'bg-rose-500/20 text-rose-300 border-rose-500/40' },
  { value: 'IN_MITIGATION', label: 'Em Mitigação', badgeClass: 'bg-amber-500/20 text-amber-300 border-amber-500/40' },
  { value: 'RISK_ACCEPTED', label: 'Risco Aceito', badgeClass: 'bg-sky-500/20 text-sky-300 border-sky-500/40' },
  { value: 'FALSE_POSITIVE', label: 'Falso Positivo', badgeClass: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' }
];

// Helper to compute deterministic impact (0.0 to 10.0)
function computeImpact(finding: ScanFinding): number {
  let base = 2.0;
  switch (finding.severity) {
    case 'CRITICAL': base = 8.5; break;
    case 'HIGH': base = 6.8; break;
    case 'MEDIUM': base = 4.5; break;
    case 'LOW': base = 2.5; break;
    case 'INFO': base = 1.0; break;
  }

  // File Criticality Adjustment
  const fileCrit = finding.fileCriticality || 'MEDIUM';
  if (fileCrit === 'CRITICAL') base += 1.4;
  else if (fileCrit === 'HIGH') base += 0.8;
  else if (fileCrit === 'LOW') base -= 0.6;

  // Category sensitivity
  if (['CLOUD_CREDENTIAL', 'PRIVATE_KEY', 'DATABASE_URI'].includes(finding.category)) {
    base += 0.8;
  } else if (['API_KEY', 'AUTH_TOKEN', 'PASSWORD'].includes(finding.category)) {
    base += 0.5;
  }

  // Cap between 0.5 and 10.0
  return Math.min(10.0, Math.max(0.5, parseFloat(base.toFixed(1))));
}

// Helper to compute deterministic likelihood (0.0 to 10.0)
function computeLikelihood(finding: ScanFinding): number {
  let base = 3.5;

  // Entropy factor (high entropy = live active key = high exploitability)
  const entropy = finding.entropy ?? 3.0;
  base += (entropy / 6.0) * 3.5;

  // File exposure
  const file = (finding.file || '').toLowerCase();
  if (file.includes('.env') || file.includes('credentials') || file.includes('secrets')) {
    base += 1.5;
  } else if (file.includes('test') || file.includes('spec') || file.includes('mock')) {
    base -= 1.8;
  } else if (file.endsWith('.js') || file.endsWith('.ts') || file.endsWith('.html')) {
    base += 0.8;
  }

  // Category exploitability
  if (['CLOUD_CREDENTIAL', 'API_KEY', 'AUTH_TOKEN'].includes(finding.category)) {
    base += 1.0;
  }

  return Math.min(10.0, Math.max(0.5, parseFloat(base.toFixed(1))));
}

export const RiskMatrix2x2: React.FC<RiskMatrix2x2Props> = ({
  findings,
  onSelectFinding,
  onNavigateToScanner,
  onNavigateToFile
}) => {
  // Configurable threshold (Impact and Likelihood cut-off, default 5.0)
  const [threshold, setThreshold] = useState<number>(() => {
    const saved = safeGetItem(STORAGE_THRESHOLD_KEY);
    return saved ? parseFloat(saved) || 5.0 : 5.0;
  });

  // User manual categorization states per finding ID
  const [userStatuses, setUserStatuses] = useState<Record<string, UserRiskStatus>>(() => {
    const saved = safeGetItem(STORAGE_STATUS_KEY);
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        console.error('Error loading user risk categories:', e);
      }
    }
    return {};
  });

  // Filter states
  const [selectedQuadrant, setSelectedQuadrant] = useState<RiskQuadrantId | 'ALL'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [activeFindingId, setActiveFindingId] = useState<string | null>(null);
  const [sortField, setSortField] = useState<'impact' | 'likelihood' | 'riskScore' | 'severity'>('riskScore');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');

  const handleUpdateStatus = (findingId: string, status: UserRiskStatus) => {
    setUserStatuses(prev => {
      const updated = { ...prev, [findingId]: status };
      safeSetItem(STORAGE_STATUS_KEY, JSON.stringify(updated));
      return updated;
    });
  };

  const handleThresholdChange = (val: number) => {
    setThreshold(val);
    safeSetItem(STORAGE_THRESHOLD_KEY, val.toString());
  };

  // Convert findings to 2x2 Risk Points
  const riskPoints = useMemo<FindingRiskPoint[]>(() => {
    return findings.map((f, idx) => {
      const rawImpact = computeImpact(f);
      const rawLikelihood = computeLikelihood(f);

      // Add slight micro-jitter for visual clarity so points don't overlay identically
      const jitterX = ((idx % 5) - 2) * 0.12;
      const jitterY = (((idx * 3) % 5) - 2) * 0.12;

      const impact = Math.min(9.8, Math.max(0.5, parseFloat((rawImpact + jitterY).toFixed(1))));
      const likelihood = Math.min(9.8, Math.max(0.5, parseFloat((rawLikelihood + jitterX).toFixed(1))));

      // Determine 2x2 Quadrant based on threshold
      let quadrant: RiskQuadrantId = 'LOW';
      if (impact >= threshold && likelihood >= threshold) {
        quadrant = 'CRITICAL';
      } else if (impact >= threshold && likelihood < threshold) {
        quadrant = 'HIGH';
      } else if (impact < threshold && likelihood >= threshold) {
        quadrant = 'MEDIUM';
      } else {
        quadrant = 'LOW';
      }

      const status: UserRiskStatus = userStatuses[f.id] || 'PENDING';
      const statusLabel = USER_STATUS_OPTIONS.find(o => o.value === status)?.label || 'Pendente';

      return {
        id: f.id,
        finding: f,
        ruleName: f.ruleName,
        ruleId: f.ruleId,
        file: f.file,
        line: f.line,
        category: f.category,
        severity: f.severity,
        entropy: f.entropy,
        impact,
        likelihood,
        quadrant,
        userStatus: status,
        statusLabel,
        riskScore: f.riskScore ?? (f.severity === 'CRITICAL' ? 85 : f.severity === 'HIGH' ? 65 : 40),
        zWeight: Math.max(15, (f.entropy || 3) * 6)
      };
    });
  }, [findings, threshold, userStatuses]);

  // Aggregate Quadrant Statistics
  const quadrantStats = useMemo(() => {
    const stats: Record<RiskQuadrantId, { count: number; percentage: number; points: FindingRiskPoint[] }> = {
      CRITICAL: { count: 0, percentage: 0, points: [] },
      HIGH: { count: 0, percentage: 0, points: [] },
      MEDIUM: { count: 0, percentage: 0, points: [] },
      LOW: { count: 0, percentage: 0, points: [] }
    };

    riskPoints.forEach(p => {
      stats[p.quadrant].count += 1;
      stats[p.quadrant].points.push(p);
    });

    const total = riskPoints.length || 1;
    (Object.keys(stats) as RiskQuadrantId[]).forEach(k => {
      stats[k].percentage = Math.round((stats[k].count / total) * 100);
    });

    return stats;
  }, [riskPoints]);

  // Filtered List for Table
  const filteredPoints = useMemo(() => {
    return riskPoints
      .filter(p => {
        if (selectedQuadrant !== 'ALL' && p.quadrant !== selectedQuadrant) {
          return false;
        }
        if (searchTerm.trim()) {
          const q = searchTerm.toLowerCase();
          const matchRule = p.ruleName.toLowerCase().includes(q) || p.ruleId.toLowerCase().includes(q);
          const matchFile = p.file.toLowerCase().includes(q);
          const matchCat = p.category.toLowerCase().includes(q);
          const matchStatus = p.statusLabel.toLowerCase().includes(q);
          return matchRule || matchFile || matchCat || matchStatus;
        }
        return true;
      })
      .sort((a, b) => {
        let diff = 0;
        if (sortField === 'impact') diff = a.impact - b.impact;
        else if (sortField === 'likelihood') diff = a.likelihood - b.likelihood;
        else if (sortField === 'riskScore') diff = a.riskScore - b.riskScore;
        else if (sortField === 'severity') {
          const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
          diff = (order[a.severity] || 0) - (order[b.severity] || 0);
        }
        return sortOrder === 'desc' ? -diff : diff;
      });
  }, [riskPoints, selectedQuadrant, searchTerm, sortField, sortOrder]);

  // Export Categorization Summary as JSON
  const handleExportJson = () => {
    const data = {
      exportTimestamp: new Date().toISOString(),
      matrixThreshold: threshold,
      totalFindings: riskPoints.length,
      distribution: {
        critical: quadrantStats.CRITICAL.count,
        high: quadrantStats.HIGH.count,
        medium: quadrantStats.MEDIUM.count,
        low: quadrantStats.LOW.count
      },
      findingsCategorized: riskPoints.map(p => ({
        id: p.id,
        rule: p.ruleName,
        ruleId: p.ruleId,
        file: p.file,
        line: p.line,
        severity: p.severity,
        calculatedImpact: p.impact,
        calculatedLikelihood: p.likelihood,
        assignedRiskQuadrant: p.quadrant,
        userCategoryStatus: p.userStatus
      }))
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secscan-risk-matrix-2x2-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const activePoint = useMemo(() => {
    if (!activeFindingId) return null;
    return riskPoints.find(p => p.id === activeFindingId) || null;
  }, [activeFindingId, riskPoints]);

  return (
    <div 
      id="risk-matrix-2x2-section"
      className="bg-[#080808] border border-[#222] p-6 space-y-6"
    >
      {/* Top Header & Overview Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#222] pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono px-2 py-0.5 bg-[#FF3E00]/10 text-[#FF3E00] border border-[#FF3E00]/30 font-bold uppercase tracking-wider">
              NIST / OWASP Risk Model
            </span>
            <span className="text-[10px] font-mono text-[#666] uppercase">
              Matriz 2x2: Impacto vs. Probabilidade
            </span>
          </div>
          <h2 className="text-base font-black tracking-wider text-white uppercase flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-[#00FF41]" />
            <span>Matriz de Risco 2x2 (Impact vs. Likelihood)</span>
          </h2>
          <p className="text-xs font-mono text-[#888] mt-1">
            Mapeia vulnerabilidades ativas em quadrantes de severidade operacional para priorização imediata e categorização formal de risco.
          </p>
        </div>

        {/* Controls: Threshold Selector & Export */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Threshold sensitivity preset buttons */}
          <div className="flex items-center bg-[#111] border border-[#333] p-1 gap-1">
            <span className="text-[9.5px] font-mono text-[#888] px-2 uppercase font-bold flex items-center gap-1">
              <Sliders className="w-3 h-3 text-[#00FF41]" />
              Corte (Divisão):
            </span>
            {[
              { val: 4.0, label: '4.0 Estrito' },
              { val: 5.0, label: '5.0 Padrão' },
              { val: 6.0, label: '6.0 Tolerante' }
            ].map(preset => (
              <button
                key={preset.val}
                type="button"
                onClick={() => handleThresholdChange(preset.val)}
                className={`text-[9.5px] font-mono px-2 py-1 transition-all cursor-pointer font-bold ${
                  threshold === preset.val
                    ? 'bg-[#00FF41] text-black font-black'
                    : 'text-[#AAA] hover:text-white hover:bg-[#222]'
                }`}
              >
                {preset.label}
              </button>
            ))}
          </div>

          {/* Export button */}
          <button
            type="button"
            onClick={handleExportJson}
            className="text-[10px] font-mono px-3 py-1.5 bg-[#141414] hover:bg-[#222] text-[#CCC] hover:text-white border border-[#333] hover:border-[#00FF41]/40 flex items-center gap-1.5 transition-all cursor-pointer font-bold"
            title="Exportar dados da Matriz de Risco em formato JSON"
          >
            <Download className="w-3.5 h-3.5 text-[#00FF41]" />
            <span>EXPORTAR JSON</span>
          </button>
        </div>
      </div>

      {/* 4 Quadrant Interactive Metric Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as RiskQuadrantId[]).map(quadId => {
          const cfg = QUADRANT_CONFIG[quadId];
          const stats = quadrantStats[quadId];
          const isSelected = selectedQuadrant === quadId;
          const Icon = cfg.icon;

          return (
            <div
              key={quadId}
              onClick={() => setSelectedQuadrant(prev => prev === quadId ? 'ALL' : quadId)}
              className={`p-3.5 border transition-all cursor-pointer select-none relative group ${
                isSelected
                  ? 'border-[#00FF41] bg-[#121212] ring-1 ring-[#00FF41]/40'
                  : 'border-[#222] bg-[#0E0E0E] hover:border-[#444] hover:bg-[#141414]'
              }`}
            >
              {/* Card Header */}
              <div className="flex items-center justify-between gap-2 mb-2">
                <div className="flex items-center gap-2">
                  <div 
                    className="w-6 h-6 rounded flex items-center justify-center shrink-0"
                    style={{ backgroundColor: `${cfg.color}20`, border: `1px solid ${cfg.color}50` }}
                  >
                    <Icon className="w-3.5 h-3.5" style={{ color: cfg.color }} />
                  </div>
                  <div>
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
                      {cfg.label}
                    </h3>
                    <p className="text-[9px] font-mono text-[#888]">{cfg.subLabel}</p>
                  </div>
                </div>
                {isSelected && (
                  <span className="text-[9px] font-mono font-bold text-[#00FF41] bg-[#00FF41]/10 px-1.5 py-0.5 border border-[#00FF41]/30">
                    FILTRADO
                  </span>
                )}
              </div>

              {/* Number and Percentage */}
              <div className="flex items-baseline justify-between mt-2 pt-2 border-t border-[#1C1C1C]">
                <div className="flex items-baseline gap-1.5">
                  <span className="text-xl font-black font-mono text-white">
                    {stats.count}
                  </span>
                  <span className="text-[10px] font-mono text-[#666]">
                    achados
                  </span>
                </div>
                <span 
                  className="text-xs font-mono font-bold"
                  style={{ color: cfg.color }}
                >
                  {stats.percentage}% do total
                </span>
              </div>

              {/* Mini Recommendation Snippet */}
              <p className="text-[9.5px] font-mono text-[#777] mt-2 line-clamp-2 leading-relaxed">
                {cfg.recommendation}
              </p>
            </div>
          );
        })}
      </div>

      {/* Main 2x2 Grid Area: Recharts Scatter Plot + Active Finding HUD */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Recharts Scatter Matrix Canvas (8 cols on lg) */}
        <div className="lg:col-span-8 bg-[#0B0B0B] border border-[#222] p-4 relative">
          {/* Visual Quadrant Labels in 4 Corners */}
          <div className="flex items-center justify-between text-[10px] font-mono mb-2 px-2 text-[#888]">
            <div className="flex items-center gap-1.5 text-[#FF7A00]">
              <span className="w-2 h-2 rounded-full bg-[#FF7A00]" />
              <strong>ALTO RISCO (Alto Impacto / Baixa Prob.)</strong>
            </div>
            <div className="flex items-center gap-1.5 text-[#FF3E00]">
              <span className="w-2 h-2 rounded-full bg-[#FF3E00]" />
              <strong>RISCO CRÍTICO (Alto Impacto / Alta Prob.)</strong>
            </div>
          </div>

          {/* Chart Container */}
          <div className="w-full h-[360px] relative">
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart
                margin={{ top: 20, right: 25, bottom: 25, left: 10 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1A1A1A" />
                
                {/* 2x2 Quadrant Background Shading via ReferenceArea */}
                {/* Top-Right: Critical Risk */}
                <ReferenceArea
                  x1={threshold}
                  x2={10}
                  y1={threshold}
                  y2={10}
                  fill="#FF3E00"
                  fillOpacity={0.07}
                  stroke="#FF3E00"
                  strokeOpacity={0.2}
                  strokeDasharray="2 2"
                />
                {/* Top-Left: High Risk */}
                <ReferenceArea
                  x1={0}
                  x2={threshold}
                  y1={threshold}
                  y2={10}
                  fill="#FF7A00"
                  fillOpacity={0.05}
                  stroke="#FF7A00"
                  strokeOpacity={0.2}
                  strokeDasharray="2 2"
                />
                {/* Bottom-Right: Medium Risk */}
                <ReferenceArea
                  x1={threshold}
                  x2={10}
                  y1={0}
                  y2={threshold}
                  fill="#EAB308"
                  fillOpacity={0.05}
                  stroke="#EAB308"
                  strokeOpacity={0.2}
                  strokeDasharray="2 2"
                />
                {/* Bottom-Left: Low Risk */}
                <ReferenceArea
                  x1={0}
                  x2={threshold}
                  y1={0}
                  y2={threshold}
                  fill="#38BDF8"
                  fillOpacity={0.04}
                  stroke="#38BDF8"
                  strokeOpacity={0.15}
                  strokeDasharray="2 2"
                />

                {/* Midpoint Dividing Axes at Threshold */}
                <ReferenceLine
                  x={threshold}
                  stroke="#00FF41"
                  strokeDasharray="4 4"
                  strokeWidth={1.5}
                  label={{
                    value: `Corte Likelihood = ${threshold}`,
                    fill: '#00FF41',
                    fontSize: 9,
                    position: 'insideTopRight'
                  }}
                />
                <ReferenceLine
                  y={threshold}
                  stroke="#00FF41"
                  strokeDasharray="4 4"
                  strokeWidth={1.5}
                  label={{
                    value: `Corte Impacto = ${threshold}`,
                    fill: '#00FF41',
                    fontSize: 9,
                    position: 'insideTopLeft'
                  }}
                />

                <XAxis
                  type="number"
                  dataKey="likelihood"
                  name="Likelihood"
                  domain={[0, 10]}
                  ticks={[0, 2.5, 5, 7.5, 10]}
                  tick={{ fill: '#888', fontSize: 10, fontFamily: 'monospace' }}
                  label={{
                    value: 'PROBABILIDADE / EXPLOITABILITY → (Baixa → Alta)',
                    position: 'bottom',
                    offset: 10,
                    fill: '#999',
                    fontSize: 10,
                    fontFamily: 'monospace'
                  }}
                  stroke="#333"
                />

                <YAxis
                  type="number"
                  dataKey="impact"
                  name="Impact"
                  domain={[0, 10]}
                  ticks={[0, 2.5, 5, 7.5, 10]}
                  tick={{ fill: '#888', fontSize: 10, fontFamily: 'monospace' }}
                  label={{
                    value: 'IMPACTO POTENCIAL → (Baixo → Catastrófico)',
                    angle: -90,
                    position: 'insideLeft',
                    offset: 5,
                    fill: '#999',
                    fontSize: 10,
                    fontFamily: 'monospace'
                  }}
                  stroke="#333"
                />

                <ZAxis type="number" dataKey="zWeight" range={[50, 260]} />

                {/* Custom Interactive Tooltip */}
                <RechartsTooltip
                  cursor={{ strokeDasharray: '3 3', stroke: '#444' }}
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload as FindingRiskPoint;
                      const cfg = QUADRANT_CONFIG[data.quadrant];

                      return (
                        <div className="bg-[#121212] border border-[#444] p-3 rounded shadow-2xl font-mono text-[10px] text-white max-w-xs z-50">
                          <div className="flex items-center justify-between gap-2 border-b border-[#222] pb-1.5 mb-2">
                            <span 
                              className="px-1.5 py-0.5 rounded font-bold text-[9px]"
                              style={{ backgroundColor: `${cfg.color}25`, color: cfg.color }}
                            >
                              {cfg.label}
                            </span>
                            <span className="text-[#888]">{data.category}</span>
                          </div>
                          <div className="font-bold text-xs text-white mb-1 truncate" title={data.ruleName}>
                            {data.ruleName}
                          </div>
                          <div className="text-[9px] text-[#AAA] truncate mb-2">
                            {data.file}:{data.line}
                          </div>

                          <div className="grid grid-cols-2 gap-1.5 bg-black/60 p-2 rounded border border-[#222] mb-2">
                            <div>
                              <span className="text-[#777] block text-[8.5px]">IMPACTO:</span>
                              <strong className="text-white text-xs">{data.impact} / 10</strong>
                            </div>
                            <div>
                              <span className="text-[#777] block text-[8.5px]">PROBABILIDADE:</span>
                              <strong className="text-white text-xs">{data.likelihood} / 10</strong>
                            </div>
                          </div>

                          <div className="flex items-center justify-between text-[9px] text-[#888]">
                            <span>Entropia: <strong>{data.entropy.toFixed(2)}</strong></span>
                            <span>Status: <strong>{data.statusLabel}</strong></span>
                          </div>

                          <div className="mt-2 text-[8.5px] text-[#00FF41] border-t border-[#222] pt-1.5">
                            Clique para inspecionar ou categorizar &rarr;
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />

                <Scatter
                  name="Vulnerabilidades"
                  data={riskPoints}
                  onClick={(node: any) => {
                    if (node && node.id) {
                      setActiveFindingId(node.id);
                      onSelectFinding(node.finding);
                    }
                  }}
                  cursor="pointer"
                >
                  {riskPoints.map((point) => {
                    const isSelected = activeFindingId === point.id;
                    const cfg = QUADRANT_CONFIG[point.quadrant];

                    return (
                      <Cell
                        key={`cell-${point.id}`}
                        fill={cfg.color}
                        stroke={isSelected ? '#FFFFFF' : '#000000'}
                        strokeWidth={isSelected ? 2.5 : 1}
                        fillOpacity={isSelected ? 1 : 0.85}
                      />
                    );
                  })}
                </Scatter>
              </ScatterChart>
            </ResponsiveContainer>
          </div>

          {/* Bottom Labels in 2 Corners */}
          <div className="flex items-center justify-between text-[10px] font-mono mt-2 px-2 text-[#888]">
            <div className="flex items-center gap-1.5 text-[#38BDF8]">
              <span className="w-2 h-2 rounded-full bg-[#38BDF8]" />
              <strong>BAIXO RISCO (Baixo Impacto / Baixa Prob.)</strong>
            </div>
            <div className="flex items-center gap-1.5 text-[#EAB308]">
              <span className="w-2 h-2 rounded-full bg-[#EAB308]" />
              <strong>RISCO MODERADO (Baixo Impacto / Alta Prob.)</strong>
            </div>
          </div>
        </div>

        {/* Sidebar Inspector & Categorization Action Panel (4 cols on lg) */}
        <div className="lg:col-span-4 bg-[#0D0D0D] border border-[#222] p-4 flex flex-col justify-between min-h-[430px]">
          <div>
            <div className="flex items-center justify-between border-b border-[#222] pb-2 mb-3">
              <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-white flex items-center gap-1.5">
                <Tag className="w-3.5 h-3.5 text-[#00FF41]" />
                <span>Painel de Categorização</span>
              </span>
              {activePoint && (
                <button
                  type="button"
                  onClick={() => setActiveFindingId(null)}
                  className="text-[9px] font-mono text-[#777] hover:text-white"
                >
                  Limpar
                </button>
              )}
            </div>

            {activePoint ? (
              <div className="space-y-3 font-mono">
                {/* Active Finding Card */}
                <div 
                  className="p-3 border rounded"
                  style={{
                    backgroundColor: `${QUADRANT_CONFIG[activePoint.quadrant].color}10`,
                    borderColor: QUADRANT_CONFIG[activePoint.quadrant].borderColor
                  }}
                >
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span 
                      className="text-[9px] font-black px-1.5 py-0.5 rounded uppercase"
                      style={{
                        backgroundColor: QUADRANT_CONFIG[activePoint.quadrant].color,
                        color: '#000000'
                      }}
                    >
                      {QUADRANT_CONFIG[activePoint.quadrant].label}
                    </span>
                    <span className="text-[9.5px] text-[#AAA]">{activePoint.severity}</span>
                  </div>

                  <h4 className="text-xs font-bold text-white mt-1 break-words">
                    {activePoint.ruleName}
                  </h4>
                  <p className="text-[9.5px] text-[#888] mt-0.5 truncate">
                    {activePoint.file}:{activePoint.line}
                  </p>
                </div>

                {/* Metric Meters */}
                <div className="space-y-2 bg-[#121212] p-3 border border-[#222]">
                  <div>
                    <div className="flex justify-between text-[9.5px] text-[#AAA] mb-1">
                      <span>Impacto Estimado:</span>
                      <strong className="text-white">{activePoint.impact} / 10</strong>
                    </div>
                    <div className="w-full h-1.5 bg-[#222] rounded overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-amber-500 to-rose-500 transition-all"
                        style={{ width: `${(activePoint.impact / 10) * 100}%` }}
                      />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-[9.5px] text-[#AAA] mb-1">
                      <span>Probabilidade (Likelihood):</span>
                      <strong className="text-white">{activePoint.likelihood} / 10</strong>
                    </div>
                    <div className="w-full h-1.5 bg-[#222] rounded overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-blue-500 to-emerald-500 transition-all"
                        style={{ width: `${(activePoint.likelihood / 10) * 100}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* Workflow Status Categorizer */}
                <div className="bg-[#121212] p-3 border border-[#222] space-y-2">
                  <label className="text-[9.5px] text-[#888] uppercase font-bold block">
                    Definir Status de Gestão de Risco:
                  </label>
                  <select
                    value={activePoint.userStatus}
                    onChange={(e) => handleUpdateStatus(activePoint.id, e.target.value as UserRiskStatus)}
                    className="w-full bg-[#0A0A0A] border border-[#333] text-white text-[10px] p-2 rounded focus:border-[#00FF41] focus:outline-none cursor-pointer"
                  >
                    {USER_STATUS_OPTIONS.map(opt => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                  <p className="text-[8.5px] text-[#666] leading-relaxed">
                    Sua classificação persiste localmente no navegador e atualiza relatórios e auditorias.
                  </p>
                </div>

                {/* Quick Action Buttons */}
                <div className="flex items-center gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() => onSelectFinding(activePoint.finding)}
                    className="flex-1 text-[10px] font-mono py-1.5 bg-[#00FF41]/15 hover:bg-[#00FF41]/30 text-[#00FF41] border border-[#00FF41]/40 font-bold flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                  >
                    <span>Ver no Inspetor</span>
                    <ChevronRight className="w-3 h-3" />
                  </button>

                  {onNavigateToFile && (
                    <button
                      type="button"
                      onClick={() => onNavigateToFile(activePoint.file)}
                      className="text-[10px] font-mono px-2.5 py-1.5 bg-[#1A1A1A] hover:bg-[#252525] text-white border border-[#333] flex items-center gap-1 transition-all cursor-pointer"
                      title="Abrir arquivo no editor"
                    >
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center text-center p-6 space-y-3 my-auto">
                <div className="w-10 h-10 rounded-full bg-[#181818] border border-[#333] flex items-center justify-center text-[#666]">
                  <Layers className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-xs font-mono font-bold text-white uppercase">
                    Selecione uma Vulnerabilidade
                  </h4>
                  <p className="text-[10px] font-mono text-[#777] mt-1 max-w-[220px]">
                    Clique em qualquer ponto do gráfico de dispersão 2x2 para inspecionar pontuação de impacto, probabilidade e categorizar o status de remediação.
                  </p>
                </div>
                {onNavigateToScanner && (
                  <button
                    type="button"
                    onClick={onNavigateToScanner}
                    className="text-[10px] font-mono text-[#00FF41] hover:underline flex items-center gap-1 mt-2"
                  >
                    <span>Abrir Scanner Completo &rarr;</span>
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Matrix Legend / Model Note */}
          <div className="border-t border-[#222] pt-3 text-[9px] font-mono text-[#666] leading-relaxed">
            <span className="text-[#888] font-bold">Fórmula de Risco:</span> Risco = Impacto × Probabilidade. Calculado com base em severidade de regra, criticidade do arquivo e entropia da credencial.
          </div>
        </div>
      </div>

      {/* Categorized Findings Table & Quadrant Filter HUD */}
      <div className="border border-[#222] bg-[#0A0A0A] p-4 space-y-4">
        {/* Table Filter Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#222] pb-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-bold text-white uppercase flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-[#00FF41]" />
              <span>Vulnerabilidades Categorizadas por Risco</span>
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 bg-[#141414] text-[#AAA] border border-[#2A2A2A] rounded">
              {filteredPoints.length} de {riskPoints.length}
            </span>
          </div>

          {/* Search Box */}
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 text-[#666] absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar regra, arquivo ou status..."
              className="w-full bg-[#121212] border border-[#333] pl-8 pr-3 py-1 text-[10px] font-mono text-white placeholder-[#555] focus:outline-none focus:border-[#00FF41]"
            />
          </div>
        </div>

        {/* Quadrant Pill Selector */}
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={() => setSelectedQuadrant('ALL')}
            className={`text-[9.5px] font-mono px-2.5 py-1 font-bold border transition-all cursor-pointer ${
              selectedQuadrant === 'ALL'
                ? 'bg-white text-black border-white'
                : 'bg-[#111] text-[#888] border-[#333] hover:text-white'
            }`}
          >
            TODOS ({riskPoints.length})
          </button>

          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as RiskQuadrantId[]).map(qId => {
            const cfg = QUADRANT_CONFIG[qId];
            const isSel = selectedQuadrant === qId;
            return (
              <button
                key={qId}
                type="button"
                onClick={() => setSelectedQuadrant(qId)}
                className={`text-[9.5px] font-mono px-2.5 py-1 font-bold border transition-all cursor-pointer flex items-center gap-1.5 ${
                  isSel
                    ? 'border-[#00FF41] bg-[#1A1A1A] text-white shadow-sm'
                    : 'border-[#282828] bg-[#111] text-[#888] hover:text-white'
                }`}
              >
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: cfg.color }} />
                <span>{cfg.label}</span>
                <span className="text-[8.5px] text-[#666]">({quadrantStats[qId].count})</span>
              </button>
            );
          })}
        </div>

        {/* Findings Table */}
        <div className="overflow-x-auto border border-[#1E1E1E]">
          <table className="w-full text-left font-mono text-[10px]">
            <thead className="bg-[#121212] text-[#888] uppercase text-[9px] border-b border-[#222]">
              <tr>
                <th className="p-2.5">Vulnerabilidade / Regra</th>
                <th className="p-2.5">Arquivo & Linha</th>
                <th 
                  className="p-2.5 cursor-pointer hover:text-white"
                  onClick={() => {
                    setSortField('severity');
                    setSortOrder(prev => prev === 'desc' ? 'asc' : 'desc');
                  }}
                >
                  <div className="flex items-center gap-1">
                    <span>Severidade</span>
                    <ArrowUpDown className="w-2.5 h-2.5" />
                  </div>
                </th>
                <th 
                  className="p-2.5 cursor-pointer hover:text-white"
                  onClick={() => {
                    setSortField('impact');
                    setSortOrder(prev => prev === 'desc' ? 'asc' : 'desc');
                  }}
                >
                  <div className="flex items-center gap-1">
                    <span>Impacto</span>
                    <ArrowUpDown className="w-2.5 h-2.5" />
                  </div>
                </th>
                <th 
                  className="p-2.5 cursor-pointer hover:text-white"
                  onClick={() => {
                    setSortField('likelihood');
                    setSortOrder(prev => prev === 'desc' ? 'asc' : 'desc');
                  }}
                >
                  <div className="flex items-center gap-1">
                    <span>Probabilidade</span>
                    <ArrowUpDown className="w-2.5 h-2.5" />
                  </div>
                </th>
                <th className="p-2.5">Quadrante 2x2</th>
                <th className="p-2.5">Categorização / Status</th>
                <th className="p-2.5 text-right">Ação</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1A1A1A]">
              {filteredPoints.length > 0 ? (
                filteredPoints.map((point) => {
                  const cfg = QUADRANT_CONFIG[point.quadrant];
                  const isSelected = activeFindingId === point.id;

                  return (
                    <tr 
                      key={point.id}
                      onClick={() => setActiveFindingId(point.id)}
                      className={`hover:bg-[#141414] transition-colors cursor-pointer ${
                        isSelected ? 'bg-[#181818]' : ''
                      }`}
                    >
                      {/* Rule Name */}
                      <td className="p-2.5 font-bold text-white max-w-[200px] truncate" title={point.ruleName}>
                        <div className="flex items-center gap-1.5">
                          <span 
                            className="w-1.5 h-1.5 rounded-full shrink-0" 
                            style={{ backgroundColor: cfg.color }}
                          />
                          <span className="truncate">{point.ruleName}</span>
                        </div>
                      </td>

                      {/* File */}
                      <td className="p-2.5 text-[#AAA] max-w-[180px] truncate" title={`${point.file}:${point.line}`}>
                        {point.file}:{point.line}
                      </td>

                      {/* Severity */}
                      <td className="p-2.5">
                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${
                          point.severity === 'CRITICAL' ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/30' :
                          point.severity === 'HIGH' ? 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/30' :
                          point.severity === 'MEDIUM' ? 'bg-[#EAB308]/15 text-[#EAB308] border-[#EAB308]/30' :
                          'bg-[#3366FF]/15 text-[#3366FF] border-[#3366FF]/30'
                        }`}>
                          {point.severity}
                        </span>
                      </td>

                      {/* Impact */}
                      <td className="p-2.5">
                        <div className="flex items-center gap-1.5">
                          <span className="font-bold text-white">{point.impact}</span>
                          <div className="w-12 h-1 bg-[#222] rounded overflow-hidden">
                            <div 
                              className="h-full bg-rose-500"
                              style={{ width: `${(point.impact / 10) * 100}%` }}
                            />
                          </div>
                        </div>
                      </td>

                      {/* Likelihood */}
                      <td className="p-2.5">
                        <div className="flex items-center gap-1.5">
                          <span className="font-bold text-white">{point.likelihood}</span>
                          <div className="w-12 h-1 bg-[#222] rounded overflow-hidden">
                            <div 
                              className="h-full bg-blue-400"
                              style={{ width: `${(point.likelihood / 10) * 100}%` }}
                            />
                          </div>
                        </div>
                      </td>

                      {/* Quadrant */}
                      <td className="p-2.5">
                        <span 
                          className="text-[9px] font-mono px-2 py-0.5 rounded font-bold"
                          style={{
                            backgroundColor: `${cfg.color}18`,
                            color: cfg.color,
                            border: `1px solid ${cfg.color}40`
                          }}
                        >
                          {cfg.label}
                        </span>
                      </td>

                      {/* User Categorization Status Select */}
                      <td className="p-2.5" onClick={(e) => e.stopPropagation()}>
                        <select
                          value={point.userStatus}
                          onChange={(e) => handleUpdateStatus(point.id, e.target.value as UserRiskStatus)}
                          className="bg-[#111] border border-[#333] text-[9px] text-white py-0.5 px-1.5 rounded focus:border-[#00FF41] focus:outline-none cursor-pointer"
                        >
                          {USER_STATUS_OPTIONS.map(opt => (
                            <option key={opt.value} value={opt.value}>
                              {opt.label}
                            </option>
                          ))}
                        </select>
                      </td>

                      {/* Actions */}
                      <td className="p-2.5 text-right">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectFinding(point.finding);
                          }}
                          className="text-[9px] font-mono px-2 py-0.5 bg-[#1A1A1A] hover:bg-[#00FF41] text-[#AAA] hover:text-black border border-[#333] transition-colors"
                        >
                          Detalhes
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={8} className="p-6 text-center text-[#666] font-mono text-xs">
                    Nenhuma vulnerabilidade encontrada com os filtros atuais.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
