import React, { useState, useEffect, useMemo } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  Cell
} from 'recharts';
import { 
  BarChart3, 
  Users, 
  Eye, 
  Globe2, 
  Smartphone, 
  Monitor, 
  Compass, 
  RefreshCw, 
  X, 
  Check, 
  Copy, 
  ExternalLink, 
  ShieldCheck, 
  Activity, 
  TrendingUp, 
  Clock, 
  Share2,
  Sparkles,
  Zap,
  Play,
  Layers,
  Sliders,
  Calendar,
  Flame,
  Sun,
  Moon,
  Info,
  CalendarDays,
  Timer,
  Hourglass,
  RotateCcw
} from 'lucide-react';
import { 
  fetchAnalyticsSummary, 
  sendAnalyticsEvent, 
  AnalyticsSummary, 
  AnalyticsTimelinePoint,
  HeatmapCellDetail,
  WeeklyHeatmapData,
  SessionMetrics,
  getCurrentSessionDurationSeconds,
  formatDurationSeconds,
  formatDurationHuman,
  resetUserSessionStartTime
} from '../lib/analyticsTracker';

interface AnalyticsDashboardModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type TimeRangeFilter = '30m' | '24h' | '7d';
type ChartStyleType = 'area' | 'bar' | 'line';
type MetricViewFilter = 'all' | 'views' | 'visitors';

type HeatmapMetricType = 'views' | 'visitors';
type HeatmapThemeType = 'emerald' | 'cyan' | 'purple' | 'amber';
type HeatmapDayFilterType = 'all' | 'weekdays' | 'weekend';

// Cyber Custom Tooltip for Recharts
const CustomRechartsTooltip: React.FC<any> = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-[#090D16]/95 border border-[#1E293B] shadow-[0_0_25px_rgba(0,0,0,0.8)] backdrop-blur-md p-3 rounded-xl font-mono text-xs text-zinc-200 min-w-[170px]">
        <div className="flex items-center justify-between border-b border-zinc-800 pb-1.5 mb-2">
          <span className="text-[10px] text-zinc-400 font-bold uppercase tracking-wider flex items-center gap-1">
            <Clock className="w-3 h-3 text-[#38BDF8]" />
            <span>{label}</span>
          </span>
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
        </div>
        <div className="space-y-1.5">
          {payload.map((entry: any, index: number) => (
            <div key={`item-${index}`} className="flex items-center justify-between gap-3">
              <span className="flex items-center gap-1.5 text-zinc-300">
                <span
                  className="w-2.5 h-2.5 rounded-sm"
                  style={{ backgroundColor: entry.color || entry.fill || '#00FF41' }}
                />
                <span className="text-[11px] font-medium">
                  {entry.name === 'views' ? 'Visualizações' : entry.name === 'visitors' ? 'Visitantes Únicos' : entry.name}
                </span>
              </span>
              <span className="font-bold font-mono text-white text-[12px]">
                {entry.value}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  }
  return null;
};

export const AnalyticsDashboardModal: React.FC<AnalyticsDashboardModalProps> = ({
  isOpen,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<'metrics' | 'setup_guide'>('metrics');
  const [summary, setSummary] = useState<AnalyticsSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [simulatingEvent, setSimulatingEvent] = useState<boolean>(false);

  // Recharts Interactive Filters
  const [timeRange, setTimeRange] = useState<TimeRangeFilter>('30m');
  const [chartStyle, setChartStyle] = useState<ChartStyleType>('area');
  const [metricFilter, setMetricFilter] = useState<MetricViewFilter>('all');

  // User Activity Heatmap State
  const [heatmapMetric, setHeatmapMetric] = useState<HeatmapMetricType>('views');
  const [heatmapTheme, setHeatmapTheme] = useState<HeatmapThemeType>('emerald');
  const [heatmapDayFilter, setHeatmapDayFilter] = useState<HeatmapDayFilterType>('all');
  const [selectedHeatmapCell, setSelectedHeatmapCell] = useState<HeatmapCellDetail | null>(null);
  const [hoveredHeatmapCell, setHoveredHeatmapCell] = useState<HeatmapCellDetail | null>(null);

  // Active User Session Live Duration Tracker
  const [userActiveSeconds, setUserActiveSeconds] = useState<number>(() => getCurrentSessionDurationSeconds());

  useEffect(() => {
    setUserActiveSeconds(getCurrentSessionDurationSeconds());
    const secondTimer = setInterval(() => {
      setUserActiveSeconds(getCurrentSessionDurationSeconds());
    }, 1000);
    return () => clearInterval(secondTimer);
  }, []);

  const handleResetSessionTimer = () => {
    resetUserSessionStartTime();
    setUserActiveSeconds(0);
  };

  const loadData = async () => {
    setLoading(true);
    const data = await fetchAnalyticsSummary();
    if (data) setSummary(data);
    setLoading(false);
  };

  useEffect(() => {
    if (!isOpen) return;
    loadData();

    if (!autoRefresh) return;
    const interval = setInterval(() => {
      fetchAnalyticsSummary().then((data) => {
        if (data) setSummary(data);
      });
    }, 6000);

    return () => clearInterval(interval);
  }, [isOpen, autoRefresh]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2500);
  };

  // Real-time Event simulation to immediately show live chart update
  const handleSimulateRealtimeHit = async () => {
    setSimulatingEvent(true);
    const sampleTabs = ['scanner', 'ctihub', 'soccommand', 'refactoring', 'dataflow'];
    const randomTab = sampleTabs[Math.floor(Math.random() * sampleTabs.length)];
    const sampleReferrers = [
      'https://api.whatsapp.com/',
      'https://www.linkedin.com/feed/',
      'https://www.google.com/',
      'Direct'
    ];
    const randomRef = sampleReferrers[Math.floor(Math.random() * sampleReferrers.length)];

    await sendAnalyticsEvent({
      type: 'pageview',
      path: '/',
      tab: randomTab,
      metadata: { referrer: randomRef, simulated: true }
    });

    const updated = await fetchAnalyticsSummary();
    if (updated) setSummary(updated);
    setTimeout(() => setSimulatingEvent(false), 500);
  };

  // Compute Active Timeline Dataset based on selected range
  const activeTimelineData: AnalyticsTimelinePoint[] = useMemo(() => {
    if (!summary) return [];
    if (timeRange === '30m' && summary.realtimeMinutes && summary.realtimeMinutes.length > 0) {
      return summary.realtimeMinutes;
    }
    if (timeRange === '7d' && summary.dailyTrend && summary.dailyTrend.length > 0) {
      return summary.dailyTrend;
    }
    return summary.timeline || [];
  }, [summary, timeRange]);

  // Colors for Referrers
  const REFERRER_COLORS: Record<string, string> = {
    'WhatsApp': '#10B981',
    'LinkedIn': '#3B82F6',
    'Google Search': '#F59E0B',
    'X / Twitter': '#0EA5E9',
    'GitHub': '#8B5CF6',
    'Direto / Favorito': '#64748B',
    'Outros Sites': '#EC4899',
  };

  // Modules Bar Chart Data formatted for Recharts
  const moduleEngagementData = useMemo(() => {
    if (!summary?.topPages) return [];
    return summary.topPages.map(page => ({
      name: page.name.toUpperCase(),
      cliques: page.count,
      percentual: page.percentage,
    }));
  }, [summary?.topPages]);

  // Referrers Bar Chart Data formatted for Recharts
  const referrersChartData = useMemo(() => {
    if (!summary?.topReferrers) return [];
    return summary.topReferrers.map(r => ({
      origem: r.source,
      acessos: r.count,
      percentual: r.percentage,
      color: REFERRER_COLORS[r.source] || '#38BDF8',
    }));
  }, [summary?.topReferrers]);

  // Filtered days for weekly heatmap
  const filteredHeatmapGrid = useMemo(() => {
    if (!summary?.weeklyHeatmap?.grid) return [];
    if (heatmapDayFilter === 'weekdays') {
      return summary.weeklyHeatmap.grid.filter(row => row[0]?.dayIndex >= 1 && row[0]?.dayIndex <= 5);
    }
    if (heatmapDayFilter === 'weekend') {
      return summary.weeklyHeatmap.grid.filter(row => row[0]?.dayIndex === 6 || row[0]?.dayIndex === 0);
    }
    return summary.weeklyHeatmap.grid;
  }, [summary?.weeklyHeatmap, heatmapDayFilter]);

  // Max value for current metric across all grid cells for relative intensity coloring
  const maxHeatmapMetricValue = useMemo(() => {
    if (!summary?.weeklyHeatmap?.grid) return 1;
    let maxVal = 1;
    summary.weeklyHeatmap.grid.forEach(row => {
      row.forEach(cell => {
        const val = heatmapMetric === 'visitors' ? cell.visitors : cell.views;
        if (val > maxVal) maxVal = val;
      });
    });
    return maxVal;
  }, [summary?.weeklyHeatmap, heatmapMetric]);

  // Handler to simulate hit on a specific cell or current time
  const handleSimulateHeatmapHit = async (targetCell?: HeatmapCellDetail | null) => {
    setSimulatingEvent(true);
    const sampleTabs = ['scanner', 'ctihub', 'soccommand', 'refactoring', 'dataflow'];
    const randomTab = targetCell?.topTab || sampleTabs[Math.floor(Math.random() * sampleTabs.length)];
    await sendAnalyticsEvent({
      type: 'pageview',
      path: '/',
      tab: randomTab,
      metadata: { simulated: true, targetHour: targetCell?.hour }
    });
    const updated = await fetchAnalyticsSummary();
    if (updated) {
      setSummary(updated);
      if (targetCell && updated.weeklyHeatmap?.grid) {
        const foundRow = updated.weeklyHeatmap.grid.find(r => r[0]?.dayIndex === targetCell.dayIndex);
        if (foundRow && foundRow[targetCell.hour]) {
          setSelectedHeatmapCell(foundRow[targetCell.hour]);
        }
      }
    }
    setTimeout(() => setSimulatingEvent(false), 500);
  };

  // Color Intensity helper based on selected theme & level
  const getCellColorClass = (cell: HeatmapCellDetail) => {
    const val = heatmapMetric === 'visitors' ? cell.visitors : cell.views;
    const ratio = maxHeatmapMetricValue > 0 ? val / maxHeatmapMetricValue : 0;
    
    let level = 0;
    if (val > 0) {
      if (ratio < 0.25) level = 1;
      else if (ratio < 0.55) level = 2;
      else if (ratio < 0.85) level = 3;
      else level = 4;
    }

    const isSelected = selectedHeatmapCell?.dayIndex === cell.dayIndex && selectedHeatmapCell?.hour === cell.hour;

    let base = '';
    if (heatmapTheme === 'emerald') {
      if (level === 0) base = 'bg-[#0B1220]/80 border-[#152338] text-zinc-600 hover:border-emerald-500/50 hover:bg-emerald-950/20';
      else if (level === 1) base = 'bg-emerald-950/50 border-emerald-900/60 text-emerald-400 hover:border-emerald-400 hover:bg-emerald-900/50';
      else if (level === 2) base = 'bg-emerald-800/70 border-emerald-600/70 text-emerald-200 font-bold hover:border-emerald-300 hover:bg-emerald-700/80 shadow-[0_0_6px_rgba(16,185,129,0.2)]';
      else if (level === 3) base = 'bg-emerald-600 border-emerald-400 text-white font-extrabold hover:border-white shadow-[0_0_10px_rgba(16,185,129,0.4)]';
      else base = 'bg-[#00FF41] border-white text-zinc-950 font-black shadow-[0_0_14px_rgba(0,255,65,0.7)] hover:scale-105';
    } else if (heatmapTheme === 'cyan') {
      if (level === 0) base = 'bg-[#0B1220]/80 border-[#152338] text-zinc-600 hover:border-sky-500/50 hover:bg-sky-950/20';
      else if (level === 1) base = 'bg-sky-950/50 border-sky-900/60 text-sky-400 hover:border-sky-400 hover:bg-sky-900/50';
      else if (level === 2) base = 'bg-sky-800/70 border-sky-600/70 text-sky-200 font-bold hover:border-sky-300 hover:bg-sky-700/80 shadow-[0_0_6px_rgba(56,189,248,0.2)]';
      else if (level === 3) base = 'bg-sky-600 border-sky-400 text-white font-extrabold hover:border-white shadow-[0_0_10px_rgba(56,189,248,0.4)]';
      else base = 'bg-[#38BDF8] border-white text-zinc-950 font-black shadow-[0_0_14px_rgba(56,189,248,0.7)] hover:scale-105';
    } else if (heatmapTheme === 'purple') {
      if (level === 0) base = 'bg-[#0B1220]/80 border-[#152338] text-zinc-600 hover:border-purple-500/50 hover:bg-purple-950/20';
      else if (level === 1) base = 'bg-purple-950/50 border-purple-900/60 text-purple-400 hover:border-purple-400 hover:bg-purple-900/50';
      else if (level === 2) base = 'bg-purple-800/70 border-purple-600/70 text-purple-200 font-bold hover:border-purple-300 hover:bg-purple-700/80 shadow-[0_0_6px_rgba(168,85,247,0.2)]';
      else if (level === 3) base = 'bg-purple-600 border-purple-400 text-white font-extrabold hover:border-white shadow-[0_0_10px_rgba(168,85,247,0.4)]';
      else base = 'bg-[#C084FC] border-white text-zinc-950 font-black shadow-[0_0_14px_rgba(192,132,252,0.7)] hover:scale-105';
    } else {
      // amber
      if (level === 0) base = 'bg-[#0B1220]/80 border-[#152338] text-zinc-600 hover:border-amber-500/50 hover:bg-amber-950/20';
      else if (level === 1) base = 'bg-amber-950/50 border-amber-900/60 text-amber-400 hover:border-amber-400 hover:bg-amber-900/50';
      else if (level === 2) base = 'bg-amber-800/70 border-amber-600/70 text-amber-200 font-bold hover:border-amber-300 hover:bg-amber-700/80 shadow-[0_0_6px_rgba(245,158,11,0.2)]';
      else if (level === 3) base = 'bg-amber-600 border-amber-400 text-white font-extrabold hover:border-white shadow-[0_0_10px_rgba(245,158,11,0.4)]';
      else base = 'bg-[#F59E0B] border-white text-zinc-950 font-black shadow-[0_0_14px_rgba(245,158,11,0.7)] hover:scale-105';
    }

    if (isSelected) {
      base += ' ring-2 ring-white scale-110 z-10';
    }
    return base;
  };

  if (!isOpen) return null;

  const ga4Snippet = `<!-- Google tag (gtag.js) - Adicione dentro da tag <head> no index.html -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-SEU_ID_AQUI"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());

  gtag('config', 'G-SEU_ID_AQUI', {
    anonymize_ip: true // Recomendado para conformidade com LGPD / GDPR
  });
</script>`;

  const cloudflareSnippet = `<!-- Cloudflare Web Analytics (Sem cookies, ultraleve, privacidade 100%) -->
<script defer src='https://static.cloudflareinsights.com/beacon.min.js' 
        data-cf-beacon='{"token": "SEU_TOKEN_CLOUDFLARE"}'></script>`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-black/85 backdrop-blur-md animate-in fade-in duration-200">
      <div 
        className="bg-[#090D16] border border-[#1E293B] rounded-2xl w-full max-w-6xl max-h-[94vh] flex flex-col shadow-2xl overflow-hidden font-sans text-zinc-200"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header Bar */}
        <div className="px-6 py-4 border-b border-[#1E293B] flex items-center justify-between bg-[#060911]/90">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500/20 via-[#00FF41]/10 to-cyan-500/20 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-[0_0_15px_rgba(0,255,65,0.15)]">
              <BarChart3 className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h2 className="text-base font-black text-white tracking-wide">
                  Telemetria & Web Analytics em Tempo Real
                </h2>
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                  <span>RECHARTS LIVE ENGINE</span>
                </span>
              </div>
              <p className="text-xs text-zinc-400">
                Dashboard de visualização interativa com gráficos Recharts de acessos, fontes de tráfego e engajamento
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Live simulation test trigger */}
            <button
              onClick={handleSimulateRealtimeHit}
              disabled={simulatingEvent}
              title="Registrar evento ao vivo para testar animação do gráfico"
              className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-emerald-950/40 hover:bg-emerald-900/50 border border-emerald-500/40 text-emerald-300 text-xs font-mono font-bold transition-all cursor-pointer active:scale-95 shadow-sm"
            >
              <Zap className={`w-3.5 h-3.5 text-emerald-400 ${simulatingEvent ? 'animate-bounce' : ''}`} />
              <span>Simular Acesso</span>
            </button>

            <button
              onClick={loadData}
              title="Atualizar métricas agora"
              disabled={loading}
              className="p-2 rounded-lg bg-[#121927] hover:bg-[#1C2636] border border-[#223044] text-zinc-300 hover:text-white transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
            </button>
            <button
              onClick={onClose}
              className="p-2 rounded-lg bg-[#121927] hover:bg-rose-950/40 border border-[#223044] hover:border-rose-500/40 text-zinc-400 hover:text-rose-200 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Switcher & Quick Controls */}
        <div className="px-6 border-b border-[#1E293B] bg-[#070B13] flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('metrics')}
              className={`py-3 px-4 text-xs font-mono font-bold border-b-2 flex items-center gap-2 transition-all cursor-pointer ${
                activeTab === 'metrics'
                  ? 'border-[#00FF41] text-[#00FF41]'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Activity className="w-4 h-4" />
              <span>Dashboard de Telemetria (Recharts)</span>
            </button>
            <button
              onClick={() => setActiveTab('setup_guide')}
              className={`py-3 px-4 text-xs font-mono font-bold border-b-2 flex items-center gap-2 transition-all cursor-pointer ${
                activeTab === 'setup_guide'
                  ? 'border-sky-500 text-sky-400'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Sparkles className="w-4 h-4" />
              <span>Como Conectar Google Analytics 4 (GA4)</span>
            </button>
          </div>

          <div className="flex items-center gap-3 text-[11px] font-mono text-zinc-400 py-2">
            <label className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="rounded bg-black border-zinc-700 text-emerald-500 focus:ring-0"
              />
              <span>Atualização Automática (6s)</span>
            </label>
          </div>
        </div>

        {/* Modal Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-5 sm:p-6 space-y-6">
          {activeTab === 'metrics' ? (
            <>
              {/* TOP HERO BANNER: Live Active User Session Counter & Global Average Duration */}
              <div className="p-4 sm:p-5 rounded-2xl bg-gradient-to-r from-[#0C1525] via-[#09111F] to-[#0A1629] border border-emerald-500/40 shadow-xl relative overflow-hidden">
                {/* Decorative background glow rings */}
                <div className="absolute -right-10 -bottom-10 w-44 h-44 rounded-full bg-emerald-500/5 blur-2xl pointer-events-none" />
                <div className="absolute left-1/3 -top-12 w-44 h-44 rounded-full bg-sky-500/5 blur-2xl pointer-events-none" />

                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  {/* Left: Current User Active Session Live Counter */}
                  <div className="flex items-start sm:items-center gap-3.5">
                    <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-500/20 to-[#00FF41]/10 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-[0_0_15px_rgba(0,255,65,0.2)] shrink-0">
                      <Timer className="w-6 h-6 text-emerald-400 animate-pulse" />
                    </div>

                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400 font-bold">
                          Tempo Ativo na Interface SecScan (Sessão Atual)
                        </span>
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/35">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                          <span>AO VIVO</span>
                        </span>
                      </div>

                      {/* Big Digital Counter Display */}
                      <div className="flex items-baseline gap-2 mt-0.5">
                        <span className="text-3xl sm:text-4xl font-black font-mono text-emerald-400 tracking-tight drop-shadow-[0_0_12px_rgba(0,255,65,0.3)]">
                          {formatDurationSeconds(userActiveSeconds)}
                        </span>
                        <span className="text-xs font-mono text-zinc-400 font-medium">
                          ({formatDurationHuman(userActiveSeconds)})
                        </span>
                      </div>

                      <div className="flex flex-wrap items-center gap-2 mt-1 text-[11px] font-mono text-zinc-400">
                        <span className="flex items-center gap-1 text-zinc-300">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                          <span>Status:</span>
                          <strong className="text-emerald-300">
                            {userActiveSeconds < 60
                              ? 'Início de Sessão'
                              : userActiveSeconds < 180
                              ? 'Navegação Ativa'
                              : userActiveSeconds < 600
                              ? 'Sessão Altamente Engajada (+3m)'
                              : 'Análise de Segurança Aprofundada (+10m)'}
                          </strong>
                        </span>
                        <span className="text-zinc-600 hidden sm:inline">•</span>
                        <button
                          onClick={handleResetSessionTimer}
                          title="Reiniciar cronômetro da sessão atual"
                          className="inline-flex items-center gap-1 text-zinc-500 hover:text-zinc-300 transition-colors cursor-pointer text-[10px]"
                        >
                          <RotateCcw className="w-3 h-3" />
                          <span>Zerar contador local</span>
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Divider on large screens */}
                  <div className="hidden lg:block w-px h-16 bg-gradient-to-b from-transparent via-[#1E293B] to-transparent" />

                  {/* Right: Calculated Average Session Duration (Todos os Usuários) */}
                  <div className="flex flex-wrap sm:flex-nowrap items-center gap-4 lg:gap-6 bg-[#070D18]/80 p-3 sm:p-3.5 rounded-xl border border-[#182638]">
                    {/* Average Metric */}
                    <div>
                      <div className="flex items-center gap-1.5 text-zinc-400 text-xs font-mono">
                        <Hourglass className="w-3.5 h-3.5 text-sky-400" />
                        <span className="font-bold text-zinc-300">Tempo Médio de Sessão (Global)</span>
                      </div>
                      <div className="text-2xl sm:text-3xl font-black font-mono text-sky-400 mt-0.5 tracking-tight">
                        {summary?.sessionMetrics?.formattedAverageDuration || '05m 12s'}
                      </div>
                      <div className="text-[10px] text-zinc-400 font-mono mt-0.5">
                        Baseado em {summary?.sessionMetrics?.totalSessionsCount || 48} sessões monitoradas
                      </div>
                    </div>

                    {/* Retention & Benchmark KPI */}
                    <div className="border-l border-zinc-800/80 pl-4 space-y-1 text-xs font-mono">
                      <div>
                        <span className="text-[10px] text-zinc-500 block uppercase">Taxa de Retenção</span>
                        <span className="text-emerald-400 font-bold text-sm">
                          {summary?.sessionMetrics?.retentionRatePercent || 88.5}%
                        </span>
                        <span className="text-[10px] text-zinc-400 block">&gt; 2 min de engajamento</span>
                      </div>
                      <div className="pt-1 border-t border-zinc-800/60">
                        <span className="text-[10px] text-sky-400 font-medium">
                          +{Math.round(((summary?.sessionMetrics?.averageDurationSeconds || 312) / 240 - 1) * 100)}% vs média AppSec
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Top High-Level Metrics Summary (5 Cards) */}
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
                {/* 1. Active Visitors Now */}
                <div className="p-4 rounded-xl bg-gradient-to-br from-emerald-950/40 to-[#0A101C] border border-emerald-500/35 relative overflow-hidden shadow-sm">
                  <div className="flex items-center justify-between text-zinc-400 text-xs mb-1 font-mono">
                    <span className="font-bold text-zinc-300">Visitantes Ativos</span>
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_#10B981]" />
                  </div>
                  <div className="text-3xl font-black text-emerald-400 font-mono tracking-tight flex items-baseline gap-1.5">
                    {summary?.activeVisitorsNow || 1}
                    <span className="text-xs text-zinc-400 font-normal">agora</span>
                  </div>
                  <div className="text-[10px] text-zinc-400 mt-1 font-mono flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                    <span>Janela dos últimos 5 minutos</span>
                  </div>
                </div>

                {/* 2. Total Page Views */}
                <div className="p-4 rounded-xl bg-[#0D1424] border border-[#1E293B]">
                  <div className="flex items-center justify-between text-zinc-400 text-xs mb-1 font-mono">
                    <span>Visualizações Totais</span>
                    <Eye className="w-3.5 h-3.5 text-sky-400" />
                  </div>
                  <div className="text-3xl font-black text-white font-mono tracking-tight">
                    {summary?.totalPageViews || 0}
                  </div>
                  <div className="text-[10px] text-zinc-400 mt-1 font-mono flex items-center gap-1 text-sky-400">
                    <TrendingUp className="w-3 h-3" />
                    <span>Pageviews registrados</span>
                  </div>
                </div>

                {/* 3. Unique Visitors Today */}
                <div className="p-4 rounded-xl bg-[#0D1424] border border-[#1E293B]">
                  <div className="flex items-center justify-between text-zinc-400 text-xs mb-1 font-mono">
                    <span>Visitantes Únicos Hoje</span>
                    <Users className="w-3.5 h-3.5 text-purple-400" />
                  </div>
                  <div className="text-3xl font-black text-purple-300 font-mono tracking-tight">
                    {summary?.uniqueVisitorsToday || 1}
                  </div>
                  <div className="text-[10px] text-zinc-400 mt-1 font-mono">
                    {summary?.uniqueVisitorsTotal || 1} no total acumulado
                  </div>
                </div>

                {/* 4. Average Session Duration */}
                <div className="p-4 rounded-xl bg-[#0D1424] border border-[#1E293B]">
                  <div className="flex items-center justify-between text-zinc-400 text-xs mb-1 font-mono">
                    <span>Tempo Médio Sessão</span>
                    <Clock className="w-3.5 h-3.5 text-emerald-400" />
                  </div>
                  <div className="text-2xl font-black text-emerald-300 font-mono tracking-tight mt-0.5">
                    {summary?.sessionMetrics?.formattedAverageDuration || '05m 12s'}
                  </div>
                  <div className="text-[10px] text-zinc-400 mt-1 font-mono flex items-center gap-1 text-emerald-400">
                    <Timer className="w-3 h-3" />
                    <span>Retenção média global</span>
                  </div>
                </div>

                {/* 5. Top Origin */}
                <div className="p-4 rounded-xl bg-[#0D1424] border border-[#1E293B] col-span-2 sm:col-span-1">
                  <div className="flex items-center justify-between text-zinc-400 text-xs mb-1 font-mono">
                    <span>País Predominante</span>
                    <Globe2 className="w-3.5 h-3.5 text-amber-400" />
                  </div>
                  <div className="text-lg font-bold text-amber-300 truncate mt-1 flex items-center gap-1.5">
                    <span>{summary?.geoBreakdown[0]?.flag || '🇧🇷'}</span>
                    <span>{summary?.geoBreakdown[0]?.country || 'Brasil'}</span>
                  </div>
                  <div className="text-[10px] text-zinc-400 mt-1 font-mono">
                    {summary?.geoBreakdown[0]?.percentage || 100}% dos acessos totais
                  </div>
                </div>
              </div>

              {/* MAIN RECHARTS SECTION: Interactive Real-Time Timeline Chart */}
              <div className="p-5 rounded-2xl bg-[#0A0F1D] border border-[#1E293B] shadow-xl space-y-4">
                {/* Chart Header with Controls */}
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-[#1E293B] pb-3.5">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                      <TrendingUp className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                        <span>Fluxo de Acessos & Visitantes em Tempo Real</span>
                        <span className="text-[10px] text-zinc-500 font-normal">
                          ({timeRange === '30m' ? 'Últimos 30 min em intervalos de 2 min' : timeRange === '24h' ? 'Últimas 24 horas' : 'Últimos 7 dias'})
                        </span>
                      </h3>
                      <p className="text-xs text-zinc-400">
                        Visualização de telemetria renderizada com Recharts SVG engine
                      </p>
                    </div>
                  </div>

                  {/* Filter Toolbar */}
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Time Range Selector */}
                    <div className="flex items-center bg-[#070A12] border border-[#1E293B] rounded-lg p-0.5 text-xs font-mono">
                      <button
                        onClick={() => setTimeRange('30m')}
                        className={`px-2.5 py-1 rounded transition-colors cursor-pointer font-bold ${
                          timeRange === '30m'
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                      >
                        30 Minutos (Live)
                      </button>
                      <button
                        onClick={() => setTimeRange('24h')}
                        className={`px-2.5 py-1 rounded transition-colors cursor-pointer font-bold ${
                          timeRange === '24h'
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                      >
                        24 Horas
                      </button>
                      <button
                        onClick={() => setTimeRange('7d')}
                        className={`px-2.5 py-1 rounded transition-colors cursor-pointer font-bold ${
                          timeRange === '7d'
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                      >
                        7 Dias
                      </button>
                    </div>

                    {/* Chart Style Toggle (Area / Bar / Line) */}
                    <div className="flex items-center bg-[#070A12] border border-[#1E293B] rounded-lg p-0.5 text-xs font-mono">
                      <button
                        onClick={() => setChartStyle('area')}
                        title="Gráfico de Área Suave"
                        className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                          chartStyle === 'area'
                            ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                      >
                        Área
                      </button>
                      <button
                        onClick={() => setChartStyle('bar')}
                        title="Gráfico de Barras"
                        className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                          chartStyle === 'bar'
                            ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                      >
                        Barras
                      </button>
                      <button
                        onClick={() => setChartStyle('line')}
                        title="Gráfico de Linhas"
                        className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                          chartStyle === 'line'
                            ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                      >
                        Linha
                      </button>
                    </div>

                    {/* Metric View Toggle */}
                    <div className="flex items-center bg-[#070A12] border border-[#1E293B] rounded-lg p-0.5 text-xs font-mono">
                      <button
                        onClick={() => setMetricFilter('all')}
                        className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                          metricFilter === 'all'
                            ? 'bg-[#1C2636] text-white font-bold'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                      >
                        Todos
                      </button>
                      <button
                        onClick={() => setMetricFilter('views')}
                        className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                          metricFilter === 'views'
                            ? 'bg-emerald-500/20 text-emerald-400 font-bold'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                      >
                        Views
                      </button>
                      <button
                        onClick={() => setMetricFilter('visitors')}
                        className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                          metricFilter === 'visitors'
                            ? 'bg-sky-500/20 text-sky-400 font-bold'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                      >
                        Visitantes
                      </button>
                    </div>
                  </div>
                </div>

                {/* Recharts Render Container */}
                <div className="h-72 w-full pt-2">
                  <ResponsiveContainer width="100%" height="100%">
                    {chartStyle === 'area' ? (
                      <AreaChart data={activeTimelineData} margin={{ top: 10, right: 15, left: -20, bottom: 0 }}>
                        <defs>
                          <linearGradient id="viewsGradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#00FF41" stopOpacity={0.4} />
                            <stop offset="95%" stopColor="#00FF41" stopOpacity={0.0} />
                          </linearGradient>
                          <linearGradient id="visitorsGradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.4} />
                            <stop offset="95%" stopColor="#38BDF8" stopOpacity={0.0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                        <XAxis 
                          dataKey="timeLabel" 
                          stroke="#64748B" 
                          tick={{ fontSize: 10, fill: '#94A3B8', fontFamily: 'monospace' }}
                          tickLine={{ stroke: '#1E293B' }}
                        />
                        <YAxis 
                          stroke="#64748B" 
                          tick={{ fontSize: 10, fill: '#94A3B8', fontFamily: 'monospace' }}
                          tickLine={{ stroke: '#1E293B' }}
                          allowDecimals={false}
                        />
                        <RechartsTooltip content={<CustomRechartsTooltip />} />
                        {(metricFilter === 'all' || metricFilter === 'views') && (
                          <Area 
                            type="monotone" 
                            dataKey="views" 
                            name="Visualizações" 
                            stroke="#00FF41" 
                            strokeWidth={2}
                            fillOpacity={1} 
                            fill="url(#viewsGradient)" 
                            isAnimationActive={true}
                          />
                        )}
                        {(metricFilter === 'all' || metricFilter === 'visitors') && (
                          <Area 
                            type="monotone" 
                            dataKey="visitors" 
                            name="Visitantes Únicos" 
                            stroke="#38BDF8" 
                            strokeWidth={2}
                            fillOpacity={1} 
                            fill="url(#visitorsGradient)" 
                            isAnimationActive={true}
                          />
                        )}
                      </AreaChart>
                    ) : chartStyle === 'bar' ? (
                      <BarChart data={activeTimelineData} margin={{ top: 10, right: 15, left: -20, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                        <XAxis 
                          dataKey="timeLabel" 
                          stroke="#64748B" 
                          tick={{ fontSize: 10, fill: '#94A3B8', fontFamily: 'monospace' }}
                          tickLine={{ stroke: '#1E293B' }}
                        />
                        <YAxis 
                          stroke="#64748B" 
                          tick={{ fontSize: 10, fill: '#94A3B8', fontFamily: 'monospace' }}
                          tickLine={{ stroke: '#1E293B' }}
                          allowDecimals={false}
                        />
                        <RechartsTooltip content={<CustomRechartsTooltip />} />
                        {(metricFilter === 'all' || metricFilter === 'views') && (
                          <Bar 
                            dataKey="views" 
                            name="Visualizações" 
                            fill="#00FF41" 
                            radius={[4, 4, 0, 0]}
                            isAnimationActive={true}
                          />
                        )}
                        {(metricFilter === 'all' || metricFilter === 'visitors') && (
                          <Bar 
                            dataKey="visitors" 
                            name="Visitantes Únicos" 
                            fill="#38BDF8" 
                            radius={[4, 4, 0, 0]}
                            isAnimationActive={true}
                          />
                        )}
                      </BarChart>
                    ) : (
                      <LineChart data={activeTimelineData} margin={{ top: 10, right: 15, left: -20, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                        <XAxis 
                          dataKey="timeLabel" 
                          stroke="#64748B" 
                          tick={{ fontSize: 10, fill: '#94A3B8', fontFamily: 'monospace' }}
                          tickLine={{ stroke: '#1E293B' }}
                        />
                        <YAxis 
                          stroke="#64748B" 
                          tick={{ fontSize: 10, fill: '#94A3B8', fontFamily: 'monospace' }}
                          tickLine={{ stroke: '#1E293B' }}
                          allowDecimals={false}
                        />
                        <RechartsTooltip content={<CustomRechartsTooltip />} />
                        {(metricFilter === 'all' || metricFilter === 'views') && (
                          <Line 
                            type="monotone" 
                            dataKey="views" 
                            name="Visualizações" 
                            stroke="#00FF41" 
                            strokeWidth={2.5} 
                            dot={{ fill: '#00FF41', r: 3 }}
                            activeDot={{ r: 6, stroke: '#FFF', strokeWidth: 2 }}
                            isAnimationActive={true}
                          />
                        )}
                        {(metricFilter === 'all' || metricFilter === 'visitors') && (
                          <Line 
                            type="monotone" 
                            dataKey="visitors" 
                            name="Visitantes Únicos" 
                            stroke="#38BDF8" 
                            strokeWidth={2.5} 
                            dot={{ fill: '#38BDF8', r: 3 }}
                            activeDot={{ r: 6, stroke: '#FFF', strokeWidth: 2 }}
                            isAnimationActive={true}
                          />
                        )}
                      </LineChart>
                    )}
                  </ResponsiveContainer>
                </div>

                {/* Timeline Chart Legend Footer */}
                <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-zinc-400 pt-2 border-t border-[#1E293B]">
                  <div className="flex items-center gap-4">
                    <span className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-[#00FF41]" />
                      <strong className="text-zinc-200">Visualizações de Página (Views)</strong>
                    </span>
                    <span className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-[#38BDF8]" />
                      <strong className="text-zinc-200">Sessões / Visitantes Únicos</strong>
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] text-zinc-500">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                    <span>Atualizado dinamicamente em tempo real</span>
                  </div>
                </div>
              </div>

              {/* USER ACTIVITY HEATMAP: Peak Access Times Throughout the Week Grid */}
              <div className="p-5 rounded-2xl bg-[#0A0F1D] border border-[#1E293B] shadow-xl space-y-4">
                {/* Heatmap Header with Controls */}
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-[#1E293B] pb-3.5">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                      <Flame className="w-4 h-4 text-emerald-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-sm font-bold text-white font-mono">
                          Mapa de Calor de Atividade Semanal (Peak Access Heatmap)
                        </h3>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 uppercase">
                          Matriz 7x24
                        </span>
                      </div>
                      <p className="text-xs text-zinc-400">
                        Visualização de intensidade por dia da semana e hora do dia para identificar picos de tráfego e janelas ideais
                      </p>
                    </div>
                  </div>

                  {/* Heatmap Interactive Toolbars */}
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Metric Selector: Views vs Visitors */}
                    <div className="flex items-center bg-[#070A12] border border-[#1E293B] rounded-lg p-0.5 text-xs font-mono">
                      <button
                        onClick={() => setHeatmapMetric('views')}
                        className={`px-2.5 py-1 rounded transition-colors cursor-pointer font-bold ${
                          heatmapMetric === 'views'
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                        title="Visualizar total de acessos / visualizações em cada faixa"
                      >
                        Visualizações
                      </button>
                      <button
                        onClick={() => setHeatmapMetric('visitors')}
                        className={`px-2.5 py-1 rounded transition-colors cursor-pointer font-bold ${
                          heatmapMetric === 'visitors'
                            ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                        title="Visualizar visitantes únicos simultâneos em cada faixa"
                      >
                        Visitantes
                      </button>
                    </div>

                    {/* Day Filter Selector: All vs Weekdays vs Weekend */}
                    <div className="flex items-center bg-[#070A12] border border-[#1E293B] rounded-lg p-0.5 text-xs font-mono">
                      <button
                        onClick={() => setHeatmapDayFilter('all')}
                        className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                          heatmapDayFilter === 'all'
                            ? 'bg-[#1C2636] text-white font-bold'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                        title="Exibir todos os 7 dias da semana"
                      >
                        7 Dias
                      </button>
                      <button
                        onClick={() => setHeatmapDayFilter('weekdays')}
                        className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                          heatmapDayFilter === 'weekdays'
                            ? 'bg-[#1C2636] text-white font-bold'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                        title="Filtrar apenas dias úteis (Segunda a Sexta)"
                      >
                        Seg - Sex
                      </button>
                      <button
                        onClick={() => setHeatmapDayFilter('weekend')}
                        className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                          heatmapDayFilter === 'weekend'
                            ? 'bg-[#1C2636] text-white font-bold'
                            : 'text-zinc-400 hover:text-white'
                        }`}
                        title="Filtrar apenas fim de semana (Sábado e Domingo)"
                      >
                        Sáb - Dom
                      </button>
                    </div>

                    {/* Palette Theme Selector */}
                    <div className="flex items-center bg-[#070A12] border border-[#1E293B] rounded-lg p-1 text-xs font-mono gap-1">
                      <button
                        onClick={() => setHeatmapTheme('emerald')}
                        title="Paleta Cyber Emerald"
                        className={`w-5 h-5 rounded-md flex items-center justify-center transition-all ${
                          heatmapTheme === 'emerald'
                            ? 'bg-emerald-500 ring-2 ring-emerald-300 scale-110'
                            : 'bg-emerald-900/60 hover:bg-emerald-800'
                        }`}
                      />
                      <button
                        onClick={() => setHeatmapTheme('cyan')}
                        title="Paleta Cyber Ocean"
                        className={`w-5 h-5 rounded-md flex items-center justify-center transition-all ${
                          heatmapTheme === 'cyan'
                            ? 'bg-sky-500 ring-2 ring-sky-300 scale-110'
                            : 'bg-sky-900/60 hover:bg-sky-800'
                        }`}
                      />
                      <button
                        onClick={() => setHeatmapTheme('purple')}
                        title="Paleta Neon Violet"
                        className={`w-5 h-5 rounded-md flex items-center justify-center transition-all ${
                          heatmapTheme === 'purple'
                            ? 'bg-purple-500 ring-2 ring-purple-300 scale-110'
                            : 'bg-purple-900/60 hover:bg-purple-800'
                        }`}
                      />
                      <button
                        onClick={() => setHeatmapTheme('amber')}
                        title="Paleta Solar Amber"
                        className={`w-5 h-5 rounded-md flex items-center justify-center transition-all ${
                          heatmapTheme === 'amber'
                            ? 'bg-amber-500 ring-2 ring-amber-300 scale-110'
                            : 'bg-amber-900/60 hover:bg-amber-800'
                        }`}
                      />
                    </div>
                  </div>
                </div>

                {/* Heatmap Peak Analytics Highlight Strip (4 KPI chips) */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5">
                  {/* 1. Peak Day */}
                  <div className="p-3 rounded-xl bg-[#070B14] border border-[#1E293B] flex items-center justify-between">
                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 block">
                        Dia com Maior Movimento
                      </span>
                      <span className="text-xs font-bold font-mono text-emerald-400 block mt-0.5">
                        {summary?.weeklyHeatmap?.peakDay.dayName || 'Terça-feira'}
                      </span>
                      <span className="text-[10px] text-zinc-500 font-mono">
                        {summary?.weeklyHeatmap?.peakDay.totalViews || 0} acessos ({summary?.weeklyHeatmap?.peakDay.percentage || 0}%)
                      </span>
                    </div>
                    <CalendarDays className="w-5 h-5 text-emerald-400/60 shrink-0" />
                  </div>

                  {/* 2. Peak Hour Window */}
                  <div className="p-3 rounded-xl bg-[#070B14] border border-[#1E293B] flex items-center justify-between">
                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 block">
                        Janela de Pico Máximo
                      </span>
                      <span className="text-xs font-bold font-mono text-sky-400 block mt-0.5">
                        {summary?.weeklyHeatmap?.peakHourWindow.label || '14:00 - 16:00'}
                      </span>
                      <span className="text-[10px] text-zinc-500 font-mono">
                        {summary?.weeklyHeatmap?.peakHourWindow.totalViews || 0} acessos acumulados
                      </span>
                    </div>
                    <Flame className="w-5 h-5 text-sky-400/60 shrink-0" />
                  </div>

                  {/* 3. Quietest Window */}
                  <div className="p-3 rounded-xl bg-[#070B14] border border-[#1E293B] flex items-center justify-between">
                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 block">
                        Horário Silencioso (Manutenção)
                      </span>
                      <span className="text-xs font-bold font-mono text-purple-400 block mt-0.5">
                        {summary?.weeklyHeatmap?.quietestHourWindow.label || '03:00 - 05:00'}
                      </span>
                      <span className="text-[10px] text-zinc-500 font-mono">
                        {summary?.weeklyHeatmap?.quietestHourWindow.totalViews || 0} acessos (Menor impacto)
                      </span>
                    </div>
                    <Moon className="w-5 h-5 text-purple-400/60 shrink-0" />
                  </div>

                  {/* 4. Busiest Period of Day */}
                  <div className="p-3 rounded-xl bg-[#070B14] border border-[#1E293B] flex items-center justify-between">
                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 block">
                        Turno Predominante
                      </span>
                      <span className="text-xs font-bold font-mono text-amber-400 block mt-0.5">
                        {summary?.weeklyHeatmap?.busiestPeriodOfDay.period || 'Tarde (12h - 18h)'}
                      </span>
                      <span className="text-[10px] text-zinc-500 font-mono">
                        {summary?.weeklyHeatmap?.busiestPeriodOfDay.percentage || 0}% do tráfego semanal
                      </span>
                    </div>
                    <Sun className="w-5 h-5 text-amber-400/60 shrink-0" />
                  </div>
                </div>

                {/* The 7x24 Heatmap Grid Table */}
                <div className="overflow-x-auto pb-1">
                  <div className="min-w-[760px] space-y-1.5">
                    {/* Period Subheaders (Madrugada, Manhã, Tarde, Noite) */}
                    <div className="grid grid-cols-[75px_repeat(24,1fr)] gap-1 text-[9px] font-mono text-zinc-400">
                      <div className="text-right pr-2 text-zinc-500 font-bold uppercase">Turno:</div>
                      <div className="col-span-6 bg-[#070B14] border border-[#182538] rounded py-0.5 text-center flex items-center justify-center gap-1 text-purple-300">
                        <Moon className="w-3 h-3 text-purple-400" />
                        <span>Madrugada (00h-05h)</span>
                      </div>
                      <div className="col-span-6 bg-[#070B14] border border-[#182538] rounded py-0.5 text-center flex items-center justify-center gap-1 text-sky-300">
                        <Sun className="w-3 h-3 text-sky-400" />
                        <span>Manhã (06h-11h)</span>
                      </div>
                      <div className="col-span-6 bg-[#070B14] border border-[#182538] rounded py-0.5 text-center flex items-center justify-center gap-1 text-emerald-300 font-bold">
                        <Flame className="w-3 h-3 text-emerald-400" />
                        <span>Tarde (12h-17h • Pico)</span>
                      </div>
                      <div className="col-span-6 bg-[#070B14] border border-[#182538] rounded py-0.5 text-center flex items-center justify-center gap-1 text-amber-300">
                        <Clock className="w-3 h-3 text-amber-400" />
                        <span>Noite (18h-23h)</span>
                      </div>
                    </div>

                    {/* Hourly Labels Header (00h, 01h, 02h ... 23h) */}
                    <div className="grid grid-cols-[75px_repeat(24,1fr)] gap-1 text-[10px] font-mono text-zinc-400 border-b border-[#1E293B] pb-1.5">
                      <div className="text-right pr-2 font-bold text-zinc-500">Dia \ Hora</div>
                      {Array.from({ length: 24 }, (_, h) => (
                        <div 
                          key={`hour-header-${h}`} 
                          className="text-center font-medium text-[10px] text-zinc-400 hover:text-white transition-colors"
                        >
                          {h.toString().padStart(2, '0')}h
                        </div>
                      ))}
                    </div>

                    {/* Days Rows */}
                    {filteredHeatmapGrid.map((dayRow, rowIdx) => {
                      const firstCell = dayRow[0];
                      if (!firstCell) return null;
                      const isWeekend = firstCell.dayIndex === 0 || firstCell.dayIndex === 6;

                      return (
                        <div 
                          key={`day-row-${firstCell.dayIndex}`} 
                          className="grid grid-cols-[75px_repeat(24,1fr)] gap-1 items-center"
                        >
                          {/* Day Row Header */}
                          <div className="text-right pr-2 flex items-center justify-end gap-1 font-mono">
                            <span 
                              className={`text-[11px] font-bold ${
                                isWeekend ? 'text-purple-300' : 'text-zinc-200'
                              }`}
                            >
                              {firstCell.dayShort}
                            </span>
                            <span 
                              className={`w-1.5 h-1.5 rounded-full ${
                                isWeekend ? 'bg-purple-400' : 'bg-emerald-500'
                              }`} 
                              title={isWeekend ? 'Fim de Semana' : 'Dia Útil'}
                            />
                          </div>

                          {/* 24 Hourly Cells */}
                          {dayRow.map((cell) => {
                            const val = heatmapMetric === 'visitors' ? cell.visitors : cell.views;
                            const isPeak = summary?.weeklyHeatmap?.peakCell && 
                              cell.dayIndex === summary.weeklyHeatmap.peakCell.dayIndex && 
                              cell.hour === summary.weeklyHeatmap.peakCell.hour;
                            const isSelected = selectedHeatmapCell?.dayIndex === cell.dayIndex && selectedHeatmapCell?.hour === cell.hour;

                            return (
                              <button
                                key={`cell-${cell.dayIndex}-${cell.hour}`}
                                onClick={() => setSelectedHeatmapCell(isSelected ? null : cell)}
                                onMouseEnter={() => setHoveredHeatmapCell(cell)}
                                onMouseLeave={() => setHoveredHeatmapCell(null)}
                                title={`${cell.dayName}, ${cell.hourLabel}: ${val} ${heatmapMetric === 'visitors' ? 'visitantes' : 'visualizações'} (Nível ${cell.intensityLevel})`}
                                className={`h-8 rounded-md border flex flex-col items-center justify-center transition-all cursor-pointer relative group text-[10px] font-mono ${getCellColorClass(cell)}`}
                              >
                                <span className="leading-none">
                                  {val > 0 ? val : '·'}
                                </span>

                                {/* Absolute Peak Cell Radar Badge */}
                                {isPeak && (
                                  <span className="absolute -top-1 -right-1 flex h-2 w-2">
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-white opacity-75" />
                                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400" />
                                  </span>
                                )}
                              </button>
                            );
                          })}
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Heatmap Active Cell Inspector & Simulation */}
                {(() => {
                  const activeCell = hoveredHeatmapCell || selectedHeatmapCell || summary?.weeklyHeatmap?.peakCell;
                  if (!activeCell) return null;

                  const metricVal = heatmapMetric === 'visitors' ? activeCell.visitors : activeCell.views;
                  const ratio = maxHeatmapMetricValue > 0 ? Math.round((metricVal / maxHeatmapMetricValue) * 100) : 0;
                  
                  let classification = 'Sem Acessos Registrados';
                  if (metricVal > 0) {
                    if (ratio >= 80) classification = '🔥 Pico Máximo de Tráfego';
                    else if (ratio >= 50) classification = '⚡ Alto Volume de Usuários';
                    else if (ratio >= 25) classification = '📊 Tráfego Moderado';
                    else classification = '🌱 Baixa Atividade';
                  }

                  return (
                    <div className="p-3.5 rounded-xl bg-[#080D17] border border-[#1E293B] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
                      <div className="flex flex-wrap items-center gap-3">
                        <div className="flex items-center gap-2">
                          <span className="w-2.5 h-2.5 rounded-full bg-[#00FF41] animate-pulse" />
                          <span className="font-bold text-white">
                            {activeCell.dayName}, {activeCell.hourLabel} às {((activeCell.hour + 1) % 24).toString().padStart(2, '0')}h
                          </span>
                        </div>
                        <div className="flex items-center gap-2 text-zinc-300">
                          <span className="px-2 py-0.5 rounded bg-[#131E30] text-emerald-300 border border-[#20324D] font-bold">
                            {activeCell.views} visualizações
                          </span>
                          <span className="px-2 py-0.5 rounded bg-[#131E30] text-sky-300 border border-[#20324D]">
                            {activeCell.visitors} visitantes únicos
                          </span>
                          <span className="text-zinc-400 hidden md:inline">
                            • {classification} ({ratio}% do pico)
                          </span>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        {selectedHeatmapCell && (
                          <button
                            onClick={() => setSelectedHeatmapCell(null)}
                            className="px-2 py-1 rounded bg-[#121927] hover:bg-[#1C2636] text-[11px] text-zinc-400 hover:text-white border border-[#223044] transition-colors cursor-pointer"
                          >
                            Limpar Seleção
                          </button>
                        )}
                        <button
                          onClick={() => handleSimulateHeatmapHit(activeCell as any)}
                          disabled={simulatingEvent}
                          title="Simular um acesso neste horário específico para testar atualização ao vivo"
                          className="px-2.5 py-1 rounded bg-emerald-950/60 hover:bg-emerald-900 border border-emerald-500/50 text-emerald-300 text-[11px] font-bold flex items-center gap-1.5 transition-all cursor-pointer active:scale-95 shadow-sm"
                        >
                          <Zap className={`w-3.5 h-3.5 text-emerald-400 ${simulatingEvent ? 'animate-bounce' : ''}`} />
                          <span>Simular Acesso (+1)</span>
                        </button>
                      </div>
                    </div>
                  );
                })()}

                {/* Heatmap Color Intensity Scale Legend */}
                <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-zinc-400 pt-2 border-t border-[#1E293B]">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-zinc-400">Escala de Intensidade:</span>
                    <div className="flex items-center gap-1.5">
                      <span className="flex items-center gap-1">
                        <span className="w-3.5 h-3.5 rounded bg-[#0A101C] border border-[#152338]" />
                        <span className="text-[10px]">0</span>
                      </span>
                      <span className="flex items-center gap-1">
                        <span className={`w-3.5 h-3.5 rounded ${
                          heatmapTheme === 'emerald' ? 'bg-emerald-950/70 border border-emerald-900/60' :
                          heatmapTheme === 'cyan' ? 'bg-sky-950/70 border border-sky-900/60' :
                          heatmapTheme === 'purple' ? 'bg-purple-950/70 border border-purple-900/60' :
                          'bg-amber-950/70 border border-amber-900/60'
                        }`} />
                        <span className="text-[10px]">Baixo</span>
                      </span>
                      <span className="flex items-center gap-1">
                        <span className={`w-3.5 h-3.5 rounded ${
                          heatmapTheme === 'emerald' ? 'bg-emerald-800/70 border border-emerald-600/70' :
                          heatmapTheme === 'cyan' ? 'bg-sky-800/70 border border-sky-600/70' :
                          heatmapTheme === 'purple' ? 'bg-purple-800/70 border border-purple-600/70' :
                          'bg-amber-800/70 border border-amber-600/70'
                        }`} />
                        <span className="text-[10px]">Médio</span>
                      </span>
                      <span className="flex items-center gap-1">
                        <span className={`w-3.5 h-3.5 rounded ${
                          heatmapTheme === 'emerald' ? 'bg-emerald-600 border border-emerald-400' :
                          heatmapTheme === 'cyan' ? 'bg-sky-600 border border-sky-400' :
                          heatmapTheme === 'purple' ? 'bg-purple-600 border border-purple-400' :
                          'bg-amber-600 border border-amber-400'
                        }`} />
                        <span className="text-[10px]">Alto</span>
                      </span>
                      <span className="flex items-center gap-1">
                        <span className={`w-3.5 h-3.5 rounded shadow-sm ${
                          heatmapTheme === 'emerald' ? 'bg-[#00FF41] border border-white' :
                          heatmapTheme === 'cyan' ? 'bg-[#38BDF8] border border-white' :
                          heatmapTheme === 'purple' ? 'bg-[#C084FC] border border-white' :
                          'bg-[#F59E0B] border border-white'
                        }`} />
                        <span className="text-[10px] font-bold text-white">Pico Máximo</span>
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 text-[11px] text-zinc-500">
                    <Info className="w-3.5 h-3.5 text-zinc-400" />
                    <span>Clique em qualquer célula para fixar e inspecionar detalhes do intervalo</span>
                  </div>
                </div>
              </div>

              {/* SECOND RECHARTS ROW: Two Bar Charts (Referrers & SecScan Module Engagement) */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {/* 1. Traffic Sources Recharts Bar Chart */}
                <div className="p-4.5 rounded-2xl bg-[#0A0F1D] border border-[#1E293B] shadow-md space-y-3">
                  <div className="flex items-center justify-between border-b border-[#1E293B] pb-2.5">
                    <div className="flex items-center gap-2">
                      <Compass className="w-4 h-4 text-emerald-400" />
                      <h3 className="text-xs font-bold font-mono uppercase text-white tracking-wider">
                        Fontes de Tráfego / Canais (Recharts)
                      </h3>
                    </div>
                    <span className="text-[10px] font-mono text-zinc-400">Total por Canal</span>
                  </div>

                  <p className="text-[11px] text-zinc-400">
                    Origem dos links compartilhados (WhatsApp, LinkedIn, Google, X/Twitter, etc.):
                  </p>

                  <div className="h-56 w-full pt-1">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart 
                        data={referrersChartData} 
                        layout="vertical"
                        margin={{ top: 5, right: 30, left: 35, bottom: 5 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" horizontal={false} />
                        <XAxis 
                          type="number" 
                          stroke="#64748B" 
                          tick={{ fontSize: 10, fill: '#94A3B8', fontFamily: 'monospace' }}
                          tickLine={{ stroke: '#1E293B' }}
                        />
                        <YAxis 
                          type="category" 
                          dataKey="origem" 
                          stroke="#64748B" 
                          tick={{ fontSize: 10, fill: '#CBD5E1', fontFamily: 'monospace' }}
                          tickLine={{ stroke: '#1E293B' }}
                        />
                        <RechartsTooltip 
                          formatter={(value: any, name: any) => [`${value} acessos`, 'Total']}
                          contentStyle={{ backgroundColor: '#090D16', borderColor: '#1E293B', borderRadius: '8px', fontSize: '11px', fontFamily: 'monospace' }}
                        />
                        <Bar 
                          dataKey="acessos" 
                          name="Acessos" 
                          radius={[0, 4, 4, 0]}
                          isAnimationActive={true}
                        >
                          {referrersChartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* 2. SecScan Module Engagement Recharts Bar Chart */}
                <div className="p-4.5 rounded-2xl bg-[#0A0F1D] border border-[#1E293B] shadow-md space-y-3">
                  <div className="flex items-center justify-between border-b border-[#1E293B] pb-2.5">
                    <div className="flex items-center gap-2">
                      <BarChart3 className="w-4 h-4 text-purple-400" />
                      <h3 className="text-xs font-bold font-mono uppercase text-white tracking-wider">
                        Engajamento por Módulo (Recharts)
                      </h3>
                    </div>
                    <span className="text-[10px] font-mono text-zinc-400">Interações</span>
                  </div>

                  <p className="text-[11px] text-zinc-400">
                    Acessos aos recursos do SecScan (Scanner SAST, Threat Heatmap, SOC Command):
                  </p>

                  <div className="h-56 w-full pt-1">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart 
                        data={moduleEngagementData}
                        margin={{ top: 10, right: 15, left: -20, bottom: 0 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                        <XAxis 
                          dataKey="name" 
                          stroke="#64748B" 
                          tick={{ fontSize: 9, fill: '#CBD5E1', fontFamily: 'monospace' }}
                          tickLine={{ stroke: '#1E293B' }}
                        />
                        <YAxis 
                          stroke="#64748B" 
                          tick={{ fontSize: 10, fill: '#94A3B8', fontFamily: 'monospace' }}
                          tickLine={{ stroke: '#1E293B' }}
                          allowDecimals={false}
                        />
                        <RechartsTooltip 
                          formatter={(value: any, name: any) => [`${value} cliques`, 'Engajamento']}
                          contentStyle={{ backgroundColor: '#090D16', borderColor: '#1E293B', borderRadius: '8px', fontSize: '11px', fontFamily: 'monospace' }}
                        />
                        <Bar 
                          dataKey="cliques" 
                          name="Cliques no Módulo" 
                          fill="#8B5CF6" 
                          radius={[4, 4, 0, 0]}
                          isAnimationActive={true}
                        >
                          {moduleEngagementData.map((_, index) => (
                            <Cell 
                              key={`mod-${index}`} 
                              fill={index % 2 === 0 ? '#8B5CF6' : '#38BDF8'} 
                            />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>

              {/* THIRD ROW: Geographic Breakdown & Devices */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {/* Geo / Countries */}
                <div className="p-4.5 rounded-2xl bg-[#0A0F1D] border border-[#1E293B] space-y-3">
                  <div className="flex items-center justify-between border-b border-[#1E293B] pb-2">
                    <div className="flex items-center gap-2">
                      <Globe2 className="w-4 h-4 text-amber-400" />
                      <h3 className="text-xs font-bold font-mono uppercase text-white tracking-wider">
                        Distribuição Geográfica de Visitantes
                      </h3>
                    </div>
                    <span className="text-[10px] font-mono text-zinc-400">GeoIP</span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {summary?.geoBreakdown.map((geo) => (
                      <div key={geo.country} className="p-2.5 rounded-lg bg-[#070B14] border border-[#172235] flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-base">{geo.flag}</span>
                          <span className="text-xs text-zinc-300 font-medium truncate max-w-[85px]">
                            {geo.country}
                          </span>
                        </div>
                        <span className="text-xs font-mono font-bold text-amber-400">
                          {geo.percentage}%
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Device & Browser Distribution */}
                <div className="p-4.5 rounded-2xl bg-[#0A0F1D] border border-[#1E293B] space-y-3">
                  <div className="flex items-center justify-between border-b border-[#1E293B] pb-2">
                    <div className="flex items-center gap-2">
                      <Smartphone className="w-4 h-4 text-sky-400" />
                      <h3 className="text-xs font-bold font-mono uppercase text-white tracking-wider">
                        Dispositivos & Navegadores
                      </h3>
                    </div>
                    <span className="text-[10px] font-mono text-zinc-400">Client Info</span>
                  </div>

                  <div className="grid grid-cols-2 gap-3 pt-1">
                    <div className="space-y-1.5 bg-[#070B14] p-3 rounded-lg border border-[#172235]">
                      <span className="text-[10px] font-mono text-zinc-400 font-bold uppercase block mb-1">
                        Dispositivo
                      </span>
                      {summary?.deviceBreakdown.map((dev) => (
                        <div key={dev.type} className="flex items-center justify-between text-xs font-mono">
                          <span className="text-zinc-300 truncate">{dev.type}</span>
                          <span className="font-bold text-sky-400">{dev.percentage}%</span>
                        </div>
                      ))}
                    </div>

                    <div className="space-y-1.5 bg-[#070B14] p-3 rounded-lg border border-[#172235]">
                      <span className="text-[10px] font-mono text-zinc-400 font-bold uppercase block mb-1">
                        Navegador
                      </span>
                      {summary?.browserBreakdown.map((b) => (
                        <div key={b.name} className="flex items-center justify-between text-xs font-mono">
                          <span className="text-zinc-300 truncate">{b.name}</span>
                          <span className="font-bold text-emerald-400">{b.percentage}%</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* FOURTH ROW: Live Recent Events Stream */}
              <div className="p-4.5 rounded-2xl bg-[#0A0F1D] border border-[#1E293B] space-y-3">
                <div className="flex items-center justify-between border-b border-[#1E293B] pb-2">
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4 text-emerald-400" />
                    <h3 className="text-xs font-bold font-mono uppercase text-white tracking-wider">
                      Feed Cronológico de Eventos Recentes em Tempo Real
                    </h3>
                  </div>
                  <span className="text-[10px] font-mono text-zinc-400">Telemetria ao vivo</span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="text-zinc-500 border-b border-[#1C2636] text-[10px] uppercase">
                        <th className="py-2 px-2">Tempo</th>
                        <th className="py-2 px-2">País</th>
                        <th className="py-2 px-2">Dispositivo</th>
                        <th className="py-2 px-2">Navegador/OS</th>
                        <th className="py-2 px-2">Origem / Referrer</th>
                        <th className="py-2 px-2">Ação</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#172235] text-zinc-300">
                      {summary?.recentEvents.map((evt) => (
                        <tr key={evt.id} className="hover:bg-white/[0.02] transition-colors">
                          <td className="py-2 px-2 text-zinc-400 text-[11px] whitespace-nowrap">
                            {evt.timeAgo}
                          </td>
                          <td className="py-2 px-2 whitespace-nowrap">{evt.country}</td>
                          <td className="py-2 px-2 capitalize whitespace-nowrap">
                            {evt.device === 'mobile' ? '📱 Mobile' : '💻 Desktop'}
                          </td>
                          <td className="py-2 px-2 text-zinc-400 whitespace-nowrap">
                            {evt.browser} ({evt.os})
                          </td>
                          <td className="py-2 px-2 whitespace-nowrap">
                            <span className="px-1.5 py-0.5 rounded bg-[#162030] text-[10px] border border-[#223044] text-zinc-300">
                              {evt.referrer}
                            </span>
                          </td>
                          <td className="py-2 px-2 text-[#00FF41] font-bold text-[11px] whitespace-nowrap">
                            {evt.tab ? `Tab: ${evt.tab}` : 'Página Inicial'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          ) : (
            /* Setup Guide Tab (Google Analytics 4 / Cloudflare / Plausible) */
            <div className="space-y-6">
              {/* Option 1: Google Analytics 4 (GA4) */}
              <div className="p-5 rounded-xl bg-[#0D131F] border border-[#1E293B] space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 font-bold">
                      G
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white">Opção 1: Google Analytics 4 (GA4)</h3>
                      <p className="text-xs text-zinc-400">Padrão da indústria, gratuito, com relatórios detalhados de audiência</p>
                    </div>
                  </div>
                  <button
                    onClick={() => handleCopy(ga4Snippet, 'ga4')}
                    className="px-3 py-1.5 rounded-lg bg-[#141B26] hover:bg-[#1E293B] border border-[#223044] text-xs font-mono text-zinc-200 hover:text-white flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    {copiedCode === 'ga4' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copiado!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copiar Código</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="space-y-2 text-xs text-zinc-300">
                  <p><strong>Como ativar em 3 passos:</strong></p>
                  <ol className="list-decimal list-inside space-y-1.5 text-zinc-400 pl-1">
                    <li>Acesse <a href="https://analytics.google.com" target="_blank" rel="noreferrer" className="text-sky-400 hover:underline">analytics.google.com</a> com sua conta Google e crie uma nova propriedade "SecScan".</li>
                    <li>Escolha a plataforma <strong>Web</strong> e copie o seu ID de métrica (começa com <code className="text-amber-300">G-XXXXXXXXXX</code>).</li>
                    <li>Cole o script abaixo dentro da tag <code className="text-emerald-400">&lt;head&gt;</code> do arquivo <code className="text-white font-mono">index.html</code> substituindo <code className="text-amber-300">G-SEU_ID_AQUI</code> pelo seu código:</li>
                  </ol>
                </div>

                <div className="relative">
                  <pre className="bg-[#05080E] p-3.5 rounded-lg border border-[#1E293B] text-[11px] font-mono text-zinc-300 overflow-x-auto leading-relaxed">
                    {ga4Snippet}
                  </pre>
                </div>
              </div>

              {/* Option 2: Cloudflare Web Analytics */}
              <div className="p-5 rounded-xl bg-[#0D131F] border border-[#1E293B] space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-orange-500/10 border border-orange-500/30 flex items-center justify-center text-orange-400 font-bold">
                      CF
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white">Opção 2: Cloudflare Web Analytics (Sem Cookies & 100% LGPD)</h3>
                      <p className="text-xs text-zinc-400">Totalmente focado em privacidade, sem coletar dados pessoais e sem banner de cookies</p>
                    </div>
                  </div>
                  <button
                    onClick={() => handleCopy(cloudflareSnippet, 'cf')}
                    className="px-3 py-1.5 rounded-lg bg-[#141B26] hover:bg-[#1E293B] border border-[#223044] text-xs font-mono text-zinc-200 hover:text-white flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    {copiedCode === 'cf' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copiado!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copiar Código</span>
                      </>
                    )}
                  </button>
                </div>

                <p className="text-xs text-zinc-300">
                  Crie uma conta gratuita em <a href="https://dash.cloudflare.com" target="_blank" rel="noreferrer" className="text-sky-400 hover:underline">dash.cloudflare.com</a>, vá em <em>Web Analytics</em>, adicione o domínio do site e adicione o script antes de <code className="text-white">&lt;/body&gt;</code>.
                </p>

                <pre className="bg-[#05080E] p-3.5 rounded-lg border border-[#1E293B] text-[11px] font-mono text-zinc-300 overflow-x-auto">
                  {cloudflareSnippet}
                </pre>
              </div>

              {/* Comparison Card */}
              <div className="p-4.5 rounded-xl bg-gradient-to-r from-emerald-950/20 to-sky-950/20 border border-[#1E293B] space-y-3">
                <div className="flex items-center gap-2 text-white font-bold text-xs uppercase font-mono tracking-wider">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span>Diferença entre as soluções de Analytics:</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-[#080D16] border border-[#172235]">
                    <strong className="text-emerald-400 block mb-1">Telemetria Nativa SecScan (Já Ativa!)</strong>
                    <p className="text-zinc-400 text-[11px]">Sem depender de terceiros, gráficos Recharts em tempo real, dados no seu backend Express.</p>
                  </div>
                  <div className="p-3 rounded-lg bg-[#080D16] border border-[#172235]">
                    <strong className="text-amber-400 block mb-1">Google Analytics 4</strong>
                    <p className="text-zinc-400 text-[11px]">Relatórios demográficos completos, funis e integração com Google Ads / Search Console.</p>
                  </div>
                  <div className="p-3 rounded-lg bg-[#080D16] border border-[#172235]">
                    <strong className="text-sky-400 block mb-1">Cloudflare / Plausible</strong>
                    <p className="text-zinc-400 text-[11px]">Máxima velocidade de carregamento (&lt; 1KB), sem cookies e conformidade estrita com a LGPD.</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 border-t border-[#1E293B] bg-[#070B13] flex items-center justify-between text-xs font-mono text-zinc-400">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
            <span>Motor de telemetria ativo com Recharts SVG • Visualização em tempo real</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-[#141B26] hover:bg-[#1E293B] border border-[#223044] text-white font-bold cursor-pointer transition-colors"
          >
            Fechar Painel
          </button>
        </div>
      </div>
    </div>
  );
};
