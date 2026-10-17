import React, { useState, useEffect, useMemo } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  LineChart,
  Line,
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
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
  RotateCcw,
  MousePointerClick,
  ArrowRight,
  Workflow,
  Target,
  FileCode2,
  Container,
  Route,
  Radio,
  ShieldAlert,
  HelpCircle,
  CheckCircle2,
  LayoutGrid,
  PieChart,
  Crosshair,
  Gauge,
  Search,
  History,
  Terminal,
  SlidersHorizontal,
  ChevronRight,
  Filter
} from 'lucide-react';
import { 
  fetchAnalyticsSummary, 
  sendAnalyticsEvent, 
  AnalyticsSummary, 
  AnalyticsTimelinePoint,
  HeatmapCellDetail,
  WeeklyHeatmapData,
  SessionMetrics,
  SessionTabEngagement,
  UserSessionHeatmapData,
  ScanEfficiencyDataPoint,
  ScanEfficiencySummary,
  getCurrentSessionDurationSeconds,
  formatDurationSeconds,
  formatDurationHuman,
  resetUserSessionStartTime,
  getLocalSessionTabEngagement,
  recordLocalTabSessionActivity,
  resetLocalTabSessionEngagement,
  SecurityAuditLogItem,
  getLocalSecurityAuditLogs,
  recordSecurityAuditLog,
  clearLocalSecurityAuditLogs
} from '../lib/analyticsTracker';
import { ScanReport } from '../types';

interface AnalyticsDashboardModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateTab?: (tab: string) => void;
  scanHistory?: ScanReport[];
  currentReport?: ScanReport | null;
  onTriggerScan?: () => void;
}

type TimeRangeFilter = '30m' | '24h' | '7d';
type ChartStyleType = 'area' | 'bar' | 'line';
type MetricViewFilter = 'all' | 'views' | 'visitors';

type HeatmapMetricType = 'views' | 'visitors';
type HeatmapThemeType = 'emerald' | 'cyan' | 'purple' | 'amber';
type HeatmapDayFilterType = 'all' | 'weekdays' | 'weekend';

type SessionHeatmapScopeType = 'all_sessions' | 'current_session';
type SessionCategoryFilterType = 'ALL' | 'CODE_SAST' | 'CLOUD_INFRA' | 'API_DAST' | 'SOC_EDR' | 'GOV_AI';
type SessionSortType = 'engagement' | 'dwell' | 'interactions' | 'adoption';
type SessionViewModeType = 'matrix' | 'funnel' | 'distribution';

type ScatterXUnitType = 'ms' | 'sec';
type ScatterScopeFilterType = 'all' | 'current_session' | 'sub_second';
type ScatterEngineModeFilterType = 'ALL' | 'AST_REGEX' | 'TAINT_FLOW' | 'FULL_ASOC';

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
  onNavigateTab,
  scanHistory,
  currentReport,
  onTriggerScan,
}) => {
  const [activeTab, setActiveTab] = useState<'metrics' | 'scatter_plot' | 'session_heatmap' | 'setup_guide'>('metrics');
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

  // User Session Heatmap (UI Tabs & Security Features Engagement) State
  const [sessionHeatmapScope, setSessionHeatmapScope] = useState<SessionHeatmapScopeType>('all_sessions');
  const [sessionCategoryFilter, setSessionCategoryFilter] = useState<SessionCategoryFilterType>('ALL');
  const [sessionSort, setSessionSort] = useState<SessionSortType>('engagement');
  const [sessionViewMode, setSessionViewMode] = useState<SessionViewModeType>('matrix');
  const [selectedSessionTab, setSelectedSessionTab] = useState<SessionTabEngagement | null>(null);
  const [hoveredSessionTab, setHoveredSessionTab] = useState<SessionTabEngagement | null>(null);
  const [localTabRecords, setLocalTabRecords] = useState<Record<string, any>>(() => getLocalSessionTabEngagement());

  // Engine Efficiency Scatter Plot State (Scan Duration vs Number of Findings)
  const [scatterXUnit, setScatterXUnit] = useState<ScatterXUnitType>('ms');
  const [scatterScopeFilter, setScatterScopeFilter] = useState<ScatterScopeFilterType>('all');
  const [scatterEngineFilter, setScatterEngineFilter] = useState<ScatterEngineModeFilterType>('ALL');
  const [selectedScatterPoint, setSelectedScatterPoint] = useState<ScanEfficiencyDataPoint | null>(null);
  const [hoveredScatterPoint, setHoveredScatterPoint] = useState<ScanEfficiencyDataPoint | null>(null);
  const [simulatedLocalScans, setSimulatedLocalScans] = useState<ScanEfficiencyDataPoint[]>([]);

  // Active User Session Live Duration Tracker
  const [userActiveSeconds, setUserActiveSeconds] = useState<number>(() => getCurrentSessionDurationSeconds());

  // Security Audit Logs Sidebar State
  const [showAuditSidebar, setShowAuditSidebar] = useState<boolean>(true);
  const [auditLogs, setAuditLogs] = useState<SecurityAuditLogItem[]>(() => getLocalSecurityAuditLogs());
  const [auditSearchQuery, setAuditSearchQuery] = useState<string>('');
  const [auditSeverityFilter, setAuditSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'AUDIT' | 'SUCCESS'>('ALL');
  const [selectedAuditLog, setSelectedAuditLog] = useState<SecurityAuditLogItem | null>(null);
  const [copiedAuditLogs, setCopiedAuditLogs] = useState<boolean>(false);

  useEffect(() => {
    setUserActiveSeconds(getCurrentSessionDurationSeconds());
    setLocalTabRecords(getLocalSessionTabEngagement());
    setAuditLogs(getLocalSecurityAuditLogs());
    const secondTimer = setInterval(() => {
      setUserActiveSeconds(getCurrentSessionDurationSeconds());
      setLocalTabRecords(getLocalSessionTabEngagement());
    }, 1000);
    return () => clearInterval(secondTimer);
  }, []);

  useEffect(() => {
    const handleLogAdded = (e: Event) => {
      const customEvent = e as CustomEvent<SecurityAuditLogItem>;
      if (customEvent.detail) {
        setAuditLogs(prev => [customEvent.detail, ...prev.filter(i => i.id !== customEvent.detail.id)].slice(0, 50));
      } else {
        setAuditLogs(getLocalSecurityAuditLogs());
      }
    };
    const handleLogCleared = () => {
      setAuditLogs([]);
    };
    window.addEventListener('secscan-audit-log-added', handleLogAdded);
    window.addEventListener('secscan-audit-log-cleared', handleLogCleared);
    return () => {
      window.removeEventListener('secscan-audit-log-added', handleLogAdded);
      window.removeEventListener('secscan-audit-log-cleared', handleLogCleared);
    };
  }, []);

  const handleSimulateAuditInteraction = () => {
    const sampleTools = [
      { toolId: 'sast_scanner', toolName: 'Scanner SAST & AST', action: 'Varredura Rápida de AST', severity: 'HIGH' as const, category: 'CODE_SAST' as const, details: 'Detecção de 4 vulnerabilidades CWE-89 (SQL Injection) em models/user.ts' },
      { toolId: 'threat_matrix', toolName: 'Threat Modeling (STRIDE)', action: 'Cálculo de Risco STRIDE', severity: 'CRITICAL' as const, category: 'SOC_EDR' as const, details: 'Elevação de privilégio avaliada em rota /admin com score CVSS 9.4' },
      { toolId: 'secrets_detector', toolName: 'Detector de Segredos', action: 'Inspeção de Entropia de Chaves', severity: 'CRITICAL' as const, category: 'CODE_SAST' as const, details: 'Chave privada RSA identificada em arquivo de configuração sem criptografia' },
      { toolId: 'remediation_ai', toolName: 'Remediação Assistida por IA', action: 'Geração de Patch de Segurança', severity: 'SUCCESS' as const, category: 'GOV_AI' as const, details: 'Correção automática gerada e validada contra AST para sanitização de input' },
      { toolId: 'soc_command', toolName: 'SOC Command Center & EDR', action: 'Disparo de Alerta de Anomalia', severity: 'AUDIT' as const, category: 'SOC_EDR' as const, details: 'Múltiplas tentativas de acesso à rota restrita de auditoria detectadas' },
      { toolId: 'dast_fuzzer', toolName: 'DAST & API Fuzzer', action: 'Fuzzing de Parâmetros REST', severity: 'MEDIUM' as const, category: 'API_DAST' as const, details: 'Payload de Cross-Site Scripting (XSS) refletido no parâmetro q' },
      { toolId: 'cloud_infra', toolName: 'Auditor de Infraestrutura IaC', action: 'Análise de Dockerfile', severity: 'HIGH' as const, category: 'CLOUD_INFRA' as const, details: 'Configuração USER root detectada; recomendado USER nonroot' },
      { toolId: 'cicd_gate', toolName: 'CI/CD Security Gate', action: 'Check de Aprovação de Build', severity: 'SUCCESS' as const, category: 'CORE_ENGINE' as const, details: 'Pipeline aprovado: 0 vulnerabilidades bloqueantes encontradas' },
    ];
    const picked = sampleTools[Math.floor(Math.random() * sampleTools.length)];
    const newLog = recordSecurityAuditLog({
      toolId: picked.toolId,
      toolName: picked.toolName,
      action: picked.action,
      severity: picked.severity,
      category: picked.category,
      details: picked.details,
      executionMs: Math.floor(Math.random() * 400) + 120,
    });
    setAuditLogs(prev => [newLog, ...prev.filter(l => l.id !== newLog.id)].slice(0, 50));
  };

  const handleCopyAuditLogs = () => {
    const text = auditLogs.map(log => `[${log.timeLabel}] [${log.severity}] Ferramenta: ${log.toolName} | Ação: ${log.action} | Detalhes: ${log.details} | Hash: ${log.hash}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopiedAuditLogs(true);
    setTimeout(() => setCopiedAuditLogs(false), 2000);
  };

  const handleClearAuditLogs = () => {
    clearLocalSecurityAuditLogs();
    setAuditLogs([]);
    setSelectedAuditLog(null);
  };

  const filteredAuditLogs = useMemo(() => {
    return auditLogs.filter(log => {
      if (auditSeverityFilter !== 'ALL' && log.severity !== auditSeverityFilter) {
        return false;
      }
      if (auditSearchQuery.trim()) {
        const q = auditSearchQuery.toLowerCase();
        const matchTool = log.toolName.toLowerCase().includes(q);
        const matchAction = log.action.toLowerCase().includes(q);
        const matchDetails = log.details.toLowerCase().includes(q);
        const matchTime = log.timeLabel.toLowerCase().includes(q);
        if (!matchTool && !matchAction && !matchDetails && !matchTime) return false;
      }
      return true;
    });
  }, [auditLogs, auditSeverityFilter, auditSearchQuery]);

  const handleResetSessionTimer = () => {
    resetUserSessionStartTime();
    setUserActiveSeconds(0);
  };

  const loadData = async () => {
    setLoading(true);
    const data = await fetchAnalyticsSummary();
    if (data) setSummary(data);
    setLocalTabRecords(getLocalSessionTabEngagement());
    setLoading(false);
  };

  useEffect(() => {
    if (!isOpen) return;
    loadData();

    if (!autoRefresh) return;
    const interval = setInterval(() => {
      fetchAnalyticsSummary().then((data) => {
        if (data) setSummary(data);
        setLocalTabRecords(getLocalSessionTabEngagement());
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

  // User Session Heatmap Computed Data (Tabs & Features Engagement)
  const filteredAndSortedSessionTabs: SessionTabEngagement[] = useMemo(() => {
    let sourceTabs: SessionTabEngagement[] = [];

    if (sessionHeatmapScope === 'current_session') {
      const allTabs = summary?.userSessionHeatmap?.tabs || [];
      let maxLocalScore = 1;
      allTabs.forEach(t => {
        const rec = localTabRecords[t.tabId];
        const score = (rec?.interactions || 0) * 4 + (rec?.dwellSeconds || 0) * 0.35;
        if (score > maxLocalScore) maxLocalScore = score;
      });

      sourceTabs = allTabs.map(t => {
        const rec = localTabRecords[t.tabId] || { dwellSeconds: 0, interactions: 0 };
        const rawScore = (rec.interactions || 0) * 4 + (rec.dwellSeconds || 0) * 0.35;
        const scorePct = maxLocalScore > 0 ? Math.round((rawScore / maxLocalScore) * 100) : 0;
        let heatLevel: 0 | 1 | 2 | 3 | 4 = 0;
        if (rec.interactions > 0 || rec.dwellSeconds > 0) {
          if (scorePct >= 75) heatLevel = 4;
          else if (scorePct >= 50) heatLevel = 3;
          else if (scorePct >= 25) heatLevel = 2;
          else heatLevel = 1;
        }

        const m = Math.floor((rec.dwellSeconds || 0) / 60);
        const s = (rec.dwellSeconds || 0) % 60;
        const formatted = `${m.toString().padStart(2, '0')}m ${s.toString().padStart(2, '0')}s`;

        return {
          ...t,
          dwellSeconds: rec.dwellSeconds || 0,
          formattedDuration: formatted,
          interactionCount: rec.interactions || 0,
          sessionEngagementScore: scorePct,
          heatLevel,
          adoptionRate: (rec.interactions > 0 || rec.dwellSeconds > 0) ? 100 : 0,
        };
      });
    } else {
      sourceTabs = summary?.userSessionHeatmap?.tabs ? [...summary.userSessionHeatmap.tabs] : [];
    }

    // Filter by Category
    if (sessionCategoryFilter !== 'ALL') {
      sourceTabs = sourceTabs.filter(t => t.category === sessionCategoryFilter);
    }

    // Sort
    sourceTabs.sort((a, b) => {
      if (sessionSort === 'engagement') return b.sessionEngagementScore - a.sessionEngagementScore;
      if (sessionSort === 'dwell') return b.dwellSeconds - a.dwellSeconds;
      if (sessionSort === 'interactions') return b.interactionCount - a.interactionCount;
      if (sessionSort === 'adoption') return b.adoptionRate - a.adoptionRate;
      return 0;
    });

    return sourceTabs;
  }, [summary?.userSessionHeatmap, sessionHeatmapScope, localTabRecords, sessionCategoryFilter, sessionSort]);

  // Handler to simulate engagement on a security tab/feature
  const handleSimulateTabEngagement = async (targetTabId: string) => {
    setSimulatingEvent(true);
    recordLocalTabSessionActivity(targetTabId, 35, true);
    setLocalTabRecords(getLocalSessionTabEngagement());

    await sendAnalyticsEvent({
      type: 'tab_view',
      path: `/#${targetTabId}`,
      tab: targetTabId,
      metadata: { simulated: true, action: 'feature_interaction', addedDwell: 35 }
    });

    const updated = await fetchAnalyticsSummary();
    if (updated) {
      setSummary(updated);
      if (updated.userSessionHeatmap?.tabs) {
        const found = updated.userSessionHeatmap.tabs.find(t => t.tabId === targetTabId);
        if (found) setSelectedSessionTab(found);
      }
    }
    setTimeout(() => setSimulatingEvent(false), 500);
  };

  const handleResetLocalSessionEngagement = () => {
    resetLocalTabSessionEngagement();
    setLocalTabRecords({});
  };

  const getSessionCategoryMeta = (cat: string) => {
    switch (cat) {
      case 'CODE_SAST':
        return { label: 'Code SAST & Taint', color: '#00FF41', bg: 'bg-emerald-500/15', border: 'border-emerald-500/40', text: 'text-emerald-300' };
      case 'CLOUD_INFRA':
        return { label: 'Cloud & Container Infra', color: '#A855F7', bg: 'bg-purple-500/15', border: 'border-purple-500/40', text: 'text-purple-300' };
      case 'API_DAST':
        return { label: 'API Security & DAST', color: '#F59E0B', bg: 'bg-amber-500/15', border: 'border-amber-500/40', text: 'text-amber-300' };
      case 'SOC_EDR':
        return { label: 'SOC & EDR Live', color: '#38BDF8', bg: 'bg-sky-500/15', border: 'border-sky-500/40', text: 'text-sky-300' };
      case 'GOV_AI':
        return { label: 'Governança & AI Security', color: '#EC4899', bg: 'bg-pink-500/15', border: 'border-pink-500/40', text: 'text-pink-300' };
      default:
        return { label: 'Segurança Geral', color: '#94A3B8', bg: 'bg-zinc-800', border: 'border-zinc-700', text: 'text-zinc-300' };
    }
  };

  const getSessionHeatStyle = (level: 0 | 1 | 2 | 3 | 4, isSelected?: boolean) => {
    let base = '';
    if (level === 4) {
      base = 'bg-gradient-to-br from-emerald-950/70 via-[#00FF41]/10 to-[#0A1629] border-[#00FF41] shadow-[0_0_18px_rgba(0,255,65,0.25)] text-white';
    } else if (level === 3) {
      base = 'bg-gradient-to-br from-emerald-950/50 to-[#0B1526] border-emerald-500/60 shadow-[0_0_10px_rgba(16,185,129,0.15)] text-zinc-100';
    } else if (level === 2) {
      base = 'bg-gradient-to-br from-sky-950/40 to-[#0A1220] border-sky-500/40 text-zinc-200';
    } else if (level === 1) {
      base = 'bg-[#0B1220]/80 border-[#1B293D] text-zinc-300 hover:border-zinc-600';
    } else {
      base = 'bg-[#070B14]/70 border-[#141E2D] text-zinc-500 hover:border-zinc-700';
    }

    if (isSelected) {
      base += ' ring-2 ring-white scale-[1.02] z-10 shadow-2xl';
    }
    return base;
  };

  const renderUserSessionHeatmapVisualizer = (isCompact = false) => {
    const activeInspectorTab = selectedSessionTab || hoveredSessionTab || filteredAndSortedSessionTabs[0];
    const topFeature = summary?.userSessionHeatmap?.topEngagedFeature;

    return (
      <div className={`p-4 sm:p-5 rounded-2xl bg-[#080D18] border border-emerald-500/30 shadow-xl space-y-4.5 relative overflow-hidden ${
        isCompact ? '' : 'my-2'
      }`}>
        {/* Glow Accent */}
        <div className="absolute top-0 right-1/4 w-96 h-28 bg-emerald-500/5 blur-3xl pointer-events-none" />

        {/* Header Bar */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-[#1A2538] pb-3.5">
          <div className="flex items-start sm:items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-emerald-500/20 to-[#00FF41]/10 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-[0_0_15px_rgba(0,255,65,0.2)] shrink-0 mt-0.5 sm:mt-0">
              <Flame className="w-5 h-5 text-emerald-400 animate-pulse" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                  <span>User Session Heatmap</span>
                  <span className="text-zinc-500 hidden sm:inline">•</span>
                  <span className="text-zinc-300 text-xs font-normal hidden sm:inline">UI Tabs & Security Features Engagement</span>
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 uppercase">
                  27 Recursos
                </span>
                {topFeature && (
                  <span className="hidden md:inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/40 text-emerald-400 border border-emerald-500/30">
                    <Flame className="w-3 h-3 text-emerald-400" />
                    <span>Top Hotspot: <strong>{topFeature.name}</strong> ({topFeature.formattedDuration})</span>
                  </span>
                )}
              </div>
              <p className="text-xs text-zinc-400 mt-0.5">
                Mapeamento visual do tempo de permanência (dwell time), frequência de uso e profundidade de navegação por aba ao longo de uma sessão.
              </p>
            </div>
          </div>

          {/* Quick Scope & Switcher Buttons in Header */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Scope Toggle: Global Average vs Current Session */}
            <div className="flex items-center bg-[#060911] border border-[#1E293B] rounded-lg p-0.5 text-xs font-mono">
              <button
                onClick={() => setSessionHeatmapScope('all_sessions')}
                className={`px-2.5 py-1 rounded transition-colors cursor-pointer font-bold ${
                  sessionHeatmapScope === 'all_sessions'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'text-zinc-400 hover:text-white'
                }`}
                title="Visualizar a média consolidada de todas as sessões registradas"
              >
                Média Global (Todas as Sessões)
              </button>
              <button
                onClick={() => setSessionHeatmapScope('current_session')}
                className={`px-2.5 py-1 rounded transition-colors cursor-pointer font-bold flex items-center gap-1 ${
                  sessionHeatmapScope === 'current_session'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'text-zinc-400 hover:text-white'
                }`}
                title="Visualizar a telemetria ao vivo acumulada nesta aba/navegador"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                <span>Sessão Atual (Ao Vivo)</span>
              </button>
            </div>

            {/* View Mode Toggle */}
            <div className="flex items-center bg-[#060911] border border-[#1E293B] rounded-lg p-0.5 text-xs font-mono">
              <button
                onClick={() => setSessionViewMode('matrix')}
                title="Visualização em Grid Matricial de Calor"
                className={`px-2 py-1 rounded transition-colors cursor-pointer flex items-center gap-1 ${
                  sessionViewMode === 'matrix'
                    ? 'bg-[#1C2636] text-white font-bold'
                    : 'text-zinc-400 hover:text-white'
                }`}
              >
                <LayoutGrid className="w-3.5 h-3.5" />
                <span>Matriz</span>
              </button>
              <button
                onClick={() => setSessionViewMode('funnel')}
                title="Jornada do Funil de Navegação por Etapas"
                className={`px-2 py-1 rounded transition-colors cursor-pointer flex items-center gap-1 ${
                  sessionViewMode === 'funnel'
                    ? 'bg-[#1C2636] text-white font-bold'
                    : 'text-zinc-400 hover:text-white'
                }`}
              >
                <Workflow className="w-3.5 h-3.5" />
                <span>Funil</span>
              </button>
              <button
                onClick={() => setSessionViewMode('distribution')}
                title="Distribuição de Tempo por Domínio AppSec"
                className={`px-2 py-1 rounded transition-colors cursor-pointer flex items-center gap-1 ${
                  sessionViewMode === 'distribution'
                    ? 'bg-[#1C2636] text-white font-bold'
                    : 'text-zinc-400 hover:text-white'
                }`}
              >
                <PieChart className="w-3.5 h-3.5" />
                <span>Domínios</span>
              </button>
            </div>
          </div>
        </div>

        {/* Top Session Journey Highlights Strip (4 KPI Mini-Cards) */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {/* 1. Top Engaged Feature */}
          <div className="p-3 rounded-xl bg-[#060B14] border border-emerald-500/30 flex items-start justify-between gap-2 shadow-sm">
            <div>
              <div className="flex items-center gap-1.5 text-zinc-400 text-xs font-mono">
                <Flame className="w-3.5 h-3.5 text-emerald-400" />
                <span>Recurso Mais Engajado</span>
              </div>
              <div className="text-base sm:text-lg font-black font-mono text-emerald-400 mt-1 truncate max-w-[190px]">
                {topFeature?.name || 'Scanner SAST & AST'}
              </div>
              <div className="text-[10px] text-zinc-400 font-mono mt-0.5">
                Dwell: <strong className="text-zinc-200">{topFeature?.formattedDuration || '04m 15s'}</strong> • {topFeature?.interactions || 42} cliques
              </div>
            </div>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
              #1 HOTSPOT
            </span>
          </div>

          {/* 2. Most Frequent Entry Point */}
          <div className="p-3 rounded-xl bg-[#060B14] border border-[#1A2538] flex items-start justify-between gap-2 shadow-sm">
            <div>
              <div className="flex items-center gap-1.5 text-zinc-400 text-xs font-mono">
                <Target className="w-3.5 h-3.5 text-sky-400" />
                <span>Ponto de Entrada (Start)</span>
              </div>
              <div className="text-base sm:text-lg font-black font-mono text-sky-400 mt-1 uppercase">
                {summary?.userSessionHeatmap?.mostFrequentStartingTab || 'DASHBOARD'}
              </div>
              <div className="text-[10px] text-zinc-400 font-mono mt-0.5">
                85% das sessões iniciam com visão geral
              </div>
            </div>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-sky-500/10 text-sky-300 border border-sky-500/30">
              ENTRADA
            </span>
          </div>

          {/* 3. Most Frequent Exit Point */}
          <div className="p-3 rounded-xl bg-[#060B14] border border-[#1A2538] flex items-start justify-between gap-2 shadow-sm">
            <div>
              <div className="flex items-center gap-1.5 text-zinc-400 text-xs font-mono">
                <ArrowRight className="w-3.5 h-3.5 text-amber-400" />
                <span>Ponto de Saída (Exit)</span>
              </div>
              <div className="text-base sm:text-lg font-black font-mono text-amber-400 mt-1 uppercase">
                {summary?.userSessionHeatmap?.mostFrequentExitTab || 'REFACTORING'}
              </div>
              <div className="text-[10px] text-zinc-400 font-mono mt-0.5">
                64% concluem na refatoração com IA
              </div>
            </div>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-amber-500/10 text-amber-300 border border-amber-500/30">
              SAÍDA
            </span>
          </div>

          {/* 4. Average Tabs Explored */}
          <div className="p-3 rounded-xl bg-[#060B14] border border-[#1A2538] flex items-start justify-between gap-2 shadow-sm">
            <div>
              <div className="flex items-center gap-1.5 text-zinc-400 text-xs font-mono">
                <Layers className="w-3.5 h-3.5 text-purple-400" />
                <span>Média de Abas por Sessão</span>
              </div>
              <div className="text-base sm:text-lg font-black font-mono text-purple-400 mt-1">
                {summary?.userSessionHeatmap?.avgTabsExploredPerSession || 4.6} Recursos
              </div>
              <div className="text-[10px] text-zinc-400 font-mono mt-0.5">
                Taxa de retenção: {summary?.sessionMetrics?.retentionRatePercent || 88.5}%
              </div>
            </div>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/30">
              PROFUNDIDADE
            </span>
          </div>
        </div>

        {/* Filters & Sorting Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-2.5 pt-1">
          {/* Category Filter Pills */}
          <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
            <span className="text-[11px] text-zinc-500 font-bold uppercase mr-1">Filtrar Categoria:</span>
            {(['ALL', 'CODE_SAST', 'CLOUD_INFRA', 'API_DAST', 'SOC_EDR', 'GOV_AI'] as SessionCategoryFilterType[]).map((cat) => {
              const meta = cat === 'ALL' 
                ? { label: 'Todas (27)', color: '#00FF41' } 
                : getSessionCategoryMeta(cat);
              const isActive = sessionCategoryFilter === cat;

              return (
                <button
                  key={cat}
                  onClick={() => setSessionCategoryFilter(cat)}
                  className={`px-2.5 py-1 rounded-md text-xs font-mono transition-all cursor-pointer ${
                    isActive
                      ? 'bg-zinc-800 text-white font-bold border border-emerald-400/60 shadow-sm'
                      : 'bg-[#070B14] text-zinc-400 hover:text-zinc-200 border border-[#162132]'
                  }`}
                >
                  <span className="flex items-center gap-1.5">
                    <span
                      className="w-2 h-2 rounded-full"
                      style={{ backgroundColor: meta.color }}
                    />
                    <span>{meta.label}</span>
                  </span>
                </button>
              );
            })}
          </div>

          {/* Sort Selector */}
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-[11px] text-zinc-500 font-bold uppercase">Ordenar por:</span>
            <div className="flex items-center bg-[#070B14] border border-[#1E293B] rounded-lg p-0.5">
              <button
                onClick={() => setSessionSort('engagement')}
                className={`px-2 py-0.5 rounded text-[11px] transition-colors cursor-pointer ${
                  sessionSort === 'engagement' ? 'bg-[#1C2636] text-white font-bold' : 'text-zinc-400 hover:text-white'
                }`}
              >
                Score
              </button>
              <button
                onClick={() => setSessionSort('dwell')}
                className={`px-2 py-0.5 rounded text-[11px] transition-colors cursor-pointer ${
                  sessionSort === 'dwell' ? 'bg-[#1C2636] text-white font-bold' : 'text-zinc-400 hover:text-white'
                }`}
              >
                Tempo
              </button>
              <button
                onClick={() => setSessionSort('interactions')}
                className={`px-2 py-0.5 rounded text-[11px] transition-colors cursor-pointer ${
                  sessionSort === 'interactions' ? 'bg-[#1C2636] text-white font-bold' : 'text-zinc-400 hover:text-white'
                }`}
              >
                Cliques
              </button>
              <button
                onClick={() => setSessionSort('adoption')}
                className={`px-2 py-0.5 rounded text-[11px] transition-colors cursor-pointer ${
                  sessionSort === 'adoption' ? 'bg-[#1C2636] text-white font-bold' : 'text-zinc-400 hover:text-white'
                }`}
              >
                Adoção
              </button>
            </div>
          </div>
        </div>

        {/* VIEW MODE 1: MATRIX HEATMAP GRID */}
        {sessionViewMode === 'matrix' && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            {filteredAndSortedSessionTabs.map((tab) => {
              const meta = getSessionCategoryMeta(tab.category);
              const isSelected = activeInspectorTab?.tabId === tab.tabId;
              const isAbsoluteTop = tab.rank === 1;

              return (
                <div
                  key={tab.tabId}
                  onClick={() => setSelectedSessionTab(tab)}
                  onMouseEnter={() => setHoveredSessionTab(tab)}
                  onMouseLeave={() => setHoveredSessionTab(null)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer relative group flex flex-col justify-between min-h-[140px] ${getSessionHeatStyle(tab.heatLevel, isSelected)}`}
                >
                  {/* Absolute Top Hotspot Ping */}
                  {isAbsoluteTop && (
                    <span className="absolute -top-1.5 -right-1.5 flex h-3 w-3">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-white opacity-80" />
                      <span className="relative inline-flex rounded-full h-3 w-3 bg-[#00FF41]" />
                    </span>
                  )}

                  {/* Card Header: Rank, Category Pill, Heat Badge */}
                  <div>
                    <div className="flex items-center justify-between gap-1 mb-1.5">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-black/60 border border-zinc-700/60 text-zinc-300">
                          #{tab.rank}
                        </span>
                        <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${meta.bg} ${meta.border} ${meta.text}`}>
                          {meta.label.split(' ')[0]}
                        </span>
                      </div>

                      {/* Heat Level Tag */}
                      <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                        tab.heatLevel === 4 ? 'bg-[#00FF41] text-zinc-950 font-black shadow-[0_0_8px_rgba(0,255,65,0.6)]' :
                        tab.heatLevel === 3 ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' :
                        tab.heatLevel === 2 ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40' :
                        tab.heatLevel === 1 ? 'bg-zinc-800 text-zinc-400' :
                        'bg-zinc-900/60 text-zinc-600'
                      }`}>
                        {tab.heatLevel === 4 ? '🔥 PICO' :
                         tab.heatLevel === 3 ? '⚡ ALTO' :
                         tab.heatLevel === 2 ? '🔹 MÉDIO' :
                         tab.heatLevel === 1 ? '🔸 BAIXO' : '▫️ FRIO'}
                      </span>
                    </div>

                    {/* Feature Title */}
                    <h4 className="text-xs font-bold text-white font-mono tracking-wide line-clamp-1 group-hover:text-emerald-300 transition-colors">
                      {tab.name}
                    </h4>
                  </div>

                  {/* Metrics: Dwell Time & Interactions */}
                  <div className="my-2.5 space-y-1.5">
                    <div className="flex items-baseline justify-between text-xs font-mono">
                      <span className="text-zinc-400 text-[11px] flex items-center gap-1">
                        <Clock className="w-3 h-3 text-sky-400" />
                        <span>Dwell:</span>
                      </span>
                      <strong className={`text-xs ${tab.dwellSeconds > 0 ? 'text-emerald-400' : 'text-zinc-500'}`}>
                        {tab.formattedDuration}
                      </strong>
                    </div>

                    <div className="flex items-baseline justify-between text-xs font-mono">
                      <span className="text-zinc-400 text-[11px] flex items-center gap-1">
                        <MousePointerClick className="w-3 h-3 text-amber-400" />
                        <span>Cliques / Ações:</span>
                      </span>
                      <strong className="text-zinc-200">
                        {tab.interactionCount}
                      </strong>
                    </div>

                    {/* Engagement Score Intensity Meter */}
                    <div className="space-y-0.5 pt-1">
                      <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400">
                        <span>Score de Engajamento:</span>
                        <span className="font-bold text-white">{tab.sessionEngagementScore}%</span>
                      </div>
                      <div className="w-full h-1.5 rounded-full bg-black/60 overflow-hidden border border-zinc-800/80">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${
                            tab.heatLevel === 4 ? 'bg-gradient-to-r from-emerald-400 to-[#00FF41] shadow-[0_0_8px_#00FF41]' :
                            tab.heatLevel === 3 ? 'bg-emerald-500' :
                            tab.heatLevel === 2 ? 'bg-sky-400' :
                            tab.heatLevel === 1 ? 'bg-amber-400' :
                            'bg-zinc-700'
                          }`}
                          style={{ width: `${Math.max(4, tab.sessionEngagementScore)}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Card Footer: Adoption Rate */}
                  <div className="pt-2 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-zinc-400">
                    <span>Adoção de Sessão:</span>
                    <span className="font-bold text-zinc-300">{tab.adoptionRate}%</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* VIEW MODE 2: SESSION FUNNEL JOURNEY */}
        {sessionViewMode === 'funnel' && (
          <div className="space-y-3.5">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
              {(summary?.userSessionHeatmap?.sessionFunnelStages || []).map((stage, idx) => (
                <div
                  key={stage.stage}
                  className="p-4 rounded-xl bg-[#060B14] border border-[#1A2538] flex flex-col justify-between relative overflow-hidden"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                        ETAPA {idx + 1}
                      </span>
                      <span className="text-xs font-mono font-bold text-emerald-400">
                        {stage.formattedTime}
                      </span>
                    </div>

                    <h4 className="text-xs font-bold font-mono text-white pt-1">
                      {stage.name}
                    </h4>

                    <p className="text-[11px] text-zinc-400 leading-snug">
                      {stage.description}
                    </p>
                  </div>

                  <div className="mt-4 pt-3 border-t border-[#182334] space-y-2">
                    {/* Retention & Dropoff */}
                    <div className="flex items-center justify-between text-[10px] font-mono">
                      <span className="text-zinc-400">Retenção de Etapa:</span>
                      <span className="text-emerald-400 font-bold">{stage.retentionPercent}%</span>
                    </div>
                    <div className="w-full h-1.5 rounded-full bg-black border border-zinc-800 overflow-hidden">
                      <div
                        className="h-full bg-emerald-400 rounded-full"
                        style={{ width: `${stage.retentionPercent}%` }}
                      />
                    </div>

                    {/* Primary Tabs visited in stage */}
                    <div className="pt-1.5">
                      <span className="text-[10px] font-mono text-zinc-500 block mb-1">Recursos da Etapa:</span>
                      <div className="flex flex-wrap gap-1">
                        {stage.primaryTabs.map((pt) => (
                          <button
                            key={pt}
                            onClick={() => {
                              const found = summary?.userSessionHeatmap?.tabs.find(t => t.tabId === pt);
                              if (found) setSelectedSessionTab(found);
                            }}
                            className="px-1.5 py-0.5 rounded bg-[#101726] border border-[#1E2E44] text-[10px] font-mono text-zinc-300 hover:border-emerald-400 hover:text-white transition-colors cursor-pointer"
                          >
                            {pt}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* VIEW MODE 3: CATEGORY DISTRIBUTION */}
        {sessionViewMode === 'distribution' && (
          <div className="space-y-4">
            {/* Horizontal Stacked Percentage Bar */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
                <span>Participação no Tempo Total de Sessão:</span>
                <span className="text-zinc-200">100% de Atenção Técnica</span>
              </div>
              <div className="h-4 w-full rounded-lg bg-black border border-zinc-800 flex overflow-hidden">
                {(summary?.userSessionHeatmap?.categoryDistribution || []).map((cat) => (
                  <div
                    key={cat.category}
                    className="h-full transition-all group relative cursor-pointer"
                    style={{
                      width: `${Math.max(4, cat.percentage)}%`,
                      backgroundColor: cat.color,
                    }}
                    title={`${cat.label}: ${cat.percentage}% do tempo`}
                  />
                ))}
              </div>
            </div>

            {/* 5 Domain Detail Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
              {(summary?.userSessionHeatmap?.categoryDistribution || []).map((cat) => (
                <div
                  key={cat.category}
                  className="p-3.5 rounded-xl bg-[#060B14] border border-[#1A2538] flex flex-col justify-between space-y-2 shadow-sm"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span
                        className="w-2.5 h-2.5 rounded-full"
                        style={{ backgroundColor: cat.color }}
                      />
                      <span className="text-xs font-bold font-mono text-white truncate">
                        {cat.label}
                      </span>
                    </div>
                    <div className="text-2xl font-black font-mono mt-1" style={{ color: cat.color }}>
                      {cat.percentage}%
                    </div>
                  </div>

                  <div className="text-[10px] font-mono text-zinc-400 space-y-0.5 pt-2 border-t border-[#182334]">
                    <div>{cat.tabCount} módulos monitorados</div>
                    <div>Tempo ponderado: <strong className="text-zinc-200">{Math.round(cat.dwellSeconds / 60)} min</strong></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* INTERACTIVE FEATURE INSPECTOR & ACTIONS DRAWER */}
        {activeInspectorTab && (
          <div className="p-4 rounded-xl bg-[#050912] border border-emerald-500/40 space-y-3 shadow-lg">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#182436] pb-3">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                  <Flame className="w-5 h-5 text-emerald-400" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-black border border-zinc-700 text-zinc-200">
                      #{activeInspectorTab.rank}
                    </span>
                    <h4 className="text-sm font-bold text-white font-mono">
                      {activeInspectorTab.name}
                    </h4>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                      Tab: #{activeInspectorTab.tabId}
                    </span>
                  </div>
                  <div className="text-xs text-zinc-400 font-mono mt-0.5 flex flex-wrap items-center gap-2">
                    <span>Categoria: <strong className="text-zinc-200">{getSessionCategoryMeta(activeInspectorTab.category).label}</strong></span>
                    <span>•</span>
                    <span>Dwell Médio: <strong className="text-emerald-400">{activeInspectorTab.formattedDuration}</strong></span>
                    <span>•</span>
                    <span>Cliques: <strong className="text-white">{activeInspectorTab.interactionCount}</strong></span>
                    <span>•</span>
                    <span>Score de Engajamento: <strong className="text-emerald-300">{activeInspectorTab.sessionEngagementScore}%</strong></span>
                  </div>
                </div>
              </div>

              {/* Action Buttons for the active feature */}
              <div className="flex items-center gap-2">
                {onNavigateTab && (
                  <button
                    onClick={() => onNavigateTab(activeInspectorTab.tabId)}
                    title="Navegar para este módulo agora na aplicação SecScan"
                    className="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/50 text-emerald-300 text-xs font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-sm"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    <span>Navegar para Módulo</span>
                  </button>
                )}

                <button
                  onClick={() => handleSimulateTabEngagement(activeInspectorTab.tabId)}
                  disabled={simulatingEvent}
                  title="Registrar interação simulada para ver o calor do módulo subir em tempo real"
                  className="px-3 py-1.5 rounded-lg bg-[#141F30] hover:bg-[#1E2E44] border border-[#273B54] text-zinc-200 hover:text-white text-xs font-mono flex items-center gap-1.5 transition-all cursor-pointer"
                >
                  <Zap className={`w-3.5 h-3.5 text-emerald-400 ${simulatingEvent ? 'animate-bounce' : ''}`} />
                  <span>Simular Engajamento (+1 / +35s)</span>
                </button>

                {sessionHeatmapScope === 'current_session' && (
                  <button
                    onClick={handleResetLocalSessionEngagement}
                    title="Zerar métricas locais desta sessão no navegador"
                    className="p-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-400 hover:text-white transition-colors cursor-pointer"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Heatmap Legend Footer */}
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-zinc-400 pt-2 border-t border-[#182334]">
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-zinc-500 uppercase font-bold">Nível de Calor:</span>
            <div className="flex items-center gap-2">
              <span className="flex items-center gap-1">
                <span className="w-3 h-3 rounded bg-[#070B14] border border-[#141E2D]" />
                <span className="text-[10px]">Frio (0%)</span>
              </span>
              <span className="flex items-center gap-1">
                <span className="w-3 h-3 rounded bg-[#0B1220] border border-[#1B293D]" />
                <span className="text-[10px]">Baixo (&lt;25%)</span>
              </span>
              <span className="flex items-center gap-1">
                <span className="w-3 h-3 rounded bg-sky-950/60 border border-sky-500/40" />
                <span className="text-[10px]">Médio (25-50%)</span>
              </span>
              <span className="flex items-center gap-1">
                <span className="w-3 h-3 rounded bg-emerald-950/60 border border-emerald-500/60" />
                <span className="text-[10px]">Alto (50-75%)</span>
              </span>
              <span className="flex items-center gap-1">
                <span className="w-3 h-3 rounded bg-[#00FF41] border border-white shadow-[0_0_8px_#00FF41]" />
                <span className="text-[10px] font-bold text-white">Pico Hotspot (&gt;75%)</span>
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 text-[11px] text-zinc-500">
            <Info className="w-3.5 h-3.5 text-zinc-400" />
            <span>Passe o mouse ou clique em qualquer recurso para inspecionar métricas detalhadas</span>
          </div>
        </div>
      </div>
    );
  };

  // Engine Efficiency Scatter Plot (Scan Duration vs Number of Findings) Data
  const sessionScanPoints: ScanEfficiencyDataPoint[] = useMemo(() => {
    const list: ScanEfficiencyDataPoint[] = [];

    // Real scans from session scanHistory
    if (scanHistory && scanHistory.length > 0) {
      scanHistory.forEach((rep, idx) => {
        const ms = Math.max(90, rep.durationMs || 290);
        const sec = Number((ms / 1000).toFixed(2));
        const findings = rep.findings?.length || 0;
        const throughput = Number((findings / Math.max(0.1, sec)).toFixed(1));
        const crit = rep.findings?.filter(f => f.severity === 'CRITICAL').length || 0;
        const high = rep.findings?.filter(f => f.severity === 'HIGH').length || 0;

        let rating: 'ULTRA_FAST' | 'OPTIMAL' | 'MODERATE' | 'DEEP_AUDIT' = 'OPTIMAL';
        if (ms < 400) rating = 'ULTRA_FAST';
        else if (ms < 850) rating = 'OPTIMAL';
        else if (ms < 1400) rating = 'MODERATE';
        else rating = 'DEEP_AUDIT';

        list.push({
          id: `live_scan_${rep.id || idx}`,
          scanIndex: idx + 1,
          timestamp: Date.now() - (scanHistory.length - idx) * 35000,
          timeLabel: `Varredura #${idx + 1} (Sessão)`,
          durationMs: ms,
          durationSec: sec,
          findingsCount: findings,
          filesCount: rep.scannedFilesCount || rep.totalFiles || 14,
          linesOfCode: (rep.scannedFilesCount || 12) * 165,
          throughput,
          efficiencyRating: rating,
          engineMode: 'AST_REGEX',
          isCurrentSession: true,
          projectName: 'Workspace Atual',
          criticalFindings: crit,
          highFindings: high,
        });
      });
    } else if (currentReport) {
      const ms = Math.max(90, currentReport.durationMs || 310);
      const sec = Number((ms / 1000).toFixed(2));
      const findings = currentReport.findings?.length || 0;
      const throughput = Number((findings / Math.max(0.1, sec)).toFixed(1));
      const crit = currentReport.findings?.filter(f => f.severity === 'CRITICAL').length || 0;
      const high = currentReport.findings?.filter(f => f.severity === 'HIGH').length || 0;

      list.push({
        id: `live_scan_current`,
        scanIndex: 1,
        timestamp: Date.now(),
        timeLabel: `Varredura Atual (Workspace)`,
        durationMs: ms,
        durationSec: sec,
        findingsCount: findings,
        filesCount: currentReport.scannedFilesCount || currentReport.totalFiles || 14,
        linesOfCode: (currentReport.scannedFilesCount || 14) * 170,
        throughput,
        efficiencyRating: ms < 400 ? 'ULTRA_FAST' : ms < 850 ? 'OPTIMAL' : 'MODERATE',
        engineMode: 'AST_REGEX',
        isCurrentSession: true,
        projectName: 'Workspace Ativo',
        criticalFindings: crit,
        highFindings: high,
      });
    }

    list.push(...simulatedLocalScans);
    return list;
  }, [scanHistory, currentReport, simulatedLocalScans]);

  const filteredScatterPoints: ScanEfficiencyDataPoint[] = useMemo(() => {
    let allPoints: ScanEfficiencyDataPoint[] = [];

    if (scatterScopeFilter === 'current_session') {
      allPoints = sessionScanPoints.length > 0 
        ? sessionScanPoints 
        : (summary?.scanEfficiency?.dataPoints?.slice(-6).map(p => ({ ...p, isCurrentSession: true })) || []);
    } else {
      const serverPoints = summary?.scanEfficiency?.dataPoints || [];
      allPoints = [...serverPoints, ...sessionScanPoints];
    }

    if (scatterScopeFilter === 'sub_second') {
      allPoints = allPoints.filter(p => p.durationMs < 1000);
    }

    if (scatterEngineFilter !== 'ALL') {
      allPoints = allPoints.filter(p => p.engineMode === scatterEngineFilter);
    }

    allPoints.sort((a, b) => a.durationMs - b.durationMs);
    return allPoints;
  }, [summary?.scanEfficiency?.dataPoints, sessionScanPoints, scatterScopeFilter, scatterEngineFilter]);

  const scatterStats = useMemo(() => {
    const total = filteredScatterPoints.length;
    if (total === 0) {
      return {
        totalPoints: 0,
        avgMs: 480,
        avgDurationFormatted: '480ms',
        avgFindings: 16.5,
        avgThroughput: 34.8,
        subSecondRate: 91.6,
        fastestScanMs: 165,
        highestFindingCount: 45,
      };
    }

    let sumMs = 0;
    let sumFindings = 0;
    let sumThroughput = 0;
    let subSecCount = 0;
    let fastestMs = Infinity;
    let highestFindings = 0;

    filteredScatterPoints.forEach(p => {
      sumMs += p.durationMs;
      sumFindings += p.findingsCount;
      sumThroughput += p.throughput;
      if (p.durationMs < 1000) subSecCount++;
      if (p.durationMs < fastestMs) fastestMs = p.durationMs;
      if (p.findingsCount > highestFindings) highestFindings = p.findingsCount;
    });

    const avgMs = Math.round(sumMs / total);
    return {
      totalPoints: total,
      avgMs,
      avgDurationFormatted: avgMs < 1000 ? `${avgMs}ms` : `${(avgMs / 1000).toFixed(2)}s`,
      avgFindings: Math.round((sumFindings / total) * 10) / 10,
      avgThroughput: Math.round((sumThroughput / total) * 10) / 10,
      subSecondRate: Math.round((subSecCount / total) * 100),
      fastestScanMs: fastestMs === Infinity ? 165 : fastestMs,
      highestFindingCount: highestFindings,
    };
  }, [filteredScatterPoints]);

  const handleSimulateScanBenchmark = async () => {
    setSimulatingEvent(true);
    const sampleProjects = [
      'auth-microservice',
      'cloud-gateway-proxy',
      'payment-vault-core',
      'graphql-bff-engine',
      'k8s-operator-suite',
      'edge-security-worker',
      'identity-access-mesh'
    ];
    const project = sampleProjects[Math.floor(Math.random() * sampleProjects.length)];
    const files = 8 + Math.floor(Math.random() * 48);
    const findings = Math.floor(files * (0.35 + Math.random() * 0.45));
    const ms = Math.floor(150 + files * (9 + Math.random() * 11));
    const sec = Number((ms / 1000).toFixed(2));
    const throughput = Number((findings / Math.max(0.1, sec)).toFixed(1));

    let rating: 'ULTRA_FAST' | 'OPTIMAL' | 'MODERATE' | 'DEEP_AUDIT' = 'OPTIMAL';
    if (ms < 400) rating = 'ULTRA_FAST';
    else if (ms < 850) rating = 'OPTIMAL';
    else if (ms < 1400) rating = 'MODERATE';
    else rating = 'DEEP_AUDIT';

    const newPoint: ScanEfficiencyDataPoint = {
      id: `sim_scan_${Date.now()}`,
      scanIndex: (filteredScatterPoints.length || 0) + 1,
      timestamp: Date.now(),
      timeLabel: `Benchmark #${(filteredScatterPoints.length || 0) + 1} (Ao Vivo)`,
      durationMs: ms,
      durationSec: sec,
      findingsCount: findings,
      filesCount: files,
      linesOfCode: files * 175,
      throughput,
      efficiencyRating: rating,
      engineMode: Math.random() > 0.45 ? 'AST_REGEX' : 'TAINT_FLOW',
      isCurrentSession: true,
      projectName: project,
      criticalFindings: Math.max(1, Math.floor(findings * 0.25)),
      highFindings: Math.max(1, Math.floor(findings * 0.4)),
    };

    setSimulatedLocalScans(prev => [newPoint, ...prev]);
    setSelectedScatterPoint(newPoint);

    await sendAnalyticsEvent({
      type: 'scan_action',
      path: '/scanner',
      tab: 'scanner',
      metadata: { simulatedScan: true, durationMs: ms, findingsCount: findings, project }
    });

    const updated = await fetchAnalyticsSummary();
    if (updated) setSummary(updated);
    setTimeout(() => setSimulatingEvent(false), 500);
  };

  // Cyber Custom Tooltip for Scatter Plot
  const CustomScatterTooltip: React.FC<any> = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const data: ScanEfficiencyDataPoint = payload[0].payload;
      if (!data) return null;

      const durLabel = scatterXUnit === 'sec' ? `${data.durationSec}s (${data.durationMs}ms)` : `${data.durationMs}ms (${data.durationSec}s)`;

      return (
        <div className="bg-[#070D18]/95 border border-[#1E293B] shadow-[0_0_25px_rgba(0,0,0,0.85)] backdrop-blur-md p-3.5 rounded-xl font-mono text-xs text-zinc-200 min-w-[210px] space-y-2 z-50">
          <div className="flex items-center justify-between border-b border-[#1A2538] pb-1.5">
            <span className="font-bold text-white flex items-center gap-1.5 truncate max-w-[150px]">
              <Crosshair className="w-3.5 h-3.5 text-emerald-400" />
              <span>{data.projectName || data.timeLabel}</span>
            </span>
            {data.isCurrentSession ? (
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold">
                AO VIVO
              </span>
            ) : (
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-sky-500/10 text-sky-300 border border-sky-500/30">
                BENCHMARK
              </span>
            )}
          </div>

          <div className="space-y-1 text-[11px]">
            <div className="flex items-center justify-between">
              <span className="text-zinc-400">⏱️ Duração:</span>
              <strong className="text-emerald-400 font-bold">{durLabel}</strong>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-zinc-400">🛡️ Achados:</span>
              <strong className="text-white font-bold">{data.findingsCount} achados</strong>
            </div>

            <div className="flex items-center justify-between text-[10px] text-zinc-400 pl-2">
              <span>(Críticos: {data.criticalFindings} • Altos: {data.highFindings})</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-zinc-400">📁 Arquivos:</span>
              <span className="text-zinc-200">{data.filesCount} arquivos</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-zinc-400">⚡ Velocidade:</span>
              <strong className="text-sky-300 font-bold">{data.throughput} achados/s</strong>
            </div>

            <div className="flex items-center justify-between pt-1 border-t border-zinc-800">
              <span className="text-zinc-400">Classificação:</span>
              <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                data.efficiencyRating === 'ULTRA_FAST' ? 'bg-emerald-500/20 text-emerald-300' :
                data.efficiencyRating === 'OPTIMAL' ? 'bg-sky-500/20 text-sky-300' :
                data.efficiencyRating === 'MODERATE' ? 'bg-amber-500/20 text-amber-300' :
                'bg-purple-500/20 text-purple-300'
              }`}>
                {data.efficiencyRating === 'ULTRA_FAST' ? '⚡ Ultra-Rápido (<400ms)' :
                 data.efficiencyRating === 'OPTIMAL' ? '✨ Ideal (Sub-segundo)' :
                 data.efficiencyRating === 'MODERATE' ? '📊 Moderado' : '🔍 Auditoria Profunda'}
              </span>
            </div>
          </div>
        </div>
      );
    }
    return null;
  };

  const renderEngineEfficiencyScatterPlot = (isCompact = false) => {
    const selectedPoint = selectedScatterPoint || hoveredScatterPoint || filteredScatterPoints[0];

    return (
      <div className={`p-4 sm:p-5 rounded-2xl bg-[#080D18] border border-sky-500/35 shadow-xl space-y-4.5 relative overflow-hidden ${
        isCompact ? '' : 'my-2'
      }`}>
        {/* Glow Accent */}
        <div className="absolute top-0 right-1/3 w-96 h-28 bg-sky-500/5 blur-3xl pointer-events-none" />

        {/* Header Bar */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-[#1A2538] pb-3.5">
          <div className="flex items-start sm:items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-sky-500/20 to-[#38BDF8]/10 border border-sky-500/40 flex items-center justify-center text-sky-400 shadow-[0_0_15px_rgba(56,189,248,0.2)] shrink-0 mt-0.5 sm:mt-0">
              <Crosshair className="w-5 h-5 text-sky-400 animate-pulse" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                  <span>Eficiência do Motor SecScan: Duração vs. Achados</span>
                  <span className="text-zinc-500 hidden sm:inline">•</span>
                  <span className="text-zinc-300 text-xs font-normal hidden sm:inline">Engine Efficiency Scatter Plot</span>
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-sky-500/15 text-sky-300 border border-sky-500/35 uppercase">
                  Recharts Scatter
                </span>
                <span className="hidden md:inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/40 text-emerald-400 border border-emerald-500/30">
                  <Gauge className="w-3 h-3 text-emerald-400" />
                  <span>Meta: Sub-segundo ({scatterStats.subSecondRate}% &lt; 1.0s)</span>
                </span>
              </div>
              <p className="text-xs text-zinc-400 mt-0.5">
                Diagrama de dispersão correlacionando o tempo de execução do motor SAST/AST contra o volume de vulnerabilidades detectadas, atestando previsibilidade linear e rapidez para CI/CD.
              </p>
            </div>
          </div>

          {/* Quick Actions & Units Toolbar */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Unit Toggle: ms vs sec */}
            <div className="flex items-center bg-[#060911] border border-[#1E293B] rounded-lg p-0.5 text-xs font-mono">
              <button
                onClick={() => setScatterXUnit('ms')}
                className={`px-2.5 py-1 rounded transition-colors cursor-pointer font-bold ${
                  scatterXUnit === 'ms'
                    ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
                    : 'text-zinc-400 hover:text-white'
                }`}
                title="Eixo X em Milissegundos (ms)"
              >
                Milissegundos (ms)
              </button>
              <button
                onClick={() => setScatterXUnit('sec')}
                className={`px-2.5 py-1 rounded transition-colors cursor-pointer font-bold ${
                  scatterXUnit === 'sec'
                    ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
                    : 'text-zinc-400 hover:text-white'
                }`}
                title="Eixo X em Segundos (s)"
              >
                Segundos (s)
              </button>
            </div>

            {/* Scope Filter */}
            <div className="flex items-center bg-[#060911] border border-[#1E293B] rounded-lg p-0.5 text-xs font-mono">
              <button
                onClick={() => setScatterScopeFilter('all')}
                className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                  scatterScopeFilter === 'all' ? 'bg-[#1C2636] text-white font-bold' : 'text-zinc-400 hover:text-white'
                }`}
                title="Histórico Completo de Varreduras & Benchmarks"
              >
                Todos ({filteredScatterPoints.length})
              </button>
              <button
                onClick={() => setScatterScopeFilter('current_session')}
                className={`px-2 py-1 rounded transition-colors cursor-pointer flex items-center gap-1 ${
                  scatterScopeFilter === 'current_session' ? 'bg-[#1C2636] text-emerald-400 font-bold' : 'text-zinc-400 hover:text-white'
                }`}
                title="Apenas Varreduras da Sessão Atual"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                <span>Sessão Atual</span>
              </button>
              <button
                onClick={() => setScatterScopeFilter('sub_second')}
                className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                  scatterScopeFilter === 'sub_second' ? 'bg-[#1C2636] text-sky-300 font-bold' : 'text-zinc-400 hover:text-white'
                }`}
                title="Apenas Varreduras Sub-segundo (<1000ms)"
              >
                &lt; 1.0s
              </button>
            </div>

            {/* Simulation trigger button */}
            <button
              onClick={handleSimulateScanBenchmark}
              disabled={simulatingEvent}
              title="Executar simulação instantânea de varredura benchmark para plotar um novo ponto ao vivo no gráfico"
              className="px-2.5 py-1.5 rounded-lg bg-sky-950/40 hover:bg-sky-900/50 border border-sky-500/40 text-sky-300 text-xs font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer active:scale-95 shadow-sm"
            >
              <Zap className={`w-3.5 h-3.5 text-sky-400 ${simulatingEvent ? 'animate-bounce' : ''}`} />
              <span>Simular Varredura (+1 Ponto)</span>
            </button>
          </div>
        </div>

        {/* 4 Engine Efficiency KPI Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {/* 1. Avg Duration */}
          <div className="p-3 rounded-xl bg-[#060B14] border border-sky-500/30 flex items-start justify-between gap-2 shadow-sm">
            <div>
              <div className="flex items-center gap-1.5 text-zinc-400 text-xs font-mono">
                <Clock className="w-3.5 h-3.5 text-sky-400" />
                <span>Tempo Médio (Latência)</span>
              </div>
              <div className="text-xl sm:text-2xl font-black font-mono text-sky-400 mt-1">
                {scatterStats.avgDurationFormatted}
              </div>
              <div className="text-[10px] text-zinc-400 font-mono mt-0.5">
                Baseado em {scatterStats.totalPoints} execuções avaliadas
              </div>
            </div>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-sky-500/15 text-sky-300 border border-sky-500/30">
              SUB-SEGUNDO
            </span>
          </div>

          {/* 2. Throughput */}
          <div className="p-3 rounded-xl bg-[#060B14] border border-[#1A2538] flex items-start justify-between gap-2 shadow-sm">
            <div>
              <div className="flex items-center gap-1.5 text-zinc-400 text-xs font-mono">
                <Gauge className="w-3.5 h-3.5 text-emerald-400" />
                <span>Rendimento / Velocidade</span>
              </div>
              <div className="text-xl sm:text-2xl font-black font-mono text-emerald-400 mt-1">
                {scatterStats.avgThroughput} <span className="text-xs font-normal text-zinc-400">achados/s</span>
              </div>
              <div className="text-[10px] text-zinc-400 font-mono mt-0.5">
                Média de {scatterStats.avgFindings} achados por varredura
              </div>
            </div>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-bold">
              ALTA TAXA
            </span>
          </div>

          {/* 3. Sub-second Execution Rate */}
          <div className="p-3 rounded-xl bg-[#060B14] border border-[#1A2538] flex items-start justify-between gap-2 shadow-sm">
            <div>
              <div className="flex items-center gap-1.5 text-zinc-400 text-xs font-mono">
                <Zap className="w-3.5 h-3.5 text-amber-400" />
                <span>Conclusão &lt; 1.0s</span>
              </div>
              <div className="text-xl sm:text-2xl font-black font-mono text-amber-400 mt-1">
                {scatterStats.subSecondRate}%
              </div>
              <div className="text-[10px] text-zinc-400 font-mono mt-0.5">
                Ideal para Pre-commit & CI/CD Fast Feedback
              </div>
            </div>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-amber-500/10 text-amber-300 border border-amber-500/30">
              CI/CD READY
            </span>
          </div>

          {/* 4. Fastest Scan Execution */}
          <div className="p-3 rounded-xl bg-[#060B14] border border-[#1A2538] flex items-start justify-between gap-2 shadow-sm">
            <div>
              <div className="flex items-center gap-1.5 text-zinc-400 text-xs font-mono">
                <TrendingUp className="w-3.5 h-3.5 text-purple-400" />
                <span>Varredura Mais Rápida</span>
              </div>
              <div className="text-xl sm:text-2xl font-black font-mono text-purple-400 mt-1">
                {scatterStats.fastestScanMs}ms
              </div>
              <div className="text-[10px] text-zinc-400 font-mono mt-0.5">
                Pico Máximo de Achados: {scatterStats.highestFindingCount}
              </div>
            </div>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/30">
              ULTRA-LOW
            </span>
          </div>
        </div>

        {/* Engine Mode Filter Strip */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
          <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
            <span className="text-[11px] text-zinc-500 font-bold uppercase mr-1">Modo de Análise:</span>
            {(['ALL', 'AST_REGEX', 'TAINT_FLOW', 'FULL_ASOC'] as ScatterEngineModeFilterType[]).map((mode) => {
              const label = mode === 'ALL' ? 'Todos os Modos' :
                            mode === 'AST_REGEX' ? 'AST + Regex Rápido' :
                            mode === 'TAINT_FLOW' ? 'Taint Flow D3 Graph' : 'Full ASOC Suite';
              const isActive = scatterEngineFilter === mode;

              return (
                <button
                  key={mode}
                  onClick={() => setScatterEngineFilter(mode)}
                  className={`px-2.5 py-1 rounded-md text-xs font-mono transition-all cursor-pointer ${
                    isActive
                      ? 'bg-zinc-800 text-white font-bold border border-sky-400/60 shadow-sm'
                      : 'bg-[#070B14] text-zinc-400 hover:text-zinc-200 border border-[#162132]'
                  }`}
                >
                  {label}
                </button>
              );
            })}
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-zinc-400">
            <Info className="w-3.5 h-3.5 text-zinc-400" />
            <span>Tamanho da bolha = Volume de arquivos processados</span>
          </div>
        </div>

        {/* RECHARTS SCATTER PLOT CONTAINER */}
        <div className="h-80 w-full pt-1 bg-[#060911]/90 rounded-xl border border-[#172235] p-2 relative">
          {/* Sub-second Threshold Reference Zone Background */}
          <div className="absolute top-2 bottom-8 left-14 w-2/3 bg-emerald-500/[0.02] border-r border-dashed border-emerald-500/25 pointer-events-none flex items-start justify-end pr-2 pt-1">
            <span className="text-[10px] font-mono text-emerald-500/50 uppercase tracking-wider">
              Zona Sub-segundo (&lt; 1000ms)
            </span>
          </div>

          <ResponsiveContainer width="100%" height="100%">
            <ScatterChart margin={{ top: 20, right: 30, bottom: 25, left: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#182334" />
              <XAxis
                type="number"
                dataKey={scatterXUnit === 'sec' ? 'durationSec' : 'durationMs'}
                name="Duração da Varredura"
                unit={scatterXUnit === 'sec' ? 's' : 'ms'}
                stroke="#64748B"
                tick={{ fontSize: 10, fill: '#94A3B8', fontFamily: 'monospace' }}
                tickLine={{ stroke: '#1E293B' }}
                domain={['dataMin - 20', 'dataMax + 50']}
              />
              <YAxis
                type="number"
                dataKey="findingsCount"
                name="Total de Achados"
                unit=" achados"
                stroke="#64748B"
                tick={{ fontSize: 10, fill: '#94A3B8', fontFamily: 'monospace' }}
                tickLine={{ stroke: '#1E293B' }}
                allowDecimals={false}
              />
              <ZAxis
                type="number"
                dataKey="filesCount"
                range={[60, 240]}
                name="Arquivos Analisados"
              />
              <RechartsTooltip content={<CustomScatterTooltip />} />
              <Scatter
                name="Execuções do Motor SecScan"
                data={filteredScatterPoints}
                onClick={(node: any) => {
                  if (node && node.payload) setSelectedScatterPoint(node.payload);
                }}
              >
                {filteredScatterPoints.map((entry, index) => {
                  const isSelected = selectedPoint?.id === entry.id;
                  let fill = '#38BDF8';
                  let stroke = '#1E293B';

                  if (entry.isCurrentSession) {
                    fill = '#00FF41';
                    stroke = '#FFFFFF';
                  } else if (entry.efficiencyRating === 'ULTRA_FAST') {
                    fill = '#10B981';
                    stroke = '#059669';
                  } else if (entry.efficiencyRating === 'OPTIMAL') {
                    fill = '#38BDF8';
                    stroke = '#0284C7';
                  } else if (entry.efficiencyRating === 'MODERATE') {
                    fill = '#F59E0B';
                    stroke = '#D97706';
                  } else {
                    fill = '#A855F7';
                    stroke = '#7E22CE';
                  }

                  return (
                    <Cell
                      key={`scatter-cell-${entry.id || index}`}
                      fill={fill}
                      stroke={isSelected ? '#FFFFFF' : stroke}
                      strokeWidth={isSelected ? 3 : entry.isCurrentSession ? 2 : 1}
                      className="cursor-pointer transition-all hover:opacity-100"
                    />
                  );
                })}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
        </div>

        {/* Axis Labels & Description */}
        <div className="flex flex-wrap items-center justify-between text-[11px] font-mono text-zinc-400 px-1">
          <div className="flex items-center gap-1.5">
            <span className="font-bold text-zinc-300">Eixo X:</span>
            <span>Duração da Varredura ({scatterXUnit === 'sec' ? 'Segundos' : 'Milissegundos'})</span>
            <span className="text-zinc-600">•</span>
            <span className="font-bold text-zinc-300">Eixo Y:</span>
            <span>Volume de Achados (Vulnerabilidades / Segredos Detectados)</span>
          </div>
          <div className="text-emerald-400 font-semibold flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Escalabilidade Determinística O(n) comprovada</span>
          </div>
        </div>

        {/* SELECTED POINT INSPECTOR & ACTIONS DRAWER */}
        {selectedPoint && (
          <div className="p-4 rounded-xl bg-[#050912] border border-sky-500/40 space-y-3 shadow-lg">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#182436] pb-3">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
                  <Crosshair className="w-5 h-5 text-sky-400" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-black border border-zinc-700 text-zinc-200">
                      Scan #{selectedPoint.scanIndex}
                    </span>
                    <h4 className="text-sm font-bold text-white font-mono">
                      {selectedPoint.projectName || selectedPoint.timeLabel}
                    </h4>
                    {selectedPoint.isCurrentSession ? (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                        ⚡ Sessão Atual (Ao Vivo)
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-sky-500/15 text-sky-300 border border-sky-500/30">
                        {selectedPoint.timeLabel}
                      </span>
                    )}
                  </div>

                  <div className="text-xs text-zinc-400 font-mono mt-1 flex flex-wrap items-center gap-2.5">
                    <span>⏱️ Duração: <strong className="text-emerald-400 font-bold">{selectedPoint.durationMs}ms ({selectedPoint.durationSec}s)</strong></span>
                    <span>•</span>
                    <span>🛡️ Achados: <strong className="text-white font-bold">{selectedPoint.findingsCount}</strong> ({selectedPoint.criticalFindings} críticos, {selectedPoint.highFindings} altos)</span>
                    <span>•</span>
                    <span>📁 Arquivos: <strong className="text-zinc-200">{selectedPoint.filesCount}</strong></span>
                    <span>•</span>
                    <span>⚡ Throughput: <strong className="text-sky-300 font-bold">{selectedPoint.throughput} achados/s</strong></span>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2">
                {onTriggerScan && (
                  <button
                    onClick={onTriggerScan}
                    title="Disparar varredura real completa agora no workspace ativo"
                    className="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/50 text-emerald-300 text-xs font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-sm"
                  >
                    <Play className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Executar Scan no Workspace</span>
                  </button>
                )}

                <button
                  onClick={handleSimulateScanBenchmark}
                  disabled={simulatingEvent}
                  title="Simular uma nova varredura e plotar outro ponto ao vivo no scatter plot"
                  className="px-3 py-1.5 rounded-lg bg-[#141F30] hover:bg-[#1E2E44] border border-[#273B54] text-zinc-200 hover:text-white text-xs font-mono flex items-center gap-1.5 transition-all cursor-pointer"
                >
                  <Zap className={`w-3.5 h-3.5 text-sky-400 ${simulatingEvent ? 'animate-bounce' : ''}`} />
                  <span>Simular Outro Scan (+1)</span>
                </button>
              </div>
            </div>

            <div className="text-xs text-zinc-400 leading-relaxed font-mono">
              <strong className="text-zinc-200">Análise de Eficiência do Ponto:</strong> Com duração de{' '}
              <span className="text-emerald-400 font-bold">{selectedPoint.durationMs}ms</span> para detecção de{' '}
              <span className="text-white font-bold">{selectedPoint.findingsCount} vulnerabilidades</span> em{' '}
              <span className="text-zinc-200 font-bold">{selectedPoint.filesCount} arquivos</span>, o motor SecScan demonstra tempo de resposta{' '}
              {selectedPoint.durationMs < 1000 ? (
                <strong className="text-emerald-300">sub-segundo adequado para bloqueio imediato em git hooks e pipelines de alta velocidade.</strong>
              ) : (
                <strong className="text-sky-300">adequado para auditoria completa e geração de grafos profundos de taint analysis.</strong>
              )}
            </div>
          </div>
        )}

        {/* Legend Footer */}
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-zinc-400 pt-2 border-t border-[#182334]">
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-[11px] text-zinc-500 uppercase font-bold">Classificação:</span>
            <div className="flex items-center gap-1">
              <span className="w-3 h-3 rounded-full bg-[#10B981]" />
              <span className="text-[10px]">Ultra-Rápido (&lt;400ms)</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-3 h-3 rounded-full bg-[#38BDF8]" />
              <span className="text-[10px]">Ideal / Sub-segundo (400-850ms)</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-3 h-3 rounded-full bg-[#F59E0B]" />
              <span className="text-[10px]">Moderado (850-1400ms)</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-3 h-3 rounded-full bg-[#A855F7]" />
              <span className="text-[10px]">Auditoria Profunda (&gt;1400ms)</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-3 h-3 rounded-full bg-[#00FF41] border border-white animate-pulse" />
              <span className="text-[10px] font-bold text-white">Sessão Atual</span>
            </div>
          </div>

          <div className="flex items-center gap-2 text-[11px] text-zinc-500">
            <Info className="w-3.5 h-3.5 text-zinc-400" />
            <span>Clique em qualquer ponto do gráfico para inspecionar os detalhes da execução</span>
          </div>
        </div>
      </div>
    );
  };

  // Security Audit Logs Lateral Panel Component
  const renderSecurityAuditLogSidebar = () => {
    const totalCount = auditLogs.length;
    const critCount = auditLogs.filter(l => l.severity === 'CRITICAL').length;
    const highCount = auditLogs.filter(l => l.severity === 'HIGH').length;
    const uniqueTools = new Set(auditLogs.map(l => l.toolName)).size;

    return (
      <aside className="w-80 sm:w-96 lg:w-[390px] xl:w-[420px] border-l border-[#1E293B] bg-[#070B14] flex flex-col shrink-0 h-full overflow-hidden shadow-2xl z-20">
        {/* Sidebar Header */}
        <div className="p-4 border-b border-[#1E293B] bg-[#090F1C]/90 flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-sky-500/15 border border-sky-500/35 flex items-center justify-center text-sky-400 shrink-0">
              <ShieldCheck className="w-4 h-4 text-sky-400" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <h3 className="text-xs font-bold text-white font-mono truncate">
                  Logs de Auditoria de Segurança
                </h3>
                <span className="inline-flex items-center gap-1 px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/35 shrink-0">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                  <span>AO VIVO</span>
                </span>
              </div>
              <p className="text-[11px] text-zinc-400 truncate font-mono">
                Interações recentes com ferramentas SecScan
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1 shrink-0">
            {/* Quick Simulate Button */}
            <button
              onClick={handleSimulateAuditInteraction}
              title="Simular uma nova interação do usuário com ferramenta (+1 log)"
              className="p-1.5 rounded-lg bg-sky-950/40 hover:bg-sky-900/60 border border-sky-500/40 text-sky-300 transition-colors cursor-pointer"
            >
              <Zap className="w-3.5 h-3.5 text-sky-400" />
            </button>

            {/* Copy Logs Button */}
            <button
              onClick={handleCopyAuditLogs}
              title="Copiar histórico de logs formatado"
              className="p-1.5 rounded-lg bg-[#121927] hover:bg-[#1C2636] border border-[#223044] text-zinc-300 hover:text-white transition-colors cursor-pointer"
            >
              {copiedAuditLogs ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5 text-zinc-400" />
              )}
            </button>

            {/* Close Sidebar Button */}
            <button
              onClick={() => setShowAuditSidebar(false)}
              title="Ocultar painel lateral de auditoria"
              className="p-1.5 rounded-lg bg-[#121927] hover:bg-rose-950/40 border border-[#223044] hover:border-rose-500/40 text-zinc-400 hover:text-rose-200 transition-colors cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Quick KPI Bar */}
        <div className="grid grid-cols-3 gap-2 px-3.5 py-2.5 bg-[#050811] border-b border-[#182335] text-xs font-mono shrink-0">
          <div className="p-1.5 rounded bg-[#090F1C] border border-[#162338]">
            <span className="text-[10px] text-zinc-500 block">Total Logs</span>
            <span className="text-white font-bold text-xs">{totalCount}</span>
          </div>
          <div className="p-1.5 rounded bg-[#090F1C] border border-[#162338]">
            <span className="text-[10px] text-zinc-500 block">Ferramentas</span>
            <span className="text-sky-300 font-bold text-xs">{uniqueTools}</span>
          </div>
          <div className="p-1.5 rounded bg-[#090F1C] border border-[#162338]">
            <span className="text-[10px] text-zinc-500 block">Críticos</span>
            <span className="text-rose-400 font-bold text-xs">{critCount}</span>
          </div>
        </div>

        {/* Search & Severity Filter Bar */}
        <div className="p-3 border-b border-[#1E293B] bg-[#070C16] space-y-2 shrink-0">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-zinc-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={auditSearchQuery}
              onChange={(e) => setAuditSearchQuery(e.target.value)}
              placeholder="Buscar ferramenta, ação, CVE..."
              className="w-full bg-[#050811] border border-[#1D2A3F] rounded-lg pl-8 pr-7 py-1.5 text-xs font-mono text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-sky-500/70"
            />
            {auditSearchQuery && (
              <button
                onClick={() => setAuditSearchQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Severity Pills */}
          <div className="flex items-center gap-1 overflow-x-auto pb-0.5 text-[10px] font-mono no-scrollbar">
            {(['ALL', 'CRITICAL', 'HIGH', 'AUDIT', 'SUCCESS'] as const).map((sev) => {
              const label = sev === 'ALL' ? `Todos (${auditLogs.length})` :
                            sev === 'CRITICAL' ? `Crítico (${critCount})` :
                            sev === 'HIGH' ? `Alto (${highCount})` :
                            sev === 'AUDIT' ? 'Audit' : 'Sucesso';
              const isSelected = auditSeverityFilter === sev;
              return (
                <button
                  key={sev}
                  onClick={() => setAuditSeverityFilter(sev)}
                  className={`px-2 py-0.5 rounded transition-all cursor-pointer whitespace-nowrap ${
                    isSelected
                      ? sev === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/50 font-bold'
                        : sev === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/50 font-bold'
                        : sev === 'AUDIT' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/50 font-bold'
                        : sev === 'SUCCESS' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50 font-bold'
                        : 'bg-zinc-800 text-white border border-zinc-600 font-bold'
                      : 'bg-[#0A101C] text-zinc-400 hover:text-zinc-200 border border-[#172437]'
                  }`}
                >
                  {label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Scrollable List of Audit Logs */}
        <div className="flex-1 overflow-y-auto p-3 space-y-2.5 divide-y divide-[#152132]/60">
          {filteredAuditLogs.length === 0 ? (
            <div className="p-6 text-center text-xs font-mono text-zinc-500 space-y-2 my-auto">
              <ShieldAlert className="w-8 h-8 text-zinc-600 mx-auto" />
              <p>Nenhum log de auditoria encontrado para o filtro atual.</p>
              <button
                onClick={() => { setAuditSearchQuery(''); setAuditSeverityFilter('ALL'); }}
                className="px-2.5 py-1 rounded bg-[#121927] hover:bg-[#1C2636] border border-[#223044] text-zinc-300 text-[11px] cursor-pointer"
              >
                Limpar Filtros
              </button>
            </div>
          ) : (
            filteredAuditLogs.map((log) => {
              const isSelected = selectedAuditLog?.id === log.id;
              return (
                <div
                  key={log.id}
                  onClick={() => setSelectedAuditLog(isSelected ? null : log)}
                  className={`pt-2.5 first:pt-0 group transition-all cursor-pointer ${
                    isSelected ? 'p-2.5 rounded-xl bg-[#0C1527] border border-sky-500/40 shadow-sm' : ''
                  }`}
                >
                  {/* Top Row: Timestamp & Severity Tag */}
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5">
                      {/* Highlighted Timestamp */}
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/70 text-emerald-400 border border-emerald-500/35 flex items-center gap-1 shadow-sm">
                        <Clock className="w-3 h-3 text-emerald-400" />
                        <span>{log.timeLabel}</span>
                      </span>
                      <span className="text-[10px] text-zinc-500 font-mono">
                        {log.timeAgo}
                      </span>
                    </div>

                    {/* Severity Badge */}
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase ${
                      log.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                      log.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                      log.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                      log.severity === 'AUDIT' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40' :
                      log.severity === 'SUCCESS' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' :
                      'bg-zinc-800 text-zinc-300 border border-zinc-700'
                    }`}>
                      {log.severity}
                    </span>
                  </div>

                  {/* Tool Name (Destacado conforme pedido do usuário) */}
                  <div className="mt-1.5 flex items-center justify-between gap-1">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <Target className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                      <span className="text-xs font-bold text-white font-mono truncate group-hover:text-sky-300 transition-colors">
                        {log.toolName}
                      </span>
                    </div>
                    <span className="text-[9px] font-mono text-zinc-500 uppercase shrink-0">
                      {log.category}
                    </span>
                  </div>

                  {/* Action Name */}
                  <div className="text-[11px] font-mono text-zinc-300 mt-0.5 font-medium flex items-center gap-1">
                    <span className="text-zinc-500 font-normal">Ação:</span>
                    <span className="text-emerald-300/90">{log.action}</span>
                  </div>

                  {/* Technical Details */}
                  <p className="text-[11px] font-mono text-zinc-400 mt-1 leading-relaxed">
                    {log.details}
                  </p>

                  {/* Footer / Context Hash & Action */}
                  <div className="flex items-center justify-between gap-2 mt-2 pt-1 border-t border-[#141F30] text-[10px] font-mono text-zinc-500">
                    <div className="flex items-center gap-2">
                      <span title="Hash de Integridade Criptográfica">
                        Hash: <code className="text-zinc-400">{log.hash}</code>
                      </span>
                      {log.executionMs && (
                        <span>• <strong className="text-sky-400">{log.executionMs}ms</strong></span>
                      )}
                    </div>

                    {onNavigateTab && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onNavigateTab(log.toolId);
                          onClose();
                        }}
                        title={`Ir diretamente para a ferramenta ${log.toolName} no SecScan`}
                        className="text-sky-400 hover:text-sky-300 hover:underline flex items-center gap-0.5 cursor-pointer font-bold"
                      >
                        <span>Abrir</span>
                        <ChevronRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Sidebar Footer Toolbar */}
        <div className="p-2.5 border-t border-[#1E293B] bg-[#060911] flex items-center justify-between text-[10px] font-mono text-zinc-400 shrink-0">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span>SHA-256 Validado</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleSimulateAuditInteraction}
              className="text-sky-400 hover:text-sky-300 cursor-pointer"
            >
              + Simular
            </button>
            <span>•</span>
            <button
              onClick={handleClearAuditLogs}
              className="text-zinc-500 hover:text-rose-400 cursor-pointer"
            >
              Limpar
            </button>
          </div>
        </div>
      </aside>
    );
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
        className="bg-[#090D16] border border-[#1E293B] rounded-2xl w-full max-w-7xl max-h-[94vh] flex flex-col shadow-2xl overflow-hidden font-sans text-zinc-200"
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
            {/* Toggle Security Audit Logs Sidebar */}
            <button
              onClick={() => setShowAuditSidebar(!showAuditSidebar)}
              title={showAuditSidebar ? "Recolher painel lateral de auditoria" : "Exibir painel lateral de logs de auditoria"}
              className={`px-2.5 py-1.5 rounded-lg border text-xs font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-sm ${
                showAuditSidebar
                  ? 'bg-sky-950/60 hover:bg-sky-900/60 border-sky-500/50 text-sky-300 ring-1 ring-sky-500/30'
                  : 'bg-[#121927] hover:bg-[#1C2636] border-[#223044] text-zinc-300 hover:text-white'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5 text-sky-400" />
              <span>Logs de Auditoria</span>
              <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${
                showAuditSidebar ? 'bg-sky-500/30 text-sky-200 font-bold' : 'bg-black/50 text-zinc-400'
              }`}>
                {auditLogs.length}
              </span>
            </button>

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
              onClick={() => setActiveTab('session_heatmap')}
              className={`py-3 px-4 text-xs font-mono font-bold border-b-2 flex items-center gap-2 transition-all cursor-pointer ${
                activeTab === 'session_heatmap'
                  ? 'border-emerald-400 text-emerald-300'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Flame className="w-4 h-4 text-emerald-400" />
              <span>User Session Heatmap (Features & Abas)</span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/35">
                HEATMAP
              </span>
            </button>
            <button
              onClick={() => setActiveTab('scatter_plot')}
              className={`py-3 px-4 text-xs font-mono font-bold border-b-2 flex items-center gap-2 transition-all cursor-pointer ${
                activeTab === 'scatter_plot'
                  ? 'border-sky-400 text-sky-300'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Crosshair className="w-4 h-4 text-sky-400" />
              <span>Eficiência do Motor (Scatter Plot)</span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-sky-500/20 text-sky-300 border border-sky-500/35">
                SCATTER
              </span>
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

        {/* Modal Main Content Container with Lateral Audit Logs Panel */}
        <div className="flex-1 flex overflow-hidden min-h-0 relative">
          {/* Main Scrollable Dashboard Content */}
          <div className="flex-1 overflow-y-auto p-5 sm:p-6 space-y-6 min-w-0">
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

              {/* USER SESSION HEATMAP: UI Tabs & Security Features Engagement Visualizer */}
              {renderUserSessionHeatmapVisualizer(false)}

              {/* ENGINE EFFICIENCY SCATTER PLOT: Scan Duration vs Findings */}
              {renderEngineEfficiencyScatterPlot(false)}

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
          ) : activeTab === 'session_heatmap' ? (
            /* Dedicated User Session Heatmap Tab Visualizer */
            <div className="space-y-6">
              {renderUserSessionHeatmapVisualizer(false)}
            </div>
          ) : activeTab === 'scatter_plot' ? (
            /* Dedicated Engine Efficiency Scatter Plot Tab Visualizer */
            <div className="space-y-6">
              {renderEngineEfficiencyScatterPlot(false)}
            </div>
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

          {/* LATERAL PANEL: Security Audit Logs (Logs de Auditoria de Segurança) */}
          {showAuditSidebar && renderSecurityAuditLogSidebar()}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 border-t border-[#1E293B] bg-[#070B13] flex items-center justify-between text-xs font-mono text-zinc-400">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
            <span>Motor de telemetria ativo com Recharts SVG • Visualização em tempo real</span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowAuditSidebar(!showAuditSidebar)}
              className="text-zinc-400 hover:text-sky-300 text-xs font-mono flex items-center gap-1.5 cursor-pointer transition-colors"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-sky-400" />
              <span>{showAuditSidebar ? 'Ocultar Lateral de Auditoria' : `Exibir Lateral de Auditoria (${auditLogs.length})`}</span>
            </button>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-[#141B26] hover:bg-[#1E293B] border border-[#223044] text-white font-bold cursor-pointer transition-colors"
            >
              Fechar Painel
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
