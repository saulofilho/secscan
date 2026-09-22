import React, { useState, useMemo, useEffect } from 'react';
import {
  ShieldAlert,
  Radio,
  Clock,
  Activity,
  AlertTriangle,
  CheckCircle2,
  Filter,
  Search,
  RefreshCw,
  TrendingDown,
  TrendingUp,
  FileText,
  Server,
  Layers,
  Terminal,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Zap,
  ArrowUpRight,
  Database,
  Lock,
  Route,
  ShieldCheck,
  Flame,
  Volume2,
  VolumeX,
  Play,
  RotateCcw
} from 'lucide-react';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend
} from 'recharts';
import {
  ScanReport,
  AuditLogEvent,
  SocCriticalAlert,
  SocTimeFilterRange,
  SeverityLevel
} from '../types';
import {
  extractSuiteCriticalAlerts,
  generateSocTrendSeries,
  calculateSocMetrics,
  isWithinTimeRange
} from '../lib/socCommandEngine';

interface SocCommandCenterViewProps {
  report: ScanReport;
  auditLogs: AuditLogEvent[];
  onNavigateToFile?: (filePath: string, line?: number) => void;
  onNavigateToScanner?: () => void;
  onNavigateToAsoc?: () => void;
  onNavigateToAuditLog?: () => void;
}

export const SocCommandCenterView: React.FC<SocCommandCenterViewProps> = ({
  report,
  auditLogs,
  onNavigateToFile,
  onNavigateToScanner,
  onNavigateToAsoc,
  onNavigateToAuditLog
}) => {
  // Time window filter: 1h, 6h, 24h, 7d, 30d, all
  const [timeRange, setTimeRange] = useState<SocTimeFilterRange>('24H');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH'>('ALL');
  const [sourceFilter, setSourceFilter] = useState<'ALL' | 'SAST' | 'SECRETS' | 'IaC' | 'API_SECURITY' | 'SCA' | 'EDR'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedAlert, setSelectedAlert] = useState<SocCriticalAlert | null>(null);
  const [isLiveStreaming, setIsLiveStreaming] = useState<boolean>(true);
  const [liveLogTick, setLiveLogTick] = useState<number>(0);

  // Auto stream / heartbeat simulation
  useEffect(() => {
    if (!isLiveStreaming) return;
    const interval = setInterval(() => {
      setLiveLogTick(prev => prev + 1);
    }, 4500);
    return () => clearInterval(interval);
  }, [isLiveStreaming]);

  // Extract all unified alerts from suite scanners
  const allAlerts = useMemo(() => {
    return extractSuiteCriticalAlerts(report, auditLogs);
  }, [report, auditLogs]);

  // Filter alerts by time range, severity, source and search
  const filteredAlerts = useMemo(() => {
    return allAlerts.filter(alert => {
      if (!isWithinTimeRange(alert.timestamp, timeRange)) return false;
      if (severityFilter !== 'ALL' && alert.severity !== severityFilter) return false;
      if (sourceFilter !== 'ALL' && alert.source !== sourceFilter) return false;
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesTitle = alert.title.toLowerCase().includes(query);
        const matchesResource = alert.targetResource.toLowerCase().includes(query);
        const matchesCwe = alert.cweOrMitre.toLowerCase().includes(query);
        const matchesDesc = alert.description.toLowerCase().includes(query);
        if (!matchesTitle && !matchesResource && !matchesCwe && !matchesDesc) return false;
      }
      return true;
    });
  }, [allAlerts, timeRange, severityFilter, sourceFilter, searchQuery]);

  // Filtered audit logs
  const filteredLogs = useMemo(() => {
    return auditLogs.filter(log => isWithinTimeRange(log.timestamp, timeRange));
  }, [auditLogs, timeRange]);

  // Trend series for charts
  const trendSeries = useMemo(() => {
    return generateSocTrendSeries(timeRange, filteredAlerts, filteredLogs.length);
  }, [timeRange, filteredAlerts, filteredLogs.length]);

  // Calculated high-level SOC metrics
  const metrics = useMemo(() => {
    return calculateSocMetrics(filteredAlerts, filteredLogs.length);
  }, [filteredAlerts, filteredLogs.length]);

  // Set default selected alert if none is selected
  useEffect(() => {
    if (!selectedAlert && filteredAlerts.length > 0) {
      setSelectedAlert(filteredAlerts[0]);
    }
  }, [filteredAlerts, selectedAlert]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#222] pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              <Radio className="w-5 h-5 animate-pulse" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-white uppercase font-mono">
                  SOC Command View &amp; Real-Time Operations
                </h1>
                <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-950/60 text-emerald-300 border border-emerald-700/50">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                  LIVE TELEMETRY
                </span>
              </div>
              <p className="text-xs text-zinc-400 font-mono mt-0.5">
                Consolidação unificada de logs de auditoria, curvas de MTTR, telemetria de ameaças e alertas críticos da suíte.
              </p>
            </div>
          </div>
        </div>

        {/* Time Window Controls & Live Stream Toggle */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Live Ingress Indicator */}
          <button
            onClick={() => setIsLiveStreaming(prev => !prev)}
            className={`px-3 py-1.5 rounded-lg border font-mono text-xs flex items-center gap-2 transition-all cursor-pointer ${
              isLiveStreaming 
                ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300 hover:bg-emerald-900/40' 
                : 'bg-zinc-900 border-zinc-800 text-zinc-400 hover:text-white'
            }`}
            title="Pausar / Retomar atualização contínua de telemetria"
          >
            <Activity className={`w-3.5 h-3.5 ${isLiveStreaming ? 'animate-spin text-emerald-400' : 'text-zinc-500'}`} />
            <span>{isLiveStreaming ? 'Streaming Ativo' : 'Stream Pausado'}</span>
          </button>

          {/* Time Filter Buttons */}
          <div className="flex items-center p-1 rounded-lg bg-[#0F0F0F] border border-[#262626] font-mono text-xs">
            {(['1H', '6H', '24H', '7D', '30D', 'ALL'] as SocTimeFilterRange[]).map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={`px-2.5 py-1 rounded-md transition-all cursor-pointer ${
                  timeRange === range
                    ? 'bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/40'
                    : 'text-zinc-400 hover:text-white'
                }`}
              >
                {range}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 font-mono">
        {/* Card 1: Critical Alerts */}
        <div className="p-3.5 rounded-xl bg-[#0C0C0C] border border-rose-900/40 relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-400 text-[10px] uppercase">
            <span>Alertas Críticos</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-rose-400">{metrics.criticalCount}</span>
            <span className="text-[10px] text-zinc-500">P0 ativos</span>
          </div>
          <span className="text-[10px] text-rose-300/80 block mt-1">
            {metrics.slaBreachRiskCount} com risco de breach
          </span>
        </div>

        {/* Card 2: High Alerts */}
        <div className="p-3.5 rounded-xl bg-[#0C0C0C] border border-amber-900/40 relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-400 text-[10px] uppercase">
            <span>Alertas Altos</span>
            <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-amber-400">{metrics.highCount}</span>
            <span className="text-[10px] text-zinc-500">P1 ativos</span>
          </div>
          <span className="text-[10px] text-amber-300/80 block mt-1">
            SLA alvo: ≤ 6h
          </span>
        </div>

        {/* Card 3: MTTR Hours */}
        <div className="p-3.5 rounded-xl bg-[#0C0C0C] border border-cyan-900/40 relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-400 text-[10px] uppercase">
            <span>Média MTTR</span>
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-cyan-400">{metrics.averageMttrHours}h</span>
            <span className="text-[10px] text-emerald-400 flex items-center">
              <TrendingDown className="w-3 h-3 inline mr-0.5" />
              18%
            </span>
          </div>
          <span className="text-[10px] text-zinc-400 block mt-1">
            Tempo Médio de Resolução
          </span>
        </div>

        {/* Card 4: Audit Logs */}
        <div className="p-3.5 rounded-xl bg-[#0C0C0C] border border-zinc-800 relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-400 text-[10px] uppercase">
            <span>Logs de Auditoria</span>
            <FileText className="w-3.5 h-3.5 text-indigo-400" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">{filteredLogs.length}</span>
            <span className="text-[10px] text-zinc-500">eventos</span>
          </div>
          <span className="text-[10px] text-zinc-400 block mt-1">
            Janela: {timeRange}
          </span>
        </div>

        {/* Card 5: Ingress Rate */}
        <div className="p-3.5 rounded-xl bg-[#0C0C0C] border border-zinc-800 relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-400 text-[10px] uppercase">
            <span>Ingress Rate</span>
            <Activity className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-emerald-400">142.6</span>
            <span className="text-[10px] text-zinc-500">ev/s</span>
          </div>
          <span className="text-[10px] text-zinc-400 block mt-1">
            Pipeline Assíncrono
          </span>
        </div>

        {/* Card 6: Health Index */}
        <div className="p-3.5 rounded-xl bg-[#0C0C0C] border border-emerald-900/40 relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-400 text-[10px] uppercase">
            <span>Health Index</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className={`text-2xl font-bold ${
              metrics.securityHealthIndex >= 80 ? 'text-emerald-400' : metrics.securityHealthIndex >= 50 ? 'text-amber-400' : 'text-rose-400'
            }`}>
              {metrics.securityHealthIndex}%
            </span>
            <span className="text-[10px] text-zinc-500">score</span>
          </div>
          <span className="text-[10px] text-zinc-400 block mt-1">
            Postura Operacional
          </span>
        </div>
      </div>

      {/* Charts Grid: Real-time MTTR Trend & Incident Ingestion */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chart 1: MTTR Trend Evolution */}
        <div className="p-5 rounded-2xl bg-[#0A0A0A] border border-[#222] space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-bold text-white font-mono uppercase">
                  Tendência de MTTR (Mean Time to Remediate)
                </h2>
              </div>
              <p className="text-xs text-zinc-400 font-mono mt-0.5">
                Curva de tempo médio em horas para fechamento de incidentes ao longo do tempo ({timeRange}).
              </p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/60">
              Meta SLA: ≤ 2.0h
            </span>
          </div>

          <div className="h-60 w-full font-mono">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trendSeries} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#222" />
                <XAxis dataKey="label" stroke="#666" tick={{ fontSize: 11 }} />
                <YAxis stroke="#666" tick={{ fontSize: 11 }} domain={[0, 5]} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111', borderColor: '#333', fontSize: '11px', fontFamily: 'monospace' }}
                  labelStyle={{ color: '#fff', fontWeight: 'bold' }}
                />
                <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                <Line
                  type="monotone"
                  dataKey="mttrCurrentHours"
                  name="MTTR Real (Horas)"
                  stroke="#22d3ee"
                  strokeWidth={2.5}
                  dot={{ r: 3, fill: '#22d3ee' }}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 2: Incident Volume & Ingestion */}
        <div className="p-5 rounded-2xl bg-[#0A0A0A] border border-[#222] space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <h2 className="text-sm font-bold text-white font-mono uppercase">
                  Ingress de Incidentes &amp; Eventos de Auditoria
                </h2>
              </div>
              <p className="text-xs text-zinc-400 font-mono mt-0.5">
                Volume de alertas críticos e eventos processados pelo pipeline do workspace.
              </p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-800/60">
              P0 / P1 / Logs
            </span>
          </div>

          <div className="h-60 w-full font-mono">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendSeries} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="auditGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#34d399" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#34d399" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#222" />
                <XAxis dataKey="label" stroke="#666" tick={{ fontSize: 11 }} />
                <YAxis stroke="#666" tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111', borderColor: '#333', fontSize: '11px', fontFamily: 'monospace' }}
                  labelStyle={{ color: '#fff', fontWeight: 'bold' }}
                />
                <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                <Area
                  type="monotone"
                  dataKey="criticalAlerts"
                  name="Alertas Críticos (P0)"
                  stroke="#f43f5e"
                  fillOpacity={1}
                  fill="url(#critGrad)"
                />
                <Area
                  type="monotone"
                  dataKey="highAlerts"
                  name="Alertas Altos (P1)"
                  stroke="#fbbf24"
                  fillOpacity={0.2}
                  fill="#fbbf24"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Main Operations Split: Live Audit Log Stream (Left) vs. Critical Alerts Console (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Live Audit Logs Terminal Stream (5 cols) */}
        <div className="lg:col-span-5 p-5 rounded-2xl bg-[#0A0A0A] border border-[#222] space-y-4">
          <div className="flex items-center justify-between border-b border-[#222] pb-3">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <h2 className="text-sm font-bold text-white font-mono uppercase">
                Audit Log Stream em Tempo Real
              </h2>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-zinc-400">
                {filteredLogs.length} eventos
              </span>
              {onNavigateToAuditLog && (
                <button
                  onClick={onNavigateToAuditLog}
                  className="p-1 rounded text-zinc-400 hover:text-white hover:bg-[#222] transition-colors"
                  title="Abrir auditoria detalhada"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Terminal Console Logs */}
          <div className="h-[440px] overflow-y-auto rounded-xl bg-black border border-white/10 p-3 font-mono text-xs space-y-2 select-text">
            {filteredLogs.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-zinc-600 space-y-2">
                <Terminal className="w-6 h-6" />
                <span>Nenhum log gravado na janela temporal {timeRange}.</span>
              </div>
            ) : (
              filteredLogs.map((log) => {
                const isCrit = log.severity === 'CRITICAL' || log.type === 'ALERT_TRIGGERED';
                const isWarn = log.severity === 'HIGH';
                return (
                  <div
                    key={log.id}
                    className={`p-2 rounded border text-[11px] leading-relaxed transition-all ${
                      isCrit 
                        ? 'bg-rose-950/20 border-rose-900/40 text-rose-300' 
                        : isWarn
                        ? 'bg-amber-950/20 border-amber-900/40 text-amber-300'
                        : 'bg-[#0F0F0F] border-white/5 text-zinc-300 hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px] text-zinc-500 mb-1">
                      <span className="text-zinc-400 font-bold">[{log.timestamp}]</span>
                      <span className={`px-1.5 py-0.2 rounded font-semibold ${
                        isCrit ? 'bg-rose-950 text-rose-400' : isWarn ? 'bg-amber-950 text-amber-400' : 'bg-zinc-800 text-zinc-400'
                      }`}>
                        {log.type}
                      </span>
                    </div>
                    <p className="break-words">{log.message}</p>
                    {log.details && (
                      <div className="mt-1 text-[10px] text-zinc-500 truncate">
                        {JSON.stringify(log.details)}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Consolidated Critical Alerts Console (7 cols) */}
        <div className="lg:col-span-7 p-5 rounded-2xl bg-[#0A0A0A] border border-[#222] space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#222] pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <h2 className="text-sm font-bold text-white font-mono uppercase">
                Central de Alertas Críticos da Suíte
              </h2>
            </div>
            
            {/* Quick Filters */}
            <div className="flex items-center gap-2">
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value as any)}
                className="bg-[#111] border border-white/15 rounded-lg px-2.5 py-1 text-xs font-mono text-zinc-300 focus:outline-none"
              >
                <option value="ALL">Todas Fontes (SAST/IaC/API/SCA)</option>
                <option value="SAST">SAST Code</option>
                <option value="SECRETS">Hardcoded Secrets</option>
                <option value="IaC">IaC &amp; Cloud</option>
                <option value="API_SECURITY">OWASP API</option>
                <option value="SCA">SCA &amp; CVEs</option>
              </select>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as any)}
                className="bg-[#111] border border-white/15 rounded-lg px-2.5 py-1 text-xs font-mono text-zinc-300 focus:outline-none"
              >
                <option value="ALL">Severidades (P0/P1)</option>
                <option value="CRITICAL">Apenas CRITICAL (P0)</option>
                <option value="HIGH">Apenas HIGH (P1)</option>
              </select>
            </div>
          </div>

          {/* Search bar inside alerts */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-zinc-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filtrar por recurso, título, regra ou CWE..."
              className="w-full bg-[#111] border border-white/10 rounded-lg pl-8 pr-3 py-1.5 text-xs font-mono text-white placeholder:text-zinc-600 focus:outline-none focus:border-emerald-500/50"
            />
          </div>

          {/* Alerts List */}
          <div className="h-[380px] overflow-y-auto space-y-2.5 pr-1 font-mono">
            {filteredAlerts.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-zinc-500 py-12 text-xs space-y-2">
                <CheckCircle2 className="w-8 h-8 text-emerald-500/50" />
                <span>Nenhum alerta crítico pendente nesta janela temporal.</span>
              </div>
            ) : (
              filteredAlerts.map((alert) => {
                const isSelected = selectedAlert?.id === alert.id;
                const isBreached = alert.elapsedHours > alert.mttrTargetHours;
                return (
                  <div
                    key={alert.id}
                    onClick={() => setSelectedAlert(alert)}
                    className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-[#181818] border-emerald-500 shadow-md'
                        : 'bg-[#0E0E0E] border-[#222] hover:border-[#333]'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            alert.severity === 'CRITICAL' 
                              ? 'bg-rose-950 text-rose-400 border border-rose-800/60' 
                              : 'bg-amber-950 text-amber-400 border border-amber-800/60'
                          }`}>
                            {alert.severity}
                          </span>
                          <span className="px-2 py-0.5 rounded text-[10px] bg-zinc-800 text-zinc-300 border border-zinc-700">
                            {alert.source}
                          </span>
                          <span className="text-[10px] text-zinc-500">
                            {alert.cweOrMitre}
                          </span>
                        </div>
                        <h3 className="text-xs font-bold text-white mt-1">
                          {alert.title}
                        </h3>
                        <p className="text-[11px] text-zinc-400 mt-0.5 line-clamp-1">
                          {alert.description}
                        </p>
                      </div>

                      {/* Elapsed vs MTTR target */}
                      <div className="text-right shrink-0">
                        <span className={`text-xs font-bold block ${isBreached ? 'text-rose-400' : 'text-emerald-400'}`}>
                          {alert.elapsedHours}h decorridas
                        </span>
                        <span className="text-[10px] text-zinc-500 block">
                          SLA Máx: {alert.mttrTargetHours}h
                        </span>
                      </div>
                    </div>

                    <div className="mt-2 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] text-zinc-400">
                      <span className="truncate max-w-[280px] text-zinc-300">
                        Alvo: {alert.targetResource}
                      </span>
                      {onNavigateToFile && alert.targetResource.includes(':') && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            const parts = alert.targetResource.split(':');
                            onNavigateToFile(parts[0], parseInt(parts[1], 10) || 1);
                          }}
                          className="text-emerald-400 hover:text-emerald-300 flex items-center gap-1 cursor-pointer"
                        >
                          <span>Ver no código</span>
                          <ChevronRight className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Selected Alert Quick-Remediation Drawer / Modal Details */}
      {selectedAlert && (
        <div className="p-5 rounded-2xl bg-[#0F0F0F] border border-[#262626] font-mono space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#222] pb-3">
            <div className="flex items-center gap-2.5">
              <span className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <Sparkles className="w-4 h-4" />
              </span>
              <div>
                <h3 className="text-sm font-bold text-white">
                  Diagnóstico e Plano de Remediação: {selectedAlert.title}
                </h3>
                <span className="text-[11px] text-zinc-400">
                  Recurso Afetado: {selectedAlert.targetResource} • Classificação: {selectedAlert.cweOrMitre}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {onNavigateToAsoc && (
                <button
                  onClick={onNavigateToAsoc}
                  className="px-3 py-1.5 rounded-lg bg-purple-950/40 text-purple-300 border border-purple-800/60 hover:bg-purple-900/40 text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Clock className="w-3.5 h-3.5" />
                  <span>Gerenciar no ASOC</span>
                </button>
              )}
              {onNavigateToScanner && (
                <button
                  onClick={onNavigateToScanner}
                  className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-black text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <span>Inspecionar no Scanner</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="p-3.5 rounded-xl bg-black border border-white/10 space-y-2">
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider block font-bold">
                Recomendação de Mitigação Imediata
              </span>
              <p className="text-zinc-300 leading-relaxed">
                {selectedAlert.remediationAdvice}
              </p>
            </div>

            <div className="p-3.5 rounded-xl bg-black border border-white/10 space-y-2">
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider block font-bold">
                Métricas Operacionais de Resposta
              </span>
              <div className="grid grid-cols-2 gap-2 text-zinc-300">
                <div>
                  <span className="text-[10px] text-zinc-500 block">Tempo Decorrido</span>
                  <strong className="text-white text-sm">{selectedAlert.elapsedHours} horas</strong>
                </div>
                <div>
                  <span className="text-[10px] text-zinc-500 block">Target SLA Corporativo</span>
                  <strong className="text-emerald-400 text-sm">≤ {selectedAlert.mttrTargetHours} horas</strong>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
