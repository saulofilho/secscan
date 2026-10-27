// SecScan Privacy-Friendly Web Analytics & Visitor Telemetry Tracker

export interface AnalyticsTimelinePoint {
  timeLabel: string;
  views: number;
  visitors: number;
  activeRate?: number;
}

export interface HeatmapCellDetail {
  dayIndex: number; // 0 = Domingo, 1 = Segunda, ..., 6 = Sábado
  dayName: string; // 'Domingo', 'Segunda-feira', etc.
  dayShort: string; // 'Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'
  hour: number; // 0..23
  hourLabel: string; // '00h', '01h', ..., '23h'
  views: number;
  visitors: number;
  intensityLevel: number; // 0 (sem acessos), 1 (baixo), 2 (médio), 3 (alto), 4 (pico máximo)
  intensityPct: number; // 0 .. 100%
  topTab?: string;
}

export interface WeeklyHeatmapData {
  days: string[];
  hours: number[];
  grid: HeatmapCellDetail[][]; // 7 days (rows) x 24 hours (columns)
  maxCellViews: number;
  totalWeekViews: number;
  totalWeekVisitors: number;
  peakCell: {
    dayIndex: number;
    dayName: string;
    dayShort: string;
    hour: number;
    hourLabel: string;
    views: number;
    visitors: number;
  };
  peakDay: {
    dayName: string;
    dayShort: string;
    totalViews: number;
    percentage: number;
  };
  peakHourWindow: {
    label: string;
    totalViews: number;
  };
  quietestHourWindow: {
    label: string;
    totalViews: number;
  };
  busiestPeriodOfDay: {
    period: string; // e.g., 'Tarde (12h - 18h)'
    views: number;
    percentage: number;
  };
}

export interface SessionTabEngagement {
  tabId: string;
  name: string;
  category: 'CODE_SAST' | 'CLOUD_INFRA' | 'API_DAST' | 'SOC_EDR' | 'GOV_AI';
  dwellSeconds: number;
  formattedDuration: string;
  interactionCount: number;
  sessionEngagementScore: number;
  adoptionRate: number;
  heatLevel: 0 | 1 | 2 | 3 | 4;
  rank: number;
  isHotspot: boolean;
}

export interface UserSessionHeatmapData {
  tabs: SessionTabEngagement[];
  topEngagedFeature: {
    tabId: string;
    name: string;
    category: string;
    formattedDuration: string;
    interactions: number;
    score: number;
  };
  mostFrequentStartingTab: string;
  mostFrequentExitTab: string;
  avgTabsExploredPerSession: number;
  sessionFunnelStages: {
    stage: string;
    name: string;
    description: string;
    avgTimeSeconds: number;
    formattedTime: string;
    dropoffPercent: number;
    retentionPercent: number;
    primaryTabs: string[];
    heatIntensity: number;
  }[];
  categoryDistribution: {
    category: 'CODE_SAST' | 'CLOUD_INFRA' | 'API_DAST' | 'SOC_EDR' | 'GOV_AI';
    label: string;
    dwellSeconds: number;
    percentage: number;
    tabCount: number;
    color: string;
  }[];
}

export interface SessionMetrics {
  averageDurationSeconds: number;
  formattedAverageDuration: string;
  totalSessionsCount: number;
  retentionRatePercent: number;
  engagedSessionsCount: number;
}

export interface ScanEfficiencyDataPoint {
  id: string;
  scanIndex: number;
  timestamp: number;
  timeLabel: string;
  durationMs: number;
  durationSec: number;
  findingsCount: number;
  filesCount: number;
  linesOfCode?: number;
  throughput: number; // findings / second
  efficiencyRating: 'ULTRA_FAST' | 'OPTIMAL' | 'MODERATE' | 'DEEP_AUDIT';
  engineMode: 'AST_REGEX' | 'TAINT_FLOW' | 'FULL_ASOC';
  isCurrentSession?: boolean;
  projectName?: string;
  criticalFindings: number;
  highFindings: number;
}

export interface ScanEfficiencySummary {
  dataPoints: ScanEfficiencyDataPoint[];
  avgDurationMs: number;
  avgDurationFormatted: string;
  avgFindingsCount: number;
  avgThroughput: number;
  totalScansEvaluated: number;
  subSecondPercent: number;
  correlationLabel: string;
  fastestScanMs: number;
  highestFindingCount: number;
}

export interface AnalyticsSummary {
  activeVisitorsNow: number;
  totalPageViews: number;
  uniqueVisitorsToday: number;
  uniqueVisitorsTotal: number;
  topPages: { name: string; count: number; percentage: number }[];
  topReferrers: { source: string; count: number; percentage: number }[];
  deviceBreakdown: { type: string; count: number; percentage: number }[];
  browserBreakdown: { name: string; count: number; percentage: number }[];
  osBreakdown: { name: string; count: number; percentage: number }[];
  geoBreakdown: { country: string; flag: string; count: number; percentage: number }[];
  timeline: AnalyticsTimelinePoint[];
  realtimeMinutes?: AnalyticsTimelinePoint[];
  dailyTrend?: AnalyticsTimelinePoint[];
  weeklyHeatmap?: WeeklyHeatmapData;
  sessionMetrics?: SessionMetrics;
  userSessionHeatmap?: UserSessionHeatmapData;
  scanEfficiency?: ScanEfficiencySummary;
  recentEvents: {
    id: string;
    timestamp: number;
    timeAgo: string;
    type: string;
    path: string;
    tab?: string;
    browser: string;
    os: string;
    device: string;
    country: string;
    referrer: string;
  }[];
  securityAuditLogs?: SecurityAuditLogItem[];
}

export interface SecurityAuditLogItem {
  id: string;
  timestamp: number;
  timeLabel: string;
  timeAgo: string;
  toolId: string;
  toolName: string;
  action: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'SUCCESS' | 'AUDIT';
  category: 'CODE_SAST' | 'CLOUD_INFRA' | 'API_DAST' | 'SOC_EDR' | 'GOV_AI' | 'CORE_ENGINE';
  details: string;
  user: string;
  hash: string;
  executionMs?: number;
  findingsCount?: number;
  metadata?: Record<string, any>;
}

const VISITOR_ID_KEY = 'secscan_anonymous_vid';
const SESSION_START_KEY = 'secscan_user_session_start_ts';

export function getOrCreateSessionStartTime(): number {
  if (typeof window === 'undefined') return Date.now();
  let val = sessionStorage.getItem(SESSION_START_KEY);
  if (!val) {
    val = Date.now().toString();
    try {
      sessionStorage.setItem(SESSION_START_KEY, val);
    } catch {
      // safe fallback
    }
  }
  return parseInt(val, 10) || Date.now();
}

export function resetUserSessionStartTime(): number {
  const now = Date.now();
  if (typeof window !== 'undefined') {
    try {
      sessionStorage.setItem(SESSION_START_KEY, now.toString());
    } catch {}
  }
  return now;
}

export function getCurrentSessionDurationSeconds(): number {
  const start = getOrCreateSessionStartTime();
  return Math.max(0, Math.floor((Date.now() - start) / 1000));
}

export function formatDurationSeconds(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) {
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  }
  return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
}

export function formatDurationHuman(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) {
    return `${h}h ${m}m ${s}s`;
  }
  return `${m}m ${s.toString().padStart(2, '0')}s`;
}

const SESSION_TAB_TRACK_KEY = 'secscan_session_tab_dwell';

export interface LocalTabRecord {
  tabId: string;
  dwellSeconds: number;
  interactions: number;
  lastVisited: number;
}

export function getLocalSessionTabEngagement(): Record<string, LocalTabRecord> {
  if (typeof window === 'undefined') return {};
  try {
    const raw = sessionStorage.getItem(SESSION_TAB_TRACK_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

export function recordLocalTabSessionActivity(tabId: string, addSeconds: number = 0, addInteraction: boolean = false): void {
  if (typeof window === 'undefined' || !tabId) return;
  try {
    const data = getLocalSessionTabEngagement();
    const current = data[tabId] || { tabId, dwellSeconds: 0, interactions: 0, lastVisited: Date.now() };
    current.dwellSeconds += addSeconds;
    if (addInteraction) {
      current.interactions += 1;
    }
    current.lastVisited = Date.now();
    data[tabId] = current;
    sessionStorage.setItem(SESSION_TAB_TRACK_KEY, JSON.stringify(data));
  } catch {
    // Fail silently
  }
}

export function resetLocalTabSessionEngagement(): void {
  if (typeof window !== 'undefined') {
    try {
      sessionStorage.removeItem(SESSION_TAB_TRACK_KEY);
    } catch {}
  }
}

export function getOrCreateVisitorId(): string {
  if (typeof window === 'undefined') return 'server_ssr';
  let vid = localStorage.getItem(VISITOR_ID_KEY);
  if (!vid) {
    vid = 'vid_' + Math.random().toString(36).substring(2, 11) + '_' + Date.now().toString(36);
    try {
      localStorage.setItem(VISITOR_ID_KEY, vid);
    } catch {
      // safe fallback for restricted storage
    }
  }
  return vid;
}

export async function sendAnalyticsEvent(payload: {
  type: 'pageview' | 'tab_view' | 'scan_action' | 'share_click';
  path?: string;
  tab?: string;
  metadata?: Record<string, any>;
}): Promise<void> {
  if (typeof window === 'undefined') return;

  try {
    const visitorId = getOrCreateVisitorId();
    const referrer = document.referrer || 'Direct / Bookmark';
    const screen = `${window.screen?.width || 0}x${window.screen?.height || 0}`;
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    const locale = navigator.language || 'pt-BR';

    await fetch('/api/analytics/track', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        visitorId,
        type: payload.type,
        path: payload.path || window.location.pathname,
        tab: payload.tab,
        referrer,
        screen,
        timezone,
        locale,
        metadata: payload.metadata,
      }),
    });
  } catch {
    // Fail silently to never interrupt user experience
  }
}

export async function fetchAnalyticsSummary(): Promise<AnalyticsSummary | null> {
  try {
    const res = await fetch('/api/analytics/summary');
    const contentType = res.headers.get('content-type') || '';
    if (!res.ok || !contentType.includes('application/json')) return null;
    return await res.json();
  } catch {
    return null;
  }
}
// -------------------------------------------------------------
// Security Tool Audit Logs Telemetry & Persistence
// -------------------------------------------------------------
export const SECURITY_AUDIT_LOGS_KEY = 'secscan_security_audit_logs';

export function generateSeedSecurityAuditLogs(): SecurityAuditLogItem[] {
  const now = Date.now();
  const formatTime = (offsetMs: number) => {
    const d = new Date(now - offsetMs);
    return d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };
  const formatTimeAgo = (seconds: number) => {
    if (seconds < 60) return `Há ${seconds}s`;
    const m = Math.floor(seconds / 60);
    return `Há ${m}m`;
  };

  return [
    {
      id: 'audit_init_01',
      timestamp: now - 18 * 1000,
      timeLabel: formatTime(18 * 1000),
      timeAgo: formatTimeAgo(18),
      toolId: 'sast_scanner',
      toolName: 'Scanner SAST & AST',
      action: 'Varredura de Código Executada',
      severity: 'HIGH',
      category: 'CODE_SAST',
      details: '14 vulnerabilidades detectadas em 18 arquivos (3 Altas CWE-89, CWE-79)',
      user: 'Operador SecScan (Sessão Atual)',
      hash: '0x8f2a1b9c',
      executionMs: 280,
      findingsCount: 14,
    },
    {
      id: 'audit_init_02',
      timestamp: now - 45 * 1000,
      timeLabel: formatTime(45 * 1000),
      timeAgo: formatTimeAgo(45),
      toolId: 'threat_matrix',
      toolName: 'Threat Modeling & Matrix STRIDE',
      action: 'Inspeção de Vetores de Ataque',
      severity: 'CRITICAL',
      category: 'SOC_EDR',
      details: 'Vetor Elevation of Privilege avaliado com risco CVSS 9.2 em rotas /api/admin',
      user: 'Operador SecScan (Sessão Atual)',
      hash: '0x3c7d4e11',
      findingsCount: 3,
    },
    {
      id: 'audit_init_03',
      timestamp: now - 92 * 1000,
      timeLabel: formatTime(92 * 1000),
      timeAgo: formatTimeAgo(92),
      toolId: 'secrets_scanner',
      toolName: 'Detector de Credenciais & Segredos',
      action: 'Análise Heurística de Entropia',
      severity: 'CRITICAL',
      category: 'CODE_SAST',
      details: '1 chave de API de alta entropia identificada no código-fonte',
      user: 'Operador SecScan (Sessão Atual)',
      hash: '0xa19f55b2',
      executionMs: 145,
      findingsCount: 1,
    },
    {
      id: 'audit_init_04',
      timestamp: now - 140 * 1000,
      timeLabel: formatTime(140 * 1000),
      timeAgo: formatTimeAgo(140),
      toolId: 'soc_command',
      toolName: 'SOC Command Center',
      action: 'Verificação de Integridade de Regras',
      severity: 'SUCCESS',
      category: 'SOC_EDR',
      details: 'Regras de bloqueio WAF e assinaturas ASOC sincronizadas com sucesso',
      user: 'Operador SecScan (Sessão Atual)',
      hash: '0x7e22bc40',
      executionMs: 90,
    },
    {
      id: 'audit_init_05',
      timestamp: now - 210 * 1000,
      timeLabel: formatTime(210 * 1000),
      timeAgo: formatTimeAgo(210),
      toolId: 'ast_explorer',
      toolName: 'AST Syntax Tree Explorer',
      action: 'Parsing de Árvore Sintática',
      severity: 'AUDIT',
      category: 'CODE_SAST',
      details: 'Grafo AST de TypeScript/JavaScript compilado e mapeado para nós CallExpression',
      user: 'Operador SecScan (Sessão Atual)',
      hash: '0x99a0b12e',
      executionMs: 310,
    },
    {
      id: 'audit_init_06',
      timestamp: now - 290 * 1000,
      timeLabel: formatTime(290 * 1000),
      timeAgo: formatTimeAgo(290),
      toolId: 'remediation_ai',
      toolName: 'Assistente de Remediação com IA',
      action: 'Geração de Patch Seguro',
      severity: 'SUCCESS',
      category: 'GOV_AI',
      details: 'Patch parametrizado gerado para neutralizar injeção de comandos CWE-78',
      user: 'Operador SecScan (Sessão Atual)',
      hash: '0x5b3318dc',
      executionMs: 620,
    },
    {
      id: 'audit_init_07',
      timestamp: now - 360 * 1000,
      timeLabel: formatTime(360 * 1000),
      timeAgo: formatTimeAgo(360),
      toolId: 'cicd_gate',
      toolName: 'CI/CD Security Gate',
      action: 'Avaliação de Política de Deploy',
      severity: 'HIGH',
      category: 'CORE_ENGINE',
      details: 'Pipeline bloqueado preventivamente: threshold de severidade alta atingido (Score: 68/100)',
      user: 'Operador SecScan (Sessão Atual)',
      hash: '0x10f3c5aa',
    },
    {
      id: 'audit_init_08',
      timestamp: now - 480 * 1000,
      timeLabel: formatTime(480 * 1000),
      timeAgo: formatTimeAgo(480),
      toolId: 'dast_fuzzer',
      toolName: 'DAST & API Fuzzer',
      action: 'Sonda Dinâmica de Headers',
      severity: 'MEDIUM',
      category: 'API_DAST',
      details: 'Cabeçalhos HSTS e Content-Security-Policy auditados com ausência de diretiva estrita',
      user: 'Operador SecScan (Sessão Atual)',
      hash: '0x4e6b7719',
      executionMs: 410,
    },
  ];
}

export function getLocalSecurityAuditLogs(): SecurityAuditLogItem[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = sessionStorage.getItem(SECURITY_AUDIT_LOGS_KEY);
    if (!raw) {
      const initial = generateSeedSecurityAuditLogs();
      sessionStorage.setItem(SECURITY_AUDIT_LOGS_KEY, JSON.stringify(initial));
      return initial;
    }
    return JSON.parse(raw);
  } catch {
    return generateSeedSecurityAuditLogs();
  }
}

export function recordSecurityAuditLog(entry: {
  toolId: string;
  toolName: string;
  action: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'SUCCESS' | 'AUDIT';
  category?: 'CODE_SAST' | 'CLOUD_INFRA' | 'API_DAST' | 'SOC_EDR' | 'GOV_AI' | 'CORE_ENGINE';
  details: string;
  executionMs?: number;
  findingsCount?: number;
  metadata?: Record<string, any>;
}): SecurityAuditLogItem {
  const now = Date.now();
  const d = new Date(now);
  const timeLabel = d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const hash = Math.random().toString(16).substring(2, 10);

  const logItem: SecurityAuditLogItem = {
    id: `audit_${now}_${Math.random().toString(36).substring(2, 6)}`,
    timestamp: now,
    timeLabel,
    timeAgo: 'Agora',
    toolId: entry.toolId,
    toolName: entry.toolName,
    action: entry.action,
    severity: entry.severity,
    category: entry.category || 'CORE_ENGINE',
    details: entry.details,
    user: 'Operador SecScan (Sessão Atual)',
    hash: `0x${hash}`,
    executionMs: entry.executionMs,
    findingsCount: entry.findingsCount,
    metadata: entry.metadata,
  };

  if (typeof window !== 'undefined') {
    try {
      const existing = getLocalSecurityAuditLogs();
      const updated = [logItem, ...existing.filter(i => i.id !== logItem.id).slice(0, 49)];
      sessionStorage.setItem(SECURITY_AUDIT_LOGS_KEY, JSON.stringify(updated));
      window.dispatchEvent(new CustomEvent('secscan-audit-log-added', { detail: logItem }));
    } catch {
      // safe fallback
    }
  }

  return logItem;
}

export function clearLocalSecurityAuditLogs(): void {
  if (typeof window !== 'undefined') {
    try {
      sessionStorage.removeItem(SECURITY_AUDIT_LOGS_KEY);
      window.dispatchEvent(new CustomEvent('secscan-audit-log-cleared'));
    } catch {}
  }
}
