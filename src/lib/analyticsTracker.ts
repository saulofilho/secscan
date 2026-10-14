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
    if (!res.ok) throw new Error('Falha ao obter métricas de telemetria');
    const data = await res.json();
    return data;
  } catch (err) {
    console.warn('Erro ao carregar resumo de analytics:', err);
    return null;
  }
}
