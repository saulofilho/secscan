/**
 * DAST Recurring Scan Scheduler Engine
 * Orchestrates periodic and automated dynamic security fuzzing against target endpoints
 * with configurable time intervals, cron expressions, payload profiles, and alerting.
 */

import { AttackCategory, FuzzingPayload, FuzzingTestResult, BUILTIN_FUZZING_PAYLOADS, simulateFuzzingTest } from './dastSimulator';

export type ScheduleIntervalPreset = '5m' | '15m' | '30m' | '1h' | '6h' | '12h' | '24h' | 'CRON';

export interface RecurringScanSchedule {
  id: string;
  name: string;
  enabled: boolean;
  targetEndpoints: string[];
  httpMethods: ('GET' | 'POST' | 'PUT' | 'DELETE')[];
  attackCategories: AttackCategory[];
  intervalPreset: ScheduleIntervalPreset;
  intervalMinutes: number;
  cronExpression?: string;
  intervalLabel: string;
  createdAt: string;
  lastRunAt?: string;
  nextRunAt: string; // ISO string
  totalRuns: number;
  vulnerabilitiesDetected: number;
  stopOnCriticalVuln: boolean;
  alertChannels: ('IN_APP' | 'SLACK_WEBHOOK' | 'EMAIL_ALERT' | 'SOAR_PLAYBOOK')[];
  status: 'IDLE' | 'RUNNING' | 'PAUSED' | 'FAILED' | 'COMPLETED';
}

export interface ScheduledScanExecutionRecord {
  id: string;
  scheduleId: string;
  scheduleName: string;
  timestamp: string;
  durationMs: number;
  endpointsTestedCount: number;
  payloadsSentCount: number;
  vulnerabilitiesFound: number;
  blockedByWafCount: number;
  safeCount: number;
  results: FuzzingTestResult[];
  status: 'SUCCESS' | 'WARNING' | 'ALERT_TRIGGERED';
}

export const INTERVAL_PRESETS: { preset: ScheduleIntervalPreset; minutes: number; label: string; cronHint: string }[] = [
  { preset: '5m', minutes: 5, label: 'A cada 5 minutos (Teste Rápido)', cronHint: '*/5 * * * *' },
  { preset: '15m', minutes: 15, label: 'A cada 15 minutos (Near Real-time)', cronHint: '*/15 * * * *' },
  { preset: '30m', minutes: 30, label: 'A cada 30 minutos', cronHint: '*/30 * * * *' },
  { preset: '1h', minutes: 60, label: 'A cada 1 hora (Padrão)', cronHint: '0 * * * *' },
  { preset: '6h', minutes: 360, label: 'A cada 6 horas', cronHint: '0 */6 * * *' },
  { preset: '12h', minutes: 720, label: 'A cada 12 horas (Turno SOC)', cronHint: '0 */12 * * *' },
  { preset: '24h', minutes: 1440, label: 'Diário (A cada 24 horas)', cronHint: '0 0 * * *' },
  { preset: 'CRON', minutes: 60, label: 'Expressão Cron Customizada', cronHint: '0 2 * * *' }
];

export const DEFAULT_RECURRING_SCHEDULES: RecurringScanSchedule[] = [
  {
    id: 'sched-payments-auth-15m',
    name: 'Auditoria Contínua Checkout & Autenticação',
    enabled: true,
    targetEndpoints: ['/api/v1/payments/charge', '/api/v1/auth/login', '/api/v1/users/profile'],
    httpMethods: ['POST', 'PUT'],
    attackCategories: ['SQL_INJECTION', 'NOSQL_INJECTION', 'COMMAND_INJECTION'],
    intervalPreset: '15m',
    intervalMinutes: 15,
    cronExpression: '*/15 * * * *',
    intervalLabel: 'A cada 15 minutos',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
    lastRunAt: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
    nextRunAt: new Date(Date.now() + 1000 * 60 * 7).toISOString(),
    totalRuns: 42,
    vulnerabilitiesDetected: 3,
    stopOnCriticalVuln: false,
    alertChannels: ['IN_APP', 'SLACK_WEBHOOK', 'SOAR_PLAYBOOK'],
    status: 'IDLE'
  },
  {
    id: 'sched-deep-owasp-daily',
    name: 'Varredura Noturna OWASP Top 10 API & Traversal',
    enabled: true,
    targetEndpoints: ['/api/v1/files/export', '/api/v1/proxy/download', '/api/v1/admin/debug'],
    httpMethods: ['GET', 'POST'],
    attackCategories: ['PATH_TRAVERSAL', 'SSRF', 'XSS', 'COMMAND_INJECTION'],
    intervalPreset: '24h',
    intervalMinutes: 1440,
    cronExpression: '0 0 * * *',
    intervalLabel: 'Diário (A cada 24 horas)',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
    lastRunAt: new Date(Date.now() - 1000 * 60 * 60 * 18).toISOString(),
    nextRunAt: new Date(Date.now() + 1000 * 60 * 60 * 6).toISOString(),
    totalRuns: 12,
    vulnerabilitiesDetected: 1,
    stopOnCriticalVuln: true,
    alertChannels: ['IN_APP', 'EMAIL_ALERT'],
    status: 'IDLE'
  },
  {
    id: 'sched-search-sqli-1h',
    name: 'Prober Recorrente SQLi em Parâmetros de Busca',
    enabled: false,
    targetEndpoints: ['/api/v1/search', '/api/v1/catalog/items'],
    httpMethods: ['GET'],
    attackCategories: ['SQL_INJECTION', 'NOSQL_INJECTION'],
    intervalPreset: '1h',
    intervalMinutes: 60,
    cronExpression: '0 * * * *',
    intervalLabel: 'A cada 1 hora',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 12).toISOString(),
    lastRunAt: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    nextRunAt: new Date(Date.now() + 1000 * 60 * 15).toISOString(),
    totalRuns: 18,
    vulnerabilitiesDetected: 0,
    stopOnCriticalVuln: false,
    alertChannels: ['IN_APP'],
    status: 'PAUSED'
  }
];

export function calculateNextRunTime(intervalMinutes: number): string {
  const nextMs = Date.now() + intervalMinutes * 60 * 1000;
  return new Date(nextMs).toISOString();
}

export function formatCountdown(nextRunAtIso: string): { totalSeconds: number; formatted: string; isPastDue: boolean } {
  const targetTime = new Date(nextRunAtIso).getTime();
  const diffMs = targetTime - Date.now();
  const isPastDue = diffMs <= 0;
  const totalSeconds = Math.max(0, Math.floor(diffMs / 1000));

  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  let formatted = '';
  if (hours > 0) {
    formatted = `${hours.toString().padStart(2, '0')}h ${minutes.toString().padStart(2, '0')}m ${seconds.toString().padStart(2, '0')}s`;
  } else {
    formatted = `${minutes.toString().padStart(2, '0')}m ${seconds.toString().padStart(2, '0')}s`;
  }

  return { totalSeconds, formatted, isPastDue };
}

/**
 * Executes a recurring scan job against its assigned endpoints and attack suites
 */
export function executeScheduledScanJob(
  schedule: RecurringScanSchedule,
  allPayloads: FuzzingPayload[] = BUILTIN_FUZZING_PAYLOADS
): { record: ScheduledScanExecutionRecord; updatedSchedule: RecurringScanSchedule } {
  const startTime = Date.now();
  const activePayloads = allPayloads.filter(p => schedule.attackCategories.includes(p.category));
  const payloadsToUse = activePayloads.length > 0 ? activePayloads : allPayloads.slice(0, 4);

  const results: FuzzingTestResult[] = [];
  let vulnerabilitiesFound = 0;
  let blockedByWafCount = 0;
  let safeCount = 0;

  schedule.targetEndpoints.forEach(endpoint => {
    schedule.httpMethods.forEach(method => {
      // Pick representative payload for each category to keep simulated scan fast yet thorough
      payloadsToUse.slice(0, 3).forEach(payload => {
        const testRes = simulateFuzzingTest(endpoint, method, payload);
        results.push(testRes);

        if (testRes.verdict === 'VULNERABLE') {
          vulnerabilitiesFound++;
        } else if (testRes.verdict === 'BLOCKED_BY_WAF') {
          blockedByWafCount++;
        } else {
          safeCount++;
        }
      });
    });
  });

  const durationMs = Math.max(120, Date.now() - startTime + Math.floor(Math.random() * 200) + 150);

  const status: 'SUCCESS' | 'WARNING' | 'ALERT_TRIGGERED' = 
    vulnerabilitiesFound > 0 ? 'ALERT_TRIGGERED' :
    blockedByWafCount > 0 ? 'WARNING' : 'SUCCESS';

  const record: ScheduledScanExecutionRecord = {
    id: `exec-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    scheduleId: schedule.id,
    scheduleName: schedule.name,
    timestamp: new Date().toLocaleTimeString(),
    durationMs,
    endpointsTestedCount: schedule.targetEndpoints.length,
    payloadsSentCount: results.length,
    vulnerabilitiesFound,
    blockedByWafCount,
    safeCount,
    results,
    status
  };

  const nextRunAt = calculateNextRunTime(schedule.intervalMinutes);
  const updatedSchedule: RecurringScanSchedule = {
    ...schedule,
    lastRunAt: new Date().toISOString(),
    nextRunAt,
    totalRuns: schedule.totalRuns + 1,
    vulnerabilitiesDetected: schedule.vulnerabilitiesDetected + vulnerabilitiesFound,
    status: schedule.stopOnCriticalVuln && vulnerabilitiesFound > 0 ? 'PAUSED' : 'IDLE'
  };

  return { record, updatedSchedule };
}

export function exportSchedulesToJson(schedules: RecurringScanSchedule[]): string {
  return JSON.stringify(schedules, null, 2);
}

export function exportScanHistoryToCsv(records: ScheduledScanExecutionRecord[]): string {
  const headers = ['ExecutionID', 'ScheduleName', 'Timestamp', 'EndpointsTested', 'PayloadsSent', 'Vulnerabilities', 'BlockedByWAF', 'Safe', 'Status'];
  const rows = records.map(r => [
    r.id,
    `"${r.scheduleName.replace(/"/g, '""')}"`,
    r.timestamp,
    r.endpointsTestedCount,
    r.payloadsSentCount,
    r.vulnerabilitiesFound,
    r.blockedByWafCount,
    r.safeCount,
    r.status
  ]);

  return [headers.join(','), ...rows.map(row => row.join(','))].join('\n');
}
