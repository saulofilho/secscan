import React, { useState, useMemo, useEffect } from 'react';
import { 
  Crosshair, 
  AlertTriangle, 
  Play, 
  Pause,
  Clock,
  Calendar,
  Plus,
  Trash2,
  Terminal, 
  ShieldCheck, 
  Copy, 
  Check, 
  Send,
  Download,
  ChevronDown,
  ChevronUp,
  CheckCircle,
  Search,
  Globe,
  Edit3,
  RefreshCw,
  Upload,
  AlertCircle,
  Settings,
  Zap,
  CheckCircle2,
  Activity,
  RotateCcw
} from 'lucide-react';
import { ApiEndpointFinding } from '../types';
import { 
  AttackCategory, 
  FuzzingPayload, 
  FuzzingTestResult, 
  BUILTIN_FUZZING_PAYLOADS, 
  auditSecurityHeaders, 
  simulateFuzzingTest 
} from '../lib/dastSimulator';
import {
  RecurringScanSchedule,
  ScheduledScanExecutionRecord,
  ScheduleIntervalPreset,
  INTERVAL_PRESETS,
  COMMON_CRON_TEMPLATES,
  DEFAULT_RECURRING_SCHEDULES,
  MAX_RECENT_EXECUTION_LOGS,
  DEFAULT_RECENT_EXECUTION_RECORDS,
  calculateNextRunTime,
  calculateNextRunFromCron,
  validateCronExpression,
  formatCountdown,
  executeScheduledScanJob,
  exportSchedulesToJson,
  exportScanHistoryToCsv
} from '../lib/dastSchedulerEngine';

interface DastFuzzerViewProps {
  endpoints: ApiEndpointFinding[];
  onLogAudit?: (event: any) => void;
}

const STORAGE_KEY_SCHEDULES = 'secscan_dast_schedules_v2';
const STORAGE_KEY_RECORDS = 'secscan_dast_history_v2';
const STORAGE_KEY_RECENT_LOGS = 'secscan_dast_recent_logs_v1';

export const DastFuzzerView: React.FC<DastFuzzerViewProps> = ({ endpoints, onLogAudit }) => {
  const [activeSubTab, setActiveSubTab] = useState<'SCHEDULER' | 'FUZZER' | 'HEADERS'>('SCHEDULER');
  
  // Fuzzer State
  const defaultEndpoint = endpoints.length > 0 ? endpoints[0].path : '/api/v1/payments/charge';
  const [targetEndpoint, setTargetEndpoint] = useState(defaultEndpoint);
  const [httpMethod, setHttpMethod] = useState<'GET' | 'POST' | 'PUT' | 'DELETE'>('POST');
  const [selectedCategory, setSelectedCategory] = useState<AttackCategory>('SQL_INJECTION');
  const [selectedPayloadId, setSelectedPayloadId] = useState<string>(BUILTIN_FUZZING_PAYLOADS[0].id);
  const [customPayloadText, setCustomPayloadText] = useState('');
  const [isRunningFuzz, setIsRunningFuzz] = useState(false);
  const [testHistory, setTestHistory] = useState<FuzzingTestResult[]>([]);
  const [copiedCode, setCopiedCode] = useState(false);

  // Headers Audit State (simulated default baseline headers)
  const [customHeaders] = useState<Record<string, string>>({
    'x-content-type-options': 'nosniff',
    'access-control-allow-origin': '*'
  });

  // ==========================================
  // RECURRING SCAN SCHEDULER STATE
  // ==========================================
  const [schedules, setSchedules] = useState<RecurringScanSchedule[]>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY_SCHEDULES);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch (e) {
      console.warn('Failed to load saved schedules', e);
    }
    return DEFAULT_RECURRING_SCHEDULES;
  });

  const [executionRecords, setExecutionRecords] = useState<ScheduledScanExecutionRecord[]>(() => {
    try {
      const savedRecent = localStorage.getItem(STORAGE_KEY_RECENT_LOGS);
      if (savedRecent) {
        const parsed = JSON.parse(savedRecent);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed.slice(0, MAX_RECENT_EXECUTION_LOGS);
      }
      const savedLegacy = localStorage.getItem(STORAGE_KEY_RECORDS);
      if (savedLegacy) {
        const parsed = JSON.parse(savedLegacy);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed.slice(0, MAX_RECENT_EXECUTION_LOGS);
      }
    } catch (e) {
      console.warn('Failed to load saved execution records', e);
    }
    return DEFAULT_RECENT_EXECUTION_RECORDS.slice(0, MAX_RECENT_EXECUTION_LOGS);
  });

  const [isSchedulerDaemonActive, setIsSchedulerDaemonActive] = useState(true);
  const [executingScheduleId, setExecutingScheduleId] = useState<string | null>(null);
  const [expandedRecordId, setExpandedRecordId] = useState<string | null>(null);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(true);
  const [editingScheduleId, setEditingScheduleId] = useState<string | null>(null);
  const [isImportModalOpen, setIsImportModalOpen] = useState(false);
  const [importJsonText, setImportJsonText] = useState('');
  const [copiedScheduleJson, setCopiedScheduleJson] = useState(false);
  const [historyFilter, setHistoryFilter] = useState<'ALL' | 'VULNERABLE' | 'WARNING'>('ALL');
  const [toastNotification, setToastNotification] = useState<{ message: string; type: 'success' | 'alert' | 'info' } | null>(null);

  // Fallback realistic registered API endpoints if scanner found none
  const registeredEndpointsList = useMemo(() => {
    if (endpoints && endpoints.length > 0) return endpoints;
    return [
      { id: 'ep-1', path: '/api/v1/payments/charge', method: 'POST' as const, riskScore: 92, params: ['amount', 'currency', 'card_token', 'customer_id'], file: 'routes/payment.ts', line: 42, isInternalOrAdmin: false, snippet: 'router.post("/api/v1/payments/charge")' },
      { id: 'ep-2', path: '/api/v1/auth/login', method: 'POST' as const, riskScore: 85, params: ['username', 'password', 'mfa_token'], file: 'routes/auth.ts', line: 18, isInternalOrAdmin: false, snippet: 'router.post("/api/v1/auth/login")' },
      { id: 'ep-3', path: '/api/v1/users/profile', method: 'GET' as const, riskScore: 65, params: ['userId', 'role', 'email'], file: 'routes/user.ts', line: 89, isInternalOrAdmin: false, snippet: 'router.get("/api/v1/users/profile")' },
      { id: 'ep-4', path: '/api/v1/files/export', method: 'GET' as const, riskScore: 88, params: ['filePath', 'format', 'download'], file: 'controllers/fileExport.ts', line: 30, isInternalOrAdmin: false, snippet: 'router.get("/api/v1/files/export")' },
      { id: 'ep-5', path: '/api/v1/proxy/download', method: 'GET' as const, riskScore: 90, params: ['targetUrl', 'timeout'], file: 'services/proxy.ts', line: 12, isInternalOrAdmin: true, snippet: 'router.get("/api/v1/proxy/download")' },
      { id: 'ep-6', path: '/api/v1/admin/debug', method: 'GET' as const, riskScore: 95, params: ['cmd', 'secretKey'], file: 'routes/admin.ts', line: 104, isInternalOrAdmin: true, snippet: 'router.get("/api/v1/admin/debug")' },
      { id: 'ep-7', path: '/api/v1/search', method: 'GET' as const, riskScore: 70, params: ['q', 'filter', 'sortBy'], file: 'routes/search.ts', line: 22, isInternalOrAdmin: false, snippet: 'router.get("/api/v1/search")' },
      { id: 'ep-8', path: '/api/v1/catalog/items', method: 'GET' as const, riskScore: 45, params: ['category', 'page', 'limit'], file: 'routes/catalog.ts', line: 15, isInternalOrAdmin: false, snippet: 'router.get("/api/v1/catalog/items")' },
    ];
  }, [endpoints]);

  // New Schedule Form State
  const [newScheduleName, setNewScheduleName] = useState('Rotina Recorrente de Fuzzing OWASP');
  const [newTargetEndpoints, setNewTargetEndpoints] = useState<string[]>(() => {
    return endpoints && endpoints.length > 0 
      ? endpoints.slice(0, 2).map(e => e.path) 
      : ['/api/v1/payments/charge', '/api/v1/auth/login'];
  });
  const [endpointFilterSearch, setEndpointFilterSearch] = useState('');
  const [customEndpointInput, setCustomEndpointInput] = useState('');
  const [newHttpMethods, setNewHttpMethods] = useState<('GET' | 'POST' | 'PUT' | 'DELETE')[]>(['GET', 'POST']);
  const [newAttackCategories, setNewAttackCategories] = useState<AttackCategory[]>([
    'SQL_INJECTION', 
    'NOSQL_INJECTION', 
    'XSS'
  ]);
  const [newIntervalPreset, setNewIntervalPreset] = useState<ScheduleIntervalPreset>('15m');
  const [newCustomCron, setNewCustomCron] = useState('0 */4 * * *');
  const [newStopOnVuln, setNewStopOnVuln] = useState(false);
  const [newAlertChannels, setNewAlertChannels] = useState<('IN_APP' | 'SLACK_WEBHOOK' | 'EMAIL_ALERT' | 'SOAR_PLAYBOOK')[]>([
    'IN_APP', 
    'SLACK_WEBHOOK'
  ]);

  // Live Cron Validation
  const cronValidation = useMemo(() => {
    if (newIntervalPreset !== 'CRON') {
      const preset = INTERVAL_PRESETS.find(p => p.preset === newIntervalPreset);
      return {
        isValid: true,
        description: preset ? preset.label : 'Intervalo pré-configurado',
        estimatedMinutes: preset ? preset.minutes : 60
      };
    }
    return validateCronExpression(newCustomCron);
  }, [newIntervalPreset, newCustomCron]);

  // Sync with LocalStorage
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY_SCHEDULES, JSON.stringify(schedules));
    } catch (e) {
      // ignore storage errors
    }
  }, [schedules]);

  useEffect(() => {
    try {
      const recordsToStore = executionRecords.slice(0, MAX_RECENT_EXECUTION_LOGS);
      localStorage.setItem(STORAGE_KEY_RECENT_LOGS, JSON.stringify(recordsToStore));
      localStorage.setItem(STORAGE_KEY_RECORDS, JSON.stringify(recordsToStore));
    } catch (e) {
      // ignore storage errors
    }
  }, [executionRecords]);

  // Live Second-by-Second Countdown Tick
  const [currentTime, setCurrentTime] = useState(Date.now());
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(Date.now());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Show temporary toast
  const showToast = (message: string, type: 'success' | 'alert' | 'info' = 'info') => {
    setToastNotification({ message, type });
    setTimeout(() => {
      setToastNotification(null);
    }, 4500);
  };

  // Run a scheduled scan job
  const triggerScheduleExecution = (scheduleId: string, isAutomated: boolean = false) => {
    const targetSchedule = schedules.find(s => s.id === scheduleId);
    if (!targetSchedule) return;

    setExecutingScheduleId(scheduleId);
    setSchedules(prev => prev.map(s => s.id === scheduleId ? { ...s, status: 'RUNNING' } : s));

    setTimeout(() => {
      const { record, updatedSchedule } = executeScheduledScanJob(targetSchedule, BUILTIN_FUZZING_PAYLOADS);
      
      setExecutionRecords(prev => [record, ...prev].slice(0, MAX_RECENT_EXECUTION_LOGS));
      setSchedules(prev => prev.map(s => s.id === scheduleId ? updatedSchedule : s));
      setExecutingScheduleId(null);

      // Audit Log
      if (onLogAudit) {
        onLogAudit({
          id: `audit-dast-sched-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          action: `Varredura DAST Recorrente "${targetSchedule.name}" executada (${record.endpointsTestedCount} endpoints, ${record.payloadsSentCount} payloads, ${record.vulnerabilitiesFound} vulnerabilidades).`,
          user: isAutomated ? 'DAST-Scheduler-Daemon' : 'SecOps-Operator',
          status: record.vulnerabilitiesFound > 0 ? 'WARNING' : 'SUCCESS'
        });
      }

      if (record.vulnerabilitiesFound > 0) {
        showToast(
          `ALERTA: O agendador "${targetSchedule.name}" detectou ${record.vulnerabilitiesFound} vulnerabilidade(s) dinâmicas em ${record.endpointsTestedCount} endpoints!`,
          'alert'
        );
      } else {
        showToast(
          `Varredura concluída com sucesso para "${targetSchedule.name}". Nenhum vetor de injeção exposto.`,
          'success'
        );
      }
    }, 800);
  };

  // Background Automatic Execution Daemon
  useEffect(() => {
    if (!isSchedulerDaemonActive) return;

    const now = Date.now();
    // Check if any enabled schedule has reached its nextRunAt
    const dueSchedule = schedules.find(
      s => s.enabled && s.status !== 'RUNNING' && s.status !== 'PAUSED' && new Date(s.nextRunAt).getTime() <= now
    );

    if (dueSchedule && executingScheduleId !== dueSchedule.id) {
      triggerScheduleExecution(dueSchedule.id, true);
    }
  }, [currentTime, isSchedulerDaemonActive, schedules, executingScheduleId]);

  // Toggle single schedule state
  const handleToggleSchedule = (scheduleId: string) => {
    setSchedules(prev => prev.map(s => {
      if (s.id === scheduleId) {
        const nextEnabled = !s.enabled;
        return {
          ...s,
          enabled: nextEnabled,
          status: nextEnabled ? 'IDLE' : 'PAUSED',
          nextRunAt: nextEnabled ? calculateNextRunTime(s.intervalMinutes) : s.nextRunAt
        };
      }
      return s;
    }));
  };

  // Delete schedule
  const handleDeleteSchedule = (scheduleId: string) => {
    setSchedules(prev => prev.filter(s => s.id !== scheduleId));
    showToast('Agendamento removido com sucesso.', 'info');
  };

  // Start editing an existing schedule
  const handleStartEditSchedule = (sched: RecurringScanSchedule) => {
    setEditingScheduleId(sched.id);
    setNewScheduleName(sched.name);
    setNewTargetEndpoints([...sched.targetEndpoints]);
    setNewHttpMethods([...sched.httpMethods]);
    setNewAttackCategories([...sched.attackCategories]);
    setNewIntervalPreset(sched.intervalPreset);
    setNewCustomCron(sched.cronExpression || '0 */4 * * *');
    setNewStopOnVuln(sched.stopOnCriticalVuln);
    setNewAlertChannels([...sched.alertChannels]);
    setIsCreateModalOpen(true);

    setTimeout(() => {
      const el = document.getElementById('scan-schedule-config-panel');
      if (el) el.scrollIntoView({ behavior: 'smooth' });
    }, 100);
  };

  // Reset and close schedule form
  const handleCancelForm = () => {
    setIsCreateModalOpen(false);
    setEditingScheduleId(null);
    setNewScheduleName('');
    setNewTargetEndpoints([]);
    setEndpointFilterSearch('');
    setCustomEndpointInput('');
  };

  // Create or Update schedule submission
  const handleSaveOrUpdateSchedule = () => {
    if (!newScheduleName.trim()) {
      showToast('Por favor, informe o nome do agendamento.', 'alert');
      return;
    }

    if (newIntervalPreset === 'CRON' && !cronValidation.isValid) {
      showToast(`Expressão Cron inválida: ${cronValidation.error}`, 'alert');
      return;
    }

    const selectedEndpoints = newTargetEndpoints.length > 0
      ? newTargetEndpoints
      : registeredEndpointsList.length > 0
      ? [registeredEndpointsList[0].path]
      : ['/api/v1/payments/charge'];

    const presetConfig = INTERVAL_PRESETS.find(p => p.preset === newIntervalPreset) || INTERVAL_PRESETS[1];
    const minutes = newIntervalPreset === 'CRON' ? cronValidation.estimatedMinutes : presetConfig.minutes;
    const cronExpr = newIntervalPreset === 'CRON' ? newCustomCron.trim() : presetConfig.cronHint;
    const intervalLabel = newIntervalPreset === 'CRON' ? `Cron (${newCustomCron.trim()})` : presetConfig.label;

    if (editingScheduleId) {
      // Update existing schedule
      setSchedules(prev => prev.map(s => {
        if (s.id === editingScheduleId) {
          const nextRunAt = s.enabled
            ? (newIntervalPreset === 'CRON' ? calculateNextRunFromCron(cronExpr) : calculateNextRunTime(minutes))
            : s.nextRunAt;
          return {
            ...s,
            name: newScheduleName.trim(),
            targetEndpoints: selectedEndpoints,
            httpMethods: newHttpMethods.length > 0 ? newHttpMethods : ['GET', 'POST'],
            attackCategories: newAttackCategories.length > 0 ? newAttackCategories : ['SQL_INJECTION'],
            intervalPreset: newIntervalPreset,
            intervalMinutes: minutes,
            cronExpression: cronExpr,
            intervalLabel,
            stopOnCriticalVuln: newStopOnVuln,
            alertChannels: newAlertChannels,
            nextRunAt
          };
        }
        return s;
      }));
      showToast(`Agendamento "${newScheduleName.trim()}" atualizado com sucesso!`, 'success');

      if (onLogAudit) {
        onLogAudit({
          id: `audit-sched-update-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          action: `Agendador DAST atualizado: "${newScheduleName.trim()}" (${intervalLabel}, ${selectedEndpoints.length} endpoints).`,
          user: 'SecOps-Operator',
          status: 'SUCCESS'
        });
      }
    } else {
      // Create new schedule
      const newSched: RecurringScanSchedule = {
        id: `sched-${Date.now()}`,
        name: newScheduleName.trim(),
        enabled: true,
        targetEndpoints: selectedEndpoints,
        httpMethods: newHttpMethods.length > 0 ? newHttpMethods : ['GET', 'POST'],
        attackCategories: newAttackCategories.length > 0 ? newAttackCategories : ['SQL_INJECTION'],
        intervalPreset: newIntervalPreset,
        intervalMinutes: minutes,
        cronExpression: cronExpr,
        intervalLabel,
        createdAt: new Date().toISOString(),
        nextRunAt: newIntervalPreset === 'CRON' ? calculateNextRunFromCron(cronExpr) : calculateNextRunTime(minutes),
        totalRuns: 0,
        vulnerabilitiesDetected: 0,
        stopOnCriticalVuln: newStopOnVuln,
        alertChannels: newAlertChannels,
        status: 'IDLE'
      };

      setSchedules(prev => [newSched, ...prev]);
      showToast(`Agendamento "${newSched.name}" criado com sucesso! Próxima execução estimada em ${minutes}m.`, 'success');

      if (onLogAudit) {
        onLogAudit({
          id: `audit-sched-create-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          action: `Novo agendador DAST criado: "${newSched.name}" (${newSched.intervalLabel}).`,
          user: 'SecOps-Operator',
          status: 'SUCCESS'
        });
      }
    }

    handleCancelForm();
  };

  // Restore default schedules
  const handleRestoreDefaultSchedules = () => {
    setSchedules(DEFAULT_RECURRING_SCHEDULES);
    try {
      localStorage.setItem(STORAGE_KEY_SCHEDULES, JSON.stringify(DEFAULT_RECURRING_SCHEDULES));
    } catch (e) {
      // ignore
    }
    showToast('Agendamentos padrão restaurados com sucesso.', 'info');
  };

  // Import schedules from JSON text
  const handleImportJson = (jsonString: string) => {
    try {
      const parsed = JSON.parse(jsonString);
      if (!Array.isArray(parsed) || parsed.length === 0) {
        throw new Error('O formato esperado é uma lista JSON contendo pelo menos um agendamento válido.');
      }
      setSchedules(parsed);
      try {
        localStorage.setItem(STORAGE_KEY_SCHEDULES, JSON.stringify(parsed));
      } catch (e) {
        // ignore
      }
      setIsImportModalOpen(false);
      setImportJsonText('');
      showToast(`${parsed.length} rotina(s) de agendamento importada(s) com sucesso!`, 'success');
    } catch (err: any) {
      showToast(`Erro ao importar JSON: ${err.message}`, 'alert');
    }
  };

  // Export options
  const handleExportJson = () => {
    const json = exportSchedulesToJson(schedules);
    navigator.clipboard.writeText(json);
    setCopiedScheduleJson(true);
    setTimeout(() => setCopiedScheduleJson(false), 2000);
    showToast('Configuração de agendamentos copiada em JSON!', 'success');
  };

  const handleExportCsv = () => {
    const csv = exportScanHistoryToCsv(executionRecords.slice(0, MAX_RECENT_EXECUTION_LOGS));
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `dast-recent-executions-${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast('Histórico recente exportado em CSV.', 'success');
  };

  const handleClearExecutionLog = () => {
    setExecutionRecords([]);
    try {
      localStorage.removeItem(STORAGE_KEY_RECENT_LOGS);
      localStorage.removeItem(STORAGE_KEY_RECORDS);
    } catch (e) {
      // ignore
    }
    showToast('Recent Execution Log limpo com sucesso.', 'info');
  };

  const handleRestoreDefaultExecutionLogs = () => {
    setExecutionRecords(DEFAULT_RECENT_EXECUTION_RECORDS.slice(0, MAX_RECENT_EXECUTION_LOGS));
    showToast('Últimos 10 resultados padrão de varredura restaurados.', 'success');
  };

  // Computed summary metrics
  const activeSchedulesCount = useMemo(() => schedules.filter(s => s.enabled).length, [schedules]);
  const totalRunsCount = useMemo(() => schedules.reduce((acc, s) => acc + s.totalRuns, 0), [schedules]);
  const totalVulnsCount = useMemo(() => schedules.reduce((acc, s) => acc + s.vulnerabilitiesDetected, 0), [schedules]);

  // Soonest upcoming schedule
  const soonestSchedule = useMemo(() => {
    const active = schedules.filter(s => s.enabled && s.status !== 'PAUSED');
    if (active.length === 0) return null;
    return [...active].sort((a, b) => new Date(a.nextRunAt).getTime() - new Date(b.nextRunAt).getTime())[0];
  }, [schedules]);

  const headersAudit = useMemo(() => {
    return auditSecurityHeaders(customHeaders);
  }, [customHeaders]);

  const availablePayloads = useMemo(() => {
    return BUILTIN_FUZZING_PAYLOADS.filter(p => p.category === selectedCategory);
  }, [selectedCategory]);

  const currentPayload = useMemo(() => {
    return availablePayloads.find(p => p.id === selectedPayloadId) || availablePayloads[0] || BUILTIN_FUZZING_PAYLOADS[0];
  }, [availablePayloads, selectedPayloadId]);

  const handleRunFuzzTest = () => {
    setIsRunningFuzz(true);
    setTimeout(() => {
      const activePayload: FuzzingPayload = customPayloadText.trim() ? {
        ...currentPayload,
        payload: customPayloadText
      } : currentPayload;

      const result = simulateFuzzingTest(targetEndpoint, httpMethod, activePayload);
      setTestHistory(prev => [result, ...prev]);
      setIsRunningFuzz(false);

      if (onLogAudit) {
        onLogAudit({
          id: `audit-fuzz-manual-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          action: `Teste DAST manual executado em ${httpMethod} ${targetEndpoint} com payload ${activePayload.name} (Veredito: ${result.verdict}).`,
          user: 'SecOps-Operator',
          status: result.verdict === 'VULNERABLE' ? 'WARNING' : 'SUCCESS'
        });
      }
    }, 400);
  };

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  // Filtered recent execution records (persisted max 10 scan results)
  const recentRecords = useMemo(() => {
    return executionRecords.slice(0, MAX_RECENT_EXECUTION_LOGS);
  }, [executionRecords]);

  const filteredRecentRecords = useMemo(() => {
    if (historyFilter === 'VULNERABLE') {
      return recentRecords.filter(r => r.vulnerabilitiesFound > 0);
    }
    if (historyFilter === 'WARNING') {
      return recentRecords.filter(r => r.blockedByWafCount > 0 || r.vulnerabilitiesFound > 0);
    }
    return recentRecords;
  }, [recentRecords, historyFilter]);

  const recentVulnCount = useMemo(() => {
    return recentRecords.filter(r => r.vulnerabilitiesFound > 0).length;
  }, [recentRecords]);

  const recentWafCount = useMemo(() => {
    return recentRecords.filter(r => r.blockedByWafCount > 0 && r.vulnerabilitiesFound === 0).length;
  }, [recentRecords]);

  const recentSafeCount = useMemo(() => {
    return recentRecords.filter(r => r.vulnerabilitiesFound === 0 && r.blockedByWafCount === 0).length;
  }, [recentRecords]);

  const filteredExecutionRecords = filteredRecentRecords;

  return (
    <div id="dast-fuzzer-view" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Toast Alert Banner */}
      {toastNotification && (
        <div className={`p-4 rounded-xl border flex items-center justify-between font-mono text-xs transition-all shadow-lg animate-fadeIn ${
          toastNotification.type === 'alert'
            ? 'bg-rose-950/80 border-rose-600 text-rose-200'
            : toastNotification.type === 'success'
            ? 'bg-emerald-950/80 border-emerald-600 text-emerald-200'
            : 'bg-zinc-900 border-zinc-700 text-zinc-200'
        }`}>
          <div className="flex items-center gap-3">
            {toastNotification.type === 'alert' ? (
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
            ) : toastNotification.type === 'success' ? (
              <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0" />
            ) : (
              <Clock className="w-5 h-5 text-cyan-400 shrink-0" />
            )}
            <span>{toastNotification.message}</span>
          </div>
          <button
            onClick={() => setToastNotification(null)}
            className="text-zinc-400 hover:text-white text-xs px-2 py-1 cursor-pointer"
          >
            Fechar
          </button>
        </div>
      )}

      {/* Header & Sub-Tabs */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#222] pb-5">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              <Crosshair className="w-5 h-5" />
            </span>
            <h1 className="text-xl font-bold tracking-tight text-white uppercase font-mono">
              DAST &amp; API Security Fuzzer
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 font-bold">
              Dynamic Application Security Testing
            </span>
            {activeSchedulesCount > 0 && isSchedulerDaemonActive && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-700/60 font-bold flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                {activeSchedulesCount} Agendador(es) Ativo(s)
              </span>
            )}
          </div>
          <p className="text-xs text-zinc-400 font-mono mt-1">
            Simulação dinâmica de ataques em endpoints descobertos (SQLi, XSS, SSRF), agendador recorrente contínuo e auditoria de cabeçalhos HTTP.
          </p>
        </div>

        {/* Subtab Navigation Buttons */}
        <div className="flex items-center gap-2 font-mono flex-wrap">
          <button
            onClick={() => setActiveSubTab('FUZZER')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer border flex items-center gap-1.5 ${
              activeSubTab === 'FUZZER'
                ? 'bg-emerald-600 text-white border-emerald-500 shadow'
                : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
            }`}
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>Fuzzer Manual</span>
          </button>
          <button
            id="btn-dast-scan-scheduler"
            onClick={() => setActiveSubTab('SCHEDULER')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer border flex items-center gap-1.5 ${
              activeSubTab === 'SCHEDULER'
                ? 'bg-emerald-600 text-white border-emerald-500 shadow'
                : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
            }`}
          >
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Scan Scheduler</span>
            <span className="text-[9px] px-1.5 py-0.2 bg-black/40 rounded text-cyan-300 font-bold">
              {activeSchedulesCount}/{schedules.length}
            </span>
          </button>
          <button
            onClick={() => setActiveSubTab('HEADERS')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer border flex items-center gap-1.5 ${
              activeSubTab === 'HEADERS'
                ? 'bg-emerald-600 text-white border-emerald-500 shadow'
                : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Cabeçalhos HTTP ({headersAudit.grade})</span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SUBTAB 1: DAST FUZZER (MANUAL INJECTION)                                 */}
      {/* ========================================================================= */}
      {activeSubTab === 'FUZZER' && (
        <div className="space-y-6">
          {/* Quick Scan Schedule Status Banner */}
          <div id="scan-schedule-quick-bar" className="bg-[#0C120E] border border-emerald-900/60 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs">
            <div className="flex items-center gap-3">
              <span className="p-2 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                <Clock className="w-4 h-4" />
              </span>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-bold text-white">Scan Schedule de Fuzzing Automatizado</span>
                  <span className={`px-2 py-0.2 rounded text-[10px] font-bold ${
                    isSchedulerDaemonActive ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/60' : 'bg-zinc-800 text-zinc-400'
                  }`}>
                    {isSchedulerDaemonActive ? 'DAEMON ATIVO' : 'PAUSADO'}
                  </span>
                </div>
                <div className="text-zinc-400 text-[11px] mt-0.5">
                  {activeSchedulesCount} rotina(s) ativa(s) nos endpoints da API &bull; Próxima execução programada:{' '}
                  {soonestSchedule ? (
                    <span className="text-emerald-300 font-bold">
                      {formatCountdown(soonestSchedule.nextRunAt).formatted} ({soonestSchedule.name})
                    </span>
                  ) : (
                    <span className="text-zinc-500">Nenhum agendamento ativo</span>
                  )}
                </div>
              </div>
            </div>

            <button
              onClick={() => {
                setActiveSubTab('SCHEDULER');
                setIsCreateModalOpen(true);
              }}
              className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center gap-1.5 self-start sm:self-auto cursor-pointer transition-colors shadow"
            >
              <Settings className="w-3.5 h-3.5" />
              <span>Painel Scan Schedule &rarr;</span>
            </button>
          </div>

          {/* Target Endpoint & Payload Selection Box */}
          <div className="bg-[#0C0C0C] border border-[#222] rounded-xl p-5 space-y-4 font-mono">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Endpoint Selector */}
              <div className="md:col-span-2 space-y-1">
                <label className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">
                  Endpoint Alvo (Descoberto pelo LinkFinder):
                </label>
                <div className="flex items-center gap-2">
                  <select
                    value={httpMethod}
                    onChange={(e) => setHttpMethod(e.target.value as any)}
                    className="bg-black/60 border border-[#2A2A2A] px-2.5 py-2 rounded-lg text-xs font-bold text-emerald-400 focus:outline-none cursor-pointer"
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                  <input
                    type="text"
                    value={targetEndpoint}
                    onChange={(e) => setTargetEndpoint(e.target.value)}
                    placeholder="/api/v1/resource"
                    className="flex-1 bg-black/60 border border-[#2A2A2A] px-3 py-2 rounded-lg text-xs text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              {/* Attack Class Selector */}
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">
                  Classe de Ataque:
                </label>
                <select
                  value={selectedCategory}
                  onChange={(e) => {
                    setSelectedCategory(e.target.value as AttackCategory);
                    setCustomPayloadText('');
                  }}
                  className="w-full bg-black/60 border border-[#2A2A2A] px-3 py-2 rounded-lg text-xs text-white focus:outline-none focus:border-emerald-500 cursor-pointer"
                >
                  <option value="SQL_INJECTION">SQL Injection (SQLi)</option>
                  <option value="NOSQL_INJECTION">NoSQL Injection (MongoDB)</option>
                  <option value="XSS">Cross-Site Scripting (XSS)</option>
                  <option value="PATH_TRAVERSAL">Path Traversal (/etc/passwd)</option>
                  <option value="SSRF">Server-Side Request Forgery</option>
                  <option value="COMMAND_INJECTION">Command Injection (Bash)</option>
                </select>
              </div>
            </div>

            {/* Payloads Selector */}
            <div className="space-y-2 pt-2 border-t border-white/5">
              <label className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">
                Payload de Fuzzing:
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {availablePayloads.map(payload => (
                  <button
                    key={payload.id}
                    onClick={() => {
                      setSelectedPayloadId(payload.id);
                      setCustomPayloadText('');
                    }}
                    className={`p-2.5 rounded-lg border text-left text-xs transition-all cursor-pointer ${
                      currentPayload.id === payload.id && !customPayloadText
                        ? 'bg-[#181818] border-emerald-500 text-white shadow'
                        : 'bg-black/40 border-[#222] text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-emerald-400">{payload.name}</span>
                      <span className="text-[9px] text-zinc-500">{payload.cwe}</span>
                    </div>
                    <code className="text-[10.5px] text-zinc-300 block truncate mt-1">{payload.payload}</code>
                  </button>
                ))}
              </div>

              {/* Action Button */}
              <div className="pt-2 flex items-center justify-between flex-wrap gap-2">
                <span className="text-[11px] text-zinc-500">
                  Alvo atual: <code className="text-zinc-300">{httpMethod} {targetEndpoint}</code>
                </span>
                <button
                  onClick={handleRunFuzzTest}
                  disabled={isRunningFuzz}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-bold uppercase tracking-wider flex items-center gap-2 transition-colors cursor-pointer shadow"
                >
                  <Send className={`w-3.5 h-3.5 ${isRunningFuzz ? 'animate-bounce' : ''}`} />
                  <span>{isRunningFuzz ? 'Injetando Payload...' : 'Disparar Fuzzing de Teste'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Test Execution Results Stream */}
          <div className="space-y-3 font-mono">
            <h3 className="text-xs font-bold text-zinc-400 uppercase tracking-wider">
              Histórico de Testes de Fuzzing Manual ({testHistory.length})
            </h3>

            {testHistory.length === 0 ? (
              <div className="p-8 text-center bg-[#0C0C0C] border border-[#222] rounded-xl text-xs text-zinc-500">
                Nenhum teste dinâmico executado nesta sessão. Clique em &quot;Disparar Fuzzing de Teste&quot; acima ou configure um &quot;Agendador Recorrente&quot; para execução automatizada.
              </div>
            ) : (
              testHistory.map(test => {
                const isVuln = test.verdict === 'VULNERABLE';
                const isWaf = test.verdict === 'BLOCKED_BY_WAF';

                return (
                  <div
                    key={test.id}
                    className={`p-4 rounded-xl border transition-all ${
                      isVuln
                        ? 'bg-[#0E0708] border-rose-900/50'
                        : isWaf
                        ? 'bg-[#0E0B07] border-amber-900/40'
                        : 'bg-[#070E0A] border-emerald-900/40'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`px-2 py-0.2 rounded text-[10px] font-bold uppercase tracking-wider ${
                            isVuln
                              ? 'bg-rose-600 text-white animate-pulse'
                              : isWaf
                              ? 'bg-amber-600 text-white'
                              : 'bg-emerald-600 text-white'
                          }`}>
                            {test.verdict}
                          </span>
                          <span className="text-xs font-bold text-white">{test.method} {test.endpoint}</span>
                          <span className="text-[10px] text-zinc-500">({test.simulatedResponseTimeMs}ms)</span>
                          <span className="text-[10px] text-zinc-500">HTTP {test.simulatedStatus}</span>
                        </div>
                        <p className="text-[11px] text-zinc-300">{test.analysis}</p>
                      </div>

                      <span className="text-[10px] text-zinc-500 shrink-0">{test.timestamp}</span>
                    </div>

                    <div className="mt-3 pt-2.5 border-t border-white/5 space-y-1.5 text-xs">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-zinc-500">Payload enviado:</span>
                        <code className="px-2 py-0.5 rounded bg-black/60 text-zinc-300 text-[10.5px]">
                          {test.payload.payload}
                        </code>
                      </div>
                      <div className="p-2.5 rounded bg-black/80 text-zinc-400 text-[10.5px] overflow-x-auto">
                        <span className="text-zinc-600 select-none block mb-1">Resposta do Servidor:</span>
                        <code>{test.responseSnippet}</code>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUBTAB 2: RECURRING SCAN SCHEDULER                                        */}
      {/* ========================================================================= */}
      {activeSubTab === 'SCHEDULER' && (
        <div id="scan-schedule-panel" className="space-y-6 font-mono">
          {/* Top Control Bar & Metrics */}
          <div className="bg-[#0C0C0C] border border-[#222] rounded-xl p-5 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#222]">
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="p-1.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                    <Clock className="w-4 h-4" />
                  </span>
                  <h2 className="text-lg font-bold text-white uppercase">
                    Scan Scheduler &amp; Fuzzing Recorrente
                  </h2>
                  <span className={`text-[10px] px-2 py-0.5 rounded font-bold border flex items-center gap-1.5 ${
                    isSchedulerDaemonActive
                      ? 'bg-emerald-950/60 text-emerald-300 border-emerald-600/60'
                      : 'bg-zinc-800 text-zinc-400 border-zinc-700'
                  }`}>
                    <span className={`w-2 h-2 rounded-full ${isSchedulerDaemonActive ? 'bg-emerald-400 animate-pulse' : 'bg-zinc-500'}`} />
                    {isSchedulerDaemonActive ? 'DAEMON ATIVO' : 'DAEMON PAUSADO'}
                  </span>
                </div>
                <p className="text-xs text-zinc-400 mt-1">
                  Agendamento automatizado de fuzzing DAST baseado em expressões Cron (POSIX 5 campos) ou intervalos pré-definidos para endpoints registrados da API.
                </p>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={() => setIsSchedulerDaemonActive(!isSchedulerDaemonActive)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold border flex items-center gap-1.5 cursor-pointer transition-colors ${
                    isSchedulerDaemonActive
                      ? 'bg-zinc-900 border-zinc-700 text-zinc-300 hover:text-white'
                      : 'bg-emerald-600 text-white border-emerald-500'
                  }`}
                  title={isSchedulerDaemonActive ? 'Pausar daemon de execução automática' : 'Retomar daemon de execução automática'}
                >
                  {isSchedulerDaemonActive ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                  <span>{isSchedulerDaemonActive ? 'Pausar Daemon' : 'Iniciar Daemon'}</span>
                </button>

                <button
                  onClick={handleExportJson}
                  className="px-3 py-1.5 rounded-lg text-xs font-bold bg-[#1A1A1A] hover:bg-[#252525] border border-[#333] text-zinc-300 hover:text-white flex items-center gap-1.5 cursor-pointer transition-colors"
                  title="Exportar todas as rotinas em formato JSON para backup ou automação"
                >
                  {copiedScheduleJson ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Exportar</span>
                </button>

                <button
                  onClick={() => setIsImportModalOpen(true)}
                  className="px-3 py-1.5 rounded-lg text-xs font-bold bg-[#1A1A1A] hover:bg-[#252525] border border-[#333] text-zinc-300 hover:text-white flex items-center gap-1.5 cursor-pointer transition-colors"
                  title="Importar agendamentos a partir de JSON"
                >
                  <Upload className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Importar</span>
                </button>

                <button
                  onClick={handleRestoreDefaultSchedules}
                  className="px-2.5 py-1.5 rounded-lg text-xs font-bold bg-[#1A1A1A] hover:bg-[#252525] border border-[#333] text-zinc-400 hover:text-white flex items-center gap-1 cursor-pointer transition-colors"
                  title="Restaurar rotinas padrão de fábrica"
                >
                  <RefreshCw className="w-3 h-3" />
                  <span>Restaurar</span>
                </button>

                <button
                  onClick={() => {
                    setEditingScheduleId(null);
                    setNewScheduleName('');
                    setNewTargetEndpoints(registeredEndpointsList.slice(0, 2).map(e => e.path));
                    setIsCreateModalOpen(true);
                  }}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold uppercase tracking-wider flex items-center gap-2 cursor-pointer shadow transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Novo Agendamento</span>
                </button>
              </div>
            </div>

            {/* Metrics Dashboard */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
              <div className="bg-black/50 border border-[#222] p-3 rounded-lg">
                <span className="text-[10px] text-zinc-500 block uppercase">Agendamentos Ativos</span>
                <div className="text-xl font-bold text-white mt-0.5">
                  {activeSchedulesCount} <span className="text-xs text-zinc-500 font-normal">/ {schedules.length}</span>
                </div>
              </div>

              <div className="bg-black/50 border border-[#222] p-3 rounded-lg">
                <span className="text-[10px] text-zinc-500 block uppercase">Varreduras Executadas</span>
                <div className="text-xl font-bold text-cyan-400 mt-0.5">{totalRunsCount}</div>
              </div>

              <div className="bg-black/50 border border-[#222] p-3 rounded-lg">
                <span className="text-[10px] text-zinc-500 block uppercase">Falhas / Vulns Detectadas</span>
                <div className={`text-xl font-bold mt-0.5 ${totalVulnsCount > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {totalVulnsCount}
                </div>
              </div>

              <div className="bg-black/50 border border-[#222] p-3 rounded-lg">
                <span className="text-[10px] text-zinc-500 block uppercase">Próxima Execução</span>
                <div className="text-sm font-bold text-emerald-300 mt-1 truncate">
                  {soonestSchedule ? (
                    <span className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
                      {formatCountdown(soonestSchedule.nextRunAt).formatted}
                    </span>
                  ) : (
                    <span className="text-zinc-500 text-xs">Nenhum ativo</span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Prompt banner when configuration panel is closed */}
          {!isCreateModalOpen && (
            <div className="bg-[#0C120E] border border-emerald-900/60 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs">
              <div className="flex items-center gap-3">
                <span className="p-2 rounded-lg bg-emerald-500/20 text-emerald-400">
                  <Calendar className="w-4 h-4" />
                </span>
                <div>
                  <span className="font-bold text-white block">Painel de Configuração de Scan Schedule</span>
                  <span className="text-zinc-400 text-[11px]">
                    Defina intervalos de recorrência Cron personalizados (ex: a cada 5m, diário, semanal) para fuzzing contínuo dos endpoints da API.
                  </span>
                </div>
              </div>
              <button
                onClick={() => {
                  setEditingScheduleId(null);
                  setNewScheduleName('');
                  setNewTargetEndpoints(registeredEndpointsList.slice(0, 2).map(e => e.path));
                  setIsCreateModalOpen(true);
                }}
                className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center gap-1.5 self-start sm:self-auto cursor-pointer transition-colors shadow"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Abrir Painel de Agendamento</span>
              </button>
            </div>
          )}

          {/* ========================================================================= */}
          {/* SCAN SCHEDULE CONFIGURATION PANEL                                         */}
          {/* ========================================================================= */}
          {isCreateModalOpen && (
            <div 
              id="scan-schedule-config-panel" 
              className="bg-[#0C0C0C] border-2 border-emerald-500/80 rounded-xl p-5 space-y-5 animate-fadeIn shadow-2xl"
            >
              {/* Panel Header */}
              <div className="flex items-center justify-between pb-3 border-b border-[#222]">
                <div className="flex items-center gap-2">
                  <span className="p-1.5 rounded bg-emerald-500/20 text-emerald-400">
                    {editingScheduleId ? <Edit3 className="w-4 h-4" /> : <Clock className="w-4 h-4" />}
                  </span>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-base font-bold text-white uppercase">
                        {editingScheduleId ? 'Editar Agendamento DAST' : 'Configurar Novo Agendador de Varredura DAST'}
                      </h3>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider ${
                        editingScheduleId 
                          ? 'bg-amber-950 text-amber-300 border border-amber-700/60'
                          : 'bg-emerald-950 text-emerald-300 border border-emerald-700/60'
                      }`}>
                        {editingScheduleId ? 'Modo Edição' : 'Novo Scan Schedule'}
                      </span>
                    </div>
                    <span className="text-[11px] text-zinc-400 block mt-0.5">
                      Defina expressões de agendamento tipo Cron para automatizar testes dinâmicos de segurança e vulnerabilidade nos endpoints registrados.
                    </span>
                  </div>
                </div>
                <button
                  onClick={handleCancelForm}
                  className="text-zinc-400 hover:text-white text-xs px-2.5 py-1 rounded bg-zinc-900 border border-zinc-700 cursor-pointer"
                >
                  ✕ Fechar
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {/* Schedule Name */}
                <div className="space-y-1.5 md:col-span-2">
                  <label className="text-[10px] font-bold text-zinc-300 uppercase tracking-wider flex items-center justify-between">
                    <span>Nome da Rotina de Varredura DAST:</span>
                    <span className="text-zinc-500 text-[9px] font-normal">Identificador visível no log de auditoria</span>
                  </label>
                  <input
                    type="text"
                    value={newScheduleName}
                    onChange={(e) => setNewScheduleName(e.target.value)}
                    placeholder="Ex: Auditoria Contínua de APIs de Pagamento & Checkout (Cron Diário)"
                    className="w-full bg-black/70 border border-[#333] px-3.5 py-2.5 rounded-lg text-xs text-white focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                  />
                </div>

                {/* Registered API Endpoints Selection Box */}
                <div className="space-y-2 md:col-span-2 bg-[#080808] border border-[#222] p-4 rounded-xl">
                  <div className="flex flex-wrap items-center justify-between gap-2 pb-1 border-b border-zinc-800">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-emerald-400" />
                      <label className="text-[11px] font-bold text-zinc-200 uppercase tracking-wider block">
                        Endpoints Registrados para Fuzzing ({newTargetEndpoints.length} selecionados):
                      </label>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          const allAvailable = registeredEndpointsList.map(e => e.path);
                          setNewTargetEndpoints(Array.from(new Set([...newTargetEndpoints, ...allAvailable])));
                        }}
                        className="text-[10px] text-emerald-400 hover:text-emerald-300 cursor-pointer font-bold transition-colors"
                      >
                        + Selecionar Todos ({registeredEndpointsList.length})
                      </button>
                      <span className="text-zinc-700">|</span>
                      <button
                        type="button"
                        onClick={() => setNewTargetEndpoints([])}
                        className="text-[10px] text-zinc-500 hover:text-zinc-300 cursor-pointer transition-colors"
                      >
                        Limpar Seleção
                      </button>
                    </div>
                  </div>

                  {/* Search Filter for Registered Endpoints */}
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-2.5 pointer-events-none" />
                    <input
                      type="text"
                      value={endpointFilterSearch}
                      onChange={(e) => setEndpointFilterSearch(e.target.value)}
                      placeholder="Filtrar endpoints registrados (ex: /payments, POST, auth, admin)..."
                      className="w-full bg-black/70 border border-[#333] pl-8 pr-3 py-1.5 rounded text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-emerald-500"
                    />
                  </div>

                  {/* Discovered / Registered Endpoints list */}
                  <div className="max-h-48 overflow-y-auto space-y-1.5 pr-1 scrollbar-thin">
                    {registeredEndpointsList
                      .filter((ep: any) => {
                        if (!endpointFilterSearch.trim()) return true;
                        const q = endpointFilterSearch.toLowerCase();
                        return ep.path.toLowerCase().includes(q) || (ep.method || '').toLowerCase().includes(q);
                      })
                      .map((ep: any) => {
                        const isSelected = newTargetEndpoints.includes(ep.path);
                        return (
                          <div
                            key={ep.path}
                            onClick={() => {
                              if (isSelected) {
                                setNewTargetEndpoints(newTargetEndpoints.filter(p => p !== ep.path));
                              } else {
                                setNewTargetEndpoints([...newTargetEndpoints, ep.path]);
                              }
                            }}
                            className={`p-2.5 rounded-lg border flex items-center justify-between text-xs cursor-pointer transition-all ${
                              isSelected
                                ? 'bg-emerald-950/40 border-emerald-500/70 text-white shadow-sm'
                                : 'bg-black/60 border-[#222] text-zinc-400 hover:border-[#333] hover:text-zinc-200'
                            }`}
                          >
                            <div className="flex items-center gap-2.5 min-w-0">
                              <input
                                type="checkbox"
                                checked={isSelected}
                                onChange={() => {}} // handled by parent div
                                className="rounded accent-emerald-500 cursor-pointer shrink-0"
                              />
                              <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold shrink-0 ${
                                ep.method === 'POST' ? 'bg-blue-950 text-blue-300 border border-blue-800' :
                                ep.method === 'GET' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                                ep.method === 'PUT' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                                'bg-rose-950 text-rose-300 border border-rose-800'
                              }`}>
                                {ep.method || 'POST'}
                              </span>
                              <span className="font-mono text-zinc-200 truncate">{ep.path}</span>
                              {ep.params && ep.params.length > 0 && (
                                <span className="text-[10px] text-zinc-500 hidden sm:inline truncate">
                                  ({ep.params.length} params)
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              {ep.isInternalOrAdmin && (
                                <span className="text-[9px] px-1 rounded bg-amber-950/80 text-amber-400 border border-amber-800/60 font-bold">
                                  ADMIN
                                </span>
                              )}
                              {ep.riskScore && (
                                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                                  ep.riskScore >= 80 ? 'bg-rose-950/60 text-rose-300 border border-rose-800/40' :
                                  ep.riskScore >= 50 ? 'bg-amber-950/60 text-amber-300 border border-amber-800/40' :
                                  'bg-zinc-800 text-zinc-400'
                                }`}>
                                  Risco: {ep.riskScore}/100
                                </span>
                              )}
                            </div>
                          </div>
                        );
                      })}
                  </div>

                  {/* Add Custom Endpoint */}
                  <div className="flex items-center gap-2 pt-2 border-t border-white/5">
                    <input
                      type="text"
                      value={customEndpointInput}
                      onChange={(e) => setCustomEndpointInput(e.target.value)}
                      placeholder="/api/v1/custom-endpoint-or-webhook"
                      className="flex-1 bg-black/60 border border-[#333] px-3 py-1.5 rounded text-xs text-white focus:outline-none focus:border-emerald-500"
                    />
                    <button
                      type="button"
                      onClick={() => {
                        if (customEndpointInput.trim() && !newTargetEndpoints.includes(customEndpointInput.trim())) {
                          setNewTargetEndpoints([...newTargetEndpoints, customEndpointInput.trim()]);
                          setCustomEndpointInput('');
                        }
                      }}
                      className="px-3.5 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-white text-xs rounded font-bold cursor-pointer transition-colors"
                    >
                      + Adicionar Alvo
                    </button>
                  </div>
                </div>

                {/* Recurrence Interval Preset */}
                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-zinc-300 uppercase tracking-wider block">
                    Intervalo de Recorrência da Varredura:
                  </label>
                  <select
                    value={newIntervalPreset}
                    onChange={(e) => setNewIntervalPreset(e.target.value as ScheduleIntervalPreset)}
                    className="w-full bg-black/70 border border-[#333] px-3 py-2 rounded-lg text-xs text-white focus:outline-none focus:border-emerald-500 cursor-pointer"
                  >
                    {INTERVAL_PRESETS.map(p => (
                      <option key={p.preset} value={p.preset}>
                        {p.label} (Cron: {p.cronHint})
                      </option>
                    ))}
                  </select>
                  <span className="text-[10px] text-zinc-500 block">
                    Selecione &quot;Expressão Cron Personalizada&quot; para definir horários de produção, fins de semana ou intervalos customizados.
                  </span>
                </div>

                {/* HTTP Methods */}
                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-zinc-300 uppercase tracking-wider block">
                    Métodos HTTP a Testar no Fuzzing:
                  </label>
                  <div className="flex items-center gap-2 pt-0.5">
                    {(['GET', 'POST', 'PUT', 'DELETE'] as const).map(method => {
                      const isSelected = newHttpMethods.includes(method);
                      return (
                        <button
                          key={method}
                          type="button"
                          onClick={() => {
                            if (isSelected) {
                              if (newHttpMethods.length > 1) {
                                setNewHttpMethods(newHttpMethods.filter(m => m !== method));
                              }
                            } else {
                              setNewHttpMethods([...newHttpMethods, method]);
                            }
                          }}
                          className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition-colors cursor-pointer ${
                            isSelected
                              ? 'bg-emerald-600 text-white border-emerald-500 shadow-sm'
                              : 'bg-black/60 border-[#333] text-zinc-400 hover:text-white'
                          }`}
                        >
                          {method}
                        </button>
                      );
                    })}
                  </div>
                  <span className="text-[10px] text-zinc-500 block">
                    Ao menos um método HTTP deve estar ativo para a rota.
                  </span>
                </div>

                {/* Custom Cron Input & Real-Time Validation Box */}
                {newIntervalPreset === 'CRON' && (
                  <div className="space-y-3 md:col-span-2 p-4 bg-cyan-950/20 border-2 border-cyan-500/60 rounded-xl">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="p-1 rounded bg-cyan-500/20 text-cyan-300">
                          <Terminal className="w-3.5 h-3.5" />
                        </span>
                        <label className="text-xs font-bold text-cyan-300 uppercase tracking-wider block">
                          Expressão Cron Customizada (POSIX 5 Campos)
                        </label>
                      </div>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-900/50 text-cyan-300 border border-cyan-700/60 font-mono font-bold">
                        Cron Engine Active
                      </span>
                    </div>

                    <div className="space-y-1.5">
                      <input
                        type="text"
                        value={newCustomCron}
                        onChange={(e) => setNewCustomCron(e.target.value)}
                        placeholder="Ex: 0 */4 * * *"
                        className={`w-full bg-black border px-3.5 py-2.5 rounded-lg text-sm text-cyan-300 font-mono focus:outline-none ${
                          cronValidation.isValid 
                            ? 'border-cyan-500/70 focus:ring-1 focus:ring-cyan-400' 
                            : 'border-rose-500 focus:ring-1 focus:ring-rose-500'
                        }`}
                      />

                      {/* Real-time Cron Validation Status Box */}
                      {cronValidation.isValid ? (
                        <div className="p-2.5 rounded bg-emerald-950/40 border border-emerald-500/60 text-emerald-300 text-xs flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                            <div>
                              <strong>Cron Válido:</strong> {cronValidation.description}
                            </div>
                          </div>
                          <span className="text-[10px] text-emerald-400/80 font-mono shrink-0">
                            ~{cronValidation.estimatedMinutes}min de cadência
                          </span>
                        </div>
                      ) : (
                        <div className="p-2.5 rounded bg-rose-950/50 border border-rose-500/60 text-rose-300 text-xs flex items-center gap-2">
                          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                          <div>
                            <strong>Erro de Sintaxe Cron:</strong> {cronValidation.error}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Quick Cron Preset Templates */}
                    <div className="space-y-1.5 pt-1">
                      <span className="text-[9.5px] text-zinc-400 block uppercase font-bold">
                        Modelos Rápidos Populares (Clique para preencher a expressão):
                      </span>
                      <div className="flex flex-wrap gap-2">
                        {COMMON_CRON_TEMPLATES.map((tmpl) => (
                          <button
                            key={tmpl.cron}
                            type="button"
                            onClick={() => setNewCustomCron(tmpl.cron)}
                            className={`px-2.5 py-1 rounded text-[10.5px] font-mono border transition-all cursor-pointer ${
                              newCustomCron === tmpl.cron
                                ? 'bg-cyan-500 text-black border-cyan-400 font-bold shadow'
                                : 'bg-black/60 text-zinc-300 border-zinc-700 hover:border-cyan-400 hover:text-white'
                            }`}
                            title={tmpl.desc}
                          >
                            <span>{tmpl.label}</span>
                            <span className="text-[9.5px] opacity-75 ml-1">({tmpl.cron})</span>
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* 5-Field Syntax Hint Graphic */}
                    <div className="text-[10px] text-zinc-400 bg-black/70 p-2.5 rounded-lg border border-zinc-800 flex items-center justify-between flex-wrap gap-2 font-mono">
                      <span>┌─ <strong>min</strong> (0-59)</span>
                      <span>┌─ <strong>hora</strong> (0-23)</span>
                      <span>┌─ <strong>dia do mês</strong> (1-31)</span>
                      <span>┌─ <strong>mês</strong> (1-12)</span>
                      <span>┌─ <strong>dia da semana</strong> (0-6)</span>
                    </div>
                  </div>
                )}

                {/* Attack Categories Multi-select */}
                <div className="space-y-1.5 md:col-span-2">
                  <label className="text-[10px] font-bold text-zinc-300 uppercase tracking-wider block">
                    Categorias de Ataque DAST a Injetar nas Execuções:
                  </label>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {[
                      { id: 'SQL_INJECTION', label: 'SQL Injection (SQLi)' },
                      { id: 'NOSQL_INJECTION', label: 'NoSQL Injection (MongoDB)' },
                      { id: 'XSS', label: 'Cross-Site Scripting (XSS)' },
                      { id: 'PATH_TRAVERSAL', label: 'Path Traversal (/etc/passwd)' },
                      { id: 'SSRF', label: 'Server-Side Request Forgery' },
                      { id: 'COMMAND_INJECTION', label: 'Command Injection (Bash)' }
                    ].map(cat => {
                      const isChecked = newAttackCategories.includes(cat.id as AttackCategory);
                      return (
                        <button
                          key={cat.id}
                          type="button"
                          onClick={() => {
                            if (isChecked) {
                              if (newAttackCategories.length > 1) {
                                setNewAttackCategories(newAttackCategories.filter(c => c !== cat.id));
                              }
                            } else {
                              setNewAttackCategories([...newAttackCategories, cat.id as AttackCategory]);
                            }
                          }}
                          className={`p-2.5 rounded-lg border text-left text-xs transition-colors cursor-pointer ${
                            isChecked
                              ? 'bg-emerald-950/40 border-emerald-500 text-white'
                              : 'bg-black/40 border-[#222] text-zinc-500 hover:text-zinc-300'
                          }`}
                        >
                          <div className="flex items-center gap-2">
                            <span className={`w-2 h-2 rounded-full ${isChecked ? 'bg-emerald-400' : 'bg-zinc-600'}`} />
                            <span className="font-bold">{cat.label}</span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Advanced Options & Alert Channels */}
                <div className="space-y-3 md:col-span-2 pt-2 border-t border-white/5">
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="stopOnVuln"
                      checked={newStopOnVuln}
                      onChange={(e) => setNewStopOnVuln(e.target.checked)}
                      className="rounded accent-emerald-500 cursor-pointer"
                    />
                    <label htmlFor="stopOnVuln" className="text-xs text-zinc-300 cursor-pointer">
                      Pausar agendador automaticamente se alguma vulnerabilidade de severidade crítica for confirmada
                    </label>
                  </div>

                  <div className="flex items-center gap-4 text-xs text-zinc-400 flex-wrap">
                    <span className="text-zinc-500 font-bold">Canais de Alerta:</span>
                    <label className="flex items-center gap-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={newAlertChannels.includes('IN_APP')}
                        onChange={(e) => {
                          if (e.target.checked) setNewAlertChannels([...newAlertChannels, 'IN_APP']);
                          else setNewAlertChannels(newAlertChannels.filter(c => c !== 'IN_APP'));
                        }}
                        className="accent-emerald-500"
                      />
                      <span>In-App Banner</span>
                    </label>
                    <label className="flex items-center gap-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={newAlertChannels.includes('SLACK_WEBHOOK')}
                        onChange={(e) => {
                          if (e.target.checked) setNewAlertChannels([...newAlertChannels, 'SLACK_WEBHOOK']);
                          else setNewAlertChannels(newAlertChannels.filter(c => c !== 'SLACK_WEBHOOK'));
                        }}
                        className="accent-emerald-500"
                      />
                      <span>Webhook Slack</span>
                    </label>
                    <label className="flex items-center gap-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={newAlertChannels.includes('SOAR_PLAYBOOK')}
                        onChange={(e) => {
                          if (e.target.checked) setNewAlertChannels([...newAlertChannels, 'SOAR_PLAYBOOK']);
                          else setNewAlertChannels(newAlertChannels.filter(c => c !== 'SOAR_PLAYBOOK'));
                        }}
                        className="accent-emerald-500"
                      />
                      <span>Gatilho SOAR Playbook</span>
                    </label>
                  </div>
                </div>
              </div>

              {/* Submit Buttons */}
              <div className="flex items-center justify-end gap-3 pt-3 border-t border-[#222]">
                <button
                  type="button"
                  onClick={handleCancelForm}
                  className="px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-bold cursor-pointer transition-colors"
                >
                  Cancelar
                </button>
                <button
                  type="button"
                  onClick={handleSaveOrUpdateSchedule}
                  className="px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold uppercase tracking-wider flex items-center gap-2 cursor-pointer shadow transition-colors"
                >
                  <Check className="w-4 h-4" />
                  <span>{editingScheduleId ? 'Salvar Alterações no Agendamento' : 'Salvar & Ativar Agendamento'}</span>
                </button>
              </div>
            </div>
          )}

          {/* Import JSON Modal */}
          {isImportModalOpen && (
            <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
              <div className="bg-[#111] border border-cyan-500/60 rounded-xl p-5 max-w-xl w-full space-y-4 shadow-2xl font-mono">
                <div className="flex items-center justify-between pb-2 border-b border-[#222]">
                  <div className="flex items-center gap-2 text-cyan-400">
                    <Upload className="w-4 h-4" />
                    <h3 className="font-bold text-sm text-white uppercase">Importar Agendamentos DAST (JSON)</h3>
                  </div>
                  <button
                    onClick={() => setIsImportModalOpen(false)}
                    className="text-zinc-500 hover:text-white text-xs cursor-pointer"
                  >
                    ✕
                  </button>
                </div>
                <p className="text-xs text-zinc-400">
                  Cole uma lista JSON de agendamentos contendo campos como <code className="text-cyan-300">name</code>, <code className="text-cyan-300">intervalPreset</code>, <code className="text-cyan-300">cronExpression</code> e <code className="text-cyan-300">targetEndpoints</code>:
                </p>
                <textarea
                  value={importJsonText}
                  onChange={(e) => setImportJsonText(e.target.value)}
                  placeholder="[{ &quot;id&quot;: &quot;sched-1&quot;, &quot;name&quot;: &quot;Scan Diário&quot;, &quot;cronExpression&quot;: &quot;0 2 * * *&quot;, ... }]"
                  rows={8}
                  className="w-full bg-black/80 border border-[#333] p-3 rounded-lg text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-400"
                />
                <div className="flex justify-end gap-2">
                  <button
                    onClick={() => setIsImportModalOpen(false)}
                    className="px-3 py-1.5 rounded bg-zinc-800 text-zinc-300 text-xs font-bold cursor-pointer"
                  >
                    Cancelar
                  </button>
                  <button
                    onClick={() => handleImportJson(importJsonText)}
                    className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-black font-bold text-xs cursor-pointer"
                  >
                    Carregar Agendamentos
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* RECENT EXECUTION LOG (PERSISTED LAST 10 SCAN RESULTS FROM SCHEDULER)     */}
          {/* ========================================================================= */}
          <div id="recent-execution-log" className="space-y-4 pt-4 border-t border-[#222]">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                    Recent Execution Log
                  </h3>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950/60 border border-cyan-700/60 text-cyan-300 font-mono">
                    Últimas {filteredRecentRecords.length} de {recentRecords.length} (Max 10)
                  </span>
                  <span className="hidden md:inline-flex items-center gap-1 text-[10px] text-emerald-400 bg-emerald-950/40 border border-emerald-800/40 px-2 py-0.5 rounded">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                    Persistido no LocalStorage
                  </span>
                </div>
                <p className="text-[11px] text-zinc-400">
                  Histórico contínuo das últimas 10 execuções do agendador automático e manual de fuzzing DAST.
                </p>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                {/* Filter Selector */}
                <div className="flex items-center bg-black border border-[#333] rounded-lg p-0.5 text-xs">
                  <button
                    onClick={() => setHistoryFilter('ALL')}
                    className={`px-2.5 py-1 rounded cursor-pointer transition-colors ${historyFilter === 'ALL' ? 'bg-zinc-800 text-white font-bold' : 'text-zinc-500 hover:text-zinc-300'}`}
                  >
                    Todos ({recentRecords.length})
                  </button>
                  <button
                    onClick={() => setHistoryFilter('VULNERABLE')}
                    className={`px-2.5 py-1 rounded cursor-pointer transition-colors ${historyFilter === 'VULNERABLE' ? 'bg-rose-950 text-rose-300 font-bold' : 'text-zinc-500 hover:text-zinc-300'}`}
                  >
                    Vulns ({recentVulnCount})
                  </button>
                  <button
                    onClick={() => setHistoryFilter('WARNING')}
                    className={`px-2.5 py-1 rounded cursor-pointer transition-colors ${historyFilter === 'WARNING' ? 'bg-amber-950 text-amber-300 font-bold' : 'text-zinc-500 hover:text-zinc-300'}`}
                  >
                    WAF / Alertas ({recentWafCount})
                  </button>
                </div>

                <button
                  onClick={handleExportCsv}
                  disabled={recentRecords.length === 0}
                  className="px-2.5 py-1.5 bg-zinc-900 hover:bg-zinc-800 border border-[#333] text-zinc-300 hover:text-white rounded text-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-40 transition-colors"
                  title="Exportar últimos 10 resultados para CSV"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>CSV</span>
                </button>

                <button
                  onClick={handleClearExecutionLog}
                  disabled={recentRecords.length === 0}
                  className="px-2.5 py-1.5 bg-zinc-900 hover:bg-rose-950/80 border border-[#333] hover:border-rose-900/60 text-zinc-400 hover:text-rose-300 rounded text-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-40 transition-colors"
                  title="Limpar registros salvos no Local Storage"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Limpar</span>
                </button>

                <button
                  onClick={handleRestoreDefaultExecutionLogs}
                  className="px-2.5 py-1.5 bg-zinc-900 hover:bg-zinc-800 border border-[#333] text-zinc-400 hover:text-cyan-300 rounded text-xs flex items-center gap-1.5 cursor-pointer transition-colors"
                  title="Restaurar as 10 amostras padrão de execução"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Amostras</span>
                </button>
              </div>
            </div>

            {/* Quick Summary Strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
              <div className="p-2 rounded bg-black/60 border border-zinc-800/80 flex items-center justify-between">
                <span className="text-zinc-500 text-[10px]">Capacidade:</span>
                <span className="font-bold text-zinc-200">{recentRecords.length} / 10 scans</span>
              </div>
              <div className="p-2 rounded bg-black/60 border border-zinc-800/80 flex items-center justify-between">
                <span className="text-zinc-500 text-[10px]">Vulneráveis:</span>
                <span className={`font-bold ${recentVulnCount > 0 ? 'text-rose-400' : 'text-zinc-400'}`}>
                  {recentVulnCount}
                </span>
              </div>
              <div className="p-2 rounded bg-black/60 border border-zinc-800/80 flex items-center justify-between">
                <span className="text-zinc-500 text-[10px]">WAF Blocks:</span>
                <span className={`font-bold ${recentWafCount > 0 ? 'text-amber-400' : 'text-zinc-400'}`}>
                  {recentWafCount}
                </span>
              </div>
              <div className="p-2 rounded bg-black/60 border border-zinc-800/80 flex items-center justify-between">
                <span className="text-zinc-500 text-[10px]">100% Seguros:</span>
                <span className="font-bold text-emerald-400">{recentSafeCount}</span>
              </div>
            </div>

            {/* Recent Execution Records List */}
            {filteredRecentRecords.length === 0 ? (
              <div className="p-8 text-center bg-[#0C0C0C] border border-[#222] rounded-xl text-xs text-zinc-500 space-y-3">
                <p>Nenhuma execução recente encontrada para o filtro atual.</p>
                <div className="flex items-center justify-center gap-3">
                  <button
                    onClick={handleRestoreDefaultExecutionLogs}
                    className="px-3 py-1.5 rounded bg-cyan-950/60 border border-cyan-700/60 text-cyan-300 font-bold hover:bg-cyan-900/60 cursor-pointer text-xs"
                  >
                    Restaurar 10 Amostras Padrão
                  </button>
                  {schedules.length > 0 && (
                    <button
                      onClick={() => triggerScheduleExecution(schedules[0].id, false)}
                      className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold cursor-pointer text-xs flex items-center gap-1.5"
                    >
                      <Play className="w-3.5 h-3.5" />
                      <span>Executar "{schedules[0].name}" Agora</span>
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredRecentRecords.map((record, idx) => {
                  const hasVuln = record.vulnerabilitiesFound > 0;
                  const isExpanded = expandedRecordId === record.id;

                  return (
                    <div
                      key={record.id}
                      className={`rounded-xl border transition-all ${
                        hasVuln
                          ? 'bg-[#0F0708] border-rose-900/60 hover:border-rose-700'
                          : record.blockedByWafCount > 0
                          ? 'bg-[#0F0C07] border-amber-900/50 hover:border-amber-700'
                          : 'bg-[#080E0A] border-emerald-950/60 hover:border-emerald-800'
                      }`}
                    >
                      <div
                        onClick={() => setExpandedRecordId(isExpanded ? null : record.id)}
                        className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer hover:bg-white/[0.02]"
                      >
                        <div className="space-y-1.5">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="px-1.5 py-0.2 rounded text-[9.5px] font-mono font-bold bg-zinc-800 text-zinc-300 border border-zinc-700">
                              #{idx + 1} {idx === 0 ? '(Mais Recente)' : ''}
                            </span>
                            <span className={`px-2 py-0.2 rounded text-[10px] font-bold uppercase tracking-wider ${
                              hasVuln
                                ? 'bg-rose-600 text-white animate-pulse'
                                : record.blockedByWafCount > 0
                                ? 'bg-amber-600 text-white'
                                : 'bg-emerald-600 text-white'
                            }`}>
                              {hasVuln ? `${record.vulnerabilitiesFound} VULN(S)` : record.blockedByWafCount > 0 ? 'WAF BLOCKED' : '100% SEGURO'}
                            </span>
                            <span className="text-xs font-bold text-white">{record.scheduleName}</span>
                            <span className="text-[10px] text-zinc-500 font-mono">({record.durationMs}ms)</span>
                          </div>

                          <div className="text-[11px] text-zinc-400">
                            Endpoints testados: <span className="text-zinc-200">{record.endpointsTestedCount}</span> &bull; Payloads enviados: <span className="text-zinc-200">{record.payloadsSentCount}</span> &bull; Seguro: <span className="text-emerald-400">{record.safeCount}</span> &bull; WAF: <span className="text-amber-400">{record.blockedByWafCount}</span>
                          </div>
                        </div>

                        <div className="flex items-center gap-3">
                          <span className="text-[10px] text-zinc-500 font-mono flex items-center gap-1">
                            <Clock className="w-3 h-3 text-zinc-600" />
                            {record.timestamp}
                          </span>
                          {isExpanded ? <ChevronUp className="w-4 h-4 text-zinc-400" /> : <ChevronDown className="w-4 h-4 text-zinc-400" />}
                        </div>
                      </div>

                      {/* Expanded Drilldown Results */}
                      {isExpanded && (
                        <div className="p-4 border-t border-white/5 space-y-3 bg-black/60">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] text-zinc-400 uppercase font-bold block">
                              Detalhamento dos Testes Dinâmicos Executados:
                            </span>
                            <code className="text-[9.5px] text-zinc-500 font-mono">ID: {record.id}</code>
                          </div>

                          <div className="space-y-2">
                            {record.results.map((res, resIdx) => (
                              <div
                                key={resIdx}
                                className="p-2.5 rounded bg-black/80 border border-[#222] text-xs space-y-1"
                              >
                                <div className="flex items-center justify-between">
                                  <div className="flex items-center gap-2">
                                    <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                                      res.verdict === 'VULNERABLE' ? 'bg-rose-600 text-white' :
                                      res.verdict === 'BLOCKED_BY_WAF' ? 'bg-amber-600 text-white' :
                                      'bg-emerald-600 text-white'
                                    }`}>
                                      {res.verdict}
                                    </span>
                                    <span className="text-zinc-200 font-bold">{res.method} {res.endpoint}</span>
                                    <span className="text-[10px] text-zinc-500">HTTP {res.simulatedStatus}</span>
                                  </div>
                                  <span className="text-[10px] text-zinc-500">{res.simulatedResponseTimeMs}ms</span>
                                </div>
                                <div className="text-[11px] text-zinc-400 font-mono">
                                  <span className="text-zinc-500">Payload: </span>
                                  <code className="text-emerald-300">{res.payload.payload}</code>
                                </div>
                                <div className="text-[10.5px] text-zinc-500 italic">
                                  &rarr; {res.analysis}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* List of Recurring Schedules */}
          <div id="active-schedules-list" className="space-y-3 pt-6 border-t border-[#222]">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-zinc-400 uppercase tracking-wider flex items-center gap-2">
                <Calendar className="w-4 h-4 text-emerald-400" />
                Rotinas de Varredura Agendadas ({schedules.length})
              </h3>
            </div>

            <div className="grid grid-cols-1 gap-4">
              {schedules.map(schedule => {
                const isRunning = executingScheduleId === schedule.id || schedule.status === 'RUNNING';
                const countdown = formatCountdown(schedule.nextRunAt);

                return (
                  <div
                    key={schedule.id}
                    className={`p-5 rounded-xl border transition-all ${
                      isRunning
                        ? 'bg-[#0E0C07] border-cyan-500 shadow-[0_0_15px_rgba(6,182,212,0.15)]'
                        : schedule.enabled
                        ? 'bg-[#0F0F0F] border-[#222] hover:border-[#333]'
                        : 'bg-[#0A0A0A] border-[#1A1A1A] opacity-75'
                    }`}
                  >
                    <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                      <div className="space-y-2 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <button
                            onClick={() => handleToggleSchedule(schedule.id)}
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border cursor-pointer ${
                              schedule.enabled
                                ? 'bg-emerald-950/60 text-emerald-400 border-emerald-700/60'
                                : 'bg-zinc-800 text-zinc-400 border-zinc-700'
                            }`}
                          >
                            {schedule.enabled ? 'ATIVO' : 'PAUSADO'}
                          </button>

                          <h4 className="text-sm font-bold text-white">{schedule.name}</h4>

                          <span className="text-[10px] px-2 py-0.5 rounded bg-black/60 text-cyan-300 border border-cyan-800/40 font-bold">
                            {schedule.intervalLabel}
                          </span>

                          {schedule.cronExpression && (
                            <code className="text-[10px] text-zinc-500 bg-black/50 px-1.5 py-0.2 rounded border border-zinc-800">
                              cron: {schedule.cronExpression}
                            </code>
                          )}
                        </div>

                        {/* Endpoints & Methods Pills */}
                        <div className="flex items-center gap-1.5 flex-wrap text-xs">
                          <span className="text-[10px] text-zinc-500 uppercase">Alvos ({schedule.targetEndpoints.length}):</span>
                          {schedule.targetEndpoints.map(ep => (
                            <span key={ep} className="px-2 py-0.5 rounded bg-black/70 border border-[#222] text-zinc-300 text-[10.5px]">
                              {ep}
                            </span>
                          ))}
                        </div>

                        {/* Attack Categories */}
                        <div className="flex items-center gap-1.5 flex-wrap text-xs">
                          <span className="text-[10px] text-zinc-500 uppercase">Ataques:</span>
                          {schedule.attackCategories.map(cat => (
                            <span key={cat} className="px-1.5 py-0.2 rounded bg-zinc-900 text-zinc-400 text-[9.5px]">
                              {cat}
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* Right Action & Countdown Column */}
                      <div className="flex flex-col sm:flex-row sm:items-center gap-4 shrink-0 lg:border-l lg:border-white/5 lg:pl-5">
                        <div className="text-right sm:text-left space-y-0.5">
                          <span className="text-[10px] text-zinc-500 uppercase block">Próxima Execução</span>
                          {schedule.enabled ? (
                            <div className="text-xs font-bold text-emerald-300 flex items-center gap-1.5">
                              <Clock className="w-3.5 h-3.5 text-cyan-400" />
                              <span>{countdown.formatted}</span>
                            </div>
                          ) : (
                            <div className="text-xs text-zinc-500">Pausado</div>
                          )}
                          <div className="text-[10px] text-zinc-600">
                            Execuções: <span className="text-zinc-400">{schedule.totalRuns}</span> &bull; Vulns: <span className={schedule.vulnerabilitiesDetected > 0 ? 'text-rose-400 font-bold' : 'text-zinc-400'}>{schedule.vulnerabilitiesDetected}</span>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => triggerScheduleExecution(schedule.id, false)}
                            disabled={isRunning}
                            className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 cursor-pointer shadow transition-colors"
                            title="Disparar execução agora"
                          >
                            <Play className={`w-3.5 h-3.5 ${isRunning ? 'animate-spin' : ''}`} />
                            <span>{isRunning ? 'Executando...' : 'Executar Agora'}</span>
                          </button>

                          <button
                            onClick={() => handleStartEditSchedule(schedule)}
                            className="p-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 hover:text-white cursor-pointer transition-colors"
                            title="Editar configuração do agendamento"
                          >
                            <Edit3 className="w-4 h-4" />
                          </button>

                          <button
                            onClick={() => handleToggleSchedule(schedule.id)}
                            className="p-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 hover:text-white cursor-pointer transition-colors"
                            title={schedule.enabled ? 'Pausar agendamento' : 'Ativar agendamento'}
                          >
                            {schedule.enabled ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                          </button>

                          <button
                            onClick={() => handleDeleteSchedule(schedule.id)}
                            className="p-1.5 rounded-lg bg-zinc-900 hover:bg-rose-950/80 text-zinc-400 hover:text-rose-400 border border-transparent hover:border-rose-800/40 cursor-pointer transition-colors"
                            title="Excluir agendamento"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUBTAB 3: HTTP SECURITY HEADERS AUDITOR                                   */}
      {/* ========================================================================= */}
      {activeSubTab === 'HEADERS' && (
        <div className="space-y-6 font-mono">
          {/* Grade Card */}
          <div className="bg-[#0C0C0C] border border-[#222] rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider block">Nota de Cabeçalhos HTTP</span>
              <h2 className="text-2xl font-bold text-white">Auditoria OWASP Secure Headers</h2>
              <p className="text-xs text-zinc-400">Proteção contra XSS, Clickjacking, MIME-sniffing e downgrade de SSL.</p>
            </div>

            <div className="flex items-center gap-4">
              <div className="text-right">
                <span className="text-xs text-zinc-500 block">Pontuação</span>
                <span className="text-xl font-bold text-white">{headersAudit.score}/100</span>
              </div>
              <div className={`w-14 h-14 rounded-2xl flex items-center justify-center font-bold text-2xl border-2 ${
                headersAudit.grade === 'A+' || headersAudit.grade === 'A'
                  ? 'bg-emerald-950/40 text-emerald-400 border-emerald-500'
                  : headersAudit.grade === 'B' || headersAudit.grade === 'C'
                  ? 'bg-amber-950/40 text-amber-400 border-amber-500'
                  : 'bg-rose-950/40 text-rose-500 border-rose-500'
              }`}>
                {headersAudit.grade}
              </div>
            </div>
          </div>

          {/* Headers Checklist */}
          <div className="space-y-3">
            {headersAudit.headers.map(header => {
              const isPresent = header.status === 'PRESENT';
              const isWeak = header.status === 'WEAK';

              return (
                <div
                  key={header.header}
                  className={`p-4 rounded-xl border ${
                    isPresent
                      ? 'bg-[#070E0A] border-emerald-900/40'
                      : isWeak
                      ? 'bg-[#0E0B07] border-amber-900/40'
                      : 'bg-[#0E0708] border-rose-900/40'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold text-sm text-white">{header.header}</span>
                        <span className={`px-2 py-0.2 rounded text-[10px] font-bold ${
                          isPresent ? 'bg-emerald-900 text-emerald-200' : isWeak ? 'bg-amber-900 text-amber-200' : 'bg-rose-900 text-rose-200'
                        }`}>
                          {header.status}
                        </span>
                        <span className="text-[10px] text-zinc-500">{header.importance}</span>
                      </div>
                      <p className="text-xs text-zinc-400">{header.description}</p>
                    </div>

                    <span className="text-[10px] text-zinc-500 shrink-0">{header.cwe}</span>
                  </div>

                  <div className="mt-3 pt-2.5 border-t border-white/5 space-y-1 text-xs">
                    {header.currentValue && (
                      <div className="text-[11px] text-zinc-400">
                        <span className="text-zinc-500">Valor Atual: </span>
                        <code>{header.currentValue}</code>
                      </div>
                    )}
                    <div className="text-[11px] text-emerald-400">
                      <span className="text-zinc-500">Valor Recomendado: </span>
                      <code>{header.recommendedValue}</code>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Remediation Snippet */}
          <div className="bg-[#0C0C0C] border border-[#222] rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-zinc-300 uppercase tracking-wider">
                Middleware Recomendado para Nota A+ (Helmet / Express):
              </span>
              <button
                onClick={() => handleCopyCode(headersAudit.recommendedMiddlewareCode)}
                className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedCode ? 'Copiado!' : 'Copiar Snippet'}</span>
              </button>
            </div>
            <pre className="p-3 bg-black rounded-lg text-emerald-300 text-xs overflow-x-auto border border-white/5">
              <code>{headersAudit.recommendedMiddlewareCode}</code>
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
