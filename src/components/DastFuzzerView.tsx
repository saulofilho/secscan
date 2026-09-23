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
  CheckCircle
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
  DEFAULT_RECURRING_SCHEDULES,
  calculateNextRunTime,
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

export const DastFuzzerView: React.FC<DastFuzzerViewProps> = ({ endpoints, onLogAudit }) => {
  const [activeSubTab, setActiveSubTab] = useState<'FUZZER' | 'SCHEDULER' | 'HEADERS'>('FUZZER');
  
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
      const saved = localStorage.getItem(STORAGE_KEY_RECORDS);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch (e) {
      console.warn('Failed to load saved execution records', e);
    }
    return [];
  });

  const [isSchedulerDaemonActive, setIsSchedulerDaemonActive] = useState(true);
  const [executingScheduleId, setExecutingScheduleId] = useState<string | null>(null);
  const [expandedRecordId, setExpandedRecordId] = useState<string | null>(null);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [copiedScheduleJson, setCopiedScheduleJson] = useState(false);
  const [historyFilter, setHistoryFilter] = useState<'ALL' | 'VULNERABLE' | 'WARNING'>('ALL');
  const [toastNotification, setToastNotification] = useState<{ message: string; type: 'success' | 'alert' | 'info' } | null>(null);

  // New Schedule Form State
  const [newScheduleName, setNewScheduleName] = useState('');
  const [newTargetEndpoints, setNewTargetEndpoints] = useState<string[]>([]);
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
      localStorage.setItem(STORAGE_KEY_RECORDS, JSON.stringify(executionRecords.slice(0, 50)));
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
      
      setExecutionRecords(prev => [record, ...prev].slice(0, 50));
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

  // Create new schedule submission
  const handleCreateSchedule = () => {
    if (!newScheduleName.trim()) {
      showToast('Por favor, informe o nome do agendamento.', 'alert');
      return;
    }

    const selectedEndpoints = newTargetEndpoints.length > 0
      ? newTargetEndpoints
      : endpoints.length > 0
      ? [endpoints[0].path]
      : ['/api/v1/resource'];

    const presetConfig = INTERVAL_PRESETS.find(p => p.preset === newIntervalPreset) || INTERVAL_PRESETS[1];
    const minutes = presetConfig.minutes;

    const newSched: RecurringScanSchedule = {
      id: `sched-${Date.now()}`,
      name: newScheduleName.trim(),
      enabled: true,
      targetEndpoints: selectedEndpoints,
      httpMethods: newHttpMethods.length > 0 ? newHttpMethods : ['GET', 'POST'],
      attackCategories: newAttackCategories.length > 0 ? newAttackCategories : ['SQL_INJECTION'],
      intervalPreset: newIntervalPreset,
      intervalMinutes: minutes,
      cronExpression: newIntervalPreset === 'CRON' ? newCustomCron : presetConfig.cronHint,
      intervalLabel: newIntervalPreset === 'CRON' ? `Cron (${newCustomCron})` : presetConfig.label,
      createdAt: new Date().toISOString(),
      nextRunAt: calculateNextRunTime(minutes),
      totalRuns: 0,
      vulnerabilitiesDetected: 0,
      stopOnCriticalVuln: newStopOnVuln,
      alertChannels: newAlertChannels,
      status: 'IDLE'
    };

    setSchedules(prev => [newSched, ...prev]);
    setIsCreateModalOpen(false);
    setNewScheduleName('');
    setNewTargetEndpoints([]);
    showToast(`Agendamento "${newSched.name}" criado com sucesso! Próxima execução em ${minutes}m.`, 'success');

    if (onLogAudit) {
      onLogAudit({
        id: `audit-sched-create-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString(),
        action: `Novo agendador DAST criado: "${newSched.name}" (${newSched.intervalLabel}).`,
        user: 'SecOps-Operator',
        status: 'SUCCESS'
      });
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
    const csv = exportScanHistoryToCsv(executionRecords);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `dast-scheduled-scans-${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast('Histórico exportado em CSV.', 'success');
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

  // Filtered records
  const filteredExecutionRecords = useMemo(() => {
    if (historyFilter === 'VULNERABLE') {
      return executionRecords.filter(r => r.vulnerabilitiesFound > 0);
    }
    if (historyFilter === 'WARNING') {
      return executionRecords.filter(r => r.blockedByWafCount > 0 || r.vulnerabilitiesFound > 0);
    }
    return executionRecords;
  }, [executionRecords, historyFilter]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
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
            onClick={() => setActiveSubTab('SCHEDULER')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer border flex items-center gap-1.5 ${
              activeSubTab === 'SCHEDULER'
                ? 'bg-emerald-600 text-white border-emerald-500 shadow'
                : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
            }`}
          >
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Agendador Recorrente</span>
            <span className="text-[9px] px-1.5 py-0.2 bg-black/40 rounded text-cyan-300 font-bold">
              {schedules.length}
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
        <div className="space-y-6 font-mono">
          {/* Top Control Bar & Metrics */}
          <div className="bg-[#0C0C0C] border border-[#222] rounded-xl p-5 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#222]">
              <div>
                <div className="flex items-center gap-2">
                  <span className="p-1.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                    <Clock className="w-4 h-4" />
                  </span>
                  <h2 className="text-lg font-bold text-white uppercase">
                    Motor de Agendamento Recorrente de DAST
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
                  Executa varreduras automatizadas nos intervalos configurados contra endpoints de produção e staging com emissão de alertas e trilha de auditoria.
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
                >
                  {isSchedulerDaemonActive ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                  <span>{isSchedulerDaemonActive ? 'Pausar Daemon' : 'Iniciar Daemon'}</span>
                </button>

                <button
                  onClick={handleExportJson}
                  className="px-3 py-1.5 rounded-lg text-xs font-bold bg-[#1A1A1A] hover:bg-[#252525] border border-[#333] text-zinc-300 hover:text-white flex items-center gap-1.5 cursor-pointer transition-colors"
                >
                  {copiedScheduleJson ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Exportar JSON</span>
                </button>

                <button
                  onClick={() => setIsCreateModalOpen(true)}
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

          {/* New Schedule Modal / Drawer */}
          {isCreateModalOpen && (
            <div className="bg-[#0C0C0C] border-2 border-emerald-500/60 rounded-xl p-5 space-y-4 animate-fadeIn shadow-2xl">
              <div className="flex items-center justify-between pb-3 border-b border-[#222]">
                <div className="flex items-center gap-2">
                  <span className="p-1.5 rounded bg-emerald-500/20 text-emerald-400">
                    <Plus className="w-4 h-4" />
                  </span>
                  <h3 className="text-base font-bold text-white uppercase">
                    Configurar Novo Agendador de Varredura DAST
                  </h3>
                </div>
                <button
                  onClick={() => setIsCreateModalOpen(false)}
                  className="text-zinc-400 hover:text-white text-xs px-2 py-1 cursor-pointer"
                >
                  ✕ Fechar
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Schedule Name */}
                <div className="space-y-1 md:col-span-2">
                  <label className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">
                    Nome da Rotina de Teste:
                  </label>
                  <input
                    type="text"
                    value={newScheduleName}
                    onChange={(e) => setNewScheduleName(e.target.value)}
                    placeholder="Ex: Auditoria Contínua de APIs de Pagamento & Checkout"
                    className="w-full bg-black/70 border border-[#333] px-3 py-2 rounded-lg text-xs text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>

                {/* Target Endpoints Selection */}
                <div className="space-y-2 md:col-span-2 bg-black/40 border border-[#222] p-3 rounded-lg">
                  <div className="flex items-center justify-between">
                    <label className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">
                      Endpoints Alvo para Fuzzing Recorrente:
                    </label>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => setNewTargetEndpoints(endpoints.map(e => e.path))}
                        className="text-[10px] text-emerald-400 hover:underline cursor-pointer"
                      >
                        Selecionar Todos ({endpoints.length})
                      </button>
                      <span className="text-zinc-600">|</span>
                      <button
                        type="button"
                        onClick={() => setNewTargetEndpoints([])}
                        className="text-[10px] text-zinc-500 hover:underline cursor-pointer"
                      >
                        Limpar
                      </button>
                    </div>
                  </div>

                  {/* Discovered Endpoints list */}
                  <div className="max-h-36 overflow-y-auto space-y-1.5 pr-1 scrollbar-thin">
                    {(endpoints.length > 0 ? endpoints : [
                      { path: '/api/v1/payments/charge', method: 'POST', riskScore: 88 },
                      { path: '/api/v1/auth/login', method: 'POST', riskScore: 75 },
                      { path: '/api/v1/users/profile', method: 'GET', riskScore: 40 },
                      { path: '/api/v1/files/export', method: 'GET', riskScore: 82 }
                    ]).map((ep: any) => {
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
                          className={`p-2 rounded border flex items-center justify-between text-xs cursor-pointer transition-colors ${
                            isSelected
                              ? 'bg-emerald-950/30 border-emerald-500 text-white'
                              : 'bg-black/50 border-[#222] text-zinc-400 hover:text-zinc-200'
                          }`}
                        >
                          <div className="flex items-center gap-2">
                            <input
                              type="checkbox"
                              checked={isSelected}
                              readOnly
                              className="rounded accent-emerald-500 cursor-pointer"
                            />
                            <span className="text-[10px] px-1.5 py-0.2 bg-zinc-800 rounded font-bold text-emerald-400">
                              {ep.method || 'POST'}
                            </span>
                            <span className="font-mono text-zinc-200">{ep.path}</span>
                          </div>
                          {ep.riskScore && (
                            <span className="text-[10px] text-zinc-500">Risco: {ep.riskScore}/100</span>
                          )}
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
                      placeholder="/api/v1/custom-endpoint"
                      className="flex-1 bg-black/60 border border-[#333] px-2.5 py-1.5 rounded text-xs text-white focus:outline-none focus:border-emerald-500"
                    />
                    <button
                      type="button"
                      onClick={() => {
                        if (customEndpointInput.trim() && !newTargetEndpoints.includes(customEndpointInput.trim())) {
                          setNewTargetEndpoints([...newTargetEndpoints, customEndpointInput.trim()]);
                          setCustomEndpointInput('');
                        }
                      }}
                      className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-white text-xs rounded font-bold cursor-pointer"
                    >
                      + Adicionar Alvo
                    </button>
                  </div>
                </div>

                {/* HTTP Methods */}
                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">
                    Métodos HTTP a Testar:
                  </label>
                  <div className="flex items-center gap-2">
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
                          className={`px-3 py-1 rounded text-xs font-bold border transition-colors cursor-pointer ${
                            isSelected
                              ? 'bg-emerald-600 text-white border-emerald-500'
                              : 'bg-black/60 border-[#333] text-zinc-400'
                          }`}
                        >
                          {method}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Interval Preset Selector */}
                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">
                    Intervalo de Recorrência:
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
                </div>

                {/* Custom Cron Input if selected */}
                {newIntervalPreset === 'CRON' && (
                  <div className="space-y-1 md:col-span-2">
                    <label className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider block">
                      Expressão Cron Customizada (padrão 5 campos minuto/hora/dia/mês/dia-semana):
                    </label>
                    <input
                      type="text"
                      value={newCustomCron}
                      onChange={(e) => setNewCustomCron(e.target.value)}
                      placeholder="0 */4 * * *"
                      className="w-full bg-black border border-cyan-500/50 px-3 py-2 rounded-lg text-xs text-cyan-300 font-mono focus:outline-none"
                    />
                  </div>
                )}

                {/* Attack Categories Multi-select */}
                <div className="space-y-1 md:col-span-2">
                  <label className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">
                    Suíte de Ataque Ativa:
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
                          className={`p-2 rounded border text-left text-xs transition-colors cursor-pointer ${
                            isChecked
                              ? 'bg-emerald-950/40 border-emerald-500 text-white'
                              : 'bg-black/40 border-[#222] text-zinc-500 hover:text-zinc-300'
                          }`}
                        >
                          <div className="flex items-center gap-1.5">
                            <span className={`w-2 h-2 rounded-full ${isChecked ? 'bg-emerald-400' : 'bg-zinc-600'}`} />
                            <span className="font-bold">{cat.label}</span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Advanced Options & Alert Channels */}
                <div className="space-y-2 md:col-span-2 pt-2 border-t border-white/5">
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="stopOnVuln"
                      checked={newStopOnVuln}
                      onChange={(e) => setNewStopOnVuln(e.target.checked)}
                      className="rounded accent-emerald-500 cursor-pointer"
                    />
                    <label htmlFor="stopOnVuln" className="text-xs text-zinc-300 cursor-pointer">
                      Pausar agendador automaticamente se alguma vulnerabilidade crítica for confirmada
                    </label>
                  </div>

                  <div className="flex items-center gap-4 text-xs text-zinc-400 flex-wrap">
                    <span className="text-zinc-500">Canais de Notificação:</span>
                    <label className="flex items-center gap-1 cursor-pointer">
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
                    <label className="flex items-center gap-1 cursor-pointer">
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
                    <label className="flex items-center gap-1 cursor-pointer">
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
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-bold cursor-pointer"
                >
                  Cancelar
                </button>
                <button
                  onClick={handleCreateSchedule}
                  className="px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold uppercase tracking-wider flex items-center gap-2 cursor-pointer shadow"
                >
                  <Check className="w-4 h-4" />
                  <span>Salvar &amp; Iniciar Agendamento</span>
                </button>
              </div>
            </div>
          )}

          {/* List of Recurring Schedules */}
          <div className="space-y-3">
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
                            <code className="text-[10px] text-zinc-500">cron: {schedule.cronExpression}</code>
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
                          >
                            <Play className={`w-3.5 h-3.5 ${isRunning ? 'animate-spin' : ''}`} />
                            <span>{isRunning ? 'Executando...' : 'Executar Agora'}</span>
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

          {/* Execution History Stream */}
          <div className="space-y-4 pt-4 border-t border-[#222]">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold text-zinc-400 uppercase tracking-wider">
                  Trilha de Execução do Agendador ({filteredExecutionRecords.length})
                </h3>
              </div>

              <div className="flex items-center gap-2">
                {/* Filter Selector */}
                <div className="flex items-center bg-black border border-[#333] rounded-lg p-0.5 text-xs">
                  <button
                    onClick={() => setHistoryFilter('ALL')}
                    className={`px-2 py-0.5 rounded cursor-pointer ${historyFilter === 'ALL' ? 'bg-zinc-800 text-white font-bold' : 'text-zinc-500'}`}
                  >
                    Todos
                  </button>
                  <button
                    onClick={() => setHistoryFilter('VULNERABLE')}
                    className={`px-2 py-0.5 rounded cursor-pointer ${historyFilter === 'VULNERABLE' ? 'bg-rose-950 text-rose-300 font-bold' : 'text-zinc-500'}`}
                  >
                    Apenas Vulns
                  </button>
                  <button
                    onClick={() => setHistoryFilter('WARNING')}
                    className={`px-2 py-0.5 rounded cursor-pointer ${historyFilter === 'WARNING' ? 'bg-amber-950 text-amber-300 font-bold' : 'text-zinc-500'}`}
                  >
                    WAF / Alertas
                  </button>
                </div>

                <button
                  onClick={handleExportCsv}
                  disabled={executionRecords.length === 0}
                  className="px-3 py-1 bg-zinc-900 hover:bg-zinc-800 border border-[#333] text-zinc-300 hover:text-white rounded text-xs flex items-center gap-1.5 cursor-pointer disabled:opacity-40"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>CSV</span>
                </button>
              </div>
            </div>

            {filteredExecutionRecords.length === 0 ? (
              <div className="p-8 text-center bg-[#0C0C0C] border border-[#222] rounded-xl text-xs text-zinc-500">
                Nenhuma execução registrada no histórico até o momento. As varreduras agendadas serão registradas aqui em tempo real.
              </div>
            ) : (
              <div className="space-y-3">
                {filteredExecutionRecords.map(record => {
                  const hasVuln = record.vulnerabilitiesFound > 0;
                  const isExpanded = expandedRecordId === record.id;

                  return (
                    <div
                      key={record.id}
                      className={`rounded-xl border transition-all ${
                        hasVuln
                          ? 'bg-[#0F0708] border-rose-900/60'
                          : record.blockedByWafCount > 0
                          ? 'bg-[#0F0C07] border-amber-900/50'
                          : 'bg-[#080E0A] border-emerald-950/60'
                      }`}
                    >
                      <div
                        onClick={() => setExpandedRecordId(isExpanded ? null : record.id)}
                        className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer hover:bg-white/[0.02]"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 flex-wrap">
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
                            <span className="text-[10px] text-zinc-500">({record.durationMs}ms)</span>
                          </div>

                          <div className="text-[11px] text-zinc-400">
                            Endpoints testados: <span className="text-zinc-200">{record.endpointsTestedCount}</span> &bull; Payloads enviados: <span className="text-zinc-200">{record.payloadsSentCount}</span> &bull; Seguro: <span className="text-emerald-400">{record.safeCount}</span>
                          </div>
                        </div>

                        <div className="flex items-center gap-3">
                          <span className="text-[10px] text-zinc-500">{record.timestamp}</span>
                          {isExpanded ? <ChevronUp className="w-4 h-4 text-zinc-400" /> : <ChevronDown className="w-4 h-4 text-zinc-400" />}
                        </div>
                      </div>

                      {/* Expanded Drilldown Results */}
                      {isExpanded && (
                        <div className="p-4 border-t border-white/5 space-y-3 bg-black/60">
                          <span className="text-[10px] text-zinc-400 uppercase font-bold block">
                            Detalhamento dos Testes Dinâmicos Executados:
                          </span>
                          <div className="space-y-2">
                            {record.results.map((res, idx) => (
                              <div
                                key={idx}
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
                                <div className="text-[11px] text-zinc-400">
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
