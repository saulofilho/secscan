import React, { useState } from 'react';
import { 
  Calendar, 
  Clock, 
  Play, 
  Plus, 
  Trash2, 
  GitBranch, 
  Check, 
  Copy, 
  AlertTriangle, 
  CheckCircle2, 
  Power, 
  Code, 
  X, 
  ChevronRight, 
  Terminal, 
  Layers, 
  Radio, 
  FileCode,
  BellRing
} from 'lucide-react';
import { ScanSchedule, ScheduleInterval, CiCdProvider, SeverityLevel, ScanReport } from '../types';
import { 
  SCHEDULE_PRESETS, 
  INITIAL_SCHEDULES, 
  validateCron, 
  describeCron, 
  generateScheduledPipelineConfig 
} from '../lib/scheduleUtils';
import { safeGetItem, safeSetItem } from '../lib/storage';

interface ScanScheduleManagerProps {
  report: ScanReport;
}

export const ScanScheduleManager: React.FC<ScanScheduleManagerProps> = ({ report }) => {
  const [schedules, setSchedules] = useState<ScanSchedule[]>(() => {
    const saved = safeGetItem('secscan_schedules');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        console.error(e);
      }
    }
    return INITIAL_SCHEDULES;
  });

  const [isCreating, setIsCreating] = useState(false);
  const [selectedScheduleForConfig, setSelectedScheduleForConfig] = useState<ScanSchedule | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [runningScheduleId, setRunningScheduleId] = useState<string | null>(null);
  const [bannerMessage, setBannerMessage] = useState<string | null>(null);

  // Form State for new schedule
  const [formData, setFormData] = useState<{
    name: string;
    repository: string;
    branch: string;
    intervalPreset: ScheduleInterval;
    customCron: string;
    provider: CiCdProvider;
    failOnSeverity: SeverityLevel;
    notifyWebhook: boolean;
    notifyEmail: boolean;
    notifyPrComment: boolean;
  }>({
    name: '',
    repository: '',
    branch: 'main',
    intervalPreset: 'DAILY_MIDNIGHT',
    customCron: '0 2 * * *',
    provider: 'github-actions',
    failOnSeverity: 'CRITICAL',
    notifyWebhook: true,
    notifyEmail: false,
    notifyPrComment: true
  });

  const [formError, setFormError] = useState<string | null>(null);

  const saveSchedules = (updated: ScanSchedule[]) => {
    setSchedules(updated);
    safeSetItem('secscan_schedules', JSON.stringify(updated));
  };

  const handleToggleSchedule = (id: string) => {
    const updated = schedules.map(s => {
      if (s.id === id) {
        const nextState = !s.enabled;
        return {
          ...s,
          enabled: nextState,
          nextRun: nextState ? 'Próxima janela do cron' : 'Pausado'
        };
      }
      return s;
    });
    saveSchedules(updated);
  };

  const handleDeleteSchedule = (id: string) => {
    const target = schedules.find(s => s.id === id);
    if (!target) return;
    const updated = schedules.filter(s => s.id !== id);
    saveSchedules(updated);
    setBannerMessage(`Agendamento "${target.name}" removido com sucesso.`);
    setTimeout(() => setBannerMessage(null), 3000);
  };

  const handleRunNow = (schedule: ScanSchedule) => {
    setRunningScheduleId(schedule.id);
    setTimeout(() => {
      const isClean = Math.random() > 0.4;
      const findingsCount = isClean ? 0 : Math.floor(Math.random() * 4) + 1;
      const impactScore = isClean ? 0 : Math.floor(Math.random() * 60) + 20;

      const updated = schedules.map(s => {
        if (s.id === schedule.id) {
          return {
            ...s,
            lastRun: {
              timestamp: 'Agora mesmo (' + new Date().toLocaleTimeString() + ')',
              status: isClean ? ('SUCCESS' as const) : ('WARNING' as const),
              findingsCount,
              securityImpactScore: impactScore,
              durationMs: Math.floor(Math.random() * 250) + 180
            }
          };
        }
        return s;
      });
      saveSchedules(updated);
      setRunningScheduleId(null);
      setBannerMessage(`Varredura agendada disparada com sucesso para ${schedule.repository}:${schedule.branch}`);
      setTimeout(() => setBannerMessage(null), 4000);
    }, 900);
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!formData.name.trim()) {
      setFormError('Informe um nome descritivo para o agendamento.');
      return;
    }
    if (!formData.repository.trim()) {
      setFormError('Informe o repositório (ex: org/service-repo).');
      return;
    }

    let resolvedCron = formData.customCron;
    if (formData.intervalPreset !== 'CUSTOM_CRON') {
      const preset = SCHEDULE_PRESETS.find(p => p.id === formData.intervalPreset);
      if (preset) resolvedCron = preset.cron;
    }

    const val = validateCron(resolvedCron);
    if (!val.valid) {
      setFormError(val.message || 'Expressão cron inválida.');
      return;
    }

    const channels: ('webhook' | 'email' | 'pr_comment')[] = [];
    if (formData.notifyWebhook) channels.push('webhook');
    if (formData.notifyEmail) channels.push('email');
    if (formData.notifyPrComment) channels.push('pr_comment');

    const newSchedule: ScanSchedule = {
      id: `sched-${Date.now()}`,
      name: formData.name.trim(),
      repository: formData.repository.trim(),
      branch: formData.branch.trim() || 'main',
      cronExpression: resolvedCron,
      intervalPreset: formData.intervalPreset,
      provider: formData.provider,
      enabled: true,
      failOnSeverity: formData.failOnSeverity,
      notifyChannels: channels,
      nextRun: 'Próximo ciclo programado',
      createdAt: new Date().toISOString()
    };

    saveSchedules([newSchedule, ...schedules]);
    setIsCreating(false);
    setBannerMessage(`Novo agendamento "${newSchedule.name}" configurado com sucesso!`);
    setTimeout(() => setBannerMessage(null), 3500);

    // Reset form
    setFormData({
      name: '',
      repository: '',
      branch: 'main',
      intervalPreset: 'DAILY_MIDNIGHT',
      customCron: '0 2 * * *',
      provider: 'github-actions',
      failOnSeverity: 'CRITICAL',
      notifyWebhook: true,
      notifyEmail: false,
      notifyPrComment: true
    });
  };

  const activeCronExpression = formData.intervalPreset === 'CUSTOM_CRON' 
    ? formData.customCron 
    : SCHEDULE_PRESETS.find(p => p.id === formData.intervalPreset)?.cron || '0 0 * * *';

  return (
    <div className="bg-[#0A0A0A] border border-[#222] overflow-hidden space-y-6">
      {/* Top Banner Header */}
      <div className="p-6 bg-[#0D0D0D] border-b border-[#222] flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <Calendar className="w-4 h-4 text-[#FF3E00]" />
            <span className="text-[10px] font-black uppercase tracking-[0.25em] text-[#FF3E00]">
              CI/CD AUTOMATED SCHEDULES
            </span>
            <span className="text-[9px] font-mono px-2 py-0.5 bg-[#141414] text-[#AAA] border border-[#333]">
              CRON ENGINE v2
            </span>
          </div>
          <h2 className="text-xl sm:text-2xl font-black text-white tracking-tight uppercase">
            Scan Schedule & Recurrent Repository Audits
          </h2>
          <p className="text-xs font-mono text-[#888] mt-1 max-w-2xl leading-relaxed">
            Configure intervalos automáticos estilo cron (horário, diário, semanal ou personalizado) para varredura contínua de repositórios específicos no seu pipeline CI/CD.
          </p>
        </div>

        <button
          onClick={() => {
            setIsCreating(!isCreating);
            setFormError(null);
          }}
          className="inline-flex items-center gap-2 px-4 py-2.5 bg-white hover:bg-[#FF3E00] hover:text-white text-black text-xs font-mono font-bold uppercase tracking-wider transition-colors shrink-0"
        >
          {isCreating ? <X className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
          <span>{isCreating ? 'Cancelar' : 'Novo Agendamento'}</span>
        </button>
      </div>

      {/* Global Notification Banner */}
      {bannerMessage && (
        <div className="mx-6 p-3 bg-[#00FF41]/10 border border-[#00FF41]/40 text-xs font-mono text-[#00FF41] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-[#00FF41]" />
            <span>{bannerMessage}</span>
          </div>
          <button onClick={() => setBannerMessage(null)} className="text-[#888] hover:text-white">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Inline Create Form Modal / Accordion */}
      {isCreating && (
        <div className="mx-6 bg-[#0E0E0E] border border-[#333] p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-[#222] pb-3">
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-[#FF3E00]" />
              <h3 className="text-xs font-black uppercase tracking-wider text-white">
                Cadastrar Novo Agendamento Automático
              </h3>
            </div>
            <span className="text-[10px] font-mono text-[#888]">
              POSIX CRON (MIN HORA DIA MÊS DOW)
            </span>
          </div>

          {formError && (
            <div className="p-3 bg-[#FF3E00]/10 border border-[#FF3E00]/40 text-xs font-mono text-[#FF3E00] flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{formError}</span>
            </div>
          )}

          <form onSubmit={handleCreateSubmit} className="space-y-5 font-mono text-xs">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Schedule Name */}
              <div>
                <label className="block text-[10px] uppercase text-[#AAA] font-bold mb-1">
                  Nome do Agendamento *
                </label>
                <input
                  type="text"
                  required
                  placeholder="Ex: Main Nightly Secret Audit"
                  value={formData.name}
                  onChange={e => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-3 py-2 bg-[#050505] border border-[#2A2A2A] text-white focus:border-[#FF3E00] focus:outline-none"
                />
              </div>

              {/* Target Repository */}
              <div>
                <label className="block text-[10px] uppercase text-[#AAA] font-bold mb-1">
                  Repositório Alvo *
                </label>
                <input
                  type="text"
                  required
                  placeholder="Ex: github.com/organization/api-backend"
                  value={formData.repository}
                  onChange={e => setFormData({ ...formData, repository: e.target.value })}
                  className="w-full px-3 py-2 bg-[#050505] border border-[#2A2A2A] text-white focus:border-[#FF3E00] focus:outline-none"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Target Branch */}
              <div>
                <label className="block text-[10px] uppercase text-[#AAA] font-bold mb-1">
                  Branch Alvo
                </label>
                <div className="flex items-center gap-2">
                  <GitBranch className="w-4 h-4 text-[#888]" />
                  <input
                    type="text"
                    placeholder="main, master, release/*"
                    value={formData.branch}
                    onChange={e => setFormData({ ...formData, branch: e.target.value })}
                    className="w-full px-3 py-2 bg-[#050505] border border-[#2A2A2A] text-white focus:border-[#FF3E00] focus:outline-none"
                  />
                </div>
              </div>

              {/* Provider */}
              <div>
                <label className="block text-[10px] uppercase text-[#AAA] font-bold mb-1">
                  Provedor CI/CD
                </label>
                <select
                  value={formData.provider}
                  onChange={e => setFormData({ ...formData, provider: e.target.value as CiCdProvider })}
                  className="w-full px-3 py-2 bg-[#050505] border border-[#2A2A2A] text-white focus:border-[#FF3E00] focus:outline-none"
                >
                  <option value="github-actions">GitHub Actions (.github/workflows)</option>
                  <option value="gitlab-ci">GitLab CI/CD (.gitlab-ci.yml)</option>
                  <option value="circleci">CircleCI (.circleci/config.yml)</option>
                  <option value="jenkins">Jenkins Pipeline (Jenkinsfile)</option>
                </select>
              </div>

              {/* Quality Gate */}
              <div>
                <label className="block text-[10px] uppercase text-[#AAA] font-bold mb-1">
                  Bloquear Pipeline Se Houver:
                </label>
                <select
                  value={formData.failOnSeverity}
                  onChange={e => setFormData({ ...formData, failOnSeverity: e.target.value as SeverityLevel })}
                  className="w-full px-3 py-2 bg-[#050505] border border-[#2A2A2A] text-white focus:border-[#FF3E00] focus:outline-none"
                >
                  <option value="CRITICAL">Apenas CRITICAL (Segredos Críticos)</option>
                  <option value="HIGH">HIGH ou CRITICAL (Risco Elevado)</option>
                  <option value="MEDIUM">MEDIUM, HIGH ou CRITICAL</option>
                  <option value="LOW">Qualquer achado (Zero Tolerance)</option>
                </select>
              </div>
            </div>

            {/* Interval Preset Selector */}
            <div>
              <label className="block text-[10px] uppercase text-[#AAA] font-bold mb-2">
                Intervalo de Agendamento (Preset ou Expressão Cron)
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
                {SCHEDULE_PRESETS.map(preset => {
                  const isSelected = formData.intervalPreset === preset.id;
                  return (
                    <div
                      key={preset.id}
                      onClick={() => setFormData({ ...formData, intervalPreset: preset.id })}
                      className={`p-3 border cursor-pointer transition-all ${
                        isSelected 
                          ? 'bg-[#181818] border-[#FF3E00] text-white' 
                          : 'bg-[#080808] border-[#222] text-[#888] hover:border-[#444]'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className={`text-[11px] font-bold ${isSelected ? 'text-[#FF3E00]' : 'text-white'}`}>
                          {preset.label}
                        </span>
                        <code className="text-[10px] font-mono px-1.5 py-0.2 bg-[#000] border border-[#222] text-[#AAA]">
                          {preset.cron}
                        </code>
                      </div>
                      <p className="text-[10px] text-[#777] leading-tight">
                        {preset.description}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Custom Cron Input (if selected) */}
            {formData.intervalPreset === 'CUSTOM_CRON' && (
              <div className="bg-[#121212] border border-[#2A2A2A] p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-[10px] uppercase text-white font-bold">
                    Expressão Cron Personalizada (5 campos POSIX)
                  </label>
                  <span className="text-[10px] text-[#00FF41]">
                    {describeCron(formData.customCron)}
                  </span>
                </div>
                <input
                  type="text"
                  placeholder="0 2 * * * (min hora dia mês dow)"
                  value={formData.customCron}
                  onChange={e => setFormData({ ...formData, customCron: e.target.value })}
                  className="w-full px-3 py-2 bg-[#050505] border border-[#333] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
                />
                <div className="text-[10px] text-[#666] flex flex-wrap gap-3">
                  <span>Exemplos:</span>
                  <code>0 3 * * * (03:00 todo dia)</code>
                  <code>*/30 * * * * (A cada 30 min)</code>
                  <code>0 0 1 * * (1º dia de cada mês)</code>
                </div>
              </div>
            )}

            {/* Notification Checkboxes */}
            <div className="border-t border-[#222] pt-4">
              <label className="block text-[10px] uppercase text-[#AAA] font-bold mb-2 flex items-center gap-2">
                <BellRing className="w-3.5 h-3.5 text-[#FF3E00]" />
                <span>Canais de Notificação para Achados</span>
              </label>
              <div className="flex flex-wrap gap-4 text-xs">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.notifyWebhook}
                    onChange={e => setFormData({ ...formData, notifyWebhook: e.target.checked })}
                    className="accent-[#FF3E00]"
                  />
                  <span className="text-white">Webhook (Slack/Discord/Teams)</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.notifyPrComment}
                    onChange={e => setFormData({ ...formData, notifyPrComment: e.target.checked })}
                    className="accent-[#FF3E00]"
                  />
                  <span className="text-white">Security Advisory & SARIF Alert</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.notifyEmail}
                    onChange={e => setFormData({ ...formData, notifyEmail: e.target.checked })}
                    className="accent-[#FF3E00]"
                  />
                  <span className="text-white">Email Digest para Equipe DevSecOps</span>
                </label>
              </div>
            </div>

            {/* Cron Summary Preview */}
            <div className="bg-[#141414] border border-[#222] p-3 text-[11px] text-[#AAA] flex items-center justify-between">
              <div>
                Sintaxe Cron Ativa: <span className="text-white font-bold font-mono ml-1">{activeCronExpression}</span>
                <span className="text-[#888] ml-2">({describeCron(activeCronExpression)})</span>
              </div>
              <span className="text-[10px] text-[#00FF41]">Fuso Horário: UTC</span>
            </div>

            {/* Form Actions */}
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setIsCreating(false)}
                className="px-4 py-2 border border-[#333] text-white hover:bg-[#1A1A1A] transition-colors uppercase text-[10px] font-bold"
              >
                Cancelar
              </button>
              <button
                type="submit"
                className="px-5 py-2 bg-[#FF3E00] hover:bg-white hover:text-black text-white transition-colors uppercase text-[10px] font-bold tracking-wider"
              >
                Salvar Agendamento
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Schedules List Table */}
      <div className="px-6 pb-6">
        <div className="border border-[#222] bg-[#0A0A0A] overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-[#121212] text-[#777] uppercase text-[10px] tracking-wider border-b border-[#222]">
              <tr>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Repositório & Agendamento</th>
                <th className="py-3 px-4">Cron & Intervalo</th>
                <th className="py-3 px-4">Quality Gate</th>
                <th className="py-3 px-4">Última Execução</th>
                <th className="py-3 px-4 text-right">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1A1A1A]">
              {schedules.map(sched => {
                const isRunning = runningScheduleId === sched.id;
                return (
                  <tr key={sched.id} className="hover:bg-[#121212] transition-colors">
                    {/* Status Toggle */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <button
                        onClick={() => handleToggleSchedule(sched.id)}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider border transition-colors ${
                          sched.enabled
                            ? 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/40 hover:bg-[#00FF41]/20'
                            : 'bg-[#222] text-[#777] border-[#333] hover:text-white'
                        }`}
                        title={sched.enabled ? 'Clique para pausar agendamento' : 'Clique para ativar agendamento'}
                      >
                        <Power className="w-3 h-3" />
                        <span>{sched.enabled ? 'ATIVO' : 'PAUSADO'}</span>
                      </button>
                    </td>

                    {/* Repository & Name */}
                    <td className="py-3.5 px-4">
                      <div className="font-bold text-white text-sm flex items-center gap-2">
                        <span>{sched.name}</span>
                        <span className="text-[9px] px-1.5 py-0.2 bg-[#1A1A1A] text-[#AAA] border border-[#333] uppercase">
                          {sched.provider}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-[11px] text-[#888] mt-0.5">
                        <span className="text-[#CCC]">{sched.repository}</span>
                        <span>•</span>
                        <span className="flex items-center gap-1 text-[#AAA]">
                          <GitBranch className="w-3 h-3 text-[#FF3E00]" />
                          {sched.branch}
                        </span>
                      </div>
                    </td>

                    {/* Cron Details */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <Clock className="w-3.5 h-3.5 text-[#FF3E00]" />
                        <code className="text-white font-bold bg-[#141414] px-2 py-0.5 border border-[#2A2A2A]">
                          {sched.cronExpression}
                        </code>
                      </div>
                      <div className="text-[10px] text-[#777] mt-1">
                        {describeCron(sched.cronExpression)}
                      </div>
                    </td>

                    {/* Quality Gate */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="text-[10px] font-bold">
                        <span className="text-[#888]">Fail on: </span>
                        <span className={`px-1.5 py-0.5 border ${
                          sched.failOnSeverity === 'CRITICAL' 
                            ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40' 
                            : 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/40'
                        }`}>
                          {sched.failOnSeverity}
                        </span>
                      </div>
                      <div className="text-[9px] text-[#666] mt-1">
                        Notifica: {sched.notifyChannels.join(', ')}
                      </div>
                    </td>

                    {/* Last Run Stats */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {sched.lastRun ? (
                        <div>
                          <div className="flex items-center gap-2">
                            <span className={`w-2 h-2 rounded-full ${
                              sched.lastRun.status === 'SUCCESS' ? 'bg-[#00FF41]' : 'bg-[#EAB308]'
                            }`} />
                            <span className="text-white font-bold">
                              {sched.lastRun.status === 'SUCCESS' ? 'Limpo (0 achados)' : `${sched.lastRun.findingsCount} achados`}
                            </span>
                            <span className="text-[10px] text-[#777]">({sched.lastRun.durationMs}ms)</span>
                          </div>
                          <div className="text-[10px] text-[#777] mt-0.5">
                            {sched.lastRun.timestamp}
                          </div>
                        </div>
                      ) : (
                        <span className="text-[#666] text-[10px]">Aguardando primeiro ciclo</span>
                      )}
                    </td>

                    {/* Action Buttons */}
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-2">
                        {/* Run Now Simulator */}
                        <button
                          onClick={() => handleRunNow(sched)}
                          disabled={isRunning}
                          className="px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider bg-[#141414] hover:bg-[#FF3E00] text-white border border-[#333] transition-colors inline-flex items-center gap-1.5 disabled:opacity-50"
                          title="Simular disparo imediato da rotina agendada"
                        >
                          <Play className={`w-3 h-3 ${isRunning ? 'animate-spin text-[#FF3E00]' : ''}`} />
                          <span>{isRunning ? 'Varrendo...' : 'Executar Agora'}</span>
                        </button>

                        {/* View Pipeline YAML */}
                        <button
                          onClick={() => setSelectedScheduleForConfig(sched)}
                          className="px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider bg-[#141414] hover:bg-white hover:text-black text-[#AAA] border border-[#333] transition-colors inline-flex items-center gap-1"
                          title="Visualizar arquivo de pipeline agendado (.github / .gitlab-ci)"
                        >
                          <FileCode className="w-3 h-3" />
                          <span>YAML</span>
                        </button>

                        {/* Delete */}
                        <button
                          onClick={() => handleDeleteSchedule(sched.id)}
                          className="p-1 text-[#666] hover:text-[#FF3E00] transition-colors"
                          title="Excluir agendamento"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal / Dialog for Viewing Generated Scheduled YAML */}
      {selectedScheduleForConfig && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4 backdrop-blur-sm">
          <div className="bg-[#0D0D0D] border border-[#333] w-full max-w-3xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl">
            <div className="p-4 bg-[#121212] border-b border-[#222] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-[#FF3E00]" />
                <span className="text-xs font-black uppercase tracking-wider text-white">
                  Pipeline YAML Agendado: {selectedScheduleForConfig.name}
                </span>
              </div>
              <button
                onClick={() => setSelectedScheduleForConfig(null)}
                className="text-[#888] hover:text-white p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 bg-[#080808] border-b border-[#222] text-xs font-mono text-[#888] flex items-center justify-between">
              <div>
                Intervalo Cron: <span className="text-white font-bold">{selectedScheduleForConfig.cronExpression}</span>
                <span className="ml-2 text-[#AAA]">({describeCron(selectedScheduleForConfig.cronExpression)})</span>
              </div>
              <button
                onClick={() => handleCopy(generateScheduledPipelineConfig(selectedScheduleForConfig), 'schedule-yaml')}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-black uppercase tracking-wider bg-[#1A1A1A] hover:bg-white hover:text-black text-white border border-[#333] transition-colors"
              >
                {copiedKey === 'schedule-yaml' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === 'schedule-yaml' ? 'Copiado!' : 'Copiar YAML'}</span>
              </button>
            </div>

            <div className="p-5 bg-[#050505] font-mono text-xs text-[#00FF41] overflow-y-auto flex-1 leading-relaxed">
              <pre>{generateScheduledPipelineConfig(selectedScheduleForConfig)}</pre>
            </div>

            <div className="p-3 bg-[#111] border-t border-[#222] flex items-center justify-between text-[11px] font-mono text-[#888]">
              <span>Cole este arquivo em <code>.github/workflows/secscan-schedule.yml</code> do seu repositório.</span>
              <button
                onClick={() => setSelectedScheduleForConfig(null)}
                className="px-4 py-1.5 bg-[#222] hover:bg-[#333] text-white text-[10px] uppercase font-bold"
              >
                Fechar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
