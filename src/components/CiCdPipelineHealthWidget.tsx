import React, { useState, useEffect, useMemo } from 'react';
import { 
  GitBranch, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  Terminal, 
  ExternalLink, 
  RefreshCw, 
  Play, 
  Check, 
  Copy, 
  Search, 
  Filter, 
  ShieldCheck, 
  ShieldAlert, 
  Activity, 
  Layers, 
  FileCode, 
  Sliders, 
  ArrowUpRight,
  GitCommit,
  Radio,
  Cpu,
  ChevronRight
} from 'lucide-react';
import { ScanReport, WorkflowRun, ScanFinding } from '../types';
import { 
  getOrInitWorkflowRuns, 
  computePipelineHealth, 
  dispatchNewWorkflowRun,
  WORKFLOW_STORAGE_KEY 
} from '../lib/cicdPipelineData';
import { WorkflowScanLogsModal } from './WorkflowScanLogsModal';
import { safeSetItem } from '../lib/storage';

interface CiCdPipelineHealthWidgetProps {
  report: ScanReport;
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToTab?: (tab: string) => void;
  onOpenWorkflowModal?: () => void;
  qualityGateMaxRisk?: number;
}

export const CiCdPipelineHealthWidget: React.FC<CiCdPipelineHealthWidgetProps> = ({
  report,
  onSelectFinding,
  onNavigateToTab,
  onOpenWorkflowModal,
  qualityGateMaxRisk = 50
}) => {
  const [runs, setRuns] = useState<WorkflowRun[]>(() => {
    return getOrInitWorkflowRuns(report, qualityGateMaxRisk);
  });

  const [selectedRunForLogs, setSelectedRunForLogs] = useState<WorkflowRun | null>(null);
  const [isLogsModalOpen, setIsLogsModalOpen] = useState(false);
  const [isDispatching, setIsDispatching] = useState(false);
  const [dispatchSuccess, setDispatchSuccess] = useState(false);
  const [branchFilter, setBranchFilter] = useState<string>('all');
  const [conclusionFilter, setConclusionFilter] = useState<'all' | 'success' | 'failure'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [lastSyncTime, setLastSyncTime] = useState<Date>(new Date());
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Sync latest run if report changes
  useEffect(() => {
    const updated = getOrInitWorkflowRuns(report, qualityGateMaxRisk);
    setRuns(updated);
    setLastSyncTime(new Date());
  }, [report, qualityGateMaxRisk]);

  const health = useMemo(() => computePipelineHealth(runs), [runs]);

  const handleOpenLogs = (run: WorkflowRun) => {
    setSelectedRunForLogs(run);
    setIsLogsModalOpen(true);
  };

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      const refreshed = getOrInitWorkflowRuns(report, qualityGateMaxRisk);
      setRuns(refreshed);
      setLastSyncTime(new Date());
      setIsRefreshing(false);
    }, 600);
  };

  const handleTriggerDispatch = () => {
    if (isDispatching) return;
    setIsDispatching(true);

    // Simulate immediate runner execution
    setTimeout(() => {
      const newRun = dispatchNewWorkflowRun(report, 'main', 'secscan-admin', qualityGateMaxRisk, runs);
      const updatedRuns = [newRun, ...runs];
      setRuns(updatedRuns);
      safeSetItem(WORKFLOW_STORAGE_KEY, JSON.stringify(updatedRuns));
      setIsDispatching(false);
      setDispatchSuccess(true);
      setLastSyncTime(new Date());
      setTimeout(() => setDispatchSuccess(false), 3000);
    }, 1200);
  };

  // Filtered runs list
  const filteredRuns = useMemo(() => {
    return runs.filter(run => {
      if (branchFilter !== 'all' && run.branch !== branchFilter) return false;
      if (conclusionFilter === 'success' && run.conclusion !== 'success') return false;
      if (conclusionFilter === 'failure' && run.conclusion !== 'failure') return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          run.title.toLowerCase().includes(q) ||
          run.commitSha.toLowerCase().includes(q) ||
          run.actor.name.toLowerCase().includes(q) ||
          run.branch.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [runs, branchFilter, conclusionFilter, searchQuery]);

  const distinctBranches = useMemo(() => {
    const branches = new Set<string>();
    runs.forEach(r => branches.add(r.branch));
    return Array.from(branches);
  }, [runs]);

  return (
    <div 
      id="cicd-pipeline-health-widget" 
      className="bg-[#0A0A0A] border-2 border-[#222] p-6 lg:p-8 space-y-6 relative overflow-hidden"
    >
      {/* Top Background Pattern */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-[#00FF41]/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header Section */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5 pb-6 border-b border-[#222] relative z-10">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono text-[#00FF41] bg-[#00FF41]/10 px-2.5 py-0.5 border border-[#00FF41]/30 uppercase font-black tracking-widest flex items-center gap-1.5">
              <Activity className="w-3 h-3 text-[#00FF41]" />
              CI/CD PIPELINE HEALTH // GITHUB ACTIONS
            </span>
            <span className="text-[10px] font-mono text-zinc-400 bg-[#161616] px-2.5 py-0.5 border border-[#333] flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#00FF41] animate-pulse" />
              INTEGRAÇÃO ATIVA (v2.4.0)
            </span>
            <span className="text-[10px] font-mono bg-[#161616] text-[#00E5FF] border border-[#00E5FF]/30 px-2 py-0.5">
              SARIF UPLOAD: CODEQL ACTIVE
            </span>
            <span className="text-[10px] font-mono text-zinc-500">
              Sincronizado {lastSyncTime.toLocaleTimeString()}
            </span>
          </div>

          <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
            <span>Saúde do Pipeline CI/CD & Execuções Recentes</span>
          </h2>
          <p className="text-xs font-mono text-zinc-400 max-w-3xl leading-relaxed">
            Monitoramento em tempo real dos fluxos de trabalho do GitHub Actions (<span className="text-white font-semibold">.github/workflows/secscan.yml</span>). Acompanhe taxas de sucesso, bloqueios por Quality Gate e inspecione logs completos das últimas varreduras SAST disparadas.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="px-3.5 py-2.5 bg-[#141414] hover:bg-[#202020] text-zinc-300 hover:text-white border border-[#333] hover:border-zinc-500 text-xs font-mono font-bold uppercase tracking-wider transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
            title="Sincronizar status dos workflows agora"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-[#00FF41] ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Atualizar</span>
          </button>

          <button
            onClick={handleTriggerDispatch}
            disabled={isDispatching}
            className="px-4 py-2.5 bg-[#00FF41] hover:bg-white text-black font-mono font-black text-xs uppercase tracking-wider transition-all flex items-center gap-2 shadow-[0_0_15px_rgba(0,255,65,0.25)] cursor-pointer disabled:opacity-60"
            title="Disparar nova execução de varredura SAST via workflow_dispatch"
          >
            {isDispatching ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Disparando Runner...</span>
              </>
            ) : dispatchSuccess ? (
              <>
                <Check className="w-3.5 h-3.5" />
                <span>Run Disparado!</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-black" />
                <span>Disparar Scan (Dispatch)</span>
              </>
            )}
          </button>

          {onOpenWorkflowModal && (
            <button
              onClick={onOpenWorkflowModal}
              className="px-3.5 py-2.5 bg-[#141414] hover:bg-[#202020] text-zinc-200 border border-[#333] hover:border-[#FF3E00] text-xs font-mono font-bold uppercase tracking-wider transition-all flex items-center gap-2 cursor-pointer"
              title="Gerar ou editar template do GitHub Actions YAML"
            >
              <FileCode className="w-3.5 h-3.5 text-[#FF3E00]" />
              <span>YAML do Workflow</span>
            </button>
          )}

          {onNavigateToTab && (
            <button
              onClick={() => onNavigateToTab('cicd')}
              className="px-3.5 py-2.5 bg-[#141414] hover:bg-[#202020] text-zinc-200 border border-[#333] hover:border-[#00E5FF] text-xs font-mono font-bold uppercase tracking-wider transition-all flex items-center gap-2 cursor-pointer"
              title="Ir para o painel completo de integração CI/CD"
            >
              <ExternalLink className="w-3.5 h-3.5 text-[#00E5FF]" />
              <span>Aba CI/CD</span>
            </button>
          )}
        </div>
      </div>

      {/* Real-time Health Metrics Cards (4 Cards) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Success Rate */}
        <div className="bg-[#0E0E0E] p-5 border border-[#262626] flex flex-col justify-between relative overflow-hidden group hover:border-[#00FF41]/40 transition-colors">
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-widest font-bold">
                Taxa de Sucesso
              </span>
              <span className={`text-[10px] font-mono px-2 py-0.5 border font-bold ${
                health.successRatePercentage >= 80 
                  ? 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/30'
                  : 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40'
              }`}>
                {health.successRatePercentage >= 80 ? 'SAUDÁVEL' : 'ATENÇÃO'}
              </span>
            </div>
            <div className="flex items-baseline gap-2 pt-2">
              <span className={`text-4xl font-black font-mono tracking-tight ${
                health.successRatePercentage >= 80 ? 'text-[#00FF41]' : 'text-[#FF3E00]'
              }`}>
                {health.successRatePercentage}%
              </span>
              <span className="text-xs font-mono text-zinc-500">
                ({health.successfulRuns}/{health.successfulRuns + health.failedRuns} runs)
              </span>
            </div>
          </div>

          {/* Progress bar */}
          <div className="mt-4 pt-3 border-t border-[#1C1C1C] space-y-1.5">
            <div className="w-full bg-[#1A1A1A] h-2 rounded-full overflow-hidden flex">
              <div 
                className="bg-[#00FF41] h-full transition-all duration-500"
                style={{ width: `${health.successRatePercentage}%` }}
              />
              <div 
                className="bg-[#FF3E00] h-full transition-all duration-500"
                style={{ width: `${100 - health.successRatePercentage}%` }}
              />
            </div>
            <div className="flex justify-between text-[9px] font-mono text-zinc-500">
              <span>{health.successfulRuns} Aprovados</span>
              <span className="text-[#FF3E00]">{health.failedRuns} Bloqueados</span>
            </div>
          </div>
        </div>

        {/* Metric 2: Quality Gate Status */}
        <div className="bg-[#0E0E0E] p-5 border border-[#262626] flex flex-col justify-between relative overflow-hidden group hover:border-[#FF3E00]/40 transition-colors">
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-widest font-bold">
                Quality Gate Status
              </span>
              <span className="text-[10px] font-mono text-zinc-400 bg-[#161616] px-1.5 py-0.5 border border-[#333]">
                Exit Code {health.lastRunStatus === 'failure' ? '1' : '0'}
              </span>
            </div>
            <div className="pt-2">
              {health.lastRunStatus === 'failure' ? (
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-8 h-8 text-[#FF3E00] shrink-0" />
                  <div>
                    <div className="text-xl font-black font-mono text-[#FF3E00] uppercase tracking-tight">
                      GATE BLOQUEADO
                    </div>
                    <div className="text-[10px] font-mono text-zinc-400">
                      Vulnerabilidades Críticas ativas
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-8 h-8 text-[#00FF41] shrink-0" />
                  <div>
                    <div className="text-xl font-black font-mono text-[#00FF41] uppercase tracking-tight">
                      GATE APROVADO
                    </div>
                    <div className="text-[10px] font-mono text-zinc-400">
                      Conforme política de segurança
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-[#1C1C1C] flex items-center justify-between text-[10px] font-mono text-zinc-400">
            <span>Fail-On: <strong className="text-white">CRITICAL</strong></span>
            <span>Teto: <strong className="text-white">{qualityGateMaxRisk} pts</strong></span>
          </div>
        </div>

        {/* Metric 3: Average Duration */}
        <div className="bg-[#0E0E0E] p-5 border border-[#262626] flex flex-col justify-between relative overflow-hidden group hover:border-zinc-600 transition-colors">
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-widest font-bold">
                Tempo Médio de Build
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 bg-[#1A1A1A] text-zinc-300 border border-[#333]">
                ubuntu-latest
              </span>
            </div>
            <div className="flex items-baseline gap-2 pt-2">
              <span className="text-4xl font-black font-mono text-white tracking-tight">
                {health.averageDurationSeconds}s
              </span>
              <span className="text-xs font-mono text-zinc-500">
                / execução
              </span>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-[#1C1C1C] flex items-center justify-between text-[10px] font-mono text-zinc-400">
            <span className="flex items-center gap-1">
              <Cpu className="w-3 h-3 text-[#00E5FF]" />
              Runner: GitHub Hosted
            </span>
            <span className="text-zinc-500">Cache npm: ON</span>
          </div>
        </div>

        {/* Metric 4: Monitored Runs & Sparkline */}
        <div className="bg-[#0E0E0E] p-5 border border-[#262626] flex flex-col justify-between relative overflow-hidden group hover:border-zinc-600 transition-colors">
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-widest font-bold">
                Últimas Execuções
              </span>
              <span className="text-[10px] font-mono text-[#00FF41] bg-[#00FF41]/10 px-1.5 py-0.5 border border-[#00FF41]/30">
                {health.totalRuns} Total
              </span>
            </div>

            {/* Run Result Blocks */}
            <div className="pt-2">
              <div className="text-[10px] font-mono text-zinc-500 mb-1.5 uppercase">
                Histórico sequencial (Clique para logs):
              </div>
              <div className="flex items-center gap-1.5 flex-wrap">
                {runs.slice(0, 10).map((r) => {
                  const isOk = r.conclusion === 'success';
                  return (
                    <button
                      key={r.id}
                      onClick={() => handleOpenLogs(r)}
                      className={`w-6 h-6 rounded flex items-center justify-center text-[10px] font-mono font-bold transition-transform hover:scale-110 cursor-pointer ${
                        isOk
                          ? 'bg-[#00FF41]/20 text-[#00FF41] border border-[#00FF41]/50 hover:bg-[#00FF41] hover:text-black'
                          : 'bg-[#FF3E00]/25 text-[#FF3E00] border border-[#FF3E00]/60 hover:bg-[#FF3E00] hover:text-white'
                      }`}
                      title={`Run #${r.runNumber} (${r.branch}) - ${r.conclusion?.toUpperCase()}. Clique para abrir logs.`}
                    >
                      {isOk ? '✓' : '✗'}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-[#1C1C1C] flex items-center justify-between text-[10px] font-mono text-zinc-400">
            <span>Branch principal: <strong className="text-white">main</strong></span>
            <button
              onClick={() => handleOpenLogs(runs[0])}
              className="text-[#00FF41] hover:underline flex items-center gap-0.5 cursor-pointer font-bold"
            >
              <span>Último Log</span>
              <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>

      {/* Filter and Search Toolbar */}
      <div className="bg-[#111] p-3.5 border border-[#222] flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        <div className="flex flex-wrap items-center gap-2.5 flex-1 min-w-[280px]">
          {/* Search */}
          <div className="relative flex-1 max-w-sm">
            <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Buscar por commit, branch ou ator..."
              className="w-full pl-9 pr-3 py-1.5 bg-[#080808] border border-[#2D2D2D] text-zinc-200 text-xs placeholder:text-zinc-600 focus:outline-none focus:border-[#00FF41]"
            />
          </div>

          {/* Branch filter */}
          <div className="flex items-center gap-1.5">
            <GitBranch className="w-3.5 h-3.5 text-zinc-500" />
            <select
              value={branchFilter}
              onChange={(e) => setBranchFilter(e.target.value)}
              className="bg-[#080808] border border-[#2D2D2D] text-zinc-200 py-1.5 px-2.5 text-xs focus:outline-none focus:border-[#00FF41]"
            >
              <option value="all">Todos os Ramos (All Branches)</option>
              {distinctBranches.map(b => (
                <option key={b} value={b}>{b}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Conclusion Status Pills */}
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] text-zinc-500 uppercase font-bold mr-1">Status:</span>
          {(['all', 'success', 'failure'] as const).map(st => (
            <button
              key={st}
              onClick={() => setConclusionFilter(st)}
              className={`px-3 py-1 text-xs font-bold border transition-colors cursor-pointer ${
                conclusionFilter === st
                  ? st === 'failure'
                    ? 'bg-[#FF3E00] text-white border-[#FF3E00]'
                    : st === 'success'
                    ? 'bg-[#00FF41] text-black border-[#00FF41]'
                    : 'bg-white text-black border-white'
                  : 'bg-[#181818] text-zinc-400 border-[#2D2D2D] hover:text-white'
              }`}
            >
              {st === 'all' ? 'Todos' : st === 'success' ? 'Aprovados' : 'Falhas'}
            </button>
          ))}
          <span className="text-[10px] text-zinc-500 ml-2">
            ({filteredRuns.length} de {runs.length})
          </span>
        </div>
      </div>

      {/* Recent Workflow Runs Table */}
      <div className="border border-[#222] bg-[#0A0A0A] overflow-x-auto">
        <table className="w-full text-left font-mono text-xs border-collapse">
          <thead>
            <tr className="bg-[#141414] border-b border-[#2A2A2A] text-zinc-400 text-[10px] uppercase tracking-wider">
              <th className="p-3.5 pl-4">Status & Run</th>
              <th className="p-3.5">Commit & Mensagem</th>
              <th className="p-3.5">Ramo (Branch)</th>
              <th className="p-3.5">Disparo</th>
              <th className="p-3.5">Achados SAST</th>
              <th className="p-3.5">Duração</th>
              <th className="p-3.5">Horário</th>
              <th className="p-3.5 pr-4 text-right">Logs do Scan</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1A1A1A]">
            {filteredRuns.length === 0 ? (
              <tr>
                <td colSpan={8} className="p-8 text-center text-zinc-500">
                  Nenhuma execução de workflow encontrada para os filtros aplicados.
                </td>
              </tr>
            ) : (
              filteredRuns.map((run) => {
                const isSuccess = run.conclusion === 'success';
                const isFailure = run.conclusion === 'failure';
                const isRunning = run.status === 'in_progress';

                return (
                  <tr 
                    key={run.id}
                    className="hover:bg-[#121212] transition-colors group"
                  >
                    {/* Status & Run # */}
                    <td className="p-3.5 pl-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        {isRunning ? (
                          <RefreshCw className="w-4 h-4 text-[#00E5FF] animate-spin" />
                        ) : isSuccess ? (
                          <CheckCircle2 className="w-4 h-4 text-[#00FF41]" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-[#FF3E00]" />
                        )}
                        <span className="font-bold text-white">#{run.runNumber}</span>
                        <span className={`text-[9px] px-1.5 py-0.5 border font-black uppercase ${
                          isSuccess
                            ? 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/30'
                            : 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40'
                        }`}>
                          {run.conclusion ? run.conclusion.toUpperCase() : run.status}
                        </span>
                      </div>
                    </td>

                    {/* Commit & Message */}
                    <td className="p-3.5 min-w-[240px]">
                      <div className="space-y-0.5">
                        <div className="text-zinc-200 font-bold truncate max-w-sm" title={run.title}>
                          {run.title}
                        </div>
                        <div className="flex items-center gap-2 text-[10px] text-zinc-500">
                          <span className="flex items-center gap-1 font-mono text-[#00FF41]">
                            <GitCommit className="w-3 h-3 text-zinc-500" />
                            {run.commitSha.slice(0, 7)}
                          </span>
                          <span>por <strong className="text-zinc-400">{run.actor.name}</strong></span>
                        </div>
                      </div>
                    </td>

                    {/* Branch */}
                    <td className="p-3.5 whitespace-nowrap">
                      <div className="flex items-center gap-1 text-zinc-300 font-mono">
                        <GitBranch className="w-3.5 h-3.5 text-zinc-500" />
                        <span className="bg-[#141414] px-2 py-0.5 border border-[#2D2D2D] rounded text-[11px]">
                          {run.branch}
                        </span>
                      </div>
                    </td>

                    {/* Trigger Event */}
                    <td className="p-3.5 whitespace-nowrap">
                      <span className="text-[10px] font-mono px-2 py-0.5 bg-[#161616] text-zinc-300 border border-[#2D2D2D] uppercase">
                        {run.event}
                      </span>
                    </td>

                    {/* SAST Findings Count */}
                    <td className="p-3.5 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        {run.findingsCount.total === 0 ? (
                          <span className="text-[10px] font-mono text-[#00FF41] bg-[#00FF41]/10 px-2 py-0.5 border border-[#00FF41]/30 font-bold">
                            0 AMEAÇAS
                          </span>
                        ) : (
                          <div className="flex items-center gap-1">
                            {run.findingsCount.critical > 0 && (
                              <span className="text-[10px] font-mono bg-[#FF3E00] text-black px-1.5 py-0.5 font-black">
                                {run.findingsCount.critical}C
                              </span>
                            )}
                            {run.findingsCount.high > 0 && (
                              <span className="text-[10px] font-mono bg-[#FF7A00]/20 text-[#FF7A00] px-1.5 py-0.5 border border-[#FF7A00]/40 font-bold">
                                {run.findingsCount.high}H
                              </span>
                            )}
                            <span className="text-[10px] text-zinc-400">
                              ({run.findingsCount.total} total)
                            </span>
                          </div>
                        )}
                      </div>
                    </td>

                    {/* Duration */}
                    <td className="p-3.5 whitespace-nowrap text-zinc-400">
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-zinc-500" />
                        <span>{run.durationSeconds}s</span>
                      </div>
                    </td>

                    {/* Time */}
                    <td className="p-3.5 whitespace-nowrap text-[11px] text-zinc-400">
                      {new Date(run.startedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>

                    {/* Action: View Scan Logs */}
                    <td className="p-3.5 pr-4 text-right whitespace-nowrap">
                      <button
                        onClick={() => handleOpenLogs(run)}
                        className="px-3 py-1.5 bg-[#1A1A1A] hover:bg-[#00FF41] hover:text-black text-zinc-200 border border-[#333] hover:border-[#00FF41] font-mono text-[11px] font-bold transition-all inline-flex items-center gap-1.5 cursor-pointer shadow-sm group-hover:border-zinc-500"
                        title={`Inspecionar logs detalhados do job #${run.runNumber}`}
                      >
                        <Terminal className="w-3 h-3 text-[#00FF41] group-hover:text-black" />
                        <span>Ver Logs</span>
                        <ChevronRight className="w-3 h-3 text-zinc-500 group-hover:text-black" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Footer Governance Strip */}
      <div className="pt-2 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono text-zinc-400">
        <div className="flex flex-wrap items-center gap-3">
          <span className="flex items-center gap-1.5 text-zinc-300">
            <ShieldCheck className="w-3.5 h-3.5 text-[#00FF41]" />
            <span>Branch Protection Rule: <strong className="text-white">require_status_checks = [secscan]</strong></span>
          </span>
          <span className="text-zinc-600">|</span>
          <span className="text-zinc-400">
            Webhook Event: <strong className="text-zinc-300">push, pull_request (SARIF Code Scanning)</strong>
          </span>
        </div>

        <button
          onClick={() => {
            const el = document.getElementById('risk-threshold-config');
            if (el) el.scrollIntoView({ behavior: 'smooth' });
          }}
          className="text-[#FF3E00] hover:text-white hover:underline flex items-center gap-1 font-bold cursor-pointer"
        >
          <Sliders className="w-3.5 h-3.5" />
          <span>Ajustar Teto de Bloqueio (Quality Gate) &darr;</span>
        </button>
      </div>

      {/* Render Scan Logs Modal */}
      <WorkflowScanLogsModal
        isOpen={isLogsModalOpen}
        run={selectedRunForLogs}
        onClose={() => setIsLogsModalOpen(false)}
        onSelectFinding={onSelectFinding}
        allFindings={report.findings}
      />
    </div>
  );
};
