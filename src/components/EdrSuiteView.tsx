import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Zap,
  Activity,
  Terminal,
  Crosshair,
  Server,
  Lock,
  Unlock,
  Eye,
  Search,
  Plus,
  Trash2,
  RefreshCw,
  Cpu,
  Layers,
  Network,
  Download,
  Copy,
  Check,
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  FileCode,
  FileSearch,
  Flame,
  Radio,
  Sliders,
  Filter,
  ArrowRight,
  GitBranch,
  Database,
  Share2
} from 'lucide-react';
import { ScanReport, ScanFinding } from '../types';
import {
  EdrProcessNode,
  EdrBehavioralRule,
  EdrMemoryDumpAnalysis,
  EdrThreatHuntingQuery,
  EdrLiveTelemetry,
  EdrProcessAction
} from '../types/edr';
import {
  INITIAL_PROCESS_TREES,
  INITIAL_BEHAVIORAL_RULES,
  INITIAL_MEMORY_DUMPS,
  INITIAL_HUNTING_QUERIES,
  INITIAL_EDR_TELEMETRY
} from '../lib/edrEngine';

interface EdrSuiteViewProps {
  report: ScanReport;
  onNavigateToScanner?: () => void;
  onNavigateToSecurityOnion?: () => void;
  onNavigateToNgfw?: () => void;
}

export const EdrSuiteView: React.FC<EdrSuiteViewProps> = ({
  report,
  onNavigateToScanner,
  onNavigateToSecurityOnion,
  onNavigateToNgfw
}) => {
  // Navigation tabs
  const [activeSubTab, setActiveSubTab] = useState<'process_tree' | 'behavioral_rules' | 'threat_hunting' | 'memory_forensics' | 'isolation_matrix'>('process_tree');

  // State
  const [processTree, setProcessTree] = useState<EdrProcessNode[]>(INITIAL_PROCESS_TREES);
  const [behavioralRules, setBehavioralRules] = useState<EdrBehavioralRule[]>(INITIAL_BEHAVIORAL_RULES);
  const [memoryDumps, setMemoryDumps] = useState<EdrMemoryDumpAnalysis[]>(INITIAL_MEMORY_DUMPS);
  const [huntingQueries, setHuntingQueries] = useState<EdrThreatHuntingQuery[]>(INITIAL_HUNTING_QUERIES);
  const [telemetry, setTelemetry] = useState<EdrLiveTelemetry>(INITIAL_EDR_TELEMETRY);

  // Selected process inspection
  const [selectedProcessPid, setSelectedProcessPid] = useState<number>(7921);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Threat hunting interactive console
  const [customHuntingQuery, setCustomHuntingQuery] = useState<string>('EventType == "ProcessCreation" and ThreatScore > 70');
  const [huntingExecuting, setHuntingExecuting] = useState<boolean>(false);
  const [huntingResultCount, setHuntingResultCount] = useState<number | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Find process helper (recursively)
  const findProcessByPid = (nodes: EdrProcessNode[], pid: number): EdrProcessNode | null => {
    for (const node of nodes) {
      if (node.pid === pid) return node;
      if (node.children && node.children.length > 0) {
        const found = findProcessByPid(node.children, pid);
        if (found) return found;
      }
    }
    return null;
  };

  const selectedProcess = useMemo(() => {
    return findProcessByPid(processTree, selectedProcessPid) || processTree[0];
  }, [processTree, selectedProcessPid]);

  // Handle process termination (Kill process tree)
  const handleTerminateProcess = (pid: number) => {
    const updateNodeAction = (nodes: EdrProcessNode[]): EdrProcessNode[] => {
      return nodes.map(node => {
        if (node.pid === pid) {
          return {
            ...node,
            actionTaken: 'TERMINATE',
            threatScore: 100
          };
        }
        if (node.children) {
          return {
            ...node,
            children: updateNodeAction(node.children)
          };
        }
        return node;
      });
    };

    setProcessTree(prev => updateNodeAction(prev));
    setTelemetry(prev => ({
      ...prev,
      blockedAttacksToday: prev.blockedAttacksToday + 1
    }));
  };

  const handleToggleRule = (id: string) => {
    setBehavioralRules(prev => prev.map(r => r.id === id ? { ...r, active: !r.active } : r));
  };

  const handleRunHuntingQuery = () => {
    setHuntingExecuting(true);
    setTimeout(() => {
      setHuntingExecuting(false);
      setHuntingResultCount(Math.floor(Math.random() * 4) + 1);
    }, 600);
  };

  const handleExportForensicsReport = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({
      telemetry,
      processTree,
      behavioralRules,
      memoryDumps,
      huntingQueries
    }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `edr-endpoint-forensics-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Render Process Tree Node Recursively
  const renderTreeNode = (node: EdrProcessNode, depth: number = 0) => {
    const isSelected = node.pid === selectedProcessPid;
    return (
      <div key={node.pid} className="space-y-1">
        <div
          onClick={() => setSelectedProcessPid(node.pid)}
          className={`p-2.5 rounded-lg border font-mono text-xs cursor-pointer transition-all flex items-center justify-between gap-3 ${
            isSelected
              ? 'bg-red-950/40 border-red-500/60 shadow-[0_0_15px_rgba(239,68,68,0.2)]'
              : 'bg-[#111] hover:bg-[#161616] border-[#222]'
          }`}
          style={{ marginLeft: `${depth * 20}px` }}
        >
          <div className="flex items-center gap-2.5 overflow-hidden">
            <div className={`p-1.5 rounded ${
              node.actionTaken === 'TERMINATE' ? 'bg-red-900/60 text-red-300' :
              node.actionTaken === 'SUSPICIOUS' ? 'bg-amber-900/60 text-amber-300' :
              'bg-emerald-950/60 text-emerald-400'
            }`}>
              <Activity className="w-3.5 h-3.5" />
            </div>

            <div className="truncate">
              <div className="flex items-center gap-2">
                <strong className="text-white font-bold">{node.name}</strong>
                <span className="text-zinc-500 text-[10px]">PID: {node.pid}</span>
                <span className="text-zinc-500 text-[10px] hidden sm:inline">PPID: {node.ppid}</span>
              </div>
              <span className="text-[10px] text-zinc-400 truncate block max-w-xs sm:max-w-md">
                {node.commandLine}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
              node.threatScore >= 80 ? 'bg-red-950 text-red-300 border border-red-800' :
              node.threatScore >= 40 ? 'bg-amber-950 text-amber-300 border border-amber-800' :
              'bg-zinc-800 text-zinc-400'
            }`}>
              Risco {node.threatScore}%
            </span>

            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
              node.actionTaken === 'TERMINATE' ? 'bg-red-950 text-red-400 border border-red-800' :
              node.actionTaken === 'SUSPICIOUS' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
              'bg-emerald-950 text-emerald-400 border border-emerald-800'
            }`}>
              {node.actionTaken}
            </span>
          </div>
        </div>

        {node.children && node.children.map(child => renderTreeNode(child, depth + 1))}
      </div>
    );
  };

  return (
    <div id="edr-suite-container" className="space-y-6">
      {/* Top Banner & Kernel Driver Telemetry */}
      <div className="bg-[#0A0A0A] border border-[#222] rounded-xl p-4 sm:p-6 relative overflow-hidden shadow-lg">
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-bl from-red-600/10 via-transparent to-transparent pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#1A1A1A] pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-lg bg-red-500/10 text-red-500 border border-red-500/30">
                <Zap className="w-5 h-5 animate-pulse" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white font-mono">
                    Endpoint Detection &amp; Response (EDR)
                  </h1>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/40 font-bold uppercase">
                    eBPF Kernel Enclave
                  </span>
                </div>
                <p className="text-xs text-zinc-400">
                  Visibilidade profunda de processos, interceptação de chamadas de sistema, análise de memória RWX e caça a ameaças (Threat Hunting)
                </p>
              </div>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="flex items-center gap-2 sm:gap-4 flex-wrap font-mono">
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Processos Ativos</span>
              <span className="text-sm font-bold text-white">{telemetry.totalMonitoredProcesses}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Ataques Bloqueados</span>
              <span className="text-sm font-bold text-red-400">{telemetry.blockedAttacksToday}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Quarentena Binária</span>
              <span className="text-sm font-bold text-amber-400">{telemetry.quarantinedBinaries}</span>
            </div>
            <button
              onClick={handleExportForensicsReport}
              className="h-9 px-3 rounded-lg bg-[#141414] hover:bg-[#1E1E1E] text-zinc-300 hover:text-white border border-[#333] font-mono text-xs inline-flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Exportar dossiê forense EDR em JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Exportar Forense</span>
            </button>
          </div>
        </div>

        {/* Live Kernel Driver & Tamper Protection Status */}
        <div className="pt-4 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Sensor de Kernel:</span>
            <span className="text-[#00FF41] font-bold">{telemetry.kernelDriver}</span>
          </div>
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Proteção Anti-Tamper:</span>
            <span className="text-cyan-400 font-bold">{telemetry.tamperProtection}</span>
          </div>
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Sensores de Rede Locais:</span>
            <span className="text-white font-bold">{telemetry.networkSensorsActive} interfaces</span>
          </div>
        </div>
      </div>

      {/* Navigation Sub-tabs */}
      <div className="flex items-center gap-2 border-b border-[#222] pb-1 overflow-x-auto no-scrollbar font-mono text-xs">
        <button
          onClick={() => setActiveSubTab('process_tree')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'process_tree'
              ? 'text-red-400 border-red-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <GitBranch className="w-3.5 h-3.5" />
          <span>Árvore de Execução &amp; Processos</span>
        </button>

        <button
          onClick={() => setActiveSubTab('behavioral_rules')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'behavioral_rules'
              ? 'text-red-400 border-red-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Crosshair className="w-3.5 h-3.5" />
          <span>Regras Comportamentais (IOA / MITRE) ({behavioralRules.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('threat_hunting')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'threat_hunting'
              ? 'text-red-400 border-red-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Search className="w-3.5 h-3.5" />
          <span>Threat Hunting (Busca Ativa de Ameaças)</span>
        </button>

        <button
          onClick={() => setActiveSubTab('memory_forensics')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'memory_forensics'
              ? 'text-red-400 border-red-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>Forense de Memória &amp; Dumps YARA ({memoryDumps.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('isolation_matrix')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'isolation_matrix'
              ? 'text-red-400 border-red-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Contenção &amp; Quarentena Host</span>
        </button>
      </div>

      {/* SUBTAB 1: Process Tree & Deep Inspection */}
      {activeSubTab === 'process_tree' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Left Column: Interactive Tree */}
          <div className="lg:col-span-6 space-y-3">
            <div className="bg-[#0E0E0E] p-3 rounded-lg border border-[#222] flex items-center justify-between">
              <span className="text-xs font-mono font-bold uppercase text-white flex items-center gap-1.5">
                <GitBranch className="w-4 h-4 text-red-500" />
                <span>Hierarquia Parent-Child de Processos</span>
              </span>
              <span className="text-[10px] font-mono text-zinc-500">Clique para inspecionar</span>
            </div>

            <div className="space-y-2">
              {processTree.map(node => renderTreeNode(node, 0))}
            </div>
          </div>

          {/* Right Column: Selected Process Deep Forensics */}
          <div className="lg:col-span-6">
            <div className="bg-[#0E0E0E] border border-[#222] rounded-xl p-5 space-y-4 font-mono text-xs">
              <div className="flex items-start justify-between border-b border-[#222] pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <strong className="text-white text-base font-bold">{selectedProcess.name}</strong>
                    <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 text-[10px]">
                      PID {selectedProcess.pid}
                    </span>
                    <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 text-[10px]">
                      PPID {selectedProcess.ppid}
                    </span>
                  </div>
                  <span className="text-[11px] text-zinc-500 block mt-0.5">
                    Usuário: <strong className="text-zinc-300">{selectedProcess.user}</strong> (Integridade: {selectedProcess.integrityLevel})
                  </span>
                </div>

                <button
                  onClick={() => handleTerminateProcess(selectedProcess.pid)}
                  className="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white font-bold text-xs uppercase inline-flex items-center gap-1.5 cursor-pointer shadow-md"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Matar Processo</span>
                </button>
              </div>

              {/* Command Line & Hash */}
              <div className="space-y-2">
                <div>
                  <span className="text-[10px] text-zinc-500 uppercase block font-bold">Linha de Comando Completa:</span>
                  <div className="p-2.5 rounded bg-[#141414] border border-[#2A2A2A] text-amber-300 break-all">
                    <code>{selectedProcess.commandLine}</code>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-zinc-500 uppercase block font-bold">Hash SHA-256 do Binário:</span>
                  <div className="p-2 rounded bg-[#141414] border border-[#2A2A2A] text-zinc-300 text-[11px] flex items-center justify-between">
                    <code className="truncate">{selectedProcess.hashSha256}</code>
                    <button
                      onClick={() => handleCopy(selectedProcess.hashSha256, 'hash')}
                      className="text-zinc-500 hover:text-white ml-2 cursor-pointer"
                    >
                      {copiedKey === 'hash' ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>

              {/* Active Sockets / Network Connections */}
              <div className="space-y-1.5 pt-2 border-t border-[#1E1E1E]">
                <span className="text-[10.5px] text-zinc-400 uppercase font-bold block">
                  Conexões de Rede Abertas ({selectedProcess.networkConnections.length})
                </span>
                {selectedProcess.networkConnections.length === 0 ? (
                  <span className="text-zinc-600 text-[11px]">Nenhum socket de rede associado a este processo.</span>
                ) : (
                  <div className="space-y-1">
                    {selectedProcess.networkConnections.map((net, i) => (
                      <div key={i} className="p-2 rounded bg-[#121212] border border-[#222] flex items-center justify-between text-[11px]">
                        <div className="flex items-center gap-2">
                          <Network className="w-3.5 h-3.5 text-cyan-400" />
                          <span className="text-white font-bold">{net.protocol}</span>
                          <span className="text-zinc-400">Porta Local: {net.localPort} &rarr; Remoto: {net.remoteAddress}:{net.remotePort}</span>
                        </div>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                          {net.state}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* File System Modifications */}
              <div className="space-y-1.5 pt-2 border-t border-[#1E1E1E]">
                <span className="text-[10.5px] text-zinc-400 uppercase font-bold block">
                  Tentativas de Modificação e Acesso a Arquivos ({selectedProcess.fileModifications.length})
                </span>
                {selectedProcess.fileModifications.length === 0 ? (
                  <span className="text-zinc-600 text-[11px]">Nenhuma modificação de disco registrada pelo driver.</span>
                ) : (
                  <div className="space-y-1">
                    {selectedProcess.fileModifications.map((file, i) => (
                      <div key={i} className="p-1.5 rounded bg-[#121212] border border-[#222] text-[11px] text-rose-400 flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 text-rose-500 shrink-0" />
                        <span className="truncate">{file}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 2: Behavioral Rules (IOA / MITRE) */}
      {activeSubTab === 'behavioral_rules' && (
        <div className="space-y-4">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-red-500" />
              <span>Regras de Indicadores de Ataque Comportamental (IOA)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Assinaturas de comportamento em tempo de execução que disparam remediação imediata antes que o malware consiga completar seus objetivos.
            </p>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {behavioralRules.map((rule) => (
              <div key={rule.id} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E1E1E] pb-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      rule.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-800' :
                      rule.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                      'bg-blue-950 text-blue-300 border border-blue-800'
                    }`}>
                      {rule.severity}
                    </span>
                    <strong className="text-white text-sm">{rule.name}</strong>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-zinc-500 text-[10.5px]">Disparos: <strong className="text-white">{rule.hitsCount}</strong></span>
                    <button
                      onClick={() => handleToggleRule(rule.id)}
                      className={`px-2 py-1 rounded text-[10px] font-bold uppercase cursor-pointer border ${
                        rule.active ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-zinc-900 text-zinc-500 border-zinc-800'
                      }`}
                    >
                      {rule.active ? 'ATIVO' : 'DESATIVADO'}
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-zinc-400">
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Tática MITRE ATT&amp;CK:</span>
                    <span className="text-white font-semibold">{rule.mitreTactic}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Técnica Específica:</span>
                    <span className="text-cyan-400 font-semibold">{rule.mitreTechnique}</span>
                  </div>
                </div>

                <div className="p-2.5 bg-[#121212] border border-[#222] rounded text-[11px]">
                  <span className="text-zinc-500 uppercase block text-[9.5px] mb-1">Condição de Disparo (Kernel Hook):</span>
                  <code className="text-amber-300 break-all">{rule.triggerCondition}</code>
                </div>

                <div className="text-[11px] text-zinc-400">
                  <strong className="text-zinc-300">Ação Automática de Remediação: </strong>
                  <span className="text-red-400 font-bold">{rule.autoRemediation}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 3: Threat Hunting Console */}
      {activeSubTab === 'threat_hunting' && (
        <div className="space-y-4">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
              <Search className="w-4 h-4 text-red-500" />
              <span>Console de Threat Hunting (Busca de Indicadores Avançados)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Escreva queries estruturadas em linguagem tipo KQL/Splunk para varrer a telemetria histórica de todos os processos e conexões.
            </p>
          </div>

          <div className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4 space-y-3 font-mono text-xs">
            <label className="text-zinc-400 font-bold uppercase text-[10.5px] block">Query de Hunting (KQL / EDR Syntax):</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={customHuntingQuery}
                onChange={(e) => setCustomHuntingQuery(e.target.value)}
                className="flex-1 h-9 px-3 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-red-500"
              />
              <button
                onClick={handleRunHuntingQuery}
                disabled={huntingExecuting}
                className="h-9 px-4 rounded bg-red-600 hover:bg-red-500 text-white font-bold uppercase inline-flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                {huntingExecuting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                <span>Executar Query</span>
              </button>
            </div>

            {huntingResultCount !== null && (
              <div className="p-3 rounded bg-black/60 border border-emerald-500/40 text-emerald-300 text-xs flex items-center justify-between">
                <span>Busca concluída em 38ms através de 432 processos e 16 sensores de rede.</span>
                <strong className="text-white">{huntingResultCount} ocorrências encontradas</strong>
              </div>
            )}
          </div>

          {/* Preset Hunting Playbooks */}
          <div className="space-y-2">
            <span className="text-zinc-400 font-mono text-xs font-bold uppercase block">Playbooks e Queries Prontas:</span>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
              {huntingQueries.map((hunt) => (
                <div key={hunt.id} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-3.5 space-y-2 flex flex-col justify-between">
                  <div className="space-y-1.5">
                    <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 text-[10px] font-bold uppercase">
                      {hunt.category}
                    </span>
                    <h3 className="font-bold text-white text-xs">{hunt.title}</h3>
                    <p className="text-zinc-400 text-[11px]">{hunt.description}</p>
                  </div>

                  <button
                    onClick={() => {
                      setCustomHuntingQuery(hunt.queryText);
                      handleRunHuntingQuery();
                    }}
                    className="w-full mt-2 py-1.5 rounded bg-[#181818] hover:bg-zinc-800 text-zinc-200 border border-[#333] text-[10.5px] font-bold cursor-pointer"
                  >
                    Carregar &amp; Rodar ({hunt.matchesFound} matches)
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 4: Memory Forensics & YARA */}
      {activeSubTab === 'memory_forensics' && (
        <div className="space-y-4">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-red-500" />
              <span>Análise Forense de Memória de Processos (Dumps &amp; Regras YARA)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Captura e varredura de regiões de memória de processos suspeitos em busca de chaves em texto plano, injeção de DLLs e shellcodes.
            </p>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {memoryDumps.map((dump) => (
              <div key={dump.id} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4.5 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E1E1E] pb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-white text-sm">{dump.processName}</span>
                    <span className="text-zinc-500 text-[11px]">PID {dump.pid}</span>
                    <span className="text-zinc-400">({dump.endpointHostname})</span>
                  </div>

                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    dump.status === 'FLAGGED' ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-zinc-800 text-zinc-400'
                  }`}>
                    {dump.status}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-zinc-400">
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Tamanho do Dump:</span>
                    <span className="text-white font-bold">{dump.dumpSizeMb} MB</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Segredos Extraídos:</span>
                    <span className="text-red-400 font-bold">{dump.extractedSecretsCount} credenciais</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Timestamp:</span>
                    <span className="text-zinc-300">{dump.timestamp}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Process Hollowing:</span>
                    <span className={dump.hollowedMemoryRegions ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                      {dump.hollowedMemoryRegions ? 'DETECTADO' : 'NENHUM'}
                    </span>
                  </div>
                </div>

                <div className="space-y-1 pt-1">
                  <span className="text-zinc-500 text-[10px] uppercase block font-bold">Assinaturas YARA Disparadas:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {dump.yaraRuleMatches.length === 0 ? (
                      <span className="text-zinc-600">Nenhuma regra YARA disparada no dump.</span>
                    ) : (
                      dump.yaraRuleMatches.map((yara, i) => (
                        <span key={i} className="px-2 py-0.5 rounded bg-red-950/60 text-red-300 border border-red-800/40 text-[10px] font-bold">
                          {yara}
                        </span>
                      ))
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 5: Isolation & Host Quarantine Matrix */}
      {activeSubTab === 'isolation_matrix' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-500" />
              <span>Matriz de Contenção de Rede &amp; Quarentena Host (Zero Trust EDR)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Isolamento instantâneo a nível de kernel: corta todo o tráfego de entrada e saída mantendo apenas o canal de comando e controle do sensor.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-[#0D0D0D] border border-red-500/30 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-[#222] pb-2">
                <strong className="text-white text-sm">Host: prod-api-gateway-01</strong>
                <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                  NORMAL
                </span>
              </div>
              <p className="text-zinc-400 text-[11px] leading-relaxed">
                Este host executa os microserviços de pagamento e gateway público. Em caso de comprometimento grave (RCE ou vazamento de chave mestre), clique abaixo para desconectá-lo da VPC.
              </p>
              <button
                onClick={() => alert('Host isolado preventivamente a nível de kernel pelo sensor EDR.')}
                className="w-full py-2 rounded bg-red-600 hover:bg-red-500 text-white font-bold uppercase text-xs cursor-pointer shadow-lg"
              >
                Acionar Contenção de Rede Imediata
              </button>
            </div>

            <div className="bg-[#0D0D0D] border border-[#222] rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-[#222] pb-2">
                <strong className="text-white text-sm">Host: worker-node-k8s-pod-7</strong>
                <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 text-[10px] font-bold">
                  NORMAL
                </span>
              </div>
              <p className="text-zinc-400 text-[11px] leading-relaxed">
                Nó de processamento assíncrono conectado ao Redis e PostgreSQL interno.
              </p>
              <button
                onClick={() => alert('Host isolado preventivamente a nível de kernel pelo sensor EDR.')}
                className="w-full py-2 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 font-bold uppercase text-xs cursor-pointer"
              >
                Acionar Contenção de Rede Imediata
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
