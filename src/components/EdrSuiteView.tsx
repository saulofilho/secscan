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
  Share2,
  Laptop,
  CheckSquare,
  Send,
  Workflow,
  Sparkles,
  ShieldCheck,
  HardDrive
} from 'lucide-react';
import { ScanReport } from '../types';
import {
  EdrProcessNode,
  EdrBehavioralRule,
  EdrMemoryDumpAnalysis,
  EdrThreatHuntingQuery,
  EdrLiveTelemetry,
  EdrHostEndpoint,
  EdrResponsePlaybook,
  EdrIocItem,
  EdrRtrCommandResult
} from '../types/edr';
import {
  INITIAL_PROCESS_TREES,
  INITIAL_BEHAVIORAL_RULES,
  INITIAL_MEMORY_DUMPS,
  INITIAL_HUNTING_QUERIES,
  INITIAL_EDR_TELEMETRY,
  INITIAL_HOST_ENDPOINTS,
  INITIAL_RESPONSE_PLAYBOOKS,
  INITIAL_IOC_ITEMS,
  INITIAL_RTR_COMMANDS
} from '../lib/edrEngine';

interface EdrSuiteViewProps {
  report: ScanReport;
  onNavigateToScanner?: () => void;
  onNavigateToSecurityOnion?: () => void;
  onNavigateToNgfw?: () => void;
}

type EdrSubTab = 
  | 'process_tree' 
  | 'behavioral_rules' 
  | 'threat_hunting' 
  | 'memory_forensics' 
  | 'endpoints_inventory'
  | 'response_playbooks'
  | 'rtr_terminal'
  | 'ioc_vault'
  | 'isolation_matrix';

export const EdrSuiteView: React.FC<EdrSuiteViewProps> = ({
  report,
  onNavigateToScanner,
  onNavigateToSecurityOnion,
  onNavigateToNgfw
}) => {
  // Navigation tabs
  const [activeSubTab, setActiveSubTab] = useState<EdrSubTab>('process_tree');

  // Core EDR Datasets
  const [processTree, setProcessTree] = useState<EdrProcessNode[]>(INITIAL_PROCESS_TREES);
  const [behavioralRules, setBehavioralRules] = useState<EdrBehavioralRule[]>(INITIAL_BEHAVIORAL_RULES);
  const [memoryDumps, setMemoryDumps] = useState<EdrMemoryDumpAnalysis[]>(INITIAL_MEMORY_DUMPS);
  const [huntingQueries, setHuntingQueries] = useState<EdrThreatHuntingQuery[]>(INITIAL_HUNTING_QUERIES);
  const [telemetry, setTelemetry] = useState<EdrLiveTelemetry>(INITIAL_EDR_TELEMETRY);
  const [endpoints, setEndpoints] = useState<EdrHostEndpoint[]>(INITIAL_HOST_ENDPOINTS);
  const [playbooks, setPlaybooks] = useState<EdrResponsePlaybook[]>(INITIAL_RESPONSE_PLAYBOOKS);
  const [iocList, setIocList] = useState<EdrIocItem[]>(INITIAL_IOC_ITEMS);
  const [rtrHistory, setRtrHistory] = useState<EdrRtrCommandResult[]>(INITIAL_RTR_COMMANDS);

  // Selected process inspection
  const [selectedProcessPid, setSelectedProcessPid] = useState<number>(7921);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Threat hunting interactive console
  const [customHuntingQuery, setCustomHuntingQuery] = useState<string>('EventType == "ProcessCreation" and ThreatScore > 70');
  const [huntingExecuting, setHuntingExecuting] = useState<boolean>(false);
  const [huntingResultCount, setHuntingResultCount] = useState<number | null>(null);

  // RTR Terminal Interactive state
  const [selectedHostForRtr, setSelectedHostForRtr] = useState<string>('prod-api-gateway-01');
  const [rtrCommandInput, setRtrCommandInput] = useState<string>('');
  const [isExecutingRtr, setIsExecutingRtr] = useState<boolean>(false);

  // New IOC state
  const [newIocType, setNewIocType] = useState<EdrIocItem['type']>('SHA256');
  const [newIocValue, setNewIocValue] = useState<string>('');
  const [newIocThreat, setNewIocThreat] = useState<string>('');
  const [showAddIocModal, setShowAddIocModal] = useState<boolean>(false);

  // Endpoint filter
  const [endpointSearch, setEndpointSearch] = useState<string>('');

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

  // Host Isolation Toggle
  const handleToggleIsolation = (endpointId: string) => {
    setEndpoints(prev => prev.map(ep => {
      if (ep.id === endpointId) {
        const newStatus = ep.isolationStatus === 'NORMAL' ? 'ISOLATED' : 'NORMAL';
        const newMode = newStatus === 'ISOLATED' ? 'KERNEL_FILTER' : 'NONE';
        return {
          ...ep,
          isolationStatus: newStatus,
          containmentMode: newMode
        };
      }
      return ep;
    }));
  };

  // Run Playbook
  const handleRunPlaybook = (playbookId: string) => {
    setPlaybooks(prev => prev.map(pb => {
      if (pb.id === playbookId) {
        return {
          ...pb,
          status: 'EXECUTING'
        };
      }
      return pb;
    }));

    setTimeout(() => {
      setPlaybooks(prev => prev.map(pb => {
        if (pb.id === playbookId) {
          return {
            ...pb,
            status: 'COMPLETED',
            lastRun: `Executado agora com sucesso em ${endpoints.length} hosts.`
          };
        }
        return pb;
      }));
    }, 1200);
  };

  // Run RTR Command
  const handleExecuteRtr = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!rtrCommandInput.trim() || isExecutingRtr) return;

    const cmd = rtrCommandInput.trim();
    setIsExecutingRtr(true);

    setTimeout(() => {
      let outputText = '';
      if (cmd.startsWith('ps')) {
        outputText = `PID  PPID USER     %CPU %MEM CMD\n 5124  2410 app-runner 14.2  4.0 node dist/server.cjs\n 2410  1402 root        1.8  1.4 /usr/bin/dockerd\n 1402     1 root        0.1  0.3 /sbin/init`;
      } else if (cmd.startsWith('kill') || cmd.startsWith('pkill')) {
        outputText = `[eBPF Sensor] Process signal sent successfully. Kernel hook confirmation: PID terminated.`;
      } else if (cmd.startsWith('netstat') || cmd.startsWith('ss')) {
        outputText = `Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\ntcp   LISTEN 0      128    0.0.0.0:3000        0.0.0.0:*`;
      } else if (cmd.startsWith('isolate')) {
        outputText = `[Containment] Host ${selectedHostForRtr} has been ISOLATED at kernel network driver level. All non-EDR traffic dropped.`;
      } else if (cmd.startsWith('quarantine')) {
        outputText = `[Forensics] File marked as immutable (chattr +i) and placed into /var/quarantine/edr-vault.enc.`;
      } else {
        outputText = `[Host: ${selectedHostForRtr}] Command executed via secure RTR channel.\nStdout: OK. Process exit code 0.`;
      }

      const newEntry: EdrRtrCommandResult = {
        id: `RTR-${Date.now()}`,
        command: cmd,
        output: outputText,
        timestamp: new Date().toLocaleTimeString(),
        status: 'SUCCESS',
        exitCode: 0
      };

      setRtrHistory(prev => [newEntry, ...prev]);
      setRtrCommandInput('');
      setIsExecutingRtr(false);
    }, 500);
  };

  // Add IOC
  const handleAddIoc = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIocValue.trim()) return;

    const newIoc: EdrIocItem = {
      id: `IOC-${Date.now()}`,
      type: newIocType,
      value: newIocValue.trim(),
      threatType: newIocThreat.trim() || 'Ameaça Identificada por Investigador',
      confidence: 95,
      mitreRef: 'T1059',
      action: 'BLOCK_AND_KILL',
      dateAdded: 'Agora'
    };

    setIocList(prev => [newIoc, ...prev]);
    setNewIocValue('');
    setNewIocThreat('');
    setShowAddIocModal(false);
  };

  const handleExportForensicsReport = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({
      telemetry,
      endpoints,
      processTree,
      behavioralRules,
      memoryDumps,
      huntingQueries,
      playbooks,
      iocList,
      rtrHistory
    }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `edr-endpoint-forensics-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Filtered Endpoints
  const filteredEndpoints = useMemo(() => {
    if (!endpointSearch.trim()) return endpoints;
    const term = endpointSearch.toLowerCase();
    return endpoints.filter(ep => 
      ep.hostname.toLowerCase().includes(term) ||
      ep.ip.toLowerCase().includes(term) ||
      ep.os.toLowerCase().includes(term)
    );
  }, [endpoints, endpointSearch]);

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
                <Crosshair className="w-5 h-5 animate-pulse" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white font-mono">
                    SecScan EDR &amp; Live Response Suite
                  </h1>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/40 font-bold uppercase">
                    eBPF Sensor Engine
                  </span>
                </div>
                <p className="text-xs text-zinc-400">
                  Monitoramento profundo de endpoints, árvore de processos parent-child, Live Response Shell (RTR), forense de memória e contenção Zero Trust.
                </p>
              </div>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="flex items-center gap-2 sm:gap-4 flex-wrap font-mono">
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Hosts Monitorados</span>
              <span className="text-sm font-bold text-white">{endpoints.length} ativos</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Processos Ativos</span>
              <span className="text-sm font-bold text-white">{telemetry.totalMonitoredProcesses}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Ataques Bloqueados</span>
              <span className="text-sm font-bold text-red-400">{telemetry.blockedAttacksToday}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Quarentenas</span>
              <span className="text-sm font-bold text-amber-400">{telemetry.quarantinedBinaries}</span>
            </div>
            <button
              onClick={handleExportForensicsReport}
              className="h-9 px-3 rounded-lg bg-[#141414] hover:bg-[#1E1E1E] text-zinc-300 hover:text-white border border-[#333] font-mono text-xs inline-flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Exportar dossiê forense EDR completo em JSON"
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
          <span>Árvore de Processos</span>
        </button>

        <button
          onClick={() => setActiveSubTab('endpoints_inventory')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'endpoints_inventory'
              ? 'text-red-400 border-red-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Laptop className="w-3.5 h-3.5" />
          <span>Inventário de Endpoints ({endpoints.length})</span>
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
          <span>Regras IOA / MITRE ({behavioralRules.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('rtr_terminal')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'rtr_terminal'
              ? 'text-red-400 border-red-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Terminal className="w-3.5 h-3.5 text-emerald-400" />
          <span>Real-Time Response (RTR Shell)</span>
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
          <span>Threat Hunting (KQL)</span>
        </button>

        <button
          onClick={() => setActiveSubTab('response_playbooks')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'response_playbooks'
              ? 'text-red-400 border-red-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Workflow className="w-3.5 h-3.5 text-amber-400" />
          <span>Playbooks de Resposta ({playbooks.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('ioc_vault')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'ioc_vault'
              ? 'text-red-400 border-red-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Database className="w-3.5 h-3.5 text-cyan-400" />
          <span>Cofre de IOCs ({iocList.length})</span>
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
          <span>Forense de Memória ({memoryDumps.length})</span>
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
          <span>Contenção Host</span>
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

      {/* SUBTAB 2: Endpoints Inventory */}
      {activeSubTab === 'endpoints_inventory' && (
        <div className="space-y-4">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
                <Laptop className="w-4 h-4 text-red-500" />
                <span>Inventário de Endpoints &amp; Sensores EDR</span>
              </h2>
              <p className="text-xs text-zinc-400">
                Parque computacional sob monitoramento do agente eBPF com telemetria contínua de recursos e status de contenção.
              </p>
            </div>

            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-zinc-500" />
              <input
                type="text"
                placeholder="Filtrar por hostname, IP ou OS..."
                value={endpointSearch}
                onChange={(e) => setEndpointSearch(e.target.value)}
                className="pl-9 pr-3 py-1.5 bg-[#141414] border border-[#333] rounded-lg text-xs text-white focus:outline-none focus:border-red-500 w-64 font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredEndpoints.map(ep => (
              <div 
                key={ep.id} 
                className={`bg-[#0D0D0D] border rounded-xl p-4.5 space-y-3 font-mono text-xs transition-all ${
                  ep.isolationStatus === 'ISOLATED'
                    ? 'border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.15)]'
                    : 'border-[#222] hover:border-[#333]'
                }`}
              >
                <div className="flex items-center justify-between border-b border-[#1E1E1E] pb-2.5">
                  <div className="flex items-center gap-2">
                    <span className={`w-2.5 h-2.5 rounded-full ${ep.isolationStatus === 'ISOLATED' ? 'bg-red-500 animate-ping' : 'bg-emerald-500'}`} />
                    <strong className="text-white text-sm">{ep.hostname}</strong>
                    <span className="text-zinc-500 text-[10px]">({ep.ip})</span>
                  </div>

                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    ep.isolationStatus === 'ISOLATED'
                      ? 'bg-red-950 text-red-300 border border-red-800'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}>
                    {ep.isolationStatus === 'ISOLATED' ? 'CONTEÚDO ISOLADO' : 'NORMAL'}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-zinc-400 text-[11px]">
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Sistema Operacional:</span>
                    <span className="text-zinc-200 truncate block">{ep.os}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Versão do Agente:</span>
                    <span className="text-cyan-400 font-semibold">{ep.agentVersion}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Carga de CPU:</span>
                    <div className="flex items-center gap-2">
                      <div className="w-20 bg-zinc-800 h-1.5 rounded-full overflow-hidden">
                        <div 
                          className={`h-full ${ep.cpuLoad > 80 ? 'bg-red-500' : 'bg-emerald-400'}`}
                          style={{ width: `${Math.min(ep.cpuLoad, 100)}%` }}
                        />
                      </div>
                      <span className="text-white font-bold">{ep.cpuLoad}%</span>
                    </div>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Uso de Memória:</span>
                    <span className="text-zinc-200 font-bold">{ep.memoryUsageMb} MB</span>
                  </div>
                </div>

                <div className="pt-2 border-t border-[#1A1A1A] flex items-center justify-between">
                  <div className="flex items-center gap-2 text-[10.5px]">
                    <span className="text-zinc-500">Alertas Ativos:</span>
                    <span className={`font-bold ${ep.activeAlertsCount > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {ep.activeAlertsCount}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => {
                        setSelectedHostForRtr(ep.hostname);
                        setActiveSubTab('rtr_terminal');
                      }}
                      className="px-2.5 py-1 rounded bg-[#181818] hover:bg-zinc-800 text-zinc-200 border border-[#333] text-[10.5px] font-bold cursor-pointer inline-flex items-center gap-1"
                    >
                      <Terminal className="w-3 h-3 text-emerald-400" />
                      <span>Abrir RTR</span>
                    </button>

                    <button
                      onClick={() => handleToggleIsolation(ep.id)}
                      className={`px-2.5 py-1 rounded text-[10.5px] font-bold uppercase cursor-pointer border ${
                        ep.isolationStatus === 'ISOLATED'
                          ? 'bg-zinc-800 text-zinc-300 border-zinc-700 hover:bg-zinc-700'
                          : 'bg-red-900/60 text-red-200 border-red-800 hover:bg-red-800'
                      }`}
                    >
                      {ep.isolationStatus === 'ISOLATED' ? 'Remover Isolamento' : 'Isolar Host'}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 3: Behavioral Rules (IOA / MITRE) */}
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

      {/* SUBTAB 4: Real-Time Response (RTR Shell) */}
      {activeSubTab === 'rtr_terminal' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-emerald-400" />
                <span>Real-Time Response (RTR Terminal)</span>
              </h2>
              <p className="text-xs text-zinc-400">
                Sessão interativa direta com o sensor do endpoint para execução de comandos cirúrgicos de investigação e contenção remota.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-zinc-500 text-[10px] uppercase">Host Alvo:</span>
              <select
                value={selectedHostForRtr}
                onChange={(e) => setSelectedHostForRtr(e.target.value)}
                className="bg-[#141414] border border-[#333] rounded px-2.5 py-1 text-xs text-white focus:outline-none focus:border-red-500"
              >
                {endpoints.map(ep => (
                  <option key={ep.id} value={ep.hostname}>
                    {ep.hostname} ({ep.ip})
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Terminal Console View */}
          <div className="bg-[#050505] border border-[#222] rounded-xl overflow-hidden shadow-2xl">
            <div className="bg-[#111] px-4 py-2 border-b border-[#222] flex items-center justify-between text-[11px]">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                <span className="text-zinc-400 font-bold ml-2">rtr-session://{selectedHostForRtr} (eBPF secure stream)</span>
              </div>
              <span className="text-emerald-400 font-bold">ONLINE [TLS 1.3 mTLS]</span>
            </div>

            {/* Terminal History */}
            <div className="p-4 space-y-4 max-h-96 overflow-y-auto">
              <div className="text-zinc-500 text-[11px] leading-relaxed">
                SecScan EDR Real-Time Response Shell v4.2.1-kernel<br />
                Type &apos;help&apos;, &apos;ps&apos;, &apos;netstat&apos;, &apos;isolate&apos;, &apos;kill &lt;pid&gt;&apos; or &apos;quarantine &lt;path&gt;&apos;.<br />
                ────────────────────────────────────────────────────────────────────────
              </div>

              {rtrHistory.map(entry => (
                <div key={entry.id} className="space-y-1">
                  <div className="flex items-center gap-2 text-cyan-300">
                    <span className="text-red-500 font-black">root@{selectedHostForRtr}:~#</span>
                    <span className="text-white font-bold">{entry.command}</span>
                    <span className="text-zinc-600 text-[9.5px] ml-auto">{entry.timestamp}</span>
                  </div>
                  <pre className="p-2.5 rounded bg-[#0A0A0A] border border-[#1A1A1A] text-zinc-300 whitespace-pre-wrap leading-relaxed text-[11px]">
                    {entry.output}
                  </pre>
                </div>
              ))}
            </div>

            {/* Terminal Input Bar */}
            <form onSubmit={handleExecuteRtr} className="p-2.5 bg-[#0D0D0D] border-t border-[#222] flex gap-2">
              <span className="text-red-500 font-black flex items-center pl-2">#</span>
              <input
                type="text"
                placeholder="Digite o comando RTR (ex: ps, netstat, kill 7921, isolate, quarantine /tmp/malware.sh)..."
                value={rtrCommandInput}
                onChange={(e) => setRtrCommandInput(e.target.value)}
                disabled={isExecutingRtr}
                className="flex-1 bg-transparent border-none text-white text-xs focus:outline-none font-mono"
              />
              <button
                type="submit"
                disabled={isExecutingRtr || !rtrCommandInput.trim()}
                className="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold uppercase text-[11px] cursor-pointer disabled:opacity-50 inline-flex items-center gap-1.5"
              >
                {isExecutingRtr ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                <span>Enviar</span>
              </button>
            </form>
          </div>
        </div>
      )}

      {/* SUBTAB 5: Threat Hunting Console */}
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

      {/* SUBTAB 6: Response Playbooks */}
      {activeSubTab === 'response_playbooks' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Workflow className="w-4 h-4 text-amber-400" />
              <span>Playbooks Automatizados de Resposta a Incidentes (SOAR Integrado)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Ações orquestradas pré-configuradas para contenção instantânea, coleta forense de evidências e erradicação de ameaças em endpoints.
            </p>
          </div>

          <div className="space-y-3">
            {playbooks.map(pb => (
              <div key={pb.id} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4.5 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E1E1E] pb-2.5">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      pb.executionType === 'AUTOMATED' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
                    }`}>
                      {pb.executionType}
                    </span>
                    <strong className="text-white text-sm">{pb.name}</strong>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      pb.status === 'COMPLETED' ? 'bg-zinc-800 text-emerald-400' :
                      pb.status === 'EXECUTING' ? 'bg-amber-950 text-amber-300 animate-pulse' :
                      'bg-zinc-800 text-zinc-400'
                    }`}>
                      {pb.status}
                    </span>
                    <button
                      onClick={() => handleRunPlaybook(pb.id)}
                      disabled={pb.status === 'EXECUTING'}
                      className="px-3 py-1 rounded bg-amber-600 hover:bg-amber-500 text-white font-bold uppercase text-[10.5px] cursor-pointer disabled:opacity-50 inline-flex items-center gap-1.5"
                    >
                      {pb.status === 'EXECUTING' ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                      <span>Disparar Playbook</span>
                    </button>
                  </div>
                </div>

                <p className="text-zinc-300 text-xs">{pb.description}</p>

                <div className="bg-[#121212] p-3 rounded-lg border border-[#222] space-y-1">
                  <span className="text-zinc-500 text-[10px] uppercase font-bold block">Etapas de Execução Orquestrada:</span>
                  <ul className="space-y-1 text-zinc-400 text-[11px]">
                    {pb.steps.map((st, i) => (
                      <li key={i} className="flex items-center gap-2">
                        <CheckSquare className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                        <span>{st}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {pb.lastRun && (
                  <span className="text-[10px] text-zinc-500 block">
                    Última Execução: <strong className="text-zinc-400">{pb.lastRun}</strong>
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 7: IOC Vault */}
      {activeSubTab === 'ioc_vault' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
                <Database className="w-4 h-4 text-cyan-400" />
                <span>Cofre Central de Indicadores de Comprometimento (IOCs)</span>
              </h2>
              <p className="text-xs text-zinc-400">
                Hashes maliciosos, endereços IPs de C2 e caminhos restritos sincronizados diretamente com os filtros de kernel dos agentes EDR.
              </p>
            </div>

            <button
              onClick={() => setShowAddIocModal(true)}
              className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold uppercase text-xs inline-flex items-center gap-1.5 cursor-pointer shadow-md"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Adicionar IOC</span>
            </button>
          </div>

          <div className="bg-[#0D0D0D] border border-[#222] rounded-xl overflow-hidden">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-[#121212] border-b border-[#222] text-[10px] text-zinc-500 uppercase tracking-wider">
                  <th className="py-2.5 px-3">Tipo</th>
                  <th className="py-2.5 px-3">Valor do IOC</th>
                  <th className="py-2.5 px-3">Classificação de Ameaça</th>
                  <th className="py-2.5 px-3">MITRE</th>
                  <th className="py-2.5 px-3">Confiança</th>
                  <th className="py-2.5 px-3">Ação do Agente</th>
                  <th className="py-2.5 px-3">Ações</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1A1A1A] text-[11px]">
                {iocList.map(ioc => (
                  <tr key={ioc.id} className="hover:bg-[#111] transition-colors">
                    <td className="py-2.5 px-3">
                      <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-cyan-300 font-bold text-[10px]">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-white font-mono break-all max-w-xs">
                      {ioc.value}
                    </td>
                    <td className="py-2.5 px-3 text-zinc-300">
                      {ioc.threatType}
                    </td>
                    <td className="py-2.5 px-3 text-zinc-400">
                      {ioc.mitreRef}
                    </td>
                    <td className="py-2.5 px-3 font-bold text-[#00FF41]">
                      {ioc.confidence}%
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        ioc.action === 'BLOCK_AND_KILL' ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
                      }`}>
                        {ioc.action}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <button
                        onClick={() => setIocList(prev => prev.filter(i => i.id !== ioc.id))}
                        className="text-zinc-500 hover:text-red-400 cursor-pointer"
                        title="Remover IOC do cofre"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Add IOC Modal */}
          {showAddIocModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-xs p-4">
              <div className="bg-[#111] border border-[#333] rounded-xl p-5 max-w-md w-full space-y-4">
                <div className="flex items-center justify-between border-b border-[#222] pb-2">
                  <strong className="text-white text-sm">Registrar Novo IOC no Sensor EDR</strong>
                  <button onClick={() => setShowAddIocModal(false)} className="text-zinc-500 hover:text-white cursor-pointer">
                    <XCircle className="w-4 h-4" />
                  </button>
                </div>

                <form onSubmit={handleAddIoc} className="space-y-3">
                  <div>
                    <label className="text-zinc-400 text-[10.5px] uppercase block mb-1">Tipo de Indicador:</label>
                    <select
                      value={newIocType}
                      onChange={(e) => setNewIocType(e.target.value as any)}
                      className="w-full bg-[#181818] border border-[#333] rounded p-2 text-xs text-white"
                    >
                      <option value="SHA256">SHA256 (Hash de Executável)</option>
                      <option value="IPV4">IPV4 (Endereço C2 / Proxy Malicioso)</option>
                      <option value="DOMAIN">DOMAIN (FQDN Exfiltração)</option>
                      <option value="FILE_PATH">FILE_PATH (Local Restrito)</option>
                      <option value="MUTEX">MUTEX (Identificador de Ransomware)</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-zinc-400 text-[10.5px] uppercase block mb-1">Valor do Indicador:</label>
                    <input
                      type="text"
                      placeholder="Ex: 4b227777d... ou 198.51.100.44"
                      value={newIocValue}
                      onChange={(e) => setNewIocValue(e.target.value)}
                      className="w-full bg-[#181818] border border-[#333] rounded p-2 text-xs text-white font-mono"
                      required
                    />
                  </div>

                  <div>
                    <label className="text-zinc-400 text-[10.5px] uppercase block mb-1">Classificação / Descrição da Ameaça:</label>
                    <input
                      type="text"
                      placeholder="Ex: Trojan Dropper / Cobalt Strike Beacon"
                      value={newIocThreat}
                      onChange={(e) => setNewIocThreat(e.target.value)}
                      className="w-full bg-[#181818] border border-[#333] rounded p-2 text-xs text-white"
                    />
                  </div>

                  <div className="flex justify-end gap-2 pt-2">
                    <button
                      type="button"
                      onClick={() => setShowAddIocModal(false)}
                      className="px-3 py-1.5 rounded bg-zinc-800 text-zinc-300 text-xs font-bold cursor-pointer"
                    >
                      Cancelar
                    </button>
                    <button
                      type="submit"
                      className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold cursor-pointer"
                    >
                      Salvar IOC
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 8: Memory Forensics & YARA */}
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

      {/* SUBTAB 9: Isolation & Host Quarantine Matrix */}
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
            {endpoints.map(ep => (
              <div 
                key={ep.id} 
                className={`bg-[#0D0D0D] border rounded-xl p-5 space-y-3 transition-all ${
                  ep.isolationStatus === 'ISOLATED'
                    ? 'border-red-500/60 shadow-[0_0_20px_rgba(239,68,68,0.2)]'
                    : 'border-[#222]'
                }`}
              >
                <div className="flex items-center justify-between border-b border-[#222] pb-2">
                  <div>
                    <strong className="text-white text-sm">{ep.hostname}</strong>
                    <span className="text-zinc-500 text-[10px] block">{ep.ip} • {ep.criticality}</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    ep.isolationStatus === 'ISOLATED'
                      ? 'bg-red-950 text-red-300 border border-red-800'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}>
                    {ep.isolationStatus}
                  </span>
                </div>
                <p className="text-zinc-400 text-[11px] leading-relaxed">
                  {ep.isolationStatus === 'ISOLATED'
                    ? 'Host desconectado da rede local e internet via filtro eBPF. Apenas a porta de telemetria TLS do agente SecScan EDR permanece aberta.'
                    : 'Host em operação normal. Em caso de comprometimento severo (RCE ou vazamento de chave mestre), clique abaixo para desconectá-lo da VPC.'}
                </p>
                <button
                  onClick={() => handleToggleIsolation(ep.id)}
                  className={`w-full py-2 rounded font-bold uppercase text-xs cursor-pointer shadow-lg transition-colors ${
                    ep.isolationStatus === 'ISOLATED'
                      ? 'bg-zinc-800 hover:bg-zinc-700 text-zinc-200'
                      : 'bg-red-600 hover:bg-red-500 text-white'
                  }`}
                >
                  {ep.isolationStatus === 'ISOLATED' ? 'Restaurar Acesso de Rede do Host' : 'Acionar Contenção de Rede Imediata'}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
