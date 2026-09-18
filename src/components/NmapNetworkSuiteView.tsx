import React, { useState, useMemo } from 'react';
import {
  Radio,
  Search,
  Filter,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Terminal,
  Activity,
  Layers,
  Clock,
  Play,
  Copy,
  Check,
  Download,
  RotateCcw,
  Sparkles,
  Server,
  Cpu,
  Workflow,
  Eye,
  Crosshair,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  FileCode2,
  Lock,
  Globe,
  Network,
  Zap,
  Info
} from 'lucide-react';
import { ScanReport } from '../types';
import { 
  NmapHostTarget, 
  NmapScanProfile, 
  NmapSuiteSession, 
  NmapPortService, 
  NmapScriptResult 
} from '../types/nmap';
import { 
  NMAP_PRESET_PROFILES, 
  NSE_SCRIPT_DATABASE, 
  generateDiscoveredHostsFromReport, 
  simulateNmapScanExecution 
} from '../lib/nmapEngine';

interface NmapNetworkSuiteViewProps {
  report: ScanReport;
  onNavigateToScanner?: () => void;
  onNavigateToEndpoints?: () => void;
}

export const NmapNetworkSuiteView: React.FC<NmapNetworkSuiteViewProps> = ({
  report,
  onNavigateToScanner,
  onNavigateToEndpoints
}) => {
  // Initial hosts state
  const [hosts, setHosts] = useState<NmapHostTarget[]>(() => generateDiscoveredHostsFromReport(report));
  const [selectedProfile, setSelectedProfile] = useState<NmapScanProfile>(NMAP_PRESET_PROFILES[0]);
  const [targetInput, setTargetInput] = useState<string>('10.0.0.0/24');
  const [customFlagsInput, setCustomFlagsInput] = useState<string>('');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [activeSubTab, setActiveSubTab] = useState<'topology' | 'ports' | 'nse' | 'terminal' | 'os'>('topology');
  const [selectedHostId, setSelectedHostId] = useState<string>(hosts[0]?.id || '');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [portFilterState, setPortFilterState] = useState<'ALL' | 'OPEN' | 'FILTERED'>('ALL');
  const [copiedTerminal, setCopiedTerminal] = useState<boolean>(false);
  const [commandCopied, setCommandCopied] = useState<boolean>(false);

  // Latest session
  const [latestSession, setLatestSession] = useState<NmapSuiteSession>(() => 
    simulateNmapScanExecution('10.0.0.0/24', NMAP_PRESET_PROFILES[0], '', hosts)
  );

  // Computed selected host
  const selectedHost = useMemo(() => {
    return hosts.find(h => h.id === selectedHostId) || hosts[0] || null;
  }, [hosts, selectedHostId]);

  // Filtered hosts based on search
  const filteredHosts = useMemo(() => {
    if (!searchQuery.trim()) return hosts;
    const q = searchQuery.toLowerCase();
    return hosts.filter(h => 
      h.hostname.toLowerCase().includes(q) ||
      h.ip.includes(q) ||
      h.ports.some(p => p.service.toLowerCase().includes(q) || p.port.toString().includes(q))
    );
  }, [hosts, searchQuery]);

  // Filtered ports for selected host
  const displayedPorts = useMemo(() => {
    if (!selectedHost) return [];
    let list = selectedHost.ports;
    if (portFilterState !== 'ALL') {
      list = list.filter(p => p.state === portFilterState);
    }
    return list;
  }, [selectedHost, portFilterState]);

  // Aggregate stats across hosts
  const stats = useMemo(() => {
    const totalHosts = hosts.length;
    const hostsUp = hosts.filter(h => h.status === 'UP').length;
    const allPorts = hosts.flatMap(h => h.ports);
    const openPorts = allPorts.filter(p => p.state === 'OPEN').length;
    const criticalVulnerabilities = hosts.reduce((acc, h) => 
      acc + h.scriptResults.filter(s => s.severity === 'CRITICAL' || s.severity === 'HIGH').length, 0
    );
    return { totalHosts, hostsUp, openPorts, criticalVulnerabilities };
  }, [hosts]);

  // Trigger simulated scan
  const handleExecuteScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      const session = simulateNmapScanExecution(targetInput, selectedProfile, customFlagsInput, hosts);
      setLatestSession(session);
      setIsScanning(false);
    }, 900);
  };

  const handleCopyCommand = () => {
    const fullCmd = `nmap ${customFlagsInput || selectedProfile.cliFlags} ${targetInput}`;
    navigator.clipboard?.writeText(fullCmd);
    setCommandCopied(true);
    setTimeout(() => setCommandCopied(false), 2000);
  };

  const handleCopyTerminal = () => {
    navigator.clipboard?.writeText(latestSession.rawConsoleOutput);
    setCopiedTerminal(true);
    setTimeout(() => setCopiedTerminal(false), 2000);
  };

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(latestSession, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `nmap-audit-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div id="nmap-network-suite-container" className="space-y-6">
      {/* Top Banner & Control Deck */}
      <div className="bg-[#0A0A0A] border border-[#222] rounded-xl p-4 sm:p-6 relative overflow-hidden shadow-lg">
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-bl from-[#00FF41]/5 via-transparent to-transparent pointer-events-none" />
        
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#1A1A1A] pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-lg bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30">
                <Network className="w-5 h-5" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white font-mono">
                    Nmap Security Suite
                  </h1>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#00FF41]/15 text-[#00FF41] border border-[#00FF41]/40 font-bold uppercase">
                    Port &amp; Host Recon
                  </span>
                </div>
                <p className="text-xs text-zinc-400">
                  Exploração de topologia de rede, auditoria de portas abertas, detecção de SO e scripts NSE
                </p>
              </div>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="flex items-center gap-2 sm:gap-4 flex-wrap">
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] font-mono text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Hosts Ativos</span>
              <span className="text-sm font-bold text-[#00FF41]">{stats.hostsUp}/{stats.totalHosts}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] font-mono text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Portas Abertas</span>
              <span className="text-sm font-bold text-amber-400">{stats.openPorts}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] font-mono text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">NSE Vulns</span>
              <span className="text-sm font-bold text-[#FF3E00]">{stats.criticalVulnerabilities}</span>
            </div>
            <button
              id="btn-nmap-export-session"
              onClick={handleExportJson}
              className="h-9 px-3 rounded-lg bg-[#141414] hover:bg-[#1E1E1E] text-zinc-300 hover:text-white border border-[#333] font-mono text-xs inline-flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Exportar dados do Nmap em formato JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Exportar JSON</span>
            </button>
          </div>
        </div>

        {/* Scan Command Builder */}
        <div className="pt-4 grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-3 space-y-1">
            <label className="text-[11px] font-mono font-bold uppercase text-zinc-400 block">
              Perfil de Varredura
            </label>
            <select
              value={selectedProfile.id}
              onChange={(e) => {
                const found = NMAP_PRESET_PROFILES.find(p => p.id === e.target.value);
                if (found) setSelectedProfile(found);
              }}
              className="w-full h-9 px-2.5 rounded bg-[#141414] border border-[#333] text-white font-mono text-xs focus:outline-none focus:border-[#00FF41]"
            >
              {NMAP_PRESET_PROFILES.map(p => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-3 space-y-1">
            <label className="text-[11px] font-mono font-bold uppercase text-zinc-400 block">
              Alvo / Sub-rede (IP/CIDR)
            </label>
            <input
              type="text"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="Ex: 10.0.0.0/24 ou 10.0.4.15"
              className="w-full h-9 px-3 rounded bg-[#141414] border border-[#333] text-white font-mono text-xs focus:outline-none focus:border-[#00FF41]"
            />
          </div>

          <div className="md:col-span-4 space-y-1">
            <label className="text-[11px] font-mono font-bold uppercase text-zinc-400 flex items-center justify-between">
              <span>Flags Nmap Customizadas</span>
              <span className="text-[10px] text-zinc-500 font-normal">Opcional</span>
            </label>
            <input
              type="text"
              value={customFlagsInput}
              onChange={(e) => setCustomFlagsInput(e.target.value)}
              placeholder={selectedProfile.cliFlags}
              className="w-full h-9 px-3 rounded bg-[#141414] border border-[#333] text-white font-mono text-xs focus:outline-none focus:border-[#00FF41]"
            />
          </div>

          <div className="md:col-span-2 flex items-center gap-2">
            <button
              id="btn-execute-nmap-scan"
              onClick={handleExecuteScan}
              disabled={isScanning}
              className={`w-full h-9 rounded inline-flex items-center justify-center gap-1.5 font-mono text-xs font-bold uppercase tracking-wider transition-all cursor-pointer shadow-md ${
                isScanning 
                  ? 'bg-zinc-800 text-zinc-500 cursor-not-allowed border border-zinc-700' 
                  : 'bg-[#00FF41] hover:bg-[#00D636] text-black border border-[#00FF41]'
              }`}
            >
              {isScanning ? (
                <>
                  <Activity className="w-3.5 h-3.5 animate-spin" />
                  <span>Sondando...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Executar</span>
                </>
              )}
            </button>
            <button
              onClick={handleCopyCommand}
              title="Copiar comando de terminal"
              className="h-9 w-9 rounded bg-[#181818] hover:bg-[#222] border border-[#333] text-zinc-400 hover:text-white flex items-center justify-center cursor-pointer shrink-0"
            >
              {commandCopied ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>

        {/* Live Command Preview Pill */}
        <div className="mt-3 px-3 py-1.5 rounded bg-[#0F0F0F] border border-[#222] flex items-center justify-between font-mono text-[11px] text-zinc-400">
          <div className="flex items-center gap-2 overflow-x-auto truncate">
            <Terminal className="w-3.5 h-3.5 text-[#00FF41] shrink-0" />
            <span className="text-zinc-500">$</span>
            <span className="text-white font-bold">nmap</span>
            <span className="text-[#00FF41]">{customFlagsInput || selectedProfile.cliFlags}</span>
            <span className="text-amber-300">{targetInput}</span>
          </div>
          <span className="text-[10px] text-zinc-500 hidden sm:inline shrink-0">
            Timing: {selectedProfile.timingTemplate} // {selectedProfile.technique}
          </span>
        </div>
      </div>

      {/* Navigation Sub-tabs */}
      <div className="flex items-center gap-2 border-b border-[#222] pb-1 overflow-x-auto no-scrollbar font-mono text-xs">
        <button
          onClick={() => setActiveSubTab('topology')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'topology'
              ? 'text-[#00FF41] border-[#00FF41] bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Server className="w-3.5 h-3.5" />
          <span>Hosts &amp; Topologia ({hosts.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('ports')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'ports'
              ? 'text-[#00FF41] border-[#00FF41] bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Crosshair className="w-3.5 h-3.5" />
          <span>Portas &amp; Banners ({stats.openPorts})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('nse')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'nse'
              ? 'text-[#00FF41] border-[#00FF41] bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>NSE Scripts &amp; Vulns ({stats.criticalVulnerabilities})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('os')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'os'
              ? 'text-[#00FF41] border-[#00FF41] bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>OS Fingerprint &amp; Stack</span>
        </button>

        <button
          onClick={() => setActiveSubTab('terminal')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'terminal'
              ? 'text-[#00FF41] border-[#00FF41] bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>Output do Terminal</span>
        </button>
      </div>

      {/* SUBTAB CONTENT 1: Topology & Hosts Grid */}
      {activeSubTab === 'topology' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Host list column */}
          <div className="lg:col-span-5 space-y-3">
            <div className="relative">
              <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Filtrar hosts por IP, hostname ou porta..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full h-9 pl-9 pr-3 rounded bg-[#111] border border-[#2A2A2A] text-white font-mono text-xs focus:outline-none focus:border-[#00FF41]"
              />
            </div>

            <div className="space-y-2">
              {filteredHosts.map((host) => {
                const isSelected = selectedHost?.id === host.id;
                const openCount = host.ports.filter(p => p.state === 'OPEN').length;
                const hasCritical = host.scriptResults.some(s => s.severity === 'CRITICAL' || s.severity === 'HIGH');
                
                return (
                  <div
                    key={host.id}
                    onClick={() => setSelectedHostId(host.id)}
                    className={`p-3.5 rounded-lg border transition-all cursor-pointer flex items-center justify-between gap-3 ${
                      isSelected 
                        ? 'bg-[#141414] border-[#00FF41]/60 shadow-[0_0_15px_rgba(0,255,65,0.1)]' 
                        : 'bg-[#0E0E0E] hover:bg-[#121212] border-[#222]'
                    }`}
                  >
                    <div className="flex items-start gap-3 min-w-0">
                      <div className={`mt-0.5 p-2 rounded ${
                        hasCritical ? 'bg-rose-950/50 text-rose-400 border border-rose-800/40' : 'bg-zinc-800 text-zinc-300'
                      }`}>
                        <Server className="w-4 h-4" />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-white truncate">
                            {host.hostname}
                          </span>
                          <span className="w-1.5 h-1.5 rounded-full bg-[#00FF41]" />
                        </div>
                        <span className="text-[11px] font-mono text-zinc-400 block">
                          {host.ip}
                        </span>
                        <span className="text-[10px] text-zinc-500 truncate block">
                          {host.osFingerprint.name}
                        </span>
                      </div>
                    </div>

                    <div className="flex flex-col items-end gap-1 shrink-0 font-mono text-right">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                        {openCount} portas
                      </span>
                      <span className="text-[9.5px] text-zinc-500">
                        {host.latencyMs}ms RTT
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Selected Host Details View */}
          <div className="lg:col-span-7">
            {selectedHost ? (
              <div className="bg-[#0D0D0D] border border-[#222] rounded-xl p-5 space-y-5">
                {/* Host Title */}
                <div className="flex items-center justify-between border-b border-[#222] pb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-lg font-bold font-mono text-white">
                        {selectedHost.hostname}
                      </h2>
                      <span className="px-2 py-0.5 rounded bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30 font-mono text-[10px] font-bold">
                        HOST UP
                      </span>
                    </div>
                    <p className="text-xs font-mono text-zinc-400 mt-0.5">
                      IPv4: <strong className="text-white">{selectedHost.ip}</strong> • MAC: {selectedHost.macAddress || 'N/A'} ({selectedHost.vendor || 'Dispositivo de Rede'})
                    </p>
                  </div>
                  <div className="text-right font-mono text-xs">
                    <span className="text-zinc-500 block text-[10px] uppercase">RTT / Latência</span>
                    <span className="text-[#00FF41] font-bold">{selectedHost.latencyMs} ms</span>
                  </div>
                </div>

                {/* Host Quick Metadata */}
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs font-mono">
                  <div className="p-2.5 bg-[#121212] border border-[#222] rounded">
                    <span className="text-[10px] text-zinc-500 uppercase block">Sistema Operacional</span>
                    <span className="text-white font-bold truncate block">{selectedHost.osFingerprint.family}</span>
                    <span className="text-[10px] text-zinc-400">Precisão: {selectedHost.osFingerprint.accuracy}%</span>
                  </div>
                  <div className="p-2.5 bg-[#121212] border border-[#222] rounded">
                    <span className="text-[10px] text-zinc-500 uppercase block">Portas Monitoradas</span>
                    <span className="text-amber-400 font-bold block">{selectedHost.ports.length} portas</span>
                    <span className="text-[10px] text-[#00FF41]">{selectedHost.ports.filter(p => p.state === 'OPEN').length} abertas</span>
                  </div>
                  <div className="p-2.5 bg-[#121212] border border-[#222] rounded col-span-2 sm:col-span-1">
                    <span className="text-[10px] text-zinc-500 uppercase block">CPE do Host</span>
                    <span className="text-zinc-300 text-[10px] truncate block">{selectedHost.osFingerprint.cpe}</span>
                    <span className="text-[10px] text-zinc-500">{selectedHost.osFingerprint.deviceType}</span>
                  </div>
                </div>

                {/* Ports list summary */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-300 flex items-center gap-1.5">
                      <Crosshair className="w-3.5 h-3.5 text-[#00FF41]" />
                      <span>Serviços &amp; Portas Abertas</span>
                    </h3>
                    <button
                      onClick={() => setActiveSubTab('ports')}
                      className="text-[11px] font-mono text-[#00FF41] hover:underline"
                    >
                      Ver detalhes das portas &rarr;
                    </button>
                  </div>

                  <div className="border border-[#222] rounded-lg overflow-hidden font-mono text-xs">
                    <table className="w-full text-left">
                      <thead className="bg-[#141414] text-zinc-400 text-[10px] uppercase border-b border-[#222]">
                        <tr>
                          <th className="py-2 px-3">Porta</th>
                          <th className="py-2 px-3">Estado</th>
                          <th className="py-2 px-3">Serviço</th>
                          <th className="py-2 px-3">Versão de Software</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#1A1A1A]">
                        {selectedHost.ports.map((p) => (
                          <tr key={`${p.port}-${p.protocol}`} className="hover:bg-[#121212]">
                            <td className="py-2 px-3 font-bold text-white">
                              {p.port}/{p.protocol}
                            </td>
                            <td className="py-2 px-3">
                              <span className={`px-1.5 py-0.5 rounded text-[9.5px] font-bold uppercase ${
                                p.state === 'OPEN' 
                                  ? 'bg-[#00FF41]/15 text-[#00FF41] border border-[#00FF41]/30' 
                                  : 'bg-zinc-800 text-zinc-400'
                              }`}>
                                {p.state}
                              </span>
                            </td>
                            <td className="py-2 px-3 text-zinc-300">{p.service}</td>
                            <td className="py-2 px-3 text-zinc-400 truncate max-w-[200px]">
                              {p.version || 'Banner não detectado'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Traceroute Topology */}
                {selectedHost.tracerouteHops && (
                  <div className="space-y-2 pt-2 border-t border-[#222]">
                    <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-300 flex items-center gap-1.5">
                      <Workflow className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Rota de Rede (Traceroute Hops)</span>
                    </h3>
                    <div className="p-3 bg-[#111] border border-[#222] rounded-lg space-y-1.5 font-mono text-xs">
                      {selectedHost.tracerouteHops.map((hop) => (
                        <div key={hop.hop} className="flex items-center justify-between text-zinc-300">
                          <div className="flex items-center gap-2">
                            <span className="w-5 text-zinc-500 font-bold">{hop.hop}</span>
                            <span className="text-white font-bold">{hop.ip}</span>
                            <span className="text-zinc-500 text-[11px]">({hop.hostname})</span>
                          </div>
                          <span className="text-cyan-400 text-[11px]">{hop.rttMs} ms</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-12 text-center text-zinc-500 font-mono text-xs border border-dashed border-[#222] rounded-xl">
                Selecione um host para inspecionar topologia e portas.
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUBTAB CONTENT 2: Ports & Banners Detailed */}
      {activeSubTab === 'ports' && selectedHost && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0E0E0E] p-3 rounded-lg border border-[#222]">
            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="text-zinc-400">Host Selecionado:</span>
              <span className="text-white font-bold">{selectedHost.hostname} ({selectedHost.ip})</span>
            </div>

            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="text-zinc-500">Filtrar Estado:</span>
              <button
                onClick={() => setPortFilterState('ALL')}
                className={`px-2 py-0.5 rounded cursor-pointer ${
                  portFilterState === 'ALL' ? 'bg-[#00FF41] text-black font-bold' : 'bg-[#1A1A1A] text-zinc-400'
                }`}
              >
                Todas ({selectedHost.ports.length})
              </button>
              <button
                onClick={() => setPortFilterState('OPEN')}
                className={`px-2 py-0.5 rounded cursor-pointer ${
                  portFilterState === 'OPEN' ? 'bg-[#00FF41] text-black font-bold' : 'bg-[#1A1A1A] text-zinc-400'
                }`}
              >
                Abertas ({selectedHost.ports.filter(p => p.state === 'OPEN').length})
              </button>
              <button
                onClick={() => setPortFilterState('FILTERED')}
                className={`px-2 py-0.5 rounded cursor-pointer ${
                  portFilterState === 'FILTERED' ? 'bg-[#00FF41] text-black font-bold' : 'bg-[#1A1A1A] text-zinc-400'
                }`}
              >
                Filtradas ({selectedHost.ports.filter(p => p.state === 'FILTERED').length})
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {displayedPorts.map((port) => (
              <div
                key={`${port.port}-${port.protocol}`}
                className="bg-[#0D0D0D] border border-[#222] hover:border-[#333] rounded-xl p-4 space-y-3 font-mono text-xs transition-colors"
              >
                <div className="flex items-center justify-between border-b border-[#1E1E1E] pb-2.5">
                  <div className="flex items-center gap-2">
                    <span className="text-base font-bold text-white">
                      {port.port}/{port.protocol}
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                      port.state === 'OPEN' 
                        ? 'bg-[#00FF41]/15 text-[#00FF41] border border-[#00FF41]/30' 
                        : 'bg-zinc-800 text-zinc-400 border border-zinc-700'
                    }`}>
                      {port.state}
                    </span>
                  </div>
                  <span className="text-zinc-400 text-xs font-bold uppercase">
                    {port.service}
                  </span>
                </div>

                <div className="space-y-1.5 text-zinc-300 text-[11px]">
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Produto &amp; Versão</span>
                    <span className="text-white font-semibold">{port.version || 'Não identificada'}</span>
                  </div>
                  {port.bannerSnippet && (
                    <div className="p-2 rounded bg-[#141414] border border-[#222] font-mono text-[10.5px] text-zinc-300 break-all">
                      <span className="text-zinc-500 text-[9px] uppercase block">Banner Raw Interrogado</span>
                      {port.bannerSnippet}
                    </div>
                  )}
                  {port.cveMatches && port.cveMatches.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 pt-1">
                      <span className="text-[10px] text-rose-400 font-bold uppercase">CVEs:</span>
                      {port.cveMatches.map(cve => (
                        <span key={cve} className="px-1.5 py-0.2 rounded bg-rose-950/60 text-rose-300 border border-rose-800/40 text-[9.5px]">
                          {cve}
                        </span>
                      ))}
                    </div>
                  )}
                  {port.remediation && (
                    <div className="pt-2 border-t border-[#1C1C1C] text-[11px] text-zinc-400">
                      <strong className="text-amber-400 font-bold">Ação Recomendada: </strong>
                      {port.remediation}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB CONTENT 3: NSE Scripts & Vuln Audit */}
      {activeSubTab === 'nse' && (
        <div className="space-y-4">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-2">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-[#FF3E00]" />
              <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
                Resultados dos Scripts Lua do Nmap Scripting Engine (NSE)
              </h2>
            </div>
            <p className="text-xs text-zinc-400">
              Correlacionamento de vulnerabilidades ativas, configurações de risco, SSL/TLS ciphers e injeção de parâmetros nos serviços mapeados.
            </p>
          </div>

          <div className="space-y-3">
            {hosts.flatMap(h => h.scriptResults.map(script => ({ ...script, hostIp: h.ip, hostName: h.hostname }))).map((script) => (
              <div
                key={`${script.hostIp}-${script.id}`}
                className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4.5 space-y-3 font-mono"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E1E1E] pb-2.5">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-white flex items-center gap-1.5">
                      <Terminal className="w-4 h-4 text-[#00FF41]" />
                      <span>{script.name}</span>
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      script.severity === 'CRITICAL' ? 'bg-rose-950/70 text-rose-300 border border-rose-800' :
                      script.severity === 'HIGH' ? 'bg-amber-950/70 text-amber-300 border border-amber-800' :
                      'bg-blue-950/70 text-blue-300 border border-blue-800'
                    }`}>
                      {script.severity}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">
                      cat: {script.category}
                    </span>
                  </div>

                  <div className="text-xs text-zinc-400">
                    Alvo: <strong className="text-white">{script.hostName} ({script.hostIp})</strong>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#121212] border border-[#1F1F1F] text-xs text-zinc-300 whitespace-pre-line leading-relaxed font-mono">
                  {script.output}
                </div>

                <div className="flex items-center justify-between pt-1 text-xs">
                  <div className="text-zinc-400">
                    <span className="text-amber-400 font-bold">Correção: </span>
                    <span>{script.recommendation}</span>
                  </div>
                  {script.cvss && (
                    <span className="text-rose-400 font-bold shrink-0 ml-2">
                      CVSS v3: {script.cvss}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* NSE Scripts Library Reference */}
          <div className="pt-4 border-t border-[#222]">
            <h3 className="text-xs font-mono font-bold uppercase text-zinc-400 mb-3 flex items-center gap-1.5">
              <FileCode2 className="w-3.5 h-3.5 text-zinc-500" />
              <span>Scripts NSE Integrados no SecScan Hub</span>
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {NSE_SCRIPT_DATABASE.map(item => (
                <div key={item.id} className="p-3 bg-[#111] border border-[#222] rounded-lg font-mono text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-[#00FF41]">{item.name}</span>
                    <span className="text-[9.5px] px-1 rounded bg-zinc-800 text-zinc-400">{item.category}</span>
                  </div>
                  <p className="text-[10.5px] text-zinc-400 leading-snug">{item.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB CONTENT 4: OS Fingerprint */}
      {activeSubTab === 'os' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {hosts.map(host => (
              <div key={host.id} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4.5 space-y-3 font-mono">
                <div className="flex items-center justify-between border-b border-[#1E1E1E] pb-2">
                  <div>
                    <h3 className="font-bold text-white text-sm">{host.hostname}</h3>
                    <span className="text-xs text-zinc-500">{host.ip}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30 text-[10px] font-bold">
                    {host.osFingerprint.accuracy}% MATCH
                  </span>
                </div>

                <div className="space-y-2 text-xs">
                  <div>
                    <span className="text-[10px] text-zinc-500 uppercase block">SO Identificado</span>
                    <span className="text-zinc-200 font-bold">{host.osFingerprint.name}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-zinc-500 uppercase block">Família do Kernel</span>
                    <span className="text-zinc-300">{host.osFingerprint.family}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-zinc-500 uppercase block">CPE (Common Platform Enumeration)</span>
                    <span className="text-[10px] text-zinc-400 break-all">{host.osFingerprint.cpe}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-zinc-500 uppercase block">Tipo de Dispositivo</span>
                    <span className="text-zinc-300 capitalize">{host.osFingerprint.deviceType}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB CONTENT 5: Raw Terminal Output */}
      {activeSubTab === 'terminal' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono text-xs text-zinc-400">
              <Terminal className="w-4 h-4 text-[#00FF41]" />
              <span>Sessão: {latestSession.sessionId}</span>
              <span>• Duração: {latestSession.durationSeconds}s</span>
            </div>
            <button
              id="btn-copy-nmap-terminal-output"
              onClick={handleCopyTerminal}
              className="px-3 py-1.5 rounded bg-[#181818] hover:bg-[#222] border border-[#333] text-zinc-300 hover:text-white font-mono text-xs flex items-center gap-1.5 cursor-pointer"
            >
              {copiedTerminal ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedTerminal ? 'Copiado' : 'Copiar Saída'}</span>
            </button>
          </div>

          <div className="p-4 rounded-xl bg-[#050505] border border-[#222] font-mono text-xs text-[#00FF41] overflow-x-auto whitespace-pre leading-relaxed shadow-inner max-h-[500px]">
            {latestSession.rawConsoleOutput}
          </div>
        </div>
      )}
    </div>
  );
};
