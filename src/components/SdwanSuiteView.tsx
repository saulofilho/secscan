import React, { useState, useMemo } from 'react';
import {
  Network,
  Share2,
  Activity,
  Globe,
  Zap,
  Sliders,
  Radio,
  Server,
  Download,
  Copy,
  Check,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Binary,
  Layers,
  ShieldCheck,
  RotateCcw,
  Plus,
  Trash2,
  Lock,
  ArrowRight,
  TrendingDown,
  Cpu,
  Wifi,
  RadioTower,
  Eye
} from 'lucide-react';
import { ScanReport } from '../types';
import {
  SdwanEdgeDevice,
  SdwanTrafficPolicy,
  SdwanTunnelMesh,
  SdwanNetworkTelemetry,
  WanLinkStatus,
  WanLinkType
} from '../types/sdwan';
import {
  INITIAL_SDWAN_EDGES,
  INITIAL_TRAFFIC_POLICIES,
  INITIAL_TUNNELS_MESH,
  INITIAL_SDWAN_TELEMETRY
} from '../lib/sdwanEngine';

interface SdwanSuiteViewProps {
  report: ScanReport;
  onNavigateToScanner?: () => void;
  onNavigateToNgfw?: () => void;
  onNavigateToIdsIps?: () => void;
  onNavigateToWaf?: () => void;
  onNavigateToDns?: () => void;
}

export const SdwanSuiteView: React.FC<SdwanSuiteViewProps> = ({
  report,
  onNavigateToScanner,
  onNavigateToNgfw,
  onNavigateToIdsIps,
  onNavigateToWaf,
  onNavigateToDns
}) => {
  const [telemetry, setTelemetry] = useState<SdwanNetworkTelemetry>(INITIAL_SDWAN_TELEMETRY);
  const [edges, setEdges] = useState<SdwanEdgeDevice[]>(INITIAL_SDWAN_EDGES);
  const [policies, setPolicies] = useState<SdwanTrafficPolicy[]>(INITIAL_TRAFFIC_POLICIES);
  const [tunnels, setTunnels] = useState<SdwanTunnelMesh[]>(INITIAL_TUNNELS_MESH);

  // Active sub-tab
  const [activeSubTab, setActiveSubTab] = useState<'edges' | 'traffic_steering' | 'tunnel_mesh' | 'sla_telemetry'>('edges');

  // Selected Edge for detailed WAN breakdown
  const [selectedEdgeId, setSelectedEdgeId] = useState<string>('edge-hq-sp');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Selected edge object
  const selectedEdge = useMemo(() => {
    return edges.find(e => e.id === selectedEdgeId) || edges[0];
  }, [edges, selectedEdgeId]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Simulate Instant WAN Failover
  const handleSimulateFailover = (linkId: string) => {
    setEdges(prev => prev.map(edge => {
      const updatedLinks = edge.activeWanLinks.map(link => {
        if (link.id === linkId) {
          const nextStatus: WanLinkStatus = link.status === 'OPTIMAL' ? 'DEGRADED' : 'OPTIMAL';
          return {
            ...link,
            status: nextStatus,
            packetLossPct: nextStatus === 'DEGRADED' ? 12.5 : 0.0,
            latencyMs: nextStatus === 'DEGRADED' ? link.latencyMs * 4 : link.latencyMs
          };
        }
        return link;
      });
      return { ...edge, activeWanLinks: updatedLinks };
    }));

    setTelemetry(prev => ({
      ...prev,
      failoversHandledWithoutDrop: prev.failoversHandledWithoutDrop + 1
    }));
  };

  // Toggle Policy FEC / Duplication
  const handleToggleFec = (policyId: string) => {
    setPolicies(prev => prev.map(p => p.id === policyId ? { ...p, forwardErrorCorrection: !p.forwardErrorCorrection } : p));
  };

  const handleToggleDuplication = (policyId: string) => {
    setPolicies(prev => prev.map(p => p.id === policyId ? { ...p, packetDuplication: !p.packetDuplication } : p));
  };

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({
      telemetry,
      edges,
      policies,
      tunnels
    }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `sdwan-orchestrator-telemetry-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div id="sdwan-suite-container" className="space-y-6 font-sans">
      {/* Top Banner & SD-WAN Orchestrator Telemetry */}
      <div className="bg-[#0A0A0A] border border-[#222] rounded-xl p-4 sm:p-6 relative overflow-hidden shadow-lg">
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-bl from-blue-500/10 via-transparent to-transparent pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#1A1A1A] pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/30">
                <Network className="w-5 h-5 animate-pulse" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white font-mono">
                    SD-WAN Orchestrator &amp; Dynamic Fabric
                  </h1>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase border bg-blue-500/20 text-blue-300 border-blue-500/40">
                    ZTP (Zero-Touch) Ativo
                  </span>
                </div>
                <p className="text-xs text-zinc-400">
                  Roteamento dinâmico baseado em SLA de aplicação (App-Aware Steering), failover instantâneo sem queda de sessão, overlay IPsec multi-link e agregação MPLS, Fibra e 5G
                </p>
              </div>
            </div>
          </div>

          {/* Quick Global Metrics Bar */}
          <div className="flex items-center gap-2 sm:gap-4 flex-wrap font-mono">
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Dispositivos Edge</span>
              <span className="text-sm font-bold text-white">{telemetry.totalSitesOnline} Sites</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Túneis Overlay</span>
              <span className="text-sm font-bold text-cyan-400">{telemetry.totalDynamicTunnels} Ativos</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Tráfego Otimizado</span>
              <span className="text-sm font-bold text-[#00FF41]">{telemetry.trafficOptimizedTodayGb} GB</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Failovers Sem Queda</span>
              <span className="text-sm font-bold text-amber-400">{telemetry.failoversHandledWithoutDrop}</span>
            </div>
            <button
              onClick={handleExportJson}
              className="h-9 px-3 rounded-lg bg-[#141414] hover:bg-[#1E1E1E] text-zinc-300 hover:text-white border border-[#333] font-mono text-xs inline-flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Exportar Topologia</span>
            </button>
          </div>
        </div>

        {/* Global Orchestrator Summary */}
        <div className="pt-4 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Estado do Plano de Controle:</span>
            <span className="text-emerald-400 font-bold">100% Sincronizado (BGP EVPN + OMP)</span>
          </div>
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Latência Média da Malha (Mesh):</span>
            <span className="text-white font-bold">{telemetry.globalAvgLatencyMs} ms</span>
          </div>
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Perda de Pacotes na Rede:</span>
            <span className="text-[#00FF41] font-bold">{telemetry.globalAvgPacketLossPct}% (Dentro do SLA)</span>
          </div>
        </div>
      </div>

      {/* Navigation Sub-tabs */}
      <div className="flex items-center gap-2 border-b border-[#222] pb-1 overflow-x-auto no-scrollbar font-mono text-xs">
        <button
          onClick={() => setActiveSubTab('edges')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'edges'
              ? 'text-blue-400 border-blue-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Server className="w-3.5 h-3.5" />
          <span>Dispositivos Edge &amp; Links WAN ({edges.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('traffic_steering')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'traffic_steering'
              ? 'text-blue-400 border-blue-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Sliders className="w-3.5 h-3.5" />
          <span>Políticas de Aplicação (App-Aware SLA) ({policies.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('tunnel_mesh')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'tunnel_mesh'
              ? 'text-blue-400 border-blue-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Share2 className="w-3.5 h-3.5" />
          <span>Malha de Túneis Overlay (IPsec Mesh) ({tunnels.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('sla_telemetry')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'sla_telemetry'
              ? 'text-blue-400 border-blue-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Telemetria de Caminho &amp; FEC (Zero Jitter)</span>
        </button>
      </div>

      {/* SUBTAB 1: Edge Devices & Physical WAN Links */}
      {activeSubTab === 'edges' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Edge Cards List */}
            <div className="lg:col-span-1 space-y-3">
              <span className="text-zinc-500 text-[10px] uppercase font-bold block">Selecione o Roteador Edge:</span>
              {edges.map((edge) => (
                <div
                  key={edge.id}
                  onClick={() => setSelectedEdgeId(edge.id)}
                  className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                    selectedEdgeId === edge.id
                      ? 'bg-[#111] border-blue-500 shadow-md'
                      : 'bg-[#0D0D0D] border-[#222] hover:border-zinc-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <strong className="text-white text-xs">{edge.name}</strong>
                    <span className="px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 text-[9.5px] font-bold">
                      {edge.role}
                    </span>
                  </div>
                  <span className="text-[10.5px] text-zinc-400 block mt-1">{edge.location}</span>

                  <div className="flex items-center justify-between text-[10px] text-zinc-500 pt-2 border-t border-[#1C1C1C] mt-2">
                    <span>{edge.activeWanLinks.length} Links WAN</span>
                    <span>CPU: {edge.cpuLoadPct}% | Mem: {edge.memoryUsagePct}%</span>
                  </div>
                </div>
              ))}
            </div>

            {/* Selected Edge Deep WAN Breakdown */}
            <div className="lg:col-span-2 space-y-4">
              <div className="bg-[#0D0D0D] border border-[#222] rounded-xl p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#222] pb-3">
                  <div>
                    <span className="text-[10px] text-zinc-500 uppercase block">Detalhamento Físico &amp; Overlay:</span>
                    <strong className="text-white text-base">{selectedEdge.name}</strong>
                    <span className="text-xs text-zinc-400 block">{selectedEdge.location}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold uppercase">
                      Firmware: {selectedEdge.firmwareVersion}
                    </span>
                  </div>
                </div>

                <div className="space-y-3">
                  <span className="text-zinc-400 font-bold uppercase text-[10.5px] block">
                    Links WAN Conectados &amp; Telemetria em Tempo Real (Probe ICMP/BFD):
                  </span>

                  {selectedEdge.activeWanLinks.map((link) => (
                    <div key={link.id} className="p-4 bg-[#121212] border border-[#222] rounded-xl space-y-3">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1A1A1A] pb-2">
                        <div className="flex items-center gap-2">
                          {link.type === 'MPLS_DEDICATED' && <Server className="w-4 h-4 text-emerald-400" />}
                          {link.type === 'INTERNET_DIA_FIBER' && <Globe className="w-4 h-4 text-blue-400" />}
                          {link.type === '5G_LTE_BACKUP' && <RadioTower className="w-4 h-4 text-amber-400" />}
                          {link.type === 'STARLINK_SATELLITE' && <Wifi className="w-4 h-4 text-cyan-400" />}
                          <div>
                            <strong className="text-white text-xs">{link.name}</strong>
                            <span className="text-[10px] text-zinc-500 block">Provedor: {link.provider}</span>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                            link.status === 'OPTIMAL' ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-rose-950 text-rose-300 border-rose-800 animate-pulse'
                          }`}>
                            {link.status}
                          </span>
                          <button
                            onClick={() => handleSimulateFailover(link.id)}
                            className="px-2.5 py-1 rounded bg-[#1C1C1C] hover:bg-zinc-700 text-zinc-300 hover:text-white border border-zinc-700 text-[10px] font-bold cursor-pointer"
                          >
                            {link.status === 'OPTIMAL' ? 'Simular Perda / Degradação' : 'Restaurar Link'}
                          </button>
                        </div>
                      </div>

                      {/* Real-Time Link Metrics Grid */}
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-[10.5px]">
                        <div className="p-2 bg-[#171717] rounded border border-[#262626]">
                          <span className="text-zinc-500 block text-[9.5px]">Capacidade / Uso</span>
                          <strong className="text-white">{link.currentThroughputMbps} / {link.bandwidthCapacityMbps} Mbps</strong>
                        </div>
                        <div className="p-2 bg-[#171717] rounded border border-[#262626]">
                          <span className="text-zinc-500 block text-[9.5px]">Latência (RTT)</span>
                          <strong className={link.latencyMs > 50 ? 'text-amber-400' : 'text-[#00FF41]'}>{link.latencyMs} ms</strong>
                        </div>
                        <div className="p-2 bg-[#171717] rounded border border-[#262626]">
                          <span className="text-zinc-500 block text-[9.5px]">Jitter (Variação)</span>
                          <strong className="text-white">{link.jitterMs} ms</strong>
                        </div>
                        <div className="p-2 bg-[#171717] rounded border border-[#262626]">
                          <span className="text-zinc-500 block text-[9.5px]">Perda de Pacotes</span>
                          <strong className={link.packetLossPct > 0 ? 'text-rose-400' : 'text-[#00FF41]'}>{link.packetLossPct}%</strong>
                        </div>
                      </div>

                      <div className="flex items-center justify-between text-[10px] text-zinc-500">
                        <span>Criptografia de Enlace: <strong className="text-zinc-300">{link.encryption}</strong></span>
                        <span>Protocolo de Monitoramento: BFD / ICMP Echo (100ms interval)</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 2: Application-Aware Traffic Steering Policies */}
      {activeSubTab === 'traffic_steering' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-blue-400" />
              <span>Roteamento Inteligente por Aplicação (App-Aware SLA Steering)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              O motor SD-WAN analisa continuamente a integridade dos links (jitter, perda e latência). Quando um link sofre degradação, o tráfego é reencaminhado em milissegundos sem interrupção para os usuários.
            </p>
          </div>

          <div className="space-y-3">
            {policies.map((pol) => (
              <div key={pol.id} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-5 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E1E1E] pb-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 text-[10px] font-bold">
                      Prioridade #{pol.priorityOrder}
                    </span>
                    <strong className="text-white text-sm">{pol.name}</strong>
                  </div>

                  <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 text-[10px]">
                    Classe: {pol.applicationClass}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3 bg-[#121212] border border-[#222] rounded space-y-1">
                    <span className="text-zinc-500 text-[10px] uppercase block">Limites Rigorosos de SLA:</span>
                    <div className="text-white text-[11px] space-y-0.5">
                      <div>Latência Máx: <strong>{pol.slaRequirement.maxLatencyMs} ms</strong></div>
                      <div>Jitter Máx: <strong>{pol.slaRequirement.maxJitterMs} ms</strong></div>
                      <div>Perda Máx: <strong>{pol.slaRequirement.maxPacketLossPct}%</strong></div>
                    </div>
                  </div>

                  <div className="p-3 bg-[#121212] border border-[#222] rounded space-y-1">
                    <span className="text-zinc-500 text-[10px] uppercase block">Caminho &amp; Roteamento Ativo:</span>
                    <div className="text-white text-[11px] space-y-0.5">
                      <div>Link Preferencial: <strong className="text-cyan-400">{pol.preferredLink}</strong></div>
                      <div>Link Fallback: <strong className="text-zinc-400">{pol.secondaryLink}</strong></div>
                      <div className="text-emerald-400 font-bold text-[10px] mt-1">{pol.activeSteeringRoute}</div>
                    </div>
                  </div>

                  <div className="p-3 bg-[#121212] border border-[#222] rounded space-y-2">
                    <span className="text-zinc-500 text-[10px] uppercase block">Otimização Avançada de Pacotes:</span>
                    <div className="space-y-1">
                      <button
                        onClick={() => handleToggleFec(pol.id)}
                        className={`w-full py-1 px-2 rounded text-[10px] font-bold uppercase cursor-pointer border flex items-center justify-between ${
                          pol.forwardErrorCorrection ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-zinc-900 text-zinc-500 border-zinc-800'
                        }`}
                      >
                        <span>FEC (Forward Error Correction)</span>
                        <span>{pol.forwardErrorCorrection ? 'ATIVO' : 'DESATIVADO'}</span>
                      </button>

                      <button
                        onClick={() => handleToggleDuplication(pol.id)}
                        className={`w-full py-1 px-2 rounded text-[10px] font-bold uppercase cursor-pointer border flex items-center justify-between ${
                          pol.packetDuplication ? 'bg-blue-950 text-blue-300 border-blue-800' : 'bg-zinc-900 text-zinc-500 border-zinc-800'
                        }`}
                      >
                        <span>Duplicação de Pacotes</span>
                        <span>{pol.packetDuplication ? 'ATIVO (Jitter Zero)' : 'DESATIVADO'}</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 3: Overlay IPsec Tunnel Mesh */}
      {activeSubTab === 'tunnel_mesh' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Share2 className="w-4 h-4 text-blue-400" />
              <span>Malha Dinâmica de Túneis IPsec Overlay (Branch-to-Branch Full Mesh)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Conexões diretas e criptografadas entre filiais sem sobrecarregar o data center principal (HQ), reduzindo a latência e acelerando o tráfego corporativo.
            </p>
          </div>

          <div className="border border-[#222] rounded-xl overflow-hidden">
            <table className="w-full text-left">
              <thead className="bg-[#141414] text-zinc-400 text-[10px] uppercase border-b border-[#222]">
                <tr>
                  <th className="py-3 px-3">Origem (Edge Spoke/Hub)</th>
                  <th className="py-3 px-3">Destino (Peer Edge)</th>
                  <th className="py-3 px-3">Tipo de Transporte</th>
                  <th className="py-3 px-3">Caminho WAN Físico Utilizado</th>
                  <th className="py-3 px-3">Latência RTT</th>
                  <th className="py-3 px-3 text-right">Status da Cifra</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1A1A1A]">
                {tunnels.map((tun, idx) => (
                  <tr key={idx} className="hover:bg-[#121212] transition-colors">
                    <td className="py-3 px-3">
                      <strong className="text-white block">{tun.sourceEdge}</strong>
                    </td>

                    <td className="py-3 px-3">
                      <strong className="text-white block">{tun.destEdge}</strong>
                    </td>

                    <td className="py-3 px-3">
                      <span className="px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 text-[10px] font-bold">
                        {tun.transportType}
                      </span>
                    </td>

                    <td className="py-3 px-3 text-zinc-400">
                      {tun.activeLinkUsed}
                    </td>

                    <td className="py-3 px-3">
                      <strong className="text-[#00FF41]">{tun.currentLatency} ms</strong>
                    </td>

                    <td className="py-3 px-3 text-right">
                      <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold uppercase inline-flex items-center gap-1">
                        <Lock className="w-3 h-3" />
                        <span>{tun.encryptionState}</span>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SUBTAB 4: SLA Telemetry & FEC Performance */}
      {activeSubTab === 'sla_telemetry' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" />
              <span>Tecnologias de Remediação em Tempo Real: FEC &amp; Packet Duplication</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Como o SD-WAN garante chamadas de voz e transmissões críticas perfeitas mesmo quando um link de internet sofre 5% a 15% de perda súbita de pacotes.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-[#0D0D0D] border border-[#222] rounded-xl p-5 space-y-3">
              <div className="flex items-center gap-2 border-b border-[#1E1E1E] pb-2">
                <span className="p-2 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  <ShieldCheck className="w-4 h-4" />
                </span>
                <strong className="text-white text-sm">Forward Error Correction (FEC)</strong>
              </div>
              <p className="text-zinc-400 text-xs leading-relaxed">
                Injeta pacotes matemáticos de paridade a cada N pacotes de dados. Se 1 pacote for descartado na internet pública devido a congestionamento de roteador, a ponta remota reconstrói o pacote perdido sem necessidade de retransmissão TCP, mantendo áudio e vídeo fluidos.
              </p>
              <div className="p-2.5 bg-[#141414] border border-[#222] rounded text-[#00FF41]">
                Status no Controlador: Ativo automaticamente ao detectar perda &gt; 1.0%
              </div>
            </div>

            <div className="bg-[#0D0D0D] border border-[#222] rounded-xl p-5 space-y-3">
              <div className="flex items-center gap-2 border-b border-[#1E1E1E] pb-2">
                <span className="p-2 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30">
                  <Zap className="w-4 h-4" />
                </span>
                <strong className="text-white text-sm">Packet Duplication (Zero-Jitter Engine)</strong>
              </div>
              <p className="text-zinc-400 text-xs leading-relaxed">
                Para transações financeiras e VoIP executivo ultra-crítico, cada pacote é replicado e enviado simultaneamente por 2 links WAN diferentes (ex: Fibra + 5G). O primeiro que chegar ao destino é processado e o duplicado é descartado na borda.
              </p>
              <div className="p-2.5 bg-[#141414] border border-[#222] rounded text-cyan-400">
                Latência Real: O RTT final equivale sempre ao melhor enlace do momento.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
