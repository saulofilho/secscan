import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Shield,
  Zap,
  Activity,
  Search,
  Plus,
  Trash2,
  Copy,
  Check,
  Download,
  Terminal,
  Radio,
  Network,
  Cpu,
  RefreshCw,
  Eye,
  Sliders,
  Filter,
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  FileCode,
  FileSearch,
  Crosshair,
  Flame,
  Binary,
  Layers,
  SlidersHorizontal,
  ArrowRight
} from 'lucide-react';
import { ScanReport } from '../types';
import {
  SnortSuricataRule,
  IdsLiveAlert,
  IdsAnomalyMetric,
  IdsSystemStatus,
  IdsAction,
  IdsMode
} from '../types/ids';
import {
  INITIAL_IDS_RULES,
  INITIAL_IDS_ALERTS,
  INITIAL_ANOMALY_METRICS,
  INITIAL_IDS_STATUS
} from '../lib/idsEngine';

interface IdsIpsSuiteViewProps {
  report: ScanReport;
  onNavigateToScanner?: () => void;
  onNavigateToSecurityOnion?: () => void;
  onNavigateToNgfw?: () => void;
  onNavigateToEdr?: () => void;
}

export const IdsIpsSuiteView: React.FC<IdsIpsSuiteViewProps> = ({
  report,
  onNavigateToScanner,
  onNavigateToSecurityOnion,
  onNavigateToNgfw,
  onNavigateToEdr
}) => {
  // Mode toggle (Passive IDS vs Inline IPS)
  const [systemStatus, setSystemStatus] = useState<IdsSystemStatus>(INITIAL_IDS_STATUS);
  const [rules, setRules] = useState<SnortSuricataRule[]>(INITIAL_IDS_RULES);
  const [alerts, setAlerts] = useState<IdsLiveAlert[]>(INITIAL_IDS_ALERTS);
  const [anomalyMetrics, setAnomalyMetrics] = useState<IdsAnomalyMetric[]>(INITIAL_ANOMALY_METRICS);

  // Active Sub-tab
  const [activeSubTab, setActiveSubTab] = useState<'alerts' | 'rules' | 'pcap_decoder' | 'anomalies' | 'generator'>('alerts');

  // Selected Alert for Deep Packet Inspection
  const [selectedAlertId, setSelectedAlertId] = useState<string>('alt-9901');
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [actionFilter, setActionFilter] = useState<string>('ALL');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Custom Rule Generator State
  const [genProtocol, setGenProtocol] = useState<'tcp' | 'udp' | 'http' | 'icmp'>('tcp');
  const [genAction, setGenAction] = useState<IdsAction>('DROP');
  const [genMsg, setGenMsg] = useState<string>('CUSTOM: Tentativa de Acesso a Rota Proibida');
  const [genContent, setGenContent] = useState<string>('/api/v1/admin');
  const [genDstPort, setGenDstPort] = useState<string>('3000');
  const [genClasstype, setGenClasstype] = useState<string>('web-application-attack');

  const selectedAlert = useMemo(() => {
    return alerts.find(a => a.id === selectedAlertId) || alerts[0];
  }, [alerts, selectedAlertId]);

  const filteredAlerts = useMemo(() => {
    let list = alerts;
    if (actionFilter !== 'ALL') {
      list = list.filter(a => a.actionTaken === actionFilter);
    }
    if (searchFilter.trim()) {
      const q = searchFilter.toLowerCase();
      list = list.filter(a =>
        a.signatureMsg.toLowerCase().includes(q) ||
        a.srcIp.toLowerCase().includes(q) ||
        a.dstIp.toLowerCase().includes(q) ||
        a.category.toLowerCase().includes(q)
      );
    }
    return list;
  }, [alerts, actionFilter, searchFilter]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleToggleMode = () => {
    setSystemStatus(prev => ({
      ...prev,
      mode: prev.mode === 'IPS_INLINE' ? 'IDS_PASSIVE' : 'IPS_INLINE'
    }));
  };

  const handleToggleRule = (id: string) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  const handleDeleteRule = (id: string) => {
    setRules(prev => prev.filter(r => r.id !== id));
  };

  const generatedRuleRaw = useMemo(() => {
    const sid = 300000 + rules.length + 1;
    return `${genAction.toLowerCase()} ${genProtocol} $EXTERNAL_NET any -> $HOME_NET ${genDstPort} (msg:"${genMsg}"; content:"${genContent}"; http_uri; classtype:${genClasstype}; sid:${sid}; rev:1;)`;
  }, [genAction, genProtocol, genDstPort, genMsg, genContent, genClasstype, rules.length]);

  const handleAddGeneratedRule = () => {
    const sid = 300000 + rules.length + 1;
    const newRule: SnortSuricataRule = {
      id: `rule-sid-${sid}`,
      sid,
      rev: 1,
      action: genAction,
      protocol: genProtocol,
      srcIp: '$EXTERNAL_NET',
      srcPort: 'any',
      direction: '->',
      dstIp: '$HOME_NET',
      dstPort: genDstPort,
      msg: genMsg,
      contentMatches: [genContent],
      classtype: genClasstype,
      enabled: true,
      hitsCount: 0,
      rawRuleString: generatedRuleRaw
    };

    setRules([newRule, ...rules]);
    setActiveSubTab('rules');
  };

  const handleExportIdsJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({
      systemStatus,
      rules,
      alerts,
      anomalyMetrics
    }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `ids-ips-signatures-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div id="ids-ips-suite-container" className="space-y-6">
      {/* Top Banner & Hardware Engine Telemetry */}
      <div className="bg-[#0A0A0A] border border-[#222] rounded-xl p-4 sm:p-6 relative overflow-hidden shadow-lg">
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-bl from-amber-500/10 via-transparent to-transparent pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#1A1A1A] pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-lg bg-amber-500/10 text-amber-500 border border-amber-500/30">
                <ShieldAlert className="w-5 h-5 animate-pulse" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white font-mono">
                    Detecção e Prevenção de Intrusão (IDS / IPS)
                  </h1>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase border ${
                    systemStatus.mode === 'IPS_INLINE'
                      ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                      : 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                  }`}>
                    {systemStatus.mode === 'IPS_INLINE' ? 'Modo IPS: Inline Drop Ativo' : 'Modo IDS: Passivo / Espelhamento TAP'}
                  </span>
                </div>
                <p className="text-xs text-zinc-400">
                  Motor de inspeção profunda de pacotes (DPI) baseado em assinaturas compatíveis com Snort/Suricata e detecção de anomalias em tempo real
                </p>
              </div>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="flex items-center gap-2 sm:gap-4 flex-wrap font-mono">
            <button
              onClick={handleToggleMode}
              className={`h-9 px-3 rounded-lg border font-mono text-xs font-bold uppercase inline-flex items-center gap-1.5 transition-colors cursor-pointer ${
                systemStatus.mode === 'IPS_INLINE'
                  ? 'bg-rose-950/60 hover:bg-rose-900/60 text-rose-300 border-rose-700'
                  : 'bg-cyan-950/60 hover:bg-cyan-900/60 text-cyan-300 border-cyan-700'
              }`}
              title="Alternar entre modo passivo (somente alerta) e modo inline (bloqueio de pacotes em trânsito)"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>{systemStatus.mode === 'IPS_INLINE' ? 'Alternar para IDS Passivo' : 'Ativar IPS Inline (Drop)'}</span>
            </button>

            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Throughput Pacotes</span>
              <span className="text-sm font-bold text-[#00FF41]">{systemStatus.packetsInspectedPerSec.toLocaleString()} pkts/s</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Drops Inline</span>
              <span className="text-sm font-bold text-rose-400">{systemStatus.droppedPacketsPerSec} pkts/s</span>
            </div>
            <button
              onClick={handleExportIdsJson}
              className="h-9 px-3 rounded-lg bg-[#141414] hover:bg-[#1E1E1E] text-zinc-300 hover:text-white border border-[#333] font-mono text-xs inline-flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Exportar regras e alertas em JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Exportar Regras</span>
            </button>
          </div>
        </div>

        {/* Live Interface Telemetry */}
        <div className="pt-4 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Interface de Captura:</span>
            <span className="text-[#00FF41] font-bold">{systemStatus.zeroCopyInterface}</span>
          </div>
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Fluxos TCP Remontados:</span>
            <span className="text-cyan-400 font-bold">{systemStatus.reassembledTcpStreams.toLocaleString()} sessões</span>
          </div>
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Regras de Assinatura Ativas:</span>
            <span className="text-white font-bold">{rules.filter(r => r.enabled).length} de {rules.length}</span>
          </div>
        </div>
      </div>

      {/* Navigation Sub-tabs */}
      <div className="flex items-center gap-2 border-b border-[#222] pb-1 overflow-x-auto no-scrollbar font-mono text-xs">
        <button
          onClick={() => setActiveSubTab('alerts')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'alerts'
              ? 'text-amber-400 border-amber-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Alertas &amp; Drops em Tempo Real ({alerts.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('pcap_decoder')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'pcap_decoder'
              ? 'text-amber-400 border-amber-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Binary className="w-3.5 h-3.5" />
          <span>Decodificador PCAP &amp; Hex Payload</span>
        </button>

        <button
          onClick={() => setActiveSubTab('rules')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'rules'
              ? 'text-amber-400 border-amber-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <SlidersHorizontal className="w-3.5 h-3.5" />
          <span>Assinaturas Snort/Suricata ({rules.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('generator')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'generator'
              ? 'text-amber-400 border-amber-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Gerador de Assinaturas IPS</span>
        </button>

        <button
          onClick={() => setActiveSubTab('anomalies')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'anomalies'
              ? 'text-amber-400 border-amber-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>Detecção de Anomalias de Tráfego ({anomalyMetrics.length})</span>
        </button>
      </div>

      {/* SUBTAB 1: Live Alerts & Drops Table */}
      {activeSubTab === 'alerts' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0E0E0E] p-3 rounded-lg border border-[#222]">
            <div className="flex items-center gap-2 flex-1 max-w-md">
              <Search className="w-4 h-4 text-zinc-500 shrink-0" />
              <input
                type="text"
                placeholder="Filtrar por mensagem, IP de origem/destino..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="w-full h-8 px-2 rounded bg-[#141414] border border-[#2A2A2A] text-white focus:outline-none focus:border-amber-500"
              />
            </div>

            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1">
                {(['ALL', 'DROP', 'ALERT', 'REJECT'] as const).map(act => (
                  <button
                    key={act}
                    onClick={() => setActionFilter(act)}
                    className={`px-2 py-1 rounded cursor-pointer transition-colors ${
                      actionFilter === act 
                        ? 'bg-amber-500 text-black font-bold' 
                        : 'bg-[#181818] text-zinc-400 hover:text-white'
                    }`}
                  >
                    {act}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="border border-[#222] rounded-xl overflow-hidden">
            <table className="w-full text-left">
              <thead className="bg-[#141414] text-zinc-400 text-[10px] uppercase border-b border-[#222]">
                <tr>
                  <th className="py-3 px-3">Timestamp / SID</th>
                  <th className="py-3 px-3">Assinatura &amp; Mensagem</th>
                  <th className="py-3 px-3">Origem &rarr; Destino</th>
                  <th className="py-3 px-3">Protocolo</th>
                  <th className="py-3 px-3">Ação Executada</th>
                  <th className="py-3 px-3 text-right">Ações</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1A1A1A]">
                {filteredAlerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-[#121212] transition-colors">
                    <td className="py-3 px-3">
                      <span className="text-zinc-500 block text-[10px]">{alert.timestamp}</span>
                      <span className="font-bold text-amber-400">SID: {alert.sid}</span>
                    </td>

                    <td className="py-3 px-3 max-w-xs sm:max-w-md">
                      <strong className="text-white block truncate">{alert.signatureMsg}</strong>
                      <span className="text-[10px] text-zinc-500">{alert.category}</span>
                    </td>

                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1 text-[11px]">
                        <span className="text-zinc-300 font-bold">{alert.srcIp}:{alert.srcPort}</span>
                        <ArrowRight className="w-3 h-3 text-zinc-600" />
                        <span className="text-zinc-300 font-bold">{alert.dstIp}:{alert.dstPort}</span>
                      </div>
                      <span className="text-[9.5px] text-zinc-500 block">{alert.interfaceName}</span>
                    </td>

                    <td className="py-3 px-3">
                      <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 font-bold text-[10px]">
                        {alert.protocol}
                      </span>
                    </td>

                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        alert.actionTaken === 'DROP' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                        alert.actionTaken === 'REJECT' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-blue-950 text-blue-300 border border-blue-800'
                      }`}>
                        {alert.actionTaken}
                      </span>
                    </td>

                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => {
                          setSelectedAlertId(alert.id);
                          setActiveSubTab('pcap_decoder');
                        }}
                        className="px-2 py-1 rounded bg-[#181818] hover:bg-zinc-800 text-amber-400 border border-amber-500/30 text-[10px] font-bold inline-flex items-center gap-1 cursor-pointer"
                      >
                        <Eye className="w-3 h-3" />
                        <span>Inspecionar Payload</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SUBTAB 2: PCAP Decoder & Hex View */}
      {activeSubTab === 'pcap_decoder' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Binary className="w-4 h-4 text-amber-500" />
              <span>Decodificador de Pacotes &amp; Despejo Hexadecimal (DPI Dump)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Inspeção de pacotes capturados no ring-buffer do kernel. Exibe cabeçalhos L3/L4 remontados e o payload textual com destaque de strings maliciosas.
            </p>
          </div>

          <div className="bg-[#0D0D0D] border border-[#222] rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#222] pb-3">
              <div>
                <span className="text-zinc-500 text-[10px] uppercase block">Pacote Capturado #{selectedAlert.pcapPacketNo}:</span>
                <strong className="text-white text-sm">{selectedAlert.signatureMsg}</strong>
              </div>

              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-bold uppercase">
                  Ação: {selectedAlert.actionTaken}
                </span>
                <span className="text-zinc-500 text-[11px]">{selectedAlert.timestamp}</span>
              </div>
            </div>

            {/* Network 5-Tuple Info */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-zinc-400">
              <div>
                <span className="text-zinc-500 text-[10px] uppercase block">IP de Origem:</span>
                <span className="text-white font-bold">{selectedAlert.srcIp}:{selectedAlert.srcPort}</span>
              </div>
              <div>
                <span className="text-zinc-500 text-[10px] uppercase block">IP de Destino:</span>
                <span className="text-white font-bold">{selectedAlert.dstIp}:{selectedAlert.dstPort}</span>
              </div>
              <div>
                <span className="text-zinc-500 text-[10px] uppercase block">Protocolo L4:</span>
                <span className="text-cyan-400 font-bold">{selectedAlert.protocol}</span>
              </div>
              <div>
                <span className="text-zinc-500 text-[10px] uppercase block">Interface:</span>
                <span className="text-zinc-300 font-bold">{selectedAlert.interfaceName}</span>
              </div>
            </div>

            {/* Ascii Stream Payload */}
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10.5px] text-zinc-400 font-bold uppercase">Payload Decodificada (ASCII Stream):</span>
                <button
                  onClick={() => handleCopy(selectedAlert.packetAsciiPayload, 'ascii')}
                  className="text-zinc-500 hover:text-white cursor-pointer inline-flex items-center gap-1 text-[10px]"
                >
                  {copiedKey === 'ascii' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                  <span>Copiar ASCII</span>
                </button>
              </div>
              <div className="p-3 bg-[#121212] border border-[#222] rounded-lg text-rose-300 break-all font-mono">
                <code>{selectedAlert.packetAsciiPayload}</code>
              </div>
            </div>

            {/* Hex Dump */}
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10.5px] text-zinc-400 font-bold uppercase">Hex Dump Raw Bytes:</span>
                <button
                  onClick={() => handleCopy(selectedAlert.packetHexPayload, 'hex')}
                  className="text-zinc-500 hover:text-white cursor-pointer inline-flex items-center gap-1 text-[10px]"
                >
                  {copiedKey === 'hex' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                  <span>Copiar Hex</span>
                </button>
              </div>
              <div className="p-3 bg-[#0A0A0A] border border-[#222] rounded-lg text-zinc-400 font-mono tracking-wider break-all text-[11px]">
                <code>{selectedAlert.packetHexPayload}</code>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 3: Rules Catalog */}
      {activeSubTab === 'rules' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <SlidersHorizontal className="w-4 h-4 text-amber-500" />
              <span>Base de Assinaturas (Snort &amp; Suricata Ruleset)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Regras oficiais compiladas para bloqueio em linha de injeções, probes e tentativas de exploração conhecidas.
            </p>
          </div>

          <div className="space-y-3">
            {rules.map((rule) => (
              <div key={rule.id} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E1E1E] pb-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      rule.action === 'DROP' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                      rule.action === 'REJECT' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                      'bg-blue-950 text-blue-300 border border-blue-800'
                    }`}>
                      {rule.action}
                    </span>
                    <strong className="text-white text-sm">SID {rule.sid}: {rule.msg}</strong>
                    {rule.cve && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950/70 text-rose-300 border border-rose-800">
                        {rule.cve}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-zinc-500 text-[10.5px]">Disparos: <strong className="text-white">{rule.hitsCount}</strong></span>
                    <button
                      onClick={() => handleToggleRule(rule.id)}
                      className={`px-2 py-1 rounded text-[10px] font-bold uppercase cursor-pointer border ${
                        rule.enabled ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-zinc-900 text-zinc-500 border-zinc-800'
                      }`}
                    >
                      {rule.enabled ? 'ATIVADA' : 'DESATIVADA'}
                    </button>
                    <button
                      onClick={() => handleDeleteRule(rule.id)}
                      className="p-1 rounded bg-[#181818] hover:bg-rose-950 text-zinc-500 hover:text-rose-400 cursor-pointer"
                      title="Excluir regra"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <div className="p-2.5 bg-[#121212] border border-[#222] rounded text-[11px] flex items-center justify-between">
                  <code className="text-amber-300 break-all">{rule.rawRuleString}</code>
                  <button
                    onClick={() => handleCopy(rule.rawRuleString, rule.id)}
                    className="text-zinc-500 hover:text-white ml-2 cursor-pointer shrink-0"
                    title="Copiar regra crua"
                  >
                    {copiedKey === rule.id ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 4: Generator */}
      {activeSubTab === 'generator' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Plus className="w-4 h-4 text-amber-500" />
              <span>Gerador Visual de Regras Snort/Suricata</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Crie rapidamente assinaturas customizadas para bloquear em linha ataques direcionados às rotas da sua aplicação.
            </p>
          </div>

          <div className="bg-[#0D0D0D] border border-[#222] rounded-xl p-5 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="space-y-1">
                <label className="text-zinc-400 font-bold uppercase text-[10.5px] block">Ação do IPS</label>
                <select
                  value={genAction}
                  onChange={(e) => setGenAction(e.target.value as IdsAction)}
                  className="w-full h-8 px-2 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-amber-500"
                >
                  <option value="DROP">DROP (Bloqueio sem aviso)</option>
                  <option value="REJECT">REJECT (Bloqueio com TCP RST)</option>
                  <option value="ALERT">ALERT (Apenas registro)</option>
                  <option value="PASS">PASS (Ignorar/Whitelist)</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-zinc-400 font-bold uppercase text-[10.5px] block">Protocolo L4/L7</label>
                <select
                  value={genProtocol}
                  onChange={(e) => setGenProtocol(e.target.value as any)}
                  className="w-full h-8 px-2 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-amber-500"
                >
                  <option value="tcp">TCP</option>
                  <option value="http">HTTP</option>
                  <option value="udp">UDP</option>
                  <option value="icmp">ICMP</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-zinc-400 font-bold uppercase text-[10.5px] block">Porta de Destino</label>
                <input
                  type="text"
                  value={genDstPort}
                  onChange={(e) => setGenDstPort(e.target.value)}
                  className="w-full h-8 px-2.5 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-amber-500"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-zinc-400 font-bold uppercase text-[10.5px] block">Mensagem da Assinatura (msg)</label>
              <input
                type="text"
                value={genMsg}
                onChange={(e) => setGenMsg(e.target.value)}
                className="w-full h-8 px-2.5 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-amber-500"
              />
            </div>

            <div className="space-y-1">
              <label className="text-zinc-400 font-bold uppercase text-[10.5px] block">Padrão de Conteúdo (content: string ou URI)</label>
              <input
                type="text"
                value={genContent}
                onChange={(e) => setGenContent(e.target.value)}
                className="w-full h-8 px-2.5 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-amber-500"
              />
            </div>

            {/* Generated Output Preview */}
            <div className="p-3 bg-[#141414] border border-[#333] rounded-lg space-y-1">
              <span className="text-[10px] text-zinc-500 uppercase block font-bold">Prévia da Regra Compilada:</span>
              <code className="text-amber-300 break-all block">{generatedRuleRaw}</code>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-[#222]">
              <button
                onClick={handleAddGeneratedRule}
                className="px-4 py-2 rounded bg-amber-500 hover:bg-amber-400 text-black font-bold uppercase inline-flex items-center gap-1.5 cursor-pointer shadow-md"
              >
                <Plus className="w-4 h-4" />
                <span>Compilar &amp; Aplicar ao Motor</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 5: Anomalies */}
      {activeSubTab === 'anomalies' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Network className="w-4 h-4 text-amber-500" />
              <span>Detecção de Anomalias Estatísticas e Heurísticas</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Identificação de ataques sem assinatura prévia, como varreduras furtivas de portas, DoS volumétrico e exfiltração de alta entropia.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {anomalyMetrics.map((anom, i) => (
              <div key={i} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4.5 space-y-3">
                <div className="flex items-center justify-between border-b border-[#1E1E1E] pb-2">
                  <strong className="text-white text-sm">{anom.metricName}</strong>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    anom.status === 'ANOMALOUS' ? 'bg-rose-950 text-rose-300 border border-rose-800 animate-pulse' :
                    'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}>
                    {anom.status}
                  </span>
                </div>

                <p className="text-zinc-400 text-[11px] leading-relaxed">
                  {anom.description}
                </p>

                <div className="flex items-center justify-between text-xs pt-1 border-t border-[#1A1A1A]">
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Valor Medido:</span>
                    <strong className={anom.status === 'ANOMALOUS' ? 'text-rose-400' : 'text-white'}>
                      {anom.currentValue} {anom.unit}
                    </strong>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Limiar de Alarme:</span>
                    <span className="text-zinc-400">{anom.baselineThreshold} {anom.unit}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
