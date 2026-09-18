import React, { useState, useMemo } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  Lock,
  Unlock,
  Layers,
  Search,
  Plus,
  Trash2,
  Check,
  Copy,
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
  Server,
  ArrowRight,
  Database,
  ExternalLink,
  Flame,
  CheckCircle2,
  XCircle,
  HelpCircle
} from 'lucide-react';
import { ScanReport } from '../types';
import {
  NgfwPolicyRule,
  NgfwAppIdSignature,
  NgfwIpsSignatureMatch,
  NgfwSslInspectionSession,
  NgfwMetrics,
  NgfwAction,
  NgfwSecurityZone
} from '../types/ngfw';
import {
  INITIAL_POLICY_RULES,
  INITIAL_APP_ID_CATALOG,
  INITIAL_IPS_MATCHES,
  INITIAL_SSL_SESSIONS,
  INITIAL_NGFW_METRICS
} from '../lib/ngfwEngine';

interface NgfwSuiteViewProps {
  report: ScanReport;
  onNavigateToScanner?: () => void;
  onNavigateToEndpoints?: () => void;
  onNavigateToSecurityOnion?: () => void;
}

export const NgfwSuiteView: React.FC<NgfwSuiteViewProps> = ({
  report,
  onNavigateToScanner,
  onNavigateToEndpoints,
  onNavigateToSecurityOnion
}) => {
  // State for Policy Rules, App-ID, IPS, SSL Inspection
  const [policies, setPolicies] = useState<NgfwPolicyRule[]>(INITIAL_POLICY_RULES);
  const [appIdCatalog, setAppIdCatalog] = useState<NgfwAppIdSignature[]>(INITIAL_APP_ID_CATALOG);
  const [ipsEvents, setIpsEvents] = useState<NgfwIpsSignatureMatch[]>(INITIAL_IPS_MATCHES);
  const [sslSessions, setSslSessions] = useState<NgfwSslInspectionSession[]>(INITIAL_SSL_SESSIONS);
  const [metrics, setMetrics] = useState<NgfwMetrics>(INITIAL_NGFW_METRICS);

  // Active navigation sub-tab
  const [activeSubTab, setActiveSubTab] = useState<'policies' | 'appid' | 'ips' | 'ssl' | 'zones'>('policies');
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [actionFilter, setActionFilter] = useState<string>('ALL');
  const [showAddModal, setShowAddModal] = useState<boolean>(false);

  // New Rule Form State
  const [newRuleName, setNewRuleName] = useState<string>('');
  const [newSourceZone, setNewSourceZone] = useState<NgfwSecurityZone>('UNTRUST');
  const [newDestZone, setNewDestZone] = useState<NgfwSecurityZone>('DMZ');
  const [newApplication, setNewApplication] = useState<string>('Stripe-Payment-API');
  const [newAction, setNewAction] = useState<NgfwAction>('BLOCK');
  const [newDescription, setNewDescription] = useState<string>('');

  // Filtering rules
  const filteredPolicies = useMemo(() => {
    let list = policies;
    if (actionFilter !== 'ALL') {
      list = list.filter(p => p.action === actionFilter);
    }
    if (searchFilter.trim()) {
      const q = searchFilter.toLowerCase();
      list = list.filter(p => 
        p.ruleName.toLowerCase().includes(q) ||
        p.sourceZone.toLowerCase().includes(q) ||
        p.destinationZone.toLowerCase().includes(q) ||
        p.applications.some(a => a.toLowerCase().includes(q)) ||
        p.description.toLowerCase().includes(q)
      );
    }
    return list.sort((a, b) => a.priority - b.priority);
  }, [policies, actionFilter, searchFilter]);

  const handleToggleRuleStatus = (id: string) => {
    setPolicies(prev => prev.map(rule => {
      if (rule.id === id) {
        return {
          ...rule,
          status: rule.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE'
        };
      }
      return rule;
    }));
  };

  const handleDeleteRule = (id: string) => {
    setPolicies(prev => prev.filter(r => r.id !== id));
  };

  const handleCreateRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleName.trim()) return;

    const newRule: NgfwPolicyRule = {
      id: `rule-${Date.now()}`,
      ruleName: newRuleName.toUpperCase().replace(/\s+/g, '-'),
      priority: policies.length > 0 ? Math.max(...policies.map(p => p.priority)) + 10 : 10,
      sourceZone: newSourceZone,
      destinationZone: newDestZone,
      sourceIps: ['any'],
      destinationIps: ['any'],
      applications: [newApplication],
      servicePorts: 'application-default',
      action: newAction,
      ipsProfileEnabled: true,
      sslInspectionEnabled: true,
      hitCount: 0,
      lastHitTimestamp: 'Nunca',
      status: 'ACTIVE',
      description: newDescription || 'Regra de política criada pelo operador de segurança.'
    };

    setPolicies([newRule, ...policies]);
    setNewRuleName('');
    setNewDescription('');
    setShowAddModal(false);
  };

  const handleExportFirewallJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({
      policies,
      appIdCatalog,
      ipsEvents,
      sslSessions,
      metrics
    }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `ngfw-security-policy-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div id="ngfw-suite-container" className="space-y-6">
      {/* Top Banner & Telemetry Deck */}
      <div className="bg-[#0A0A0A] border border-[#222] rounded-xl p-4 sm:p-6 relative overflow-hidden shadow-lg">
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-bl from-rose-500/5 via-transparent to-transparent pointer-events-none" />
        
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#1A1A1A] pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-lg bg-rose-500/10 text-rose-500 border border-rose-500/30">
                <Flame className="w-5 h-5" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white font-mono">
                    Next-Gen Firewall (NGFW)
                  </h1>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/40 font-bold uppercase">
                    L7 Deep Packet &amp; Zero Trust
                  </span>
                </div>
                <p className="text-xs text-zinc-400">
                  Políticas de segurança baseadas em App-ID (Camada 7), prevenção inline de intrusões (IPS) e inspeção SSL/TLS
                </p>
              </div>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="flex items-center gap-2 sm:gap-4 flex-wrap">
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] font-mono text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Throughput</span>
              <span className="text-sm font-bold text-[#00FF41]">{metrics.throughputMbps} Mbps</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] font-mono text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Ameaças Bloqueadas</span>
              <span className="text-sm font-bold text-rose-400">{metrics.threatsBlockedToday}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] font-mono text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Sessões SSL Inspec.</span>
              <span className="text-sm font-bold text-cyan-400">{metrics.sslInspectedSessionsPct}%</span>
            </div>
            <button
              id="btn-export-ngfw-rules"
              onClick={handleExportFirewallJson}
              className="h-9 px-3 rounded-lg bg-[#141414] hover:bg-[#1E1E1E] text-zinc-300 hover:text-white border border-[#333] font-mono text-xs inline-flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Exportar políticas do Firewall em JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Exportar Políticas</span>
            </button>
          </div>
        </div>

        {/* Real-time Hardware & Packet Status Bar */}
        <div className="pt-4 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Sessões Concorrentes:</span>
            <span className="text-white font-bold">{metrics.activeSessions.toLocaleString()}</span>
          </div>
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Total de Pacotes L7:</span>
            <span className="text-white font-bold">{metrics.totalPacketsProcessed.toLocaleString()}</span>
          </div>
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Carga de CPU (DPDK):</span>
            <span className="text-amber-400 font-bold">{metrics.cpuLoadPct}%</span>
          </div>
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Uso de Memória RAM:</span>
            <span className="text-[#00FF41] font-bold">{metrics.memoryUsagePct}%</span>
          </div>
        </div>
      </div>

      {/* Navigation Sub-tabs */}
      <div className="flex items-center gap-2 border-b border-[#222] pb-1 overflow-x-auto no-scrollbar font-mono text-xs">
        <button
          onClick={() => setActiveSubTab('policies')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'policies'
              ? 'text-rose-400 border-rose-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          <span>Políticas de Segurança ({policies.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('appid')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'appid'
              ? 'text-rose-400 border-rose-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Catálogo App-ID ({appIdCatalog.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('ips')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'ips'
              ? 'text-rose-400 border-rose-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Prevenção de Intrusões (IPS) ({ipsEvents.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('ssl')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'ssl'
              ? 'text-rose-400 border-rose-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Lock className="w-3.5 h-3.5" />
          <span>Inspeção SSL/TLS &amp; DLP ({sslSessions.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('zones')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'zones'
              ? 'text-rose-400 border-rose-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>Zonas de Segurança (Zero Trust)</span>
        </button>
      </div>

      {/* SUBTAB 1: Security Policies Table */}
      {activeSubTab === 'policies' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0E0E0E] p-3 rounded-lg border border-[#222]">
            <div className="flex items-center gap-2 flex-1 max-w-md">
              <Search className="w-4 h-4 text-zinc-500 shrink-0" />
              <input
                type="text"
                placeholder="Filtrar por nome da regra, zona, App-ID..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="w-full h-8 px-2 rounded bg-[#141414] border border-[#2A2A2A] text-white font-mono text-xs focus:outline-none focus:border-rose-500"
              />
            </div>

            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1 font-mono text-xs">
                {(['ALL', 'ALLOW', 'BLOCK', 'DROP', 'RESET'] as const).map(act => (
                  <button
                    key={act}
                    onClick={() => setActionFilter(act)}
                    className={`px-2 py-1 rounded cursor-pointer transition-colors ${
                      actionFilter === act 
                        ? 'bg-rose-500 text-white font-bold' 
                        : 'bg-[#181818] text-zinc-400 hover:text-white'
                    }`}
                  >
                    {act}
                  </button>
                ))}
              </div>

              <button
                id="btn-open-create-rule"
                onClick={() => setShowAddModal(true)}
                className="h-8 px-3 rounded bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-bold uppercase inline-flex items-center gap-1 cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Nova Regra</span>
              </button>
            </div>
          </div>

          <div className="border border-[#222] rounded-xl overflow-hidden font-mono text-xs">
            <table className="w-full text-left">
              <thead className="bg-[#141414] text-zinc-400 text-[10px] uppercase border-b border-[#222]">
                <tr>
                  <th className="py-3 px-3">Prioridade / Regra</th>
                  <th className="py-3 px-3">Zona Origem &rarr; Destino</th>
                  <th className="py-3 px-3">Aplicações (App-ID)</th>
                  <th className="py-3 px-3">Ação</th>
                  <th className="py-3 px-3">Perfis de Segurança</th>
                  <th className="py-3 px-3">Hits (Contagem)</th>
                  <th className="py-3 px-3 text-right">Ações</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1A1A1A]">
                {filteredPolicies.map((rule) => (
                  <tr key={rule.id} className="hover:bg-[#121212] transition-colors">
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        <span className="w-6 text-zinc-500 font-bold">#{rule.priority}</span>
                        <div>
                          <span className="font-bold text-white block">{rule.ruleName}</span>
                          <span className="text-[10px] text-zinc-500 line-clamp-1">{rule.description}</span>
                        </div>
                      </div>
                    </td>

                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1 text-[11px]">
                        <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 font-bold">
                          {rule.sourceZone}
                        </span>
                        <ArrowRight className="w-3 h-3 text-zinc-500" />
                        <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 font-bold">
                          {rule.destinationZone}
                        </span>
                      </div>
                      <span className="text-[9.5px] text-zinc-500 block mt-0.5">
                        Portas: {rule.servicePorts}
                      </span>
                    </td>

                    <td className="py-3 px-3">
                      <div className="flex flex-wrap gap-1">
                        {rule.applications.map(app => (
                          <span key={app} className="px-1.5 py-0.5 rounded bg-blue-950/60 text-blue-300 border border-blue-800/40 text-[10px] font-bold">
                            {app}
                          </span>
                        ))}
                      </div>
                    </td>

                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        rule.action === 'ALLOW' ? 'bg-[#00FF41]/15 text-[#00FF41] border border-[#00FF41]/30' :
                        rule.action === 'BLOCK' ? 'bg-rose-950/70 text-rose-300 border border-rose-800' :
                        rule.action === 'DROP' ? 'bg-amber-950/70 text-amber-300 border border-amber-800' :
                        'bg-purple-950/70 text-purple-300 border border-purple-800'
                      }`}>
                        {rule.action}
                      </span>
                    </td>

                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1.5 text-[10px]">
                        <span className={`px-1.5 py-0.5 rounded border ${rule.ipsProfileEnabled ? 'bg-rose-950/50 text-rose-400 border-rose-800/50' : 'bg-zinc-800 text-zinc-600 border-transparent'}`}>
                          IPS
                        </span>
                        <span className={`px-1.5 py-0.5 rounded border ${rule.sslInspectionEnabled ? 'bg-cyan-950/50 text-cyan-400 border-cyan-800/50' : 'bg-zinc-800 text-zinc-600 border-transparent'}`}>
                          SSL Decrypt
                        </span>
                      </div>
                    </td>

                    <td className="py-3 px-3">
                      <span className="text-white font-bold">{rule.hitCount.toLocaleString()}</span>
                      <span className="text-[9.5px] text-zinc-500 block">{rule.lastHitTimestamp}</span>
                    </td>

                    <td className="py-3 px-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => handleToggleRuleStatus(rule.id)}
                          className={`px-2 py-1 rounded text-[10px] font-bold uppercase cursor-pointer border ${
                            rule.status === 'ACTIVE' 
                              ? 'bg-zinc-800 text-zinc-300 border-zinc-700 hover:bg-zinc-700' 
                              : 'bg-zinc-900 text-zinc-600 border-zinc-800'
                          }`}
                        >
                          {rule.status}
                        </button>
                        <button
                          onClick={() => handleDeleteRule(rule.id)}
                          className="p-1 rounded bg-[#181818] hover:bg-rose-950 text-zinc-400 hover:text-rose-400 border border-transparent hover:border-rose-900 cursor-pointer"
                          title="Remover regra"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SUBTAB 2: App-ID Catalog */}
      {activeSubTab === 'appid' && (
        <div className="space-y-4">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-rose-500" />
              <span>Assinaturas App-ID (Identificação de Aplicações L7)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Ao contrário de firewalls tradicionais baseados apenas em portas TCP/UDP, o NGFW inspeciona o payload da aplicação independentemente da porta utilizada.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {appIdCatalog.map((app) => (
              <div key={app.id} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4 space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between border-b border-[#1E1E1E] pb-2">
                  <span className="font-bold text-white text-sm">
                    {app.name}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    app.riskLevel >= 4 ? 'bg-rose-950/70 text-rose-300 border border-rose-800' :
                    app.riskLevel === 3 ? 'bg-amber-950/70 text-amber-300 border border-amber-800' :
                    'bg-blue-950/70 text-blue-300 border border-blue-800'
                  }`}>
                    Risco {app.riskLevel}/5
                  </span>
                </div>

                <p className="text-zinc-300 text-[11px] leading-relaxed">
                  {app.description}
                </p>

                <div className="space-y-1 text-zinc-400 text-[10.5px]">
                  <div>
                    <span className="text-zinc-500 uppercase block text-[9.5px]">Categoria:</span>
                    <span className="text-white font-semibold">{app.category}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 uppercase block text-[9.5px]">Portas Padrão:</span>
                    <span className="text-cyan-400">{app.standardPorts.join(', ')}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 uppercase block text-[9.5px]">Decriptografia SSL:</span>
                    <span className={app.sslDecrypted ? 'text-[#00FF41]' : 'text-zinc-500'}>
                      {app.sslDecrypted ? 'Habilitada (Inspeciona Payload)' : 'Bypass / Inalterado'}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 3: IPS (Intrusion Prevention System) */}
      {activeSubTab === 'ips' && (
        <div className="space-y-4">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-500" />
              <span>Eventos de Prevenção de Intrusão Inline (IPS Engine)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Assinaturas de exploração de vulnerabilidades, tentativas de injeção de comandos e probes bloqueados em tempo real no gateway.
            </p>
          </div>

          <div className="space-y-3">
            {ipsEvents.map((ips) => (
              <div key={ips.id} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4.5 space-y-3 font-mono">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E1E1E] pb-2.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-950 text-rose-300 border border-rose-800">
                      {ips.actionTaken}
                    </span>
                    <span className="text-sm font-bold text-white">
                      {ips.signatureName}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">
                      {ips.threatId}
                    </span>
                    {ips.cve && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-900/40 text-rose-300 border border-rose-700/50">
                        {ips.cve}
                      </span>
                    )}
                  </div>

                  <span className="text-xs text-zinc-500">
                    {ips.timestamp}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-zinc-400">
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Origem:</span>
                    <span className="text-white font-bold">{ips.sourceIp}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Destino:</span>
                    <span className="text-white font-bold">{ips.destinationIp}</span>
                  </div>
                </div>

                <div className="p-3 bg-[#111] border border-[#222] rounded-lg text-xs font-mono">
                  <span className="text-zinc-500 text-[10px] uppercase block mb-1">Payload Inspecionada &amp; Bloqueada:</span>
                  <code className="text-rose-400 break-all">{ips.payloadSnippet}</code>
                </div>

                <div className="text-xs text-zinc-400 pt-1">
                  <strong className="text-amber-400">Ação Recomendada: </strong>
                  {ips.mitigationRecommendation}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 4: SSL Inspection & DLP */}
      {activeSubTab === 'ssl' && (
        <div className="space-y-4">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-400" />
              <span>Inspeção Profunda de Tráfego Criptografado (SSL/TLS Forward Proxy &amp; DLP)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Descriptografa conexões HTTPS autorizadas para inspecionar payloads contra vazamento de credenciais e malware oculto em TLS.
            </p>
          </div>

          <div className="space-y-3">
            {sslSessions.map((session) => (
              <div key={session.sessionId} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4.5 space-y-3 font-mono text-xs">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E1E1E] pb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-white text-sm">
                      {session.flow}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-cyan-950/70 text-cyan-300 border border-cyan-800">
                      {session.decryptionStatus}
                    </span>
                    <span className="text-zinc-500">
                      SNI: <strong className="text-zinc-300">{session.sni}</strong>
                    </span>
                  </div>

                  <span className="text-zinc-500">
                    {session.timestamp}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-zinc-400">
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Versão TLS:</span>
                    <span className="text-white font-semibold">{session.tlsVersion}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Cipher Suite:</span>
                    <span className="text-white font-semibold">{session.cipherSuite}</span>
                  </div>
                </div>

                {session.threatFound && (
                  <div className="p-3 bg-rose-950/30 border border-rose-800/60 rounded-lg text-rose-300 text-xs">
                    <strong className="block text-rose-400 font-bold mb-1 flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4" />
                      <span>Alerta de Vazamento de Segredos (DLP Inline)</span>
                    </strong>
                    {session.threatDetails}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 5: Security Zones */}
      {activeSubTab === 'zones' && (
        <div className="space-y-4">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
              <Network className="w-4 h-4 text-rose-500" />
              <span>Topologia de Zonas de Segurança (Zero Trust Architecture)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Isolamento estrito entre redes externas não confiáveis, DMZ de APIs, rede corporativa e camada de banco de dados.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
            <div className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between border-b border-[#1E1E1E] pb-2">
                <span className="font-bold text-rose-400 text-sm">UNTRUST (Internet Externa)</span>
                <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 text-[10px]">Zero Trust</span>
              </div>
              <p className="text-zinc-400 text-[11px]">
                Zona de maior risco contendo conexões públicas de entrada. Nenhum tráfego para INTERNAL_CORP é permitido por padrão.
              </p>
            </div>

            <div className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between border-b border-[#1E1E1E] pb-2">
                <span className="font-bold text-amber-400 text-sm">DMZ (Gateways &amp; APIs)</span>
                <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 text-[10px]">Isolada</span>
              </div>
              <p className="text-zinc-400 text-[11px]">
                Contém o cluster Nginx e os containers Express (ex: 10.0.4.15). Aceita tráfego web inspecionado e comunica-se com a DMZ financeira.
              </p>
            </div>

            <div className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between border-b border-[#1E1E1E] pb-2">
                <span className="font-bold text-cyan-400 text-sm">DATABASE_TIER (Postgres/Redis)</span>
                <span className="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 text-[10px]">Restrita</span>
              </div>
              <p className="text-zinc-400 text-[11px]">
                Sub-rede 10.0.8.0/24 protegida por regra de isolamento sumário contra a Internet. Conexões aceitas somente a partir da DMZ de APIs autorizadas.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Nova Regra de Política */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0F0F0F] border border-[#333] rounded-xl max-w-lg w-full p-5 space-y-4 font-mono shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#222] pb-3">
              <div className="flex items-center gap-2">
                <Flame className="w-4 h-4 text-rose-500" />
                <h3 className="text-sm font-bold text-white uppercase">Criar Nova Política NGFW</h3>
              </div>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-zinc-500 hover:text-white cursor-pointer"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateRule} className="space-y-3 text-xs">
              <div className="space-y-1">
                <label className="text-zinc-400 block font-bold uppercase text-[10.5px]">Nome da Regra</label>
                <input
                  type="text"
                  required
                  placeholder="Ex: BLOCK-TOR-EXIT-NODES"
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  className="w-full h-8 px-2.5 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-rose-500 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1">
                  <label className="text-zinc-400 block font-bold uppercase text-[10.5px]">Zona de Origem</label>
                  <select
                    value={newSourceZone}
                    onChange={(e) => setNewSourceZone(e.target.value as NgfwSecurityZone)}
                    className="w-full h-8 px-2 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-rose-500"
                  >
                    <option value="UNTRUST">UNTRUST</option>
                    <option value="DMZ">DMZ</option>
                    <option value="INTERNAL_CORP">INTERNAL_CORP</option>
                    <option value="CLOUD_VPC">CLOUD_VPC</option>
                    <option value="DATABASE_TIER">DATABASE_TIER</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-zinc-400 block font-bold uppercase text-[10.5px]">Zona de Destino</label>
                  <select
                    value={newDestZone}
                    onChange={(e) => setNewDestZone(e.target.value as NgfwSecurityZone)}
                    className="w-full h-8 px-2 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-rose-500"
                  >
                    <option value="DATABASE_TIER">DATABASE_TIER</option>
                    <option value="DMZ">DMZ</option>
                    <option value="UNTRUST">UNTRUST</option>
                    <option value="INTERNAL_CORP">INTERNAL_CORP</option>
                    <option value="CLOUD_VPC">CLOUD_VPC</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1">
                  <label className="text-zinc-400 block font-bold uppercase text-[10.5px]">Aplicação (App-ID)</label>
                  <select
                    value={newApplication}
                    onChange={(e) => setNewApplication(e.target.value)}
                    className="w-full h-8 px-2 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-rose-500"
                  >
                    {appIdCatalog.map(app => (
                      <option key={app.id} value={app.name}>{app.name}</option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-zinc-400 block font-bold uppercase text-[10.5px]">Ação de Bloqueio/Permissão</label>
                  <select
                    value={newAction}
                    onChange={(e) => setNewAction(e.target.value as NgfwAction)}
                    className="w-full h-8 px-2 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-rose-500"
                  >
                    <option value="BLOCK">BLOCK</option>
                    <option value="DROP">DROP</option>
                    <option value="RESET">RESET</option>
                    <option value="ALLOW">ALLOW</option>
                    <option value="QUARANTINE">QUARANTINE</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-zinc-400 block font-bold uppercase text-[10.5px]">Descrição / Justificativa</label>
                <textarea
                  rows={2}
                  placeholder="Justificativa de segurança para a regra..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  className="w-full p-2 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-rose-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#222]">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 cursor-pointer"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 rounded bg-rose-600 hover:bg-rose-500 text-white font-bold cursor-pointer"
                >
                  Salvar e Aplicar
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
