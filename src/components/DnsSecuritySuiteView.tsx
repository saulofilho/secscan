import React, { useState, useMemo } from 'react';
import {
  Globe,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Lock,
  Unlock,
  Key,
  Search,
  Plus,
  Trash2,
  Copy,
  Check,
  Download,
  Activity,
  Filter,
  Eye,
  Terminal,
  Cpu,
  RefreshCw,
  SlidersHorizontal,
  ArrowRight,
  Zap,
  Network,
  Radio,
  FileCode,
  Flame,
  Binary
} from 'lucide-react';
import { ScanReport } from '../types';
import {
  DnsQueryLog,
  DnsSinkholeRule,
  DgaDetectionModel,
  DnssecChainOfTrust,
  DnsTunnelExfiltrationSession,
  DnsSecurityOverview,
  DnsSecurityStatus
} from '../types/dns';
import {
  INITIAL_DNS_QUERIES,
  INITIAL_SINKHOLE_RULES,
  INITIAL_DGA_MODELS,
  INITIAL_DNSSEC_CHAINS,
  INITIAL_TUNNEL_SESSIONS,
  INITIAL_DNS_OVERVIEW
} from '../lib/dnsEngine';

interface DnsSecuritySuiteViewProps {
  report: ScanReport;
  onNavigateToScanner?: () => void;
  onNavigateToSecurityOnion?: () => void;
  onNavigateToNgfw?: () => void;
  onNavigateToIdsIps?: () => void;
}

export const DnsSecuritySuiteView: React.FC<DnsSecuritySuiteViewProps> = ({
  report,
  onNavigateToScanner,
  onNavigateToSecurityOnion,
  onNavigateToNgfw,
  onNavigateToIdsIps
}) => {
  const [overview, setOverview] = useState<DnsSecurityOverview>(INITIAL_DNS_OVERVIEW);
  const [queries, setQueries] = useState<DnsQueryLog[]>(INITIAL_DNS_QUERIES);
  const [sinkholeRules, setSinkholeRules] = useState<DnsSinkholeRule[]>(INITIAL_SINKHOLE_RULES);
  const [dgaModels, setDgaModels] = useState<DgaDetectionModel[]>(INITIAL_DGA_MODELS);
  const [dnssecChains, setDnssecChains] = useState<DnssecChainOfTrust[]>(INITIAL_DNSSEC_CHAINS);
  const [tunnelSessions, setTunnelSessions] = useState<DnsTunnelExfiltrationSession[]>(INITIAL_TUNNEL_SESSIONS);

  // Active sub-tab
  const [activeSubTab, setActiveSubTab] = useState<'live_queries' | 'sinkhole_rpz' | 'dga_ml' | 'dns_tunnel' | 'dnssec_validator'>('live_queries');

  // Search & Filter
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // New Sinkhole Rule Form state
  const [newDomainPattern, setNewDomainPattern] = useState<string>('*.malicious-domain.com');
  const [newRedirectIp, setNewRedirectIp] = useState<string>('10.0.0.99');
  const [newCategory, setNewCategory] = useState<string>('C2 Malware Beacon');

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleToggleSinkholeRule = (id: string) => {
    setSinkholeRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  const handleDeleteSinkholeRule = (id: string) => {
    setSinkholeRules(prev => prev.filter(r => r.id !== id));
  };

  const handleAddSinkholeRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomainPattern.trim()) return;

    const newRule: DnsSinkholeRule = {
      id: `sink-${Date.now()}`,
      domainPattern: newDomainPattern.trim(),
      targetRedirectIp: `${newRedirectIp.trim()} (Sinkhole Honeypot)`,
      threatCategory: newCategory.trim(),
      enabled: true,
      totalInterceptions: 0
    };

    setSinkholeRules([newRule, ...sinkholeRules]);
    setNewDomainPattern('');
  };

  const handleExportDnsJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({
      overview,
      queries,
      sinkholeRules,
      dgaModels,
      dnssecChains,
      tunnelSessions
    }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `dns-security-telemetry-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const filteredQueries = useMemo(() => {
    let list = queries;
    if (statusFilter !== 'ALL') {
      list = list.filter(q => q.status === statusFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(item =>
        item.queryDomain.toLowerCase().includes(q) ||
        item.clientIp.toLowerCase().includes(q) ||
        item.clientHostname.toLowerCase().includes(q) ||
        item.threatDescription.toLowerCase().includes(q)
      );
    }
    return list;
  }, [queries, statusFilter, searchQuery]);

  return (
    <div id="dns-security-suite-container" className="space-y-6">
      {/* Top Banner & DNS Resolver Telemetry */}
      <div className="bg-[#0A0A0A] border border-[#222] rounded-xl p-4 sm:p-6 relative overflow-hidden shadow-lg">
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-bl from-blue-600/10 via-transparent to-transparent pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#1A1A1A] pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-lg bg-blue-500/10 text-blue-500 border border-blue-500/30">
                <Globe className="w-5 h-5 animate-pulse" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white font-mono">
                    Proteção do Sistema de Nomes (DNS Security Suite)
                  </h1>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/40 font-bold uppercase">
                    RPZ &amp; DNSSEC Enforced
                  </span>
                </div>
                <p className="text-xs text-zinc-400">
                  Proteção contra exfiltração por tunelamento DNS, detecção de domínios gerados por algoritmos (DGA), DNS Sinkhole com redirecionamento de ameaças e validação estrita da cadeia DNSSEC.
                </p>
              </div>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="flex items-center gap-2 sm:gap-4 flex-wrap font-mono">
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Consultas Hoje</span>
              <span className="text-sm font-bold text-white">{overview.totalQueriesToday.toLocaleString()}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Bloqueios Sinkhole</span>
              <span className="text-sm font-bold text-red-400">{overview.blockedQueriesToday}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Validação DNSSEC</span>
              <span className="text-sm font-bold text-[#00FF41]">{overview.dnssecValidationRate}%</span>
            </div>
            <button
              onClick={handleExportDnsJson}
              className="h-9 px-3 rounded-lg bg-[#141414] hover:bg-[#1E1E1E] text-zinc-300 hover:text-white border border-[#333] font-mono text-xs inline-flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Exportar telemetria de segurança DNS em JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Exportar Telemetria</span>
            </button>
          </div>
        </div>

        {/* Live Resolver Status & Feeds */}
        <div className="pt-4 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Resolvedor Ativo:</span>
            <span className="text-cyan-400 font-bold truncate max-w-[200px]">{overview.resolverType}</span>
          </div>
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Túneis DNS Frustrados:</span>
            <span className="text-amber-400 font-bold">{overview.tunnelExfiltrationsThwarted} sessões interceptadas</span>
          </div>
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Feeds de Ameaça RPZ:</span>
            <span className="text-[#00FF41] font-bold truncate max-w-[200px]">Ativo &amp; Sincronizado</span>
          </div>
        </div>
      </div>

      {/* Navigation Sub-tabs */}
      <div className="flex items-center gap-2 border-b border-[#222] pb-1 overflow-x-auto no-scrollbar font-mono text-xs">
        <button
          onClick={() => setActiveSubTab('live_queries')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'live_queries'
              ? 'text-blue-400 border-blue-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Consultas DNS &amp; Registro de Auditoria ({queries.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('sinkhole_rpz')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'sinkhole_rpz'
              ? 'text-blue-400 border-blue-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>DNS Sinkhole &amp; Response Policy Zones (RPZ) ({sinkholeRules.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('dga_ml')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'dga_ml'
              ? 'text-blue-400 border-blue-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>Detector de Algoritmos DGA (Machine Learning)</span>
        </button>

        <button
          onClick={() => setActiveSubTab('dns_tunnel')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'dns_tunnel'
              ? 'text-blue-400 border-blue-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>Inspeção de Tunelamento &amp; Exfiltração</span>
        </button>

        <button
          onClick={() => setActiveSubTab('dnssec_validator')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'dnssec_validator'
              ? 'text-blue-400 border-blue-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Lock className="w-3.5 h-3.5" />
          <span>Validador da Cadeia DNSSEC (Chain of Trust)</span>
        </button>
      </div>

      {/* SUBTAB 1: Live Queries Log */}
      {activeSubTab === 'live_queries' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0E0E0E] p-3 rounded-lg border border-[#222]">
            <div className="flex items-center gap-2 flex-1 max-w-md">
              <Search className="w-4 h-4 text-zinc-500 shrink-0" />
              <input
                type="text"
                placeholder="Filtrar por domínio, cliente, IP ou categoria..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full h-8 px-2 rounded bg-[#141414] border border-[#2A2A2A] text-white focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="flex items-center gap-1 overflow-x-auto">
              {(['ALL', 'SAFE', 'BLOCKED_SINKHOLE', 'SUSPICIOUS_TUNNEL', 'DGA_DETECTED'] as const).map(st => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`px-2 py-1 rounded cursor-pointer transition-colors ${
                    statusFilter === st 
                      ? 'bg-blue-600 text-white font-bold' 
                      : 'bg-[#181818] text-zinc-400 hover:text-white'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          <div className="border border-[#222] rounded-xl overflow-hidden">
            <table className="w-full text-left">
              <thead className="bg-[#141414] text-zinc-400 text-[10px] uppercase border-b border-[#222]">
                <tr>
                  <th className="py-3 px-3">Timestamp / Tipo</th>
                  <th className="py-3 px-3">Domínio Consultado</th>
                  <th className="py-3 px-3">Cliente (Origem)</th>
                  <th className="py-3 px-3">Entropia</th>
                  <th className="py-3 px-3">DNSSEC</th>
                  <th className="py-3 px-3">Status de Segurança</th>
                  <th className="py-3 px-3 text-right">Ação / Resolução</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1A1A1A]">
                {filteredQueries.map((query) => (
                  <tr key={query.id} className="hover:bg-[#121212] transition-colors">
                    <td className="py-3 px-3">
                      <span className="text-zinc-500 block text-[10px]">{query.timestamp}</span>
                      <span className="font-bold text-cyan-400">RR: {query.queryType}</span>
                    </td>

                    <td className="py-3 px-3 max-w-xs sm:max-w-sm">
                      <strong className="text-white block truncate">{query.queryDomain}</strong>
                      <span className="text-[10px] text-zinc-400 truncate block">{query.threatDescription}</span>
                    </td>

                    <td className="py-3 px-3">
                      <span className="text-zinc-200 font-bold block">{query.clientHostname}</span>
                      <span className="text-[10px] text-zinc-500">{query.clientIp}</span>
                    </td>

                    <td className="py-3 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        query.entropyShannon > 4.5 ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-zinc-800 text-zinc-400'
                      }`}>
                        {query.entropyShannon.toFixed(2)} bits
                      </span>
                    </td>

                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase inline-flex items-center gap-1 ${
                        query.dnssecStatus === 'SECURE_VALIDATED' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                        query.dnssecStatus === 'BOGUS_SIGNATURE_MISMATCH' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                        'bg-zinc-800 text-zinc-400'
                      }`}>
                        {query.dnssecStatus === 'SECURE_VALIDATED' ? <Lock className="w-2.5 h-2.5" /> : <Unlock className="w-2.5 h-2.5" />}
                        <span>{query.dnssecStatus === 'SECURE_VALIDATED' ? 'VÁLIDO' : query.dnssecStatus}</span>
                      </span>
                    </td>

                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        query.status === 'SAFE' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                        query.status === 'BLOCKED_SINKHOLE' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                        query.status === 'SUSPICIOUS_TUNNEL' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-purple-950 text-purple-300 border border-purple-800'
                      }`}>
                        {query.status}
                      </span>
                    </td>

                    <td className="py-3 px-3 text-right">
                      {query.sinkholeRedirectIp ? (
                        <span className="text-red-400 font-bold text-[11px] block">
                          &rarr; Redirecionado: {query.sinkholeRedirectIp}
                        </span>
                      ) : (
                        <span className="text-[#00FF41] font-mono text-[11px] block">
                          {query.resolvedIp}
                        </span>
                      )}
                      <span className="text-[9.5px] text-zinc-500">TTL: {query.ttlSeconds}s</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SUBTAB 2: DNS Sinkhole & RPZ Rules */}
      {activeSubTab === 'sinkhole_rpz' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-blue-500" />
              <span>DNS Sinkhole &amp; Zonas de Política de Resposta (Response Policy Zones - RPZ)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Intercepta requisições de domínios maliciosos (C2, malware, ransomware, phishing) e responde com um IP de honeypot interno isolado para contenção e análise de telemetria sem expor a infraestrutura à Internet.
            </p>
          </div>

          {/* New Rule Form */}
          <form onSubmit={handleAddSinkholeRule} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4 space-y-3">
            <strong className="text-white text-xs uppercase block font-bold">Criar Nova Regra de Interceptação Sinkhole:</strong>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="text-zinc-400 text-[10.5px] block font-bold mb-1">Padrão de Domínio (FQDN ou Wildcard)</label>
                <input
                  type="text"
                  placeholder="*.malicious-domain.com"
                  value={newDomainPattern}
                  onChange={(e) => setNewDomainPattern(e.target.value)}
                  className="w-full h-8 px-2 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="text-zinc-400 text-[10.5px] block font-bold mb-1">IP de Redirecionamento (Sinkhole Honeypot)</label>
                <input
                  type="text"
                  placeholder="10.0.0.99"
                  value={newRedirectIp}
                  onChange={(e) => setNewRedirectIp(e.target.value)}
                  className="w-full h-8 px-2 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="text-zinc-400 text-[10.5px] block font-bold mb-1">Categoria de Ameaça</label>
                <input
                  type="text"
                  placeholder="C2 Malware Beacon"
                  value={newCategory}
                  onChange={(e) => setNewCategory(e.target.value)}
                  className="w-full h-8 px-2 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            <div className="flex justify-end">
              <button
                type="submit"
                className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-bold uppercase inline-flex items-center gap-1 cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Adicionar Regra RPZ</span>
              </button>
            </div>
          </form>

          {/* Rules List */}
          <div className="space-y-3">
            {sinkholeRules.map((rule) => (
              <div key={rule.id} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4 space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E1E1E] pb-2">
                  <div className="flex items-center gap-2">
                    <span className="p-1 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30">
                      <Globe className="w-3.5 h-3.5" />
                    </span>
                    <strong className="text-white text-sm">{rule.domainPattern}</strong>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                      {rule.threatCategory}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-zinc-500 text-[10.5px]">Intercepções: <strong className="text-white">{rule.totalInterceptions}</strong></span>
                    <button
                      onClick={() => handleToggleSinkholeRule(rule.id)}
                      className={`px-2 py-1 rounded text-[10px] font-bold uppercase cursor-pointer border ${
                        rule.enabled ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-zinc-900 text-zinc-500 border-zinc-800'
                      }`}
                    >
                      {rule.enabled ? 'ATIVADA' : 'DESATIVADA'}
                    </button>
                    <button
                      onClick={() => handleDeleteSinkholeRule(rule.id)}
                      className="p-1 rounded bg-[#181818] hover:bg-rose-950 text-zinc-500 hover:text-rose-400 cursor-pointer"
                      title="Excluir regra"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-zinc-400">
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Destino do Redirecionamento (Sinkhole IP):</span>
                    <span className="text-amber-400 font-bold">{rule.targetRedirectIp}</span>
                  </div>
                  {rule.lastInterceptedAt && (
                    <div>
                      <span className="text-zinc-500 text-[10px] uppercase block">Última Interceptação:</span>
                      <span className="text-zinc-300">{rule.lastInterceptedAt}</span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 3: DGA Detection ML */}
      {activeSubTab === 'dga_ml' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-blue-500" />
              <span>Detecção de Domínios Gerados por Algoritmos (DGA Heuristics &amp; ML)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Classificador baseado em entropia de Shannon, proporção entre consoantes e vogais e pontuação n-gram para identificar domínios pseudo-aleatórios utilizados por malwares para se conectar a servidores de comando e controle voláteis.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {dgaModels.map((item, i) => (
              <div key={i} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4.5 space-y-3 flex flex-col justify-between">
                <div className="space-y-2">
                  <div className="flex items-center justify-between border-b border-[#1E1E1E] pb-2">
                    <strong className="text-white text-xs truncate max-w-[180px]">{item.dgaDomain}</strong>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      item.confidenceScore >= 80 ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    }`}>
                      {item.confidenceScore >= 80 ? 'DGA MALICIOSO' : 'BENIGNO'}
                    </span>
                  </div>

                  <div className="space-y-1.5 text-zinc-400">
                    <div className="flex justify-between">
                      <span className="text-zinc-500">Família Prevista:</span>
                      <strong className="text-purple-400">{item.predictedMalwareFamily}</strong>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-zinc-500">Confiança ML:</span>
                      <strong className="text-white">{item.confidenceScore}%</strong>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-zinc-500">Entropia Shannon:</span>
                      <strong className="text-cyan-400">{item.calculatedEntropy.toFixed(2)} bits</strong>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-zinc-500">Razão Consoante/Vogal:</span>
                      <strong className="text-zinc-200">{item.consonantVowelRatio}:1</strong>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-zinc-500">Pontuação N-Gram:</span>
                      <strong className="text-zinc-200">{item.ngramScore}</strong>
                    </div>
                  </div>
                </div>

                <div className="pt-2 border-t border-[#1E1E1E]">
                  <button
                    onClick={() => alert(`Domínio ${item.dgaDomain} isolado e injetado no sinkhole RPZ.`)}
                    className="w-full py-1.5 rounded bg-[#181818] hover:bg-zinc-800 text-blue-400 border border-blue-500/30 font-bold uppercase cursor-pointer"
                  >
                    Ação: {item.actionTaken}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 4: DNS Tunneling & Exfiltration */}
      {activeSubTab === 'dns_tunnel' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Network className="w-4 h-4 text-blue-500" />
              <span>Inspeção e Bloqueio de Tunelamento DNS (DNS Data Exfiltration)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Monitoramento de canais encobertos que abusam de consultas recursivas (especialmente TXT e CNAME com subdomínios longos) para vazar dados confidenciais ou estabelecer proxies de comando através de firewalls.
            </p>
          </div>

          <div className="space-y-3">
            {tunnelSessions.map((session) => (
              <div key={session.sessionId} className="bg-[#0D0D0D] border border-amber-500/30 rounded-xl p-5 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#222] pb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-white text-sm">{session.sessionId}</span>
                    <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 text-[10px]">
                      {session.detectedProtocol}
                    </span>
                  </div>

                  <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-bold uppercase animate-pulse">
                    {session.status}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-zinc-400">
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Host Cliente Infectado:</span>
                    <span className="text-white font-bold">{session.clientIp}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Domínio Ápice do Túnel:</span>
                    <span className="text-cyan-400 font-bold">{session.apexDomain}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Total de Chunks DNS:</span>
                    <span className="text-white font-bold">{session.totalChunksCount} requisições</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 text-[10px] uppercase block">Dados Interceptados:</span>
                    <span className="text-amber-400 font-bold">{session.estimatedBytesLeaked} bytes</span>
                  </div>
                </div>

                {/* Sample Reassembled Data */}
                <div className="space-y-1 pt-1">
                  <span className="text-zinc-500 text-[10px] uppercase block font-bold">Amostra dos Dados Remontados (Base64 Reconstructed Payload):</span>
                  <div className="p-3 rounded bg-[#141414] border border-[#2A2A2A] text-rose-300 break-all">
                    <code>{session.reassembledDataSample}</code>
                  </div>
                </div>

                <div className="flex justify-end gap-2 pt-2 border-t border-[#1E1E1E]">
                  <button
                    onClick={() => alert(`Túnel ${session.apexDomain} bloqueado e cliente ${session.clientIp} colocado em quarentena.`)}
                    className="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white font-bold uppercase cursor-pointer"
                  >
                    Encerrar Túnel &amp; Isolar Host
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 5: DNSSEC Validator */}
      {activeSubTab === 'dnssec_validator' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Lock className="w-4 h-4 text-blue-500" />
              <span>Validador da Cadeia Criptográfica DNSSEC (Chain of Trust)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Verificação ponta-a-ponta das assinaturas digitais RRSIG, registros DS da zona superior e chaves DNSKEY (KSK/ZSK) para garantir integridade e prevenir ataques de envenenamento de cache (DNS Cache Poisoning).
            </p>
          </div>

          <div className="space-y-3">
            {dnssecChains.map((chain, i) => (
              <div key={i} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-5 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#222] pb-2">
                  <div className="flex items-center gap-2">
                    <strong className="text-white text-sm">{chain.domain}</strong>
                    <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 text-[10px]">
                      Algoritmo: {chain.algorithm}
                    </span>
                  </div>

                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase flex items-center gap-1 ${
                    chain.rrsigStatus === 'VALID' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'
                  }`}>
                    {chain.rrsigStatus === 'VALID' ? <Check className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                    <span>RRSIG: {chain.rrsigStatus}</span>
                  </span>
                </div>

                <div className="space-y-2">
                  <div className="p-2.5 bg-[#121212] border border-[#222] rounded">
                    <span className="text-zinc-500 text-[9.5px] uppercase block font-bold">1. Âncora de Confiança Raiz (Root KSK .):</span>
                    <span className="text-zinc-300 break-all">{chain.rootAnchorKey}</span>
                  </div>

                  <div className="p-2.5 bg-[#121212] border border-[#222] rounded">
                    <span className="text-zinc-500 text-[9.5px] uppercase block font-bold">2. Delegação TLD (Delegation Signer DS Record):</span>
                    <span className="text-zinc-300 break-all">{chain.tldDsRecord}</span>
                  </div>

                  <div className="p-2.5 bg-[#121212] border border-[#222] rounded">
                    <span className="text-zinc-500 text-[9.5px] uppercase block font-bold">3. Chave de Assinatura da Zona (Zone Signing Key ZSK):</span>
                    <span className="text-zinc-300 break-all">{chain.zoneDnsKey}</span>
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
