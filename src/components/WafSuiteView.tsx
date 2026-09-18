import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
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
  ArrowRight,
  Bot,
  Lock,
  Globe,
  Gauge
} from 'lucide-react';
import { ScanReport } from '../types';
import {
  WafSecurityRule,
  WafLiveBlockedEvent,
  WafRateLimitPolicy,
  WafVirtualPatch,
  WafEngineOverview,
  WafAction,
  WafAttackType
} from '../types/waf';
import {
  INITIAL_WAF_RULES,
  INITIAL_WAF_EVENTS,
  INITIAL_RATE_POLICIES,
  INITIAL_VIRTUAL_PATCHES,
  INITIAL_WAF_OVERVIEW
} from '../lib/wafEngine';

interface WafSuiteViewProps {
  report: ScanReport;
  onNavigateToScanner?: () => void;
  onNavigateToSecurityOnion?: () => void;
  onNavigateToNgfw?: () => void;
  onNavigateToIdsIps?: () => void;
  onNavigateToDns?: () => void;
}

export const WafSuiteView: React.FC<WafSuiteViewProps> = ({
  report,
  onNavigateToScanner,
  onNavigateToSecurityOnion,
  onNavigateToNgfw,
  onNavigateToIdsIps,
  onNavigateToDns
}) => {
  const [overview, setOverview] = useState<WafEngineOverview>(INITIAL_WAF_OVERVIEW);
  const [rules, setRules] = useState<WafSecurityRule[]>(INITIAL_WAF_RULES);
  const [events, setEvents] = useState<WafLiveBlockedEvent[]>(INITIAL_WAF_EVENTS);
  const [ratePolicies, setRatePolicies] = useState<WafRateLimitPolicy[]>(INITIAL_RATE_POLICIES);
  const [virtualPatches, setVirtualPatches] = useState<WafVirtualPatch[]>(INITIAL_VIRTUAL_PATCHES);

  // Active sub-tab
  const [activeSubTab, setActiveSubTab] = useState<'events' | 'owasp_crs' | 'rate_limit' | 'virtual_patches' | 'rule_builder'>('events');

  // Selected event for deep payload analysis
  const [selectedEventId, setSelectedEventId] = useState<string>('waf-evt-501');
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // New Rule Builder Form State
  const [builderName, setBuilderName] = useState<string>('Anti-GraphQL Introspection Abuse');
  const [builderCategory, setBuilderCategory] = useState<WafAttackType>('API_ABUSE');
  const [builderRegex, setBuilderRegex] = useState<string>(`(?i)__schema|__type|IntrospectionQuery`);
  const [builderScore, setBuilderScore] = useState<number>(5);
  const [builderAction, setBuilderAction] = useState<WafAction>('BLOCK_403');

  const selectedEvent = useMemo(() => {
    return events.find(e => e.id === selectedEventId) || events[0];
  }, [events, selectedEventId]);

  const filteredEvents = useMemo(() => {
    let list = events;
    if (categoryFilter !== 'ALL') {
      list = list.filter(e => e.attackType === categoryFilter);
    }
    if (searchFilter.trim()) {
      const q = searchFilter.toLowerCase();
      list = list.filter(item =>
        item.uriPath.toLowerCase().includes(q) ||
        item.clientIp.toLowerCase().includes(q) ||
        item.userAgent.toLowerCase().includes(q) ||
        item.payloadSnippet.toLowerCase().includes(q)
      );
    }
    return list;
  }, [events, categoryFilter, searchFilter]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleToggleMode = () => {
    setOverview(prev => ({
      ...prev,
      mode: prev.mode === 'BLOCKING_ACTIVE' ? 'LEARNING_MODE' : 'BLOCKING_ACTIVE'
    }));
  };

  const handleToggleRule = (id: string) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  const handleDeleteRule = (id: string) => {
    setRules(prev => prev.filter(r => r.id !== id));
  };

  const handleToggleRatePolicy = (id: string) => {
    setRatePolicies(prev => prev.map(p => p.id === id ? { ...p, enabled: !p.enabled } : p));
  };

  const handleCreateRule = (e: React.FormEvent) => {
    e.preventDefault();
    const newRuleId = 950000 + rules.length + 1;
    const newRule: WafSecurityRule = {
      id: `waf-rule-${newRuleId}`,
      ruleId: newRuleId,
      name: builderName,
      category: builderCategory,
      anomalyScore: builderScore,
      action: builderAction,
      phase: 2,
      patternRegex: builderRegex,
      enabled: true,
      totalHits: 0,
      owaspCrsReference: `Custom Security Rule - ${newRuleId}`
    };

    setRules([newRule, ...rules]);
    setActiveSubTab('owasp_crs');
  };

  const handleExportWafJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({
      overview,
      rules,
      events,
      ratePolicies,
      virtualPatches
    }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `waf-security-telemetry-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div id="waf-suite-container" className="space-y-6">
      {/* Top Banner & Engine Telemetry */}
      <div className="bg-[#0A0A0A] border border-[#222] rounded-xl p-4 sm:p-6 relative overflow-hidden shadow-lg">
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-bl from-emerald-500/10 via-transparent to-transparent pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#1A1A1A] pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <ShieldCheck className="w-5 h-5 animate-pulse" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white font-mono">
                    Firewall de Aplicações Web (WAF L7)
                  </h1>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase border ${
                    overview.mode === 'BLOCKING_ACTIVE'
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                  }`}>
                    {overview.mode === 'BLOCKING_ACTIVE' ? 'Modo Bloqueio: Ativo (Enforcing)' : 'Modo Aprendizado: Passivo'}
                  </span>
                </div>
                <p className="text-xs text-zinc-400">
                  Proteção na camada de aplicação (L7) com mitigação de OWASP Top 10, Virtual Patching de vulnerabilidades conhecidas, controle de taxa e gestão de bots maliciosos
                </p>
              </div>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="flex items-center gap-2 sm:gap-4 flex-wrap font-mono">
            <button
              onClick={handleToggleMode}
              className={`h-9 px-3 rounded-lg border font-mono text-xs font-bold uppercase inline-flex items-center gap-1.5 transition-colors cursor-pointer ${
                overview.mode === 'BLOCKING_ACTIVE'
                  ? 'bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border-zinc-700'
                  : 'bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border-emerald-700'
              }`}
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>{overview.mode === 'BLOCKING_ACTIVE' ? 'Mudar p/ Aprendizado' : 'Ativar Bloqueio L7'}</span>
            </button>

            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Requisições Hoje</span>
              <span className="text-sm font-bold text-white">{overview.totalRequestsToday.toLocaleString()}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Bloqueios L7</span>
              <span className="text-sm font-bold text-rose-400">{overview.blockedAttacksToday}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Latência Média</span>
              <span className="text-sm font-bold text-[#00FF41]">{overview.avgInspectionLatencyMs} ms</span>
            </div>
            <button
              onClick={handleExportWafJson}
              className="h-9 px-3 rounded-lg bg-[#141414] hover:bg-[#1E1E1E] text-zinc-300 hover:text-white border border-[#333] font-mono text-xs inline-flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Exportar Logs</span>
            </button>
          </div>
        </div>

        {/* Live Engine Details */}
        <div className="pt-4 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Modelo de Detecção:</span>
            <span className="text-cyan-400 font-bold">OWASP ModSecurity CRS v3.3 (Anomaly Scoring)</span>
          </div>
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Limiar de Bloqueio (Threshold):</span>
            <span className="text-white font-bold">{overview.anomalyThreshold} pontos de anomalia</span>
          </div>
          <div className="p-2.5 bg-[#111] border border-[#222] rounded flex items-center justify-between">
            <span className="text-zinc-500">Virtual Patches Ativos:</span>
            <span className="text-[#00FF41] font-bold">{overview.activeVirtualPatchesCount} CVEs blindados</span>
          </div>
        </div>
      </div>

      {/* Navigation Sub-tabs */}
      <div className="flex items-center gap-2 border-b border-[#222] pb-1 overflow-x-auto no-scrollbar font-mono text-xs">
        <button
          onClick={() => setActiveSubTab('events')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'events'
              ? 'text-emerald-400 border-emerald-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Ataques &amp; Bloqueios L7 ({events.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('owasp_crs')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'owasp_crs'
              ? 'text-emerald-400 border-emerald-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <SlidersHorizontal className="w-3.5 h-3.5" />
          <span>Regras OWASP Core Rule Set ({rules.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('rate_limit')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'rate_limit'
              ? 'text-emerald-400 border-emerald-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Gauge className="w-3.5 h-3.5" />
          <span>Políticas de Rate Limit &amp; Anti-Brute Force ({ratePolicies.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('virtual_patches')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'virtual_patches'
              ? 'text-emerald-400 border-emerald-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Lock className="w-3.5 h-3.5" />
          <span>Virtual Patching (CVE Shield) ({virtualPatches.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('rule_builder')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'rule_builder'
              ? 'text-emerald-400 border-emerald-500 bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Criador de Regras Customizadas</span>
        </button>
      </div>

      {/* SUBTAB 1: Live Blocked Events */}
      {activeSubTab === 'events' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0E0E0E] p-3 rounded-lg border border-[#222]">
            <div className="flex items-center gap-2 flex-1 max-w-md">
              <Search className="w-4 h-4 text-zinc-500 shrink-0" />
              <input
                type="text"
                placeholder="Filtrar por rota, IP de origem, user-agent ou payload..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="w-full h-8 px-2 rounded bg-[#141414] border border-[#2A2A2A] text-white focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div className="flex items-center gap-1 overflow-x-auto">
              {(['ALL', 'SQL_INJECTION', 'CROSS_SITE_SCRIPTING', 'SERVER_SIDE_REQUEST_FORGERY', 'CREDENTIAL_STUFFING'] as const).map(cat => (
                <button
                  key={cat}
                  onClick={() => setCategoryFilter(cat)}
                  className={`px-2 py-1 rounded cursor-pointer transition-colors text-[10.5px] ${
                    categoryFilter === cat 
                      ? 'bg-emerald-600 text-white font-bold' 
                      : 'bg-[#181818] text-zinc-400 hover:text-white'
                  }`}
                >
                  {cat.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>

          <div className="border border-[#222] rounded-xl overflow-hidden">
            <table className="w-full text-left">
              <thead className="bg-[#141414] text-zinc-400 text-[10px] uppercase border-b border-[#222]">
                <tr>
                  <th className="py-3 px-3">Timestamp / Método</th>
                  <th className="py-3 px-3">Rota / Endpoint Atacado</th>
                  <th className="py-3 px-3">Origem &amp; Geolocalização</th>
                  <th className="py-3 px-3">Categoria / Regras</th>
                  <th className="py-3 px-3">Pontuação Anomalia</th>
                  <th className="py-3 px-3">Ação Executada</th>
                  <th className="py-3 px-3 text-right">Ações</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1A1A1A]">
                {filteredEvents.map((evt) => (
                  <tr key={evt.id} className="hover:bg-[#121212] transition-colors">
                    <td className="py-3 px-3">
                      <span className="text-zinc-500 block text-[10px]">{evt.timestamp}</span>
                      <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 font-bold text-[10px]">
                        {evt.httpMethod}
                      </span>
                    </td>

                    <td className="py-3 px-3 max-w-xs sm:max-w-sm">
                      <strong className="text-white block truncate">{evt.uriPath}</strong>
                      <span className="text-[10px] text-zinc-500 truncate block">{evt.userAgent}</span>
                    </td>

                    <td className="py-3 px-3">
                      <span className="text-zinc-200 font-bold block">{evt.clientIp}</span>
                      <span className="text-[10px] text-zinc-400">{evt.clientGeo}</span>
                    </td>

                    <td className="py-3 px-3">
                      <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold text-[10px] block w-fit mb-1">
                        {evt.attackType}
                      </span>
                      <span className="text-[9.5px] text-zinc-500">{evt.triggeredRules.length} regra(s) CRS acionada(s)</span>
                    </td>

                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1.5">
                        <span className={`font-bold text-sm ${evt.totalAnomalyScore >= 10 ? 'text-rose-400' : 'text-amber-400'}`}>
                          {evt.totalAnomalyScore} pts
                        </span>
                        <span className="text-zinc-600 text-[10px]">(Bot: {evt.botScore}%)</span>
                      </div>
                    </td>

                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        evt.actionEnforced === 'BLOCK_403' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                        evt.actionEnforced === 'CHALLENGE_CAPTCHA' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-blue-950 text-blue-300 border border-blue-800'
                      }`}>
                        {evt.actionEnforced} ({evt.httpStatusReturned})
                      </span>
                    </td>

                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => setSelectedEventId(evt.id)}
                        className="px-2 py-1 rounded bg-[#181818] hover:bg-zinc-800 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold inline-flex items-center gap-1 cursor-pointer"
                      >
                        <Eye className="w-3 h-3" />
                        <span>Payload</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Selected Event Payload Detail Box */}
          <div className="bg-[#0D0D0D] border border-[#222] rounded-xl p-5 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#222] pb-2">
              <div>
                <span className="text-zinc-500 text-[10px] uppercase block">Inspeção Detalhada do Evento:</span>
                <strong className="text-white text-sm">{selectedEvent.httpMethod} {selectedEvent.uriPath}</strong>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-zinc-400 text-xs">{selectedEvent.clientGeo}</span>
                <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 text-[10px] font-bold uppercase">
                  {selectedEvent.actionEnforced}
                </span>
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-zinc-400 font-bold uppercase text-[10.5px] block">Regras Acionadas &amp; Padrões Casados:</span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {selectedEvent.triggeredRules.map((r, idx) => (
                  <div key={idx} className="p-2.5 bg-[#141414] border border-[#222] rounded space-y-1">
                    <div className="flex justify-between items-center">
                      <strong className="text-white text-xs">CRS {r.ruleId}: {r.ruleName}</strong>
                      <span className="text-amber-400 font-bold text-[10px]">+{r.anomalyScore} pts</span>
                    </div>
                    <code className="text-rose-300 text-[11px] block break-all">Casou: &quot;{r.matchedString}&quot;</code>
                  </div>
                ))}
              </div>
            </div>

            <div className="space-y-1 pt-1">
              <div className="flex items-center justify-between">
                <span className="text-zinc-400 font-bold uppercase text-[10.5px]">Amostra do Payload HTTP Interceptado:</span>
                <button
                  onClick={() => handleCopy(selectedEvent.payloadSnippet, 'payload')}
                  className="text-zinc-500 hover:text-white cursor-pointer inline-flex items-center gap-1 text-[10px]"
                >
                  {copiedKey === 'payload' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                  <span>Copiar Payload</span>
                </button>
              </div>
              <div className="p-3 bg-[#121212] border border-[#222] rounded-lg text-rose-300 font-mono break-all">
                <code>{selectedEvent.payloadSnippet}</code>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 2: OWASP CRS Rules Catalog */}
      {activeSubTab === 'owasp_crs' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <SlidersHorizontal className="w-4 h-4 text-emerald-400" />
              <span>OWASP ModSecurity Core Rule Set (CRS v3.3)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Assinaturas oficiais e heurísticas de anomalia calibradas para bloqueio instantâneo na borda de SQLi, XSS, RCE, SSRF e Local File Inclusion.
            </p>
          </div>

          <div className="space-y-3">
            {rules.map((rule) => (
              <div key={rule.id} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E1E1E] pb-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold">
                      ID: {rule.ruleId}
                    </span>
                    <strong className="text-white text-sm">{rule.name}</strong>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                      Fase {rule.phase}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-zinc-500 text-[10.5px]">Hits: <strong className="text-white">{rule.totalHits}</strong></span>
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
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <div className="p-2.5 bg-[#121212] border border-[#222] rounded text-[11px] flex items-center justify-between">
                  <code className="text-emerald-300 break-all">{rule.patternRegex}</code>
                  <button
                    onClick={() => handleCopy(rule.patternRegex, rule.id)}
                    className="text-zinc-500 hover:text-white ml-2 cursor-pointer shrink-0"
                  >
                    {copiedKey === rule.id ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 3: Rate Limiting & Bot Management */}
      {activeSubTab === 'rate_limit' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Gauge className="w-4 h-4 text-emerald-400" />
              <span>Políticas de Rate Limit &amp; Mitigação de Bots</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Controle de volumetria de requisições por cliente/IP para evitar ataques de força bruta em autenticações, credential stuffing e scraping predatório de conteúdo.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {ratePolicies.map((pol) => (
              <div key={pol.id} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4.5 space-y-3 flex flex-col justify-between">
                <div className="space-y-2">
                  <div className="flex items-center justify-between border-b border-[#1E1E1E] pb-2">
                    <strong className="text-white text-xs">{pol.name}</strong>
                    <button
                      onClick={() => handleToggleRatePolicy(pol.id)}
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase cursor-pointer ${
                        pol.enabled ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-zinc-900 text-zinc-500'
                      }`}
                    >
                      {pol.enabled ? 'ATIVO' : 'DESATIVADO'}
                    </button>
                  </div>

                  <div className="space-y-1 text-zinc-400">
                    <div className="flex justify-between">
                      <span className="text-zinc-500">Endpoint Alvo:</span>
                      <strong className="text-cyan-400">{pol.targetEndpoint}</strong>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-zinc-500">Limite de Taxa:</span>
                      <strong className="text-white">{pol.rateLimitThreshold} reqs / {pol.windowSeconds}s</strong>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-zinc-500">Ação no Excesso:</span>
                      <strong className="text-amber-400">{pol.actionOnExceed}</strong>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-zinc-500">IPs Bloqueados Atualmente:</span>
                      <strong className="text-rose-400">{pol.activeBansCount} clientes</strong>
                    </div>
                  </div>
                </div>

                <div className="pt-2 border-t border-[#1E1E1E]">
                  <button
                    onClick={() => alert(`Reset do contador de bans para ${pol.name}`)}
                    className="w-full py-1.5 rounded bg-[#181818] hover:bg-zinc-800 text-zinc-300 font-bold uppercase cursor-pointer text-[10px]"
                  >
                    Liberar IPs Bloqueados
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 4: Virtual Patching (CVE Shield) */}
      {activeSubTab === 'virtual_patches' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-400" />
              <span>Virtual Patching (Blindagem de Vulnerabilidades L7)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Mitigação imediata na camada de rede de vulnerabilidades conhecidas (CVEs) sem necessidade de reescrever código ou realizar deploys emergenciais de bibliotecas e frameworks legados.
            </p>
          </div>

          <div className="space-y-3">
            {virtualPatches.map((patch) => (
              <div key={patch.cveId} className="bg-[#0D0D0D] border border-emerald-500/30 rounded-xl p-5 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#222] pb-2">
                  <div className="flex items-center gap-2">
                    <strong className="text-emerald-400 text-sm">{patch.cveId}</strong>
                    <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 text-[10px]">
                      {patch.targetSoftware}
                    </span>
                  </div>

                  <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold uppercase flex items-center gap-1">
                    <ShieldCheck className="w-3 h-3" />
                    <span>Status: {patch.activeStatus}</span>
                  </span>
                </div>

                <p className="text-zinc-300 text-xs leading-relaxed">
                  {patch.description}
                </p>

                <div className="flex items-center justify-between pt-2 border-t border-[#1E1E1E] text-zinc-500">
                  <span>Regra CRS Mitigadora: <strong className="text-white">ID {patch.mitigationRuleId}</strong></span>
                  <span>Blindagem Aplicada em: {patch.patchDate}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 5: Custom Rule Builder */}
      {activeSubTab === 'rule_builder' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Plus className="w-4 h-4 text-emerald-400" />
              <span>Criador Visual de Regras de Bloqueio WAF</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Crie regras personalizadas de inspeção de payloads HTTP para proteger endpoints e lógicas de negócios específicas da sua aplicação.
            </p>
          </div>

          <form onSubmit={handleCreateRule} className="bg-[#0D0D0D] border border-[#222] rounded-xl p-5 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-zinc-400 font-bold uppercase text-[10.5px] block">Nome da Regra</label>
                <input
                  type="text"
                  value={builderName}
                  onChange={(e) => setBuilderName(e.target.value)}
                  className="w-full h-8 px-2.5 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-zinc-400 font-bold uppercase text-[10.5px] block">Categoria de Ataque</label>
                <select
                  value={builderCategory}
                  onChange={(e) => setBuilderCategory(e.target.value as any)}
                  className="w-full h-8 px-2 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-emerald-500"
                >
                  <option value="SQL_INJECTION">SQL Injection (SQLi)</option>
                  <option value="CROSS_SITE_SCRIPTING">Cross-Site Scripting (XSS)</option>
                  <option value="REMOTE_CODE_EXECUTION">Remote Code Execution (RCE)</option>
                  <option value="SERVER_SIDE_REQUEST_FORGERY">Server-Side Request Forgery (SSRF)</option>
                  <option value="PATH_TRAVERSAL">Path Traversal / LFI</option>
                  <option value="API_ABUSE">API Abuse / Broken Logic</option>
                </select>
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-zinc-400 font-bold uppercase text-[10.5px] block">Expressão Regular (Regex Pattern)</label>
              <input
                type="text"
                value={builderRegex}
                onChange={(e) => setBuilderRegex(e.target.value)}
                className="w-full h-8 px-2.5 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-zinc-400 font-bold uppercase text-[10.5px] block">Pontuação de Anomalia</label>
                <input
                  type="number"
                  min="1"
                  max="10"
                  value={builderScore}
                  onChange={(e) => setBuilderScore(Number(e.target.value))}
                  className="w-full h-8 px-2.5 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-zinc-400 font-bold uppercase text-[10.5px] block">Ação no Casamento</label>
                <select
                  value={builderAction}
                  onChange={(e) => setBuilderAction(e.target.value as any)}
                  className="w-full h-8 px-2 rounded bg-[#141414] border border-[#333] text-white focus:outline-none focus:border-emerald-500"
                >
                  <option value="BLOCK_403">Bloqueio Imediato (403 Forbidden)</option>
                  <option value="CHALLENGE_CAPTCHA">Desafio Interativo (CAPTCHA)</option>
                  <option value="LOG_ONLY">Apenas Registro (Log Only)</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-[#222]">
              <button
                type="submit"
                className="px-4 py-2 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold uppercase inline-flex items-center gap-1.5 cursor-pointer"
              >
                <Plus className="w-4 h-4" />
                <span>Compilar Regra &amp; Injetar no Motor</span>
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
