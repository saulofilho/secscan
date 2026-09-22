import React, { useState, useMemo, useEffect } from 'react';
import {
  Globe,
  Radio,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Search,
  Filter,
  RefreshCw,
  ExternalLink,
  Download,
  Copy,
  Check,
  Activity,
  Zap,
  Tag,
  Crosshair,
  Skull,
  Terminal,
  Layers,
  ChevronDown,
  ChevronUp,
  Info,
  Clock,
  Sparkles,
  Lock,
  Boxes,
  FileCode2,
  Database,
  ArrowRight,
  Target
} from 'lucide-react';
import {
  ScanFinding,
  SeverityLevel,
  ThreatIntelFeedStatus,
  ThreatActorProfile,
  OtxPulse,
  ThreatIocItem,
  FindingThreatIntelTag,
  AuditLogEvent
} from '../types';
import {
  INITIAL_THREAT_FEEDS,
  THREAT_ACTOR_PROFILES,
  INITIAL_OTX_PULSES,
  correlateFindingWithThreatIntel,
  autoTagAllFindingsWithCti,
  searchIocReputation,
  exportCtiToStix21
} from '../lib/cyberThreatIntelEngine';

interface CyberThreatIntelHubViewProps {
  findings: ScanFinding[];
  onUpdateFindings?: (updated: ScanFinding[]) => void;
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToScanner?: () => void;
  onLogAudit?: (event: AuditLogEvent) => void;
}

type CtiSubTab = 'TAGGED_FINDINGS' | 'OTX_PULSES' | 'THREAT_ACTORS' | 'IOC_LOOKUP' | 'STIX_EXPORT';

export const CyberThreatIntelHubView: React.FC<CyberThreatIntelHubViewProps> = ({
  findings = [],
  onUpdateFindings,
  onSelectFinding,
  onNavigateToScanner,
  onLogAudit
}) => {
  // Navigation & Sub-tabs
  const [activeTab, setActiveTab] = useState<CtiSubTab>('TAGGED_FINDINGS');

  // Live feeds state
  const [feeds, setFeeds] = useState<ThreatIntelFeedStatus[]>(INITIAL_THREAT_FEEDS);
  const [pulses, setPulses] = useState<OtxPulse[]>(INITIAL_OTX_PULSES);
  const [actors] = useState<ThreatActorProfile[]>(THREAT_ACTOR_PROFILES);
  const [isRealtimeSyncing, setIsRealtimeSyncing] = useState(false);
  const [autoSyncInterval, setAutoSyncInterval] = useState<number>(30); // seconds
  const [isRealtimeActive, setIsRealtimeActive] = useState(true);
  const [lastSyncTime, setLastSyncTime] = useState<string>('Agora');

  // Filters
  const [findingSearch, setFindingSearch] = useState('');
  const [actorFilter, setActorFilter] = useState<string>('ALL');
  const [urgencyFilter, setUrgencyFilter] = useState<string>('ALL');
  const [cisaKevOnly, setCisaKevOnly] = useState(false);
  const [selectedPulse, setSelectedPulse] = useState<OtxPulse | null>(null);
  const [selectedActor, setSelectedActor] = useState<ThreatActorProfile | null>(null);

  // IOC Lookup State
  const [iocLookupQuery, setIocLookupQuery] = useState('AKIAIOSFODNN7EXAMPLE');
  const [lookupResult, setLookupResult] = useState(() => searchIocReputation('AKIAIOSFODNN7EXAMPLE', INITIAL_OTX_PULSES));

  // Copy & Export State
  const [copiedStix, setCopiedStix] = useState(false);
  const [copiedTagId, setCopiedTagId] = useState<string | null>(null);

  // Correlation computation
  const correlationSummary = useMemo(() => {
    return autoTagAllFindingsWithCti(findings, pulses, actors);
  }, [findings, pulses, actors]);

  const enrichedFindings = correlationSummary.taggedFindings;

  // Real-time polling simulation effect
  useEffect(() => {
    if (!isRealtimeActive) return;

    const timer = setInterval(() => {
      // Simulate slight heartbeat update on feeds
      setFeeds(prev =>
        prev.map(f => ({
          ...f,
          lastSyncTimestamp: new Date().toISOString(),
          pulseCount: f.pulseCount + Math.floor(Math.random() * 3)
        }))
      );
      setLastSyncTime('Há poucos segundos');
    }, autoSyncInterval * 1000);

    return () => clearInterval(timer);
  }, [isRealtimeActive, autoSyncInterval]);

  // Filtered Enriched Findings
  const filteredFindings = useMemo(() => {
    return enrichedFindings.filter(f => {
      const tag = f.threatIntelTag;
      if (!tag) return false;

      if (cisaKevOnly && !tag.cisaKevExploited) return false;
      if (actorFilter !== 'ALL' && tag.threatActor?.id !== actorFilter) return false;
      if (urgencyFilter !== 'ALL' && tag.remediationUrgency !== urgencyFilter) return false;

      if (findingSearch.trim()) {
        const q = findingSearch.toLowerCase();
        const actorName = tag.threatActor?.name.toLowerCase() || '';
        const ttp = tag.threatActorTtp?.toLowerCase() || '';
        const campaign = tag.campaigns.join(' ').toLowerCase();
        return (
          f.ruleName.toLowerCase().includes(q) ||
          f.file.toLowerCase().includes(q) ||
          actorName.includes(q) ||
          ttp.includes(q) ||
          campaign.includes(q)
        );
      }
      return true;
    });
  }, [enrichedFindings, cisaKevOnly, actorFilter, urgencyFilter, findingSearch]);

  // Manual Trigger: Sincronizar Feeds
  const handleManualSyncFeeds = () => {
    setIsRealtimeSyncing(true);
    setTimeout(() => {
      // Add a simulated live pulse if not already there
      const simulatedNewPulse: OtxPulse = {
        id: `pulse-live-${Date.now()}`,
        name: 'Zero-Day API Token Harvesting & GitHub Secret Scrape Feed',
        author: 'AlienVault LevelBlue CTI',
        description: 'Fluxo em tempo real detectando bots autônomos varrendo commits públicos por credenciais AWS, GCP e tokens de pagamento.',
        created: new Date().toISOString(),
        modified: new Date().toISOString(),
        tlp: 'WHITE',
        tags: ['Real-Time', 'AlienVault', 'Secrets', 'API Security'],
        adversary: 'Scattered Spider',
        subscriberCount: 2980,
        cves: ['CVE-2026-1182'],
        iocs: [
          {
            id: `ioc-live-${Date.now()}`,
            type: 'IPv4',
            indicator: '185.220.101.5',
            title: 'Scattered Spider Active Proxy Node',
            confidence: 97,
            severity: 'CRITICAL',
            firstSeen: '2026-09-22',
            lastSeen: '2026-09-22',
            sourceFeed: 'ALIENVAULT_OTX',
            threatActor: 'Scattered Spider',
            maliciousContext: 'IP executando varreduras massivas de endpoints.'
          }
        ]
      };

      setPulses(prev => [simulatedNewPulse, ...prev]);
      setIsRealtimeSyncing(false);
      setLastSyncTime('Agora');

      if (onLogAudit) {
        onLogAudit({
          id: `audit-cti-sync-${Date.now()}`,
          timestamp: new Date().toISOString(),
          type: 'RULE_APPLIED',
          message: 'CTI Hub: Feeds AlienVault OTX e CISA KEV sincronizados com sucesso. Novos IOCs incorporados.',
          severity: 'INFO',
          details: { feedsCount: feeds.length, totalPulses: pulses.length + 1 }
        });
      }
    }, 1200);
  };

  // Trigger: Auto-Tag Findings into Main State
  const handleApplyTagsToWorkspace = () => {
    if (onUpdateFindings) {
      onUpdateFindings(correlationSummary.taggedFindings);
    }

    if (onLogAudit) {
      onLogAudit({
        id: `audit-cti-tag-${Date.now()}`,
        timestamp: new Date().toISOString(),
        type: 'RULE_APPLIED',
        message: `CTI Hub: ${correlationSummary.totalTagged} achados foram etiquetados com Threat Actors e IOCs do AlienVault OTX / CISA KEV.`,
        severity: 'INFO',
        details: {
          totalTagged: correlationSummary.totalTagged,
          criticalCount: correlationSummary.criticalUrgencyCount,
          cisaKevCount: correlationSummary.cisaKevCount
        }
      });
    }
  };

  // Perform IOC search
  const handlePerformLookup = (q: string) => {
    setIocLookupQuery(q);
    const res = searchIocReputation(q, pulses);
    setLookupResult(res);
  };

  // Export STIX
  const stixJsonString = useMemo(() => {
    return exportCtiToStix21(findings, actors, pulses);
  }, [findings, actors, pulses]);

  const handleCopyStix = () => {
    navigator.clipboard.writeText(stixJsonString);
    setCopiedStix(true);
    setTimeout(() => setCopiedStix(false), 2000);
  };

  const handleDownloadStix = () => {
    const blob = new Blob([stixJsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'secscan-cti-bundle.stix21.json';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Severity color helpers
  const getSeverityBadge = (sev: SeverityLevel) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'LOW':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
      default:
        return 'bg-zinc-800 text-zinc-400 border-zinc-700';
    }
  };

  const getUrgencyBadge = (urgency: string) => {
    switch (urgency) {
      case 'IMMEDIATE_ACTION':
        return 'bg-red-500/20 text-red-400 border-red-500/40 animate-pulse';
      case 'HIGH_PRIORITY':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
      default:
        return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
    }
  };

  return (
    <div className="space-y-6 pb-16 font-sans">
      {/* Top Banner Header */}
      <div className="bg-[#0A0A0A] p-6 sm:p-8 border border-[#222]">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="text-[10px] font-black tracking-[0.25em] text-[#00FF41] uppercase">
                // REAL-TIME CYBER THREAT INTELLIGENCE (CTI) HUB
              </span>
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-[#141414] text-white border border-[#333] flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${isRealtimeActive ? 'bg-[#00FF41] animate-ping' : 'bg-zinc-600'}`} />
                {isRealtimeActive ? 'STREAM AO VIVO ATIVO' : 'SYNC MANUAL'}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 bg-red-500/15 text-red-400 border border-red-500/30 font-bold">
                {correlationSummary.cisaKevCount} CISA KEV DETECTADOS
              </span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white uppercase mt-1 flex items-center gap-3">
              <Globe className="w-7 h-7 text-[#00FF41]" />
              <span>Cyber Threat Intelligence Hub</span>
            </h1>
            <p className="text-xs font-mono text-[#888] mt-1.5 max-w-3xl leading-relaxed">
              Integração em tempo real com feeds públicos globais (<strong className="text-white">AlienVault OTX</strong>, <strong className="text-white">CISA KEV</strong>, <strong className="text-white">MISP CIRCL</strong> e <strong className="text-white">AbuseIPDB</strong>). Correlaciona automaticamente achados de código a perfis de atores hostis (<strong className="text-white">Scattered Spider</strong>, <strong className="text-white">Lazarus Group</strong>, <strong className="text-white">Volt Typhoon</strong>) e IOCs ativos.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              id="btn-sync-cti-feeds"
              type="button"
              onClick={handleManualSyncFeeds}
              disabled={isRealtimeSyncing}
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-[#141414] hover:bg-[#202020] text-white font-mono text-xs uppercase tracking-wider border border-[#333] transition-all cursor-pointer disabled:opacity-50"
              title="Forçar sincronização de novos pulses e IOCs com AlienVault OTX e CISA KEV"
            >
              <RefreshCw className={`w-4 h-4 text-[#00FF41] ${isRealtimeSyncing ? 'animate-spin' : ''}`} />
              <span>{isRealtimeSyncing ? 'Sincronizando...' : 'Sincronizar Feeds'}</span>
            </button>

            <button
              id="btn-apply-cti-tags"
              type="button"
              onClick={handleApplyTagsToWorkspace}
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-[#00FF41] hover:bg-[#00dd38] text-black font-mono font-black text-xs uppercase tracking-wider transition-all cursor-pointer shadow-lg shadow-[#00FF41]/10 active:scale-95"
              title="Propagar etiquetas CTI para o scanner central e painéis de SAST"
            >
              <Tag className="w-4 h-4 text-black" />
              <span>Aplicar Tags aos Achados ({correlationSummary.totalTagged})</span>
            </button>
          </div>
        </div>

        {/* Live Feeds Status Bar */}
        <div className="mt-6 pt-5 border-t border-[#1C1C1C] grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {feeds.map(feed => (
            <div
              key={feed.id}
              className="p-2.5 bg-[#050505] border border-[#1E1E1E] text-xs font-mono flex flex-col justify-between"
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-zinc-500 font-bold uppercase truncate">{feed.badge}</span>
                <span className="text-[9px] px-1 py-0.2 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">
                  {feed.status}
                </span>
              </div>
              <div className="font-bold text-white text-[11px] truncate mt-1">{feed.name.split('(')[0]}</div>
              <div className="flex items-center justify-between text-[10px] text-zinc-400 mt-2 pt-1 border-t border-[#151515]">
                <span>{feed.pulseCount.toLocaleString()} pulses</span>
                <span className="text-zinc-500">{feed.reliabilityScore}% conf.</span>
              </div>
            </div>
          ))}
        </div>

        {/* Sub-tabs Navigation */}
        <div className="flex flex-wrap items-center justify-between gap-3 mt-6 pt-5 border-t border-[#1C1C1C]">
          <div className="flex items-center bg-[#121212] p-1 border border-[#262626] flex-wrap">
            <button
              type="button"
              onClick={() => setActiveTab('TAGGED_FINDINGS')}
              className={`px-3.5 py-1.5 text-xs font-mono font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer ${
                activeTab === 'TAGGED_FINDINGS'
                  ? 'bg-[#00FF41] text-black font-black'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <Tag className="w-3.5 h-3.5" />
              <span>Achados Correlacionados ({correlationSummary.totalTagged})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('OTX_PULSES')}
              className={`px-3.5 py-1.5 text-xs font-mono font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer ${
                activeTab === 'OTX_PULSES'
                  ? 'bg-[#00FF41] text-black font-black'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <Radio className="w-3.5 h-3.5" />
              <span>Pulses OTX & CISA KEV ({pulses.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('THREAT_ACTORS')}
              className={`px-3.5 py-1.5 text-xs font-mono font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer ${
                activeTab === 'THREAT_ACTORS'
                  ? 'bg-[#00FF41] text-black font-black'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <Skull className="w-3.5 h-3.5" />
              <span>Dossiês de Ameaças ({actors.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('IOC_LOOKUP')}
              className={`px-3.5 py-1.5 text-xs font-mono font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer ${
                activeTab === 'IOC_LOOKUP'
                  ? 'bg-[#00FF41] text-black font-black'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <Search className="w-3.5 h-3.5" />
              <span>Buscador de IOC</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('STIX_EXPORT')}
              className={`px-3.5 py-1.5 text-xs font-mono font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer ${
                activeTab === 'STIX_EXPORT'
                  ? 'bg-[#00FF41] text-black font-black'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <FileCode2 className="w-3.5 h-3.5" />
              <span>Exportar STIX 2.1</span>
            </button>
          </div>

          <div className="flex items-center gap-3 text-[11px] font-mono text-zinc-400">
            <span className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-zinc-500" />
              Última Sincronização: <strong className="text-white">{lastSyncTime}</strong>
            </span>
          </div>
        </div>
      </div>

      {/* SUB-TAB 1: TAGGED FINDINGS */}
      {activeTab === 'TAGGED_FINDINGS' && (
        <div className="space-y-6">
          {/* Filters Bar */}
          <div className="bg-[#0A0A0A] border border-[#222] p-4 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="relative w-full md:w-80">
              <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Filtrar por ator, regra, TTP, arquivo..."
                value={findingSearch}
                onChange={(e) => setFindingSearch(e.target.value)}
                className="w-full bg-[#050505] border border-[#333] text-white text-xs pl-9 pr-3 py-2 font-mono focus:border-[#00FF41] focus:outline-none"
              />
            </div>

            <div className="flex items-center gap-2.5 flex-wrap w-full md:w-auto justify-end">
              <select
                value={actorFilter}
                onChange={(e) => setActorFilter(e.target.value)}
                className="bg-[#050505] border border-[#333] text-zinc-300 text-xs px-2.5 py-2 font-mono focus:border-[#00FF41] focus:outline-none"
              >
                <option value="ALL">Todos os Threat Actors</option>
                {actors.map(act => (
                  <option key={act.id} value={act.id}>
                    {act.name} ({act.codeName})
                  </option>
                ))}
              </select>

              <select
                value={urgencyFilter}
                onChange={(e) => setUrgencyFilter(e.target.value)}
                className="bg-[#050505] border border-[#333] text-zinc-300 text-xs px-2.5 py-2 font-mono focus:border-[#00FF41] focus:outline-none"
              >
                <option value="ALL">Todas as Urgências</option>
                <option value="IMMEDIATE_ACTION">Ação Imediata (P0)</option>
                <option value="HIGH_PRIORITY">Alta Prioridade (P1)</option>
                <option value="MONITOR">Monitoramento</option>
              </select>

              <label className="flex items-center gap-2 text-xs font-mono text-zinc-300 bg-[#050505] border border-[#333] px-3 py-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={cisaKevOnly}
                  onChange={(e) => setCisaKevOnly(e.target.checked)}
                  className="rounded bg-[#111] border-[#444] text-[#00FF41] focus:ring-0"
                />
                <span className="font-bold text-red-400">Apenas CISA KEV</span>
              </label>
            </div>
          </div>

          {/* Tagged Findings Cards Grid */}
          {filteredFindings.length === 0 ? (
            <div className="p-12 bg-[#0A0A0A] border border-[#222] text-center space-y-3">
              <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
              <h3 className="text-base font-bold text-white font-mono uppercase">
                Nenhum achado encontrado com os filtros CTI aplicados
              </h3>
              <p className="text-xs font-mono text-zinc-400 max-w-md mx-auto">
                Tente redefinir os filtros de atores ou faça uma nova varredura de arquivos no workspace.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredFindings.map(finding => {
                const tag = finding.threatIntelTag!;

                return (
                  <div
                    key={finding.id}
                    className="bg-[#0A0A0A] border border-[#222] hover:border-[#444] transition-all p-5 space-y-4 font-mono text-xs"
                  >
                    {/* Top Row: Threat Actor Badge, CISA KEV status & Severity */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1A1A1A]">
                      <div className="flex items-center gap-2 flex-wrap">
                        {tag.threatActor ? (
                          <span className="px-2.5 py-1 bg-red-500/15 border border-red-500/40 text-red-300 font-bold flex items-center gap-1.5 text-xs">
                            <Skull className="w-3.5 h-3.5 text-red-400" />
                            <span>ATOR: {tag.threatActor.name}</span>
                            <span className="text-[10px] text-zinc-400">({tag.threatActor.codeName})</span>
                          </span>
                        ) : (
                          <span className="px-2.5 py-1 bg-zinc-800 border border-zinc-700 text-zinc-300">
                            Padrão de Ameaça OTX
                          </span>
                        )}

                        {tag.cisaKevExploited && (
                          <span className="px-2 py-1 bg-red-600 text-white font-black text-[10px] tracking-wider uppercase flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3 text-white" />
                            <span>CISA KEV: EXPLOIT ATIVO</span>
                          </span>
                        )}

                        <span className={`px-2 py-0.5 border text-[10px] font-bold ${getUrgencyBadge(tag.remediationUrgency)}`}>
                          URGÊNCIA: {tag.remediationUrgency.replace('_', ' ')}
                        </span>
                      </div>

                      <div className="flex items-center gap-3 text-zinc-400 text-[11px]">
                        <span>
                          Amplificador de Risco:{' '}
                          <strong className="text-[#00FF41]">{tag.riskScoreAmplifier}x</strong>
                        </span>
                        <span className={`px-2 py-0.5 border text-[10px] font-bold ${getSeverityBadge(finding.severity)}`}>
                          {finding.severity}
                        </span>
                      </div>
                    </div>

                    {/* Middle Section: Finding Info & Threat Summary */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                      <div className="lg:col-span-2 space-y-2">
                        <div className="flex items-center gap-2">
                          <span className="text-white font-bold text-sm">
                            {finding.ruleName}
                          </span>
                          <span className="text-zinc-500 text-[11px]">
                            {finding.file}:{finding.line}
                          </span>
                        </div>

                        <p className="text-zinc-300 text-[11px] leading-relaxed bg-[#050505] p-3 border border-[#1A1A1A]">
                          <strong className="text-[#00FF41]">Correlação CTI:</strong> {tag.threatSummary}
                        </p>

                        <div className="text-[11px] text-zinc-400 flex items-center gap-2">
                          <Target className="w-3.5 h-3.5 text-cyan-400" />
                          <span>MITRE ATT&CK TTP: <strong className="text-white">{tag.threatActorTtp || 'T1190 / Exploit Web App'}</strong></span>
                        </div>
                      </div>

                      {/* Associated OTX Pulses & Campaigns */}
                      <div className="space-y-2 bg-[#050505] p-3 border border-[#1A1A1A]">
                        <div className="text-[10px] font-bold text-zinc-400 uppercase flex items-center gap-1.5">
                          <Radio className="w-3.5 h-3.5 text-amber-400" />
                          Campanhas & Pulses OTX:
                        </div>
                        <div className="space-y-1">
                          {tag.campaigns.map((camp, cIdx) => (
                            <div key={cIdx} className="text-[10.5px] text-zinc-300 flex items-center gap-1.5">
                              <span className="w-1.5 h-1.5 rounded-full bg-[#00FF41]" />
                              <span>{camp}</span>
                            </div>
                          ))}
                          {tag.matchingPulses.map(pulse => (
                            <div key={pulse.id} className="text-[10px] text-zinc-400 pt-1">
                              <span className="text-cyan-400 font-bold">OTX Pulse:</span> {pulse.name}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Bottom Actions Row */}
                    <div className="pt-2 border-t border-[#1A1A1A] flex flex-wrap items-center justify-between gap-3 text-[11px]">
                      <div className="flex items-center gap-2 text-zinc-500">
                        <span>Arquivo Afetado: <code className="text-zinc-300">{finding.file}</code></span>
                      </div>

                      <div className="flex items-center gap-2">
                        {onSelectFinding && (
                          <button
                            type="button"
                            onClick={() => {
                              onSelectFinding(finding);
                              onNavigateToScanner?.();
                            }}
                            className="px-3 py-1 bg-[#141414] hover:bg-[#202020] text-zinc-300 hover:text-white border border-[#333] transition-colors cursor-pointer"
                          >
                            Inspecionar no Scanner
                          </button>
                        )}

                        <button
                          type="button"
                          onClick={() => {
                            navigator.clipboard.writeText(
                              `[CTI TAG] Ator: ${tag.threatActor?.name || 'OTX Public'} | TTP: ${tag.threatActorTtp} | CISA KEV: ${tag.cisaKevExploited ? 'Sim' : 'Não'} | Arquivo: ${finding.file}:${finding.line}`
                            );
                            setCopiedTagId(finding.id);
                            setTimeout(() => setCopiedTagId(null), 2000);
                          }}
                          className="px-3 py-1 bg-[#141414] hover:bg-[#202020] text-zinc-300 hover:text-[#00FF41] border border-[#333] transition-colors flex items-center gap-1.5 cursor-pointer"
                        >
                          {copiedTagId === finding.id ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-[#00FF41]" />
                              <span className="text-[#00FF41]">Tag Copiada!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5" />
                              <span>Copiar Tag CTI</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* SUB-TAB 2: OTX & CISA KEV PULSES */}
      {activeTab === 'OTX_PULSES' && (
        <div className="space-y-6">
          <div className="bg-[#0A0A0A] border border-[#222] p-5 space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold uppercase text-white flex items-center gap-2">
                  <Radio className="w-4 h-4 text-[#00FF41]" />
                  Feeds Públicos de Ameaças: AlienVault OTX & CISA KEV
                </h3>
                <p className="text-[11px] text-zinc-400 mt-1">
                  Pulses verificados recebidos das redes de inteligência aberta da AT&T Cybersecurity, CIRCL e CISA.
                </p>
              </div>

              <span className="text-[10px] text-zinc-400 bg-[#050505] px-2.5 py-1 border border-[#222]">
                {pulses.length} Pulses Carregados
              </span>
            </div>

            <div className="space-y-4">
              {pulses.map(pulse => (
                <div
                  key={pulse.id}
                  className="bg-[#050505] border border-[#1E1E1E] p-4 space-y-3"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-white text-sm">{pulse.name}</span>
                      <span className="text-[9.5px] px-1.5 py-0.2 bg-[#121212] text-zinc-400 border border-[#2A2A2A]">
                        TLP: {pulse.tlp}
                      </span>
                      {pulse.adversary && (
                        <span className="text-[9.5px] px-1.5 py-0.2 bg-red-500/15 text-red-400 border border-red-500/30">
                          {pulse.adversary}
                        </span>
                      )}
                    </div>

                    <span className="text-[10.5px] text-zinc-500 font-mono">
                      {pulse.author} | {new Date(pulse.created).toLocaleDateString('pt-BR')}
                    </span>
                  </div>

                  <p className="text-zinc-300 text-[11px] leading-relaxed">
                    {pulse.description}
                  </p>

                  {/* Tags */}
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {pulse.tags.map((t, idx) => (
                      <span key={idx} className="text-[9.5px] px-2 py-0.5 bg-[#141414] text-zinc-400 border border-[#222]">
                        #{t}
                      </span>
                    ))}
                    {pulse.cves?.map((cve, idx) => (
                      <span key={idx} className="text-[9.5px] px-2 py-0.5 bg-red-500/10 text-red-400 border border-red-500/20 font-bold">
                        {cve}
                      </span>
                    ))}
                  </div>

                  {/* IOC Table inside pulse */}
                  <div className="mt-3 pt-3 border-t border-[#181818] space-y-2">
                    <div className="text-[10px] uppercase font-bold text-zinc-400">
                      Indicadores de Comprometimento (IOCs) no Pulse ({pulse.iocs.length}):
                    </div>
                    <div className="space-y-1.5">
                      {pulse.iocs.map(ioc => (
                        <div
                          key={ioc.id}
                          className="p-2 bg-[#090909] border border-[#1A1A1A] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px]"
                        >
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="text-[9px] px-1.5 py-0.2 bg-[#181818] text-zinc-400 border border-[#333] shrink-0 font-bold">
                              {ioc.type}
                            </span>
                            <code className="text-[#00FF41] font-bold truncate select-all">
                              {ioc.indicator}
                            </code>
                          </div>
                          <span className="text-zinc-400 text-[10px] shrink-0">
                            Confiança: {ioc.confidence}% | {ioc.sourceFeed}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 3: THREAT ACTORS MATRIX */}
      {activeTab === 'THREAT_ACTORS' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 font-mono text-xs">
          {actors.map(actor => (
            <div
              key={actor.id}
              className="bg-[#0A0A0A] border border-[#222] p-5 space-y-4 hover:border-[#444] transition-all flex flex-col justify-between"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-3 border-b border-[#1A1A1A]">
                  <div>
                    <div className="flex items-center gap-2">
                      <Skull className="w-4 h-4 text-red-400" />
                      <h3 className="text-sm font-black text-white uppercase">{actor.name}</h3>
                    </div>
                    <span className="text-[10.5px] text-zinc-500 mt-0.5 block">{actor.codeName}</span>
                  </div>

                  <div className="text-right">
                    <span className="text-[10px] text-zinc-500 block">THREAT SCORE</span>
                    <span className="text-sm font-black text-red-400">{actor.threatScore} / 100</span>
                  </div>
                </div>

                <p className="text-zinc-300 text-[11px] leading-relaxed">
                  {actor.description}
                </p>

                <div className="grid grid-cols-2 gap-2 text-[10.5px] bg-[#050505] p-3 border border-[#1A1A1A]">
                  <div>
                    <span className="text-zinc-500 block">Origem:</span>
                    <span className="text-white font-bold">{actor.origin}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block">Motivação:</span>
                    <span className="text-amber-300 font-bold">{actor.motivation}</span>
                  </div>
                </div>

                {/* Targeted Technologies */}
                <div>
                  <span className="text-[10px] text-zinc-500 font-bold uppercase block mb-1">
                    Tecnologias Visadas em Repositórios:
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {actor.targetedTechnologies.map((tech, tIdx) => (
                      <span key={tIdx} className="text-[9.5px] px-2 py-0.5 bg-[#141414] text-cyan-300 border border-[#222]">
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>

                {/* MITRE ATT&CK TTPs */}
                <div>
                  <span className="text-[10px] text-zinc-500 font-bold uppercase block mb-1">
                    Principais Táticas & Técnicas (TTPs):
                  </span>
                  <div className="space-y-1">
                    {actor.ttps.map((ttp, idx) => (
                      <div key={idx} className="text-[10px] text-zinc-400 flex items-center justify-between bg-[#070707] p-1.5 border border-[#151515]">
                        <span className="text-white font-semibold">{ttp.techniqueId} - {ttp.name}</span>
                        <span className="text-zinc-500 text-[9px]">{ttp.tactic}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="pt-3 border-t border-[#181818] flex items-center justify-between text-[10px] text-zinc-500">
                <span>Atividade: <strong className="text-zinc-300">{actor.lastActive}</strong></span>
                <span className="text-[#00FF41]">Campanhas ativas: {actor.activeCampaigns.length}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* SUB-TAB 4: IOC QUICK LOOKUP & REPUTATION */}
      {activeTab === 'IOC_LOOKUP' && (
        <div className="bg-[#0A0A0A] border border-[#222] p-6 space-y-6 font-mono text-xs">
          <div>
            <h3 className="text-sm font-bold uppercase text-white flex items-center gap-2">
              <Search className="w-4 h-4 text-[#00FF41]" />
              Buscador Rápido de IOC & Avaliação de Reputação
            </h3>
            <p className="text-[11px] text-zinc-400 mt-1">
              Cole qualquer endereço IPv4, domínio, hash MD5/SHA-256 ou prefixo de chave para consultar a reputação em tempo real no banco do OTX.
            </p>
          </div>

          {/* Search Box */}
          <div className="flex flex-col sm:flex-row items-center gap-3">
            <input
              type="text"
              value={iocLookupQuery}
              onChange={(e) => handlePerformLookup(e.target.value)}
              placeholder="Ex: 198.51.100.44, AKIAIOSFODNN7EXAMPLE, auth-sync-gateway.org..."
              className="w-full bg-[#050505] border border-[#333] text-white px-3 py-2.5 text-xs font-mono focus:border-[#00FF41] focus:outline-none"
            />
            <button
              type="button"
              onClick={() => handlePerformLookup(iocLookupQuery)}
              className="px-5 py-2.5 bg-[#00FF41] hover:bg-[#00dd38] text-black font-black uppercase text-xs tracking-wider cursor-pointer shrink-0"
            >
              Consultar IOC
            </button>
          </div>

          {/* Lookup Result Box */}
          <div className="p-5 bg-[#050505] border border-[#1E1E1E] space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#181818]">
              <div>
                <span className="text-[10px] text-zinc-500 uppercase block">INDICADOR PESQUISADO:</span>
                <code className="text-sm font-bold text-white">{lookupResult.query || 'Nenhum'}</code>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-[10px] text-zinc-400">VEREDITO:</span>
                <span
                  className={`px-2.5 py-1 font-bold text-xs border ${
                    lookupResult.reputation === 'MALICIOUS'
                      ? 'bg-red-500/20 text-red-400 border-red-500/40'
                      : lookupResult.reputation === 'SUSPICIOUS'
                      ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                      : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                  }`}
                >
                  {lookupResult.reputation}
                </span>
              </div>
            </div>

            {lookupResult.foundMatches.length === 0 ? (
              <div className="text-zinc-500 py-3 text-center">
                Nenhuma correlação maliciosa direta encontrada nos feeds locais para este indicador.
              </div>
            ) : (
              <div className="space-y-3">
                <div className="text-[11px] font-bold text-zinc-300 uppercase">
                  Ocorrências Detectadas ({lookupResult.foundMatches.length}):
                </div>
                {lookupResult.foundMatches.map(match => (
                  <div key={match.id} className="p-3 bg-[#080808] border border-[#222] space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-white font-bold">{match.title || match.indicator}</span>
                      <span className="text-zinc-500 text-[10px]">{match.sourceFeed}</span>
                    </div>
                    <p className="text-[11px] text-zinc-400">{match.maliciousContext}</p>
                    {match.threatActor && (
                      <span className="text-[9.5px] px-1.5 py-0.2 bg-red-500/15 text-red-400 border border-red-500/30 inline-block mt-1">
                        Ator Associado: {match.threatActor}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUB-TAB 5: STIX 2.1 EXPORT */}
      {activeTab === 'STIX_EXPORT' && (
        <div className="bg-[#0A0A0A] border border-[#222] p-5 space-y-4 font-mono text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold uppercase text-white flex items-center gap-2">
                <FileCode2 className="w-4 h-4 text-[#00FF41]" />
                Exportação de Inteligência em Formato Padrão STIX 2.1 (OASIS)
              </h3>
              <p className="text-[11px] text-zinc-400 mt-1">
                Gere bundles em formato JSON para importação direta em ferramentas de SIEM, OpenCTI, MISP ou Cortex XSOAR.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleCopyStix}
                className="px-3 py-1.5 bg-[#141414] hover:bg-[#202020] text-white border border-[#333] transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                {copiedStix ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-[#00FF41]" />
                    <span className="text-[#00FF41]">Copiado!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-zinc-400" />
                    <span>Copiar STIX JSON</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={handleDownloadStix}
                className="px-3.5 py-1.5 bg-[#00FF41] hover:bg-[#00dd38] text-black font-black uppercase tracking-wider transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5 text-black" />
                <span>Baixar Bundle STIX</span>
              </button>
            </div>
          </div>

          <div className="bg-[#050505] p-4 border border-[#1A1A1A] max-h-96 overflow-y-auto text-[11px] text-[#00FF41]">
            <pre className="font-mono whitespace-pre">{stixJsonString}</pre>
          </div>
        </div>
      )}
    </div>
  );
};
