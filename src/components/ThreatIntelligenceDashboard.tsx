import React, { useState, useEffect, useMemo } from 'react';
import { 
  Radio, 
  ShieldAlert, 
  ExternalLink, 
  Search, 
  RefreshCw, 
  Filter, 
  CheckCircle2, 
  AlertTriangle, 
  Zap, 
  Download, 
  Copy, 
  Globe, 
  Server, 
  Hash, 
  Crosshair, 
  ArrowUpRight,
  ShieldCheck,
  Clock,
  Sparkles
} from 'lucide-react';
import { ThreatIntelActivity, ThreatIntelSource, ThreatIntelFeedSummary, ScanReport } from '../types';
import { 
  fetchThreatFeedsSafe, 
  correlateThreatsSafe, 
  lookupThreatSafe 
} from '../lib/osintThreatFeedsData';

interface ThreatIntelligenceDashboardProps {
  report: ScanReport | null;
  onNavigateToFile?: (filePath: string, line?: number) => void;
  onNavigateToTab?: (tab: string) => void;
}

export const ThreatIntelligenceDashboard: React.FC<ThreatIntelligenceDashboardProps> = ({
  report,
  onNavigateToFile,
  onNavigateToTab
}) => {
  const [activities, setActivities] = useState<ThreatIntelActivity[]>([]);
  const [summary, setSummary] = useState<ThreatIntelFeedSummary | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [selectedSource, setSelectedSource] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [isCorrelating, setIsCorrelating] = useState<boolean>(false);
  const [correlationResults, setCorrelationResults] = useState<any[]>([]);
  const [lookupQuery, setLookupQuery] = useState<string>('');
  const [lookupResult, setLookupResult] = useState<any | null>(null);
  const [isLookingUp, setIsLookingUp] = useState<boolean>(false);

  // Fetch OSINT threat feeds safely
  const fetchFeeds = async () => {
    setIsLoading(true);
    try {
      const data = await fetchThreatFeedsSafe({
        source: selectedSource !== 'ALL' ? selectedSource : undefined,
        limit: 30
      });
      setActivities(data.activities || []);
      setSummary(data.summary || null);
    } catch {
      // Graceful fallback handled inside fetchThreatFeedsSafe
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchFeeds();
    const interval = setInterval(fetchFeeds, 45000); // Polling every 45s
    return () => clearInterval(interval);
  }, []);

  // Execute Workspace correlation
  const handleRunCorrelation = async () => {
    if (!report) return;
    setIsCorrelating(true);
    try {
      const data = await correlateThreatsSafe(
        report.findings || [],
        report.apiEndpoints || []
      );
      setCorrelationResults(data.correlations || []);
    } catch {
      // Graceful fallback handled inside correlateThreatsSafe
    } finally {
      setIsCorrelating(false);
    }
  };

  // Perform quick lookup
  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupQuery.trim()) return;
    setIsLookingUp(true);
    try {
      const data = await lookupThreatSafe(lookupQuery.trim());
      setLookupResult(data);
    } catch {
      // Graceful fallback handled inside lookupThreatSafe
    } finally {
      setIsLookingUp(false);
    }
  };

  // Copy indicator to clipboard
  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Filter activities
  const filteredActivities = useMemo(() => {
    return activities.filter((act) => {
      const matchSource = selectedSource === 'ALL' || act.source === selectedSource;
      const matchSeverity = selectedSeverity === 'ALL' || act.severity === selectedSeverity;
      const matchSearch =
        !searchQuery.trim() ||
        act.indicator.toLowerCase().includes(searchQuery.toLowerCase()) ||
        act.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        act.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (act.malwareFamily && act.malwareFamily.toLowerCase().includes(searchQuery.toLowerCase())) ||
        act.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));

      return matchSource && matchSeverity && matchSearch;
    });
  }, [activities, selectedSource, selectedSeverity, searchQuery]);

  // Export IOCs
  const handleExportIOCs = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredActivities, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `secscan-threat-intel-iocs-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div id="threat-intel-section" className="bg-[#0A0A0A] border-2 border-[#2A2A2A] p-6 lg:p-8 space-y-6 relative overflow-hidden">
      <div className="absolute top-0 right-0 w-80 h-80 bg-[#00FF41]/5 rounded-bl-full pointer-events-none" />

      {/* Header & Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-[#222]">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono text-[#00FF41] bg-[#00FF41]/10 px-2.5 py-0.5 border border-[#00FF41]/40 uppercase font-black tracking-widest flex items-center gap-1.5">
              <Radio className="w-3 h-3 text-[#00FF41] animate-pulse" />
              THREAT INTELLIGENCE // OSINT INTEGRATION
            </span>
            <span className="text-[10px] font-mono text-[#888]">
              ALIENVAULT OTX &bull; ABUSE.CH URLHAUS &bull; THREATFOX &bull; FEODO &bull; CISA KEV
            </span>
            <span className="text-[10px] font-mono bg-[#141414] text-[#00F0FF] border border-[#00F0FF]/30 px-2 py-0.5 font-bold">
              {summary?.activeCampaignsCount ?? activities.length} CAMPANHAS ATIVAS
            </span>
          </div>

          <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
            <span>Inteligência de Ameaças em Tempo Real</span>
          </h2>
          <p className="text-xs font-mono text-[#888] max-w-3xl leading-relaxed">
            Feeds abertos de OSINT sincronizados em tempo real. Monitora IOCs maliciosos, gateways de exfiltração C2, scripts maliciosos de supply-chain e campanhas adversárias ativas para correlação imediata com o código analisado.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            id="btn-correlate-threat-intel"
            onClick={handleRunCorrelation}
            disabled={isCorrelating || !report}
            className="px-4 py-2.5 bg-[#141414] hover:bg-[#1F1F1F] text-[#00FF41] hover:text-white border border-[#00FF41]/50 hover:border-[#00FF41] font-mono font-bold text-xs uppercase tracking-wider transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
            title="Correlacionar achados e endpoints do scan com IOCs ativos de OSINT"
          >
            <Crosshair className={`w-3.5 h-3.5 ${isCorrelating ? 'animate-spin' : ''}`} />
            <span>{isCorrelating ? 'Correlacionando...' : 'Correlacionar com Scan'}</span>
          </button>

          <button
            id="btn-refresh-threat-intel"
            onClick={fetchFeeds}
            disabled={isLoading}
            className="px-3 py-2.5 bg-[#141414] hover:bg-[#222] text-[#AAA] hover:text-white border border-[#333] font-mono text-xs uppercase transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            title="Sincronizar feeds de inteligência de ameaças agora"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-[#00FF41]' : ''}`} />
            <span className="hidden sm:inline">Sync Feeds</span>
          </button>

          <button
            id="btn-export-threat-iocs"
            onClick={handleExportIOCs}
            className="px-3 py-2.5 bg-[#141414] hover:bg-[#222] text-[#AAA] hover:text-white border border-[#333] font-mono text-xs uppercase transition-all flex items-center gap-1.5 cursor-pointer"
            title="Exportar IOCs em formato JSON"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Exportar IOCs</span>
          </button>
        </div>
      </div>

      {/* OSINT Feeds Live Health Indicators */}
      {summary?.sourcesOnline && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5">
          {summary.sourcesOnline.map((src, idx) => (
            <div
              key={idx}
              onClick={() => setSelectedSource(selectedSource === src.source ? 'ALL' : src.source)}
              className={`p-2.5 border font-mono transition-all cursor-pointer flex flex-col justify-between ${
                selectedSource === src.source
                  ? 'bg-[#0E2014] border-[#00FF41] text-white shadow-[0_0_12px_rgba(0,255,65,0.15)]'
                  : 'bg-[#0D0D0D] border-[#222] text-[#AAA] hover:border-[#444]'
              }`}
            >
              <div className="flex items-center justify-between text-[9px] mb-1">
                <span className="flex items-center gap-1 text-[#00FF41]">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#00FF41] animate-ping inline-block" />
                  ONLINE
                </span>
                <span className="text-[#666]">{src.latencyMs}ms</span>
              </div>
              <div className="font-bold text-[11px] text-white truncate">{src.name.split(' ')[0]}</div>
              <div className="text-[10px] text-[#888] truncate">{src.name.split(' ').slice(1).join(' ')}</div>
              <div className="mt-2 text-[10px] text-[#00FF41] font-bold">
                {src.indicatorsCount.toLocaleString()} IOCs
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Quick Observable OSINT Lookup Bar */}
      <div className="bg-[#111] border border-[#2A2A2A] p-4 space-y-3">
        <form onSubmit={handleLookup} className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-[#888] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={lookupQuery}
              onChange={(e) => setLookupQuery(e.target.value)}
              placeholder="Pesquisar IP, Domínio, Hash SHA256 ou CVE em bases OSINT (ex: auth-sts-aws-verification.com ou CVE-2024-3400)..."
              className="w-full bg-[#080808] border border-[#333] pl-9 pr-3 py-2 text-xs font-mono text-white placeholder-[#555] focus:outline-none focus:border-[#00FF41]"
            />
          </div>
          <button
            type="submit"
            disabled={isLookingUp || !lookupQuery.trim()}
            className="px-4 py-2 bg-[#00FF41] hover:bg-white text-black font-mono font-bold text-xs uppercase tracking-wider transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 shrink-0"
          >
            {isLookingUp ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            <span>Consultar OSINT</span>
          </button>
        </form>

        {/* Instant Lookup Result Display */}
        {lookupResult && (
          <div className={`p-3 border font-mono text-xs space-y-1.5 ${
            lookupResult.matched
              ? 'bg-[#FF3E00]/10 border-[#FF3E00]/50 text-white'
              : 'bg-[#00FF41]/10 border-[#00FF41]/50 text-white'
          }`}>
            <div className="flex items-center justify-between">
              <span className="font-bold flex items-center gap-1.5">
                {lookupResult.matched ? (
                  <AlertTriangle className="w-4 h-4 text-[#FF3E00]" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-[#00FF41]" />
                )}
                <span>VEREDITO: {lookupResult.verdict}</span>
              </span>
              <span className="text-[10px] text-[#AAA]">{lookupResult.matchCount} correspondência(s) encontrada(s)</span>
            </div>
            <p className="text-[11px] text-[#DDD]">{lookupResult.recommendation}</p>
          </div>
        )}
      </div>

      {/* Correlation Findings Alert Banner */}
      {correlationResults.length > 0 && (
        <div className="bg-[#FF3E00]/15 border-2 border-[#FF3E00] p-4 space-y-3 font-mono">
          <div className="flex items-center justify-between text-xs">
            <span className="text-[#FF3E00] font-black uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-[#FF3E00] animate-bounce" />
              ALERTA DE CORRELAÇÃO OSINT: {correlationResults.length} INDICADOR(ES) CORRESPONDEM AO CÓDIGO DO WORKSPACE!
            </span>
            <span className="text-[10px] bg-[#FF3E00] text-black font-bold px-2 py-0.5">AÇÃO IMEDIATA</span>
          </div>

          <div className="space-y-2">
            {correlationResults.map((item, idx) => (
              <div key={idx} className="bg-[#111] p-3 border border-[#FF3E00]/40 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                <div className="space-y-1">
                  <div className="text-xs font-bold text-white flex items-center gap-2">
                    <span className="text-[#FF3E00] font-mono">[{item.correlationType}]</span>
                    <span>{item.threatActivity?.title}</span>
                  </div>
                  <div className="text-[11px] text-[#AAA]">
                    Arquivo: <span className="text-[#00FF41]">{item.file}:{item.line}</span> &bull; Regra: <span className="text-white">{item.findingRule}</span>
                  </div>
                </div>

                {onNavigateToFile && item.file && (
                  <button
                    onClick={() => onNavigateToFile(item.file, item.line)}
                    className="px-3 py-1.5 bg-[#FF3E00] hover:bg-white text-black font-bold text-[10px] uppercase font-mono transition-all flex items-center gap-1 cursor-pointer shrink-0"
                  >
                    <span>Inspecionar Linha</span>
                    <ArrowUpRight className="w-3 h-3" />
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filters and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-mono text-[#888] flex items-center gap-1">
            <Filter className="w-3 h-3" />
            Fonte:
          </span>
          {['ALL', 'ALIENVAULT_OTX', 'ABUSE_CH_URLHAUS', 'ABUSE_CH_THREATFOX', 'ABUSE_CH_FEODO', 'CISA_KEV'].map((src) => (
            <button
              key={src}
              onClick={() => setSelectedSource(src)}
              className={`px-2.5 py-1 text-[10px] font-mono font-bold transition-all cursor-pointer border ${
                selectedSource === src
                  ? 'bg-[#00FF41] text-black border-[#00FF41]'
                  : 'bg-[#141414] text-[#888] border-[#333] hover:text-white hover:border-[#666]'
              }`}
            >
              {src === 'ALL' ? 'TODAS AS FONTES' : src.replace('ABUSE_CH_', '').replace('_', ' ')}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-[#888]">Severidade:</span>
          {['ALL', 'CRITICAL', 'HIGH'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSelectedSeverity(sev)}
              className={`px-2 py-0.5 text-[10px] font-mono font-bold border transition-all cursor-pointer ${
                selectedSeverity === sev
                  ? sev === 'CRITICAL' ? 'bg-[#FF3E00] text-white border-[#FF3E00]' : 'bg-white text-black border-white'
                  : 'bg-[#141414] text-[#888] border-[#333]'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Activity Cards Grid */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-[11px] font-mono text-[#AAA]">
          <span>Exibindo {filteredActivities.length} de {activities.length} atividades de ameaça ativas</span>
          <span className="flex items-center gap-1 text-[10px] text-[#666]">
            <Clock className="w-3 h-3" />
            Auto-refresh a cada 45s
          </span>
        </div>

        {isLoading && activities.length === 0 ? (
          <div className="p-12 text-center font-mono text-xs text-[#888] space-y-3">
            <RefreshCw className="w-6 h-6 animate-spin text-[#00FF41] mx-auto" />
            <div>Carregando feeds de inteligência de ameaças OSINT...</div>
          </div>
        ) : filteredActivities.length === 0 ? (
          <div className="p-8 text-center font-mono text-xs text-[#666] bg-[#0E0E0E] border border-[#222]">
            Nenhuma atividade de ameaça corresponde aos filtros selecionados.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredActivities.map((act) => {
              const isCopied = copiedId === act.id;
              return (
                <div
                  key={act.id}
                  className="bg-[#0C0C0C] border border-[#262626] hover:border-[#00FF41]/60 p-4 transition-all flex flex-col justify-between gap-3 relative group"
                >
                  <div className="space-y-2.5">
                    {/* Source & Severity Header */}
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className={`text-[9px] font-mono px-2 py-0.5 font-bold uppercase border ${
                          act.source === 'ALIENVAULT_OTX'
                            ? 'bg-[#00F0FF]/10 text-[#00F0FF] border-[#00F0FF]/40'
                            : act.source === 'CISA_KEV'
                            ? 'bg-[#FF3E00]/10 text-[#FF3E00] border-[#FF3E00]/40'
                            : 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/40'
                        }`}>
                          {act.sourceName}
                        </span>

                        <span className={`text-[9px] font-mono px-1.5 py-0.5 font-black uppercase ${
                          act.severity === 'CRITICAL' ? 'bg-[#FF3E00] text-black' : 'bg-[#FF9900] text-black'
                        }`}>
                          {act.severity}
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono text-[#00FF41] font-bold">
                          {act.confidenceScore}% CONF
                        </span>
                        <span className="text-[9px] font-mono text-[#888] flex items-center gap-1">
                          <span className="w-1.5 h-1.5 rounded-full bg-[#00FF41]" />
                          {act.status}
                        </span>
                      </div>
                    </div>

                    {/* Indicator Box */}
                    <div className="bg-[#141414] border border-[#2E2E2E] p-2 flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        {act.indicatorType === 'IP' && <Server className="w-3.5 h-3.5 text-[#00F0FF] shrink-0" />}
                        {act.indicatorType === 'DOMAIN' && <Globe className="w-3.5 h-3.5 text-[#00FF41] shrink-0" />}
                        {act.indicatorType === 'URL' && <ExternalLink className="w-3.5 h-3.5 text-[#FF9900] shrink-0" />}
                        {act.indicatorType === 'HASH_SHA256' && <Hash className="w-3.5 h-3.5 text-[#FF3E00] shrink-0" />}
                        {act.indicatorType === 'CVE' && <ShieldAlert className="w-3.5 h-3.5 text-[#FF3E00] shrink-0" />}
                        <span className="font-mono text-xs text-white font-bold truncate">
                          {act.indicator}
                        </span>
                      </div>

                      <button
                        onClick={() => handleCopy(act.indicator, act.id)}
                        className="p-1 hover:bg-[#222] text-[#888] hover:text-white transition-colors cursor-pointer shrink-0"
                        title="Copiar Indicador (IOC)"
                      >
                        {isCopied ? <CheckCircle2 className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>

                    {/* Threat Details */}
                    <div>
                      <h4 className="text-xs font-bold text-white font-mono leading-tight mb-1">
                        {act.title}
                      </h4>
                      <p className="text-[11px] font-mono text-[#888] line-clamp-2 leading-relaxed">
                        {act.description}
                      </p>
                    </div>

                    {/* Threat Metadata Badges */}
                    <div className="flex flex-wrap items-center gap-1.5 pt-1">
                      {act.malwareFamily && (
                        <span className="text-[9px] font-mono bg-[#181818] text-[#00FF41] px-1.5 py-0.5 border border-[#333] font-bold">
                          {act.malwareFamily}
                        </span>
                      )}
                      {act.asnOrCountry && (
                        <span className="text-[9px] font-mono bg-[#181818] text-[#AAA] px-1.5 py-0.5 border border-[#333]">
                          {act.asnOrCountry}
                        </span>
                      )}
                      {act.tags.slice(0, 3).map((tag, tIdx) => (
                        <span key={tIdx} className="text-[9px] font-mono bg-[#141414] text-[#666] px-1.5 py-0.5 border border-[#222]">
                          #{tag}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Defense Action & Advisory Link */}
                  <div className="pt-2 border-t border-[#1C1C1C] space-y-2">
                    <div className="text-[10px] font-mono text-[#DDD] bg-[#121212] p-2 border-l-2 border-[#00FF41]">
                      <span className="text-[#00FF41] font-bold block mb-0.5">AÇÃO DE MITIGAÇÃO:</span>
                      {act.defenseAction}
                    </div>

                    <div className="flex items-center justify-between text-[10px] font-mono pt-1">
                      <span className="text-[#666]">
                        Visto: {new Date(act.lastSeen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                      <a
                        href={act.referenceUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[#00F0FF] hover:underline flex items-center gap-1"
                      >
                        <span>Ver Pulse / Advisory</span>
                        <ArrowUpRight className="w-3 h-3" />
                      </a>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Threat Intel Governance Footer */}
      <div className="p-3.5 bg-[#080808] border border-[#222] font-mono text-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-[#AAA]">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-[#00FF41] shrink-0" />
          <span>
            Os dados de inteligência de ameaças são sincronizados dinamicamente via protocolos abertos de OSINT. Não armazenam nem transmitem segredos internos para servidores externos.
          </span>
        </div>
        <button
          onClick={handleRunCorrelation}
          className="text-[#00FF41] hover:text-white font-bold text-xs uppercase tracking-wider underline shrink-0 cursor-pointer"
        >
          Executar Correlação Automática &rarr;
        </button>
      </div>
    </div>
  );
};
