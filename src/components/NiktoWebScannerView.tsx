import React, { useState, useMemo } from 'react';
import {
  Globe,
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
  FileCode2,
  Lock,
  Network,
  FileSearch,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Sliders,
  CheckCircle2,
  XCircle,
  Code2
} from 'lucide-react';
import { ScanReport } from '../types';
import {
  NiktoTargetProfile,
  NiktoScanOptions,
  NiktoScanSession,
  NiktoCheckItem,
  NiktoSecurityHeaderCheck
} from '../types/nikto';
import {
  NIKTO_TUNING_DICTIONARY,
  buildDefaultTargets,
  simulateNiktoScan
} from '../lib/niktoEngine';

interface NiktoWebScannerViewProps {
  report: ScanReport;
  onNavigateToScanner?: () => void;
  onNavigateToEndpoints?: () => void;
}

export const NiktoWebScannerView: React.FC<NiktoWebScannerViewProps> = ({
  report,
  onNavigateToScanner,
  onNavigateToEndpoints
}) => {
  const [targets, setTargets] = useState<NiktoTargetProfile[]>(() => buildDefaultTargets(report));
  const [selectedTargetId, setSelectedTargetId] = useState<string>(targets[0]?.id || '');
  
  // Options state
  const [targetUrlInput, setTargetUrlInput] = useState<string>(targets[0]?.targetUrl || 'https://api.internal.finance.corp');
  const [useSsl, setUseSsl] = useState<boolean>(true);
  const [selectedTuning, setSelectedTuning] = useState<string[]>(['1', '2', '3', 'b', 'c']);
  const [customUserAgent, setCustomUserAgent] = useState<string>('Mozilla/5.0 (compatible; SecScan-Nikto/2.5.0)');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [activeSubTab, setActiveSubTab] = useState<'findings' | 'headers' | 'methods' | 'tuning' | 'terminal'>('findings');
  const [copiedTerminal, setCopiedTerminal] = useState<boolean>(false);
  const [copiedCommand, setCopiedCommand] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO'>('ALL');

  // Active session
  const [latestSession, setLatestSession] = useState<NiktoScanSession>(() =>
    simulateNiktoScan({
      targetUrl: targets[0]?.targetUrl || 'https://api.internal.finance.corp',
      port: 443,
      useSsl: true,
      tuningCategories: ['1', '2', '3', 'b', 'c'],
      customUserAgent: 'Mozilla/5.0 (compatible; SecScan-Nikto/2.5.0)',
      timeoutSeconds: 10,
      singleHostScanOnly: true
    }, targets)
  );

  const selectedTarget = useMemo(() => {
    return targets.find(t => t.id === selectedTargetId) || targets[0] || null;
  }, [targets, selectedTargetId]);

  // Aggregate stats
  const stats = useMemo(() => {
    const allFindings = targets.flatMap(t => t.findings);
    const critical = allFindings.filter(f => f.severity === 'CRITICAL').length;
    const high = allFindings.filter(f => f.severity === 'HIGH').length;
    const totalChecks = targets.reduce((sum, t) => sum + t.checksPassed + t.checksFailed, 0);
    const weakHeaders = targets.flatMap(t => t.securityHeaders).filter(h => h.status !== 'VALID').length;
    return { allFindingsCount: allFindings.length, critical, high, totalChecks, weakHeaders };
  }, [targets]);

  // Filtered findings for selected target
  const filteredFindings = useMemo(() => {
    if (!selectedTarget) return [];
    let list = selectedTarget.findings;
    if (severityFilter !== 'ALL') {
      list = list.filter(f => f.severity === severityFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(f => 
        f.uri.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q) ||
        (f.osvdb && f.osvdb.toString().includes(q))
      );
    }
    return list;
  }, [selectedTarget, severityFilter, searchQuery]);

  const handleToggleTuning = (code: string) => {
    if (selectedTuning.includes(code)) {
      setSelectedTuning(selectedTuning.filter(c => c !== code));
    } else {
      setSelectedTuning([...selectedTuning, code]);
    }
  };

  const handleExecuteScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      const session = simulateNiktoScan({
        targetUrl: targetUrlInput,
        port: useSsl ? 443 : 80,
        useSsl,
        tuningCategories: selectedTuning,
        customUserAgent,
        timeoutSeconds: 10,
        singleHostScanOnly: true
      }, targets);
      setLatestSession(session);
      setIsScanning(false);
    }, 850);
  };

  const handleCopyCommand = () => {
    navigator.clipboard?.writeText(latestSession.cliCommand);
    setCopiedCommand(true);
    setTimeout(() => setCopiedCommand(false), 2000);
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
    downloadAnchor.setAttribute("download", `nikto-audit-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div id="nikto-web-scanner-container" className="space-y-6">
      {/* Top Banner & Control Deck */}
      <div className="bg-[#0A0A0A] border border-[#222] rounded-xl p-4 sm:p-6 relative overflow-hidden shadow-lg">
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-bl from-[#FF7A00]/5 via-transparent to-transparent pointer-events-none" />
        
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#1A1A1A] pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-lg bg-[#FF7A00]/10 text-[#FF7A00] border border-[#FF7A00]/30">
                <Globe className="w-5 h-5" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white font-mono">
                    Nikto Web Server Scanner
                  </h1>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#FF7A00]/15 text-[#FF7A00] border border-[#FF7A00]/40 font-bold uppercase">
                    Misconfig &amp; Header Audit
                  </span>
                </div>
                <p className="text-xs text-zinc-400">
                  Inspeção profunda de servidores web, arquivos perigosos, métodos HTTP de risco e conformidade de cabeçalhos
                </p>
              </div>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="flex items-center gap-2 sm:gap-4 flex-wrap">
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] font-mono text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Críticos</span>
              <span className="text-sm font-bold text-rose-400">{stats.critical}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] font-mono text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Altos</span>
              <span className="text-sm font-bold text-amber-400">{stats.high}</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] font-mono text-center">
              <span className="text-[10px] text-zinc-500 uppercase block">Headers Fracos</span>
              <span className="text-sm font-bold text-cyan-400">{stats.weakHeaders}</span>
            </div>
            <button
              id="btn-nikto-export-session"
              onClick={handleExportJson}
              className="h-9 px-3 rounded-lg bg-[#141414] hover:bg-[#1E1E1E] text-zinc-300 hover:text-white border border-[#333] font-mono text-xs inline-flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Exportar sessão Nikto em formato JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Exportar JSON</span>
            </button>
          </div>
        </div>

        {/* Scan Command Builder */}
        <div className="pt-4 grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-6 space-y-1">
            <label className="text-[11px] font-mono font-bold uppercase text-zinc-400 block">
              URL do Servidor Web / Host de Destino (-h)
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={targetUrlInput}
                onChange={(e) => setTargetUrlInput(e.target.value)}
                placeholder="https://api.internal.finance.corp"
                className="w-full h-9 px-3 rounded bg-[#141414] border border-[#333] text-white font-mono text-xs focus:outline-none focus:border-[#FF7A00]"
              />
              <button
                type="button"
                onClick={() => setUseSsl(!useSsl)}
                className={`px-3 h-9 rounded font-mono text-xs font-bold uppercase border cursor-pointer ${
                  useSsl ? 'bg-[#FF7A00]/20 text-[#FF7A00] border-[#FF7A00]/50' : 'bg-zinc-800 text-zinc-400 border-zinc-700'
                }`}
              >
                {useSsl ? 'SSL/TLS' : 'HTTP'}
              </button>
            </div>
          </div>

          <div className="md:col-span-4 space-y-1">
            <label className="text-[11px] font-mono font-bold uppercase text-zinc-400 block">
              Host Cadastrado
            </label>
            <select
              value={selectedTargetId}
              onChange={(e) => {
                setSelectedTargetId(e.target.value);
                const found = targets.find(t => t.id === e.target.value);
                if (found) setTargetUrlInput(found.targetUrl);
              }}
              className="w-full h-9 px-2.5 rounded bg-[#141414] border border-[#333] text-white font-mono text-xs focus:outline-none focus:border-[#FF7A00]"
            >
              {targets.map(t => (
                <option key={t.id} value={t.id}>
                  {t.host} ({t.webServerBanner})
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-2 flex items-center gap-2">
            <button
              id="btn-execute-nikto-scan"
              onClick={handleExecuteScan}
              disabled={isScanning}
              className={`w-full h-9 rounded inline-flex items-center justify-center gap-1.5 font-mono text-xs font-bold uppercase tracking-wider transition-all cursor-pointer shadow-md ${
                isScanning 
                  ? 'bg-zinc-800 text-zinc-500 cursor-not-allowed border border-zinc-700' 
                  : 'bg-[#FF7A00] hover:bg-[#E56E00] text-black border border-[#FF7A00]'
              }`}
            >
              {isScanning ? (
                <>
                  <Activity className="w-3.5 h-3.5 animate-spin" />
                  <span>Auditando...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Escanear</span>
                </>
              )}
            </button>
            <button
              onClick={handleCopyCommand}
              title="Copiar comando Nikto CLI"
              className="h-9 w-9 rounded bg-[#181818] hover:bg-[#222] border border-[#333] text-zinc-400 hover:text-white flex items-center justify-center cursor-pointer shrink-0"
            >
              {copiedCommand ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>

        {/* Live Command Preview Pill */}
        <div className="mt-3 px-3 py-1.5 rounded bg-[#0F0F0F] border border-[#222] flex items-center justify-between font-mono text-[11px] text-zinc-400">
          <div className="flex items-center gap-2 overflow-x-auto truncate">
            <Terminal className="w-3.5 h-3.5 text-[#FF7A00] shrink-0" />
            <span className="text-zinc-500">$</span>
            <span className="text-white font-bold">{latestSession.cliCommand}</span>
          </div>
          <span className="text-[10px] text-zinc-500 hidden sm:inline shrink-0">
            Tuning: [{selectedTuning.join(',')}] // Banner: {selectedTarget?.webServerBanner}
          </span>
        </div>
      </div>

      {/* Navigation Sub-tabs */}
      <div className="flex items-center gap-2 border-b border-[#222] pb-1 overflow-x-auto no-scrollbar font-mono text-xs">
        <button
          onClick={() => setActiveSubTab('findings')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'findings'
              ? 'text-[#FF7A00] border-[#FF7A00] bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>Vulnerabilidades &amp; Arquivos ({selectedTarget?.findings.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('headers')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'headers'
              ? 'text-[#FF7A00] border-[#FF7A00] bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Lock className="w-3.5 h-3.5" />
          <span>Cabeçalhos de Segurança ({selectedTarget?.securityHeaders.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('methods')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'methods'
              ? 'text-[#FF7A00] border-[#FF7A00] bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Métodos HTTP ({selectedTarget?.httpMethods.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('tuning')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'tuning'
              ? 'text-[#FF7A00] border-[#FF7A00] bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Sliders className="w-3.5 h-3.5" />
          <span>Filtros de Tuning ({selectedTuning.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('terminal')}
          className={`px-3 py-2 rounded-t-lg font-bold uppercase transition-colors flex items-center gap-1.5 cursor-pointer border-b-2 ${
            activeSubTab === 'terminal'
              ? 'text-[#FF7A00] border-[#FF7A00] bg-[#0A0A0A]'
              : 'text-zinc-400 border-transparent hover:text-white'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>Log do Nikto</span>
        </button>
      </div>

      {/* SUBTAB 1: Findings & Dangerous Files */}
      {activeSubTab === 'findings' && selectedTarget && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0E0E0E] p-3 rounded-lg border border-[#222]">
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Filtrar por URI, OSVDB ou descrição..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full h-9 pl-9 pr-3 rounded bg-[#141414] border border-[#2A2A2A] text-white font-mono text-xs focus:outline-none focus:border-[#FF7A00]"
              />
            </div>

            <div className="flex items-center gap-1.5 font-mono text-xs overflow-x-auto">
              {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'INFO'] as const).map(sev => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2.5 py-1 rounded cursor-pointer transition-colors ${
                    severityFilter === sev 
                      ? 'bg-[#FF7A00] text-black font-bold' 
                      : 'bg-[#181818] text-zinc-400 hover:text-white'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            {filteredFindings.map((finding) => (
              <div
                key={finding.id}
                className="bg-[#0D0D0D] border border-[#222] hover:border-[#333] rounded-xl p-4.5 space-y-3 font-mono transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E1E1E] pb-2.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-zinc-800 text-zinc-300">
                      {finding.httpMethod}
                    </span>
                    <span className="text-sm font-bold text-white">
                      {finding.uri}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      finding.severity === 'CRITICAL' ? 'bg-rose-950/70 text-rose-300 border border-rose-800' :
                      finding.severity === 'HIGH' ? 'bg-amber-950/70 text-amber-300 border border-amber-800' :
                      finding.severity === 'MEDIUM' ? 'bg-orange-950/70 text-orange-300 border border-orange-800' :
                      'bg-blue-950/70 text-blue-300 border border-blue-800'
                    }`}>
                      {finding.severity}
                    </span>
                    {finding.osvdb && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-400">
                        OSVDB-{finding.osvdb}
                      </span>
                    )}
                  </div>

                  <span className="text-xs text-zinc-500">
                    cat: {finding.category} (tuning: {finding.tuningCode})
                  </span>
                </div>

                <p className="text-xs text-zinc-300 leading-relaxed">
                  {finding.description}
                </p>

                {finding.serverBannerSnippet && (
                  <div className="p-2.5 rounded bg-[#121212] border border-[#1E1E1E] text-xs text-zinc-400 font-mono">
                    <span className="text-zinc-500 text-[10px] uppercase block">Snippet de Resposta do Servidor:</span>
                    <code className="text-[#00FF41]">{finding.serverBannerSnippet}</code>
                  </div>
                )}

                <div className="pt-2 border-t border-[#1C1C1C] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                  <div className="text-zinc-400">
                    <strong className="text-[#FF7A00]">Recomendação: </strong>
                    {finding.recommendation}
                  </div>
                  {finding.referenceUrl && (
                    <a
                      href={finding.referenceUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyan-400 hover:underline flex items-center gap-1 shrink-0"
                    >
                      <span>Referência Externa</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>

                {finding.remediationSnippet && (
                  <div className="p-2.5 bg-[#080808] border border-zinc-800 rounded text-xs text-zinc-300">
                    <span className="text-[10px] text-zinc-500 uppercase block font-bold mb-1">Snippet de Configuração Sugerido:</span>
                    <pre className="text-[#00FF41] overflow-x-auto text-[11px]">{finding.remediationSnippet}</pre>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 2: Security Headers */}
      {activeSubTab === 'headers' && selectedTarget && (
        <div className="space-y-4">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
              <Lock className="w-4 h-4 text-[#FF7A00]" />
              <span>Auditoria de Cabeçalhos HTTP de Proteção</span>
            </h2>
            <p className="text-xs text-zinc-400">
              Validação de defesas contra ataques XSS, Clickjacking, MIME-sniffing e downgrade de conexão SSL/TLS.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {selectedTarget.securityHeaders.map((header) => (
              <div
                key={header.headerName}
                className="bg-[#0D0D0D] border border-[#222] rounded-xl p-4.5 space-y-3 font-mono text-xs"
              >
                <div className="flex items-center justify-between border-b border-[#1E1E1E] pb-2">
                  <span className="font-bold text-white text-sm">
                    {header.headerName}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    header.status === 'VALID' ? 'bg-[#00FF41]/15 text-[#00FF41] border border-[#00FF41]/30' :
                    header.status === 'WEAK' ? 'bg-amber-950/70 text-amber-300 border border-amber-800' :
                    'bg-rose-950/70 text-rose-300 border border-rose-800'
                  }`}>
                    {header.status}
                  </span>
                </div>

                <div className="space-y-1.5 text-zinc-300">
                  <div>
                    <span className="text-[10px] text-zinc-500 uppercase block">Valor Detectado</span>
                    <span className={header.actualValue ? 'text-white' : 'text-zinc-600 italic'}>
                      {header.actualValue || 'Cabeçalho não retornado'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] text-zinc-500 uppercase block">Valor Recomendado</span>
                    <span className="text-[#00FF41] font-semibold">{header.expectedValue}</span>
                  </div>
                  <p className="text-zinc-400 text-[11px] leading-relaxed pt-1">
                    {header.riskDescription}
                  </p>
                </div>

                {header.remediationSnippet && (
                  <div className="p-2 bg-[#080808] border border-zinc-800 rounded">
                    <span className="text-[9.5px] text-zinc-500 uppercase block mb-0.5">Nginx / Reverse Proxy Config:</span>
                    <code className="text-[#FF7A00] text-[10.5px] block break-all">{header.remediationSnippet}</code>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 3: HTTP Methods */}
      {activeSubTab === 'methods' && selectedTarget && (
        <div className="space-y-4">
          <div className="border border-[#222] rounded-xl overflow-hidden font-mono text-xs">
            <table className="w-full text-left">
              <thead className="bg-[#141414] text-zinc-400 text-[10px] uppercase border-b border-[#222]">
                <tr>
                  <th className="py-3 px-4">Método HTTP</th>
                  <th className="py-3 px-4">Status de Permissão</th>
                  <th className="py-3 px-4">Código HTTP</th>
                  <th className="py-3 px-4">Nível de Risco / Análise</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1A1A1A]">
                {selectedTarget.httpMethods.map((m) => (
                  <tr key={m.method} className="hover:bg-[#121212]">
                    <td className="py-3 px-4 font-bold text-white text-sm">
                      {m.method}
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        m.allowed 
                          ? m.isDangerous ? 'bg-rose-950/70 text-rose-300 border border-rose-800' : 'bg-[#00FF41]/15 text-[#00FF41] border border-[#00FF41]/30'
                          : 'bg-zinc-800 text-zinc-400'
                      }`}>
                        {m.allowed ? (m.isDangerous ? 'HABILITADO (PERIGOSO)' : 'HABILITADO') : 'BLOQUEADO'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-zinc-300 font-bold">
                      {m.statusResponse}
                    </td>
                    <td className="py-3 px-4 text-zinc-300">
                      {m.riskNote ? (
                        <span className="text-rose-400 font-bold">{m.riskNote}</span>
                      ) : (
                        <span className="text-zinc-500">Método comum de operação padrão.</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SUBTAB 4: Nikto Tuning Configuration */}
      {activeSubTab === 'tuning' && (
        <div className="space-y-4">
          <div className="bg-[#0E0E0E] p-4 rounded-xl border border-[#222] space-y-1">
            <h2 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-[#FF7A00]" />
              <span>Dicionário de Categorias de Tuning (-Tuning)</span>
            </h2>
            <p className="text-xs text-zinc-400">
              O Nikto permite ligar e desligar tipos específicos de testes. Selecione as categorias para refinar o escopo da varredura.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {NIKTO_TUNING_DICTIONARY.map((item) => {
              const isActive = selectedTuning.includes(item.code);
              return (
                <div
                  key={item.code}
                  onClick={() => handleToggleTuning(item.code)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer font-mono flex items-start gap-3 ${
                    isActive 
                      ? 'bg-[#141414] border-[#FF7A00]/60 shadow-[0_0_15px_rgba(255,122,0,0.1)]' 
                      : 'bg-[#0E0E0E] border-[#222] opacity-60 hover:opacity-100'
                  }`}
                >
                  <div className={`mt-0.5 w-5 h-5 rounded flex items-center justify-center text-xs font-bold shrink-0 ${
                    isActive ? 'bg-[#FF7A00] text-black' : 'bg-zinc-800 text-zinc-400'
                  }`}>
                    {item.code}
                  </div>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-white">
                        {item.label}
                      </span>
                      <span className="text-[10px] text-zinc-500">
                        ({item.code})
                      </span>
                    </div>
                    <p className="text-[11px] text-zinc-400 leading-snug">
                      {item.desc}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* SUBTAB 5: Console Output */}
      {activeSubTab === 'terminal' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between font-mono text-xs">
            <div className="flex items-center gap-2 text-zinc-400">
              <Terminal className="w-4 h-4 text-[#FF7A00]" />
              <span>Sessão: {latestSession.sessionId}</span>
              <span>• Duração: {latestSession.durationSeconds}s</span>
            </div>
            <button
              id="btn-copy-nikto-terminal-output"
              onClick={handleCopyTerminal}
              className="px-3 py-1.5 rounded bg-[#181818] hover:bg-[#222] border border-[#333] text-zinc-300 hover:text-white font-mono text-xs flex items-center gap-1.5 cursor-pointer"
            >
              {copiedTerminal ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedTerminal ? 'Copiado' : 'Copiar Saída'}</span>
            </button>
          </div>

          <div className="p-4 rounded-xl bg-[#050505] border border-[#222] font-mono text-xs text-[#FF7A00] overflow-x-auto whitespace-pre leading-relaxed shadow-inner max-h-[500px]">
            {latestSession.rawConsoleOutput}
          </div>
        </div>
      )}
    </div>
  );
};
