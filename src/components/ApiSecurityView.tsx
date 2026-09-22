import React, { useState, useMemo } from 'react';
import {
  Route,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Layers,
  Search,
  Filter,
  Copy,
  Check,
  Terminal,
  FileCode,
  Zap,
  Globe,
  ArrowRight,
  ExternalLink,
  ShieldCheck,
  SlidersHorizontal,
  ChevronDown,
  ChevronUp,
  KeyRound,
  Ban
} from 'lucide-react';
import { ScannedFile } from '../types';
import { auditApiSecurity, OWASP_API_DEFINITIONS } from '../lib/apiSecurityScanner';

interface ApiSecurityViewProps {
  files: ScannedFile[];
  onNavigateToFile?: (filePath: string, line?: number) => void;
}

export const ApiSecurityView: React.FC<ApiSecurityViewProps> = ({ files, onNavigateToFile }) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const report = useMemo(() => {
    return auditApiSecurity(files);
  }, [files]);

  const filteredFindings = useMemo(() => {
    return report.findings.filter(f => {
      if (selectedCategory !== 'ALL' && f.category !== selectedCategory) return false;
      if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesEndpoint = f.endpoint.toLowerCase().includes(q);
        const matchesTitle = f.vulnerabilityTitle.toLowerCase().includes(q);
        const matchesDesc = f.description.toLowerCase().includes(q);
        if (!matchesEndpoint && !matchesTitle && !matchesDesc) return false;
      }
      return true;
    });
  }, [report.findings, selectedCategory, selectedSeverity, searchQuery]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 font-mono text-zinc-200">
      {/* Top Hero Banner */}
      <div className="bg-[#05090D] border border-cyan-500/30 rounded-xl p-5 sm:p-6 shadow-[0_0_25px_rgba(6,182,212,0.08)] relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/40 flex items-center gap-1.5">
                <Route className="w-5 h-5 text-cyan-400" />
                <Lock className="w-4 h-4 text-cyan-300" />
              </div>
              <h1 className="text-xl sm:text-2xl font-black tracking-tight text-white uppercase">
                API Security &amp; BOLA/IDOR Inspector
              </h1>
              <span className="px-2.5 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-700/60 text-xs font-bold">
                OWASP API Security Top 10 (2023)
              </span>
            </div>
            <p className="text-xs sm:text-sm text-zinc-400 max-w-3xl leading-relaxed">
              Auditoria especializada para contratos REST e GraphQL. Detecção automatizada de BOLA/IDOR (Broken Object Level Authorization), Mass Assignment em schemas de banco de dados, BFLA em rotas administrativas e ausência de Rate Limiting.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <div className="px-5 py-3 rounded-xl bg-black/60 border border-cyan-900/50 flex items-center gap-4">
              <div>
                <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">API Posture Score</span>
                <span className={`text-2xl font-black ${
                  report.apiRiskScore >= 80 ? 'text-emerald-400' : report.apiRiskScore >= 50 ? 'text-amber-400' : 'text-rose-400'
                }`}>
                  {report.apiRiskScore}/100
                </span>
              </div>
              <div className="w-12 h-12 rounded-full border-2 flex items-center justify-center font-bold text-sm"
                   style={{
                     borderColor: report.apiRiskScore >= 80 ? '#34d399' : report.apiRiskScore >= 50 ? '#fbbf24' : '#f43f5e',
                     color: report.apiRiskScore >= 80 ? '#34d399' : report.apiRiskScore >= 50 ? '#fbbf24' : '#f43f5e'
                   }}>
                {report.apiRiskScore}%
              </div>
            </div>
          </div>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5 pt-5 border-t border-zinc-800/80">
          <div className="bg-black/40 border border-zinc-800 rounded-lg p-3">
            <div className="text-[10px] text-zinc-400 uppercase tracking-wider">Rotas Analisadas</div>
            <div className="text-xl font-bold text-white mt-0.5">{report.totalEndpointsAudited}</div>
            <div className="text-[10px] text-zinc-500 mt-0.5">Express / Controllers</div>
          </div>

          <div className="bg-black/40 border border-rose-900/40 rounded-lg p-3">
            <div className="text-[10px] text-rose-400 uppercase tracking-wider">Falhas Críticas (P0)</div>
            <div className="text-xl font-bold text-rose-400 mt-0.5">{report.summaryBySeverity.CRITICAL}</div>
            <div className="text-[10px] text-rose-500/80 mt-0.5">BOLA / BFLA Exploits</div>
          </div>

          <div className="bg-black/40 border border-amber-900/40 rounded-lg p-3">
            <div className="text-[10px] text-amber-400 uppercase tracking-wider">Falhas Altas (P1)</div>
            <div className="text-xl font-bold text-amber-300 mt-0.5">{report.summaryBySeverity.HIGH}</div>
            <div className="text-[10px] text-amber-500 mt-0.5">Mass Assignment / Rate Limit</div>
          </div>

          <div className="bg-black/40 border border-cyan-900/40 rounded-lg p-3">
            <div className="text-[10px] text-cyan-400 uppercase tracking-wider">Categorias OWASP</div>
            <div className="text-xl font-bold text-cyan-300 mt-0.5">{Object.keys(report.summaryByCategory).length}</div>
            <div className="text-[10px] text-cyan-500 mt-0.5">Vetores Mapeados</div>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3.5 bg-[#080E09] border border-zinc-800 rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 flex-1 min-w-[260px]">
          <Search className="w-4 h-4 text-zinc-400 shrink-0" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Buscar por endpoint (ex: /users/:id), BOLA, Mass Assignment..."
            className="w-full bg-black/50 border border-zinc-800 rounded-lg px-3 py-1.5 text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-400"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Category Filter */}
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-black/50 border border-zinc-800 rounded-lg px-3 py-1.5 text-zinc-300 focus:outline-none focus:border-cyan-400"
          >
            <option value="ALL">Todas as Categorias OWASP</option>
            {Object.entries(OWASP_API_DEFINITIONS).map(([key, def]) => (
              <option key={key} value={key}>{key.split('_')[0]}: {def.title.slice(0, 30)}...</option>
            ))}
          </select>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-black/50 border border-zinc-800 rounded-lg px-3 py-1.5 text-zinc-300 focus:outline-none focus:border-cyan-400"
          >
            <option value="ALL">Todas as Severidades</option>
            <option value="CRITICAL">P0 - Crítica</option>
            <option value="HIGH">P1 - Alta</option>
            <option value="MEDIUM">P2 - Média</option>
          </select>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-4">
        {filteredFindings.length === 0 ? (
          <div className="p-12 text-center bg-[#070D08] border border-zinc-800 rounded-xl space-y-3">
            <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
            <p className="font-bold text-white text-base">Nenhuma vulnerabilidade de API encontrada nos filtros selecionados.</p>
            <p className="text-xs text-zinc-400 max-w-md mx-auto">
              Seus endpoints cumprem as diretrizes do OWASP API Security Top 10 para BOLA, autenticação e controle de taxa.
            </p>
          </div>
        ) : (
          filteredFindings.map(finding => {
            const isExpanded = expandedId === finding.id;

            return (
              <div
                key={finding.id}
                className="bg-[#080E09] border border-zinc-800 hover:border-zinc-700 rounded-xl overflow-hidden transition-all"
              >
                {/* Finding Header */}
                <div className="p-4 sm:p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  <div className="space-y-2 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        finding.severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : 'bg-amber-950 text-amber-300 border border-amber-800'
                      }`}>
                        {finding.severity}
                      </span>

                      <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[10px] font-bold">
                        {finding.category}
                      </span>

                      <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 text-[10px]">
                        {finding.cwe}
                      </span>

                      <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-400 text-[10px]">
                        {finding.method} {finding.endpoint}
                      </span>
                    </div>

                    <h3 className="font-bold text-base text-white">
                      {finding.vulnerabilityTitle}
                    </h3>

                    <p className="text-xs text-zinc-400 leading-relaxed max-w-4xl">
                      {finding.description}
                    </p>

                    {finding.file && (
                      <div className="flex items-center gap-3 pt-1 text-xs text-zinc-500">
                        <button
                          type="button"
                          onClick={() => onNavigateToFile && onNavigateToFile(finding.file!, finding.line)}
                          className="inline-flex items-center gap-1.5 text-zinc-400 hover:text-cyan-400 cursor-pointer transition-colors"
                        >
                          <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                          <span className="font-semibold underline underline-offset-2">{finding.file}:{finding.line}</span>
                        </button>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-2 shrink-0 self-start lg:self-center">
                    <button
                      type="button"
                      onClick={() => setExpandedId(isExpanded ? null : finding.id)}
                      className="px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700 text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
                    >
                      <span>{isExpanded ? 'Recolher' : 'Ver PoC & Código'}</span>
                      {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                {/* Expanded PoC Exploit & Remediation */}
                {isExpanded && (
                  <div className="p-4 sm:p-5 bg-black/60 border-t border-zinc-800/80 space-y-4 text-xs">
                    {/* PoC Exploit cURL */}
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-zinc-400">
                        <span className="font-bold text-rose-400 flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5" />
                          <span>Prova de Conceito (PoC Exploit cURL):</span>
                        </span>
                        <button
                          type="button"
                          onClick={() => handleCopy(finding.sampleExploitCurl, `curl-${finding.id}`)}
                          className="px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-[11px] flex items-center gap-1 cursor-pointer"
                        >
                          {copiedId === `curl-${finding.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedId === `curl-${finding.id}` ? 'Copiado!' : 'Copiar cURL'}</span>
                        </button>
                      </div>
                      <pre className="p-3 bg-black rounded-lg text-rose-300 border border-rose-950/60 overflow-x-auto font-mono text-[11px]">
                        <code>{finding.sampleExploitCurl}</code>
                      </pre>
                    </div>

                    {/* Secured Code Snippet */}
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-zinc-400">
                        <span className="font-bold text-emerald-400 flex items-center gap-1.5">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          <span>Padrão de Código Seguro Recomendado (Remediação):</span>
                        </span>
                        <button
                          type="button"
                          onClick={() => handleCopy(finding.securedCodeSnippet, `code-${finding.id}`)}
                          className="px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-[11px] flex items-center gap-1 cursor-pointer"
                        >
                          {copiedId === `code-${finding.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedId === `code-${finding.id}` ? 'Copiado!' : 'Copiar Código'}</span>
                        </button>
                      </div>
                      <pre className="p-3 bg-black rounded-lg text-emerald-300 border border-emerald-950/60 overflow-x-auto font-mono text-[11px]">
                        <code>{finding.securedCodeSnippet}</code>
                      </pre>
                    </div>

                    {/* Remediation Guide */}
                    <div className="p-3 bg-zinc-900/60 border border-zinc-800 rounded-lg">
                      <span className="font-bold text-zinc-300 block mb-1">Guia de Engenharia:</span>
                      <p className="text-zinc-400 leading-relaxed">{finding.remediation}</p>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
