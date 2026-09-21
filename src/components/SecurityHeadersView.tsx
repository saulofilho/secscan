import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Globe,
  Sliders,
  Copy,
  Check,
  RotateCcw,
  Sparkles,
  ExternalLink,
  Lock,
  Server,
  Layers,
  CheckCircle2,
  XCircle,
  FileCode2,
  Terminal,
  Info
} from 'lucide-react';
import {
  evaluateSecurityHeaders,
  STANDARD_SECURITY_HEADER_RULES
} from '../lib/securityHeadersEngine';
import { SecurityHeadersAuditReport } from '../types/securityTools';

interface SecurityHeadersViewProps {
  onNavigateToScanner?: () => void;
  onNavigateToEndpoints?: () => void;
}

const PRESET_SAMPLE_HEADERS: { name: string; description: string; headers: Record<string, string> }[] = [
  {
    name: 'Servidor Desprotegido (Padrão Vulnerável - Nota F)',
    description: 'Nenhum cabeçalho de segurança configurado. Suscetível a XSS, Clickjacking e MIME sniffing.',
    headers: {
      'Server': 'nginx/1.18.0',
      'Content-Type': 'text/html; charset=UTF-8',
      'Connection': 'keep-alive'
    }
  },
  {
    name: 'Configuração Parcial (Comum em Startups - Nota C)',
    description: 'Possui HSTS e X-Frame-Options, mas sem CSP ou Permissions-Policy.',
    headers: {
      'Strict-Transport-Security': 'max-age=31536000',
      'X-Frame-Options': 'SAMEORIGIN',
      'X-Content-Type-Options': 'nosniff',
      'Server': 'cloudflare'
    }
  },
  {
    name: 'Hardened Enterprise (OWASP A+ Grade)',
    description: 'Todos os cabeçalhos modernos configurados com CSP estrito, HSTS com preload e isolamento de origem.',
    headers: {
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; frame-ancestors 'none';",
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin'
    }
  }
];

export const SecurityHeadersView: React.FC<SecurityHeadersViewProps> = ({
  onNavigateToScanner,
  onNavigateToEndpoints
}) => {
  const [selectedPreset, setSelectedPreset] = useState<number>(1);
  const [targetUrl, setTargetUrl] = useState<string>('https://app.corp.finance');
  const [customHeadersText, setCustomHeadersText] = useState<string>(() => {
    return Object.entries(PRESET_SAMPLE_HEADERS[1].headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');
  });
  const [serverTab, setServerTab] = useState<'nginx' | 'apache' | 'express' | 'next' | 'caddy'>('nginx');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Parse headers from custom textarea
  const headersMap = useMemo(() => {
    const map: Record<string, string> = {};
    customHeadersText.split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx > 0) {
        const k = line.slice(0, idx).trim();
        const v = line.slice(idx + 1).trim();
        if (k) map[k] = v;
      }
    });
    return map;
  }, [customHeadersText]);

  const auditReport: SecurityHeadersAuditReport = useMemo(() => {
    return evaluateSecurityHeaders(headersMap, targetUrl);
  }, [headersMap, targetUrl]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleLoadPreset = (index: number) => {
    setSelectedPreset(index);
    const p = PRESET_SAMPLE_HEADERS[index];
    setCustomHeadersText(
      Object.entries(p.headers).map(([k, v]) => `${k}: ${v}`).join('\n')
    );
  };

  const gradeColor = 
    auditReport.grade === 'A+' || auditReport.grade === 'A' ? 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10' :
    auditReport.grade === 'B' ? 'text-cyan-400 border-cyan-500/40 bg-cyan-500/10' :
    auditReport.grade === 'C' ? 'text-amber-400 border-amber-500/40 bg-amber-500/10' :
    'text-rose-400 border-rose-500/40 bg-rose-500/10';

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-[#0F0F0F] border border-[#222]">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/10 border border-cyan-500/30 flex items-center justify-center shrink-0 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
            <Lock className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-xl font-black text-white uppercase tracking-tight">
                Security Headers &amp; CSP Studio
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 uppercase">
                HTTP Hardening
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#1A1A1A] text-zinc-400 border border-zinc-700">
                OWASP Secure Headers
              </span>
            </div>
            <p className="text-sm text-zinc-400 mt-1">
              Avalie e gere cabeçalhos de segurança HTTP modernos: Content-Security-Policy (CSP), HSTS, X-Frame-Options e políticas de isolamento de origem.
            </p>
          </div>
        </div>

        {/* Grade Badge */}
        <div className="flex items-center gap-4 shrink-0 self-end md:self-auto">
          <div className="text-right">
            <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider block">Nota de Segurança</span>
            <span className="text-xs font-mono text-zinc-400">Score: {auditReport.totalScore}/100</span>
          </div>
          <div className={`w-16 h-16 rounded-xl border-2 flex items-center justify-center font-black text-2xl font-mono shadow-lg ${gradeColor}`}>
            {auditReport.grade}
          </div>
        </div>
      </div>

      {/* Preset Selector */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {PRESET_SAMPLE_HEADERS.map((p, idx) => (
          <button
            key={p.name}
            onClick={() => handleLoadPreset(idx)}
            className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer ${
              selectedPreset === idx
                ? 'bg-cyan-950/20 border-cyan-500/50 shadow-sm ring-1 ring-cyan-500/30'
                : 'bg-[#0F0F0F] border-[#222] hover:border-[#333] hover:bg-[#141414]'
            }`}
          >
            <div className="flex items-center justify-between gap-2 mb-1">
              <span className="text-xs font-bold text-white">{p.name}</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-black/40 text-zinc-400 border border-zinc-800">
                Preset {idx + 1}
              </span>
            </div>
            <p className="text-[11px] text-zinc-400 line-clamp-2">{p.description}</p>
          </button>
        ))}
      </div>

      {/* Main Grid: Headers Inspector & Live Editor */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Headers Evaluation Table (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <span>Auditoria de Cabeçalhos ({auditReport.headersEvaluated.length})</span>
            </h2>
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-rose-400 font-bold">{auditReport.criticalMissing.length} ausente(s)</span>
              <span className="text-zinc-600">•</span>
              <span className="text-emerald-400 font-bold">
                {auditReport.headersEvaluated.filter(h => h.isCompliant).length} em conformidade
              </span>
            </div>
          </div>

          <div className="space-y-3">
            {auditReport.headersEvaluated.map(item => {
              const statusColor = 
                item.status === 'OPTIMAL' ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30' :
                item.status === 'ACCEPTABLE' ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30' :
                item.status === 'WEAK' ? 'bg-amber-500/10 text-amber-300 border-amber-500/30' :
                'bg-rose-500/10 text-rose-300 border-rose-500/30';

              return (
                <div
                  key={item.headerName}
                  className="p-4 rounded-lg bg-[#0F0F0F] border border-[#222] hover:border-[#333] transition-colors"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-sm font-bold text-white">{item.headerName}</span>
                        <span className={`px-2 py-0.2 rounded text-[9.5px] font-mono font-bold border uppercase ${statusColor}`}>
                          {item.status}
                        </span>
                        <span className="text-[9.5px] font-mono px-1.5 py-0.2 rounded bg-black/40 text-zinc-400 border border-zinc-800">
                          {item.rule.cwe}
                        </span>
                      </div>
                      <p className="text-xs text-zinc-400">{item.rule.description}</p>
                    </div>

                    <button
                      onClick={() => handleCopy(item.remediationSnippet, item.headerName)}
                      className="p-1.5 rounded bg-[#181818] hover:bg-[#222] text-zinc-400 hover:text-white border border-[#333] transition-colors cursor-pointer shrink-0"
                      title="Copiar configuração recomendada"
                    >
                      {copiedKey === item.headerName ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>

                  {/* Value display */}
                  <div className="mt-3 p-2.5 rounded bg-black/50 border border-zinc-800 font-mono text-[11px] break-all">
                    {item.isPresent ? (
                      <span className="text-zinc-300">{item.configuredValue}</span>
                    ) : (
                      <span className="text-rose-400 italic">Não enviado na resposta do servidor</span>
                    )}
                  </div>

                  {/* Issues or Recommendation */}
                  {item.issues.length > 0 ? (
                    <div className="mt-2 space-y-1">
                      {item.issues.map((iss, i) => (
                        <div key={i} className="flex items-center gap-1.5 text-[11px] text-amber-300">
                          <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />
                          <span>{iss}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="mt-2 flex items-center gap-1.5 text-[11px] text-emerald-400">
                      <CheckCircle2 className="w-3 h-3 shrink-0" />
                      <span>Configuração adequada conforme as recomendações OWASP.</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Custom Raw Headers & Server Exporter (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          {/* Raw Header Input */}
          <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-300 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span>Headers HTTP Atuais (Editor Direto)</span>
              </h3>
              <span className="text-[10px] font-mono text-zinc-500">Chave: Valor</span>
            </div>

            <textarea
              value={customHeadersText}
              onChange={(e) => setCustomHeadersText(e.target.value)}
              rows={8}
              className="w-full p-3 rounded-lg bg-black/70 border border-zinc-800 text-zinc-200 font-mono text-xs focus:outline-none focus:border-cyan-500/60 transition-colors"
              placeholder="Exemplo:&#10;Strict-Transport-Security: max-age=31536000&#10;X-Frame-Options: DENY"
            />

            <div className="flex items-center justify-between text-[11px] text-zinc-400">
              <span>Edite acima para testar seus cabeçalhos em tempo real.</span>
              <button
                onClick={() => handleLoadPreset(2)}
                className="text-cyan-400 hover:text-cyan-300 font-bold underline cursor-pointer"
              >
                Aplicar A+ Recomendado
              </button>
            </div>
          </div>

          {/* Hardened Server Config Exporter */}
          <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-emerald-400" />
                <span>Gerador de Configuração de Servidor</span>
              </h3>
              <button
                onClick={() => {
                  const code = 
                    serverTab === 'nginx' ? auditReport.serverConfigSnippets.nginx :
                    serverTab === 'apache' ? auditReport.serverConfigSnippets.apache :
                    serverTab === 'express' ? auditReport.serverConfigSnippets.expressHelmet :
                    serverTab === 'next' ? auditReport.serverConfigSnippets.nextConfig :
                    auditReport.serverConfigSnippets.caddy;
                  handleCopy(code, 'server-export');
                }}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#1C1C1C] hover:bg-[#252525] text-xs font-mono text-zinc-200 border border-[#333] transition-colors cursor-pointer"
              >
                {copiedKey === 'server-export' ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400 font-bold">Copiado!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copiar Snippet</span>
                  </>
                )}
              </button>
            </div>

            {/* Server Tabs */}
            <div className="flex items-center gap-1 border-b border-[#222] pb-2 overflow-x-auto no-scrollbar">
              {(['nginx', 'apache', 'express', 'next', 'caddy'] as const).map(tab => (
                <button
                  key={tab}
                  onClick={() => setServerTab(tab)}
                  className={`px-2.5 py-1 rounded text-xs font-mono font-bold uppercase transition-colors cursor-pointer ${
                    serverTab === tab
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  {tab === 'express' ? 'Express Helmet' : tab === 'next' ? 'Next.js' : tab.toUpperCase()}
                </button>
              ))}
            </div>

            {/* Code Output Box */}
            <pre className="p-3 rounded-lg bg-black/80 border border-zinc-800 font-mono text-[11px] text-zinc-300 overflow-x-auto max-h-64 leading-relaxed">
              {serverTab === 'nginx' && auditReport.serverConfigSnippets.nginx}
              {serverTab === 'apache' && auditReport.serverConfigSnippets.apache}
              {serverTab === 'express' && auditReport.serverConfigSnippets.expressHelmet}
              {serverTab === 'next' && auditReport.serverConfigSnippets.nextConfig}
              {serverTab === 'caddy' && auditReport.serverConfigSnippets.caddy}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
