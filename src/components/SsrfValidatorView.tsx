import React, { useState, useMemo } from 'react';
import {
  Globe,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  Copy,
  Check,
  RotateCcw,
  Sparkles,
  Terminal,
  Server,
  Layers,
  FileCode2,
  CheckCircle2,
  XCircle,
  Network,
  Lock,
  ExternalLink,
  Info
} from 'lucide-react';
import {
  validateSsrfTarget,
  SAMPLE_SSRF_PAYLOADS,
  generateSafeClientSnippet
} from '../lib/ssrfValidatorEngine';
import { SsrfCheckResult } from '../types/securityTools';

interface SsrfValidatorViewProps {
  onNavigateToScanner?: () => void;
  onNavigateToEndpoints?: () => void;
}

export const SsrfValidatorView: React.FC<SsrfValidatorViewProps> = ({
  onNavigateToScanner,
  onNavigateToEndpoints
}) => {
  const [selectedSampleIndex, setSelectedSampleIndex] = useState<number>(0);
  const [targetUrlInput, setTargetUrlInput] = useState<string>(() => SAMPLE_SSRF_PAYLOADS[0].url);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const result: SsrfCheckResult = useMemo(() => {
    return validateSsrfTarget(targetUrlInput);
  }, [targetUrlInput]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleLoadSample = (index: number) => {
    setSelectedSampleIndex(index);
    setTargetUrlInput(SAMPLE_SSRF_PAYLOADS[index].url);
  };

  const riskBadgeColor =
    result.riskLevel === 'SAFE' ? 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10' :
    result.riskLevel === 'BLOCKED_PRIVATE' ? 'text-amber-400 border-amber-500/40 bg-amber-500/10' :
    'text-rose-400 border-rose-500/40 bg-rose-500/10';

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-[#0F0F0F] border border-[#222]">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-500/20 to-teal-500/10 border border-emerald-500/30 flex items-center justify-center shrink-0 shadow-[0_0_15px_rgba(16,185,129,0.15)]">
            <Globe className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-xl font-black text-white uppercase tracking-tight">
                SSRF &amp; Webhook Safety Validator
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 uppercase">
                API Security
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#1A1A1A] text-zinc-400 border border-zinc-700">
                OWASP Top 10 A10:2021
              </span>
            </div>
            <p className="text-sm text-zinc-400 mt-1">
              Validador de requisições de saída HTTP e webhooks para prevenção de Server-Side Request Forgery (SSRF): proteção de metadados de nuvem (169.254.169.254), faixas privadas RFC 1918 e evasões por IP decimal/hexadecimal.
            </p>
          </div>
        </div>

        {/* Risk Status Indicator */}
        <div className="flex items-center gap-4 shrink-0 self-end md:self-auto">
          <div className="text-right">
            <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider block">Status do Destino</span>
            <span className="text-xs font-mono font-bold text-zinc-300">
              {result.riskLevel}
            </span>
          </div>
          <div className={`px-3 py-2 rounded-xl border-2 flex items-center justify-center font-black text-sm font-mono shadow-lg uppercase ${riskBadgeColor}`}>
            {result.riskLevel === 'SAFE' ? 'DESTINO SEGURO' : 'BLOQUEIO SSRF'}
          </div>
        </div>
      </div>

      {/* Preset Payloads Selector */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        {SAMPLE_SSRF_PAYLOADS.map((sample, idx) => (
          <button
            key={sample.name}
            onClick={() => handleLoadSample(idx)}
            className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer ${
              selectedSampleIndex === idx
                ? 'bg-emerald-950/20 border-emerald-500/50 shadow-sm ring-1 ring-emerald-500/30'
                : 'bg-[#0F0F0F] border-[#222] hover:border-[#333] hover:bg-[#141414]'
            }`}
          >
            <div className="flex items-center justify-between gap-2 mb-1">
              <span className="text-xs font-bold text-white line-clamp-1">{sample.name}</span>
            </div>
            <p className="text-[11px] text-zinc-400 line-clamp-2">{sample.description}</p>
          </button>
        ))}
      </div>

      {/* Target URL Input Bar */}
      <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white flex items-center gap-1.5">
            <Globe className="w-3.5 h-3.5 text-emerald-400" />
            <span>URL de Destino / Webhook a ser Testada</span>
          </h3>
          <span className="text-[10px] font-mono text-zinc-500">Validação em Tempo Real</span>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="text"
            value={targetUrlInput}
            onChange={(e) => setTargetUrlInput(e.target.value)}
            className="flex-1 p-3 rounded-lg bg-black/70 border border-zinc-800 text-zinc-200 font-mono text-xs focus:outline-none focus:border-emerald-500/60 transition-colors"
            placeholder="Insira a URL (ex: http://169.254.169.254/latest/meta-data/)"
          />
          <button
            onClick={() => handleCopy(targetUrlInput, 'input-url')}
            className="p-3 rounded-lg bg-[#181818] hover:bg-[#222] text-zinc-400 hover:text-white border border-[#333] transition-colors cursor-pointer shrink-0"
            title="Copiar URL"
          >
            {copiedKey === 'input-url' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Main Grid: Diagnostic & Safe Client Code */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Diagnostics (6 cols) */}
        <div className="lg:col-span-6 space-y-4">
          <div className="p-5 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-4">
            <div className="flex items-center justify-between border-b border-[#222] pb-3">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                Diagnóstico de Triagem SSRF
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border uppercase ${riskBadgeColor}`}>
                {result.classification}
              </span>
            </div>

            {/* Network properties */}
            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded bg-black/50 border border-zinc-900 space-y-1">
                <span className="text-[10px] text-zinc-500 uppercase block">Esquema</span>
                <span className="font-bold text-white">{result.scheme.toUpperCase()}</span>
              </div>
              <div className="p-2.5 rounded bg-black/50 border border-zinc-900 space-y-1">
                <span className="text-[10px] text-zinc-500 uppercase block">Hostname / IP</span>
                <span className="font-bold text-white truncate block">{result.hostname}</span>
              </div>
              <div className="p-2.5 rounded bg-black/50 border border-zinc-900 space-y-1">
                <span className="text-[10px] text-zinc-500 uppercase block">Porta</span>
                <span className="font-bold text-white">{result.port}</span>
              </div>
              <div className="p-2.5 rounded bg-black/50 border border-zinc-900 space-y-1">
                <span className="text-[10px] text-zinc-500 uppercase block">Metadados de Nuvem</span>
                <span className={`font-bold ${result.isCloudMetadata ? 'text-rose-400' : 'text-zinc-400'}`}>
                  {result.isCloudMetadata ? 'SIM (IMDSv1)' : 'NÃO'}
                </span>
              </div>
            </div>

            {/* Technique Details */}
            <div className="space-y-2 text-xs">
              <div className="p-3 rounded bg-black/60 border border-zinc-800 space-y-1">
                <span className="text-[10px] font-mono font-bold text-zinc-500 uppercase block">Técnica de Ataque Mapeada:</span>
                <span className="text-rose-300 font-mono font-bold">{result.attackTechnique}</span>
              </div>

              <div className="flex items-start gap-2 text-xs text-emerald-400 bg-emerald-500/5 p-3 rounded border border-emerald-500/20">
                <Sparkles className="w-4 h-4 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <span className="font-bold block uppercase text-[10px]">Recomendação de Defesa:</span>
                  <span className="text-zinc-300">{result.remediationAdvice}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Hardened Outbound Client (6 cols) */}
        <div className="lg:col-span-6 space-y-4">
          <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Cliente HTTP Blindado contra SSRF (Node.js/Axios)</span>
              </h3>
              <button
                onClick={() => handleCopy(result.safeClientExample, 'safe-client')}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#1C1C1C] hover:bg-[#252525] text-xs font-mono text-zinc-200 border border-[#333] transition-colors cursor-pointer"
              >
                {copiedKey === 'safe-client' ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400 font-bold">Copiado!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copiar Código</span>
                  </>
                )}
              </button>
            </div>

            <p className="text-xs text-zinc-400">
              Implementação de referência com pré-resolução DNS, bloqueio determinístico de faixas privadas RFC 1918 e desativação de redirects:
            </p>

            <pre className="p-3 rounded-lg bg-black/80 border border-zinc-800 font-mono text-[11px] text-zinc-300 overflow-x-auto max-h-80 leading-relaxed">
              {result.safeClientExample}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
