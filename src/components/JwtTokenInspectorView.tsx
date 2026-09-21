import React, { useState, useMemo } from 'react';
import {
  KeyRound,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Copy,
  Check,
  RotateCcw,
  Sparkles,
  Terminal,
  FileCode2,
  CheckCircle2,
  XCircle,
  Clock,
  Lock,
  Unlock,
  Eye,
  Info
} from 'lucide-react';
import {
  auditJwtToken,
  SAMPLE_TOKENS,
  generateAlgNoneExploitToken
} from '../lib/jwtInspectorEngine';
import { JwtAuditReport } from '../types/securityTools';

interface JwtTokenInspectorViewProps {
  onNavigateToScanner?: () => void;
}

export const JwtTokenInspectorView: React.FC<JwtTokenInspectorViewProps> = ({
  onNavigateToScanner
}) => {
  const [selectedSampleIndex, setSelectedSampleIndex] = useState<number>(0);
  const [tokenInput, setTokenInput] = useState<string>(() => SAMPLE_TOKENS[0].token);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Tamper state
  const [tamperRole, setTamperRole] = useState<string>('superadmin');
  const [generatedExploitToken, setGeneratedExploitToken] = useState<string | null>(null);

  const report: JwtAuditReport = useMemo(() => {
    return auditJwtToken(tokenInput);
  }, [tokenInput]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleLoadSample = (index: number) => {
    setSelectedSampleIndex(index);
    setTokenInput(SAMPLE_TOKENS[index].token);
    setGeneratedExploitToken(null);
  };

  const handleGenerateNoneExploit = () => {
    const forgedPayload = {
      ...report.payload,
      role: tamperRole,
      isAdmin: true,
      permissions: ['*']
    };
    const exploit = generateAlgNoneExploitToken(tokenInput, forgedPayload);
    setGeneratedExploitToken(exploit);
  };

  const scoreColor =
    report.securityScore >= 80 ? 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10' :
    report.securityScore >= 50 ? 'text-amber-400 border-amber-500/40 bg-amber-500/10' :
    'text-rose-400 border-rose-500/40 bg-rose-500/10';

  const parts = tokenInput.trim().split('.');

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-[#0F0F0F] border border-[#222]">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-violet-500/20 to-purple-500/10 border border-violet-500/30 flex items-center justify-center shrink-0 shadow-[0_0_15px_rgba(139,92,246,0.15)]">
            <KeyRound className="w-6 h-6 text-violet-400" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-xl font-black text-white uppercase tracking-tight">
                JWT &amp; API Token Forensic Inspector
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-violet-500/20 text-violet-300 border border-violet-500/30 uppercase">
                Autenticação &amp; Criptografia
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#1A1A1A] text-zinc-400 border border-zinc-700">
                RFC 7519 Forensics
              </span>
            </div>
            <p className="text-sm text-zinc-400 mt-1">
              Decodifique e investigue tokens JSON Web Token (JWT): validação forense de algoritmo (alg: none), quebra de senhas HMAC fracas, expiração retroativa e dados confidenciais expostos no payload.
            </p>
          </div>
        </div>

        {/* Security Score */}
        <div className="flex items-center gap-4 shrink-0 self-end md:self-auto">
          <div className="text-right">
            <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider block">Token Security</span>
            <span className="text-xs font-mono font-bold text-zinc-300">
              {report.vulnerabilities.filter(v => v.severity === 'CRITICAL').length} Crítico(s)
            </span>
          </div>
          <div className={`w-16 h-16 rounded-xl border-2 flex items-center justify-center font-black text-xl font-mono shadow-lg ${scoreColor}`}>
            {report.securityScore}%
          </div>
        </div>
      </div>

      {/* Preset Token Selector */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        {SAMPLE_TOKENS.map((sample, idx) => (
          <button
            key={sample.name}
            onClick={() => handleLoadSample(idx)}
            className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer ${
              selectedSampleIndex === idx
                ? 'bg-violet-950/20 border-violet-500/50 shadow-sm ring-1 ring-violet-500/30'
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

      {/* Raw Token Input with color-coded syntax representation */}
      <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white flex items-center gap-1.5">
            <KeyRound className="w-3.5 h-3.5 text-violet-400" />
            <span>Token JWT Bruto (Header.Payload.Signature)</span>
          </h3>
          <div className="flex items-center gap-3 text-xs font-mono">
            <span className="text-rose-400 font-bold">● Header</span>
            <span className="text-purple-400 font-bold">● Payload</span>
            <span className="text-cyan-400 font-bold">● Assinatura</span>
          </div>
        </div>

        <textarea
          value={tokenInput}
          onChange={(e) => setTokenInput(e.target.value)}
          rows={3}
          className="w-full p-3 rounded-lg bg-black/70 border border-zinc-800 text-zinc-200 font-mono text-xs focus:outline-none focus:border-violet-500/60 transition-colors leading-relaxed break-all"
          placeholder="Cole seu token JWT aqui (Bearer eyJ...)"
        />

        {parts.length >= 2 && (
          <div className="p-3 rounded-lg bg-black/50 border border-zinc-900 font-mono text-xs break-all leading-relaxed">
            <span className="text-rose-400 font-bold">{parts[0]}</span>
            <span className="text-zinc-600">.</span>
            <span className="text-purple-400 font-bold">{parts[1]}</span>
            {parts[2] && (
              <>
                <span className="text-zinc-600">.</span>
                <span className="text-cyan-400 font-bold">{parts[2]}</span>
              </>
            )}
          </div>
        )}
      </div>

      {/* Main Grid: Decoded Structure & Forensics */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Decoded Header & Payload (6 cols) */}
        <div className="lg:col-span-6 space-y-4">
          {/* Header Decoded */}
          <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-rose-400 flex items-center gap-1.5">
                <FileCode2 className="w-3.5 h-3.5" />
                <span>1. Header (Algoritmo &amp; Tipo)</span>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/30 uppercase">
                alg: {report.algorithm}
              </span>
            </div>
            <pre className="p-3 rounded-lg bg-black/80 border border-zinc-800 font-mono text-xs text-rose-300 overflow-x-auto">
              {JSON.stringify(report.header, null, 2)}
            </pre>
          </div>

          {/* Payload Decoded */}
          <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-purple-400 flex items-center gap-1.5">
                <FileCode2 className="w-3.5 h-3.5" />
                <span>2. Payload (Claims &amp; Dados)</span>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30">
                {Object.keys(report.payload).length} Claims
              </span>
            </div>
            <pre className="p-3 rounded-lg bg-black/80 border border-zinc-800 font-mono text-xs text-purple-300 overflow-x-auto max-h-60">
              {JSON.stringify(report.payload, null, 2)}
            </pre>
          </div>

          {/* Canonical Claims Status */}
          <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-2">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-400">
              Auditoria de Claims Canônicas (RFC 7519)
            </h3>
            <div className="space-y-1.5">
              {report.claimsAudit.map((c, i) => (
                <div key={i} className="flex items-center justify-between text-xs p-2 rounded bg-black/40 border border-zinc-900">
                  <span className="font-mono font-bold text-white uppercase">{c.claim}</span>
                  <span className={`text-[11px] font-mono ${
                    c.status === 'VALID' ? 'text-emerald-400' :
                    c.status === 'WARNING' ? 'text-amber-400' : 'text-rose-400 font-bold'
                  }`}>
                    {c.detail}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Vulnerabilities & Exploit Simulator (6 cols) */}
        <div className="lg:col-span-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-violet-400" />
              <span>Vulnerabilidades Forenses ({report.vulnerabilities.length})</span>
            </h2>
          </div>

          {/* Vulnerability List */}
          <div className="space-y-3">
            {report.vulnerabilities.length === 0 ? (
              <div className="p-8 rounded-xl bg-[#0F0F0F] border border-emerald-500/30 text-center space-y-2">
                <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto" />
                <h3 className="text-sm font-bold text-white">Token em Conformidade</h3>
                <p className="text-xs text-zinc-400 max-w-md mx-auto">
                  Nenhuma vulnerabilidade crítica de assinatura (alg: none, segredo fraco ou expiração retroativa) foi detectada.
                </p>
              </div>
            ) : (
              report.vulnerabilities.map(vuln => {
                const sevColor = 
                  vuln.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-300 border-rose-500/30' :
                  vuln.severity === 'HIGH' ? 'bg-amber-500/10 text-amber-300 border-amber-500/30' :
                  'bg-yellow-500/10 text-yellow-300 border-yellow-500/30';

                return (
                  <div
                    key={vuln.id}
                    className="p-4 rounded-lg bg-[#0F0F0F] border border-[#222] hover:border-[#333] transition-colors space-y-2"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs font-bold text-white">{vuln.title}</span>
                      <span className={`px-2 py-0.2 rounded text-[9.5px] font-mono font-bold border uppercase ${sevColor}`}>
                        {vuln.severity}
                      </span>
                    </div>

                    <p className="text-xs text-zinc-400 leading-relaxed">{vuln.description}</p>

                    <div className="p-2 rounded bg-black/60 border border-zinc-800 text-[11px] text-rose-300 space-y-1">
                      <span className="font-bold text-zinc-500 block text-[10px] uppercase">Cenário de Ataque:</span>
                      <span>{vuln.exploitScenario}</span>
                    </div>

                    <div className="flex items-start gap-1.5 text-xs text-emerald-400 bg-emerald-500/5 p-2 rounded border border-emerald-500/20">
                      <Sparkles className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                      <span>{vuln.remediation}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Exploit Simulator: alg=none Forge */}
          <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white flex items-center gap-1.5">
                <Unlock className="w-3.5 h-3.5 text-rose-400" />
                <span>Simulador de Forja de Token (alg: "none")</span>
              </h3>
              <span className="text-[10px] font-mono text-zinc-500">CVE-2015-9235</span>
            </div>

            <p className="text-xs text-zinc-400">
              Altere a role do payload e forje um token desprovido de assinatura para testar se o seu backend valida adequadamente o algoritmo:
            </p>

            <div className="flex items-center gap-2">
              <input
                type="text"
                value={tamperRole}
                onChange={(e) => setTamperRole(e.target.value)}
                placeholder="Nova role (ex: admin, superuser)"
                className="flex-1 p-2 rounded bg-black border border-zinc-800 text-xs font-mono text-zinc-200 focus:outline-none focus:border-rose-500"
              />
              <button
                onClick={handleGenerateNoneExploit}
                className="px-3 py-2 rounded bg-rose-500 hover:bg-rose-600 text-white text-xs font-mono font-bold transition-colors cursor-pointer"
              >
                Gerar Token Forjado
              </button>
            </div>

            {generatedExploitToken && (
              <div className="p-3 rounded bg-black/80 border border-rose-500/40 space-y-2">
                <div className="flex items-center justify-between text-[11px] text-rose-300 font-mono">
                  <span>Token Forjado Pronto (alg: none):</span>
                  <button
                    onClick={() => handleCopy(generatedExploitToken, 'exploit-token')}
                    className="underline text-white hover:text-rose-200 cursor-pointer font-bold"
                  >
                    {copiedKey === 'exploit-token' ? 'Copiado!' : 'Copiar Token'}
                  </button>
                </div>
                <div className="font-mono text-[11px] text-zinc-300 break-all">
                  {generatedExploitToken}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
