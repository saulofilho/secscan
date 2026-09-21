import React, { useState, useMemo } from 'react';
import {
  CloudCog,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
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
  Key,
  Flame,
  Info
} from 'lucide-react';
import {
  auditIamPolicy,
  SAMPLE_IAM_POLICIES
} from '../lib/cloudIamEngine';
import { IamAuditReport } from '../types/securityTools';

interface CloudIamSecurityViewProps {
  onNavigateToScanner?: () => void;
}

export const CloudIamSecurityView: React.FC<CloudIamSecurityViewProps> = ({
  onNavigateToScanner
}) => {
  const [selectedSampleIndex, setSelectedSampleIndex] = useState<number>(0);
  const [customPolicyText, setCustomPolicyText] = useState<string>(() => SAMPLE_IAM_POLICIES[0].json);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const report: IamAuditReport = useMemo(() => {
    return auditIamPolicy(customPolicyText, SAMPLE_IAM_POLICIES[selectedSampleIndex]?.name || 'Custom-Policy');
  }, [customPolicyText, selectedSampleIndex]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleLoadSample = (index: number) => {
    setSelectedSampleIndex(index);
    setCustomPolicyText(SAMPLE_IAM_POLICIES[index].json);
  };

  const postureColor =
    report.posture === 'HARDENED' ? 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10' :
    report.posture === 'OVERPRIVILEGED' ? 'text-amber-400 border-amber-500/40 bg-amber-500/10' :
    'text-rose-400 border-rose-500/40 bg-rose-500/10';

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-[#0F0F0F] border border-[#222]">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-amber-500/20 to-orange-500/10 border border-amber-500/30 flex items-center justify-center shrink-0 shadow-[0_0_15px_rgba(245,158,11,0.15)]">
            <Key className="w-6 h-6 text-amber-400" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-xl font-black text-white uppercase tracking-tight">
                Cloud IAM &amp; CSPM Least-Privilege Auditor
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30 uppercase">
                AWS / Cloud Security
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#1A1A1A] text-zinc-400 border border-zinc-700">
                NIST 800-53 AC-6
              </span>
            </div>
            <p className="text-sm text-zinc-400 mt-1">
              Auditoria formal de políticas de identidade e acesso (IAM): detecção de privilégios excessivos (wildcards *), vetores de escalada de privilégio (PassRole, CreatePolicyVersion) e exposição pública de recursos.
            </p>
          </div>
        </div>

        {/* Posture Score */}
        <div className="flex items-center gap-4 shrink-0 self-end md:self-auto">
          <div className="text-right">
            <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider block">Posture Score</span>
            <span className="text-xs font-mono font-bold text-zinc-300">
              {report.posture}
            </span>
          </div>
          <div className={`w-16 h-16 rounded-xl border-2 flex items-center justify-center font-black text-xl font-mono shadow-lg ${postureColor}`}>
            {report.riskScore}%
          </div>
        </div>
      </div>

      {/* Preset Sample Selector */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        {SAMPLE_IAM_POLICIES.map((sample, idx) => (
          <button
            key={sample.name}
            onClick={() => handleLoadSample(idx)}
            className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer ${
              selectedSampleIndex === idx
                ? 'bg-amber-950/20 border-amber-500/50 shadow-sm ring-1 ring-amber-500/30'
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

      {/* Main Grid: Findings & Editor */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Findings List (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <span>Diagnóstico de Segurança ({report.findings.length})</span>
            </h2>
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-rose-400 font-bold">
                {report.findings.filter(f => f.severity === 'CRITICAL').length} Crítico(s)
              </span>
              <span className="text-zinc-600">•</span>
              <span className="text-amber-400 font-bold">
                {report.findings.filter(f => f.severity === 'HIGH').length} Alto(s)
              </span>
            </div>
          </div>

          {/* Privilege Escalation Alerts */}
          {report.privilegeEscalationVectors.length > 0 && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 space-y-2">
              <div className="flex items-center gap-2 text-rose-400">
                <Flame className="w-4 h-4 shrink-0 animate-pulse" />
                <span className="text-xs font-mono font-bold uppercase">
                  Alerta Crítico: Vetores de Escalada de Privilégios Ativos!
                </span>
              </div>
              <ul className="text-xs text-rose-300 space-y-1 pl-4 list-disc">
                {report.privilegeEscalationVectors.map(vec => (
                  <li key={vec}>{vec}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Findings List */}
          <div className="space-y-3">
            {report.findings.length === 0 ? (
              <div className="p-8 rounded-xl bg-[#0F0F0F] border border-emerald-500/30 text-center space-y-2">
                <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto" />
                <h3 className="text-sm font-bold text-white">Política em Conformidade (Least-Privilege)</h3>
                <p className="text-xs text-zinc-400 max-w-md mx-auto">
                  Nenhum wildcard excessivo, permissão aberta a público ou vetor de escalada de privilégios foi detectado.
                </p>
              </div>
            ) : (
              report.findings.map(finding => {
                const sevColor = 
                  finding.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-300 border-rose-500/30' :
                  finding.severity === 'HIGH' ? 'bg-amber-500/10 text-amber-300 border-amber-500/30' :
                  'bg-yellow-500/10 text-yellow-300 border-yellow-500/30';

                return (
                  <div
                    key={finding.id}
                    className="p-4 rounded-lg bg-[#0F0F0F] border border-[#222] hover:border-[#333] transition-colors space-y-2.5"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-xs font-bold text-white">{finding.title}</span>
                          <span className={`px-2 py-0.2 rounded text-[9.5px] font-mono font-bold border uppercase ${sevColor}`}>
                            {finding.severity}
                          </span>
                          <span className="text-[9.5px] font-mono px-1.5 py-0.2 rounded bg-black/40 text-zinc-400 border border-zinc-800">
                            {finding.benchmark}
                          </span>
                          <span className="text-[9.5px] font-mono text-zinc-500">
                            {finding.cwe}
                          </span>
                        </div>
                        <p className="text-xs text-zinc-400 leading-relaxed">{finding.description}</p>
                      </div>

                      <button
                        onClick={() => handleCopy(finding.remediation, finding.id)}
                        className="p-1.5 rounded bg-[#181818] hover:bg-[#222] text-zinc-400 hover:text-white border border-[#333] transition-colors cursor-pointer shrink-0"
                        title="Copiar recomendação"
                      >
                        {copiedKey === finding.id ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>

                    <div className="p-2 rounded bg-black/60 border border-zinc-800 font-mono text-[11px] text-amber-300">
                      <code>Alvo: {finding.affectedActionOrResource}</code>
                    </div>

                    <div className="flex items-start gap-1.5 text-xs text-emerald-400 bg-emerald-500/5 p-2 rounded border border-emerald-500/20">
                      <Sparkles className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                      <span>{finding.remediation}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: JSON Policy Editor & Hardened Generator (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          {/* Policy JSON Editor */}
          <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white flex items-center gap-1.5">
                <FileCode2 className="w-3.5 h-3.5 text-amber-400" />
                <span>Política IAM em JSON</span>
              </h3>
              <span className="text-[10px] font-mono text-zinc-500">Validador JSON</span>
            </div>

            <textarea
              value={customPolicyText}
              onChange={(e) => setCustomPolicyText(e.target.value)}
              rows={11}
              className="w-full p-3 rounded-lg bg-black/70 border border-zinc-800 text-zinc-200 font-mono text-xs focus:outline-none focus:border-amber-500/60 transition-colors leading-relaxed"
              placeholder="Cole o JSON da política IAM da AWS aqui..."
            />

            <div className="flex items-center justify-between text-[11px] text-zinc-400">
              <span>Edite qualquer permissão para recalcular o posture score.</span>
              <button
                onClick={() => handleLoadSample(3)}
                className="text-amber-400 hover:text-amber-300 font-bold underline cursor-pointer"
              >
                Carregar Hardened
              </button>
            </div>
          </div>

          {/* Hardened Policy Generator */}
          <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5" />
                <span>Política de Privilégio Mínimo (Least Privilege)</span>
              </h3>

              <button
                onClick={() => handleCopy(report.leastPrivilegePolicySnippet, 'least-privilege-export')}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#1C1C1C] hover:bg-[#252525] text-xs font-mono text-zinc-200 border border-[#333] transition-colors cursor-pointer"
              >
                {copiedKey === 'least-privilege-export' ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400 font-bold">Copiado!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copiar JSON</span>
                  </>
                )}
              </button>
            </div>

            <pre className="p-3 rounded-lg bg-black/80 border border-zinc-800 font-mono text-[11px] text-zinc-300 overflow-x-auto max-h-72 leading-relaxed">
              {report.leastPrivilegePolicySnippet}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
