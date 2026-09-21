import React, { useState, useMemo } from 'react';
import {
  Container,
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
  Cpu,
  Info
} from 'lucide-react';
import {
  auditDockerfile,
  SAMPLE_DOCKERFILES
} from '../lib/containerSecurityEngine';
import { ContainerAuditReport, DockerfileFinding } from '../types/securityTools';
import { ScannedFile } from '../types';

interface ContainerSecurityViewProps {
  files?: ScannedFile[];
  onNavigateToScanner?: () => void;
  onApplyHardenedDockerfile?: (content: string) => void;
}

export const ContainerSecurityView: React.FC<ContainerSecurityViewProps> = ({
  files = [],
  onNavigateToScanner,
  onApplyHardenedDockerfile
}) => {
  // Find Dockerfile in workspace if present
  const workspaceDockerFile = files.find(f => f.name.toLowerCase() === 'dockerfile' || f.name.toLowerCase().endsWith('.dockerfile'));

  const [selectedSampleIndex, setSelectedSampleIndex] = useState<number>(0);
  const [customDockerfileText, setCustomDockerfileText] = useState<string>(() => {
    return workspaceDockerFile?.content || SAMPLE_DOCKERFILES[0].content;
  });
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [appliedNotification, setAppliedNotification] = useState<boolean>(false);

  const report: ContainerAuditReport = useMemo(() => {
    return auditDockerfile(customDockerfileText, workspaceDockerFile?.name || 'Dockerfile');
  }, [customDockerfileText, workspaceDockerFile]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleLoadSample = (index: number) => {
    setSelectedSampleIndex(index);
    setCustomDockerfileText(SAMPLE_DOCKERFILES[index].content);
  };

  const handleApplyToWorkspace = () => {
    if (onApplyHardenedDockerfile) {
      onApplyHardenedDockerfile(report.hardenedDockerfileSnippet);
      setAppliedNotification(true);
      setTimeout(() => setAppliedNotification(false), 3000);
    }
  };

  const scoreColor =
    report.totalScore >= 80 ? 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10' :
    report.totalScore >= 50 ? 'text-amber-400 border-amber-500/40 bg-amber-500/10' :
    'text-rose-400 border-rose-500/40 bg-rose-500/10';

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-[#0F0F0F] border border-[#222]">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500/20 to-indigo-500/10 border border-blue-500/30 flex items-center justify-center shrink-0 shadow-[0_0_15px_rgba(59,130,246,0.15)]">
            <Container className="w-6 h-6 text-blue-400" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-xl font-black text-white uppercase tracking-tight">
                Trivy &amp; Container Security Scanner
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/20 text-blue-300 border border-blue-500/30 uppercase">
                DevSecOps
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#1A1A1A] text-zinc-400 border border-zinc-700">
                CIS Docker Benchmark 4.1
              </span>
            </div>
            <p className="text-sm text-zinc-400 mt-1">
              Análise estática de vulnerabilidades e boas práticas em Dockerfiles: execução não-root, montagem do socket do Docker host, vazamento de segredos em camadas e CVEs em imagens base.
            </p>
          </div>
        </div>

        {/* Score & Status */}
        <div className="flex items-center gap-4 shrink-0 self-end md:self-auto">
          <div className="text-right">
            <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider block">Container Health</span>
            <span className="text-xs font-mono font-bold text-zinc-300">
              {report.summary.critical} Crítico(s) • {report.summary.high} Alto(s)
            </span>
          </div>
          <div className={`w-16 h-16 rounded-xl border-2 flex items-center justify-center font-black text-xl font-mono shadow-lg ${scoreColor}`}>
            {report.totalScore}%
          </div>
        </div>
      </div>

      {/* Sample selector */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {SAMPLE_DOCKERFILES.map((sample, idx) => (
          <button
            key={sample.name}
            onClick={() => handleLoadSample(idx)}
            className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer ${
              selectedSampleIndex === idx
                ? 'bg-blue-950/20 border-blue-500/50 shadow-sm ring-1 ring-blue-500/30'
                : 'bg-[#0F0F0F] border-[#222] hover:border-[#333] hover:bg-[#141414]'
            }`}
          >
            <div className="flex items-center justify-between gap-2 mb-1">
              <span className="text-xs font-bold text-white">{sample.name}</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-black/40 text-zinc-400 border border-zinc-800">
                Amostra {idx + 1}
              </span>
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
              <ShieldAlert className="w-4 h-4 text-blue-400" />
              <span>Vulnerabilidades Detectadas ({report.findings.length})</span>
            </h2>
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-rose-400 font-bold">{report.summary.critical} Crítica(s)</span>
              <span className="text-zinc-600">•</span>
              <span className="text-amber-400 font-bold">{report.summary.high} Alta(s)</span>
              <span className="text-zinc-600">•</span>
              <span className="text-blue-400 font-bold">{report.summary.medium} Média(s)</span>
            </div>
          </div>

          {/* Base Image Audit Card */}
          <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-mono font-bold text-white uppercase">
                  Imagem Base: {report.baseImageAudit.baseImage}:{report.baseImageAudit.tag}
                </span>
              </div>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                report.baseImageAudit.isOutdated 
                  ? 'bg-rose-500/10 text-rose-300 border-rose-500/30' 
                  : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
              }`}>
                {report.baseImageAudit.isOutdated ? 'DESATUALIZADA / VULNERÁVEL' : 'IMAGEM ATUALIZADA'}
              </span>
            </div>

            <div className="text-xs text-zinc-400">
              Recomendação de tag segura: <code className="text-emerald-400 font-mono font-bold">{report.baseImageAudit.latestSecureTag}</code>
            </div>

            {report.baseImageAudit.criticalCves.length > 0 && (
              <div className="mt-2 space-y-1">
                <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider block">CVEs Conhecidas na Versão Base:</span>
                {report.baseImageAudit.criticalCves.map(cve => (
                  <div key={cve} className="text-[11px] font-mono text-rose-300 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                    <span>{cve}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Findings List */}
          <div className="space-y-3">
            {report.findings.length === 0 ? (
              <div className="p-8 rounded-xl bg-[#0F0F0F] border border-emerald-500/30 text-center space-y-2">
                <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto" />
                <h3 className="text-sm font-bold text-white">Dockerfile Hardened &amp; Seguro</h3>
                <p className="text-xs text-zinc-400 max-w-md mx-auto">
                  Nenhuma vulnerabilidade crítica ou má prática de CIS Docker Benchmark foi encontrada neste Dockerfile.
                </p>
              </div>
            ) : (
              report.findings.map(finding => {
                const sevColor = 
                  finding.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-300 border-rose-500/30' :
                  finding.severity === 'HIGH' ? 'bg-amber-500/10 text-amber-300 border-amber-500/30' :
                  finding.severity === 'MEDIUM' ? 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30' :
                  'bg-blue-500/10 text-blue-300 border-blue-500/30';

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
                            {finding.ruleCode}
                          </span>
                          <span className="text-[9.5px] font-mono text-zinc-500">
                            Linha {finding.lineNumber}
                          </span>
                        </div>
                        <p className="text-xs text-zinc-400 leading-relaxed">{finding.description}</p>
                      </div>

                      <button
                        onClick={() => handleCopy(finding.suggestedPatch, finding.id)}
                        className="p-1.5 rounded bg-[#181818] hover:bg-[#222] text-zinc-400 hover:text-white border border-[#333] transition-colors cursor-pointer shrink-0"
                        title="Copiar correção sugerida"
                      >
                        {copiedKey === finding.id ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>

                    {/* Problematic Line */}
                    <div className="p-2 rounded bg-black/60 border border-zinc-800 font-mono text-[11px] text-rose-300">
                      <code>{finding.lineContent}</code>
                    </div>

                    {/* Remediation */}
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

        {/* Right Column: Dockerfile Editor & Hardened Generator (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          {/* Editor */}
          <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white flex items-center gap-1.5">
                <FileCode2 className="w-3.5 h-3.5 text-blue-400" />
                <span>Dockerfile em Análise</span>
              </h3>
              <span className="text-[10px] font-mono text-zinc-500">Editor Dinâmico</span>
            </div>

            <textarea
              value={customDockerfileText}
              onChange={(e) => setCustomDockerfileText(e.target.value)}
              rows={10}
              className="w-full p-3 rounded-lg bg-black/70 border border-zinc-800 text-zinc-200 font-mono text-xs focus:outline-none focus:border-blue-500/60 transition-colors leading-relaxed"
              placeholder="Cole seu Dockerfile aqui para auditoria instantânea..."
            />

            <div className="flex items-center justify-between text-[11px] text-zinc-400">
              <span>Edite qualquer linha para recalcular os riscos.</span>
              <button
                onClick={() => handleLoadSample(2)}
                className="text-blue-400 hover:text-blue-300 font-bold underline cursor-pointer"
              >
                Carregar Hardened
              </button>
            </div>
          </div>

          {/* Hardened Template Generator */}
          <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#222] space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5" />
                <span>Dockerfile Blindado Recomendado</span>
              </h3>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleCopy(report.hardenedDockerfileSnippet, 'hardened-dockerfile')}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#1C1C1C] hover:bg-[#252525] text-xs font-mono text-zinc-200 border border-[#333] transition-colors cursor-pointer"
                >
                  {copiedKey === 'hardened-dockerfile' ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span className="text-emerald-400 font-bold">Copiado!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copiar</span>
                    </>
                  )}
                </button>

                {onApplyHardenedDockerfile && (
                  <button
                    onClick={handleApplyToWorkspace}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-xs font-mono text-emerald-300 border border-emerald-500/40 transition-colors cursor-pointer font-bold"
                  >
                    <span>Salvar no Workspace</span>
                  </button>
                )}
              </div>
            </div>

            {appliedNotification && (
              <div className="p-2 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-200 text-xs font-mono">
                Dockerfile atualizado com sucesso no workspace!
              </div>
            )}

            <pre className="p-3 rounded-lg bg-black/80 border border-zinc-800 font-mono text-[11px] text-zinc-300 overflow-x-auto max-h-72 leading-relaxed">
              {report.hardenedDockerfileSnippet}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
