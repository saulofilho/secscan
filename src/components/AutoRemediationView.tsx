import React, { useState, useMemo } from 'react';
import { 
  Wrench, 
  Sparkles, 
  FileDiff, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldCheck, 
  Copy, 
  Check, 
  RotateCcw, 
  Play, 
  FileCode2,
  ExternalLink
} from 'lucide-react';
import { ScannedFile, ScanFinding } from '../types';
import { 
  generateRemediationPatchForFinding, 
  applyPatchToFile, 
  RemediationPatch 
} from '../lib/autoRemediator';

interface AutoRemediationViewProps {
  files: ScannedFile[];
  findings: ScanFinding[];
  onUpdateFiles: (updatedFiles: ScannedFile[]) => void;
  onReScan: () => void;
  onNavigateToFile?: (filePath: string, line?: number) => void;
}

export const AutoRemediationView: React.FC<AutoRemediationViewProps> = ({
  files,
  findings,
  onUpdateFiles,
  onReScan,
  onNavigateToFile
}) => {
  const [appliedPatches, setAppliedPatches] = useState<Record<string, RemediationPatch>>({});
  const [feedbackMessage, setFeedbackMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Generate candidate patches from findings
  const candidatePatches: RemediationPatch[] = useMemo(() => {
    const list: RemediationPatch[] = [];
    for (const finding of findings) {
      const patch = generateRemediationPatchForFinding(finding, files);
      if (patch) {
        if (appliedPatches[patch.id]) {
          list.push(appliedPatches[patch.id]);
        } else {
          list.push(patch);
        }
      }
    }
    return list;
  }, [findings, files, appliedPatches]);

  const handleApplyPatch = (patch: RemediationPatch) => {
    const result = applyPatchToFile(files, patch);
    if (result.success) {
      onUpdateFiles(result.updatedFiles);
      setAppliedPatches(prev => ({
        ...prev,
        [patch.id]: { ...patch, status: 'APPLIED' }
      }));
      setFeedbackMessage({ type: 'success', text: result.message });
      // Trigger a re-scan after applying patch
      setTimeout(() => {
        onReScan();
      }, 300);
    } else {
      setFeedbackMessage({ type: 'error', text: result.message });
    }
  };

  const handleCopyDiff = (diff: string, id: string) => {
    navigator.clipboard.writeText(diff);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 font-mono">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#222] pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              <Wrench className="w-5 h-5" />
            </span>
            <h1 className="text-xl font-bold tracking-tight text-white uppercase">
              Auto-Remediação &amp; Gerador de Patches (1-Click)
            </h1>
            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 font-bold">
              Unified Diffs &amp; Code Rewrite
            </span>
          </div>
          <p className="text-xs text-zinc-400 mt-1">
            Geração de correções automáticas para segredos hardcoded, injeção de código, eval e configurações inseguras com aplicação direta no código.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-zinc-400">
            Patches Disponíveis: <strong>{candidatePatches.length}</strong>
          </span>
        </div>
      </div>

      {/* Alert Feedback Toast if any */}
      {feedbackMessage && (
        <div className={`p-4 rounded-xl border flex items-center justify-between gap-3 text-xs ${
          feedbackMessage.type === 'success'
            ? 'bg-emerald-950/40 border-emerald-600 text-emerald-200'
            : 'bg-rose-950/40 border-rose-600 text-rose-200'
        }`}>
          <div className="flex items-center gap-2">
            {feedbackMessage.type === 'success' ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-rose-400" />}
            <span>{feedbackMessage.text}</span>
          </div>
          <button
            onClick={() => setFeedbackMessage(null)}
            className="text-xs text-zinc-400 hover:text-white cursor-pointer"
          >
            Fechar
          </button>
        </div>
      )}

      {/* Patches List */}
      <div className="space-y-4">
        {candidatePatches.length === 0 ? (
          <div className="p-12 text-center bg-[#0C0C0C] border border-[#222] rounded-xl text-xs text-zinc-500 space-y-2">
            <ShieldCheck className="w-8 h-8 text-emerald-500 mx-auto" />
            <p className="font-bold text-zinc-300 text-sm">Nenhuma vulnerabilidade pendente de remediação no momento.</p>
            <p className="text-zinc-500">Execute uma análise ou altere arquivos para gerar sugestões de patches de segurança.</p>
          </div>
        ) : (
          candidatePatches.map(patch => {
            const isApplied = patch.status === 'APPLIED';

            return (
              <div
                key={patch.id}
                className={`p-5 rounded-xl border transition-all ${
                  isApplied
                    ? 'bg-[#070E0A] border-emerald-800/60'
                    : 'bg-[#0A0A0A] border-[#222] hover:border-[#333]'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`px-2 py-0.2 rounded text-[10px] font-bold ${
                        isApplied ? 'bg-emerald-900 text-emerald-200' : 'bg-amber-950 text-amber-200 border border-amber-800'
                      }`}>
                        {isApplied ? 'APLICADO NO WORKSPACE' : 'PATCH PRONTO'}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-300">
                        {patch.category}
                      </span>
                      <span className="text-[10px] text-zinc-500">{patch.cwe}</span>
                    </div>

                    <h3 className="font-bold text-sm text-white">{patch.title}</h3>
                    <p className="text-xs text-zinc-400 leading-relaxed">{patch.explanation}</p>

                    <div className="flex items-center gap-2 text-xs text-zinc-500 pt-1">
                      <FileCode2 className="w-3.5 h-3.5 text-zinc-400" />
                      <span>{patch.file}:{patch.line}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 self-start sm:self-auto shrink-0">
                    <button
                      onClick={() => handleCopyDiff(patch.unifiedDiff, patch.id)}
                      className="px-2.5 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
                      title="Copiar diff unificado"
                    >
                      {copiedId === patch.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedId === patch.id ? 'Copiado' : 'Diff'}</span>
                    </button>

                    <button
                      onClick={() => handleApplyPatch(patch)}
                      disabled={isApplied}
                      className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer shadow ${
                        isApplied
                          ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/40 cursor-default'
                          : 'bg-emerald-600 hover:bg-emerald-500 text-white'
                      }`}
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>{isApplied ? 'Patch Aplicado ✓' : 'Aplicar Patch no Código'}</span>
                    </button>
                  </div>
                </div>

                {/* Unified Diff Box */}
                <div className="mt-4 pt-3 border-t border-white/5 space-y-2">
                  <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider block">
                    Visualização do Patch Unificado (Git Diff):
                  </span>
                  <pre className="p-3 bg-black rounded-lg text-xs overflow-x-auto border border-white/5 font-mono leading-relaxed">
                    <code>
                      {patch.unifiedDiff.split('\n').map((line, idx) => {
                        const isMinus = line.startsWith('-');
                        const isPlus = line.startsWith('+');
                        const isHeader = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++');

                        return (
                          <div
                            key={idx}
                            className={`${
                              isMinus
                                ? 'text-rose-400 bg-rose-950/30'
                                : isPlus
                                ? 'text-emerald-300 bg-emerald-950/30 font-bold'
                                : isHeader
                                ? 'text-cyan-400/80'
                                : 'text-zinc-400'
                            }`}
                          >
                            {line}
                          </div>
                        );
                      })}
                    </code>
                  </pre>
                </div>

                {/* Env snippet if needed */}
                {patch.envSnippetNeeded && (
                  <div className="mt-3 p-3 bg-zinc-900/60 border border-zinc-800 rounded-lg text-xs space-y-1">
                    <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">
                      Variável de Ambiente Correspondente (.env.example):
                    </span>
                    <code className="text-zinc-300 text-[11px] block">{patch.envSnippetNeeded}</code>
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
