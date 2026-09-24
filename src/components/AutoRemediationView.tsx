import React, { useState, useMemo, useEffect, useCallback } from 'react';
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
  ExternalLink,
  RefreshCw,
  Filter,
  Search,
  ArrowRight,
  Layers,
  ArrowLeftRight,
  KeyRound,
  ListChecks,
  Undo2,
  ShieldAlert,
  Cpu,
  CheckCheck,
  FolderCode,
  FileText,
  ChevronRight,
  Zap,
  Info
} from 'lucide-react';
import { ScannedFile, ScanFinding, AuditLogEvent, SuggestedFixEnvConfig } from '../types';
import { 
  generateRemediationPatchForFinding, 
  convertSuggestedFixToPatch,
  applyPatchToFile, 
  revertPatchFromFile,
  applyBatchPatchesToFiles,
  syncEnvVariablesToWorkspace,
  RemediationPatch 
} from '../lib/autoRemediator';
import { requestSuggestedFix } from '../lib/suggestedFixService';

interface AutoRemediationViewProps {
  files: ScannedFile[];
  findings: ScanFinding[];
  onUpdateFiles: (updatedFiles: ScannedFile[]) => void;
  onReScan: () => void;
  onNavigateToFile?: (filePath: string, line?: number) => void;
  onApplyFix?: (finding: ScanFinding, newSnippet: string) => void;
  onLogAudit?: (event: AuditLogEvent) => void;
}

export const AutoRemediationView: React.FC<AutoRemediationViewProps> = ({
  files,
  findings,
  onUpdateFiles,
  onReScan,
  onNavigateToFile,
  onApplyFix,
  onLogAudit
}) => {
  // Patches state (keyed by patch id)
  const [patches, setPatches] = useState<Record<string, RemediationPatch>>({});
  const [loadingFixes, setLoadingFixes] = useState<Record<string, boolean>>({});
  const [isBatchGenerating, setIsBatchGenerating] = useState(false);
  const [batchProgress, setBatchProgress] = useState<{ current: number; total: number; message: string }>({
    current: 0,
    total: 0,
    message: ''
  });

  // UI Filters
  const [selectedFileFilter, setSelectedFileFilter] = useState<string>('ALL');
  const [selectedSeverityFilter, setSelectedSeverityFilter] = useState<string>('ALL');
  const [selectedStatusFilter, setSelectedStatusFilter] = useState<'ALL' | 'PENDING' | 'APPLIED'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [diffViewMode, setDiffViewMode] = useState<Record<string, 'diff' | 'side-by-side' | 'code' | 'env' | 'checklist'>>({});

  // Notification feedback
  const [feedback, setFeedback] = useState<{
    type: 'success' | 'error' | 'info';
    title: string;
    message: string;
  } | null>(null);

  // Copied states
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Initialize or update patches when findings/files change
  useEffect(() => {
    if (!findings || findings.length === 0) {
      setPatches({});
      return;
    }

    setPatches(prev => {
      const next: Record<string, RemediationPatch> = {};
      findings.forEach(finding => {
        const patchId = `patch-${finding.id}`;
        if (prev[patchId]) {
          next[patchId] = prev[patchId];
        } else {
          const generated = generateRemediationPatchForFinding(finding, files);
          if (generated) {
            next[patchId] = generated;
          }
        }
      });
      return next;
    });
  }, [findings, files]);

  // Unique vulnerable files list
  const vulnerableFiles = useMemo(() => {
    const map = new Map<string, { count: number; criticals: number; highs: number }>();
    findings.forEach(f => {
      const current = map.get(f.file) || { count: 0, criticals: 0, highs: 0 };
      current.count += 1;
      if (f.severity === 'CRITICAL') current.criticals += 1;
      if (f.severity === 'HIGH') current.highs += 1;
      map.set(f.file, current);
    });
    return Array.from(map.entries()).map(([path, stats]) => ({
      path,
      fileName: path.split('/').pop() || path,
      ...stats
    }));
  }, [findings]);

  // Convert patches map to array for display
  const patchList = useMemo(() => {
    return Object.values(patches);
  }, [patches]);

  // Filtered patches
  const filteredPatches = useMemo(() => {
    return patchList.filter(patch => {
      // File filter
      if (selectedFileFilter !== 'ALL' && patch.file !== selectedFileFilter) {
        return false;
      }
      // Severity filter
      if (selectedSeverityFilter !== 'ALL' && patch.severity !== selectedSeverityFilter) {
        return false;
      }
      // Status filter
      if (selectedStatusFilter !== 'ALL' && patch.status !== selectedStatusFilter) {
        return false;
      }
      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesTitle = patch.title.toLowerCase().includes(q);
        const matchesFile = patch.file.toLowerCase().includes(q);
        const matchesCwe = patch.cwe.toLowerCase().includes(q);
        const matchesSnippet = patch.originalSnippet.toLowerCase().includes(q) || patch.replacementSnippet.toLowerCase().includes(q);
        if (!matchesTitle && !matchesFile && !matchesCwe && !matchesSnippet) {
          return false;
        }
      }
      return true;
    });
  }, [patchList, selectedFileFilter, selectedSeverityFilter, selectedStatusFilter, searchQuery]);

  // Aggregated metrics
  const metrics = useMemo(() => {
    const total = patchList.length;
    const applied = patchList.filter(p => p.status === 'APPLIED').length;
    const pending = patchList.filter(p => p.status === 'PENDING').length;
    const aiPowered = patchList.filter(p => p.source === 'gemini').length;
    const riskMitigated = patchList
      .filter(p => p.status === 'APPLIED')
      .reduce((acc, p) => acc + (p.riskReductionPoints || 15), 0);

    return { total, applied, pending, aiPowered, riskMitigated };
  }, [patchList]);

  // Generate AI fix for an individual patch using Gemini (/api/suggested-fix)
  const handleGenerateAiFix = async (patch: RemediationPatch) => {
    const finding = findings.find(f => f.id === patch.findingId);
    if (!finding) return;

    setLoadingFixes(prev => ({ ...prev, [patch.id]: true }));
    const targetFile = files.find(f => f.path === patch.file || f.name === patch.file);

    try {
      const fixResult = await requestSuggestedFix(finding, targetFile?.content);
      if (fixResult && targetFile) {
        const aiPatch = convertSuggestedFixToPatch(fixResult, finding, targetFile);
        // Preserve applied state if it was already applied
        if (patch.status === 'APPLIED') {
          aiPatch.status = 'APPLIED';
          aiPatch.previousFileContentSnapshot = patch.previousFileContentSnapshot;
        }

        setPatches(prev => ({
          ...prev,
          [patch.id]: aiPatch
        }));

        setFeedback({
          type: 'success',
          title: 'Sugestão da IA Pronta!',
          message: `O modelo ${fixResult.model || 'Gemini'} sintetizou uma correção segura contextual para ${patch.file}:${patch.line}.`
        });
      }
    } catch (err) {
      console.error('Erro ao chamar IA para patch:', err);
      setFeedback({
        type: 'error',
        title: 'Falha na IA',
        message: 'Não foi possível consultar o modelo Gemini. Usando motor determinístico de segurança como fallback.'
      });
    } finally {
      setLoadingFixes(prev => ({ ...prev, [patch.id]: false }));
    }
  };

  // Batch generate AI suggestions for all pending patches
  const handleBatchGenerateAiFixes = async () => {
    const pendingPatches = patchList.filter(p => p.status === 'PENDING');
    if (pendingPatches.length === 0) {
      setFeedback({
        type: 'info',
        title: 'Nenhum patch pendente',
        message: 'Todas as vulnerabilidades já foram remediadas ou analisadas.'
      });
      return;
    }

    setIsBatchGenerating(true);
    setBatchProgress({ current: 0, total: pendingPatches.length, message: 'Iniciando síntese de correções com IA...' });

    let count = 0;
    const updatedPatches: Record<string, RemediationPatch> = { ...patches };

    for (const patch of pendingPatches) {
      count++;
      setBatchProgress({
        current: count,
        total: pendingPatches.length,
        message: `Analisando ${patch.file} (${count}/${pendingPatches.length})...`
      });

      const finding = findings.find(f => f.id === patch.findingId);
      const targetFile = files.find(f => f.path === patch.file || f.name === patch.file);

      if (finding && targetFile) {
        try {
          const fixResult = await requestSuggestedFix(finding, targetFile.content);
          if (fixResult) {
            const aiPatch = convertSuggestedFixToPatch(fixResult, finding, targetFile);
            updatedPatches[patch.id] = aiPatch;
          }
        } catch (e) {
          console.warn('Erro individual de IA em lote:', e);
        }
      }
    }

    setPatches(updatedPatches);
    setIsBatchGenerating(false);
    setFeedback({
      type: 'success',
      title: 'Geração em Lote Concluída!',
      message: `${count} correções foram analisadas e sintetizadas com inteligência artificial.`
    });
  };

  // 1-Click Apply single patch to workspace file
  const handleApplySinglePatch = (patch: RemediationPatch) => {
    const result = applyPatchToFile(files, patch);
    if (result.success) {
      onUpdateFiles(result.updatedFiles);

      // Update patch state with snapshot
      setPatches(prev => ({
        ...prev,
        [patch.id]: {
          ...patch,
          status: 'APPLIED',
          previousFileContentSnapshot: result.previousSnapshot
        }
      }));

      // Log audit
      if (onLogAudit) {
        const auditEvent: AuditLogEvent = {
          id: `audit-patch-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          type: 'FIX_APPLIED',
          message: `Auto-Remediação 1-Clique aplicada em ${patch.file} (linha ${patch.line}) via ${patch.model || patch.source}.`,
          severity: (patch.severity as any) || 'HIGH',
          details: {
            file: patch.file,
            line: patch.line,
            cwe: patch.cwe,
            model: patch.model
          }
        };
        onLogAudit(auditEvent);
      }

      setFeedback({
        type: 'success',
        title: 'Patch Aplicado com Sucesso!',
        message: result.message
      });

      // Trigger automatic re-scan to lower risk score
      setTimeout(() => {
        onReScan();
      }, 350);
    } else {
      setFeedback({
        type: 'error',
        title: 'Erro ao Aplicar Patch',
        message: result.message
      });
    }
  };

  // 1-Click Revert single patch
  const handleRevertSinglePatch = (patch: RemediationPatch) => {
    const result = revertPatchFromFile(files, patch);
    if (result.success) {
      onUpdateFiles(result.updatedFiles);

      setPatches(prev => ({
        ...prev,
        [patch.id]: {
          ...patch,
          status: 'PENDING'
        }
      }));

      if (onLogAudit) {
        const auditEvent: AuditLogEvent = {
          id: `audit-revert-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          type: 'SCAN_COMPLETE',
          message: `Reversão de patch executada para ${patch.file} (linha ${patch.line}).`,
          severity: 'LOW',
          details: { file: patch.file, line: patch.line }
        };
        onLogAudit(auditEvent);
      }

      setFeedback({
        type: 'info',
        title: 'Patch Revertido',
        message: result.message
      });

      setTimeout(() => {
        onReScan();
      }, 350);
    } else {
      setFeedback({
        type: 'error',
        title: 'Erro na Reversão',
        message: result.message
      });
    }
  };

  // 1-Click Batch apply: All patches for a specific file
  const handleApplyAllForFile = (filePath: string) => {
    const filePatches = patchList.filter(p => p.file === filePath && p.status !== 'APPLIED');
    if (filePatches.length === 0) return;

    const result = applyBatchPatchesToFiles(files, filePatches);
    if (result.appliedCount > 0) {
      onUpdateFiles(result.updatedFiles);

      // Mark applied
      setPatches(prev => {
        const next = { ...prev };
        filePatches.forEach(p => {
          if (next[p.id]) {
            next[p.id] = { ...next[p.id], status: 'APPLIED' };
          }
        });
        return next;
      });

      setFeedback({
        type: 'success',
        title: 'Arquivo Remediado!',
        message: `${result.appliedCount} vulnerabilidade(s) remediadas em ${filePath}.`
      });

      setTimeout(() => {
        onReScan();
      }, 350);
    } else {
      setFeedback({
        type: 'error',
        title: 'Falha na remediação do arquivo',
        message: 'Nenhum patch pôde ser alinhado com precisão no arquivo.'
      });
    }
  };

  // 1-Click Batch apply: All pending patches across the entire workspace
  const handleApplyAllPendingPatches = () => {
    const pending = patchList.filter(p => p.status === 'PENDING');
    if (pending.length === 0) return;

    const result = applyBatchPatchesToFiles(files, pending);
    if (result.appliedCount > 0) {
      onUpdateFiles(result.updatedFiles);

      setPatches(prev => {
        const next = { ...prev };
        pending.forEach(p => {
          if (next[p.id]) {
            next[p.id] = { ...next[p.id], status: 'APPLIED' };
          }
        });
        return next;
      });

      setFeedback({
        type: 'success',
        title: 'Remediação em Lote Concluída!',
        message: `${result.appliedCount} patches de segurança foram aplicados diretamente ao workspace.`
      });

      setTimeout(() => {
        onReScan();
      }, 400);
    }
  };

  // 1-Click sync environment variables to .env.example
  const handleSyncEnvToWorkspace = () => {
    const result = syncEnvVariablesToWorkspace(files, patchList);
    if (result.addedVariables.length > 0) {
      onUpdateFiles(result.updatedFiles);
      setFeedback({
        type: 'success',
        title: 'Variáveis Sincronizadas!',
        message: `${result.addedVariables.length} variável(is) injetadas no arquivo .env.example: ${result.addedVariables.join(', ')}`
      });
    } else {
      setFeedback({
        type: 'info',
        title: 'Variáveis Já Configuradas',
        message: 'Todas as variáveis de ambiente necessárias já constam no .env.example.'
      });
    }
  };

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 font-mono text-zinc-200">
      {/* Top Hero Banner / Control Header */}
      <div className="bg-[#050B06] border border-[#00FF41]/30 rounded-xl p-5 sm:p-6 shadow-[0_0_25px_rgba(0,255,65,0.06)] relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-[#00FF41]/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <div className="p-2 rounded-lg bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/40 flex items-center gap-1.5">
                <Wrench className="w-5 h-5 text-[#00FF41]" />
                <Sparkles className="w-4 h-4 text-[#00E5FF] animate-pulse" />
              </div>
              <h1 className="text-xl sm:text-2xl font-black tracking-tight text-white uppercase">
                Auto-Remediação em 1-Clique (AI AppSec Engine)
              </h1>
              <span className="px-2.5 py-0.5 rounded bg-[#00FF41]/20 text-[#00FF41] border border-[#00FF41]/50 text-xs font-bold flex items-center gap-1">
                <Cpu className="w-3.5 h-3.5" />
                <span>Gemini 3.8 Flash + Resilient AST</span>
              </span>
            </div>
            <p className="text-xs sm:text-sm text-zinc-400 max-w-3xl leading-relaxed">
              Aceite e aplique refatorações de segurança sintetizadas por inteligência artificial diretamente nos arquivos do projeto. O motor analisa o contexto sintático, remove segredos hardcoded, injeta variáveis em cofre, sanitiza chamadas de DOM e reescreve consultas parametrizadas em tempo real.
            </p>
          </div>

          {/* Global 1-Click Action Buttons */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              id="btn-batch-generate-ai"
              onClick={handleBatchGenerateAiFixes}
              disabled={isBatchGenerating || metrics.pending === 0}
              className="px-4 py-2 bg-[#0d2610] hover:bg-[#143a18] text-[#00FF41] hover:text-white border border-[#00FF41]/50 rounded-lg text-xs font-bold uppercase tracking-wider transition-all flex items-center gap-2 cursor-pointer disabled:opacity-40 shadow-[0_0_15px_rgba(0,255,65,0.15)]"
              title="Gerar sugestões de correção via Gemini AI para todas as vulnerabilidades pendentes"
            >
              <Sparkles className={`w-4 h-4 ${isBatchGenerating ? 'animate-spin text-[#00E5FF]' : 'text-[#00FF41]'}`} />
              <span>{isBatchGenerating ? 'Sintetizando IA...' : 'Gerar Correções com IA'}</span>
            </button>

            <button
              type="button"
              id="btn-batch-apply-all"
              onClick={handleApplyAllPendingPatches}
              disabled={metrics.pending === 0}
              className="px-4 py-2 bg-[#00FF41] hover:bg-white text-black rounded-lg text-xs font-black uppercase tracking-wider transition-all flex items-center gap-2 cursor-pointer disabled:opacity-40 shadow-[0_0_20px_rgba(0,255,65,0.3)] hover:shadow-[0_0_25px_rgba(255,255,255,0.5)]"
              title="Aplica todas as correções aprovadas diretamente aos arquivos em memória"
            >
              <Zap className="w-4 h-4 fill-black" />
              <span>Auto-Remediar Tudo (1-Click)</span>
            </button>

            <button
              type="button"
              id="btn-sync-env-vars"
              onClick={handleSyncEnvToWorkspace}
              className="px-3 py-2 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700 rounded-lg text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Injeta variáveis de ambiente sugeridas nos arquivos .env.example"
            >
              <KeyRound className="w-3.5 h-3.5 text-amber-400" />
              <span>Sync .env.example</span>
            </button>
          </div>
        </div>

        {/* Batch AI Progress bar */}
        {isBatchGenerating && (
          <div className="mt-4 pt-4 border-t border-[#00FF41]/20 space-y-2">
            <div className="flex items-center justify-between text-xs text-[#00FF41]">
              <span className="flex items-center gap-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>{batchProgress.message}</span>
              </span>
              <span className="font-bold">
                {batchProgress.current} / {batchProgress.total} ({Math.round((batchProgress.current / (batchProgress.total || 1)) * 100)}%)
              </span>
            </div>
            <div className="w-full bg-zinc-900 h-2 rounded-full overflow-hidden border border-[#00FF41]/30">
              <div 
                className="bg-gradient-to-r from-[#00FF41] via-[#00E5FF] to-[#00FF41] h-full transition-all duration-300"
                style={{ width: `${(batchProgress.current / (batchProgress.total || 1)) * 100}%` }}
              />
            </div>
          </div>
        )}

        {/* Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mt-5 pt-5 border-t border-zinc-800/80">
          <div className="bg-black/50 border border-zinc-800 rounded-lg p-3">
            <div className="text-[10px] text-zinc-400 uppercase tracking-wider">Vulnerabilidades</div>
            <div className="text-xl font-bold text-white mt-0.5">{metrics.total}</div>
            <div className="text-[10px] text-zinc-500 mt-0.5">{vulnerableFiles.length} arquivos afetados</div>
          </div>

          <div className="bg-black/50 border border-zinc-800 rounded-lg p-3">
            <div className="text-[10px] text-zinc-400 uppercase tracking-wider">Pendentes</div>
            <div className="text-xl font-bold text-amber-400 mt-0.5">{metrics.pending}</div>
            <div className="text-[10px] text-amber-500/80 mt-0.5">Aguardando 1-clique</div>
          </div>

          <div className="bg-black/50 border border-[#00FF41]/30 rounded-lg p-3">
            <div className="text-[10px] text-[#00FF41] uppercase tracking-wider">Remediados</div>
            <div className="text-xl font-bold text-[#00FF41] mt-0.5">{metrics.applied}</div>
            <div className="text-[10px] text-emerald-400/80 mt-0.5">Integrados no workspace</div>
          </div>

          <div className="bg-black/50 border border-cyan-800/40 rounded-lg p-3">
            <div className="text-[10px] text-cyan-400 uppercase tracking-wider">Patches com IA</div>
            <div className="text-xl font-bold text-cyan-300 mt-0.5">{metrics.aiPowered}</div>
            <div className="text-[10px] text-cyan-500 mt-0.5">Gemini 3.8 Flash</div>
          </div>

          <div className="bg-black/50 border border-purple-800/40 rounded-lg p-3 col-span-2 sm:col-span-1">
            <div className="text-[10px] text-purple-300 uppercase tracking-wider">Risco Mitigado</div>
            <div className="text-xl font-bold text-purple-400 mt-0.5">+{metrics.riskMitigated} pts</div>
            <div className="text-[10px] text-purple-500 mt-0.5">Redução de MTTR</div>
          </div>
        </div>
      </div>

      {/* Feedback Alert if any */}
      {feedback && (
        <div className={`p-4 rounded-xl border flex items-center justify-between gap-3 text-xs ${
          feedback.type === 'success'
            ? 'bg-emerald-950/40 border-emerald-600 text-emerald-200'
            : feedback.type === 'error'
            ? 'bg-rose-950/40 border-rose-600 text-rose-200'
            : 'bg-cyan-950/40 border-cyan-600 text-cyan-200'
        }`}>
          <div className="flex items-center gap-2.5">
            {feedback.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : feedback.type === 'error' ? (
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            ) : (
              <Info className="w-4 h-4 text-cyan-400 shrink-0" />
            )}
            <div>
              <span className="font-bold">{feedback.title}: </span>
              <span>{feedback.message}</span>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setFeedback(null)}
            className="text-xs text-zinc-400 hover:text-white cursor-pointer px-2 py-1 rounded bg-black/40"
          >
            Fechar
          </button>
        </div>
      )}

      {/* Vulnerable Files Filter Tabs */}
      {vulnerableFiles.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs text-zinc-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
              <FolderCode className="w-3.5 h-3.5 text-[#00FF41]" />
              <span>Arquivos com Vulnerabilidades Ativas ({vulnerableFiles.length}):</span>
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setSelectedFileFilter('ALL')}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer border ${
                selectedFileFilter === 'ALL'
                  ? 'bg-[#00FF41] text-black border-[#00FF41] shadow-[0_0_10px_rgba(0,255,65,0.2)]'
                  : 'bg-zinc-900/80 text-zinc-400 border-zinc-800 hover:text-white hover:border-zinc-700'
              }`}
            >
              Todos os Arquivos ({patchList.length})
            </button>

            {vulnerableFiles.map(file => {
              const filePendingCount = patchList.filter(p => p.file === file.path && p.status === 'PENDING').length;
              const isSelected = selectedFileFilter === file.path;

              return (
                <div key={file.path} className="flex items-center">
                  <button
                    type="button"
                    onClick={() => setSelectedFileFilter(file.path)}
                    className={`px-3 py-1.5 rounded-l-lg text-xs transition-all cursor-pointer border-y border-l flex items-center gap-2 ${
                      isSelected
                        ? 'bg-[#0a2310] text-[#00FF41] border-[#00FF41]/60 font-bold'
                        : 'bg-zinc-900/80 text-zinc-300 border-zinc-800 hover:text-white hover:border-zinc-700'
                    }`}
                  >
                    <span>{file.fileName}</span>
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                      filePendingCount > 0 ? 'bg-rose-900/70 text-rose-200' : 'bg-emerald-900/70 text-emerald-200'
                    }`}>
                      {filePendingCount > 0 ? `${filePendingCount} pendente` : 'Limpo ✓'}
                    </span>
                  </button>

                  {/* 1-Click File remediation trigger */}
                  {filePendingCount > 0 && (
                    <button
                      type="button"
                      onClick={() => handleApplyAllForFile(file.path)}
                      className="px-2 py-1.5 rounded-r-lg bg-[#00FF41]/20 hover:bg-[#00FF41] text-[#00FF41] hover:text-black border border-[#00FF41]/50 text-xs font-bold transition-colors cursor-pointer"
                      title={`Remediar todas as ${filePendingCount} vulnerabilidades de ${file.fileName} em 1-clique`}
                    >
                      <Zap className="w-3 h-3" />
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="p-3.5 bg-[#080E09] border border-zinc-800 rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-zinc-400 shrink-0" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filtrar por nome de arquivo, regra, CWE ou snippet de código..."
            className="w-full bg-black/50 border border-zinc-800 rounded-lg px-3 py-1.5 text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-[#00FF41]"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Status filter */}
          <div className="flex items-center gap-1 bg-black/40 p-1 rounded-lg border border-zinc-800">
            <button
              type="button"
              onClick={() => setSelectedStatusFilter('ALL')}
              className={`px-2.5 py-1 rounded text-[11px] font-bold transition-colors cursor-pointer ${
                selectedStatusFilter === 'ALL' ? 'bg-[#00FF41] text-black' : 'text-zinc-400 hover:text-white'
              }`}
            >
              Todos ({patchList.length})
            </button>
            <button
              type="button"
              onClick={() => setSelectedStatusFilter('PENDING')}
              className={`px-2.5 py-1 rounded text-[11px] font-bold transition-colors cursor-pointer ${
                selectedStatusFilter === 'PENDING' ? 'bg-amber-400 text-black' : 'text-zinc-400 hover:text-white'
              }`}
            >
              Pendentes ({metrics.pending})
            </button>
            <button
              type="button"
              onClick={() => setSelectedStatusFilter('APPLIED')}
              className={`px-2.5 py-1 rounded text-[11px] font-bold transition-colors cursor-pointer ${
                selectedStatusFilter === 'APPLIED' ? 'bg-emerald-500 text-black' : 'text-zinc-400 hover:text-white'
              }`}
            >
              Aplicados ({metrics.applied})
            </button>
          </div>

          {/* Severity filter */}
          <select
            value={selectedSeverityFilter}
            onChange={(e) => setSelectedSeverityFilter(e.target.value)}
            aria-label="Filtrar por Severidade"
            className="bg-black/50 border border-zinc-800 rounded-lg px-3 py-1.5 text-zinc-300 focus:outline-none focus:border-[#00FF41]"
          >
            <option value="ALL">Todas as Severidades</option>
            <option value="CRITICAL">P0 - Crítica</option>
            <option value="HIGH">P1 - Alta</option>
            <option value="WARNING">P2 - Média/Aviso</option>
          </select>
        </div>
      </div>

      {/* Patches Cards List */}
      <div className="space-y-5">
        {filteredPatches.length === 0 ? (
          <div className="p-12 text-center bg-[#070D08] border border-zinc-800 rounded-xl space-y-3">
            <ShieldCheck className="w-10 h-10 text-[#00FF41] mx-auto" />
            <p className="font-bold text-white text-base">Nenhuma vulnerabilidade pendente com os filtros selecionados.</p>
            <p className="text-xs text-zinc-400 max-w-md mx-auto">
              Seu workspace está limpo ou todos os patches de segurança foram aplicados. Altere os filtros ou execute uma nova análise de código.
            </p>
          </div>
        ) : (
          filteredPatches.map(patch => {
            const isApplied = patch.status === 'APPLIED';
            const isLoading = loadingFixes[patch.id];
            const currentTab = diffViewMode[patch.id] || 'diff';
            const isAi = patch.source === 'gemini';

            return (
              <div
                key={patch.id}
                id={`remediation-card-${patch.id}`}
                className={`rounded-xl border transition-all overflow-hidden ${
                  isApplied
                    ? 'bg-[#040A05] border-[#00FF41]/40 shadow-[0_0_15px_rgba(0,255,65,0.04)]'
                    : 'bg-[#080E09] border-zinc-800 hover:border-zinc-700'
                }`}
              >
                {/* Patch Top Banner */}
                <div className="p-4 sm:p-5 border-b border-zinc-800/80 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  <div className="space-y-1.5 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                        isApplied 
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                          : 'bg-amber-950 text-amber-300 border border-amber-800 animate-pulse'
                      }`}>
                        {isApplied ? '✓ APLICADO NO WORKSPACE' : 'AGUARDANDO APROVAÇÃO'}
                      </span>

                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        patch.severity === 'CRITICAL' 
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : patch.severity === 'HIGH'
                          ? 'bg-orange-950 text-orange-300 border border-orange-800'
                          : 'bg-yellow-950 text-yellow-300 border border-yellow-800'
                      }`}>
                        {patch.severity || 'HIGH'}
                      </span>

                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold flex items-center gap-1 ${
                        isAi 
                          ? 'bg-cyan-950 text-cyan-300 border border-cyan-700'
                          : 'bg-zinc-800 text-zinc-300 border border-zinc-700'
                      }`}>
                        <Sparkles className="w-3 h-3 text-[#00E5FF]" />
                        <span>{patch.model || (isAi ? 'Gemini 3.8 Flash' : 'AppSec Deterministic')}</span>
                      </span>

                      <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-800/80 text-zinc-400 border border-zinc-700">
                        {patch.cwe}
                      </span>
                    </div>

                    <h3 className="font-bold text-base text-white flex items-center gap-2 pt-0.5">
                      <span>{patch.title}</span>
                    </h3>

                    <p className="text-xs text-zinc-400 leading-relaxed max-w-4xl">
                      {patch.explanation}
                    </p>

                    {/* File path location click */}
                    <div className="flex items-center gap-3 pt-1 text-xs text-zinc-500">
                      <button
                        type="button"
                        onClick={() => onNavigateToFile && onNavigateToFile(patch.file, patch.line)}
                        className="inline-flex items-center gap-1.5 text-zinc-400 hover:text-[#00FF41] cursor-pointer transition-colors"
                        title="Ver no Inspetor de Código"
                      >
                        <FileCode2 className="w-3.5 h-3.5 text-[#00FF41]" />
                        <span className="font-semibold underline underline-offset-2">{patch.file}:{patch.line}</span>
                      </button>

                      {patch.securePattern && (
                        <span className="inline-flex items-center gap-1 text-emerald-400 text-[11px]">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          <span>{patch.securePattern}</span>
                        </span>
                      )}
                    </div>
                  </div>

                  {/* 1-Click Action Controls */}
                  <div className="flex items-center gap-2 self-start lg:self-center shrink-0">
                    {/* Re-generate with AI button */}
                    <button
                      type="button"
                      onClick={() => handleGenerateAiFix(patch)}
                      disabled={isLoading}
                      className="px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-cyan-300 border border-cyan-800/50 text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                      title="Solicitar refinamento contextual com Gemini AI"
                    >
                      <RotateCcw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
                      <span>{isLoading ? 'Analisando...' : (isAi ? 'Regerar IA' : 'Otimizar com IA')}</span>
                    </button>

                    {/* Copy unified diff */}
                    <button
                      type="button"
                      onClick={() => handleCopyText(patch.unifiedDiff, `diff-${patch.id}`)}
                      className="px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700 text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
                      title="Copiar Git Unified Diff para a área de transferência"
                    >
                      {copiedId === `diff-${patch.id}` ? (
                        <Check className="w-3.5 h-3.5 text-[#00FF41]" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                      <span>{copiedId === `diff-${patch.id}` ? 'Copiado' : 'Diff'}</span>
                    </button>

                    {/* Primary 1-Click Apply Button */}
                    {!isApplied ? (
                      <button
                        type="button"
                        id={`btn-apply-patch-${patch.id}`}
                        onClick={() => handleApplySinglePatch(patch)}
                        className="px-4 py-2 rounded-lg bg-[#00FF41] hover:bg-white text-black font-black text-xs uppercase tracking-wider transition-all flex items-center gap-2 cursor-pointer shadow-[0_0_15px_rgba(0,255,65,0.25)] hover:shadow-[0_0_20px_rgba(255,255,255,0.4)]"
                        title="Aplica este patch diretamente no arquivo do projeto"
                      >
                        <Zap className="w-3.5 h-3.5 fill-black" />
                        <span>Aplicar Patch (1-Click)</span>
                      </button>
                    ) : (
                      <div className="flex items-center gap-1.5">
                        <span className="px-3 py-1.5 rounded-lg bg-emerald-950 text-emerald-300 border border-emerald-700 text-xs font-bold flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Aplicado ✓</span>
                        </span>

                        <button
                          type="button"
                          onClick={() => handleRevertSinglePatch(patch)}
                          className="px-2.5 py-1.5 rounded-lg bg-zinc-900 hover:bg-rose-950 text-zinc-400 hover:text-rose-200 border border-zinc-700 hover:border-rose-800 text-xs transition-colors cursor-pointer flex items-center gap-1"
                          title="Reverter alteração para o estado original do arquivo"
                        >
                          <Undo2 className="w-3.5 h-3.5" />
                          <span>Desfazer</span>
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* Diff & Code Inspection Tabs */}
                <div className="px-4 sm:px-5 pt-3 bg-black/40 border-b border-zinc-800 flex items-center justify-between gap-2 overflow-x-auto">
                  <div className="flex items-center gap-1">
                    <button
                      type="button"
                      onClick={() => setDiffViewMode(prev => ({ ...prev, [patch.id]: 'diff' }))}
                      className={`px-3 py-1.5 text-xs font-bold transition-all border-b-2 cursor-pointer flex items-center gap-1.5 ${
                        currentTab === 'diff'
                          ? 'border-[#00FF41] text-[#00FF41]'
                          : 'border-transparent text-zinc-400 hover:text-white'
                      }`}
                    >
                      <FileDiff className="w-3.5 h-3.5" />
                      <span>Git Unified Diff</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setDiffViewMode(prev => ({ ...prev, [patch.id]: 'side-by-side' }))}
                      className={`px-3 py-1.5 text-xs font-bold transition-all border-b-2 cursor-pointer flex items-center gap-1.5 ${
                        currentTab === 'side-by-side'
                          ? 'border-[#00FF41] text-[#00FF41]'
                          : 'border-transparent text-zinc-400 hover:text-white'
                      }`}
                    >
                      <ArrowLeftRight className="w-3.5 h-3.5" />
                      <span>Lado a Lado (Antes vs Depois)</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setDiffViewMode(prev => ({ ...prev, [patch.id]: 'code' }))}
                      className={`px-3 py-1.5 text-xs font-bold transition-all border-b-2 cursor-pointer flex items-center gap-1.5 ${
                        currentTab === 'code'
                          ? 'border-[#00FF41] text-[#00FF41]'
                          : 'border-transparent text-zinc-400 hover:text-white'
                      }`}
                    >
                      <FileText className="w-3.5 h-3.5" />
                      <span>Código Seguro Sanitizado</span>
                    </button>

                    {patch.envConfig && (
                      <button
                        type="button"
                        onClick={() => setDiffViewMode(prev => ({ ...prev, [patch.id]: 'env' }))}
                        className={`px-3 py-1.5 text-xs font-bold transition-all border-b-2 cursor-pointer flex items-center gap-1.5 ${
                          currentTab === 'env'
                            ? 'border-amber-400 text-amber-400'
                            : 'border-transparent text-zinc-400 hover:text-white'
                        }`}
                      >
                        <KeyRound className="w-3.5 h-3.5" />
                        <span>Variável .env</span>
                      </button>
                    )}

                    {patch.securityChecklist && patch.securityChecklist.length > 0 && (
                      <button
                        type="button"
                        onClick={() => setDiffViewMode(prev => ({ ...prev, [patch.id]: 'checklist' }))}
                        className={`px-3 py-1.5 text-xs font-bold transition-all border-b-2 cursor-pointer flex items-center gap-1.5 ${
                          currentTab === 'checklist'
                            ? 'border-cyan-400 text-cyan-400'
                            : 'border-transparent text-zinc-400 hover:text-white'
                        }`}
                      >
                        <ListChecks className="w-3.5 h-3.5" />
                        <span>Checklist ({patch.securityChecklist.length})</span>
                      </button>
                    )}
                  </div>

                  <span className="text-[11px] text-zinc-500 hidden sm:inline">
                    Linha {patch.line} em {patch.file}
                  </span>
                </div>

                {/* Tab Contents */}
                <div className="p-4 sm:p-5 bg-[#020502]">
                  {/* TAB 1: Unified Git Diff */}
                  {currentTab === 'diff' && (
                    <pre className="p-4 bg-black rounded-lg text-xs overflow-x-auto border border-zinc-800/80 font-mono leading-relaxed">
                      <code>
                        {patch.unifiedDiff.split('\n').map((line, idx) => {
                          const isMinus = line.startsWith('-');
                          const isPlus = line.startsWith('+');
                          const isHeader = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++');

                          return (
                            <div
                              key={idx}
                              className={`py-0.5 px-2 rounded-sm ${
                                isMinus
                                  ? 'text-rose-300 bg-rose-950/40 border-l-2 border-rose-500'
                                  : isPlus
                                  ? 'text-emerald-200 bg-emerald-950/50 border-l-2 border-emerald-400 font-bold'
                                  : isHeader
                                  ? 'text-cyan-400/90 font-semibold'
                                  : 'text-zinc-400'
                              }`}
                            >
                              {line}
                            </div>
                          );
                        })}
                      </code>
                    </pre>
                  )}

                  {/* TAB 2: Side-by-Side Comparison */}
                  {currentTab === 'side-by-side' && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="p-3.5 bg-[#0e0505] border border-rose-900/40 rounded-lg space-y-2">
                        <div className="flex items-center justify-between text-[11px] font-bold text-rose-400 uppercase tracking-wider pb-1 border-b border-rose-900/30">
                          <span>Código Vulnerável (Antes)</span>
                          <span className="text-rose-500 text-[10px]">CWE Inseguro</span>
                        </div>
                        <pre className="text-xs text-rose-300 font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">
                          {patch.originalSnippet}
                        </pre>
                      </div>

                      <div className="p-3.5 bg-[#041006] border border-emerald-800/40 rounded-lg space-y-2">
                        <div className="flex items-center justify-between text-[11px] font-bold text-emerald-400 uppercase tracking-wider pb-1 border-b border-emerald-900/30">
                          <span>Código Sanitizado por IA (Depois)</span>
                          <span className="text-emerald-500 text-[10px]">Padrão Seguro</span>
                        </div>
                        <pre className="text-xs text-emerald-300 font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed font-bold">
                          {patch.replacementSnippet}
                        </pre>
                      </div>
                    </div>
                  )}

                  {/* TAB 3: Safe Code Ready to Copy */}
                  {currentTab === 'code' && (
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-zinc-400">Código gerado para substituição:</span>
                        <button
                          type="button"
                          onClick={() => handleCopyText(patch.replacementSnippet, `code-${patch.id}`)}
                          className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-xs flex items-center gap-1 cursor-pointer"
                        >
                          {copiedId === `code-${patch.id}` ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedId === `code-${patch.id}` ? 'Copiado!' : 'Copiar Trecho'}</span>
                        </button>
                      </div>
                      <pre className="p-4 bg-black rounded-lg text-xs text-[#00FF41] border border-zinc-800 overflow-x-auto font-mono">
                        <code>{patch.replacementSnippet}</code>
                      </pre>
                    </div>
                  )}

                  {/* TAB 4: Environment Variable Config */}
                  {currentTab === 'env' && patch.envConfig && (
                    <div className="p-4 bg-zinc-900/70 border border-amber-900/40 rounded-lg space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-amber-400 font-bold text-xs">
                          <KeyRound className="w-4 h-4" />
                          <span>Parâmetro de Ambiente Requerido:</span>
                        </div>
                        <button
                          type="button"
                          onClick={() => handleCopyText(patch.envConfig!.exampleLine, `env-${patch.id}`)}
                          className="px-2.5 py-1 rounded bg-black/60 hover:bg-black text-xs text-zinc-300 flex items-center gap-1 cursor-pointer border border-zinc-700"
                        >
                          {copiedId === `env-${patch.id}` ? <Check className="w-3 h-3 text-amber-400" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedId === `env-${patch.id}` ? 'Copiado!' : 'Copiar Linha'}</span>
                        </button>
                      </div>

                      <pre className="p-3 bg-black rounded text-xs text-amber-200 border border-zinc-800 font-mono">
                        <code>{patch.envConfig.exampleLine}</code>
                      </pre>

                      <p className="text-xs text-zinc-400">
                        {patch.envConfig.instructions}
                      </p>
                    </div>
                  )}

                  {/* TAB 5: AI Post-Remediation Checklist */}
                  {currentTab === 'checklist' && patch.securityChecklist && (
                    <div className="p-4 bg-black/60 border border-zinc-800 rounded-lg space-y-2.5">
                      <div className="flex items-center gap-2 text-xs font-bold text-cyan-400 uppercase tracking-wider">
                        <ListChecks className="w-4 h-4" />
                        <span>Passos Recomendados pela IA para Encerramento do Incidente:</span>
                      </div>
                      <ul className="space-y-1.5 text-xs text-zinc-300">
                        {patch.securityChecklist.map((item, idx) => (
                          <li key={idx} className="flex items-start gap-2">
                            <span className="text-[#00FF41] mt-0.5">•</span>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
