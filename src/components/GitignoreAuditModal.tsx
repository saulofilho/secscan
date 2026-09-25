import React, { useState, useMemo, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  AlertOctagon, 
  FileText, 
  Copy, 
  Check, 
  Download, 
  X, 
  Search, 
  Filter, 
  FolderLock, 
  KeyRound, 
  Database, 
  FileCode, 
  Terminal, 
  RefreshCw, 
  CheckCircle2, 
  ExternalLink,
  PlusCircle,
  Eye,
  Server,
  Laptop
} from 'lucide-react';
import { ScannedFile } from '../types';
import { 
  auditGitignoreSecurity, 
  GitignoreAuditResult, 
  IgnoredFileAuditItem,
  SECURITY_BEST_PRACTICE_RULES
} from '../lib/gitignoreAuditor';

interface GitignoreAuditModalProps {
  isOpen: boolean;
  onClose: () => void;
  files: ScannedFile[];
  onApplyGitignoreToWorkspace?: (gitignoreContent: string) => void;
  onRemoveFileFromWorkspace?: (fileName: string) => void;
}

export const GitignoreAuditModal: React.FC<GitignoreAuditModalProps> = ({
  isOpen,
  onClose,
  files,
  onApplyGitignoreToWorkspace,
  onRemoveFileFromWorkspace
}) => {
  const [activeTab, setActiveTab] = useState<'FILES' | 'RULES' | 'PREVIEW'>('FILES');
  const [sourceMode, setSourceMode] = useState<'WORKSPACE' | 'DISK'>('WORKSPACE');
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'UNPROTECTED' | 'COVERED'>('ALL');
  const [isCopied, setIsCopied] = useState(false);
  const [isAppendingCopied, setIsAppendingCopied] = useState(false);
  const [appliedNotification, setAppliedNotification] = useState<string | null>(null);
  const [diskAuditResult, setDiskAuditResult] = useState<GitignoreAuditResult | null>(null);
  const [isLoadingDisk, setIsLoadingDisk] = useState(false);
  const [diskError, setDiskError] = useState<string | null>(null);

  // 1. Audit local workspace files
  const workspaceAuditResult = useMemo(() => {
    return auditGitignoreSecurity({
      files,
      source: 'WORKSPACE'
    });
  }, [files]);

  // Fetch disk repository audit from server API
  const fetchDiskAudit = async () => {
    setIsLoadingDisk(true);
    setDiskError(null);
    try {
      const response = await fetch('/api/gitignore/audit');
      const contentType = response.headers.get('content-type') || '';
      if (!response.ok || !contentType.includes('application/json')) {
        throw new Error(`Servidor indisponível ou resposta não formatada em JSON.`);
      }
      const data: GitignoreAuditResult = await response.json();
      setDiskAuditResult(data);
    } catch (err: any) {
      setDiskError(err.message || 'Falha ao conectar à API do servidor.');
    } finally {
      setIsLoadingDisk(false);
    }
  };

  useEffect(() => {
    if (isOpen && sourceMode === 'DISK' && !diskAuditResult) {
      fetchDiskAudit();
    }
  }, [isOpen, sourceMode]);

  const activeResult: GitignoreAuditResult = (sourceMode === 'DISK' && diskAuditResult) 
    ? diskAuditResult 
    : workspaceAuditResult;

  // Filtered files
  const filteredFiles = useMemo(() => {
    return activeResult.ignoredFiles.filter(item => {
      const matchesSearch = 
        item.fileName.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.filePath.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.categoryTitle.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.suggestedRule.toLowerCase().includes(searchQuery.toLowerCase());

      if (!matchesSearch) return false;

      if (statusFilter === 'UNPROTECTED') return !item.isCoveredByGitignore;
      if (statusFilter === 'COVERED') return item.isCoveredByGitignore;
      return true;
    });
  }, [activeResult, searchQuery, statusFilter]);

  if (!isOpen) return null;

  const handleCopyRecommended = () => {
    navigator.clipboard.writeText(activeResult.recommendedGitignore);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2500);
  };

  const handleCopyMissingRules = () => {
    navigator.clipboard.writeText(activeResult.missingRulesToAppend || activeResult.recommendedGitignore);
    setIsAppendingCopied(true);
    setTimeout(() => setIsAppendingCopied(false), 2500);
  };

  const handleDownloadGitignore = () => {
    const blob = new Blob([activeResult.recommendedGitignore], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = '.gitignore';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleApplyToWorkspace = () => {
    if (onApplyGitignoreToWorkspace) {
      onApplyGitignoreToWorkspace(activeResult.recommendedGitignore);
      setAppliedNotification('.gitignore padronizado foi adicionado com sucesso ao seu workspace de análise!');
      setTimeout(() => setAppliedNotification(null), 4000);
    }
  };

  const getStatusBadge = () => {
    if (activeResult.status === 'VALID') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-xs font-semibold">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          <span>.gitignore Válido ({activeResult.stats.securityScore}%)</span>
        </span>
      );
    }
    if (activeResult.status === 'INCOMPLETE') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 text-xs font-semibold">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          <span>.gitignore Incompleto ({activeResult.stats.securityScore}%)</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40 text-xs font-semibold">
        <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
        <span>.gitignore Ausente (0%)</span>
      </span>
    );
  };

  const getSeverityBadge = (severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW') => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[10px] font-mono font-bold">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-300 border border-orange-500/30 text-[10px] font-mono font-bold">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[10px] font-mono">MEDIUM</span>;
      default:
        return <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 text-[10px] font-mono">LOW</span>;
    }
  };

  return (
    <div 
      id="modal-gitignore-security-audit"
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-black/80 backdrop-blur-sm animate-fade-in"
      onClick={onClose}
    >
      <div 
        className="relative w-full max-w-5xl max-h-[92vh] flex flex-col rounded-2xl bg-[#0d1117] border border-white/15 shadow-2xl overflow-hidden text-zinc-100"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-black/40">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-indigo-500/20 border border-indigo-500/30 text-indigo-300">
              <FolderLock className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h2 className="text-lg font-bold text-white tracking-tight">Auditoria de .gitignore & Práticas de Segurança</h2>
                {getStatusBadge()}
              </div>
              <p className="text-xs text-zinc-400 mt-0.5">
                Validação de arquivos sensíveis no diretório de trabalho que deveriam ser ignorados para evitar vazamento em commits.
              </p>
            </div>
          </div>

          <button
            id="btn-close-gitignore-audit"
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-white/10 transition-colors"
            title="Fechar modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Source Switcher & Notification */}
        <div className="px-6 py-2.5 bg-zinc-900/60 border-b border-white/5 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-zinc-400 font-medium">Alvo de Auditoria:</span>
            <div className="inline-flex rounded-lg bg-black/50 p-1 border border-white/10">
              <button
                type="button"
                onClick={() => setSourceMode('WORKSPACE')}
                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-all ${
                  sourceMode === 'WORKSPACE'
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                <Laptop className="w-3.5 h-3.5" />
                <span>Workspace Atual ({files.length} arquivos)</span>
              </button>

              <button
                type="button"
                onClick={() => setSourceMode('DISK')}
                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-all ${
                  sourceMode === 'DISK'
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                <Server className="w-3.5 h-3.5" />
                <span>Repositório no Disco (Servidor)</span>
              </button>
            </div>

            {sourceMode === 'DISK' && (
              <button
                type="button"
                onClick={fetchDiskAudit}
                disabled={isLoadingDisk}
                className="p-1.5 rounded-md hover:bg-white/10 text-zinc-400 hover:text-white transition-colors"
                title="Recarregar arquivos do disco"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoadingDisk ? 'animate-spin text-indigo-400' : ''}`} />
              </button>
            )}
          </div>

          <div className="text-xs text-zinc-400 font-mono">
            {activeResult.summaryMessage}
          </div>
        </div>

        {appliedNotification && (
          <div className="px-6 py-2 bg-emerald-950/80 border-b border-emerald-500/30 text-emerald-200 text-xs flex items-center justify-between animate-fade-in">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>{appliedNotification}</span>
            </div>
            <button onClick={() => setAppliedNotification(null)} className="text-emerald-400 hover:text-emerald-200">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {diskError && sourceMode === 'DISK' && (
          <div className="px-6 py-2 bg-rose-950/80 border-b border-rose-500/30 text-rose-200 text-xs flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-rose-400" />
            <span>Erro ao inspecionar disco: {diskError}</span>
          </div>
        )}

        {/* KPI Metric Cards */}
        <div className="px-6 py-4 grid grid-cols-2 sm:grid-cols-4 gap-3 bg-black/20 border-b border-white/5">
          {/* Status */}
          <div className="p-3 rounded-xl bg-white/[0.03] border border-white/5 space-y-1">
            <div className="text-[11px] text-zinc-400 font-medium">Status do .gitignore</div>
            <div className="text-sm font-bold text-white flex items-center gap-1.5">
              {activeResult.hasGitignore ? (
                <>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>Presente ({activeResult.currentRulesCount} regras)</span>
                </>
              ) : (
                <>
                  <AlertOctagon className="w-4 h-4 text-rose-400" />
                  <span>Não Encontrado</span>
                </>
              )}
            </div>
            <div className="text-[10px] text-zinc-500">
              Pontuação de Higiene: <strong className="text-zinc-300">{activeResult.stats.securityScore}/100</strong>
            </div>
          </div>

          {/* Unprotected sensitive files */}
          <div className={`p-3 rounded-xl border space-y-1 ${
            activeResult.stats.unprotectedExposedCount > 0 
              ? 'bg-rose-500/10 border-rose-500/30 text-rose-200' 
              : 'bg-white/[0.03] border-white/5'
          }`}>
            <div className="text-[11px] text-zinc-400 font-medium">Arquivos Desprotegidos</div>
            <div className="text-sm font-bold flex items-center gap-1.5">
              {activeResult.stats.unprotectedExposedCount > 0 ? (
                <>
                  <AlertTriangle className="w-4 h-4 text-rose-400 animate-pulse" />
                  <span className="text-rose-300">{activeResult.stats.unprotectedExposedCount} Arquivo(s) Expostos</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span className="text-emerald-300">0 em Risco</span>
                </>
              )}
            </div>
            <div className="text-[10px] text-zinc-400">
              {activeResult.stats.unprotectedExposedCount > 0 ? 'Seriam comitados por "git add ."' : 'Nenhum segredo sem gitignore'}
            </div>
          </div>

          {/* Protected / Covered files */}
          <div className="p-3 rounded-xl bg-white/[0.03] border border-white/5 space-y-1">
            <div className="text-[11px] text-zinc-400 font-medium">Arquivos Protegidos</div>
            <div className="text-sm font-bold text-white flex items-center gap-1.5">
              <Check className="w-4 h-4 text-emerald-400" />
              <span>{activeResult.stats.properlyCoveredCount} Arquivo(s)</span>
            </div>
            <div className="text-[10px] text-zinc-500">
              Cobertos pelo .gitignore atual
            </div>
          </div>

          {/* Categories covered */}
          <div className="p-3 rounded-xl bg-white/[0.03] border border-white/5 space-y-1">
            <div className="text-[11px] text-zinc-400 font-medium">Categorias Cobertas</div>
            <div className="text-sm font-bold text-white flex items-center gap-1.5">
              <KeyRound className="w-4 h-4 text-indigo-400" />
              <span>
                {activeResult.categoriesCoverage.filter(c => c.isCovered).length} / {activeResult.categoriesCoverage.length}
              </span>
            </div>
            <div className="text-[10px] text-zinc-500">
              {activeResult.missingCriticalCategories.length > 0 ? (
                <span className="text-amber-400">{activeResult.missingCriticalCategories.length} críticas faltando</span>
              ) : (
                <span className="text-emerald-400">100% de cobertura crítica</span>
              )}
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="px-6 border-b border-white/10 flex items-center gap-6 bg-zinc-900/40 text-xs font-medium">
          <button
            type="button"
            onClick={() => setActiveTab('FILES')}
            className={`py-3 border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'FILES'
                ? 'border-indigo-500 text-white font-semibold'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <FileCode className="w-4 h-4" />
            <span>Arquivos no Diretório de Trabalho ({activeResult.ignoredFiles.length})</span>
            {activeResult.stats.unprotectedExposedCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full bg-rose-500 text-white text-[10px] font-bold">
                {activeResult.stats.unprotectedExposedCount}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('RULES')}
            className={`py-3 border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'RULES'
                ? 'border-indigo-500 text-white font-semibold'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <ShieldCheck className="w-4 h-4" />
            <span>Checklist de Boas Práticas (OWASP / GitHub)</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('PREVIEW')}
            className={`py-3 border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'PREVIEW'
                ? 'border-indigo-500 text-white font-semibold'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Modelo .gitignore Padrão Ouro</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6">
          {/* TAB 1: FILES LIST */}
          {activeTab === 'FILES' && (
            <div className="space-y-4">
              {/* Search and Filters */}
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="relative flex-1 min-w-[240px]">
                  <Search className="w-4 h-4 text-zinc-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    placeholder="Filtrar por nome de arquivo, caminho ou categoria..."
                    className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-black/40 border border-white/10 text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-indigo-500"
                  />
                  {searchQuery && (
                    <button onClick={() => setSearchQuery('')} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-white">
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>

                <div className="flex items-center gap-1.5 text-xs">
                  <span className="text-zinc-400 font-mono text-[11px]">Exibir:</span>
                  <button
                    type="button"
                    onClick={() => setStatusFilter('ALL')}
                    className={`px-2.5 py-1 rounded-md transition-colors ${
                      statusFilter === 'ALL' ? 'bg-indigo-600 text-white font-medium' : 'bg-white/5 text-zinc-400 hover:text-white'
                    }`}
                  >
                    Todos ({activeResult.ignoredFiles.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setStatusFilter('UNPROTECTED')}
                    className={`px-2.5 py-1 rounded-md transition-colors ${
                      statusFilter === 'UNPROTECTED' ? 'bg-rose-600 text-white font-medium' : 'bg-white/5 text-zinc-400 hover:text-white'
                    }`}
                  >
                    Desprotegidos ({activeResult.stats.unprotectedExposedCount})
                  </button>
                  <button
                    type="button"
                    onClick={() => setStatusFilter('COVERED')}
                    className={`px-2.5 py-1 rounded-md transition-colors ${
                      statusFilter === 'COVERED' ? 'bg-emerald-600 text-white font-medium' : 'bg-white/5 text-zinc-400 hover:text-white'
                    }`}
                  >
                    Ignorados ({activeResult.stats.properlyCoveredCount})
                  </button>
                </div>
              </div>

              {/* Files Table / List */}
              {filteredFiles.length === 0 ? (
                <div className="p-12 text-center rounded-xl bg-black/30 border border-white/10 space-y-3">
                  <ShieldCheck className="w-12 h-12 text-emerald-400 mx-auto" />
                  <h3 className="text-sm font-bold text-white">Nenhum arquivo sensível pendente encontrado</h3>
                  <p className="text-xs text-zinc-400 max-w-md mx-auto">
                    {searchQuery 
                      ? 'Nenhum arquivo correspondeu aos filtros aplicados.' 
                      : 'O diretório de trabalho analisado não possui arquivos de credenciais, chaves ou logs que necessitem de regras no .gitignore.'}
                  </p>
                </div>
              ) : (
                <div className="space-y-2.5">
                  {filteredFiles.map((item) => {
                    const isExposed = !item.isCoveredByGitignore;
                    return (
                      <div 
                        key={item.id}
                        className={`p-3.5 rounded-xl border transition-all ${
                          isExposed 
                            ? 'bg-rose-950/20 border-rose-500/40 hover:border-rose-500/60' 
                            : 'bg-black/30 border-white/10 hover:border-white/20'
                        }`}
                      >
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div className="space-y-1 min-w-[260px] flex-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-mono text-sm font-bold text-white">{item.fileName}</span>
                              {getSeverityBadge(item.severity)}
                              <span className="px-2 py-0.5 rounded bg-white/5 text-zinc-300 text-[10px] font-medium border border-white/10">
                                {item.categoryTitle}
                              </span>
                              {isExposed ? (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 text-[10px] font-bold">
                                  <AlertTriangle className="w-3 h-3" />
                                  <span>DESPROTEGIDO (RISCO DE COMMIT)</span>
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px] font-medium">
                                  <Check className="w-3 h-3" />
                                  <span>IGNORADO (Regra: {item.coveredByRule || item.suggestedRule})</span>
                                </span>
                              )}
                            </div>

                            <div className="text-xs text-zinc-300 leading-relaxed">
                              {item.reason}
                            </div>

                            <div className="text-[11px] text-zinc-400 flex items-center gap-2">
                              <span>Caminho: <code className="font-mono text-indigo-300">{item.filePath}</code></span>
                              {item.fileSize !== undefined && item.fileSize > 0 && (
                                <span>• {(item.fileSize / 1024).toFixed(1)} KB</span>
                              )}
                            </div>
                          </div>

                          {/* Quick Action / Suggested Rule */}
                          <div className="flex flex-col items-end gap-1.5 text-right">
                            <div className="text-[10px] text-zinc-400">Regra de Segurança Recomendada:</div>
                            <code className="px-2 py-1 rounded bg-black/60 border border-white/15 text-xs font-mono text-emerald-300 font-bold">
                              {item.suggestedRule}
                            </code>

                            {isExposed && onRemoveFileFromWorkspace && sourceMode === 'WORKSPACE' && (
                              <button
                                type="button"
                                onClick={() => onRemoveFileFromWorkspace(item.fileName)}
                                className="mt-1 px-2 py-0.5 rounded text-[10px] text-rose-300 hover:text-white bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/30 transition-colors"
                              >
                                Remover do Workspace
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: RULES CHECKLIST */}
          {activeTab === 'RULES' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-indigo-950/30 border border-indigo-500/30 text-xs text-indigo-200 flex items-center justify-between">
                <div>
                  <h4 className="font-bold text-white text-sm mb-1">Checklist de Cobertura de Segurança do .gitignore</h4>
                  <p className="text-zinc-300">
                    O SecScan compara seu arquivo .gitignore contra 9 categorias críticas de proteção recomendadas pela OWASP e pelo GitHub Security Advisory.
                  </p>
                </div>
                <div className="text-right">
                  <div className="text-xl font-mono font-bold text-emerald-400">
                    {activeResult.categoriesCoverage.filter(c => c.isCovered).length} / {activeResult.categoriesCoverage.length}
                  </div>
                  <div className="text-[10px] text-zinc-400">Categorias Atendidas</div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {SECURITY_BEST_PRACTICE_RULES.map((rule) => {
                  const coverage = activeResult.categoriesCoverage.find(c => c.category === rule.category);
                  const isCovered = coverage?.isCovered ?? false;

                  return (
                    <div 
                      key={rule.id}
                      className={`p-4 rounded-xl border flex flex-col justify-between ${
                        isCovered 
                          ? 'bg-black/20 border-emerald-500/30' 
                          : 'bg-rose-950/15 border-rose-500/30'
                      }`}
                    >
                      <div className="space-y-2">
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            {isCovered ? (
                              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                            ) : (
                              <AlertOctagon className="w-4 h-4 text-rose-400 flex-shrink-0" />
                            )}
                            <h4 className="text-xs font-bold text-white">{rule.categoryTitle}</h4>
                          </div>
                          {getSeverityBadge(rule.severity)}
                        </div>

                        <p className="text-[11px] text-zinc-400 leading-relaxed">
                          {rule.securityReason}
                        </p>

                        <div className="space-y-1">
                          <div className="text-[10px] text-zinc-500 font-mono">Padrões essenciais:</div>
                          <div className="flex flex-wrap gap-1">
                            {rule.patterns.map(p => (
                              <code key={p} className="px-1.5 py-0.2 rounded bg-white/5 border border-white/10 text-[10px] text-zinc-300 font-mono">
                                {p}
                              </code>
                            ))}
                          </div>
                        </div>
                      </div>

                      <div className="mt-3 pt-3 border-t border-white/5 flex items-center justify-between text-[11px]">
                        <span className={`font-medium ${isCovered ? 'text-emerald-400' : 'text-rose-400'}`}>
                          {isCovered ? '✓ Protegido no .gitignore atual' : '✗ Regra ausente no repositório'}
                        </span>
                        {coverage?.matchedRules && coverage.matchedRules.length > 0 && (
                          <span className="text-zinc-400 font-mono text-[10px]">
                            Regra: {coverage.matchedRules.join(', ')}
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB 3: PREVIEW & EXPORT */}
          {activeTab === 'PREVIEW' && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h4 className="text-sm font-bold text-white">Modelo .gitignore Padronizado (Padrão Ouro de Segurança)</h4>
                  <p className="text-xs text-zinc-400">
                    Template completo que neutraliza o envio acidental de arquivos de ambiente, chaves privadas, dumps SQL e credenciais de nuvem.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleCopyRecommended}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-white text-xs font-semibold transition-colors cursor-pointer border border-white/20 shadow-sm"
                  >
                    {isCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-white/80" />}
                    <span>{isCopied ? 'Copiado!' : 'Copiar Template'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleDownloadGitignore}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold transition-colors cursor-pointer shadow-sm"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Baixar .gitignore</span>
                  </button>

                  {onApplyGitignoreToWorkspace && (
                    <button
                      type="button"
                      onClick={handleApplyToWorkspace}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors cursor-pointer shadow-sm"
                      title="Adicionar arquivo .gitignore diretamente ao workspace do SecScan"
                    >
                      <PlusCircle className="w-3.5 h-3.5" />
                      <span>Aplicar ao Workspace</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Code viewer */}
              <div className="relative rounded-xl bg-black/60 border border-white/10 overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2 bg-zinc-900/80 border-b border-white/10 text-xs font-mono text-zinc-400">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-3.5 h-3.5 text-indigo-400" />
                    <span>.gitignore (Hardened Security Standard)</span>
                  </div>
                  <span>{activeResult.recommendedGitignore.split('\n').length} linhas</span>
                </div>
                <pre className="p-4 text-xs font-mono text-zinc-200 overflow-x-auto max-h-[380px] leading-relaxed">
                  {activeResult.recommendedGitignore}
                </pre>
              </div>

              {/* Missing rules snippet if partial */}
              {activeResult.missingRulesToAppend && (
                <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 space-y-2">
                  <div className="flex items-center justify-between">
                    <h5 className="text-xs font-bold text-amber-300 flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4" />
                      <span>Regras que Faltam no seu .gitignore Atual:</span>
                    </h5>
                    <button
                      type="button"
                      onClick={handleCopyMissingRules}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 text-xs font-mono transition-colors"
                    >
                      {isAppendingCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{isAppendingCopied ? 'Copiado!' : 'Copiar Apenas Faltantes'}</span>
                    </button>
                  </div>
                  <pre className="p-3 rounded bg-black/50 border border-white/5 text-[11px] font-mono text-zinc-300 overflow-x-auto">
                    {activeResult.missingRulesToAppend}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-white/10 bg-black/40 flex items-center justify-between text-xs text-zinc-400">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[11px]">
              Verificação em conformidade com <strong>OWASP Top 10 A05:2021 (Security Misconfiguration)</strong>.
            </span>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-white font-medium transition-colors"
          >
            Concluído
          </button>
        </div>
      </div>
    </div>
  );
};
