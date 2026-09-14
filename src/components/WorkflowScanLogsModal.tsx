import React, { useState, useMemo, useEffect } from 'react';
import { 
  X, 
  Terminal, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  GitBranch, 
  GitCommit, 
  Copy, 
  Check, 
  Download, 
  Search, 
  ShieldAlert, 
  ExternalLink,
  ChevronRight,
  Filter,
  RefreshCw,
  Layers,
  ArrowUpRight
} from 'lucide-react';
import { WorkflowRun, WorkflowLogStep, ScanFinding } from '../types';
import { safeCopyText } from '../lib/storage';

interface WorkflowScanLogsModalProps {
  run: WorkflowRun | null;
  isOpen: boolean;
  onClose: () => void;
  onSelectFinding?: (finding: ScanFinding) => void;
  allFindings?: ScanFinding[];
}

export const WorkflowScanLogsModal: React.FC<WorkflowScanLogsModalProps> = ({
  run,
  isOpen,
  onClose,
  onSelectFinding,
  allFindings = []
}) => {
  const [selectedStepId, setSelectedStepId] = useState<string>('all');
  const [logLevelFilter, setLogLevelFilter] = useState<'ALL' | 'ERROR' | 'WARN' | 'INFO'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedLogs, setCopiedLogs] = useState(false);
  const [copiedSha, setCopiedSha] = useState(false);

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Reset filter when run changes
  useEffect(() => {
    setSelectedStepId('all');
    setLogLevelFilter('ALL');
    setSearchQuery('');
  }, [run?.id]);

  if (!isOpen || !run) return null;

  const isSuccess = run.conclusion === 'success';
  const isFailure = run.conclusion === 'failure';

  const handleCopyLogs = async () => {
    const textToCopy = run.rawLogs || run.steps.flatMap(s => s.lines.map(l => `[${l.timestamp}] [${l.level}] ${l.message}`)).join('\n');
    const ok = await safeCopyText(textToCopy);
    if (ok) {
      setCopiedLogs(true);
      setTimeout(() => setCopiedLogs(false), 2000);
    }
  };

  const handleCopySha = async () => {
    const ok = await safeCopyText(run.commitSha);
    if (ok) {
      setCopiedSha(true);
      setTimeout(() => setCopiedSha(false), 2000);
    }
  };

  const handleDownloadLogFile = () => {
    const textContent = run.rawLogs || run.steps.flatMap(s => s.lines.map(l => `[${l.timestamp}] [${l.level}] ${l.message}`)).join('\n');
    const blob = new Blob([textContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secscan-github-actions-run-${run.runNumber}-${run.commitSha.slice(0, 7)}.log`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Compile active lines based on active step selection and filters
  const displayedLines = useMemo(() => {
    let sourceLines = selectedStepId === 'all'
      ? run.steps.flatMap(step => step.lines.map(l => ({ ...l, stepName: step.name })))
      : (run.steps.find(s => s.id === selectedStepId)?.lines || []).map(l => ({ 
          ...l, 
          stepName: run.steps.find(s => s.id === selectedStepId)?.name || '' 
        }));

    if (logLevelFilter !== 'ALL') {
      sourceLines = sourceLines.filter(l => l.level === logLevelFilter);
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      sourceLines = sourceLines.filter(l => 
        l.message.toLowerCase().includes(q) || 
        l.timestamp.toLowerCase().includes(q) ||
        l.level.toLowerCase().includes(q)
      );
    }

    return sourceLines;
  }, [run, selectedStepId, logLevelFilter, searchQuery]);

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200"
      onClick={onClose}
    >
      <div 
        className="bg-[#0D0D0D] border-2 border-[#333] w-full max-w-6xl max-h-[92vh] flex flex-col shadow-[0_0_50px_rgba(0,0,0,0.9)] overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top Header Bar */}
        <div className="bg-[#141414] border-b border-[#2A2A2A] p-4 sm:p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="space-y-1.5 flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[10px] font-mono px-2 py-0.5 bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/30 font-black uppercase tracking-widest flex items-center gap-1">
                <Terminal className="w-3 h-3" />
                GITHUB ACTIONS WORKFLOW LOGS
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 bg-[#1F1F1F] text-zinc-300 border border-[#333]">
                Run #{run.runNumber}
              </span>
              <span className={`text-[10px] font-mono px-2 py-0.5 border font-bold flex items-center gap-1 ${
                isSuccess 
                  ? 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/30' 
                  : isFailure
                  ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40'
                  : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
              }`}>
                {isSuccess && <CheckCircle2 className="w-3 h-3 text-[#00FF41]" />}
                {isFailure && <AlertTriangle className="w-3 h-3 text-[#FF3E00]" />}
                {run.conclusion ? run.conclusion.toUpperCase() : run.status.toUpperCase()}
              </span>
              <span className="text-[10px] font-mono text-zinc-400 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {run.durationSeconds}s
              </span>
            </div>

            <h2 className="text-base sm:text-lg font-bold text-white truncate flex items-center gap-2">
              <span>{run.title}</span>
            </h2>

            <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-zinc-400">
              <span className="flex items-center gap-1">
                <GitBranch className="w-3.5 h-3.5 text-zinc-500" />
                <span className="text-zinc-200 font-semibold">{run.branch}</span>
              </span>
              <span>•</span>
              <button 
                onClick={handleCopySha}
                className="flex items-center gap-1 text-zinc-400 hover:text-white transition-colors cursor-pointer group"
                title="Copiar Commit SHA"
              >
                <GitCommit className="w-3.5 h-3.5 text-zinc-500" />
                <span className="font-mono text-[#00FF41]">{run.commitSha.slice(0, 7)}</span>
                {copiedSha ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3 text-zinc-500 group-hover:text-white" />}
              </button>
              <span>•</span>
              <span>Trigger: <strong className="text-zinc-200 uppercase">{run.event}</strong></span>
              <span>•</span>
              <span>Ator: <strong className="text-zinc-200">{run.actor.name}</strong></span>
              <span>•</span>
              <span>Workflow: <span className="text-[#00E5FF]">{run.workflowFile}</span></span>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0 self-end md:self-center">
            <button
              onClick={handleCopyLogs}
              className="px-3 py-2 bg-[#1E1E1E] hover:bg-[#2A2A2A] text-zinc-200 border border-[#333] text-xs font-mono font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Copiar log completo para área de transferência"
            >
              {copiedLogs ? (
                <>
                  <Check className="w-3.5 h-3.5 text-[#00FF41]" />
                  <span className="text-[#00FF41]">Copiado!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Copiar Log</span>
                </>
              )}
            </button>

            <button
              onClick={handleDownloadLogFile}
              className="px-3 py-2 bg-[#1E1E1E] hover:bg-[#2A2A2A] text-zinc-200 border border-[#333] text-xs font-mono font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Baixar arquivo de log bruto (.log)"
            >
              <Download className="w-3.5 h-3.5 text-[#00FF41]" />
              <span>Baixar .log</span>
            </button>

            <button
              onClick={onClose}
              className="p-2 hover:bg-[#222] text-zinc-400 hover:text-white transition-colors cursor-pointer"
              title="Fechar (Esc)"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Workflow Steps Horizontal Bar */}
        <div className="bg-[#111] border-b border-[#222] p-2.5 flex items-center gap-2 overflow-x-auto text-xs font-mono">
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold px-2 shrink-0 flex items-center gap-1">
            <Layers className="w-3 h-3" />
            Etapas:
          </span>

          <button
            onClick={() => setSelectedStepId('all')}
            className={`px-3 py-1.5 border text-xs font-bold transition-all shrink-0 cursor-pointer flex items-center gap-1.5 ${
              selectedStepId === 'all'
                ? 'bg-white text-black border-white'
                : 'bg-[#181818] text-zinc-400 border-[#2D2D2D] hover:border-zinc-500 hover:text-white'
            }`}
          >
            <span>Todos os Passos ({run.steps.length})</span>
          </button>

          {run.steps.map((step, idx) => {
            const isStepActive = selectedStepId === step.id;
            const isStepFailed = step.status === 'failed';

            return (
              <button
                key={step.id}
                onClick={() => setSelectedStepId(step.id)}
                className={`px-2.5 py-1.5 border text-xs transition-all shrink-0 cursor-pointer flex items-center gap-1.5 ${
                  isStepActive
                    ? isStepFailed
                      ? 'bg-[#FF3E00] text-white border-[#FF3E00]'
                      : 'bg-[#00FF41] text-black border-[#00FF41] font-black'
                    : isStepFailed
                    ? 'bg-[#2A0800] text-[#FF3E00] border-[#FF3E00]/40 hover:bg-[#3D0C00]'
                    : 'bg-[#181818] text-zinc-300 border-[#2D2D2D] hover:border-zinc-500 hover:text-white'
                }`}
              >
                <span className="opacity-60 text-[10px]">{idx + 1}.</span>
                <span className="font-medium truncate max-w-[170px]">{step.name}</span>
                <span className={`text-[10px] ${isStepActive ? 'opacity-90' : 'text-zinc-500'}`}>
                  {step.durationSeconds}s
                </span>
                {isStepFailed && <AlertTriangle className="w-3 h-3 text-[#FF3E00] shrink-0" />}
              </button>
            );
          })}
        </div>

        {/* Filter & Search Bar */}
        <div className="bg-[#121212] border-b border-[#222] p-3 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2 flex-1 min-w-[240px]">
            <div className="relative w-full max-w-md">
              <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filtrar mensagens de log, regras ou arquivos..."
                className="w-full pl-9 pr-8 py-1.5 bg-[#080808] border border-[#2D2D2D] text-zinc-200 text-xs placeholder:text-zinc-600 focus:outline-none focus:border-[#00FF41]"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-white"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold flex items-center gap-1">
              <Filter className="w-3 h-3" />
              Nível:
            </span>

            {(['ALL', 'ERROR', 'WARN', 'INFO'] as const).map(lvl => (
              <button
                key={lvl}
                onClick={() => setLogLevelFilter(lvl)}
                className={`px-2.5 py-1 text-[11px] font-bold border transition-colors cursor-pointer ${
                  logLevelFilter === lvl
                    ? lvl === 'ERROR'
                      ? 'bg-[#FF3E00] text-white border-[#FF3E00]'
                      : lvl === 'WARN'
                      ? 'bg-amber-400 text-black border-amber-400'
                      : lvl === 'INFO'
                      ? 'bg-[#00FF41] text-black border-[#00FF41]'
                      : 'bg-white text-black border-white'
                    : 'bg-[#181818] text-zinc-400 border-[#2D2D2D] hover:text-white'
                }`}
              >
                {lvl}
              </button>
            ))}

            <span className="text-[10px] text-zinc-500 ml-2">
              {displayedLines.length} linha(s)
            </span>
          </div>
        </div>

        {/* Quality Gate Diagnostic Banner inside Log Modal */}
        {isFailure && (
          <div className="bg-[#240500] border-b border-[#FF3E00]/40 p-3 px-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono text-[#FF8533]">
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="w-4 h-4 text-[#FF3E00] shrink-0 animate-pulse" />
              <div>
                <strong className="text-white uppercase font-bold">Falha no Quality Gate: </strong>
                <span>
                  O job encerrou com <strong className="text-[#FF3E00]">Exit Code 1</strong>. Foram identificados {run.findingsCount.critical} achados críticos e {run.findingsCount.total} vulnerabilidades totais.
                </span>
              </div>
            </div>

            <div className="text-[10px] text-zinc-400 shrink-0">
              Teto de Risco: <strong>{run.riskScore} pts</strong>
            </div>
          </div>
        )}

        {/* Terminal Log Console Body */}
        <div className="flex-1 overflow-y-auto p-4 bg-[#050505] font-mono text-xs text-zinc-300 leading-relaxed selection:bg-[#00FF41]/30 selection:text-white space-y-1">
          {displayedLines.length === 0 ? (
            <div className="py-16 text-center text-zinc-500 space-y-2">
              <Terminal className="w-8 h-8 mx-auto text-zinc-600 mb-2" />
              <p>Nenhuma linha encontrada para o filtro selecionado.</p>
              <button
                onClick={() => {
                  setSelectedStepId('all');
                  setLogLevelFilter('ALL');
                  setSearchQuery('');
                }}
                className="text-xs text-[#00FF41] hover:underline"
              >
                Limpar todos os filtros
              </button>
            </div>
          ) : (
            displayedLines.map((line, idx) => {
              const isErr = line.level === 'ERROR';
              const isWarn = line.level === 'WARN';
              const isInfo = line.level === 'INFO';

              // If line has findingId, find matched finding in workspace
              const matchedFinding = line.findingId 
                ? allFindings.find(f => f.id === line.findingId) 
                : null;

              return (
                <div 
                  key={idx}
                  className={`group flex items-start gap-2.5 py-0.5 px-2 hover:bg-[#141414] transition-colors rounded ${
                    line.highlight 
                      ? 'bg-[#FF3E00]/10 border-l-2 border-[#FF3E00]' 
                      : ''
                  }`}
                >
                  <span className="text-zinc-600 select-none text-[10px] w-9 text-right shrink-0 pt-0.5">
                    {idx + 1}
                  </span>

                  <span className="text-zinc-500 select-none text-[10px] shrink-0 pt-0.5">
                    {line.timestamp.slice(11, 19)}
                  </span>

                  <span className={`text-[10px] font-bold px-1.5 py-0 rounded shrink-0 uppercase ${
                    isErr 
                      ? 'bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/30' 
                      : isWarn 
                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' 
                      : 'bg-zinc-800 text-zinc-400'
                  }`}>
                    {line.level}
                  </span>

                  <span className={`flex-1 break-all ${
                    isErr 
                      ? 'text-[#FF7A00] font-semibold' 
                      : isWarn 
                      ? 'text-amber-300' 
                      : 'text-zinc-300'
                  }`}>
                    {line.message}
                  </span>

                  {/* Deep link button if this log line is linked to a vulnerability finding */}
                  {matchedFinding && onSelectFinding && (
                    <button
                      onClick={() => {
                        onSelectFinding(matchedFinding);
                        onClose();
                      }}
                      className="opacity-0 group-hover:opacity-100 transition-opacity px-2 py-0.5 bg-[#FF3E00] text-black text-[9px] font-black uppercase flex items-center gap-1 hover:bg-white cursor-pointer shrink-0"
                      title="Auditar achado no Scanner do SecScan"
                    >
                      <span>Auditar</span>
                      <ArrowUpRight className="w-2.5 h-2.5" />
                    </button>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Footer info strip */}
        <div className="bg-[#111] border-t border-[#222] p-3 px-5 flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-zinc-400">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#00FF41] animate-ping" />
            <span>Runner: <strong className="text-white">ubuntu-latest</strong></span>
            <span className="text-zinc-600">|</span>
            <span>SARIF Upload: <strong className={run.sarifUploaded ? 'text-[#00FF41]' : 'text-zinc-500'}>{run.sarifUploaded ? 'OK (CodeQL)' : 'NÃO'}</strong></span>
            <span className="text-zinc-600">|</span>
            <span>Achados: <strong className="text-white">{run.findingsCount.total}</strong> ({run.findingsCount.critical} Críticos)</span>
          </div>

          <div className="flex items-center gap-3">
            <span className="text-[11px] text-zinc-500">
              Log capturado via GitHub Actions API v3
            </span>
            <button
              onClick={onClose}
              className="px-4 py-1.5 bg-white text-black hover:bg-zinc-200 font-bold text-xs uppercase tracking-wider transition-colors cursor-pointer"
            >
              Fechar
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
