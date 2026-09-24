import React, { useState, useMemo } from 'react';
import { 
  History, 
  Clock, 
  FileCode, 
  CheckCircle2, 
  AlertTriangle, 
  AlertOctagon, 
  ShieldAlert, 
  ShieldCheck, 
  ChevronDown, 
  ChevronUp, 
  ArrowUpRight,
  Filter,
  Layers,
  Sparkles,
  Info
} from 'lucide-react';
import { ScanReport, ScanFinding } from '../types';

interface ScanHistoryListProps {
  scanHistory: ScanReport[];
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToScanner?: () => void;
}

export const ScanHistoryList: React.FC<ScanHistoryListProps> = ({
  scanHistory = [],
  onSelectFinding,
  onNavigateToScanner
}) => {
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);
  const [sortOrder, setSortOrder] = useState<'NEWEST_FIRST' | 'OLDEST_FIRST'>('NEWEST_FIRST');

  // Sorted scan entries (limited to last 10 entries)
  const displayedScans = useMemo(() => {
    const list = [...scanHistory].slice(-10);
    if (sortOrder === 'NEWEST_FIRST') {
      return list.reverse();
    }
    return list;
  }, [scanHistory, sortOrder]);

  // Aggregate stats across the history
  const totalScans = scanHistory.length;
  const latestScan = scanHistory[scanHistory.length - 1];

  const formatTimestamp = (timestampStr: string): string => {
    if (!timestampStr) return 'N/A';
    try {
      // Check if it's an ISO date string or similar parseable date
      const date = new Date(timestampStr);
      if (!isNaN(date.getTime()) && timestampStr.includes('T')) {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' (' + date.toLocaleDateString() + ')';
      }
    } catch {
      // ignore
    }
    return timestampStr;
  };

  return (
    <div id="scan-history-list" className="bg-[#080808] border border-[#222] p-5 rounded-xl space-y-4 font-sans">
      {/* Component Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#222]">
        <div className="space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="p-1.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <History className="w-4 h-4" />
            </span>
            <h2 className="text-xs font-black tracking-[0.2em] text-white uppercase">
              Scan Execution History
            </h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#141414] text-cyan-400 border border-[#333]">
              {totalScans} / 10 Varreduras
            </span>
            {latestScan && (
              <span className="hidden md:inline-flex items-center gap-1 text-[10px] font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-800/40 px-2 py-0.5 rounded">
                <Sparkles className="w-3 h-3 text-emerald-400" />
                Motor Ativo
              </span>
            )}
          </div>
          <p className="text-[11px] font-mono text-zinc-400">
            Histórico das últimas 10 execuções de análise no workspace com timestamp, contagem de arquivos e findings.
          </p>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center bg-black border border-[#333] rounded-lg p-0.5 text-[11px] font-mono">
            <button
              onClick={() => setSortOrder('NEWEST_FIRST')}
              className={`px-2.5 py-1 rounded cursor-pointer transition-colors ${
                sortOrder === 'NEWEST_FIRST'
                  ? 'bg-zinc-800 text-white font-bold'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
              title="Exibir varreduras mais recentes primeiro"
            >
              Mais Recentes
            </button>
            <button
              onClick={() => setSortOrder('OLDEST_FIRST')}
              className={`px-2.5 py-1 rounded cursor-pointer transition-colors ${
                sortOrder === 'OLDEST_FIRST'
                  ? 'bg-zinc-800 text-white font-bold'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
              title="Exibir varreduras em ordem cronológica"
            >
              Cronológica
            </button>
          </div>

          {onNavigateToScanner && (
            <button
              onClick={onNavigateToScanner}
              className="text-[11px] font-mono text-zinc-400 hover:text-white px-2.5 py-1 rounded bg-[#111] hover:bg-[#1a1a1a] border border-[#333] flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <span>Ver Scanner</span>
              <ArrowUpRight className="w-3 h-3 text-emerald-400" />
            </button>
          )}
        </div>
      </div>

      {/* Empty State */}
      {displayedScans.length === 0 ? (
        <div className="p-8 text-center bg-[#050505] border border-dashed border-[#222] rounded-lg space-y-2">
          <Info className="w-6 h-6 text-zinc-500 mx-auto" />
          <p className="text-xs font-mono text-zinc-400">
            Nenhuma varredura registrada no histórico ainda.
          </p>
          <p className="text-[11px] font-mono text-zinc-600">
            Execute uma análise de código no workspace para registrar o snapshot histórico.
          </p>
        </div>
      ) : (
        /* Scrollable List Container (Limited to last 10 entries) */
        <div 
          id="scan-history-scrollable-list"
          className="max-h-72 overflow-y-auto space-y-2 pr-1 scrollbar-thin scrollbar-thumb-zinc-800 scrollbar-track-transparent"
        >
          {displayedScans.map((scan, index) => {
            const scanSeqNumber = sortOrder === 'NEWEST_FIRST' 
              ? displayedScans.length - index 
              : index + 1;
            const isLatest = latestScan && scan.id === latestScan.id;
            const findingsCount = scan.findings ? scan.findings.length : 0;
            const fileCount = scan.totalFiles ?? scan.scannedFilesCount ?? 0;
            const criticalCount = scan.metrics?.criticalCount ?? scan.findings?.filter(f => f.severity === 'CRITICAL').length ?? 0;
            const highCount = scan.metrics?.highCount ?? scan.findings?.filter(f => f.severity === 'HIGH').length ?? 0;
            const isExpanded = expandedScanId === scan.id;

            return (
              <div
                key={scan.id || `scan-${index}`}
                className={`border rounded-lg transition-all ${
                  isLatest
                    ? 'bg-[#0E1511] border-emerald-900/60 hover:border-emerald-700/80'
                    : 'bg-[#0A0A0A] border-[#1F1F1F] hover:border-[#333]'
                }`}
              >
                <div 
                  onClick={() => setExpandedScanId(isExpanded ? null : scan.id)}
                  className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer select-none"
                >
                  {/* Left: Scan Identifier & Timestamp */}
                  <div className="flex items-center gap-3">
                    <div className="shrink-0">
                      {findingsCount === 0 ? (
                        <span className="p-2 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center justify-center">
                          <CheckCircle2 className="w-4 h-4" />
                        </span>
                      ) : criticalCount > 0 ? (
                        <span className="p-2 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 flex items-center justify-center">
                          <AlertOctagon className="w-4 h-4" />
                        </span>
                      ) : (
                        <span className="p-2 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center justify-center">
                          <AlertTriangle className="w-4 h-4" />
                        </span>
                      )}
                    </div>

                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono font-bold text-white tracking-wide">
                          Varredura #{scanSeqNumber}
                        </span>
                        {isLatest && (
                          <span className="text-[9px] font-mono font-extrabold uppercase px-1.5 py-0.2 bg-emerald-950 text-emerald-300 border border-emerald-600/60 rounded">
                            Mais Recente
                          </span>
                        )}
                        <span className="text-[10px] font-mono text-zinc-500">
                          ID: {scan.id?.substring(0, 8) || 'scan-rec'}
                        </span>
                      </div>

                      {/* Timestamp */}
                      <div className="flex items-center gap-1.5 text-[11px] font-mono text-zinc-400 mt-0.5">
                        <Clock className="w-3 h-3 text-cyan-400 shrink-0" />
                        <span>Timestamp:</span>
                        <span className="text-zinc-200 font-semibold">
                          {formatTimestamp(scan.timestamp)}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Right: File Count, Findings Count, & Details Toggle */}
                  <div className="flex items-center gap-3 sm:gap-5 font-mono text-xs flex-wrap self-end sm:self-auto">
                    {/* File Count */}
                    <div className="flex items-center gap-1.5 bg-black/50 border border-zinc-800/80 px-2.5 py-1 rounded">
                      <FileCode className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <span className="text-zinc-400 text-[11px]">Arquivos:</span>
                      <span className="font-bold text-white text-xs">
                        {fileCount}
                      </span>
                    </div>

                    {/* Findings Count */}
                    <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded border ${
                      findingsCount === 0
                        ? 'bg-emerald-950/40 border-emerald-800/50 text-emerald-300'
                        : criticalCount > 0
                        ? 'bg-rose-950/40 border-rose-800/50 text-rose-300'
                        : 'bg-amber-950/40 border-amber-800/50 text-amber-300'
                    }`}>
                      <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                      <span className="text-[11px]">Findings:</span>
                      <span className="font-bold text-xs">
                        {findingsCount}
                      </span>
                    </div>

                    {/* Expand/Collapse Chevron */}
                    <div className="text-zinc-500 hover:text-zinc-300">
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </div>
                  </div>
                </div>

                {/* Expanded Details Drawer */}
                {isExpanded && (
                  <div className="px-4 pb-4 pt-1 border-t border-[#1C1C1C] bg-black/40 space-y-3 font-mono text-xs">
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2">
                      <div className="p-2 rounded bg-black/60 border border-zinc-800">
                        <span className="text-[10px] text-zinc-500 block uppercase">Críticos</span>
                        <span className="text-rose-400 font-bold text-sm">{criticalCount}</span>
                      </div>
                      <div className="p-2 rounded bg-black/60 border border-zinc-800">
                        <span className="text-[10px] text-zinc-500 block uppercase">Altos</span>
                        <span className="text-amber-400 font-bold text-sm">{highCount}</span>
                      </div>
                      <div className="p-2 rounded bg-black/60 border border-zinc-800">
                        <span className="text-[10px] text-zinc-500 block uppercase">Ignorados</span>
                        <span className="text-zinc-300 font-bold text-sm">{scan.ignoredFilesCount ?? 0}</span>
                      </div>
                      <div className="p-2 rounded bg-black/60 border border-zinc-800">
                        <span className="text-[10px] text-zinc-500 block uppercase">Score de Segurança</span>
                        <span className="text-emerald-400 font-bold text-sm">
                          {scan.metrics?.securityScore ?? 100}%
                        </span>
                      </div>
                    </div>

                    {/* Findings Sample List if present */}
                    {scan.findings && scan.findings.length > 0 ? (
                      <div className="space-y-1.5 pt-1">
                        <span className="text-[10px] text-zinc-400 font-bold uppercase block">
                          Amostra de Vulnerabilidades Detectadas ({Math.min(3, scan.findings.length)} de {scan.findings.length}):
                        </span>
                        <div className="space-y-1">
                          {scan.findings.slice(0, 3).map((f, fIdx) => (
                            <div 
                              key={f.id || `f-${fIdx}`}
                              onClick={(e) => {
                                e.stopPropagation();
                                if (onSelectFinding) onSelectFinding(f);
                              }}
                              className="p-2 rounded bg-[#0D0D0D] hover:bg-[#141414] border border-[#262626] flex items-center justify-between text-[11px] cursor-pointer"
                            >
                              <div className="flex items-center gap-2 truncate">
                                <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                                  f.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300' :
                                  f.severity === 'HIGH' ? 'bg-amber-950 text-amber-300' : 'bg-zinc-800 text-zinc-300'
                                }`}>
                                  {f.severity}
                                </span>
                                <span className="text-zinc-200 truncate">{f.ruleName || f.description || f.category}</span>
                              </div>
                              <span className="text-zinc-500 text-[10px] shrink-0 font-mono ml-2">
                                {f.file}:{f.line}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div className="p-2 bg-emerald-950/20 border border-emerald-900/30 rounded text-emerald-400 text-[11px] flex items-center gap-2">
                        <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
                        <span>Nenhuma vulnerabilidade detectada nesta execução. Arquivos em conformidade.</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Footer Summary Strip */}
      <div className="pt-2 border-t border-[#1C1C1C] flex flex-wrap items-center justify-between gap-2 text-[10px] font-mono text-zinc-500">
        <span>Limite máximo: 10 execuções registradas em memória</span>
        {latestScan && (
          <span>
            Última varredura concluída: {formatTimestamp(latestScan.timestamp)} ({latestScan.totalFiles ?? latestScan.scannedFilesCount} arquivos, {latestScan.findings?.length ?? 0} findings)
          </span>
        )}
      </div>
    </div>
  );
};
