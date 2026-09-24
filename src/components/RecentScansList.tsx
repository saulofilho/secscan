import React, { useState, useMemo, useRef, useEffect } from 'react';
import { 
  History, 
  Clock, 
  FileCode2, 
  AlertTriangle, 
  ShieldAlert, 
  ShieldCheck, 
  CheckCircle2, 
  Search, 
  X, 
  Copy, 
  Check, 
  ArrowUpRight, 
  ChevronRight, 
  Filter, 
  Activity, 
  FileText, 
  Route, 
  Eye, 
  Info,
  Calendar,
  Layers
} from 'lucide-react';
import { ScanReport, ScanFinding } from '../types';

export interface RecentScansListProps {
  scanHistory?: ScanReport[];
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToScanner?: () => void;
}

export const RecentScansList: React.FC<RecentScansListProps> = ({
  scanHistory = [],
  onSelectFinding,
  onNavigateToScanner
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedScan, setSelectedScan] = useState<ScanReport | null>(null);
  const [copiedJson, setCopiedJson] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);

  // Close popover on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setSelectedScan(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Format timestamp helper
  const formatTimestamp = (timestampStr: string): { formatted: string; relative: string } => {
    if (!timestampStr) return { formatted: 'N/A', relative: 'Recente' };
    try {
      const date = new Date(timestampStr);
      if (!isNaN(date.getTime())) {
        const formatted = `${date.toLocaleDateString()} ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
        const diffMs = Date.now() - date.getTime();
        const diffMins = Math.floor(diffMs / 60000);
        let relative = 'Agora';
        if (diffMins > 0 && diffMins < 60) {
          relative = `Há ${diffMins}m`;
        } else if (diffMins >= 60) {
          const diffHours = Math.floor(diffMins / 60);
          relative = `Há ${diffHours}h`;
        }
        return { formatted, relative };
      }
    } catch {
      // ignore
    }
    return { formatted: timestampStr, relative: 'Recente' };
  };

  // Filtered and sorted scans (newest first, limited to recent history)
  const filteredScans = useMemo(() => {
    const list = [...scanHistory].reverse();
    if (!searchTerm.trim()) return list;

    const term = searchTerm.toLowerCase();
    return list.filter(scan => {
      const timeStr = scan.timestamp?.toLowerCase() || '';
      const filesCount = String(scan.scannedFilesCount || scan.totalFiles || 0);
      const findingsCount = String(scan.findings?.length || 0);
      const riskLevel = scan.metrics?.riskLevel?.toLowerCase() || '';
      return (
        timeStr.includes(term) ||
        filesCount.includes(term) ||
        findingsCount.includes(term) ||
        riskLevel.includes(term)
      );
    });
  }, [scanHistory, searchTerm]);

  // Summary statistics
  const totalScans = scanHistory.length;
  const totalFindingsAccumulated = useMemo(() => {
    return scanHistory.reduce((acc, s) => acc + (s.findings?.length || 0), 0);
  }, [scanHistory]);

  const handleCopyScanSummary = (scan: ScanReport) => {
    const summary = {
      scanId: scan.id,
      timestamp: scan.timestamp,
      filesProcessed: scan.scannedFilesCount || scan.totalFiles,
      findingsCount: scan.findings?.length || 0,
      criticalFindings: scan.metrics?.criticalCount || 0,
      highFindings: scan.metrics?.highCount || 0,
      mediumFindings: scan.metrics?.mediumCount || 0,
      lowFindings: scan.metrics?.lowCount || 0,
      riskScore: scan.metrics?.riskScore ?? 0,
      riskLevel: scan.metrics?.riskLevel ?? 'LOW',
      durationMs: scan.durationMs || 0
    };
    navigator.clipboard.writeText(JSON.stringify(summary, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  return (
    <div 
      id="recent-scans-list-container" 
      className="bg-[#0A0A0A] border-2 border-[#1E1E1E] hover:border-[#2A2A2A] transition-colors p-5 sm:p-6 rounded-none space-y-4 shadow-xl relative"
    >
      {/* Component Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#222]">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5 flex-wrap">
            <span className="w-8 h-8 bg-[#161616] border border-[#333] text-[#00FF41] flex items-center justify-center font-mono shrink-0 shadow-[0_0_12px_rgba(0,255,65,0.15)]">
              <History className="w-4 h-4" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono px-2 py-0.5 bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30 font-bold uppercase tracking-wider">
                  AUDITORIA HISTÓRICA
                </span>
                <span className="text-xs font-mono text-[#777]">
                  {totalScans} {totalScans === 1 ? 'registro' : 'registros'}
                </span>
              </div>
              <h2 className="text-base font-black uppercase text-white tracking-wide mt-0.5 flex items-center gap-2">
                Recent Scans List
              </h2>
            </div>
          </div>
          <p className="text-xs font-mono text-[#888] max-w-2xl leading-relaxed">
            Visualização em lista contínua das execuções de análise no workspace. Clique em qualquer linha histórica para abrir o resumo analítico e telemetria forense.
          </p>
        </div>

        {/* Search & Quick Stats */}
        <div className="flex flex-wrap items-center gap-3 shrink-0">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-[#666] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filtrar por data, arquivos..."
              className="bg-black border border-[#333] focus:border-[#00FF41] pl-8 pr-3 py-1.5 text-xs font-mono text-white outline-none w-52 sm:w-60 placeholder-[#555] transition-colors"
            />
            {searchTerm && (
              <button 
                onClick={() => setSearchTerm('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-[#777] hover:text-white"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          <div className="bg-[#121212] border border-[#222] px-3 py-1.5 flex items-center gap-3 text-xs font-mono">
            <div>
              <span className="text-[9px] text-[#666] uppercase block">Total Execuções</span>
              <span className="text-[#00FF41] font-bold">{totalScans}</span>
            </div>
            <div className="w-px h-6 bg-[#222]" />
            <div>
              <span className="text-[9px] text-[#666] uppercase block">Total Achados</span>
              <span className="text-[#FF7A00] font-bold">{totalFindingsAccumulated}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Scrollable List Table */}
      <div className="border border-[#222] bg-black overflow-hidden">
        {/* Table Column Headers */}
        <div className="grid grid-cols-12 bg-[#121212] border-b border-[#222] py-2.5 px-4 text-[10px] font-mono font-bold uppercase tracking-wider text-[#888]">
          <div className="col-span-4 sm:col-span-3 flex items-center gap-1.5">
            <Clock className="w-3 h-3 text-[#00FF41]" />
            <span>Timestamp</span>
          </div>
          <div className="col-span-3 sm:col-span-3 flex items-center gap-1.5">
            <FileCode2 className="w-3 h-3 text-[#3366FF]" />
            <span>Files Processed</span>
          </div>
          <div className="col-span-3 sm:col-span-4 flex items-center gap-1.5">
            <AlertTriangle className="w-3 h-3 text-[#FF3E00]" />
            <span>Findings Detected</span>
          </div>
          <div className="col-span-2 sm:col-span-2 text-right">
            <span>Ações</span>
          </div>
        </div>

        {/* Scrollable Rows Container */}
        <div className="max-h-[380px] overflow-y-auto divide-y divide-[#181818] scrollbar-thin select-text">
          {filteredScans.length === 0 ? (
            <div className="py-12 px-4 text-center font-mono text-xs space-y-2">
              <History className="w-8 h-8 text-[#444] mx-auto animate-pulse" />
              <div className="text-white font-bold uppercase tracking-wider">
                Nenhum histórico de varredura encontrado
              </div>
              <p className="text-[#666] text-[11px] max-w-sm mx-auto">
                {searchTerm 
                  ? 'Nenhum resultado corresponde ao termo de busca pesquisado.'
                  : 'Execute uma análise no workspace para registrar o primeiro ponto histórico de auditoria.'}
              </p>
            </div>
          ) : (
            filteredScans.map((scan, idx) => {
              const { formatted, relative } = formatTimestamp(scan.timestamp);
              const filesCount = scan.scannedFilesCount || scan.totalFiles || 0;
              const findingsCount = scan.findings?.length || 0;
              const critCount = scan.metrics?.criticalCount || 0;
              const highCount = scan.metrics?.highCount || 0;
              const medCount = scan.metrics?.mediumCount || 0;
              const isClean = findingsCount === 0;
              const isSelected = selectedScan?.id === scan.id;

              return (
                <div
                  key={scan.id || `scan-${idx}`}
                  onClick={() => setSelectedScan(scan)}
                  className={`grid grid-cols-12 py-3 px-4 text-xs font-mono transition-all items-center cursor-pointer group ${
                    isSelected
                      ? 'bg-[#181818] border-l-4 border-l-[#00FF41]'
                      : 'hover:bg-[#121212] border-l-4 border-l-transparent'
                  }`}
                  title="Clique para abrir o resumo detalhado desta varredura"
                >
                  {/* Timestamp Column */}
                  <div className="col-span-4 sm:col-span-3 space-y-0.5">
                    <div className="text-white font-bold flex items-center gap-1.5 group-hover:text-[#00FF41] transition-colors truncate">
                      <span>{formatted}</span>
                    </div>
                    <div className="text-[10px] text-[#666] flex items-center gap-1.5">
                      <span className="px-1 py-0.2 bg-[#1A1A1A] border border-[#2A2A2A] text-[#AAA]">
                        {relative}
                      </span>
                      {scan.durationMs !== undefined && (
                        <span>{scan.durationMs}ms</span>
                      )}
                    </div>
                  </div>

                  {/* Files Processed Column */}
                  <div className="col-span-3 sm:col-span-3 space-y-0.5">
                    <div className="text-white font-bold flex items-center gap-1.5">
                      <span>{filesCount} {filesCount === 1 ? 'arquivo' : 'arquivos'}</span>
                    </div>
                    <div className="text-[10px] text-[#666]">
                      {scan.ignoredFilesCount ? `${scan.ignoredFilesCount} ignorados` : 'Todos processados'}
                    </div>
                  </div>

                  {/* Findings Detected Column */}
                  <div className="col-span-3 sm:col-span-4 space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`font-bold ${isClean ? 'text-[#00FF41]' : 'text-white'}`}>
                        {findingsCount} {findingsCount === 1 ? 'achado' : 'achados'}
                      </span>
                      {scan.metrics?.riskScore !== undefined && (
                        <span className={`text-[10px] px-1.5 py-0.2 border font-bold ${
                          scan.metrics.riskScore >= 75 ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/30' :
                          scan.metrics.riskScore >= 40 ? 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/30' :
                          'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/30'
                        }`}>
                          Score: {scan.metrics.riskScore}/100
                        </span>
                      )}
                    </div>

                    {/* Mini severity distribution badges */}
                    {!isClean && (
                      <div className="flex items-center gap-1 flex-wrap text-[9.5px]">
                        {critCount > 0 && (
                          <span className="px-1 py-0.2 bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40 font-bold">
                            {critCount} Crit
                          </span>
                        )}
                        {highCount > 0 && (
                          <span className="px-1 py-0.2 bg-[#FF7A00]/20 text-[#FF7A00] border border-[#FF7A00]/40 font-bold">
                            {highCount} High
                          </span>
                        )}
                        {medCount > 0 && (
                          <span className="px-1 py-0.2 bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            {medCount} Med
                          </span>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Actions Column */}
                  <div className="col-span-2 sm:col-span-2 text-right">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedScan(scan);
                      }}
                      className="px-2.5 py-1 bg-[#1A1A1A] hover:bg-[#00FF41] text-[#AAA] hover:text-black border border-[#333] hover:border-[#00FF41] text-[10px] font-bold uppercase transition-all inline-flex items-center gap-1 cursor-pointer"
                      title="Exibir Popover com Resumo Completo"
                    >
                      <span>Ver Resumo</span>
                      <ChevronRight className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Summary Popover / Modal Overlay for Selected Historical Scan */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
          <div 
            ref={popoverRef}
            className="bg-[#0F0F0F] border-2 border-[#00FF41] w-full max-w-2xl max-h-[90vh] flex flex-col shadow-[0_0_40px_rgba(0,255,65,0.2)] animate-scaleIn"
          >
            {/* Popover Header */}
            <div className="p-4 sm:p-5 border-b border-[#222] bg-[#141414] flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 bg-[#1A1A1A] border border-[#333] text-[#00FF41] flex items-center justify-center font-mono shrink-0">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono px-2 py-0.5 bg-[#00FF41]/20 text-[#00FF41] border border-[#00FF41]/40 font-bold uppercase">
                      RESUMO DA VARREDURA
                    </span>
                    <span className="text-[10px] font-mono text-[#777]">
                      ID: {selectedScan.id || 'N/A'}
                    </span>
                  </div>
                  <h3 className="text-sm sm:text-base font-bold text-white uppercase mt-0.5">
                    Execução de {formatTimestamp(selectedScan.timestamp).formatted}
                  </h3>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setSelectedScan(null)}
                className="w-8 h-8 rounded-none bg-[#1A1A1A] hover:bg-rose-950/60 text-[#888] hover:text-white border border-[#333] flex items-center justify-center transition-colors cursor-pointer"
                title="Fechar popover (Esc)"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Popover Body Content */}
            <div className="p-5 overflow-y-auto space-y-5 font-mono text-xs scrollbar-thin">
              {/* Key Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-black border border-[#222] p-3">
                  <span className="text-[10px] text-[#666] uppercase block">Arquivos Analisados</span>
                  <span className="text-base font-bold text-white mt-1 block">
                    {selectedScan.scannedFilesCount || selectedScan.totalFiles || 0}
                  </span>
                  <span className="text-[9.5px] text-[#555]">
                    {selectedScan.ignoredFilesCount || 0} ignorados
                  </span>
                </div>

                <div className="bg-black border border-[#222] p-3">
                  <span className="text-[10px] text-[#666] uppercase block">Vulnerabilidades</span>
                  <span className={`text-base font-bold mt-1 block ${
                    (selectedScan.findings?.length || 0) > 0 ? 'text-[#FF3E00]' : 'text-[#00FF41]'
                  }`}>
                    {selectedScan.findings?.length || 0}
                  </span>
                  <span className="text-[9.5px] text-[#555]">
                    {selectedScan.metrics?.criticalCount || 0} críticas
                  </span>
                </div>

                <div className="bg-black border border-[#222] p-3">
                  <span className="text-[10px] text-[#666] uppercase block">Risk Score Geral</span>
                  <span className={`text-base font-bold mt-1 block ${
                    (selectedScan.metrics?.riskScore ?? 0) >= 75 ? 'text-[#FF3E00]' :
                    (selectedScan.metrics?.riskScore ?? 0) >= 40 ? 'text-[#FF7A00]' :
                    'text-[#00FF41]'
                  }`}>
                    {selectedScan.metrics?.riskScore ?? 0}/100
                  </span>
                  <span className="text-[9.5px] text-[#555]">
                    Nível {selectedScan.metrics?.riskLevel || 'LOW'}
                  </span>
                </div>

                <div className="bg-black border border-[#222] p-3">
                  <span className="text-[10px] text-[#666] uppercase block">Latência da Varredura</span>
                  <span className="text-base font-bold text-cyan-400 mt-1 block">
                    {selectedScan.durationMs !== undefined ? `${selectedScan.durationMs}ms` : 'Em cache'}
                  </span>
                  <span className="text-[9.5px] text-[#555]">Motor SAST v2</span>
                </div>
              </div>

              {/* Severity Breakdown Bar */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[11px] uppercase text-[#888]">
                  <span>Distribuição por Criticidade</span>
                  <span>Total: {selectedScan.findings?.length || 0}</span>
                </div>
                <div className="w-full bg-[#1A1A1A] h-2.5 flex overflow-hidden border border-[#222]">
                  {(selectedScan.metrics?.criticalCount || 0) > 0 && (
                    <div 
                      style={{ width: `${((selectedScan.metrics?.criticalCount || 0) / (selectedScan.findings?.length || 1)) * 100}%` }}
                      className="bg-[#FF3E00] h-full"
                      title={`Críticos: ${selectedScan.metrics?.criticalCount}`}
                    />
                  )}
                  {(selectedScan.metrics?.highCount || 0) > 0 && (
                    <div 
                      style={{ width: `${((selectedScan.metrics?.highCount || 0) / (selectedScan.findings?.length || 1)) * 100}%` }}
                      className="bg-[#FF7A00] h-full"
                      title={`Altos: ${selectedScan.metrics?.highCount}`}
                    />
                  )}
                  {(selectedScan.metrics?.mediumCount || 0) > 0 && (
                    <div 
                      style={{ width: `${((selectedScan.metrics?.mediumCount || 0) / (selectedScan.findings?.length || 1)) * 100}%` }}
                      className="bg-amber-400 h-full"
                      title={`Médios: ${selectedScan.metrics?.mediumCount}`}
                    />
                  )}
                  {(selectedScan.metrics?.lowCount || 0) > 0 && (
                    <div 
                      style={{ width: `${((selectedScan.metrics?.lowCount || 0) / (selectedScan.findings?.length || 1)) * 100}%` }}
                      className="bg-[#3366FF] h-full"
                      title={`Baixos: ${selectedScan.metrics?.lowCount}`}
                    />
                  )}
                </div>
                <div className="flex items-center gap-3 text-[10px] text-[#888] pt-1">
                  <span className="text-[#FF3E00] font-bold">● {selectedScan.metrics?.criticalCount || 0} Críticos</span>
                  <span className="text-[#FF7A00] font-bold">● {selectedScan.metrics?.highCount || 0} Altos</span>
                  <span className="text-amber-400 font-bold">● {selectedScan.metrics?.mediumCount || 0} Médios</span>
                  <span className="text-[#3366FF] font-bold">● {selectedScan.metrics?.lowCount || 0} Baixos</span>
                </div>
              </div>

              {/* Top Findings Detected in this specific scan */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-[11px] uppercase text-[#888]">
                  <span>Amostra de Achados Registrados ({selectedScan.findings?.length || 0})</span>
                  {selectedScan.findings && selectedScan.findings.length > 5 && (
                    <span className="text-[10px] text-[#555]">Exibindo primeiros 5 achados</span>
                  )}
                </div>

                {(!selectedScan.findings || selectedScan.findings.length === 0) ? (
                  <div className="p-4 bg-black border border-[#222] text-[#00FF41] flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                    <span>Nenhuma vulnerabilidade ou segredo exposto detectado nesta execução. Workspace em conformidade.</span>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                    {selectedScan.findings.slice(0, 5).map((f, fIdx) => (
                      <div
                        key={f.id || `f-${fIdx}`}
                        onClick={() => {
                          if (onSelectFinding) onSelectFinding(f);
                          if (onNavigateToScanner) {
                            setSelectedScan(null);
                            onNavigateToScanner();
                          }
                        }}
                        className="p-3 bg-black border border-[#222] hover:border-[#444] space-y-1.5 transition-colors cursor-pointer"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2 truncate">
                            <span className={`px-1.5 py-0.2 text-[9px] font-bold uppercase border ${
                              f.severity === 'CRITICAL' ? 'bg-[#FF3E00]/20 text-[#FF3E00] border-[#FF3E00]/40' :
                              f.severity === 'HIGH' ? 'bg-[#FF7A00]/20 text-[#FF7A00] border-[#FF7A00]/40' :
                              'bg-amber-500/20 text-amber-300 border-amber-500/40'
                            }`}>
                              {f.severity}
                            </span>
                            <span className="font-bold text-white truncate">{f.ruleName}</span>
                          </div>
                          <span className="text-[10px] text-[#666] shrink-0">
                            {f.file}:{f.line}
                          </span>
                        </div>

                        {f.maskedSecret && (
                          <div className="bg-[#111] px-2 py-1 text-[11px] text-[#FF3E00] border border-[#222] truncate">
                            {f.maskedSecret}
                          </div>
                        )}

                        <p className="text-[10px] text-[#888] line-clamp-1">
                          {f.remediation}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Popover Footer Bar */}
            <div className="p-4 border-t border-[#222] bg-[#141414] flex flex-wrap items-center justify-between gap-3">
              <button
                type="button"
                onClick={() => handleCopyScanSummary(selectedScan)}
                className="px-3 py-1.5 bg-[#1E1E1E] hover:bg-[#2A2A2A] text-white text-xs font-mono font-bold flex items-center gap-1.5 transition-colors cursor-pointer border border-[#333]"
              >
                {copiedJson ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedJson ? 'Copiado JSON!' : 'Copiar Resumo (JSON)'}</span>
              </button>

              <div className="flex items-center gap-2">
                {onNavigateToScanner && (
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedScan(null);
                      onNavigateToScanner();
                    }}
                    className="px-3 py-1.5 bg-[#00FF41] hover:bg-[#00D636] text-black text-xs font-mono font-black uppercase flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <span>Inspecionar no Scanner</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setSelectedScan(null)}
                  className="px-3 py-1.5 bg-[#1A1A1A] hover:bg-[#252525] text-[#AAA] hover:text-white text-xs font-mono transition-colors cursor-pointer border border-[#333]"
                >
                  Fechar
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
