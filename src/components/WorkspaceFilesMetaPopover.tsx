import React, { useState, useMemo, useEffect, useRef } from 'react';
import { 
  FileText, 
  HardDrive, 
  Code2, 
  Calendar, 
  Search, 
  X, 
  Copy, 
  Check, 
  Clock, 
  Layers,
  ArrowUpRight,
  Filter
} from 'lucide-react';
import { ScannedFile } from '../types';

interface WorkspaceFilesMetaPopoverProps {
  files: ScannedFile[];
  isOpen: boolean;
  onClose: () => void;
  onSelectFile?: (file: ScannedFile) => void;
}

export interface FileMetadataItem {
  name: string;
  path: string;
  extension: string;
  totalLines: number;
  sizeBytes: number;
  sizeKb: string;
  lastModifiedFormatted: string;
  lastModifiedTimestamp: number;
  rawFile: ScannedFile;
}

/**
 * Formats a timestamp or date into a localized, professional date string.
 */
function formatModifiedDate(timestamp?: number | string): { formatted: string; timestamp: number } {
  if (!timestamp) {
    // Default fallback to a recent deterministic timestamp
    const now = Date.now();
    return {
      formatted: new Date(now).toLocaleString('pt-BR', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      }),
      timestamp: now
    };
  }

  const date = typeof timestamp === 'number' ? new Date(timestamp) : new Date(timestamp);
  const validTimestamp = isNaN(date.getTime()) ? Date.now() : date.getTime();
  
  return {
    formatted: new Date(validTimestamp).toLocaleString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    }),
    timestamp: validTimestamp
  };
}

export const WorkspaceFilesMetaPopover: React.FC<WorkspaceFilesMetaPopoverProps> = ({
  files,
  isOpen,
  onClose,
  onSelectFile
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedItem, setCopiedItem] = useState<string | null>(null);
  const popoverRef = useRef<HTMLDivElement>(null);

  // Close on Escape or click outside
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    const handleClickOutside = (e: MouseEvent) => {
      if (popoverRef.current && !popoverRef.current.contains(e.target as Node)) {
        // Only close if not clicking the toggle button
        const target = e.target as HTMLElement;
        if (!target.closest('#btn-validation-file-metadata')) {
          onClose();
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('mousedown', handleClickOutside);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen, onClose]);

  // Compute rich metadata for each file
  const fileMetadataList = useMemo<FileMetadataItem[]>(() => {
    return files.map((file, idx) => {
      const content = file.content || '';
      const totalLines = content.length > 0 ? content.split(/\r\n|\r|\n/).length : 0;
      const sizeBytes = file.size ?? new Blob([content]).size;
      const sizeKb = (sizeBytes / 1024).toFixed(2);
      
      // Fallback modified time if not set: deterministic relative offsets for demo fidelity
      const fallbackTime = Date.now() - (files.length - idx) * 3600000 * 4;
      const modified = formatModifiedDate(file.lastModified || fallbackTime);

      return {
        name: file.name,
        path: file.path || file.name,
        extension: file.extension || file.name.split('.').pop() || 'txt',
        totalLines,
        sizeBytes,
        sizeKb,
        lastModifiedFormatted: modified.formatted,
        lastModifiedTimestamp: modified.timestamp,
        rawFile: file
      };
    });
  }, [files]);

  // Global aggregate metrics
  const totals = useMemo(() => {
    const count = fileMetadataList.length;
    const totalLines = fileMetadataList.reduce((acc, f) => acc + f.totalLines, 0);
    const totalBytes = fileMetadataList.reduce((acc, f) => acc + f.sizeBytes, 0);
    const totalKb = (totalBytes / 1024).toFixed(2);
    const avgLines = count > 0 ? Math.round(totalLines / count) : 0;

    return { count, totalLines, totalBytes, totalKb, avgLines };
  }, [fileMetadataList]);

  // Filtered files
  const filteredFiles = useMemo(() => {
    if (!searchQuery.trim()) return fileMetadataList;
    const q = searchQuery.toLowerCase().trim();
    return fileMetadataList.filter(f => 
      f.name.toLowerCase().includes(q) || 
      f.path.toLowerCase().includes(q) ||
      f.extension.toLowerCase().includes(q)
    );
  }, [fileMetadataList, searchQuery]);

  const handleCopyFileMeta = (item: FileMetadataItem, e: React.MouseEvent) => {
    e.stopPropagation();
    const text = `Arquivo: ${item.path}\nLinhas de Código: ${item.totalLines} LOC\nTamanho: ${item.sizeKb} KB (${item.sizeBytes} bytes)\nÚltima Modificação: ${item.lastModifiedFormatted}`;
    navigator.clipboard.writeText(text).then(() => {
      setCopiedItem(item.path);
      setTimeout(() => setCopiedItem(null), 1800);
    });
  };

  const handleCopyAllMeta = () => {
    const lines = [
      `=== METADADOS DO WORKSPACE (${totals.count} ARQUIVOS) ===`,
      `Total Linhas de Código: ${totals.totalLines} LOC`,
      `Tamanho Total: ${totals.totalKb} KB (${totals.totalBytes} bytes)`,
      `Média de Linhas/Arquivo: ${totals.avgLines} LOC\n`,
      `DETALHAMENTO:`
    ];

    fileMetadataList.forEach((f, idx) => {
      lines.push(`[${idx + 1}] ${f.path}`);
      lines.push(`    LOC: ${f.totalLines} | Tamanho: ${f.sizeKb} KB | Modificado: ${f.lastModifiedFormatted}`);
    });

    navigator.clipboard.writeText(lines.join('\n')).then(() => {
      setCopiedItem('ALL');
      setTimeout(() => setCopiedItem(null), 1800);
    });
  };

  if (!isOpen) return null;

  return (
    <div
      id="workspace-files-metadata-popover"
      ref={popoverRef}
      className="absolute right-0 top-full mt-2 w-full sm:w-[540px] max-w-[95vw] bg-[#0A0C10] border-2 border-[#333] shadow-2xl rounded-lg z-50 overflow-hidden font-mono text-xs animate-in fade-in zoom-in-95 duration-150"
    >
      {/* Popover Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-[#12151D] border-b border-white/10">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded bg-[#3366FF]/20 border border-[#3366FF]/40 text-[#3366FF]">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <h4 className="text-white font-bold text-xs uppercase tracking-wider flex items-center gap-2">
              <span>Metadados dos Arquivos do Workspace</span>
              <span className="px-1.5 py-0.2 rounded bg-white/10 text-white/90 text-[10px] font-mono">
                {totals.count}
              </span>
            </h4>
            <p className="text-[10px] text-zinc-400">
              Linhas de código, peso em KB e carimbo de modificação
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={handleCopyAllMeta}
            className="p-1 rounded hover:bg-white/10 text-zinc-400 hover:text-white transition-colors cursor-pointer"
            title="Copiar metadados de todos os arquivos"
          >
            {copiedItem === 'ALL' ? (
              <span className="text-emerald-400 text-[9.5px] font-bold flex items-center gap-0.5 px-1">
                <Check className="w-3 h-3" /> Copiado
              </span>
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded hover:bg-white/10 text-zinc-400 hover:text-white transition-colors cursor-pointer"
            title="Fechar popover"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Aggregate KPI Strip */}
      <div className="grid grid-cols-3 gap-2 p-3 bg-black/40 border-b border-white/10 text-center">
        <div className="p-2 rounded bg-white/5 border border-white/5">
          <div className="flex items-center justify-center gap-1 text-[10px] text-zinc-400 uppercase">
            <Code2 className="w-3 h-3 text-[#3366FF]" />
            <span>Total LOC</span>
          </div>
          <div className="mt-1 text-sm font-black text-white">
            {totals.totalLines.toLocaleString()}
          </div>
          <div className="text-[9px] text-zinc-500">Média {totals.avgLines}/arq</div>
        </div>

        <div className="p-2 rounded bg-white/5 border border-white/5">
          <div className="flex items-center justify-center gap-1 text-[10px] text-zinc-400 uppercase">
            <HardDrive className="w-3 h-3 text-[#00FF41]" />
            <span>Tamanho Total</span>
          </div>
          <div className="mt-1 text-sm font-black text-[#00FF41]">
            {totals.totalKb} KB
          </div>
          <div className="text-[9px] text-zinc-500">{totals.totalBytes.toLocaleString()} bytes</div>
        </div>

        <div className="p-2 rounded bg-white/5 border border-white/5">
          <div className="flex items-center justify-center gap-1 text-[10px] text-zinc-400 uppercase">
            <Calendar className="w-3 h-3 text-[#FF7A00]" />
            <span>Arquivos Ativos</span>
          </div>
          <div className="mt-1 text-sm font-black text-[#FF7A00]">
            {totals.count}
          </div>
          <div className="text-[9px] text-zinc-500">No workspace</div>
        </div>
      </div>

      {/* Search Input for fast file location */}
      <div className="p-2.5 bg-[#0D0F16] border-b border-white/10 flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            id="input-popover-search-files"
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filtrar por nome, caminho ou extensão (.js, .ts)..."
            className="w-full bg-black/60 border border-white/10 focus:border-[#3366FF] text-white pl-8 pr-7 py-1 text-[11px] rounded outline-hidden placeholder-zinc-500 transition-colors"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-white"
            >
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* File List Items */}
      <div className="max-h-72 overflow-y-auto divide-y divide-white/5 scrollbar-thin p-1">
        {filteredFiles.length === 0 ? (
          <div className="p-6 text-center text-zinc-500 text-xs">
            Nenhum arquivo encontrado no workspace.
          </div>
        ) : (
          filteredFiles.map((item) => (
            <div
              key={item.path}
              onClick={() => onSelectFile && onSelectFile(item.rawFile)}
              className="p-2.5 hover:bg-white/5 rounded transition-colors cursor-pointer group flex items-center justify-between gap-3"
            >
              <div className="min-w-0 flex-1 space-y-1">
                <div className="flex items-center gap-1.5">
                  <span className="px-1.5 py-0.2 rounded bg-white/10 text-white font-bold text-[9px] uppercase">
                    {item.extension}
                  </span>
                  <span className="font-bold text-white text-[11.5px] truncate group-hover:text-[#3366FF] transition-colors" title={item.path}>
                    {item.name}
                  </span>
                  {onSelectFile && (
                    <ArrowUpRight className="w-3 h-3 text-zinc-500 opacity-0 group-hover:opacity-100 transition-opacity" />
                  )}
                </div>

                {item.path !== item.name && (
                  <div className="text-[9.5px] text-zinc-500 truncate" title={item.path}>
                    {item.path}
                  </div>
                )}

                {/* Metadata badges row */}
                <div className="flex flex-wrap items-center gap-2 text-[10px] text-zinc-400 pt-0.5">
                  <span className="flex items-center gap-1 text-sky-300">
                    <Code2 className="w-3 h-3" />
                    <strong>{item.totalLines}</strong> linhas
                  </span>

                  <span className="text-zinc-600">•</span>

                  <span className="flex items-center gap-1 text-emerald-300">
                    <HardDrive className="w-3 h-3" />
                    <strong>{item.sizeKb} KB</strong>
                    <span className="text-zinc-500 text-[9px]">({item.sizeBytes} B)</span>
                  </span>

                  <span className="text-zinc-600">•</span>

                  <span className="flex items-center gap-1 text-zinc-400" title={`Timestamp: ${item.lastModifiedTimestamp}`}>
                    <Calendar className="w-3 h-3 text-zinc-500" />
                    <span>{item.lastModifiedFormatted}</span>
                  </span>
                </div>
              </div>

              {/* Action: Copy this file's metadata */}
              <div className="shrink-0" onClick={(e) => e.stopPropagation()}>
                <button
                  type="button"
                  onClick={(e) => handleCopyFileMeta(item, e)}
                  className="p-1.5 rounded hover:bg-white/10 text-zinc-400 hover:text-white transition-colors cursor-pointer"
                  title="Copiar metadados deste arquivo"
                >
                  {copiedItem === item.path ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Popover Footer */}
      <div className="p-2.5 bg-[#0D0F16] border-t border-white/10 flex items-center justify-between text-[10px] text-zinc-400">
        <span>Clique em um arquivo para selecioná-lo no editor</span>
        <button
          type="button"
          onClick={onClose}
          className="px-2 py-0.5 rounded bg-white/10 hover:bg-white/20 text-white font-bold transition-colors cursor-pointer"
        >
          Fechar
        </button>
      </div>
    </div>
  );
};
