import React, { useState, useMemo } from 'react';
import { 
  Ban, 
  Plus, 
  Trash2, 
  Check, 
  RotateCcw, 
  FileCode, 
  HelpCircle, 
  Search, 
  Sparkles, 
  X,
  FileCheck,
  Layers,
  Copy,
  FolderTree
} from 'lucide-react';
import { IgnorePatternItem, ScannedFile } from '../types';
import { matchesIgnorePattern, DEFAULT_GLOBAL_IGNORE_PATTERNS } from '../lib/scanner';

interface GlobalIgnoreModalProps {
  isOpen: boolean;
  onClose: () => void;
  patterns?: IgnorePatternItem[];
  onUpdatePatterns?: (newPatterns: IgnorePatternItem[]) => void;
  onSavePatterns?: (newPatterns: IgnorePatternItem[]) => void;
  onTogglePattern?: (id: string) => void;
  workspaceFiles?: ScannedFile[];
  onTriggerRescan?: () => void;
}

const PRESET_SUGGESTIONS = [
  { pattern: 'tests/*', label: 'tests/*', description: 'Ignora todos os arquivos dentro do diretório tests/' },
  { pattern: '*.test.*', label: '*.test.*', description: 'Ignora arquivos de testes unitários (*.test.js, *.test.ts)' },
  { pattern: '*.spec.*', label: '*.spec.*', description: 'Ignora suítes de especificação (*.spec.ts, *.spec.js)' },
  { pattern: 'fixtures/*', label: 'fixtures/*', description: 'Ignora massas de dados de teste e fixtures mockadas' },
  { pattern: 'mock/*', label: 'mock/*', description: 'Ignora diretórios de mock de serviços' },
  { pattern: 'docs/*', label: 'docs/*', description: 'Ignora documentação, guias e especificações markdown' },
  { pattern: '*.md', label: '*.md', description: 'Ignora todos os arquivos Markdown' },
  { pattern: '*.lock', label: '*.lock', description: 'Ignora lockfiles de dependências (package-lock, yarn.lock)' }
];

export const GlobalIgnoreModal: React.FC<GlobalIgnoreModalProps> = ({
  isOpen,
  onClose,
  patterns = [],
  onUpdatePatterns,
  onSavePatterns,
  onTogglePattern,
  workspaceFiles = [],
  onTriggerRescan
}) => {
  const safePatterns = Array.isArray(patterns) ? patterns : [];
  const safeFiles = Array.isArray(workspaceFiles) ? workspaceFiles : [];

  const handleUpdate = (updated: IgnorePatternItem[]) => {
    if (onUpdatePatterns) onUpdatePatterns(updated);
    if (onSavePatterns) onSavePatterns(updated);
  };

  const [newPatternInput, setNewPatternInput] = useState('');
  const [newDescriptionInput, setNewDescriptionInput] = useState('');
  const [searchFilter, setSearchFilter] = useState('');
  const [copiedSuccess, setCopiedSuccess] = useState(false);
  const [selectedPatternForDetails, setSelectedPatternForDetails] = useState<string | null>(null);

  // Calculate matched files for each pattern
  const patternMatchMap = useMemo(() => {
    const map = new Map<string, string[]>();
    for (const item of safePatterns) {
      const matched = safeFiles
        .filter(f => matchesIgnorePattern(f.path, item.pattern))
        .map(f => f.path);
      map.set(item.id, matched);
    }
    return map;
  }, [safePatterns, safeFiles]);

  // Real-time preview for input
  const inputMatchingFiles = useMemo(() => {
    if (!newPatternInput.trim()) return [];
    return safeFiles
      .filter(f => matchesIgnorePattern(f.path, newPatternInput.trim()))
      .map(f => f.path);
  }, [newPatternInput, safeFiles]);

  // Filtered patterns
  const filteredPatterns = useMemo(() => {
    if (!searchFilter.trim()) return safePatterns;
    const term = searchFilter.toLowerCase();
    return safePatterns.filter(p => 
      p.pattern.toLowerCase().includes(term) ||
      (p.description && p.description.toLowerCase().includes(term))
    );
  }, [safePatterns, searchFilter]);

  const activeCount = safePatterns.filter(p => p.enabled).length;

  const totalExcludedFiles = useMemo(() => {
    const activePatternStrings = safePatterns.filter(p => p.enabled).map(p => p.pattern);
    return safeFiles.filter(f => 
      activePatternStrings.some(pat => matchesIgnorePattern(f.path, pat))
    ).length;
  }, [safePatterns, safeFiles]);

  if (!isOpen) return null;

  const handleAddPattern = (rawPat?: string, rawDesc?: string) => {
    const patternToAdd = (rawPat || newPatternInput).trim();
    if (!patternToAdd) return;

    // Check duplicate
    const existingIndex = safePatterns.findIndex(p => p.pattern.toLowerCase() === patternToAdd.toLowerCase());
    if (existingIndex >= 0) {
      // If it exists but was disabled, re-enable it
      const updated = [...safePatterns];
      updated[existingIndex] = { ...updated[existingIndex], enabled: true };
      handleUpdate(updated);
      setNewPatternInput('');
      setNewDescriptionInput('');
      return;
    }

    const newItem: IgnorePatternItem = {
      id: `custom-ignore-${Date.now()}`,
      pattern: patternToAdd,
      enabled: true,
      description: (rawDesc || newDescriptionInput).trim() || 'Padrão customizado de exclusão global',
      isBuiltIn: false,
      createdAt: new Date().toISOString().slice(0, 10)
    };

    handleUpdate([newItem, ...safePatterns]);
    setNewPatternInput('');
    setNewDescriptionInput('');
  };

  const handleTogglePattern = (id: string) => {
    if (onTogglePattern) {
      onTogglePattern(id);
    } else {
      const updated = safePatterns.map(p => 
        p.id === id ? { ...p, enabled: !p.enabled } : p
      );
      handleUpdate(updated);
    }
  };

  const handleDeletePattern = (id: string) => {
    const updated = safePatterns.filter(p => p.id !== id);
    handleUpdate(updated);
  };

  const handleResetDefaults = () => {
    if (window.confirm('Deseja restaurar a lista padrão de exclusões recomendadas?')) {
      handleUpdate(DEFAULT_GLOBAL_IGNORE_PATTERNS);
    }
  };

  const handleCopyList = () => {
    const active = safePatterns.filter(p => p.enabled).map(p => p.pattern).join('\n');
    navigator.clipboard.writeText(active);
    setCopiedSuccess(true);
    setTimeout(() => setCopiedSuccess(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm animate-in fade-in duration-150">
      <div 
        id="global-ignore-modal-container"
        className="w-full max-w-4xl bg-[#0A0A0A] border-2 border-[#333] shadow-[0_0_50px_rgba(0,0,0,0.9)] max-h-[92vh] flex flex-col overflow-hidden text-white font-sans"
      >
        {/* Top Header */}
        <div className="p-6 bg-[#080808] border-b border-[#222] flex items-start justify-between gap-4 shrink-0">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 bg-[#FF3E00]/15 border border-[#FF3E00]/40 text-[#FF3E00] font-mono text-[10px] font-black uppercase tracking-widest">
                <Ban className="w-3 h-3" />
                GLOBAL IGNORE LIST
              </span>
              <span className="text-[10px] font-mono text-[#888]">
                // SAST EXCLUSION POLICY ENGINE
              </span>
              <span className="text-[10px] font-mono bg-[#141414] text-[#00FF41] border border-[#00FF41]/30 px-2 py-0.5 font-bold">
                {activeCount} ATIVOS
              </span>
              <span className="text-[10px] font-mono bg-[#141414] text-[#AAA] border border-[#333] px-2 py-0.5">
                {totalExcludedFiles} ARQUIVO(S) EXCLUÍDO(S) NO WORKSPACE
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2">
              <span>Lista Global de Exclusão de Arquivos</span>
            </h2>
            <p className="text-xs font-mono text-[#888] max-w-2xl leading-relaxed">
              Padrões globais que são excluídos permanentemente de todas as análises estáticas (código-fonte, uploads, re-escaneamentos e agendamentos).
            </p>
          </div>

          <button
            id="btn-close-ignore-modal"
            onClick={onClose}
            className="w-9 h-9 bg-[#111] hover:bg-[#FF3E00] hover:text-white text-[#888] border border-[#333] flex items-center justify-center transition-colors shrink-0"
            title="Fechar (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1 custom-scrollbar">
          {/* Add New Pattern Section */}
          <div className="bg-[#0D0D0D] border border-[#262626] p-4 sm:p-5 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-widest text-[#AAA] font-bold flex items-center gap-1.5">
                <Plus className="w-3.5 h-3.5 text-[#FF3E00]" />
                Adicionar Novo Arquivo, Diretório ou Padrão Glob
              </span>
              <span className="text-[9px] font-mono text-[#666]">
                Exemplos: tests/*, fixtures/**, *.test.ts, docs/*
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-12 gap-3">
              <div className="sm:col-span-5">
                <input
                  id="input-new-ignore-pattern"
                  type="text"
                  placeholder="Padrão (ex.: tests/*, *.spec.js)"
                  value={newPatternInput}
                  onChange={(e) => setNewPatternInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleAddPattern();
                  }}
                  className="w-full h-10 bg-[#050505] border border-[#333] focus:border-[#FF3E00] text-xs font-mono px-3 text-white outline-none placeholder-[#555]"
                />
              </div>

              <div className="sm:col-span-5">
                <input
                  id="input-new-ignore-description"
                  type="text"
                  placeholder="Descrição opcional (ex.: Diretório de testes)"
                  value={newDescriptionInput}
                  onChange={(e) => setNewDescriptionInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleAddPattern();
                  }}
                  className="w-full h-10 bg-[#050505] border border-[#333] focus:border-[#FF3E00] text-xs font-mono px-3 text-white outline-none placeholder-[#555]"
                />
              </div>

              <div className="sm:col-span-2">
                <button
                  id="btn-submit-add-pattern"
                  onClick={() => handleAddPattern()}
                  disabled={!newPatternInput.trim()}
                  className="w-full h-10 bg-[#FF3E00] hover:bg-white hover:text-black text-white font-black text-xs uppercase tracking-wider transition-colors flex items-center justify-center gap-1.5 disabled:opacity-40 disabled:hover:bg-[#FF3E00] disabled:hover:text-white"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Adicionar</span>
                </button>
              </div>
            </div>

            {/* Real-time Match Inspector for current typing */}
            {newPatternInput.trim() && (
              <div className="p-3 bg-[#050505] border border-[#333] text-xs font-mono space-y-1.5">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-[#AAA] flex items-center gap-1">
                    <Search className="w-3 h-3 text-[#FF3E00]" />
                    Correspondência em tempo real no Workspace:
                  </span>
                  <span className={`font-bold ${inputMatchingFiles.length > 0 ? 'text-[#00FF41]' : 'text-[#888]'}`}>
                    {inputMatchingFiles.length} arquivo(s) afetado(s)
                  </span>
                </div>
                {inputMatchingFiles.length > 0 ? (
                  <div className="max-h-24 overflow-y-auto space-y-1 text-[10px] text-[#DDD] pt-1">
                    {inputMatchingFiles.map(path => (
                      <div key={path} className="flex items-center gap-1.5 truncate">
                        <span className="text-[#FF3E00]">↳</span>
                        <span className="truncate">{path}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-[10px] text-[#666] italic">
                    Nenhum arquivo no workspace atual coincide com este padrão ainda (ele será aplicado automaticamente a uploads futuros).
                  </div>
                )}
              </div>
            )}

            {/* Quick Presets */}
            <div className="space-y-1.5 pt-1">
              <span className="text-[9px] font-mono text-[#777] uppercase font-bold tracking-wider block">
                Atalhos Rápidos de Exclusão:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {PRESET_SUGGESTIONS.map((preset) => {
                  const alreadyExists = patterns.some(p => p.pattern.toLowerCase() === preset.pattern.toLowerCase());
                  const isEnabled = patterns.find(p => p.pattern.toLowerCase() === preset.pattern.toLowerCase())?.enabled;

                  return (
                    <button
                      key={preset.pattern}
                      onClick={() => handleAddPattern(preset.pattern, preset.description)}
                      className={`px-2.5 py-1 text-[10px] font-mono border transition-all flex items-center gap-1.5 ${
                        alreadyExists && isEnabled
                          ? 'border-[#00FF41]/40 bg-[#00FF41]/10 text-[#00FF41]'
                          : alreadyExists
                          ? 'border-[#444] bg-[#111] text-[#777]'
                          : 'border-[#333] bg-[#0A0A0A] hover:border-[#FF3E00] text-[#AAA] hover:text-white'
                      }`}
                      title={preset.description}
                    >
                      <span className="font-bold">{preset.label}</span>
                      {alreadyExists && isEnabled && <Check className="w-3 h-3 text-[#00FF41]" />}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Patterns List Controls */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
            <div className="relative flex-1 max-w-sm">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#666]" />
              <input
                type="text"
                placeholder="Filtrar padrões..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="w-full h-9 pl-9 pr-3 bg-[#080808] border border-[#222] focus:border-[#444] text-xs font-mono text-white outline-none"
              />
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCopyList}
                className="px-3 py-1.5 bg-[#111] hover:bg-[#222] border border-[#333] text-xs font-mono text-[#AAA] hover:text-white flex items-center gap-1.5 transition-colors"
                title="Copiar padrões ativos"
              >
                {copiedSuccess ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                <span>{copiedSuccess ? 'Copiado!' : 'Copiar Lista'}</span>
              </button>

              <button
                onClick={handleResetDefaults}
                className="px-3 py-1.5 bg-[#111] hover:bg-[#222] border border-[#333] text-xs font-mono text-[#AAA] hover:text-white flex items-center gap-1.5 transition-colors"
                title="Restaurar padrões de fábrica recomendados"
              >
                <RotateCcw className="w-3 h-3" />
                <span>Padrões Recomendados</span>
              </button>
            </div>
          </div>

          {/* Patterns Table */}
          <div className="border border-[#222] bg-[#080808] overflow-hidden">
            <div className="grid grid-cols-12 gap-3 px-4 py-2.5 bg-[#050505] border-b border-[#222] text-[9.5px] font-mono font-bold uppercase tracking-wider text-[#777]">
              <div className="col-span-1 text-center">Status</div>
              <div className="col-span-4">Padrão / Glob</div>
              <div className="col-span-4">Descrição</div>
              <div className="col-span-2 text-center">Arquivos Afetados</div>
              <div className="col-span-1 text-right">Ação</div>
            </div>

            <div className="divide-y divide-[#141414] max-h-72 overflow-y-auto">
              {filteredPatterns.length === 0 ? (
                <div className="p-8 text-center text-xs font-mono text-[#666]">
                  Nenhum padrão de exclusão encontrado para "{searchFilter}".
                </div>
              ) : (
                filteredPatterns.map((item) => {
                  const matchedFiles = patternMatchMap.get(item.id) || [];
                  const isSelected = selectedPatternForDetails === item.id;

                  return (
                    <div 
                      key={item.id}
                      className={`grid grid-cols-12 gap-3 px-4 py-3 items-center text-xs font-mono transition-colors ${
                        item.enabled ? 'hover:bg-[#0F0F0F]' : 'opacity-50 bg-[#060606]'
                      }`}
                    >
                      {/* Checkbox / Toggle */}
                      <div className="col-span-1 flex justify-center">
                        <button
                          type="button"
                          onClick={() => handleTogglePattern(item.id)}
                          className={`w-5 h-5 border flex items-center justify-center transition-all ${
                            item.enabled 
                              ? 'bg-[#FF3E00] border-[#FF3E00] text-white shadow-[0_0_8px_rgba(255,62,0,0.5)]' 
                              : 'bg-[#111] border-[#333] text-transparent hover:border-[#666]'
                          }`}
                          title={item.enabled ? 'Clique para desativar' : 'Clique para ativar'}
                        >
                          <Check className="w-3.5 h-3.5 stroke-[3]" />
                        </button>
                      </div>

                      {/* Pattern String */}
                      <div className="col-span-4 flex items-center gap-2 min-w-0">
                        <span className={`font-mono font-bold px-2 py-0.5 border text-xs truncate ${
                          item.enabled 
                            ? 'bg-[#141414] text-white border-[#333]' 
                            : 'bg-[#0A0A0A] text-[#666] border-[#222]'
                        }`}>
                          {item.pattern}
                        </span>
                        {item.isBuiltIn && (
                          <span className="text-[8px] font-mono px-1 py-0.2 bg-[#222] text-[#888] uppercase tracking-wider shrink-0">
                            CORE
                          </span>
                        )}
                      </div>

                      {/* Description */}
                      <div className="col-span-4 text-xs text-[#AAA] truncate" title={item.description}>
                        {item.description || 'Sem descrição'}
                      </div>

                      {/* Matched Files Count */}
                      <div className="col-span-2 text-center">
                        {matchedFiles.length > 0 ? (
                          <button
                            type="button"
                            onClick={() => setSelectedPatternForDetails(isSelected ? null : item.id)}
                            className="inline-flex items-center gap-1 px-2 py-0.5 bg-[#220700] text-[#FF3E00] hover:bg-[#FF3E00] hover:text-white border border-[#FF3E00]/40 text-[10px] font-bold font-mono transition-colors"
                            title="Clique para ver arquivos correspondentes"
                          >
                            <span>{matchedFiles.length} arq.</span>
                          </button>
                        ) : (
                          <span className="text-[10px] text-[#555] font-mono">0 arq.</span>
                        )}
                      </div>

                      {/* Delete action */}
                      <div className="col-span-1 text-right">
                        <button
                          type="button"
                          onClick={() => handleDeletePattern(item.id)}
                          className="p-1.5 text-[#666] hover:text-[#FF3E00] hover:bg-[#220700] transition-colors"
                          title="Excluir regra"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>

                      {/* Expandable matched files view */}
                      {isSelected && matchedFiles.length > 0 && (
                        <div className="col-span-12 p-3 bg-[#050505] border border-[#333] text-[10px] font-mono space-y-1 text-[#DDD]">
                          <div className="text-[9px] text-[#888] uppercase font-bold tracking-wider">
                            Arquivos ignorados por "{item.pattern}":
                          </div>
                          {matchedFiles.map(path => (
                            <div key={path} className="flex items-center gap-2 truncate">
                              <Ban className="w-3 h-3 text-[#FF3E00] shrink-0" />
                              <span className="truncate">{path}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* Bottom Footer Actions */}
        <div className="p-5 bg-[#080808] border-t border-[#222] flex flex-col sm:flex-row items-center justify-between gap-4 shrink-0 font-mono text-xs">
          <div className="text-[#888] flex items-center gap-2">
            <Sparkles className="w-3.5 h-3.5 text-[#FF3E00]" />
            <span>As exclusões são salvas localmente e têm efeito imediato em todos os escaneamentos futuros.</span>
          </div>

          <div className="flex items-center gap-3 w-full sm:w-auto">
            <button
              onClick={onClose}
              className="flex-1 sm:flex-none px-4 py-2.5 border border-[#333] hover:border-white bg-[#111] text-white font-bold text-xs uppercase tracking-wider transition-colors"
            >
              Fechar
            </button>
            <button
              id="btn-apply-ignore-and-rescan"
              onClick={() => {
                onTriggerRescan();
                onClose();
              }}
              className="flex-1 sm:flex-none px-6 py-2.5 bg-[#FF3E00] hover:bg-white hover:text-black text-white font-black text-xs uppercase tracking-[0.15em] transition-all flex items-center justify-center gap-2"
            >
              <FileCheck className="w-3.5 h-3.5" />
              <span>Aplicar & Re-escanear</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
