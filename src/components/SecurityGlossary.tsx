import React, { useState, useMemo, useRef, useEffect } from 'react';
import { 
  BookOpen, 
  HelpCircle, 
  ShieldAlert, 
  ExternalLink, 
  Check, 
  Copy, 
  X, 
  Search, 
  AlertTriangle, 
  Sparkles, 
  RotateCw, 
  ChevronRight, 
  Flame, 
  Code2, 
  FileText,
  ShieldCheck,
  Zap,
  Info
} from 'lucide-react';
import { 
  SecurityGlossaryEntry, 
  SECURITY_GLOSSARY_ENTRIES, 
  getGlossaryEntryForFinding 
} from '../lib/securityGlossary';
import { ScanFinding } from '../types';

interface SecurityGlossaryTooltipProps {
  finding?: ScanFinding;
  entryOverride?: SecurityGlossaryEntry;
  onOpenFullGlossary?: (entry: SecurityGlossaryEntry) => void;
  className?: string;
  variant?: 'badge' | 'icon' | 'button';
}

/**
 * Context-aware tooltip / popover for findings in ScannerView and Dashboard
 */
export const SecurityGlossaryTooltip: React.FC<SecurityGlossaryTooltipProps> = ({
  finding,
  entryOverride,
  onOpenFullGlossary,
  className = '',
  variant = 'badge'
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const entry = useMemo(() => {
    if (entryOverride) return entryOverride;
    if (finding) return getGlossaryEntryForFinding(finding);
    return SECURITY_GLOSSARY_ENTRIES[0];
  }, [finding, entryOverride]);

  // Handle outside click to close popover
  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (
        popoverRef.current && 
        !popoverRef.current.contains(e.target as Node) &&
        triggerRef.current &&
        !triggerRef.current.contains(e.target as Node)
      ) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleOutsideClick);
    }
    return () => {
      document.removeEventListener('mousedown', handleOutsideClick);
    };
  }, [isOpen]);

  const cvssColor = entry.cvssScore >= 9.0 
    ? 'text-[#FF3E00] border-[#FF3E00]/40 bg-[#220700]' 
    : entry.cvssScore >= 7.0 
    ? 'text-[#FF7A00] border-[#FF7A00]/40 bg-[#221000]' 
    : 'text-[#FFD600] border-[#FFD600]/40 bg-[#221D00]';

  return (
    <div className={`relative inline-block ${className}`}>
      {/* Trigger */}
      {variant === 'badge' ? (
        <button
          ref={triggerRef}
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          className="inline-flex items-center gap-1.5 px-2 py-0.5 bg-[#141414] hover:bg-[#1E1E1E] border border-[#333] hover:border-[#FF3E00] text-[#AAA] hover:text-white text-[10px] font-mono transition-all group cursor-pointer"
          title="Clique para ver o significado técnico no Glossário de Segurança"
        >
          <BookOpen className="w-3 h-3 text-[#FF3E00] group-hover:scale-110 transition-transform" />
          <span className="font-bold">{entry.cwe.id}</span>
          <span className="text-[9px] text-[#666] hidden sm:inline">• {entry.owasp.code}</span>
        </button>
      ) : variant === 'button' ? (
        <button
          ref={triggerRef}
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-[#111] hover:bg-[#200500] border border-[#333] hover:border-[#FF3E00] text-xs font-mono text-[#DDD] hover:text-[#FF3E00] transition-colors cursor-pointer"
        >
          <HelpCircle className="w-3.5 h-3.5 text-[#FF3E00]" />
          <span>Glossário</span>
        </button>
      ) : (
        <button
          ref={triggerRef}
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          className="p-1 text-[#888] hover:text-[#FF3E00] hover:bg-[#220700] border border-transparent hover:border-[#FF3E00]/40 transition-colors cursor-pointer"
          title="Ver explicação no Glossário de Segurança"
        >
          <HelpCircle className="w-3.5 h-3.5" />
        </button>
      )}

      {/* Context-aware popover */}
      {isOpen && (
        <div
          ref={popoverRef}
          className="absolute z-50 left-0 sm:left-auto sm:right-0 mt-2 w-80 sm:w-96 bg-[#0D0D0D] border-2 border-[#333] shadow-[0_10px_35px_rgba(0,0,0,0.9)] p-4 font-sans text-left animate-in fade-in duration-150 text-white"
        >
          {/* Header */}
          <div className="flex items-start justify-between gap-2 border-b border-[#222] pb-3 mb-3">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-[9px] font-mono px-1.5 py-0.5 bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/40 font-bold uppercase tracking-wider">
                  GLOSSÁRIO DE SEGURANÇA
                </span>
                <span className={`text-[9px] font-mono px-1.5 py-0.5 border font-bold ${cvssColor}`}>
                  CVSS {entry.cvssScore}
                </span>
              </div>
              <h4 className="text-xs font-black uppercase text-white tracking-wide">
                {entry.title}
              </h4>
            </div>

            <button
              onClick={() => setIsOpen(false)}
              className="text-[#666] hover:text-white p-1 hover:bg-[#222] transition-colors"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Body */}
          <div className="space-y-3 text-xs">
            {/* Badges CWE / OWASP */}
            <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono">
              <a 
                href={entry.cwe.url} 
                target="_blank" 
                rel="noreferrer"
                className="px-2 py-0.5 bg-[#141414] hover:bg-[#222] border border-[#333] hover:border-[#666] text-[#DDD] flex items-center gap-1 transition-colors"
              >
                <span>{entry.cwe.id}: {entry.cwe.name}</span>
                <ExternalLink className="w-2.5 h-2.5 text-[#888]" />
              </a>
              <span className="px-2 py-0.5 bg-[#141414] border border-[#333] text-[#AAA]">
                OWASP {entry.owasp.code}
              </span>
            </div>

            {/* Summary */}
            <p className="text-[11px] font-mono text-[#AAA] leading-relaxed">
              {entry.summary}
            </p>

            {/* Threat & Attacker Objective */}
            <div className="p-2.5 bg-[#050505] border border-[#222] space-y-1 text-[10px] font-mono">
              <div className="text-[#FF3E00] font-bold flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                <span>Objetivo do Invasor:</span>
              </div>
              <p className="text-[#888] leading-tight">
                {entry.attackerObjective}
              </p>
            </div>

            {/* Blast Radius */}
            <div className="text-[10px] font-mono text-[#777]">
              <strong className="text-[#CCC]">Raio de Impacto:</strong> {entry.blastRadius}
            </div>
          </div>

          {/* Footer Action */}
          <div className="mt-4 pt-3 border-t border-[#222] flex items-center justify-between">
            <span className="text-[9px] font-mono text-[#666]">
              SAST Knowledge Base
            </span>
            {onOpenFullGlossary && (
              <button
                type="button"
                onClick={() => {
                  setIsOpen(false);
                  onOpenFullGlossary(entry);
                }}
                className="inline-flex items-center gap-1 text-[10px] font-black uppercase tracking-wider text-[#FF3E00] hover:text-white transition-colors cursor-pointer"
              >
                <span>Abrir no Glossário</span>
                <ChevronRight className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

interface SecurityGlossaryInlineCardProps {
  finding: ScanFinding;
  onOpenFullGlossary?: (entry: SecurityGlossaryEntry) => void;
}

/**
 * Expandable in-depth technical explanation card embedded inside ScannerView finding cards
 */
export const SecurityGlossaryInlineCard: React.FC<SecurityGlossaryInlineCardProps> = ({
  finding,
  onOpenFullGlossary
}) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);
  const entry = useMemo(() => getGlossaryEntryForFinding(finding), [finding]);

  const handleCopyGoodPattern = () => {
    navigator.clipboard.writeText(entry.safePattern.good);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="border border-[#222] bg-[#0A0A0A] text-white">
      {/* Toggle Bar */}
      <button
        type="button"
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-3 flex items-center justify-between bg-[#0D0D0D] hover:bg-[#141414] transition-colors text-left"
      >
        <div className="flex items-center gap-2.5">
          <BookOpen className="w-3.5 h-3.5 text-[#FF3E00]" />
          <div>
            <span className="text-[11px] font-black uppercase font-mono tracking-wider text-white">
              Glossário de Segurança // {entry.title}
            </span>
            <span className="text-[9px] font-mono text-[#888] ml-2 hidden sm:inline">
              ({entry.cwe.id} • OWASP {entry.owasp.code})
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-[#AAA]">
          <span className="text-[10px] text-[#FF3E00] font-bold">
            {isExpanded ? 'Recolher Explicação' : 'Entenda o Risco Técnico'}
          </span>
          <ChevronRight className={`w-3.5 h-3.5 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
        </div>
      </button>

      {/* Expanded Technical Breakdown */}
      {isExpanded && (
        <div className="p-4 sm:p-5 border-t border-[#222] space-y-4 font-mono text-xs">
          {/* Executive Overview */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="p-3 bg-[#050505] border border-[#222] space-y-1">
              <div className="text-[10px] text-[#888] uppercase font-bold">Classificação CWE / OWASP</div>
              <div className="text-white font-bold text-xs">{entry.cwe.id}</div>
              <div className="text-[10px] text-[#AAA]">{entry.owasp.code} - {entry.owasp.title}</div>
            </div>

            <div className="p-3 bg-[#050505] border border-[#222] space-y-1">
              <div className="text-[10px] text-[#888] uppercase font-bold">Vetor de Ataque (Threat Vector)</div>
              <div className="text-[#FF7A00] font-bold text-xs">Acesso Indireto &amp; Exploração</div>
              <div className="text-[10px] text-[#AAA] line-clamp-2">{entry.threatScenario}</div>
            </div>

            <div className="p-3 bg-[#050505] border border-[#222] space-y-1">
              <div className="text-[10px] text-[#888] uppercase font-bold">Raio de Impacto</div>
              <div className="text-[#FF3E00] font-bold text-xs">Severidade {entry.severity}</div>
              <div className="text-[10px] text-[#AAA] line-clamp-2">{entry.blastRadius}</div>
            </div>
          </div>

          {/* Secure vs Insecure Code Example */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-bold text-[#AAA] flex items-center gap-1.5">
                <Code2 className="w-3.5 h-3.5 text-[#FF3E00]" />
                Padrão de Código Seguro (Como Corrigir)
              </span>
              <button
                type="button"
                onClick={handleCopyGoodPattern}
                className="px-2.5 py-1 bg-[#111] hover:bg-[#222] border border-[#333] text-[10px] font-mono text-white flex items-center gap-1 transition-colors cursor-pointer"
              >
                {copiedCode ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                <span>{copiedCode ? 'Copiado!' : 'Copiar Código Seguro'}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-[11px]">
              {/* Bad pattern */}
              <div className="p-3 bg-[#110402] border border-[#FF3E00]/40 space-y-1.5">
                <div className="text-[10px] text-[#FF3E00] font-bold uppercase tracking-wider">
                  ❌ Inseguro (Detectado no Repositório)
                </div>
                <pre className="text-[#FFC4B0] overflow-x-auto whitespace-pre font-mono p-2 bg-black/60 border border-[#330A00]">
                  {entry.safePattern.bad}
                </pre>
              </div>

              {/* Good pattern */}
              <div className="p-3 bg-[#031105] border border-[#00FF41]/40 space-y-1.5">
                <div className="text-[10px] text-[#00FF41] font-bold uppercase tracking-wider">
                  ✅ Seguro (Recomendado pela Política)
                </div>
                <pre className="text-[#B9F6CA] overflow-x-auto whitespace-pre font-mono p-2 bg-black/60 border border-[#00330E]">
                  {entry.safePattern.good}
                </pre>
              </div>
            </div>

            <p className="text-[10px] text-[#777] italic">
              {entry.safePattern.explanation}
            </p>
          </div>

          {/* Step-by-step remediation */}
          <div className="p-3.5 bg-[#050505] border border-[#222] space-y-2">
            <div className="text-[10px] uppercase font-bold text-white flex items-center gap-1.5">
              <Sparkles className="w-3 h-3 text-[#FF3E00]" />
              Procedimento Recomendado de Remediação &amp; Rotação:
            </div>
            <ul className="space-y-1 text-[11px] text-[#AAA] list-disc list-inside">
              {entry.remediationSteps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ul>
          </div>

          {/* Footer deep link */}
          {onOpenFullGlossary && (
            <div className="flex justify-end pt-1">
              <button
                type="button"
                onClick={() => onOpenFullGlossary(entry)}
                className="text-[10px] font-bold text-[#FF3E00] hover:text-white uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <span>Ver verbete completo no Glossário de Segurança</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

interface SecurityGlossaryModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialSelectedId?: string;
  selectedEntryId?: string;
}

/**
 * Full-screen / Modal comprehensive Security Glossary dictionary
 */
export const SecurityGlossaryModal: React.FC<SecurityGlossaryModalProps> = ({
  isOpen,
  onClose,
  initialSelectedId,
  selectedEntryId: propSelectedEntryId
}) => {
  const activeInitialId = initialSelectedId || propSelectedEntryId;
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedEntryId, setSelectedEntryId] = useState<string>(
    activeInitialId || SECURITY_GLOSSARY_ENTRIES[0].id
  );
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Synchronize when initial selected ID changes
  useEffect(() => {
    if (activeInitialId) {
      setSelectedEntryId(activeInitialId);
    }
  }, [activeInitialId]);

  const categories = useMemo(() => {
    const list = Array.from(new Set(SECURITY_GLOSSARY_ENTRIES.map(e => e.category)));
    return ['ALL', ...list];
  }, []);

  const filteredEntries = useMemo(() => {
    return SECURITY_GLOSSARY_ENTRIES.filter(entry => {
      const matchesCat = selectedCategory === 'ALL' || entry.category === selectedCategory;
      if (!matchesCat) return false;

      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        entry.title.toLowerCase().includes(q) ||
        entry.cwe.id.toLowerCase().includes(q) ||
        entry.cwe.name.toLowerCase().includes(q) ||
        entry.owasp.code.toLowerCase().includes(q) ||
        entry.summary.toLowerCase().includes(q) ||
        entry.tags.some(t => t.toLowerCase().includes(q))
      );
    });
  }, [searchQuery, selectedCategory]);

  const selectedEntry = useMemo(() => {
    return (
      SECURITY_GLOSSARY_ENTRIES.find(e => e.id === selectedEntryId) ||
      filteredEntries[0] ||
      SECURITY_GLOSSARY_ENTRIES[0]
    );
  }, [selectedEntryId, filteredEntries]);

  if (!isOpen) return null;

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/85 backdrop-blur-sm animate-in fade-in duration-150">
      <div 
        id="security-glossary-modal-container"
        className="w-full max-w-6xl bg-[#0A0A0A] border-2 border-[#333] shadow-[0_0_60px_rgba(0,0,0,0.95)] max-h-[94vh] flex flex-col overflow-hidden text-white font-sans"
      >
        {/* Top Header */}
        <div className="p-5 sm:p-6 bg-[#080808] border-b border-[#222] flex items-start justify-between gap-4 shrink-0">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 bg-[#FF3E00]/15 border border-[#FF3E00]/40 text-[#FF3E00] font-mono text-[10px] font-black uppercase tracking-widest">
                <BookOpen className="w-3 h-3" />
                SECURITY GLOSSARY &amp; THREAT KNOWLEDGE BASE
              </span>
              <span className="text-[10px] font-mono text-[#888]">
                // ENCYCLOPEDIA &amp; REMEDIATION MANUAL
              </span>
              <span className="text-[10px] font-mono bg-[#141414] text-[#00FF41] border border-[#00FF41]/30 px-2 py-0.5 font-bold">
                {SECURITY_GLOSSARY_ENTRIES.length} VERBETES CATALOGADOS
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2">
              <span>Glossário de Vulnerabilidades &amp; Segredos</span>
            </h2>
            <p className="text-xs font-mono text-[#888] max-w-2xl leading-relaxed">
              Guia técnico e referencial de CWE, OWASP Top 10, impacto e remediação para cada categoria de segredo e exposição detectada pela engine SAST.
            </p>
          </div>

          <button
            id="btn-close-glossary-modal"
            onClick={onClose}
            className="w-9 h-9 bg-[#111] hover:bg-[#FF3E00] hover:text-white text-[#888] border border-[#333] flex items-center justify-center transition-colors shrink-0 cursor-pointer"
            title="Fechar (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Search & Category Filter Bar */}
        <div className="p-4 bg-[#0D0D0D] border-b border-[#1E1E1E] flex flex-col sm:flex-row items-center justify-between gap-3 shrink-0">
          <div className="relative w-full sm:w-80">
            <Search className="w-3.5 h-3.5 text-[#666] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Buscar vulnerabilidade, CWE, OWASP ou tag..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full h-9 pl-9 pr-3 bg-[#050505] border border-[#2A2A2A] focus:border-[#FF3E00] text-xs font-mono text-white outline-none placeholder-[#555]"
            />
          </div>

          {/* Category Tabs */}
          <div className="flex flex-wrap items-center gap-1.5 w-full sm:w-auto overflow-x-auto">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-2.5 py-1 text-[10px] font-mono uppercase font-bold border transition-colors cursor-pointer ${
                  selectedCategory === cat
                    ? 'bg-[#FF3E00] text-white border-[#FF3E00]'
                    : 'bg-[#111] text-[#888] border-[#222] hover:border-[#444] hover:text-white'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* Two-Column Master / Detail Layout */}
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 overflow-hidden">
          {/* Left Column: List of Terms */}
          <div className="lg:col-span-4 border-b lg:border-b-0 lg:border-r border-[#1E1E1E] bg-[#080808] overflow-y-auto max-h-56 lg:max-h-none custom-scrollbar divide-y divide-[#141414]">
            {filteredEntries.length === 0 ? (
              <div className="p-8 text-center text-xs font-mono text-[#666]">
                Nenhum verbete encontrado para os filtros selecionados.
              </div>
            ) : (
              filteredEntries.map((entry) => {
                const isSelected = selectedEntry.id === entry.id;
                return (
                  <button
                    key={entry.id}
                    onClick={() => setSelectedEntryId(entry.id)}
                    className={`w-full p-4 text-left transition-all flex flex-col gap-1.5 cursor-pointer ${
                      isSelected
                        ? 'bg-[#160601] border-l-4 border-[#FF3E00] text-white'
                        : 'hover:bg-[#0E0E0E] text-[#AAA] border-l-4 border-transparent'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[9px] font-mono px-1.5 py-0.2 bg-[#1A1A1A] border border-[#2A2A2A] text-[#888]">
                        {entry.cwe.id}
                      </span>
                      <span className={`text-[9px] font-mono px-1.5 py-0.2 font-black ${
                        entry.severity === 'CRITICAL' ? 'text-[#FF3E00]' : 'text-[#FF7A00]'
                      }`}>
                        {entry.severity} • {entry.cvssScore}
                      </span>
                    </div>

                    <div className="text-xs font-bold font-sans text-white leading-tight">
                      {entry.title}
                    </div>

                    <p className="text-[10px] font-mono text-[#777] line-clamp-2">
                      {entry.summary}
                    </p>
                  </button>
                );
              })
            )}
          </div>

          {/* Right Column: Detailed Encyclopedia View */}
          <div className="lg:col-span-8 bg-[#0A0A0A] overflow-y-auto p-6 sm:p-8 space-y-6 custom-scrollbar">
            {/* Entry Header */}
            <div className="space-y-3 pb-5 border-b border-[#222]">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[10px] font-mono px-2 py-0.5 bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/40 font-bold uppercase tracking-widest">
                  {selectedEntry.category}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 bg-[#141414] border border-[#333] text-white font-bold">
                  {selectedEntry.cwe.id}: {selectedEntry.cwe.name}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 bg-[#141414] border border-[#333] text-[#AAA]">
                  OWASP {selectedEntry.owasp.code} ({selectedEntry.owasp.year})
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 font-bold border ${
                  selectedEntry.cvssScore >= 9 
                    ? 'border-[#FF3E00]/40 text-[#FF3E00] bg-[#220700]' 
                    : 'border-[#FF7A00]/40 text-[#FF7A00] bg-[#221000]'
                }`}>
                  CVSS BASE {selectedEntry.cvssScore} / 10.0
                </span>
              </div>

              <h3 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white">
                {selectedEntry.title}
              </h3>

              <p className="text-xs sm:text-sm font-mono text-[#AAA] leading-relaxed">
                {selectedEntry.summary}
              </p>
            </div>

            {/* Attack Anatomy Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 bg-[#080808] border border-[#222] space-y-2">
                <div className="text-[10px] font-mono uppercase font-bold text-[#FF3E00] flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Cenário de Ameaça
                </div>
                <p className="text-xs font-mono text-[#888] leading-relaxed">
                  {selectedEntry.threatScenario}
                </p>
              </div>

              <div className="p-4 bg-[#080808] border border-[#222] space-y-2">
                <div className="text-[10px] font-mono uppercase font-bold text-[#FF7A00] flex items-center gap-1.5">
                  <Flame className="w-3.5 h-3.5" />
                  Objetivo do Atacante
                </div>
                <p className="text-xs font-mono text-[#888] leading-relaxed">
                  {selectedEntry.attackerObjective}
                </p>
              </div>

              <div className="p-4 bg-[#080808] border border-[#222] space-y-2">
                <div className="text-[10px] font-mono uppercase font-bold text-[#FFD600] flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5" />
                  Raio de Explosão (Blast Radius)
                </div>
                <p className="text-xs font-mono text-[#888] leading-relaxed">
                  {selectedEntry.blastRadius}
                </p>
              </div>
            </div>

            {/* Code Remediation: Bad vs Good */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-white flex items-center gap-2">
                  <Code2 className="w-4 h-4 text-[#FF3E00]" />
                  Comparativo de Código: Padrão Inseguro vs. Padrão Seguro
                </span>
                <button
                  onClick={() => handleCopy(selectedEntry.safePattern.good, 'safe-code')}
                  className="px-3 py-1.5 bg-[#111] hover:bg-[#222] border border-[#333] text-xs font-mono text-white flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  {copiedKey === 'safe-code' ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey === 'safe-code' ? 'Copiado!' : 'Copiar Seguro'}</span>
                </button>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Bad pattern */}
                <div className="p-4 bg-[#140502] border border-[#FF3E00]/40 space-y-2">
                  <div className="text-[10px] font-mono text-[#FF3E00] font-black uppercase tracking-wider flex items-center gap-1.5">
                    <X className="w-3.5 h-3.5" />
                    Padrão Inseguro (Vulnerável a Extração)
                  </div>
                  <pre className="text-xs font-mono text-[#FFC4B0] p-3 bg-black/70 border border-[#360B00] overflow-x-auto whitespace-pre">
                    {selectedEntry.safePattern.bad}
                  </pre>
                </div>

                {/* Good pattern */}
                <div className="p-4 bg-[#031505] border border-[#00FF41]/40 space-y-2">
                  <div className="text-[10px] font-mono text-[#00FF41] font-black uppercase tracking-wider flex items-center gap-1.5">
                    <Check className="w-3.5 h-3.5" />
                    Padrão Seguro (Hardening Recomendado)
                  </div>
                  <pre className="text-xs font-mono text-[#B9F6CA] p-3 bg-black/70 border border-[#00380E] overflow-x-auto whitespace-pre">
                    {selectedEntry.safePattern.good}
                  </pre>
                </div>
              </div>

              <p className="text-xs font-mono text-[#888] italic bg-[#050505] p-3 border border-[#1A1A1A]">
                💡 {selectedEntry.safePattern.explanation}
              </p>
            </div>

            {/* Remediation Checklist */}
            <div className="p-5 bg-[#080808] border border-[#222] space-y-3">
              <div className="text-xs font-mono font-bold uppercase tracking-wider text-white flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-[#FF3E00]" />
                Checklist de Remediação &amp; Contenção Imediata
              </div>

              <div className="space-y-2 text-xs font-mono text-[#CCC]">
                {selectedEntry.remediationSteps.map((step, idx) => (
                  <div key={idx} className="flex items-start gap-2.5 p-2 bg-[#050505] border border-[#1A1A1A]">
                    <span className="w-5 h-5 bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/30 flex items-center justify-center font-bold text-[10px] shrink-0">
                      {idx + 1}
                    </span>
                    <span className="leading-relaxed">{step}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Secret Rotation Protocol */}
            <div className="p-4 bg-[#050505] border border-[#222] space-y-2 font-mono text-xs">
              <div className="flex items-center gap-2 text-[#AAA] uppercase font-bold text-[10px]">
                <RotateCw className="w-3.5 h-3.5 text-[#FF3E00]" />
                Protocolo de Rotação do Segredo:
              </div>
              <p className="text-[#888] leading-relaxed">
                {selectedEntry.rotationRecommendation}
              </p>
            </div>

            {/* External Reference Links */}
            <div className="pt-3 border-t border-[#222] flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="text-[#666]">Fontes Oficiais:</span>
                <a
                  href={selectedEntry.cwe.url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-[#FF3E00] hover:underline flex items-center gap-1 font-bold"
                >
                  <span>MITRE CWE Database</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              <div className="flex items-center gap-1.5">
                {selectedEntry.tags.map(tag => (
                  <span key={tag} className="text-[10px] px-1.5 py-0.2 bg-[#141414] text-[#888] border border-[#222]">
                    #{tag}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-[#080808] border-t border-[#222] flex items-center justify-between shrink-0 font-mono text-xs">
          <div className="text-[#666] hidden sm:block">
            Mapeamento em conformidade com OWASP Top 10 e CWE Top 25 Most Dangerous Software Weaknesses.
          </div>
          <button
            onClick={onClose}
            className="px-6 py-2.5 bg-[#141414] hover:bg-white hover:text-black border border-[#333] text-white font-bold text-xs uppercase tracking-wider transition-colors ml-auto cursor-pointer"
          >
            Fechar Glossário
          </button>
        </div>
      </div>
    </div>
  );
};
