import React, { useState, useMemo } from 'react';
import { 
  BookOpen, 
  X, 
  Search, 
  ArrowRight, 
  Sparkles, 
  Code2, 
  ShieldCheck, 
  Copy, 
  Check, 
  Terminal, 
  Layers,
  ChevronRight,
  ExternalLink,
  HelpCircle,
  Play
} from 'lucide-react';
import { TOOL_GUIDES, ToolGuideItem } from '../lib/toolGuideData';

interface ToolGuideModalProps {
  isOpen: boolean;
  onClose: () => void;
  activeTab?: string;
  onNavigateToTab: (tabId: string) => void;
}

export const ToolGuideModal: React.FC<ToolGuideModalProps> = ({
  isOpen,
  onClose,
  activeTab = 'compliance',
  onNavigateToTab
}) => {
  const [selectedToolId, setSelectedToolId] = useState<string>(activeTab in TOOL_GUIDES ? activeTab : 'compliance');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  // Sync selectedToolId if activeTab changes and modal opens
  React.useEffect(() => {
    if (activeTab && activeTab in TOOL_GUIDES) {
      setSelectedToolId(activeTab);
    }
  }, [activeTab, isOpen]);

  const categories = ['ALL', 'Conformidade & Governança', 'AppSec & SAST', 'Defesa & Runtime', 'Infraestrutura & DevSecOps'];

  const filteredTools = useMemo(() => {
    const list = Object.values(TOOL_GUIDES);
    return list.filter(item => {
      if (selectedCategory !== 'ALL' && item.category !== selectedCategory) return false;
      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase();
        return item.name.toLowerCase().includes(q) || 
               item.shortSummary.toLowerCase().includes(q) ||
               item.badge.toLowerCase().includes(q);
      }
      return true;
    });
  }, [selectedCategory, searchTerm]);

  const currentTool: ToolGuideItem = TOOL_GUIDES[selectedToolId] || TOOL_GUIDES['compliance'];

  if (!isOpen) return null;

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(label);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const handleSelectToolAndGo = (id: string) => {
    onNavigateToTab(id);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-md flex items-center justify-center p-3 sm:p-5">
      <div className="bg-[#0A0A0A] max-w-5xl w-full h-[90vh] max-h-[850px] border border-[#2B2B2B] shadow-2xl flex flex-col overflow-hidden rounded-xl animate-in fade-in zoom-in-95 duration-200">
        
        {/* Header Bar */}
        <div className="p-4 sm:p-5 bg-[#0F0F0F] border-b border-[#222] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[#FF3E00]/10 border border-[#FF3E00]/30 flex items-center justify-center text-[#FF3E00]">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base sm:text-lg font-bold font-mono tracking-tight text-white uppercase">
                  Manual de Uso &amp; Guia das Ferramentas
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/30 font-bold">
                  Docs &amp; Exemplos Práticos
                </span>
              </div>
              <p className="text-xs text-zinc-400 font-mono mt-0.5">
                Explicação detalhada de cada módulo, arquitetura de funcionamento, passo a passo no sistema e exemplos reais.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-[#141414] hover:bg-[#222] text-zinc-400 hover:text-white border border-[#333] flex items-center justify-center transition-colors cursor-pointer"
            title="Fechar Manual"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Area: Two-column layout (Sidebar + Detail) */}
        <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
          
          {/* Left Navigation: List of Tools */}
          <div className="w-full md:w-72 lg:w-80 bg-[#080808] border-b md:border-b-0 md:border-r border-[#222] flex flex-col shrink-0">
            {/* Search Input */}
            <div className="p-3 border-b border-[#1C1C1C]">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Filtrar ferramentas..."
                  className="w-full bg-[#111] border border-[#2A2A2A] rounded-md pl-8 pr-3 py-1.5 text-xs text-white placeholder-zinc-500 font-mono focus:outline-none focus:border-[#FF3E00]/60"
                />
              </div>
            </div>

            {/* Category Filter Pills */}
            <div className="px-3 py-2 border-b border-[#1C1C1C] flex gap-1 overflow-x-auto no-scrollbar">
              {categories.map((cat) => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`text-[10px] font-mono px-2 py-0.5 rounded whitespace-nowrap transition-colors cursor-pointer ${
                    selectedCategory === cat
                      ? 'bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40 font-bold'
                      : 'bg-[#121212] text-zinc-400 hover:text-zinc-200 border border-transparent'
                  }`}
                >
                  {cat === 'ALL' ? 'Todas' : cat.split(' ')[0]}
                </button>
              ))}
            </div>

            {/* List of tools */}
            <div className="flex-1 overflow-y-auto p-2 space-y-1">
              {filteredTools.map((tool) => {
                const isSelected = selectedToolId === tool.id;
                return (
                  <button
                    key={tool.id}
                    onClick={() => setSelectedToolId(tool.id)}
                    className={`w-full text-left p-2.5 rounded-lg border transition-all cursor-pointer flex items-center justify-between gap-2 ${
                      isSelected
                        ? 'bg-[#171717] border-[#FF3E00]/50 text-white shadow-xs'
                        : 'bg-transparent border-transparent text-zinc-400 hover:bg-[#111] hover:text-zinc-200'
                    }`}
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="text-xs font-mono font-bold truncate">
                          {tool.name}
                        </span>
                      </div>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-black/50 text-[#00F0FF] border border-cyan-900/40">
                          {tool.badge}
                        </span>
                        <span className="text-[9px] text-zinc-500 truncate font-mono">
                          {tool.category}
                        </span>
                      </div>
                    </div>
                    <ChevronRight className={`w-3.5 h-3.5 shrink-0 ${isSelected ? 'text-[#FF3E00]' : 'text-zinc-600'}`} />
                  </button>
                );
              })}
            </div>
          </div>

          {/* Right Detail Pane */}
          <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6 bg-[#0B0B0B]">
            {/* Header info of selected tool */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1C1C1C] pb-4">
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/60 font-bold uppercase">
                    {currentTool.category}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/30 font-bold">
                    {currentTool.badge}
                  </span>
                </div>
                <h3 className="text-lg sm:text-xl font-black font-mono tracking-tight text-white mt-1">
                  {currentTool.name}
                </h3>
                <p className="text-xs text-zinc-300 font-mono mt-1 max-w-3xl leading-relaxed">
                  {currentTool.shortSummary}
                </p>
              </div>

              <button
                onClick={() => handleSelectToolAndGo(currentTool.id)}
                className="px-3.5 py-2 rounded-lg bg-[#FF3E00] hover:bg-[#E03700] text-white font-mono text-xs font-bold uppercase tracking-wider flex items-center gap-2 shrink-0 transition-colors shadow-sm cursor-pointer"
              >
                <span>Ir para a Ferramenta</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* 1. Como Funciona (Arquitetura e Teoria) */}
            <div className="bg-[#101010] border border-[#222] rounded-xl p-4 sm:p-5 space-y-2">
              <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs font-bold uppercase tracking-wider">
                <Sparkles className="w-4 h-4" />
                <span>1. O que é e Como Funciona por baixo dos panos</span>
              </div>
              <div className="text-xs text-zinc-300 font-mono leading-relaxed whitespace-pre-line">
                {currentTool.howItWorks}
              </div>
            </div>

            {/* 2. Como Usar no Sistema (Passo a Passo) */}
            <div className="bg-[#101010] border border-[#222] rounded-xl p-4 sm:p-5 space-y-3">
              <div className="flex items-center gap-2 text-amber-400 font-mono text-xs font-bold uppercase tracking-wider">
                <Play className="w-4 h-4" />
                <span>2. Como Usar no SecScan (Passo a Passo Prático)</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {currentTool.stepByStepGuide.map((step) => (
                  <div key={step.step} className="bg-[#0A0A0A] border border-[#1F1F1F] rounded-lg p-3 flex gap-2.5">
                    <span className="w-6 h-6 rounded bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/30 text-xs font-bold font-mono flex items-center justify-center shrink-0">
                      {step.step}
                    </span>
                    <div>
                      <h4 className="text-xs font-bold font-mono text-white">
                        {step.action}
                      </h4>
                      <p className="text-[11px] text-zinc-400 font-mono mt-0.5 leading-relaxed">
                        {step.description}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* 3. Exemplo Prático Completo */}
            <div className="bg-[#101010] border border-[#222] rounded-xl p-4 sm:p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-[#00FF41] font-mono text-xs font-bold uppercase tracking-wider">
                  <Code2 className="w-4 h-4" />
                  <span>3. Exemplo Prático &amp; Cenário Real</span>
                </div>
                <span className="text-[10px] font-mono text-zinc-400">
                  {currentTool.example.title}
                </span>
              </div>

              {/* Scenario Context */}
              <div className="p-3 bg-[#0A0A0A] border border-[#1A1A1A] rounded-lg text-xs font-mono text-zinc-300">
                <strong className="text-zinc-200">Cenário:</strong> {currentTool.example.scenario}
              </div>

              {/* Input Snippet / Test Payload */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400">
                  <span>Código / Requisição de Entrada:</span>
                  <button
                    onClick={() => handleCopy(currentTool.example.inputSnippet, 'input')}
                    className="flex items-center gap-1 hover:text-white transition-colors cursor-pointer"
                  >
                    {copiedSection === 'input' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedSection === 'input' ? 'Copiado!' : 'Copiar'}</span>
                  </button>
                </div>
                <pre className="p-3 bg-[#050505] border border-[#222] rounded-lg text-xs font-mono text-rose-300 overflow-x-auto leading-relaxed">
                  {currentTool.example.inputSnippet}
                </pre>
              </div>

              {/* System Detection */}
              <div className="space-y-1">
                <span className="text-[11px] font-mono text-zinc-400">Detecção e Diagnóstico da Ferramenta:</span>
                <div className="p-3 bg-[#0A0A0A] border border-amber-900/30 rounded-lg text-xs font-mono text-amber-300 leading-relaxed whitespace-pre-line">
                  {currentTool.example.systemDetection}
                </div>
              </div>

              {/* Output Remediation */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400">
                  <span className="text-[#00FF41]">Solução / Código Remediado:</span>
                  <button
                    onClick={() => handleCopy(currentTool.example.outputRemediation, 'output')}
                    className="flex items-center gap-1 text-[#00FF41] hover:text-white transition-colors cursor-pointer"
                  >
                    {copiedSection === 'output' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedSection === 'output' ? 'Copiado!' : 'Copiar'}</span>
                  </button>
                </div>
                <pre className="p-3 bg-[#050505] border border-[#00FF41]/30 rounded-lg text-xs font-mono text-[#00FF41] overflow-x-auto leading-relaxed whitespace-pre-line">
                  {currentTool.example.outputRemediation}
                </pre>
              </div>
            </div>

            {/* Quick Action Footer */}
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-lg bg-[#141414] hover:bg-[#222] text-zinc-300 font-mono text-xs font-bold uppercase tracking-wider transition-colors cursor-pointer border border-[#333]"
              >
                Fechar
              </button>
              <button
                onClick={() => handleSelectToolAndGo(currentTool.id)}
                className="px-4 py-2 rounded-lg bg-[#FF3E00] hover:bg-[#E03700] text-white font-mono text-xs font-bold uppercase tracking-wider flex items-center gap-2 transition-colors cursor-pointer"
              >
                <span>Usar esta Ferramenta Agora</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
