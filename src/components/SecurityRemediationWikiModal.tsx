import React, { useState, useMemo, useEffect } from 'react';
import { 
  BookOpen, 
  Search, 
  X, 
  ShieldAlert, 
  Check, 
  Copy, 
  ExternalLink, 
  AlertTriangle, 
  Terminal, 
  FileCode, 
  GitBranch, 
  RotateCw, 
  ShieldCheck, 
  Sparkles, 
  ChevronRight,
  Flame,
  ArrowRight,
  Layers,
  Filter,
  CheckCircle2,
  Lock,
  Code2
} from 'lucide-react';
import { 
  RemediationWikiGuide, 
  REMEDIATION_WIKI_GUIDES, 
  getRemediationGuideForFinding,
  RemediationStep 
} from '../lib/remediationWikiData';
import { ScanFinding } from '../types';

interface SecurityRemediationWikiModalProps {
  isOpen: boolean;
  onClose: () => void;
  selectedGuideId?: string;
  initialFinding?: ScanFinding | null;
  findings?: ScanFinding[];
  onNavigateToFileLine?: (fileName: string, line: number) => void;
}

export const SecurityRemediationWikiModal: React.FC<SecurityRemediationWikiModalProps> = ({
  isOpen,
  onClose,
  selectedGuideId,
  initialFinding,
  findings = [],
  onNavigateToFileLine
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [showOnlyDetected, setShowOnlyDetected] = useState<boolean>(false);
  const [activeGuideId, setActiveGuideId] = useState<string>(selectedGuideId || REMEDIATION_WIKI_GUIDES[0].id);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeStepTab, setActiveStepTab] = useState<number>(0);

  // Group findings by guide ID
  const detectedGuideCounts = useMemo(() => {
    const counts: Record<string, { count: number; findings: ScanFinding[] }> = {};
    findings.forEach(f => {
      const guide = getRemediationGuideForFinding(f);
      if (!counts[guide.id]) {
        counts[guide.id] = { count: 0, findings: [] };
      }
      counts[guide.id].count += 1;
      counts[guide.id].findings.push(f);
    });
    return counts;
  }, [findings]);

  // If initialFinding is supplied, focus its guide on open
  useEffect(() => {
    if (initialFinding) {
      const guide = getRemediationGuideForFinding(initialFinding);
      setActiveGuideId(guide.id);
    } else if (selectedGuideId) {
      setActiveGuideId(selectedGuideId);
    }
  }, [initialFinding, selectedGuideId, isOpen]);

  // Keyboard close
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Filtered guides
  const filteredGuides = useMemo(() => {
    return REMEDIATION_WIKI_GUIDES.filter(guide => {
      // Detected only filter
      if (showOnlyDetected && !detectedGuideCounts[guide.id]) {
        return false;
      }

      // Category filter
      if (selectedCategory !== 'ALL' && guide.category !== selectedCategory) {
        return false;
      }

      // Severity filter
      if (selectedSeverity !== 'ALL' && guide.severity !== selectedSeverity) {
        return false;
      }

      // Search query
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        guide.title.toLowerCase().includes(q) ||
        guide.cwe.id.toLowerCase().includes(q) ||
        guide.cwe.name.toLowerCase().includes(q) ||
        guide.owasp.code.toLowerCase().includes(q) ||
        guide.summary.toLowerCase().includes(q) ||
        guide.threatScenario.toLowerCase().includes(q) ||
        guide.tags.some(t => t.toLowerCase().includes(q)) ||
        guide.applicableRuleIds.some(r => r.toLowerCase().includes(q))
      );
    });
  }, [searchQuery, selectedCategory, selectedSeverity, showOnlyDetected, detectedGuideCounts]);

  const activeGuide = useMemo(() => {
    return (
      REMEDIATION_WIKI_GUIDES.find(g => g.id === activeGuideId) ||
      filteredGuides[0] ||
      REMEDIATION_WIKI_GUIDES[0]
    );
  }, [activeGuideId, filteredGuides]);

  const activeOccurrences = useMemo(() => {
    return detectedGuideCounts[activeGuide.id]?.findings || [];
  }, [detectedGuideCounts, activeGuide.id]);

  if (!isOpen) return null;

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleCopyFullMarkdown = (guide: RemediationWikiGuide) => {
    const md = `### 🛡️ Guia de Remediação: ${guide.title}
**Severidade:** ${guide.severity} (CVSS ${guide.cvssScore}) | **CWE:** [${guide.cwe.id}](${guide.cwe.url}) - ${guide.cwe.name} | **OWASP:** ${guide.owasp.code}

#### 📋 Resumo
${guide.summary}

#### ⚠️ Cenário de Ameaça & Raio de Explosão
- **Ameaça:** ${guide.threatScenario}
- **Impacto:** ${guide.blastRadius}

#### 🛠️ Plano de Remediação Passo a Passo:
${guide.stepByStepPatching.map(s => `##### Passo ${s.stepNumber}: ${s.title}
${s.description}
${s.commandOrSnippet ? `\`\`\`${s.commandType || 'bash'}\n${s.commandOrSnippet}\n\`\`\`` : ''}
> 💡 *Nota-chave:* ${s.keyTakeaway}
`).join('\n')}

#### 💻 Código: Antes vs. Depois
\`\`\`${guide.beforeAfterCode.language}
// INSEGURO:
${guide.beforeAfterCode.before}

// SEGURO:
${guide.beforeAfterCode.after}
\`\`\`

#### 🧹 Expurgo do Histórico Git:
\`\`\`bash
${guide.gitHistoryPurge.command}
\`\`\`
*Aviso:* ${guide.gitHistoryPurge.warning}

---
*Gerado automaticamente via SecScan Security Remediation Wiki*`;

    handleCopy(md, 'full-markdown');
  };

  const severityColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'text-[#FF3E00] border-[#FF3E00]/40 bg-[#220700]';
      case 'HIGH':
        return 'text-[#FF7A00] border-[#FF7A00]/40 bg-[#221000]';
      case 'MEDIUM':
        return 'text-[#FFD600] border-[#FFD600]/40 bg-[#221D00]';
      default:
        return 'text-[#00FF41] border-[#00FF41]/40 bg-[#002209]';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 md:p-6 bg-black/85 backdrop-blur-sm animate-in fade-in duration-150">
      <div 
        id="security-remediation-wiki-modal"
        className="w-full max-w-7xl bg-[#0A0A0A] border-2 border-[#333] shadow-[0_0_60px_rgba(0,0,0,0.95)] h-[94vh] flex flex-col overflow-hidden text-white font-sans"
      >
        {/* Top Header */}
        <div className="p-4 sm:p-5 bg-[#080808] border-b border-[#222] flex items-start justify-between gap-4 shrink-0">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 bg-[#FF3E00]/15 border border-[#FF3E00]/40 text-[#FF3E00] font-mono text-[10px] font-black uppercase tracking-widest">
                <BookOpen className="w-3.5 h-3.5" />
                SECURITY REMEDIATION WIKI &amp; PATCHING PLAYBOOKS
              </span>
              <span className="text-[10px] font-mono text-[#888]">
                // GUIA PASSO A PASSO PARA DEVSECOPS
              </span>
              {findings.length > 0 && (
                <span className="inline-flex items-center gap-1 text-[10px] font-mono bg-[#141414] text-[#00FF41] border border-[#00FF41]/30 px-2 py-0.5 font-bold">
                  <Flame className="w-3 h-3 text-[#FF3E00]" />
                  {Object.keys(detectedGuideCounts).length} VULNERABILIDADES DETECTADAS NO PROJETO
                </span>
              )}
            </div>

            <h2 className="text-lg sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2">
              <span>Wiki de Remediação &amp; Correção de Vulnerabilidades</span>
            </h2>
            <p className="text-xs font-mono text-[#888] max-w-3xl leading-relaxed">
              Playbooks técnicos e passo a passo para contenção imediata, substituição de código inseguro, expurgo de histórico Git e rotação segura de credenciais.
            </p>
          </div>

          <button
            id="btn-close-remediation-wiki-modal"
            onClick={onClose}
            className="w-9 h-9 bg-[#111] hover:bg-[#FF3E00] hover:text-white text-[#888] border border-[#333] flex items-center justify-center transition-colors shrink-0 cursor-pointer"
            title="Fechar Wiki (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Active Context Banner when triggered from a specific finding */}
        {initialFinding && (
          <div className="px-4 py-2.5 bg-[#140600] border-b border-[#FF3E00]/30 flex flex-wrap items-center justify-between gap-3 shrink-0">
            <div className="flex items-center gap-2.5 text-xs font-mono">
              <span className="px-2 py-0.5 bg-[#FF3E00] text-white font-black text-[9px] uppercase tracking-wider">
                OCORRÊNCIA VINCULADA
              </span>
              <span className="text-white font-bold">{initialFinding.ruleName}</span>
              <span className="text-[#888]">em</span>
              <span className="text-[#00FF41] underline">{initialFinding.file}:{initialFinding.line}</span>
              <span className="text-[#666] hidden sm:inline">•</span>
              <span className="text-[#AAA] font-mono text-[11px] bg-[#000] px-2 py-0.5 border border-[#222]">
                {initialFinding.maskedSecret}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono text-[#FF7A00]">
                Exibindo playbook específico abaixo
              </span>
            </div>
          </div>
        )}

        {/* Filter & Search Bar */}
        <div className="p-3 sm:p-4 bg-[#0D0D0D] border-b border-[#1E1E1E] flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 shrink-0">
          {/* Search Input */}
          <div className="relative flex-1 max-w-md">
            <Search className="w-3.5 h-3.5 text-[#666] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Buscar por tipo, CWE, AWS, Stripe, JWT, banco..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#050505] border border-[#2A2A2A] text-xs font-mono text-white pl-9 pr-8 py-2 focus:border-[#FF3E00] focus:outline-none placeholder:text-[#555]"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#666] hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Quick Filters */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Toggle Detectadas no Scan */}
            <button
              onClick={() => setShowOnlyDetected(!showOnlyDetected)}
              className={`px-3 py-1.5 text-[10px] font-mono font-bold uppercase tracking-wider border transition-all flex items-center gap-1.5 cursor-pointer ${
                showOnlyDetected
                  ? 'bg-[#FF3E00] text-white border-[#FF3E00]'
                  : 'bg-[#141414] text-[#AAA] border-[#333] hover:border-[#FF3E00]/60 hover:text-white'
              }`}
            >
              <Flame className="w-3 h-3 text-amber-400" />
              <span>Apenas Detectadas ({Object.keys(detectedGuideCounts).length})</span>
            </button>

            {/* Severity Filter Dropdown */}
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-[#141414] border border-[#333] text-[10px] font-mono text-[#AAA] px-2.5 py-1.5 uppercase font-bold focus:border-[#FF3E00] focus:outline-none cursor-pointer"
            >
              <option value="ALL">Todas Severidades</option>
              <option value="CRITICAL">Crítica (CVSS 9.0+)</option>
              <option value="HIGH">Alta (CVSS 7.0-8.9)</option>
              <option value="MEDIUM">Média</option>
            </select>

            {/* Category Filter Dropdown */}
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="bg-[#141414] border border-[#333] text-[10px] font-mono text-[#AAA] px-2.5 py-1.5 uppercase font-bold focus:border-[#FF3E00] focus:outline-none cursor-pointer"
            >
              <option value="ALL">Todas Categorias</option>
              <option value="CLOUD_CREDENTIAL">Credenciais Nuvem</option>
              <option value="AUTH_TOKEN">Tokens &amp; JWT</option>
              <option value="DATABASE_URI">Banco de Dados</option>
              <option value="API_KEY">Chaves de API</option>
              <option value="PRIVATE_KEY">Chaves Privadas</option>
              <option value="PASSWORD">Senhas</option>
              <option value="API_PATH">Rotas de API</option>
              <option value="ENTROPY">Alta Entropia</option>
            </select>
          </div>
        </div>

        {/* Content Body: Sidebar + Main Details */}
        <div className="flex-1 flex flex-col md:flex-row overflow-hidden min-h-0">
          {/* Left Sidebar: Guide List */}
          <div className="w-full md:w-80 lg:w-96 border-b md:border-b-0 md:border-r border-[#1E1E1E] bg-[#070707] flex flex-col shrink-0 overflow-hidden">
            <div className="p-2.5 bg-[#0A0A0A] border-b border-[#1A1A1A] flex items-center justify-between text-[10px] font-mono text-[#777]">
              <span>GUIAS CATALOGADOS ({filteredGuides.length})</span>
              <span>ORDENADOS POR IMPACTO</span>
            </div>

            <div className="flex-1 overflow-y-auto divide-y divide-[#141414]">
              {filteredGuides.length === 0 ? (
                <div className="p-8 text-center font-mono space-y-2">
                  <Filter className="w-6 h-6 text-[#555] mx-auto mb-2" />
                  <p className="text-xs text-[#888]">Nenhum playbook encontrado para estes filtros.</p>
                  <button
                    onClick={() => {
                      setSearchQuery('');
                      setSelectedCategory('ALL');
                      setSelectedSeverity('ALL');
                      setShowOnlyDetected(false);
                    }}
                    className="text-[10px] text-[#FF3E00] underline font-bold uppercase"
                  >
                    Resetar Filtros
                  </button>
                </div>
              ) : (
                filteredGuides.map(guide => {
                  const isSelected = guide.id === activeGuide.id;
                  const detectedInfo = detectedGuideCounts[guide.id];

                  return (
                    <button
                      key={guide.id}
                      onClick={() => {
                        setActiveGuideId(guide.id);
                        setActiveStepTab(0);
                      }}
                      className={`w-full text-left p-3.5 transition-all flex flex-col gap-1.5 cursor-pointer relative group ${
                        isSelected 
                          ? 'bg-[#141414] border-l-4 border-l-[#FF3E00]' 
                          : 'hover:bg-[#0E0E0E]'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-1.5">
                        <div className="flex items-center gap-1.5">
                          <span className={`text-[9px] font-mono px-1.5 py-0.2 border font-bold uppercase ${severityColor(guide.severity)}`}>
                            {guide.severity}
                          </span>
                          <span className="text-[9px] font-mono text-[#888]">
                            {guide.cwe.id}
                          </span>
                        </div>

                        {detectedInfo ? (
                          <span className="inline-flex items-center gap-1 text-[9px] font-mono font-bold bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/40 px-1.5 py-0.5">
                            <Flame className="w-2.5 h-2.5" />
                            {detectedInfo.count} {detectedInfo.count === 1 ? 'detectado' : 'detectados'}
                          </span>
                        ) : (
                          <span className="text-[9px] font-mono text-[#555]">
                            Referência
                          </span>
                        )}
                      </div>

                      <h4 className={`text-xs font-bold transition-colors line-clamp-1 ${
                        isSelected ? 'text-white' : 'text-[#CCC] group-hover:text-white'
                      }`}>
                        {guide.title}
                      </h4>

                      <p className="text-[10px] font-mono text-[#666] line-clamp-2 leading-relaxed">
                        {guide.summary}
                      </p>

                      <div className="flex flex-wrap items-center gap-1 pt-0.5">
                        {guide.tags.slice(0, 3).map(tag => (
                          <span key={tag} className="text-[8px] font-mono text-[#555] bg-[#111] px-1 py-0.2 border border-[#222]">
                            #{tag}
                          </span>
                        ))}
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          </div>

          {/* Right Main Panel: Comprehensive Remediation Playbook */}
          <div className="flex-1 overflow-y-auto bg-[#0A0A0A] p-4 sm:p-6 space-y-6">
            {/* Guide Header Banner */}
            <div className="p-5 bg-[#0E0E0E] border border-[#222] space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#1A1A1A] pb-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`text-[10px] font-mono px-2 py-0.5 border font-bold uppercase tracking-wider ${severityColor(activeGuide.severity)}`}>
                    SEVERIDADE: {activeGuide.severity}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 bg-[#141414] text-[#AAA] border border-[#333] font-bold">
                    CVSS {activeGuide.cvssScore}
                  </span>
                  <a
                    href={activeGuide.cwe.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] font-mono text-[#00FF41] hover:underline flex items-center gap-1 bg-[#141414] px-2 py-0.5 border border-[#222]"
                    title="Ver definição oficial no MITRE CWE"
                  >
                    <span>{activeGuide.cwe.id}</span>
                    <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                  <span className="text-[10px] font-mono text-[#888] bg-[#141414] px-2 py-0.5 border border-[#222]">
                    OWASP {activeGuide.owasp.code} ({activeGuide.owasp.title})
                  </span>
                </div>

                {/* Action Buttons */}
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopyFullMarkdown(activeGuide)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-mono font-bold uppercase tracking-wider text-black bg-white hover:bg-[#FF3E00] hover:text-white transition-colors cursor-pointer"
                    title="Copiar Playbook formatado em Markdown para tickets/Jira/PR"
                  >
                    {copiedKey === 'full-markdown' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                    <span>Copiar Guia (Markdown)</span>
                  </button>
                </div>
              </div>

              <div>
                <h3 className="text-lg sm:text-xl font-black uppercase text-white tracking-wide">
                  {activeGuide.title}
                </h3>
                <p className="text-xs font-mono text-[#AAA] mt-1.5 leading-relaxed">
                  {activeGuide.summary}
                </p>
              </div>

              {/* Threat Scenario & Blast Radius Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                <div className="p-3 bg-[#050505] border border-[#222] space-y-1">
                  <div className="flex items-center gap-1.5 text-[10px] font-mono font-bold text-[#FF7A00] uppercase tracking-wider">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>Cenário de Exploração do Atacante:</span>
                  </div>
                  <p className="text-[11px] font-mono text-[#888] leading-relaxed">
                    {activeGuide.threatScenario}
                  </p>
                </div>

                <div className="p-3 bg-[#050505] border border-[#222] space-y-1">
                  <div className="flex items-center gap-1.5 text-[10px] font-mono font-bold text-[#FF3E00] uppercase tracking-wider">
                    <Flame className="w-3.5 h-3.5" />
                    <span>Raio de Explosão (Blast Radius):</span>
                  </div>
                  <p className="text-[11px] font-mono text-[#888] leading-relaxed">
                    {activeGuide.blastRadius}
                  </p>
                </div>
              </div>
            </div>

            {/* If there are occurrences in this scan, display them here! */}
            {activeOccurrences.length > 0 && (
              <div className="p-4 bg-[#120500] border border-[#FF3E00]/40 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Flame className="w-4 h-4 text-[#FF3E00]" />
                    <h4 className="text-xs font-black uppercase tracking-wider text-white">
                      Ocorrências Detectadas no Workspace Atual ({activeOccurrences.length})
                    </h4>
                  </div>
                  <span className="text-[10px] font-mono text-[#FF7A00]">
                    Clique em um arquivo para ir até a linha
                  </span>
                </div>

                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {activeOccurrences.map(f => (
                    <div
                      key={f.id}
                      className="p-2.5 bg-[#0A0A0A] border border-[#2A1510] flex flex-wrap items-center justify-between gap-2 text-xs font-mono"
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-[9px] px-1.5 py-0.5 bg-[#FF3E00] text-white font-bold">
                          L{f.line}
                        </span>
                        <span className="text-white font-bold">{f.file}</span>
                        <span className="text-[#666]">|</span>
                        <span className="text-[#FF7A00] text-[11px] truncate max-w-xs">{f.maskedSecret}</span>
                      </div>

                      <div className="flex items-center gap-2">
                        {onNavigateToFileLine && (
                          <button
                            onClick={() => {
                              onNavigateToFileLine(f.file, f.line);
                              onClose();
                            }}
                            className="px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider bg-[#1E1E1E] hover:bg-[#FF3E00] text-white border border-[#333] transition-colors"
                          >
                            Inspecionar no Scanner &rarr;
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* STEP-BY-STEP PLAYBOOK SECTION */}
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-[#222] pb-2">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-[#FF3E00]" />
                  <h4 className="text-xs font-black uppercase tracking-[0.15em] text-white">
                    Plano de Ação Passo a Passo para Correção
                  </h4>
                </div>
                <span className="text-[10px] font-mono text-[#888]">
                  {activeGuide.stepByStepPatching.length} ETAPAS RECOMENDADAS
                </span>
              </div>

              {/* Stepper Steps List */}
              <div className="space-y-4">
                {activeGuide.stepByStepPatching.map((step, idx) => (
                  <div 
                    key={step.stepNumber}
                    className="border border-[#222] bg-[#080808] p-4 space-y-3 relative group hover:border-[#333] transition-colors"
                  >
                    {/* Step Title Header */}
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <div className="w-6 h-6 rounded-none bg-[#FF3E00] text-white font-mono font-black text-xs flex items-center justify-center shrink-0">
                          {step.stepNumber}
                        </div>
                        <div>
                          <h5 className="text-xs font-bold text-white uppercase tracking-wide">
                            {step.title}
                          </h5>
                        </div>
                      </div>

                      {step.commandOrSnippet && (
                        <button
                          onClick={() => handleCopy(step.commandOrSnippet!, `step-${idx}`)}
                          className="px-2 py-1 bg-[#141414] hover:bg-[#222] border border-[#333] text-[#AAA] hover:text-white text-[10px] font-mono inline-flex items-center gap-1 transition-colors"
                          title="Copiar comando ou snippet"
                        >
                          {copiedKey === `step-${idx}` ? (
                            <>
                              <Check className="w-3 h-3 text-[#00FF41]" />
                              <span className="text-[#00FF41]">Copiado</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copiar</span>
                            </>
                          )}
                        </button>
                      )}
                    </div>

                    {/* Step Description */}
                    <p className="text-xs font-mono text-[#AAA] pl-9 leading-relaxed">
                      {step.description}
                    </p>

                    {/* Step Command / Code Snippet */}
                    {step.commandOrSnippet && (
                      <div className="pl-9">
                        <div className="bg-[#000] border border-[#1E1E1E] p-3 font-mono text-xs text-[#00FF41] overflow-x-auto relative">
                          <div className="text-[9px] font-mono text-[#555] mb-1 uppercase tracking-wider flex items-center gap-1">
                            <Terminal className="w-3 h-3 text-[#FF3E00]" />
                            <span>{step.commandType === 'bash' ? 'Terminal Shell' : step.commandType === 'sql' ? 'SQL Query' : step.commandType === 'env' ? 'Configuração (.env)' : 'Código'}</span>
                          </div>
                          <pre className="whitespace-pre-wrap break-all leading-relaxed">
                            {step.commandOrSnippet}
                          </pre>
                        </div>
                      </div>
                    )}

                    {/* Key Takeaway */}
                    <div className="pl-9">
                      <div className="text-[10px] font-mono text-[#FF7A00] flex items-center gap-1.5 bg-[#140C00] p-2 border-l-2 border-l-[#FF7A00]">
                        <AlertTriangle className="w-3 h-3 shrink-0" />
                        <span><strong>Nota Crítica:</strong> {step.keyTakeaway}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* BEFORE VS AFTER CODE SECTION */}
            <div className="space-y-3 pt-2">
              <div className="flex items-center justify-between border-b border-[#222] pb-2">
                <div className="flex items-center gap-2">
                  <Code2 className="w-4 h-4 text-[#00FF41]" />
                  <h4 className="text-xs font-black uppercase tracking-[0.15em] text-white">
                    Refatoração de Código: Antes vs. Depois
                  </h4>
                </div>
                <button
                  onClick={() => handleCopy(activeGuide.beforeAfterCode.after, 'after-code')}
                  className="text-[10px] font-mono text-[#00FF41] hover:underline flex items-center gap-1 font-bold"
                >
                  {copiedKey === 'after-code' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  <span>Copiar Padrão Seguro</span>
                </button>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Before: Insecure */}
                <div className="border border-[#FF3E00]/30 bg-[#080200] p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono font-bold text-[#FF3E00] uppercase tracking-wider flex items-center gap-1">
                      <X className="w-3 h-3" />
                      Padrão Inseguro (Detectado)
                    </span>
                    <button
                      onClick={() => handleCopy(activeGuide.beforeAfterCode.before, 'before-code')}
                      className="text-[#666] hover:text-white p-1"
                      title="Copiar código antes"
                    >
                      <Copy className="w-3 h-3" />
                    </button>
                  </div>
                  <pre className="p-3 bg-[#000] border border-[#2A0F00] text-[11px] font-mono text-[#FF8A80] overflow-x-auto whitespace-pre-wrap">
                    {activeGuide.beforeAfterCode.before}
                  </pre>
                </div>

                {/* After: Safe */}
                <div className="border border-[#00FF41]/30 bg-[#000A03] p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono font-bold text-[#00FF41] uppercase tracking-wider flex items-center gap-1">
                      <Check className="w-3 h-3" />
                      Padrão Seguro Recomendado
                    </span>
                    <button
                      onClick={() => handleCopy(activeGuide.beforeAfterCode.after, 'after-code-btn')}
                      className="text-[#666] hover:text-[#00FF41] p-1"
                      title="Copiar código seguro"
                    >
                      <Copy className="w-3 h-3" />
                    </button>
                  </div>
                  <pre className="p-3 bg-[#000] border border-[#00220A] text-[11px] font-mono text-[#00FF41] overflow-x-auto whitespace-pre-wrap">
                    {activeGuide.beforeAfterCode.after}
                  </pre>
                </div>
              </div>

              <p className="text-[11px] font-mono text-[#888] bg-[#0D0D0D] p-2.5 border border-[#1E1E1E]">
                💡 <strong>Por que esta mudança funciona:</strong> {activeGuide.beforeAfterCode.explanation}
              </p>
            </div>

            {/* GIT HISTORY PURGE & ROTATION PLAYBOOK */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-2">
              {/* Git History Scrub */}
              <div className="p-4 bg-[#080808] border border-[#222] space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <GitBranch className="w-4 h-4 text-[#FF7A00]" />
                    <h5 className="text-xs font-bold uppercase tracking-wider text-white">
                      Expurgo no Histórico Git
                    </h5>
                  </div>
                  <button
                    onClick={() => handleCopy(activeGuide.gitHistoryPurge.command, 'git-purge')}
                    className="text-[10px] font-mono text-[#AAA] hover:text-white flex items-center gap-1"
                  >
                    {copiedKey === 'git-purge' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                    <span>Copiar</span>
                  </button>
                </div>

                <p className="text-[10px] font-mono text-[#888]">
                  Mesmo removendo o segredo do commit atual, clones antigos ou commits anteriores mantêm a credencial viva.
                </p>

                <div className="p-2.5 bg-[#000] border border-[#1A1A1A] font-mono text-[11px] text-[#FF7A00] overflow-x-auto">
                  <pre className="whitespace-pre-wrap break-all">
                    {activeGuide.gitHistoryPurge.command}
                  </pre>
                </div>

                <div className="p-2 bg-[#1A0A00] border border-[#FF3E00]/30 text-[10px] font-mono text-[#FF8A80]">
                  ⚠️ <strong>Aviso:</strong> {activeGuide.gitHistoryPurge.warning}
                </div>
              </div>

              {/* Secret Rotation & Long-Term Prevention */}
              <div className="p-4 bg-[#080808] border border-[#222] space-y-3">
                <div className="flex items-center gap-2">
                  <RotateCw className="w-4 h-4 text-[#00FF41]" />
                  <h5 className="text-xs font-bold uppercase tracking-wider text-white">
                    Rotação &amp; Prevenção Contínua
                  </h5>
                </div>

                <div className="space-y-1 text-xs font-mono">
                  <span className="text-[10px] font-bold text-[#AAA] uppercase">Procedimento de Rotação:</span>
                  <p className="text-[11px] text-[#888] bg-[#050505] p-2 border border-[#1A1A1A] leading-relaxed">
                    {activeGuide.secretRotationGuide}
                  </p>
                </div>

                <div className="space-y-1.5 pt-1">
                  <span className="text-[10px] font-mono font-bold text-white uppercase flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-[#00FF41]" />
                    Medidas Preventivas (DevSecOps):
                  </span>
                  <ul className="space-y-1 font-mono text-[10px] text-[#AAA]">
                    {activeGuide.preventativeMeasures.map((measure, mIdx) => (
                      <li key={mIdx} className="flex items-start gap-1.5">
                        <span className="text-[#00FF41] shrink-0 font-bold">&gt;</span>
                        <span>{measure}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-3 bg-[#080808] border-t border-[#1E1E1E] flex flex-col sm:flex-row items-center justify-between gap-3 shrink-0 text-xs font-mono text-[#888]">
          <div className="flex items-center gap-3">
            <span className="text-white font-bold flex items-center gap-1.5">
              <span className="w-2 h-2 bg-[#00FF41] inline-block animate-pulse"></span>
              SECSCAN_REMEDIATION_WIKI // ONLINE
            </span>
            <span className="text-[#444]">|</span>
            <span>{REMEDIATION_WIKI_GUIDES.length} PLAYBOOKS CATALOGADOS</span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-1.5 bg-[#141414] hover:bg-[#222] border border-[#333] hover:border-white text-white text-[10px] font-black uppercase tracking-wider transition-colors cursor-pointer"
            >
              Fechar Guia
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
