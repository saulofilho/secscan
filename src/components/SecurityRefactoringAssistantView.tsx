import React, { useState, useMemo, useCallback } from 'react';
import {
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  Eye,
  Copy,
  Check,
  ArrowRight,
  ArrowLeftRight,
  FileDiff,
  Wrench,
  Layers,
  Search,
  Filter,
  RotateCcw,
  FileCode2,
  ExternalLink,
  Lock,
  Unlock,
  KeyRound,
  Zap,
  AlertTriangle,
  CheckCircle2,
  Info,
  Terminal,
  Cpu,
  ChevronRight,
  Code2,
  BookmarkPlus
} from 'lucide-react';
import {
  ScannedFile,
  ScanFinding,
  AuditLogEvent,
  SecurityRefactoringRecipe,
  RefactoringCategory
} from '../types';
import {
  REFACTORING_RECIPES,
  findApplicableRecipes,
  parseUnifiedDiffLines
} from '../lib/securityRefactoringData';

interface SecurityRefactoringAssistantViewProps {
  files: ScannedFile[];
  findings: ScanFinding[];
  onUpdateFiles?: (updatedFiles: ScannedFile[]) => void;
  onReScan?: () => void;
  onNavigateToFile?: (filePath: string, line?: number) => void;
  onLogAudit?: (event: AuditLogEvent) => void;
}

export const SecurityRefactoringAssistantView: React.FC<SecurityRefactoringAssistantViewProps> = ({
  files,
  findings,
  onUpdateFiles,
  onReScan,
  onNavigateToFile,
  onLogAudit
}) => {
  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<RefactoringCategory | 'ALL'>('ALL');
  const [onlyMatchedInWorkspace, setOnlyMatchedInWorkspace] = useState(false);

  // Active Preview State
  const [activePreviewRecipe, setActivePreviewRecipe] = useState<SecurityRefactoringRecipe | null>(null);
  const [previewMode, setPreviewMode] = useState<'split' | 'unified'>('split');
  const [selectedTargetFile, setSelectedTargetFile] = useState<string>('');

  // Applied patches tracking (to support Undo / Revert in workspace)
  const [appliedRecipeHistory, setAppliedRecipeHistory] = useState<Record<string, { originalContent: string; appliedContent: string; filePath: string }>>({});
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Custom Snippet Playground state
  const [showCustomPlayground, setShowCustomPlayground] = useState(false);
  const [customInputCode, setCustomInputCode] = useState(`// Exemplo de código criptográfico inseguro
const crypto = require('crypto');

function hashSecret(secret) {
  return crypto.createHash('md5').update(secret).digest('hex');
}`);
  const [customSelectedArchetype, setCustomSelectedArchetype] = useState<string>('crypto-md5-to-argon2');

  // Match analysis
  const matchedAnalysis = useMemo(() => {
    return findApplicableRecipes(files, findings);
  }, [files, findings]);

  // Total matches found in current workspace
  const workspaceMatchesCount = useMemo(() => {
    return matchedAnalysis.filter(m => m.matchedFile !== undefined).length;
  }, [matchedAnalysis]);

  // Filtered recipes
  const filteredRecipes = useMemo(() => {
    return REFACTORING_RECIPES.filter(recipe => {
      // Category filter
      if (selectedCategory !== 'ALL' && recipe.category !== selectedCategory) {
        return false;
      }

      // Workspace match filter
      if (onlyMatchedInWorkspace) {
        const hasMatch = matchedAnalysis.some(m => m.recipe.id === recipe.id && m.matchedFile !== undefined);
        if (!hasMatch) return false;
      }

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesTitle = recipe.title.toLowerCase().includes(q);
        const matchesSummary = recipe.shortSummary.toLowerCase().includes(q);
        const matchesLegacy = recipe.legacyLibraryOrPattern.toLowerCase().includes(q);
        const matchesModern = recipe.modernReplacement.toLowerCase().includes(q);
        const matchesCwe = recipe.cwe.toLowerCase().includes(q);
        const matchesTags = recipe.tags.some(t => t.toLowerCase().includes(q));
        return matchesTitle || matchesSummary || matchesLegacy || matchesModern || matchesCwe || matchesTags;
      }

      return true;
    });
  }, [selectedCategory, onlyMatchedInWorkspace, searchQuery, matchedAnalysis]);

  // Copy helper
  const handleCopy = useCallback((text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  }, []);

  // Open Preview modal
  const handleOpenPreview = (recipe: SecurityRefactoringRecipe) => {
    setActivePreviewRecipe(recipe);
    // Find if a workspace file matches
    const match = matchedAnalysis.find(m => m.recipe.id === recipe.id);
    if (match?.matchedFile) {
      setSelectedTargetFile(match.matchedFile.path);
    } else {
      // Default to either first file or default target name
      setSelectedTargetFile(recipe.defaultTargetFileName || files[0]?.path || '');
    }
  };

  // Close Preview modal
  const handleClosePreview = () => {
    setActivePreviewRecipe(null);
  };

  // Apply Refactored Code to Workspace File
  const handleApplyToWorkspace = (recipe: SecurityRefactoringRecipe) => {
    if (!onUpdateFiles || files.length === 0) return;

    let target = files.find(f => f.path === selectedTargetFile || f.name === selectedTargetFile);
    
    // If not found by exact path, try finding by name or create file
    if (!target) {
      target = files.find(f => f.name.endsWith('.js') || f.name.endsWith('.ts'));
    }

    if (!target) return;

    const originalContent = target.content;
    let newContent = target.content;

    // Check if the file contains the legacy snippet or if we should replace whole/matching parts
    if (recipe.beforeCode && target.content.includes(recipe.beforeCode.trim())) {
      newContent = target.content.replace(recipe.beforeCode.trim(), recipe.afterCode.trim());
    } else {
      // Intelligently append or substitute imports and functions
      newContent = `// [SecScan Refactored] Modernized with ${recipe.modernReplacement}\n${recipe.afterCode}\n\n// --- Original Code Preserved Below ---\n${target.content}`;
    }

    const updatedFiles = files.map(f => {
      if (f.path === target?.path) {
        return {
          ...f,
          content: newContent,
          lastModified: Date.now(),
          size: new Blob([newContent]).size
        };
      }
      return f;
    });

    // Record history for Undo
    setAppliedRecipeHistory(prev => ({
      ...prev,
      [recipe.id]: {
        originalContent,
        appliedContent: newContent,
        filePath: target?.path || ''
      }
    }));

    onUpdateFiles(updatedFiles);

    if (onLogAudit) {
      onLogAudit({
        id: `audit-refactor-${Date.now()}`,
        timestamp: new Date().toISOString(),
        type: 'FIX_APPLIED',
        message: `Refatoração de segurança aplicada em ${target.path}: Substituição de ${recipe.legacyLibraryOrPattern} por ${recipe.modernReplacement} (${recipe.cwe}).`,
        severity: 'HIGH',
        details: {
          recipeId: recipe.id,
          targetFile: target.path,
          cwe: recipe.cwe,
          legacy: recipe.legacyLibraryOrPattern,
          modern: recipe.modernReplacement
        }
      });
    }

    if (onReScan) {
      setTimeout(() => onReScan(), 300);
    }
  };

  // Revert Refactored Code
  const handleRevertWorkspace = (recipeId: string) => {
    const history = appliedRecipeHistory[recipeId];
    if (!history || !onUpdateFiles) return;

    const updatedFiles = files.map(f => {
      if (f.path === history.filePath) {
        return {
          ...f,
          content: history.originalContent,
          lastModified: Date.now(),
          size: new Blob([history.originalContent]).size
        };
      }
      return f;
    });

    setAppliedRecipeHistory(prev => {
      const next = { ...prev };
      delete next[recipeId];
      return next;
    });

    onUpdateFiles(updatedFiles);

    if (onLogAudit) {
      onLogAudit({
        id: `audit-revert-${Date.now()}`,
        timestamp: new Date().toISOString(),
        type: 'FIX_APPLIED',
        message: `Refatoração de segurança revertida para o estado original em ${history.filePath}.`,
        severity: 'INFO',
        details: {
          recipeId,
          targetFile: history.filePath,
          action: 'REVERT'
        }
      });
    }

    if (onReScan) {
      setTimeout(() => onReScan(), 300);
    }
  };

  // Parsed diff lines for active preview
  const activeDiff = useMemo(() => {
    if (!activePreviewRecipe) return null;
    return parseUnifiedDiffLines(activePreviewRecipe.beforeCode, activePreviewRecipe.afterCode);
  }, [activePreviewRecipe]);

  const categories: { id: RefactoringCategory | 'ALL'; label: string; count: number }[] = [
    { id: 'ALL', label: 'Todos os Padrões', count: REFACTORING_RECIPES.length },
    { id: 'CRYPTOGRAPHY', label: 'Criptografia & Cifras', count: REFACTORING_RECIPES.filter(r => r.category === 'CRYPTOGRAPHY').length },
    { id: 'AUTHENTICATION', label: 'Autenticação & JWT', count: REFACTORING_RECIPES.filter(r => r.category === 'AUTHENTICATION').length },
    { id: 'INJECTION', label: 'Injeção SQL & Shell', count: REFACTORING_RECIPES.filter(r => r.category === 'INJECTION').length },
    { id: 'SECRETS', label: 'Segredos & Config', count: REFACTORING_RECIPES.filter(r => r.category === 'SECRETS').length },
    { id: 'DATA_VALIDATION', label: 'Higienização & DOM XSS', count: REFACTORING_RECIPES.filter(r => r.category === 'DATA_VALIDATION').length },
    { id: 'NETWORK_SSRF', label: 'SSRF & Rede', count: REFACTORING_RECIPES.filter(r => r.category === 'NETWORK_SSRF').length },
    { id: 'FILE_SYSTEM', label: 'Path Traversal & FS', count: REFACTORING_RECIPES.filter(r => r.category === 'FILE_SYSTEM').length },
  ];

  return (
    <div id="security-refactoring-assistant-container" className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
      {/* Header Banner */}
      <div id="refactoring-assistant-header" className="bg-slate-900 border border-slate-800 rounded-2xl p-6 text-slate-100 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-br from-indigo-500/10 via-emerald-500/5 to-transparent rounded-full blur-3xl pointer-events-none" />
        
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2 max-w-2xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold tracking-wide">
              <Sparkles className="w-3.5 h-3.5" />
              <span>Modern Security Code Architecture</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
              <Wrench className="w-7 h-7 text-indigo-400" />
              Security Refactoring Assistant
            </h1>
            <p className="text-slate-300 text-sm leading-relaxed">
              Sugestões guiadas de refatoração para vulnerabilidades comuns. Substitua bibliotecas criptográficas obsoletas
              (MD5, DES, createCipher) por alternativas seguras modernas (Argon2id, AES-256-GCM, CSPRNG) com visualizador
              comparativo de estado <strong className="text-emerald-400">Antes / Depois (Preview)</strong>.
            </p>
          </div>

          {/* Quick Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 bg-slate-800/80 border border-slate-700/60 p-4 rounded-xl backdrop-blur-sm">
            <div className="text-center p-2">
              <div className="text-2xl font-bold text-white">{REFACTORING_RECIPES.length}</div>
              <div className="text-xs text-slate-400">Padrões Modernos</div>
            </div>
            <div className="text-center p-2 border-x border-slate-700/60">
              <div className="text-2xl font-bold text-amber-400">{workspaceMatchesCount}</div>
              <div className="text-xs text-slate-400">No Workspace</div>
            </div>
            <div className="text-center p-2 col-span-2 sm:col-span-1">
              <div className="text-2xl font-bold text-emerald-400">-8.9 pts</div>
              <div className="text-xs text-slate-400">Média CVSS Drop</div>
            </div>
          </div>
        </div>

        {/* Workspace Match Alert Notification */}
        {workspaceMatchesCount > 0 && (
          <div className="mt-5 pt-4 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-amber-950/20 border border-amber-500/20 rounded-xl p-3.5">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-amber-500/20 text-amber-400 flex items-center justify-center shrink-0">
                <AlertTriangle className="w-4 h-4" />
              </div>
              <div>
                <div className="text-xs font-semibold text-amber-300">
                  {workspaceMatchesCount} arquivo(s) no workspace utilizam bibliotecas ou padrões obsoletos detectados!
                </div>
                <div className="text-xs text-slate-400">
                  Detectamos referências a funções como MD5, createCipher ou Math.random() nos arquivos carregados.
                </div>
              </div>
            </div>
            <button
              id="btn-filter-workspace-matches"
              onClick={() => setOnlyMatchedInWorkspace(prev => !prev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors shrink-0 flex items-center gap-1.5 ${
                onlyMatchedInWorkspace
                  ? 'bg-amber-500 text-slate-950 font-semibold'
                  : 'bg-slate-800 text-amber-300 hover:bg-slate-700 border border-amber-500/30'
              }`}
            >
              <Filter className="w-3.5 h-3.5" />
              {onlyMatchedInWorkspace ? 'Exibindo Apenas do Workspace' : 'Filtrar Ocorrências no Workspace'}
            </button>
          </div>
        )}
      </div>

      {/* Control Bar: Categories & Search */}
      <div id="refactoring-controls-bar" className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-4">
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              id="refactoring-search-input"
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Buscar por biblioteca (ex: md5, createCipher, crypto-js, jwt), CWE ou palavra-chave..."
              className="w-full pl-9 pr-4 py-2 text-sm bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white text-slate-800 placeholder-slate-400"
            />
          </div>

          {/* Toggle Custom Playground */}
          <button
            id="btn-toggle-custom-playground"
            onClick={() => setShowCustomPlayground(prev => !prev)}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors shrink-0 flex items-center gap-2 border ${
              showCustomPlayground
                ? 'bg-indigo-50 text-indigo-700 border-indigo-200'
                : 'bg-slate-50 text-slate-700 border-slate-200 hover:bg-slate-100'
            }`}
          >
            <Code2 className="w-4 h-4 text-indigo-600" />
            <span>{showCustomPlayground ? 'Ocultar Playground Customizado' : 'Testar Trecho Customizado'}</span>
          </button>
        </div>

        {/* Category Pills */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-thin">
          {categories.map((cat) => (
            <button
              key={cat.id}
              onClick={() => setSelectedCategory(cat.id)}
              className={`px-3 py-1.5 rounded-full text-xs font-medium transition-all shrink-0 flex items-center gap-1.5 ${
                selectedCategory === cat.id
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              <span>{cat.label}</span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                selectedCategory === cat.id ? 'bg-indigo-500 text-white' : 'bg-slate-200 text-slate-700'
              }`}>
                {cat.count}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Custom Playground Drawer (Optional interactive experimentation) */}
      {showCustomPlayground && (
        <div id="custom-snippet-playground" className="bg-slate-900 border border-indigo-500/30 rounded-xl p-5 text-slate-100 shadow-lg space-y-4 animate-in fade-in duration-200">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-indigo-400 font-semibold text-sm">
              <Terminal className="w-4 h-4" />
              <span>Playground Interativo: Cole seu Snippet Legado</span>
            </div>
            <div className="flex items-center gap-3">
              <label className="text-xs text-slate-400">Padrão de Refatoração:</label>
              <select
                value={customSelectedArchetype}
                onChange={(e) => setCustomSelectedArchetype(e.target.value)}
                className="bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 px-3 py-1 focus:ring-1 focus:ring-indigo-500"
              >
                {REFACTORING_RECIPES.map(r => (
                  <option key={r.id} value={r.id}>{r.title}</option>
                ))}
              </select>
            </div>
          </div>

          <textarea
            value={customInputCode}
            onChange={(e) => setCustomInputCode(e.target.value)}
            rows={5}
            placeholder="Cole qualquer trecho de código JavaScript / TypeScript aqui..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />

          <div className="flex justify-end gap-2">
            <button
              onClick={() => {
                const targetRecipe = REFACTORING_RECIPES.find(r => r.id === customSelectedArchetype) || REFACTORING_RECIPES[0];
                handleOpenPreview(targetRecipe);
              }}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-lg flex items-center gap-1.5 transition-colors shadow-md"
            >
              <Eye className="w-4 h-4" />
              <span>Abrir Preview Comparativo Antes / Depois</span>
            </button>
          </div>
        </div>
      )}

      {/* Recipe Cards Grid */}
      <div id="refactoring-recipes-grid" className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {filteredRecipes.map((recipe) => {
          const matchInfo = matchedAnalysis.find(m => m.recipe.id === recipe.id);
          const isApplied = !!appliedRecipeHistory[recipe.id];

          return (
            <div
              key={recipe.id}
              id={`recipe-card-${recipe.id}`}
              className={`bg-white border rounded-xl p-5 shadow-sm transition-all hover:shadow-md flex flex-col justify-between ${
                matchInfo?.matchedFile ? 'border-indigo-300 ring-1 ring-indigo-200/50' : 'border-slate-200'
              }`}
            >
              <div className="space-y-4">
                {/* Card Top: Badges */}
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold tracking-wide uppercase ${
                      recipe.category === 'CRYPTOGRAPHY'
                        ? 'bg-purple-100 text-purple-700 border border-purple-200'
                        : recipe.category === 'INJECTION'
                        ? 'bg-rose-100 text-rose-700 border border-rose-200'
                        : recipe.category === 'AUTHENTICATION'
                        ? 'bg-blue-100 text-blue-700 border border-blue-200'
                        : recipe.category === 'SECRETS'
                        ? 'bg-amber-100 text-amber-700 border border-amber-200'
                        : 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                    }`}>
                      {recipe.category}
                    </span>

                    <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-50 text-rose-700 border border-rose-200">
                      {recipe.severity}
                    </span>

                    <span className="text-[11px] text-slate-500 font-mono">
                      {recipe.cwe.split(':')[0]}
                    </span>
                  </div>

                  {/* CVSS Drop Meter */}
                  <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs font-semibold">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                    <span>CVSS: {recipe.cvssReduction.before} ➔ {recipe.cvssReduction.after}</span>
                  </div>
                </div>

                {/* Card Title & Summary */}
                <div>
                  <h3 className="text-base font-bold text-slate-900 group-hover:text-indigo-600 transition-colors">
                    {recipe.title}
                  </h3>
                  <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">
                    {recipe.shortSummary}
                  </p>
                </div>

                {/* Legacy vs Modern Pill Box */}
                <div className="bg-slate-50 border border-slate-200/80 rounded-lg p-3 space-y-2 text-xs">
                  <div className="flex items-start gap-2">
                    <span className="px-1.5 py-0.5 rounded bg-rose-100 text-rose-700 font-mono font-bold text-[10px] shrink-0 mt-0.5">
                      LEGADO
                    </span>
                    <span className="text-slate-700 font-mono truncate" title={recipe.legacyLibraryOrPattern}>
                      {recipe.legacyLibraryOrPattern}
                    </span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-700 font-mono font-bold text-[10px] shrink-0 mt-0.5">
                      MODERNO
                    </span>
                    <span className="text-emerald-800 font-mono font-medium truncate" title={recipe.modernReplacement}>
                      {recipe.modernReplacement}
                    </span>
                  </div>
                </div>

                {/* Workspace Match Indicator if detected */}
                {matchInfo?.matchedFile && (
                  <div className="flex items-center gap-2 p-2 bg-indigo-50 border border-indigo-100 rounded-lg text-xs text-indigo-900">
                    <FileCode2 className="w-4 h-4 text-indigo-600 shrink-0" />
                    <span className="truncate">
                      Detectado em: <strong className="font-mono text-indigo-700">{matchInfo.matchedFile.path}</strong>
                    </span>
                  </div>
                )}
              </div>

              {/* Card Actions: Preview Button (Core requirement!) */}
              <div className="mt-5 pt-4 border-t border-slate-100 flex items-center justify-between gap-3">
                <button
                  id={`btn-preview-recipe-${recipe.id}`}
                  onClick={() => handleOpenPreview(recipe)}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shadow-sm hover:shadow"
                >
                  <Eye className="w-4 h-4" />
                  <span>Preview Antes / Depois</span>
                </button>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopy(recipe.afterCode, `card-${recipe.id}`)}
                    className="p-2 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200 transition-colors"
                    title="Copiar snippet moderno"
                  >
                    {copiedKey === `card-${recipe.id}` ? (
                      <Check className="w-4 h-4 text-emerald-600" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>

                  {isApplied ? (
                    <button
                      onClick={() => handleRevertWorkspace(recipe.id)}
                      className="px-3 py-2 bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-200 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors"
                      title="Reverter para o código legado"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      <span>Reverter</span>
                    </button>
                  ) : matchInfo?.matchedFile ? (
                    <button
                      onClick={() => {
                        handleOpenPreview(recipe);
                        handleApplyToWorkspace(recipe);
                      }}
                      className="px-3 py-2 bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-200 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors"
                    >
                      <Zap className="w-3.5 h-3.5 text-emerald-600" />
                      <span>Aplicar ao Arquivo</span>
                    </button>
                  ) : null}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {filteredRecipes.length === 0 && (
        <div className="bg-slate-50 border border-slate-200 rounded-xl p-12 text-center text-slate-500 space-y-3">
          <Filter className="w-8 h-8 mx-auto text-slate-400" />
          <h4 className="text-base font-semibold text-slate-700">Nenhum padrão encontrado</h4>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Nenhuma receita corresponde aos filtros selecionados. Tente ajustar o termo de busca ou limpar o filtro de categoria.
          </p>
          <button
            onClick={() => {
              setSearchQuery('');
              setSelectedCategory('ALL');
              setOnlyMatchedInWorkspace(false);
            }}
            className="px-4 py-2 bg-white border border-slate-300 text-slate-700 text-xs font-medium rounded-lg hover:bg-slate-50"
          >
            Redefinir Filtros
          </button>
        </div>
      )}

      {/* ========================================================================= */}
      {/* THE PREVIEW MODAL: Interactive Comparison of Before vs After State        */}
      {/* ========================================================================= */}
      {activePreviewRecipe && (
        <div
          id="refactoring-preview-modal-overlay"
          className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-6 overflow-y-auto animate-in fade-in duration-150"
        >
          <div
            id="refactoring-preview-modal"
            className="bg-white rounded-2xl border border-slate-200 shadow-2xl w-full max-w-5xl max-h-[92vh] flex flex-col overflow-hidden text-slate-900"
          >
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-indigo-100 text-indigo-800">
                    {activePreviewRecipe.category}
                  </span>
                  <span className="text-xs font-mono text-slate-500">
                    {activePreviewRecipe.cwe}
                  </span>
                  <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 flex items-center gap-1">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                    CVSS: {activePreviewRecipe.cvssReduction.before} ➔ {activePreviewRecipe.cvssReduction.after}
                  </span>
                </div>
                <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                  <FileDiff className="w-5 h-5 text-indigo-600" />
                  {activePreviewRecipe.title}
                </h2>
              </div>

              {/* View Switcher: Split vs Unified */}
              <div className="flex items-center gap-2">
                <div className="bg-slate-200/80 p-0.5 rounded-lg flex items-center text-xs">
                  <button
                    onClick={() => setPreviewMode('split')}
                    className={`px-3 py-1.5 rounded-md font-medium transition-all flex items-center gap-1.5 ${
                      previewMode === 'split'
                        ? 'bg-white text-indigo-700 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <ArrowLeftRight className="w-3.5 h-3.5" />
                    <span>Lado a Lado (Split)</span>
                  </button>
                  <button
                    onClick={() => setPreviewMode('unified')}
                    className={`px-3 py-1.5 rounded-md font-medium transition-all flex items-center gap-1.5 ${
                      previewMode === 'unified'
                        ? 'bg-white text-indigo-700 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <FileCode2 className="w-3.5 h-3.5" />
                    <span>Git Diff Unificado</span>
                  </button>
                </div>

                <button
                  onClick={handleClosePreview}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200 transition-colors"
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Modal Body (Scrollable) */}
            <div className="p-6 overflow-y-auto space-y-6 flex-1">
              {/* Context Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-rose-50/60 border border-rose-200/70 rounded-xl p-4 text-xs space-y-2">
                  <div className="flex items-center gap-2 text-rose-800 font-bold">
                    <Unlock className="w-4 h-4 text-rose-600" />
                    <span>Por que o código legado é vulnerável?</span>
                  </div>
                  <p className="text-slate-700 leading-relaxed">
                    {activePreviewRecipe.vulnerabilityExplanation}
                  </p>
                </div>

                <div className="bg-emerald-50/60 border border-emerald-200/70 rounded-xl p-4 text-xs space-y-2">
                  <div className="flex items-center gap-2 text-emerald-800 font-bold">
                    <Lock className="w-4 h-4 text-emerald-600" />
                    <span>Como a alternativa moderna protege a aplicação?</span>
                  </div>
                  <p className="text-slate-700 leading-relaxed">
                    {activePreviewRecipe.modernSolutionExplanation}
                  </p>
                </div>
              </div>

              {/* Code Comparison Section */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs text-slate-600">
                  <span className="font-semibold text-slate-700 flex items-center gap-1.5">
                    <FileDiff className="w-4 h-4 text-indigo-500" />
                    Comparativo de Código: Estado Anterior vs. Estado Refatorado
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleCopy(activePreviewRecipe.afterCode, 'modal-after-code')}
                      className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium flex items-center gap-1.5 transition-colors"
                    >
                      {copiedKey === 'modal-after-code' ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                          <span className="text-emerald-700">Copiado!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copiar Código Seguro</span>
                        </>
                      )}
                    </button>
                    <button
                      onClick={() => handleCopy(activePreviewRecipe.unifiedDiff, 'modal-diff')}
                      className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium flex items-center gap-1.5 transition-colors"
                    >
                      {copiedKey === 'modal-diff' ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                          <span className="text-emerald-700">Patch Copiado!</span>
                        </>
                      ) : (
                        <>
                          <Terminal className="w-3.5 h-3.5" />
                          <span>Copiar Git Diff</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Split Mode: Before on Left, After on Right */}
                {previewMode === 'split' ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Before (Legacy Insecure) */}
                    <div className="border border-rose-200 rounded-xl overflow-hidden shadow-sm flex flex-col">
                      <div className="bg-rose-50 px-4 py-2 border-b border-rose-200 flex items-center justify-between text-xs font-bold text-rose-800">
                        <span className="flex items-center gap-1.5">
                          <Unlock className="w-3.5 h-3.5 text-rose-600" />
                          Antes: Padrão Inseguro Legado
                        </span>
                        <span className="text-[11px] font-normal text-rose-600">
                          {activePreviewRecipe.legacyLibraryOrPattern}
                        </span>
                      </div>
                      <div className="bg-slate-950 p-4 font-mono text-xs overflow-x-auto text-rose-300 leading-relaxed flex-1">
                        <pre className="whitespace-pre">
                          <code>{activePreviewRecipe.beforeCode}</code>
                        </pre>
                      </div>
                    </div>

                    {/* After (Modern Secure) */}
                    <div className="border border-emerald-200 rounded-xl overflow-hidden shadow-sm flex flex-col">
                      <div className="bg-emerald-50 px-4 py-2 border-b border-emerald-200 flex items-center justify-between text-xs font-bold text-emerald-800">
                        <span className="flex items-center gap-1.5">
                          <Lock className="w-3.5 h-3.5 text-emerald-600" />
                          Depois: Moderno & FIPS/OWASP Conforme
                        </span>
                        <span className="text-[11px] font-normal text-emerald-600">
                          {activePreviewRecipe.modernReplacement}
                        </span>
                      </div>
                      <div className="bg-slate-950 p-4 font-mono text-xs overflow-x-auto text-emerald-300 leading-relaxed flex-1">
                        <pre className="whitespace-pre">
                          <code>{activePreviewRecipe.afterCode}</code>
                        </pre>
                      </div>
                    </div>
                  </div>
                ) : (
                  /* Unified Git Diff Mode */
                  <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-950 text-slate-100 font-mono text-xs shadow-inner">
                    <div className="bg-slate-900 px-4 py-2 border-b border-slate-800 text-slate-400 flex items-center justify-between text-[11px]">
                      <span>Git Unified Diff Patch</span>
                      <span className="text-slate-500">Formato Standard RFC 6902 / Git</span>
                    </div>
                    <div className="p-4 overflow-x-auto leading-relaxed max-h-80">
                      <pre className="whitespace-pre">
                        {activePreviewRecipe.unifiedDiff.split('\n').map((line, idx) => {
                          const isRemoved = line.startsWith('-');
                          const isAdded = line.startsWith('+');
                          const isHeader = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++');

                          return (
                            <div
                              key={idx}
                              className={`${
                                isRemoved
                                  ? 'bg-rose-950/50 text-rose-300 px-2 py-0.5 rounded-sm'
                                  : isAdded
                                  ? 'bg-emerald-950/50 text-emerald-300 px-2 py-0.5 rounded-sm'
                                  : isHeader
                                  ? 'text-cyan-400 font-bold'
                                  : 'text-slate-400 px-2'
                              }`}
                            >
                              {line}
                            </div>
                          );
                        })}
                      </pre>
                    </div>
                  </div>
                )}
              </div>

              {/* Prerequisites & Migration Warnings */}
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3">
                <h4 className="text-xs font-bold text-slate-800 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-indigo-600" />
                  Pré-requisitos e Instruções de Migração
                </h4>

                <div className="flex flex-wrap gap-2">
                  {activePreviewRecipe.prerequisites.map((req, idx) => (
                    <div key={idx} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 text-slate-200 font-mono text-xs">
                      <span>{req}</span>
                      <button
                        onClick={() => handleCopy(req, `req-${idx}`)}
                        className="text-slate-400 hover:text-white"
                        title="Copiar comando"
                      >
                        {copiedKey === `req-${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                  ))}
                </div>

                {activePreviewRecipe.breakingChangesWarning && (
                  <div className="flex items-start gap-2 p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800">
                    <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                    <div>
                      <strong className="font-semibold">Atenção a Quebras de Contrato: </strong>
                      {activePreviewRecipe.breakingChangesWarning}
                    </div>
                  </div>
                )}
              </div>

              {/* Workspace Direct Application Bar */}
              <div className="bg-indigo-50/70 border border-indigo-200 rounded-xl p-4 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
                <div className="space-y-1">
                  <div className="text-xs font-bold text-indigo-900 flex items-center gap-1.5">
                    <Zap className="w-4 h-4 text-indigo-600" />
                    Aplicar Modernização Diretamente ao Workspace
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-indigo-700">Arquivo de destino:</span>
                    <select
                      value={selectedTargetFile}
                      onChange={(e) => setSelectedTargetFile(e.target.value)}
                      className="bg-white border border-indigo-200 rounded-md text-xs px-2.5 py-1 text-slate-800 font-mono focus:ring-1 focus:ring-indigo-500"
                    >
                      {files.map(f => (
                        <option key={f.path} value={f.path}>{f.path}</option>
                      ))}
                      {files.length === 0 && (
                        <option value="src/services/encryptionService.js">src/services/encryptionService.js (Novo)</option>
                      )}
                    </select>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {appliedRecipeHistory[activePreviewRecipe.id] ? (
                    <button
                      onClick={() => handleRevertWorkspace(activePreviewRecipe.id)}
                      className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-colors"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      <span>Reverter Alteração</span>
                    </button>
                  ) : (
                    <button
                      onClick={() => handleApplyToWorkspace(activePreviewRecipe)}
                      className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-colors"
                    >
                      <CheckCircle2 className="w-4 h-4" />
                      <span>Aplicar Refatoração ao Arquivo</span>
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs text-slate-500">
              <div className="flex items-center gap-2">
                <a
                  href={activePreviewRecipe.cweUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-indigo-600 hover:underline flex items-center gap-1"
                >
                  <span>Documentação MITRE {activePreviewRecipe.cwe.split(':')[0]}</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
                <span>•</span>
                <a
                  href={activePreviewRecipe.owaspUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-indigo-600 hover:underline flex items-center gap-1"
                >
                  <span>OWASP Top 10 Reference</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              <button
                onClick={handleClosePreview}
                className="px-4 py-1.5 bg-slate-200 hover:bg-slate-300 text-slate-800 rounded-lg font-medium transition-colors"
              >
                Fechar Preview
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
