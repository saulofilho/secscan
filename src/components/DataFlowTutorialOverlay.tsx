import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  ArrowRight,
  Route,
  Scan,
  Hand,
  MousePointer,
  ChevronRight,
  ChevronLeft,
  X,
  Sparkles,
  SlidersHorizontal,
  Info,
  CheckCircle2,
  AlertTriangle,
  Move,
  Code2,
  Terminal,
  HelpCircle
} from 'lucide-react';

export interface DataFlowTutorialOverlayProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectLayoutMode?: (mode: 'FORCE' | 'PIPELINE' | 'HIERARCHICAL') => void;
  onTriggerZoomToFit?: () => void;
  onTogglePanMode?: () => void;
  isPanMode?: boolean;
}

interface StepItem {
  id: string;
  badge: string;
  title: string;
  concept: 'SOURCE' | 'SANITIZER' | 'SINK' | 'FLOW' | 'CONTROLS';
  summary: string;
  details: string[];
  codeExample?: {
    bad?: string;
    good?: string;
    explanation: string;
  };
  shortcuts?: { key: string; label: string }[];
  highlightAnchor?: 'hud' | 'toolbar' | 'canvas-center' | 'canvas-left' | 'canvas-right';
}

export const DataFlowTutorialOverlay: React.FC<DataFlowTutorialOverlayProps> = ({
  isOpen,
  onClose,
  onSelectLayoutMode,
  onTriggerZoomToFit,
  onTogglePanMode,
  isPanMode = false
}) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [simulatedSanitizerActive, setSimulatedSanitizerActive] = useState(false);
  const [showHotspots, setShowHotspots] = useState(true);

  // Keyboard navigation for tutorial
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      } else if (e.key === 'ArrowRight' || e.key === 'Enter') {
        setCurrentStepIndex(prev => Math.min(steps.length - 1, prev + 1));
      } else if (e.key === 'ArrowLeft') {
        setCurrentStepIndex(prev => Math.max(0, prev - 1));
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen]);

  if (!isOpen) return null;

  const steps: StepItem[] = [
    {
      id: 'concept-overview',
      badge: '01 // TAINT ANALYSIS & FLUXO DE DADOS',
      title: 'O que é um Grafo de Fluxo de Dados?',
      concept: 'FLOW',
      summary: 'A análise de fluxo (Taint Analysis) rastreia como dados não sanitizados inseridos pelo usuário viajam pela aplicação até atingirem operações críticas do sistema.',
      details: [
        'Propagação de Contaminação: Variáveis recebidas em rotas de API são marcadas como "tainted" (potencialmente hostis).',
        'Caminho de Execução: O motor do SecScan constrói uma árvore de dependência semântica ligando fontes, nós intermediários e chamadas sensíveis.',
        'Detecção de Vulnerabilidades: Se um dado contaminado chega a uma função perigosa sem passar por validação prévia, uma violação de segurança é emitida.'
      ],
      highlightAnchor: 'canvas-center'
    },
    {
      id: 'concept-sources',
      badge: '02 // SOURCES (FONTES DE ENTRADA)',
      title: 'Sources: Onde o Dado Externo Entra',
      concept: 'SOURCE',
      summary: 'Nós representados em Ciano/Verde. São os pontos de entrada por onde o usuário ou agentes externos enviam informações para o sistema.',
      details: [
        'Exemplos no Código: req.query.id, req.body.payload, window.location.search, process.env não validado.',
        'Características no Grafo: Geralmente localizados na coluna ou borda esquerda do diagrama.',
        'Risco Associado: Dados de fontes devem sempre ser tratados com desconfiança (princípio de Zero Trust em nível de código).'
      ],
      codeExample: {
        bad: 'const userInput = req.query.filename;',
        good: 'const userInput = validator.escape(req.query.filename);',
        explanation: 'Qualquer parâmetro extraído de requisições HTTP é considerado uma Source de risco até passar por uma validação explícita.'
      },
      highlightAnchor: 'canvas-left'
    },
    {
      id: 'concept-sanitizers',
      badge: '03 // SANITIZERS (FILTROS DE SEGURANÇA)',
      title: 'Sanitizers: A Barreira que Neutraliza o Ataque',
      concept: 'SANITIZER',
      summary: 'Nós representados em Verde Esmeralda/Azul. Funções e métodos responsáveis por validar, sanitizar, escapar ou tipar os dados.',
      details: [
        'Exemplos no Código: DOMPurify.sanitize(), validator.isUUID(), zodSchema.parse(), regex.test(), encodeURIComponent().',
        'Impacto no Grafo: Quando uma aresta de dados atravessa um Sanitizer registrado, o status do fluxo é marcado como SEGURO/NEUTRALIZADO.',
        'Boas Práticas: Sempre prefira bibliotecas testadas contra vetores de bypass a expressões regulares manuais complexas.'
      ],
      codeExample: {
        bad: '// Sem sanitizer: dado vai direto para a execução\nres.send(`<h1>${userInput}</h1>`);',
        good: '// Com sanitizer: caracteres perigosos são neutralizados\nconst safeHtml = DOMPurify.sanitize(userInput);\nres.send(`<h1>${safeHtml}</h1>`);',
        explanation: 'O Sanitizer remove a contaminação (un-taints) antes que o dado chegue a um Sink crítico.'
      },
      highlightAnchor: 'canvas-center'
    },
    {
      id: 'concept-sinks',
      badge: '04 // SINKS (SUMIDOUROS CRÍTICOS)',
      title: 'Sinks: Onde a Vulnerabilidade Explode',
      concept: 'SINK',
      summary: 'Nós representados em Vermelho/Laranja Neon. São funções nativas ou de terceiros onde a execução de dados não tratados gera exploits graves.',
      details: [
        'Sinks de XSS (CWE-79): innerHTML, document.write(), eval(), Function(), dangerouslySetInnerHTML.',
        'Sinks de SQL Injection (CWE-89): db.raw(), pool.query("SELECT * FROM users WHERE id = " + id).',
        'Sinks de Command Injection (CWE-78): child_process.exec(), spawn(..., { shell: true }).',
        'Sinks de Path Traversal (CWE-22): fs.readFile(userInput), path.join(baseDir, userInput).'
      ],
      codeExample: {
        bad: '// VULNERÁVEL: Sink executando SQL concatenado\ndb.query(`SELECT * FROM accounts WHERE user_id = "${req.body.id}"`);',
        good: '// CORRIGIDO: Sink parametrizado com Prepared Statement\ndb.query("SELECT * FROM accounts WHERE user_id = $1", [req.body.id]);',
        explanation: 'O grafo alerta com bordas pulsantes nós de Sink que recebem fluxos de dados não purificados.'
      },
      highlightAnchor: 'canvas-right'
    },
    {
      id: 'concept-navigation',
      badge: '05 // ZOOM, PAN & NAVEGAÇÃO INTERATIVA',
      title: 'Dominando os Controles de Zoom, Pan e Layout',
      concept: 'CONTROLS',
      summary: 'Projetado para repositórios com dezenas de rotas e fluxos densos. Utilize os atalhos e botões para inspecionar cada nó com facilidade.',
      details: [
        'Zoom-to-Fit (Atalho F): Calcula a extensão exata do grafo e redimensiona a escala para enquadrar todos os nós perfeitamente no canvas.',
        'Modo Pan Livre (Atalho P): Trava o clique e permite arrastar a tela inteira sem deslocar nós por acidente.',
        'Navegação Direcional D-Pad & Teclado: Use as setas do teclado para passear suavemente pelo canvas.',
        'Modos de Layout: Force-Directed (física e gravidade interativa) e Pipeline (colunas de Entrada, Processamento e Destino).'
      ],
      shortcuts: [
        { key: 'F', label: 'Zoom to Fit (Enquadrar)' },
        { key: 'P', label: 'Alternar Modo Pan Livre' },
        { key: 'Setas', label: 'Pan Direcional (↑ ↓ ← →)' },
        { key: '+ / -', label: 'Aumentar / Reduzir Zoom' },
        { key: '0', label: 'Resetar Zoom para 100%' }
      ],
      highlightAnchor: 'hud'
    }
  ];

  const currentStep = steps[currentStepIndex];

  return (
    <div
      id="dataflow-tutorial-overlay-layer"
      className="absolute inset-0 z-40 bg-black/75 backdrop-blur-xs flex flex-col justify-between p-4 sm:p-6 select-text pointer-events-auto animate-in fade-in duration-200"
    >
      {/* Top Header Bar inside Canvas Overlay */}
      <div className="flex items-center justify-between gap-3 bg-[#0A0A0A]/95 border border-[#2B2B2B] p-3 rounded-xl shadow-2xl backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[#FF3E00]/15 border border-[#FF3E00]/40 flex items-center justify-center text-[#FF3E00] shrink-0">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xs font-black uppercase tracking-wider text-white">
                Guia Interativo // Interpretação de Grafos de Fluxo (Taint Analysis)
              </h2>
              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#161616] text-[#00E5FF] border border-[#2A2A2A]">
                Passo {currentStepIndex + 1} de {steps.length}
              </span>
            </div>
            <p className="text-[10px] font-mono text-zinc-400">
              Aprenda a mapear Sources, Sanitizers, Sinks e a navegar com Zoom-to-Fit e Pan.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Toggle Hotspots */}
          <button
            id="btn-tutorial-toggle-hotspots"
            onClick={() => setShowHotspots(prev => !prev)}
            className={`px-2.5 py-1.5 rounded text-[10px] font-mono font-bold transition-all flex items-center gap-1.5 cursor-pointer border ${
              showHotspots
                ? 'bg-[#1A262E] text-[#00E5FF] border-[#00E5FF]/40'
                : 'bg-[#141414] text-zinc-400 border-[#222] hover:text-white'
            }`}
            title="Exibir ou ocultar marcadores de dicas flutuantes sobre o canvas"
          >
            <Info className="w-3 h-3" />
            <span className="hidden sm:inline">Dicas Visuais</span>
          </button>

          {/* Close Overlay */}
          <button
            id="btn-close-dataflow-tutorial"
            onClick={onClose}
            className="p-1.5 text-zinc-400 hover:text-white bg-[#141414] hover:bg-[#202020] border border-[#2A2A2A] rounded-lg transition-colors cursor-pointer"
            title="Fechar Tutorial do Grafo (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Floating Canvas Hotspots (visual layer on top of nodes and HUD) */}
      {showHotspots && (
        <div className="relative flex-1 pointer-events-none my-3">
          {/* Hotspot 1: Navigation HUD Guide (Top-Left) */}
          <div className="absolute top-2 left-2 pointer-events-auto bg-[#0A0A0A]/95 border-2 border-[#00E5FF]/50 rounded-xl p-2.5 shadow-2xl max-w-xs animate-pulse-subtle">
            <div className="flex items-center gap-1.5 text-[#00E5FF] text-[10px] font-mono font-bold uppercase tracking-wider mb-1">
              <Move className="w-3 h-3" />
              <span>Controles de Pan & Zoom</span>
            </div>
            <p className="text-[10.5px] font-mono text-zinc-300 leading-tight">
              Use o botão <strong className="text-[#00E5FF]">Fit (F)</strong> para enquadrar nós instantaneamente e o <strong className="text-[#FF3E00]">Modo Pan (P)</strong> para arrastar a tela sem alterar as posições.
            </p>
            {onTriggerZoomToFit && (
              <div className="mt-2 flex items-center gap-1.5">
                <button
                  onClick={onTriggerZoomToFit}
                  className="px-2 py-1 rounded bg-[#00E5FF]/20 hover:bg-[#00E5FF] text-[#00E5FF] hover:text-black border border-[#00E5FF]/40 text-[9.5px] font-mono font-bold transition-all cursor-pointer flex items-center gap-1"
                >
                  <Scan className="w-3 h-3" />
                  <span>Testar Zoom-to-Fit</span>
                </button>
                {onTogglePanMode && (
                  <button
                    onClick={onTogglePanMode}
                    className={`px-2 py-1 rounded border text-[9.5px] font-mono font-bold transition-all cursor-pointer flex items-center gap-1 ${
                      isPanMode
                        ? 'bg-[#FF3E00] text-white border-[#FF3E00]'
                        : 'bg-[#181818] text-zinc-300 border-[#333] hover:text-white'
                    }`}
                  >
                    <Hand className="w-3 h-3" />
                    <span>{isPanMode ? 'Pan Ativo' : 'Ativar Pan'}</span>
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Hotspot 2: Sources Pin (Left) */}
          <div className="absolute top-1/4 left-1/4 -translate-x-1/2 pointer-events-auto bg-[#0A0A0A]/95 border border-[#00E5FF]/40 rounded-xl p-2 shadow-xl max-w-[210px] hidden md:block">
            <div className="flex items-center gap-1 text-[#00E5FF] text-[10px] font-mono font-bold uppercase">
              <span className="w-2 h-2 rounded-full bg-[#00E5FF] animate-ping" />
              <span>1. Source (Entrada)</span>
            </div>
            <p className="text-[10px] font-mono text-zinc-300 mt-1 leading-snug">
              Nós ciano/verde: parâmetros de requisição (<code className="text-[#00E5FF]">req.query</code>, <code className="text-[#00E5FF]">req.body</code>).
            </p>
          </div>

          {/* Hotspot 3: Sanitizers Pin (Center) */}
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-auto bg-[#0A0A0A]/95 border border-[#00FF41]/40 rounded-xl p-2 shadow-xl max-w-[220px] hidden md:block">
            <div className="flex items-center gap-1 text-[#00FF41] text-[10px] font-mono font-bold uppercase">
              <ShieldCheck className="w-3 h-3" />
              <span>2. Sanitizer (Validador)</span>
            </div>
            <p className="text-[10px] font-mono text-zinc-300 mt-1 leading-snug">
              Nós esmeralda: funções que neutralizam o risco antes da execução (<code className="text-[#00FF41]">escape</code>, <code className="text-[#00FF41]">DOMPurify</code>).
            </p>
          </div>

          {/* Hotspot 4: Sinks Pin (Right) */}
          <div className="absolute top-1/4 right-8 pointer-events-auto bg-[#0A0A0A]/95 border border-[#FF3E00]/60 rounded-xl p-2 shadow-xl max-w-[210px] hidden md:block">
            <div className="flex items-center gap-1 text-[#FF3E00] text-[10px] font-mono font-bold uppercase">
              <ShieldAlert className="w-3 h-3" />
              <span>3. Sink (Destino Crítico)</span>
            </div>
            <p className="text-[10px] font-mono text-zinc-300 mt-1 leading-snug">
              Nós vermelhos: operações onde dados inseguros causam XSS ou SQLi (<code className="text-[#FF3E00]">eval</code>, <code className="text-[#FF3E00]">innerHTML</code>).
            </p>
          </div>
        </div>
      )}

      {/* Main Educational Card & Interactive Step Panel */}
      <div className="bg-[#0A0A0A]/95 border border-[#2B2B2B] rounded-xl shadow-2xl p-4 sm:p-5 backdrop-blur-md max-w-4xl mx-auto w-full">
        {/* Step Indicator Pills */}
        <div className="flex items-center justify-between border-b border-[#1E1E1E] pb-3 mb-3 gap-2 overflow-x-auto">
          <div className="flex items-center gap-1.5">
            {steps.map((step, idx) => (
              <button
                key={step.id}
                onClick={() => setCurrentStepIndex(idx)}
                className={`px-2.5 py-1 rounded text-[10px] font-mono transition-all shrink-0 cursor-pointer ${
                  idx === currentStepIndex
                    ? 'bg-[#FF3E00] text-white font-bold shadow-sm'
                    : idx < currentStepIndex
                    ? 'bg-[#181818] text-zinc-300 hover:text-white border border-[#333]'
                    : 'bg-[#101010] text-zinc-400 hover:text-white'
                }`}
              >
                {idx + 1}. {step.concept}
              </button>
            ))}
          </div>

          <div className="text-[10px] font-mono text-zinc-400 hidden sm:flex items-center gap-1 shrink-0">
            <span>Atalhos:</span>
            <kbd className="px-1 py-0.5 rounded bg-[#181818] text-zinc-300 border border-[#333]">←</kbd>
            <kbd className="px-1 py-0.5 rounded bg-[#181818] text-zinc-300 border border-[#333]">→</kbd>
            <span className="text-zinc-400">navegar</span>
          </div>
        </div>

        {/* Step Content */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
          {/* Left Column: Concept & Description */}
          <div className="md:col-span-7 space-y-3">
            <div>
              <span className="text-[9.5px] font-mono font-bold tracking-wider text-[#FF3E00] uppercase">
                {currentStep.badge}
              </span>
              <h3 className="text-sm sm:text-base font-bold text-white mt-0.5">
                {currentStep.title}
              </h3>
              <p className="text-xs font-mono text-zinc-300 mt-1 leading-relaxed">
                {currentStep.summary}
              </p>
            </div>

            {/* Bullet Points */}
            <div className="space-y-1.5 bg-[#121212] p-3 rounded-lg border border-[#1E1E1E]">
              {currentStep.details.map((point, pIdx) => (
                <div key={pIdx} className="text-[11px] font-mono text-zinc-300 flex items-start gap-2">
                  <span className="text-[#00E5FF] mt-0.5">▪</span>
                  <span className="leading-snug">{point}</span>
                </div>
              ))}
            </div>

            {/* Keyboard Shortcuts List if step has shortcuts */}
            {currentStep.shortcuts && (
              <div className="bg-[#101820] p-2.5 rounded-lg border border-[#00E5FF]/20 flex flex-wrap gap-2 items-center">
                <span className="text-[10px] font-mono font-bold text-[#00E5FF] uppercase">
                  Atalhos Rápidos de Navegação:
                </span>
                {currentStep.shortcuts.map((sc, sIdx) => (
                  <div key={sIdx} className="inline-flex items-center gap-1 bg-black/60 px-2 py-0.5 rounded border border-[#00E5FF]/30 text-[10px] font-mono">
                    <kbd className="text-[#00E5FF] font-bold">{sc.key}</kbd>
                    <span className="text-zinc-400">({sc.label})</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Right Column: Interactive Demonstration / Code Comparison */}
          <div className="md:col-span-5 flex flex-col justify-between gap-3 bg-[#0F0F0F] p-3 rounded-lg border border-[#222]">
            {/* Interactive Flow Simulator Widget */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-zinc-300 flex items-center gap-1">
                  <Zap className="w-3 h-3 text-[#FF3E00]" />
                  <span>Simulador Interativo de Rota</span>
                </span>
                <button
                  id="btn-tutorial-toggle-sim-sanitizer"
                  onClick={() => setSimulatedSanitizerActive(prev => !prev)}
                  className={`px-2 py-0.5 rounded text-[9.5px] font-mono font-bold transition-all border cursor-pointer ${
                    simulatedSanitizerActive
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                  }`}
                  title="Alternar presença de função de sanitização na rota de taint"
                >
                  {simulatedSanitizerActive ? '✓ Com Sanitizer' : '✗ Sem Sanitizer'}
                </button>
              </div>

              {/* Graphical Path Pipeline Preview */}
              <div className="p-3 bg-[#070707] rounded border border-[#222] flex items-center justify-between text-center font-mono text-[10px]">
                {/* Source Node */}
                <div className="p-1.5 rounded bg-[#0A1A22] border border-[#00E5FF]/40 text-[#00E5FF] min-w-[70px]">
                  <div className="font-bold">SOURCE</div>
                  <div className="text-[8.5px] text-zinc-400">req.query</div>
                </div>

                {/* Animated Arrow */}
                <ArrowRight className={`w-3.5 h-3.5 ${simulatedSanitizerActive ? 'text-emerald-400' : 'text-rose-500 animate-pulse'}`} />

                {/* Sanitizer Node (active or bypassed) */}
                <div className={`p-1.5 rounded min-w-[80px] border transition-all ${
                  simulatedSanitizerActive
                    ? 'bg-[#0A2215] border-emerald-500/60 text-emerald-400 shadow-sm'
                    : 'bg-[#181818] border-[#333] text-zinc-400 line-through opacity-60'
                }`}>
                  <div className="font-bold">{simulatedSanitizerActive ? 'SANITIZER' : 'BYPASSED'}</div>
                  <div className="text-[8.5px]">{simulatedSanitizerActive ? 'escapeHtml()' : 'nenhum'}</div>
                </div>

                {/* Animated Arrow */}
                <ArrowRight className={`w-3.5 h-3.5 ${simulatedSanitizerActive ? 'text-emerald-400' : 'text-rose-500 animate-pulse'}`} />

                {/* Sink Node */}
                <div className={`p-1.5 rounded min-w-[70px] border transition-all ${
                  simulatedSanitizerActive
                    ? 'bg-[#0A2215] border-emerald-500/40 text-emerald-400'
                    : 'bg-[#290B05] border-[#FF3E00] text-[#FF3E00] shadow-[0_0_10px_rgba(255,62,0,0.3)] animate-pulse'
                }`}>
                  <div className="font-bold">SINK</div>
                  <div className="text-[8.5px]">{simulatedSanitizerActive ? 'res.send' : 'innerHTML'}</div>
                </div>
              </div>

              {/* Status Outcome Badge */}
              <div className={`p-2 rounded border text-[10.5px] font-mono leading-tight ${
                simulatedSanitizerActive
                  ? 'bg-emerald-950/40 border-emerald-800/50 text-emerald-200'
                  : 'bg-rose-950/40 border-rose-800/60 text-rose-200'
              }`}>
                {simulatedSanitizerActive ? (
                  <div className="flex items-start gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <strong className="font-bold text-emerald-300">FLUXO PROTEGIDO: </strong>
                      O dado foi purificado antes de tocar a saída. Risco de injeção neutralizado.
                    </div>
                  </div>
                ) : (
                  <div className="flex items-start gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-[#FF3E00] shrink-0 mt-0.5" />
                    <div>
                      <strong className="font-bold text-[#FF3E00]">TAINT DETECTADO (CRÍTICO): </strong>
                      Entrada arbitrária atinge um sink executável sem sanitização (XSS / CWE-79).
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Code Snippet if present in current step */}
            {currentStep.codeExample && (
              <div className="space-y-1 font-mono text-[10px] bg-black p-2.5 rounded border border-[#222]">
                <div className="text-zinc-400 uppercase text-[9px] font-bold">Exemplo Comparativo:</div>
                {currentStep.codeExample.bad && (
                  <div className="text-rose-400 bg-rose-950/30 p-1.5 rounded border border-rose-900/40 whitespace-pre-wrap">
                    {currentStep.codeExample.bad}
                  </div>
                )}
                {currentStep.codeExample.good && (
                  <div className="text-emerald-300 bg-emerald-950/30 p-1.5 rounded border border-emerald-900/40 whitespace-pre-wrap mt-1">
                    {currentStep.codeExample.good}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Footer Navigation Bar */}
        <div className="flex items-center justify-between pt-3 mt-3 border-t border-[#1E1E1E]">
          <button
            id="btn-tutorial-prev-step"
            onClick={() => setCurrentStepIndex(prev => Math.max(0, prev - 1))}
            disabled={currentStepIndex === 0}
            className="px-3 py-1.5 rounded text-[11px] font-mono font-bold uppercase tracking-wider text-zinc-300 hover:text-white bg-[#141414] hover:bg-[#202020] border border-[#2B2B2B] disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center gap-1.5 cursor-pointer"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            <span>Anterior</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              id="btn-tutorial-finish-early"
              onClick={onClose}
              className="px-3 py-1.5 rounded text-[11px] font-mono text-zinc-400 hover:text-white transition-colors cursor-pointer"
            >
              Concluir Guia
            </button>

            {currentStepIndex < steps.length - 1 ? (
              <button
                id="btn-tutorial-next-step"
                onClick={() => setCurrentStepIndex(prev => Math.min(steps.length - 1, prev + 1))}
                className="px-4 py-1.5 rounded text-[11px] font-mono font-bold uppercase tracking-wider bg-white text-black hover:bg-[#FF3E00] hover:text-white transition-all flex items-center gap-1.5 cursor-pointer shadow-sm"
              >
                <span>Próximo Passo</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            ) : (
              <button
                id="btn-tutorial-complete"
                onClick={onClose}
                className="px-4 py-1.5 rounded text-[11px] font-mono font-bold uppercase tracking-wider bg-[#00FF41] text-black hover:bg-white transition-all flex items-center gap-1.5 cursor-pointer shadow-sm"
              >
                <span>Pronto! Explorar Grafo</span>
                <CheckCircle2 className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
