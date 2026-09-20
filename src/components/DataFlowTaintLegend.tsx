import React, { useState } from 'react';
import {
  ShieldAlert,
  Play,
  Pause,
  ChevronLeft,
  ChevronRight,
  Focus,
  Maximize2,
  Minimize2,
  Code2,
  Sparkles,
  ArrowRight,
  Filter,
  Check,
  Zap,
  Info,
  Layers,
  X,
  Radio
} from 'lucide-react';
import { TaintVariableFlow, DataFlowNode, DataFlowNodeType } from '../types';

interface DataFlowTaintLegendProps {
  taintFlows: TaintVariableFlow[];
  selectedTaintFlow: TaintVariableFlow | null;
  onSelectTaintFlow: (flow: TaintVariableFlow | null) => void;
  activeStepIndex: number;
  onSelectStepIndex: (index: number) => void;
  isPlaying: boolean;
  onTogglePlay: () => void;
  highlightAllTainted: boolean;
  onToggleHighlightAll: () => void;
  showVariableLabels: boolean;
  onToggleShowVariableLabels: () => void;
  filterNodeType: DataFlowNodeType | 'TAINTED' | null;
  onToggleFilterNodeType: (type: DataFlowNodeType | 'TAINTED') => void;
  onZoomToPath?: () => void;
  onInspectNode?: (nodeId: string) => void;
  nodesMap: Map<string, DataFlowNode>;
}

export const DataFlowTaintLegend: React.FC<DataFlowTaintLegendProps> = ({
  taintFlows,
  selectedTaintFlow,
  onSelectTaintFlow,
  activeStepIndex,
  onSelectStepIndex,
  isPlaying,
  onTogglePlay,
  highlightAllTainted,
  onToggleHighlightAll,
  showVariableLabels,
  onToggleShowVariableLabels,
  filterNodeType,
  onToggleFilterNodeType,
  onZoomToPath,
  onInspectNode,
  nodesMap
}) => {
  const [isExpanded, setIsExpanded] = useState(true);
  const [activeTab, setActiveTab] = useState<'VARS' | 'TRACER' | 'LEGEND'>('VARS');

  const totalFlows = taintFlows.length;

  if (totalFlows === 0) {
    // Basic interactive legend if no taint flows detected
    return (
      <div className="absolute bottom-3 left-3 bg-[#0A0A0A]/95 backdrop-blur-md border border-[#262626] rounded-xl px-3.5 py-2.5 text-[11px] font-mono flex flex-wrap items-center gap-3 text-zinc-300 shadow-xl z-20">
        <span className="text-[10px] uppercase font-bold text-zinc-500 tracking-wider flex items-center gap-1.5">
          <Layers className="w-3.5 h-3.5 text-zinc-400" />
          <span>Legenda:</span>
        </span>
        <button
          onClick={() => onToggleFilterNodeType('ENDPOINT')}
          className={`flex items-center gap-1.5 px-2 py-0.5 rounded transition-all ${
            filterNodeType === 'ENDPOINT'
              ? 'bg-[#00E5FF]/20 text-[#00E5FF] border border-[#00E5FF]/40'
              : 'hover:bg-[#1A1A1A] text-zinc-300'
          }`}
        >
          <span className="w-2.5 h-2.5 rounded bg-[#00E5FF]" />
          <span>Endpoint API</span>
        </button>
        <button
          onClick={() => onToggleFilterNodeType('CONSUMER')}
          className={`flex items-center gap-1.5 px-2 py-0.5 rounded transition-all ${
            filterNodeType === 'CONSUMER'
              ? 'bg-[#F59E0B]/20 text-[#F59E0B] border border-[#F59E0B]/40'
              : 'hover:bg-[#1A1A1A] text-zinc-300'
          }`}
        >
          <span className="w-2.5 h-2.5 rounded bg-[#F59E0B]" />
          <span>Consumer Function</span>
        </button>
        <button
          onClick={() => onToggleFilterNodeType('SINK')}
          className={`flex items-center gap-1.5 px-2 py-0.5 rounded transition-all ${
            filterNodeType === 'SINK'
              ? 'bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40'
              : 'hover:bg-[#1A1A1A] text-zinc-300'
          }`}
        >
          <span className="w-2.5 h-2.5 rounded bg-[#FF3E00] animate-pulse" />
          <span>Sink Perigoso</span>
        </button>
      </div>
    );
  }

  // Collapsed Mode
  if (!isExpanded) {
    return (
      <div className="absolute bottom-3 left-3 z-30">
        <button
          onClick={() => setIsExpanded(true)}
          className="flex items-center gap-2.5 bg-[#0A0A0A]/95 hover:bg-[#141414] backdrop-blur-md border border-[#FF3E00]/40 hover:border-[#FF3E00] rounded-xl px-3.5 py-2 shadow-2xl transition-all duration-200 text-left group"
        >
          <div className="w-6 h-6 rounded-lg bg-[#FF3E00]/20 flex items-center justify-center text-[#FF3E00]">
            <ShieldAlert className="w-3.5 h-3.5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-white">
              <span>Rastreador de Variáveis Tainted</span>
              <span className="px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 text-[10px] border border-rose-500/30">
                {totalFlows}
              </span>
            </div>
            <div className="text-[10px] text-zinc-400 font-mono flex items-center gap-1">
              <span>{selectedTaintFlow ? `Ativo: $${selectedTaintFlow.variableName}` : 'Clique para expandir trilha interativa'}</span>
            </div>
          </div>
          <Maximize2 className="w-3.5 h-3.5 text-zinc-400 group-hover:text-white transition-colors ml-1" />
        </button>
      </div>
    );
  }

  // Active step node details for tracer view
  const currentStepNodeId = selectedTaintFlow?.pathNodeIds[activeStepIndex];
  const currentStepNode = currentStepNodeId ? nodesMap.get(currentStepNodeId) : null;

  return (
    <div className="absolute bottom-3 left-3 z-30 w-[calc(100vw-24px)] sm:w-[540px] md:w-[600px] max-w-[95vw] bg-[#0A0A0A]/95 backdrop-blur-xl border border-[#2B2B2B] rounded-2xl shadow-2xl flex flex-col transition-all duration-200 overflow-hidden font-mono">
      {/* Header Bar */}
      <div className="px-3.5 py-2.5 bg-[#111] border-b border-[#222] flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-rose-400">
            <ShieldAlert className="w-3.5 h-3.5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-white uppercase tracking-wider">
                Rastreamento de Variáveis Tainted
              </span>
              <span className="px-1.5 py-0.5 text-[9.5px] rounded bg-rose-950/60 text-rose-300 border border-rose-800/50 font-bold">
                {totalFlows} Detectadas
              </span>
            </div>
          </div>
        </div>

        {/* View Tabs & Minimize */}
        <div className="flex items-center gap-1.5">
          <div className="bg-[#181818] p-0.5 rounded-lg border border-[#2B2B2B] flex items-center text-[10px]">
            <button
              onClick={() => setActiveTab('VARS')}
              className={`px-2 py-1 rounded transition-colors ${
                activeTab === 'VARS' ? 'bg-[#262626] text-white font-bold' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Variáveis
            </button>
            <button
              onClick={() => setActiveTab('TRACER')}
              className={`px-2 py-1 rounded transition-colors flex items-center gap-1 ${
                activeTab === 'TRACER' ? 'bg-[#262626] text-white font-bold' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <span>Trilhas</span>
              {selectedTaintFlow && (
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
              )}
            </button>
            <button
              onClick={() => setActiveTab('LEGEND')}
              className={`px-2 py-1 rounded transition-colors ${
                activeTab === 'LEGEND' ? 'bg-[#262626] text-white font-bold' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Legenda
            </button>
          </div>

          <button
            onClick={() => setIsExpanded(false)}
            title="Minimizar Legenda"
            className="p-1 rounded-md text-zinc-400 hover:text-white hover:bg-[#222] transition-colors"
          >
            <Minimize2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="p-3 text-xs max-h-[300px] overflow-y-auto space-y-2.5">
        {/* TAB 1: TAINTED VARIABLES SELECTOR */}
        {activeTab === 'VARS' && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-[11px] text-zinc-400">
              <span>Selecione uma variável para traçar a propagação Untrusted ➔ Sink:</span>
              <div className="flex items-center gap-2">
                <button
                  onClick={onToggleHighlightAll}
                  className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
                    highlightAllTainted
                      ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 font-bold'
                      : 'bg-[#181818] text-zinc-400 border-[#333] hover:text-white'
                  }`}
                >
                  {highlightAllTainted ? '✓ Todas Destacadas' : 'Destacar Todas'}
                </button>
                {selectedTaintFlow && (
                  <button
                    onClick={() => onSelectTaintFlow(null)}
                    className="text-[10px] text-zinc-400 hover:text-rose-300 transition-colors"
                  >
                    Limpar
                  </button>
                )}
              </div>
            </div>

            {/* Variable Pills / Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
              {taintFlows.map((flow) => {
                const isSelected = selectedTaintFlow?.id === flow.id;
                return (
                  <button
                    key={flow.id}
                    onClick={() => {
                      if (isSelected) {
                        onSelectTaintFlow(null);
                      } else {
                        onSelectTaintFlow(flow);
                        setActiveTab('TRACER');
                      }
                    }}
                    className={`text-left p-2 rounded-xl border transition-all duration-150 flex flex-col justify-between group ${
                      isSelected
                        ? 'bg-rose-950/40 border-rose-500 shadow-md shadow-rose-950/30'
                        : 'bg-[#141414] hover:bg-[#1A1A1A] border-[#262626] hover:border-zinc-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1.5 mb-1">
                      <div className="flex items-center gap-1.5 font-bold">
                        <span className={`w-2 h-2 rounded-full ${isSelected ? 'bg-rose-400 animate-pulse' : 'bg-rose-500'}`} />
                        <span className="font-mono text-rose-200 text-[11px] group-hover:text-rose-100">
                          ${flow.variableName}
                        </span>
                      </div>
                      <span className="px-1.5 py-0.5 rounded bg-zinc-900 text-[9.5px] text-zinc-400 border border-zinc-800">
                        {flow.sinkType}
                      </span>
                    </div>

                    <div className="text-[10px] text-zinc-400 truncate flex items-center gap-1">
                      <span className="text-cyan-400 truncate">{flow.sourceLabel}</span>
                      <ArrowRight className="w-2.5 h-2.5 text-zinc-600 shrink-0" />
                      <span className="text-rose-400 truncate">{flow.sinkLabel}</span>
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Quick Helper Banner */}
            <div className="flex items-center justify-between bg-[#121212] px-2.5 py-1.5 rounded-lg border border-[#222] text-[10.5px] text-zinc-400">
              <span className="flex items-center gap-1.5">
                <Radio className="w-3 h-3 text-[#00E5FF]" />
                <span>Rótulos flutuantes nas arestas:</span>
              </span>
              <button
                onClick={onToggleShowVariableLabels}
                className={`px-2 py-0.5 rounded text-[10px] font-bold border transition-colors ${
                  showVariableLabels
                    ? 'bg-[#00E5FF]/20 text-[#00E5FF] border-[#00E5FF]/40'
                    : 'bg-[#1C1C1C] text-zinc-400 border-[#333]'
                }`}
              >
                {showVariableLabels ? 'VISÍVEL' : 'OCULTO'}
              </button>
            </div>
          </div>
        )}

        {/* TAB 2: STEP-BY-STEP PATH TRACER */}
        {activeTab === 'TRACER' && (
          <div className="space-y-3">
            {!selectedTaintFlow ? (
              <div className="p-4 text-center text-zinc-500 space-y-1.5">
                <Sparkles className="w-5 h-5 mx-auto text-zinc-600" />
                <p className="text-xs">Nenhuma variável selecionada para rastreamento.</p>
                <p className="text-[10px]">
                  Clique na aba "Variáveis" e escolha uma variável para traçar sua execução passo a passo.
                </p>
              </div>
            ) : (
              <>
                {/* Active Flow Header & Player Bar */}
                <div className="p-2.5 bg-[#141414] rounded-xl border border-rose-500/30 flex flex-col gap-2">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] uppercase font-bold text-rose-400 tracking-wider">
                          Variável em Rastreamento:
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold text-xs border border-rose-500/30">
                          ${selectedTaintFlow.variableName}
                        </span>
                      </div>
                      <div className="text-[10px] text-zinc-400 mt-0.5">
                        Passo {activeStepIndex + 1} de {selectedTaintFlow.pathNodeIds.length} —{' '}
                        {activeStepIndex === 0
                          ? 'Entrada Untrusted (Fonte)'
                          : activeStepIndex === selectedTaintFlow.pathNodeIds.length - 1
                          ? 'Sink Crítico (Exploit)'
                          : 'Propagação de Variável (Handler)'}
                      </div>
                    </div>

                    {/* Step Player Controls */}
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => onSelectStepIndex(Math.max(0, activeStepIndex - 1))}
                        disabled={activeStepIndex === 0}
                        title="Passo Anterior"
                        className="p-1.5 rounded-lg bg-[#222] hover:bg-[#2A2A2A] text-zinc-300 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                      >
                        <ChevronLeft className="w-3.5 h-3.5" />
                      </button>

                      <button
                        onClick={onTogglePlay}
                        title={isPlaying ? 'Pausar Reprodução' : 'Animar Propagação Automática'}
                        className={`px-2 py-1 rounded-lg flex items-center gap-1 font-bold text-[10px] transition-colors ${
                          isPlaying
                            ? 'bg-rose-500 text-white'
                            : 'bg-[#2A2A2A] hover:bg-[#333] text-zinc-200'
                        }`}
                      >
                        {isPlaying ? (
                          <>
                            <Pause className="w-3 h-3" />
                            <span>PAUSAR</span>
                          </>
                        ) : (
                          <>
                            <Play className="w-3 h-3 text-rose-400" />
                            <span>ANIMAR</span>
                          </>
                        )}
                      </button>

                      <button
                        onClick={() =>
                          onSelectStepIndex(
                            Math.min(selectedTaintFlow.pathNodeIds.length - 1, activeStepIndex + 1)
                          )
                        }
                        disabled={activeStepIndex === selectedTaintFlow.pathNodeIds.length - 1}
                        title="Próximo Passo"
                        className="p-1.5 rounded-lg bg-[#222] hover:bg-[#2A2A2A] text-zinc-300 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                      >
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>

                      {onZoomToPath && (
                        <button
                          onClick={onZoomToPath}
                          title="Centralizar Câmera no Caminho"
                          className="p-1.5 rounded-lg bg-[#222] hover:bg-[#2A2A2A] text-zinc-300 transition-colors ml-1"
                        >
                          <Focus className="w-3.5 h-3.5 text-[#00E5FF]" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Visual Step Progress Dots */}
                  <div className="flex items-center gap-1.5 pt-1 border-t border-[#222]">
                    {selectedTaintFlow.pathNodeIds.map((nodeId, idx) => {
                      const node = nodesMap.get(nodeId);
                      const isCurrent = activeStepIndex === idx;
                      return (
                        <button
                          key={nodeId}
                          onClick={() => onSelectStepIndex(idx)}
                          className={`flex-1 py-1 px-1 rounded-md text-[9.5px] font-mono transition-all flex items-center justify-center gap-1 border truncate ${
                            isCurrent
                              ? 'bg-rose-500 text-white border-rose-400 font-bold shadow'
                              : 'bg-[#181818] text-zinc-400 hover:text-white border-[#2A2A2A]'
                          }`}
                        >
                          <span>{idx + 1}.</span>
                          <span className="truncate">{node?.label.replace('()', '') || nodeId}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Current Active Step Deep Dive Card */}
                {currentStepNode && (
                  <div className="p-2.5 bg-[#121212] rounded-xl border border-[#262626] space-y-1.5">
                    <div className="flex items-center justify-between text-[11px]">
                      <div className="flex items-center gap-2">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            currentStepNode.type === 'ENDPOINT'
                              ? 'bg-[#00E5FF]'
                              : currentStepNode.type === 'CONSUMER'
                              ? 'bg-[#F59E0B]'
                              : 'bg-[#FF3E00] animate-pulse'
                          }`}
                        />
                        <span className="font-bold text-white">{currentStepNode.label}</span>
                        <span className="px-1.5 py-0.2 rounded bg-[#1F1F1F] text-zinc-400 text-[9.5px] border border-[#333]">
                          {currentStepNode.type}
                        </span>
                      </div>

                      {onInspectNode && (
                        <button
                          onClick={() => onInspectNode(currentStepNode.id)}
                          className="flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300 transition-colors"
                        >
                          <Code2 className="w-3 h-3" />
                          <span>Inspecionar Código</span>
                        </button>
                      )}
                    </div>

                    <div className="text-[10px] text-zinc-400 font-mono">
                      Arquivo: <span className="text-zinc-200">{currentStepNode.file}:{currentStepNode.line}</span>
                    </div>

                    {currentStepNode.snippet && (
                      <div className="p-1.5 rounded bg-black/60 border border-[#222] font-mono text-[10px] text-rose-300 overflow-x-auto whitespace-pre">
                        {currentStepNode.snippet}
                      </div>
                    )}

                    <div className="text-[10px] text-zinc-400 leading-relaxed">
                      {activeStepIndex === 0 && (
                        <span>
                          Origem não sanitizada. A variável <strong className="text-rose-300">${selectedTaintFlow.variableName}</strong> é recebida pela requisição HTTP e injetada no ciclo de dados.
                        </span>
                      )}
                      {activeStepIndex > 0 && activeStepIndex < selectedTaintFlow.pathNodeIds.length - 1 && (
                        <span>
                          A função recebe os dados da requisição e repassa o payload contendo <strong className="text-rose-300">${selectedTaintFlow.variableName}</strong> adiante sem validação ou escape.
                        </span>
                      )}
                      {activeStepIndex === selectedTaintFlow.pathNodeIds.length - 1 && (
                        <span>
                          <strong className="text-rose-400">Ponto de Impacto:</strong> A variável <strong className="text-rose-300">${selectedTaintFlow.variableName}</strong> é executada pelo sink perigoso ({selectedTaintFlow.sinkType}), configurando vulnerabilidade explorável ({selectedTaintFlow.cwe?.id || 'CWE'}).
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* TAB 3: INTERACTIVE VISUAL LEGEND & FILTERS */}
        {activeTab === 'LEGEND' && (
          <div className="space-y-2.5">
            <div className="text-[11px] text-zinc-400">
              Clique nos tipos de nós abaixo para isolar no grafo:
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <button
                onClick={() => onToggleFilterNodeType('ENDPOINT')}
                className={`p-2 rounded-xl border text-left transition-all ${
                  filterNodeType === 'ENDPOINT'
                    ? 'bg-[#00E5FF]/20 border-[#00E5FF] text-white'
                    : 'bg-[#141414] hover:bg-[#1A1A1A] border-[#262626] text-zinc-300'
                }`}
              >
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="w-2.5 h-2.5 rounded bg-[#00E5FF]" />
                  <span className="font-bold text-xs">Fonte Não Confiável (Source)</span>
                </div>
                <p className="text-[10px] text-zinc-400">
                  Rotas HTTP e portas de entrada externas (req.body, req.query, headers).
                </p>
              </button>

              <button
                onClick={() => onToggleFilterNodeType('CONSUMER')}
                className={`p-2 rounded-xl border text-left transition-all ${
                  filterNodeType === 'CONSUMER'
                    ? 'bg-[#F59E0B]/20 border-[#F59E0B] text-white'
                    : 'bg-[#141414] hover:bg-[#1A1A1A] border-[#262626] text-zinc-300'
                }`}
              >
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="w-2.5 h-2.5 rounded bg-[#F59E0B]" />
                  <span className="font-bold text-xs">Manipulador (Handler)</span>
                </div>
                <p className="text-[10px] text-zinc-400">
                  Funções intermediárias que propagam variáveis tainted.
                </p>
              </button>

              <button
                onClick={() => onToggleFilterNodeType('SINK')}
                className={`p-2 rounded-xl border text-left transition-all ${
                  filterNodeType === 'SINK'
                    ? 'bg-[#FF3E00]/20 border-[#FF3E00] text-white'
                    : 'bg-[#141414] hover:bg-[#1A1A1A] border-[#262626] text-zinc-300'
                }`}
              >
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="w-2.5 h-2.5 rounded bg-[#FF3E00] animate-pulse" />
                  <span className="font-bold text-xs">Sink Crítico (Target)</span>
                </div>
                <p className="text-[10px] text-zinc-400">
                  Primitivas de execução de código, DOM injection ou storage inseguro.
                </p>
              </button>

              <button
                onClick={() => onToggleFilterNodeType('TAINTED')}
                className={`p-2 rounded-xl border text-left transition-all ${
                  filterNodeType === 'TAINTED'
                    ? 'bg-rose-500/25 border-rose-500 text-white'
                    : 'bg-[#141414] hover:bg-[#1A1A1A] border-[#262626] text-zinc-300'
                }`}
              >
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="w-4 border-t-2 border-dashed border-[#FF3E00]" />
                  <span className="font-bold text-xs">Fluxo Tainted Completo</span>
                </div>
                <p className="text-[10px] text-zinc-400">
                  Caminhos diretos ligando fontes não confiáveis a sinks críticos.
                </p>
              </button>
            </div>

            {filterNodeType && (
              <div className="flex justify-end pt-1">
                <button
                  onClick={() => onToggleFilterNodeType(filterNodeType)}
                  className="text-[10px] text-zinc-400 hover:text-white transition-colors"
                >
                  Limpar Filtro de Categoria
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
