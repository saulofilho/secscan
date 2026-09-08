import React from 'react';
import {
  SlidersHorizontal,
  Layers,
  Network,
  GitFork,
  Play,
  Pause,
  RotateCcw,
  MoveHorizontal,
  MoveVertical,
  Spline,
  Eye,
  EyeOff,
  Flame,
  Check,
  X,
  Compass,
  Sparkles,
  Info
} from 'lucide-react';
import { DataFlowGraphSettings } from '../types';

interface DataFlowSettingsPanelProps {
  isOpen: boolean;
  onClose: () => void;
  settings: DataFlowGraphSettings;
  onUpdateSettings: (updater: Partial<DataFlowGraphSettings> | ((prev: DataFlowGraphSettings) => DataFlowGraphSettings)) => void;
  onResetDefaults: () => void;
  activeNodesCount: number;
  activeLinksCount: number;
  totalTaintFlows: number;
}

export const DataFlowSettingsPanel: React.FC<DataFlowSettingsPanelProps> = ({
  isOpen,
  onClose,
  settings,
  onUpdateSettings,
  onResetDefaults,
  activeNodesCount,
  activeLinksCount,
  totalTaintFlows
}) => {
  if (!isOpen) return null;

  return (
    <div className="absolute top-0 right-0 w-full sm:w-[420px] h-full z-40 bg-[#0A0A0A]/95 backdrop-blur-xl border-l border-[#262626] shadow-2xl flex flex-col transition-all duration-300 animate-in slide-in-from-right">
      {/* Header */}
      <div className="p-4 sm:p-5 border-b border-[#222] flex items-center justify-between gap-3 bg-[#0E0E0E]">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-[#FF3E00]/15 border border-[#FF3E00]/30 flex items-center justify-center text-[#FF3E00]">
            <SlidersHorizontal className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-white font-mono flex items-center gap-2">
              <span>Configurações de Layout</span>
              <span className="text-[9.5px] px-2 py-0.5 rounded bg-[#1C1C1C] text-[#00E5FF] border border-[#333] font-mono">
                {settings.layoutMode === 'HIERARCHICAL' ? 'HIERÁRQUICO' : settings.layoutMode === 'FORCE' ? 'FORCE-DIRECTED' : 'PIPELINE'}
              </span>
            </h3>
            <p className="text-[11px] text-zinc-400 font-mono">
              Ajuste física, posicionamento estático e filtros de fluxo
            </p>
          </div>
        </div>

        <button
          onClick={onClose}
          className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-[#1F1F1F] transition-colors"
          title="Fechar painel de configurações"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Scrollable Content */}
      <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-6 text-xs font-mono">
        {/* Graph Meta Status Bar */}
        <div className="grid grid-cols-3 gap-2 bg-[#121212] p-2.5 rounded-lg border border-[#222] text-center">
          <div>
            <span className="text-[10px] text-zinc-500 uppercase block">Nós Visíveis</span>
            <span className="text-xs font-bold text-white">{activeNodesCount}</span>
          </div>
          <div>
            <span className="text-[10px] text-zinc-500 uppercase block">Conexões</span>
            <span className="text-xs font-bold text-[#00E5FF]">{activeLinksCount}</span>
          </div>
          <div>
            <span className="text-[10px] text-zinc-500 uppercase block">Caminhos Taint</span>
            <span className="text-xs font-bold text-[#FF3E00]">{totalTaintFlows}</span>
          </div>
        </div>

        {/* Primary Layout Mode Switch */}
        <div className="space-y-3">
          <label className="text-[11px] font-bold uppercase tracking-wider text-zinc-300 block flex items-center justify-between">
            <span>Modo de Layout Primário</span>
            <span className="text-[10px] text-[#FF3E00] font-normal">// ESCOLHA O MECANISMO</span>
          </label>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {/* Hierarchical Mode Card */}
            <button
              type="button"
              onClick={() => onUpdateSettings({ layoutMode: 'HIERARCHICAL' })}
              className={`p-3 rounded-lg border text-left transition-all ${
                settings.layoutMode === 'HIERARCHICAL'
                  ? 'bg-[#18110D] border-[#FF3E00] shadow-[0_0_15px_rgba(255,62,0,0.15)]'
                  : 'bg-[#121212] border-[#262626] hover:border-[#383838]'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-white flex items-center gap-1.5">
                  <GitFork className="w-3.5 h-3.5 text-[#FF3E00]" />
                  <span>Hierárquico</span>
                </span>
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#262626] text-zinc-300 font-bold">
                  ESTÁTICO
                </span>
              </div>
              <p className="text-[10px] text-zinc-400 leading-relaxed">
                Estrutura colunar/DAG com posições fixas. Elimina sobreposições em fluxos complexos.
              </p>
            </button>

            {/* Force-Directed Mode Card */}
            <button
              type="button"
              onClick={() => onUpdateSettings({ layoutMode: 'FORCE' })}
              className={`p-3 rounded-lg border text-left transition-all ${
                settings.layoutMode === 'FORCE'
                  ? 'bg-[#0D181D] border-[#00E5FF] shadow-[0_0_15px_rgba(0,229,255,0.15)]'
                  : 'bg-[#121212] border-[#262626] hover:border-[#383838]'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-white flex items-center gap-1.5">
                  <Network className="w-3.5 h-3.5 text-[#00E5FF]" />
                  <span>Force-Directed</span>
                </span>
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#262626] text-[#00E5FF] font-bold">
                  DINÂMICO
                </span>
              </div>
              <p className="text-[10px] text-zinc-400 leading-relaxed">
                Simulação física D3 interativa com forças de repulsão e atração elástica de links.
              </p>
            </button>
          </div>
        </div>

        {/* Sub-Settings for HIERARCHICAL MODE */}
        {settings.layoutMode === 'HIERARCHICAL' && (
          <div className="space-y-4 pt-2 border-t border-[#1F1F1F]">
            <div className="flex items-center gap-2">
              <GitFork className="w-4 h-4 text-[#FF3E00]" />
              <span className="text-[11px] font-bold uppercase tracking-wider text-white">
                Parâmetros do Modo Hierárquico (Estático)
              </span>
            </div>

            {/* Orientation */}
            <div className="space-y-2">
              <span className="text-[10.5px] text-zinc-400 block">Orientação do Fluxo</span>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => onUpdateSettings({ hierarchicalOrientation: 'HORIZONTAL' })}
                  className={`p-2 rounded-lg border flex items-center justify-center gap-2 transition-all ${
                    settings.hierarchicalOrientation === 'HORIZONTAL'
                      ? 'bg-[#222] border-[#FF3E00] text-white font-bold'
                      : 'bg-[#121212] border-[#262626] text-zinc-400 hover:text-white'
                  }`}
                >
                  <MoveHorizontal className="w-3.5 h-3.5 text-[#FF3E00]" />
                  <span>Horizontal (Esq ➔ Dir)</span>
                </button>

                <button
                  type="button"
                  onClick={() => onUpdateSettings({ hierarchicalOrientation: 'VERTICAL' })}
                  className={`p-2 rounded-lg border flex items-center justify-center gap-2 transition-all ${
                    settings.hierarchicalOrientation === 'VERTICAL'
                      ? 'bg-[#222] border-[#FF3E00] text-white font-bold'
                      : 'bg-[#121212] border-[#262626] text-zinc-400 hover:text-white'
                  }`}
                >
                  <MoveVertical className="w-3.5 h-3.5 text-[#FF3E00]" />
                  <span>Vertical (Cima ➔ Baixo)</span>
                </button>
              </div>
            </div>

            {/* Rank Separation Slider */}
            <div className="space-y-1.5 bg-[#121212] p-3 rounded-lg border border-[#222]">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-zinc-300">Separação entre Camadas</span>
                <span className="text-[#00E5FF] font-bold font-mono">{settings.rankSeparation}px</span>
              </div>
              <input
                type="range"
                min={160}
                max={360}
                step={10}
                value={settings.rankSeparation}
                onChange={e => onUpdateSettings({ rankSeparation: Number(e.target.value) })}
                className="w-full accent-[#FF3E00] cursor-pointer bg-[#222] h-1.5 rounded-lg"
              />
              <div className="flex justify-between text-[9px] text-zinc-500">
                <span>Compacto (160px)</span>
                <span>Padrão (250px)</span>
                <span>Amplo (360px)</span>
              </div>
            </div>

            {/* Node Separation Slider */}
            <div className="space-y-1.5 bg-[#121212] p-3 rounded-lg border border-[#222]">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-zinc-300">Espaçamento entre Nós (Mesma Camada)</span>
                <span className="text-[#00E5FF] font-bold font-mono">{settings.nodeSeparation}px</span>
              </div>
              <input
                type="range"
                min={55}
                max={140}
                step={5}
                value={settings.nodeSeparation}
                onChange={e => onUpdateSettings({ nodeSeparation: Number(e.target.value) })}
                className="w-full accent-[#FF3E00] cursor-pointer bg-[#222] h-1.5 rounded-lg"
              />
              <div className="flex justify-between text-[9px] text-zinc-500">
                <span>Denso (55px)</span>
                <span>Normal (85px)</span>
                <span>Espaçoso (140px)</span>
              </div>
            </div>

            {/* Curve Style & Sinks Alignment */}
            <div className="space-y-2">
              <span className="text-[10.5px] text-zinc-400 block">Estilo das Arestas</span>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => onUpdateSettings({ curveStyle: 'BEZIER' })}
                  className={`p-2 rounded-lg border flex items-center justify-center gap-1.5 ${
                    settings.curveStyle === 'BEZIER'
                      ? 'bg-[#222] border-[#00E5FF] text-white font-bold'
                      : 'bg-[#121212] border-[#262626] text-zinc-400 hover:text-white'
                  }`}
                >
                  <Spline className="w-3.5 h-3.5 text-[#00E5FF]" />
                  <span>Curvas Bézier</span>
                </button>

                <button
                  type="button"
                  onClick={() => onUpdateSettings({ curveStyle: 'STRAIGHT' })}
                  className={`p-2 rounded-lg border flex items-center justify-center gap-1.5 ${
                    settings.curveStyle === 'STRAIGHT'
                      ? 'bg-[#222] border-[#00E5FF] text-white font-bold'
                      : 'bg-[#121212] border-[#262626] text-zinc-400 hover:text-white'
                  }`}
                >
                  <span>Linhas Diretas</span>
                </button>
              </div>
            </div>

            {/* Align Sinks To Final Column */}
            <label className="flex items-start gap-2.5 p-2.5 bg-[#121212] rounded-lg border border-[#222] cursor-pointer hover:border-[#333]">
              <input
                type="checkbox"
                checked={settings.alignSinksToEnd}
                onChange={e => onUpdateSettings({ alignSinksToEnd: e.target.checked })}
                className="mt-0.5 accent-[#FF3E00] rounded"
              />
              <div>
                <span className="text-[11px] font-bold text-zinc-200 block">
                  Alinhar Sinks Perigosos no Nível Final
                </span>
                <span className="text-[10px] text-zinc-400">
                  Garante que todos os alvos de injeção/sinks fiquem uniformemente posicionados na última coluna.
                </span>
              </div>
            </label>
          </div>
        )}

        {/* Sub-Settings for FORCE-DIRECTED MODE */}
        {settings.layoutMode === 'FORCE' && (
          <div className="space-y-4 pt-2 border-t border-[#1F1F1F]">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-[#00E5FF]" />
                <span className="text-[11px] font-bold uppercase tracking-wider text-white">
                  Física do Force-Directed (Dinâmico)
                </span>
              </div>

              {/* Pause / Play physics button */}
              <button
                type="button"
                onClick={() => onUpdateSettings(prev => ({ ...prev, isPhysicsPaused: !prev.isPhysicsPaused }))}
                className={`inline-flex items-center gap-1 px-2.5 py-1 rounded text-[10px] font-bold transition-all ${
                  settings.isPhysicsPaused
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                    : 'bg-[#1E1E1E] text-zinc-300 border border-[#333] hover:text-white'
                }`}
                title={settings.isPhysicsPaused ? 'Retomar simulação dinâmica' : 'Congelar posições físicas'}
              >
                {settings.isPhysicsPaused ? (
                  <>
                    <Play className="w-3 h-3 text-amber-400 fill-current" />
                    <span>FÍSICA PAUSADA</span>
                  </>
                ) : (
                  <>
                    <Pause className="w-3 h-3 text-[#00E5FF]" />
                    <span>SIMULAÇÃO ATIVA</span>
                  </>
                )}
              </button>
            </div>

            {/* Charge Strength Slider */}
            <div className="space-y-1.5 bg-[#121212] p-3 rounded-lg border border-[#222]">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-zinc-300">Força de Repulsão (Charge)</span>
                <span className="text-[#00E5FF] font-bold font-mono">{settings.chargeStrength}</span>
              </div>
              <input
                type="range"
                min={-900}
                max={-150}
                step={50}
                value={settings.chargeStrength}
                onChange={e => onUpdateSettings({ chargeStrength: Number(e.target.value) })}
                className="w-full accent-[#00E5FF] cursor-pointer bg-[#222] h-1.5 rounded-lg"
              />
              <div className="flex justify-between text-[9px] text-zinc-500">
                <span>Disperso (-900)</span>
                <span>Padrão (-450)</span>
                <span>Compacto (-150)</span>
              </div>
            </div>

            {/* Link Distance Slider */}
            <div className="space-y-1.5 bg-[#121212] p-3 rounded-lg border border-[#222]">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-zinc-300">Comprimento dos Links</span>
                <span className="text-[#00E5FF] font-bold font-mono">{settings.linkDistance}px</span>
              </div>
              <input
                type="range"
                min={80}
                max={280}
                step={10}
                value={settings.linkDistance}
                onChange={e => onUpdateSettings({ linkDistance: Number(e.target.value) })}
                className="w-full accent-[#00E5FF] cursor-pointer bg-[#222] h-1.5 rounded-lg"
              />
              <div className="flex justify-between text-[9px] text-zinc-500">
                <span>Curto (80px)</span>
                <span>Equilibrado (150px)</span>
                <span>Longo (280px)</span>
              </div>
            </div>

            {/* Collision Radius */}
            <div className="space-y-1.5 bg-[#121212] p-3 rounded-lg border border-[#222]">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-zinc-300">Raio de Prevenção de Colisão</span>
                <span className="text-[#00E5FF] font-bold font-mono">{settings.collisionRadius}px</span>
              </div>
              <input
                type="range"
                min={36}
                max={75}
                step={2}
                value={settings.collisionRadius}
                onChange={e => onUpdateSettings({ collisionRadius: Number(e.target.value) })}
                className="w-full accent-[#00E5FF] cursor-pointer bg-[#222] h-1.5 rounded-lg"
              />
            </div>
          </div>
        )}

        {/* Global Filters & Readability Helpers */}
        <div className="space-y-3 pt-2 border-t border-[#1F1F1F]">
          <span className="text-[11px] font-bold uppercase tracking-wider text-zinc-300 block">
            Filtros & Redução de Ruído (Fluxos Complexos)
          </span>

          {/* Hide Isolated Nodes */}
          <label className="flex items-start gap-2.5 p-2.5 bg-[#121212] rounded-lg border border-[#222] cursor-pointer hover:border-[#333]">
            <input
              type="checkbox"
              checked={settings.hideIsolatedNodes}
              onChange={e => onUpdateSettings({ hideIsolatedNodes: e.target.checked })}
              className="mt-0.5 accent-[#FF3E00] rounded"
            />
            <div>
              <span className="text-[11px] font-bold text-zinc-200 block">
                Ocultar Nós Desconectados (Sem Arestas)
              </span>
              <span className="text-[10px] text-zinc-400">
                Filtra funções e endpoints isolados que não possuem fluxo rastreável de dados para os sinks.
              </span>
            </div>
          </label>

          {/* Show Level Guides */}
          <label className="flex items-start gap-2.5 p-2.5 bg-[#121212] rounded-lg border border-[#222] cursor-pointer hover:border-[#333]">
            <input
              type="checkbox"
              checked={settings.showLevelGuides}
              onChange={e => onUpdateSettings({ showLevelGuides: e.target.checked })}
              className="mt-0.5 accent-[#00E5FF] rounded"
            />
            <div>
              <span className="text-[11px] font-bold text-zinc-200 block">
                Exibir Réguas de Nível e Guias no Fundo
              </span>
              <span className="text-[10px] text-zinc-400">
                Desenha delimitadores visuais das fases de fluxo (Ingress ➔ Processamento ➔ Sinks).
              </span>
            </div>
          </label>

          {/* Highlight Taint Edges */}
          <label className="flex items-start gap-2.5 p-2.5 bg-[#121212] rounded-lg border border-[#222] cursor-pointer hover:border-[#333]">
            <input
              type="checkbox"
              checked={settings.highlightTaintEdges}
              onChange={e => onUpdateSettings({ highlightTaintEdges: e.target.checked })}
              className="mt-0.5 accent-[#FF3E00] rounded"
            />
            <div>
              <span className="text-[11px] font-bold text-zinc-200 block flex items-center gap-1.5">
                <Flame className="w-3.5 h-3.5 text-[#FF3E00]" />
                <span>Realce Intenso em Caminhos de Taint</span>
              </span>
              <span className="text-[10px] text-zinc-400">
                Acentua a animação pulsante nas arestas vulneráveis até os sinks DOM.
              </span>
            </div>
          </label>
        </div>
      </div>

      {/* Footer Controls */}
      <div className="p-4 border-t border-[#222] bg-[#0E0E0E] flex items-center justify-between gap-3 shrink-0">
        <button
          type="button"
          onClick={onResetDefaults}
          className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#161616] hover:bg-[#222] text-zinc-300 hover:text-white border border-[#2E2E2E] text-xs font-mono transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Restaurar Padrões</span>
        </button>

        <button
          type="button"
          onClick={onClose}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#FF3E00] hover:bg-white hover:text-black text-white text-xs font-mono font-bold transition-all"
        >
          <Check className="w-3.5 h-3.5" />
          <span>Aplicar & Fechar</span>
        </button>
      </div>
    </div>
  );
};
