import React, { useState } from 'react';
import {
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  GitCommit,
  Flame,
  Sparkles,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Focus,
  Ghost,
  RefreshCw,
  Pin,
  HelpCircle
} from 'lucide-react';
import {
  DataFlowDeltaAnalysis,
  DataFlowVulnerabilityDelta,
  TaintVariableFlow
} from '../types';

export type DeltaFilterMode = 'ALL' | 'NEW_VULNERABILITIES' | 'NEW_NODES' | 'RESOLVED';

interface DataFlowDeltaPanelProps {
  delta: DataFlowDeltaAnalysis;
  filterMode: DeltaFilterMode;
  onSelectFilterMode: (mode: DeltaFilterMode) => void;
  showGhostNodes: boolean;
  onToggleGhostNodes: () => void;
  onFocusVulnerability: (flow: TaintVariableFlow) => void;
  onInspectNode?: (nodeId: string, filePath?: string, line?: number) => void;
  onSetCurrentAsBaseline: () => void;
  onSimulateCodeChanges: (scenario: 'PARTIAL_TAINT' | 'CLEAN_BASELINE') => void;
  baselineType: 'AUTO_PREVIOUS' | 'MANUAL_PINNED' | 'SIMULATED' | 'NONE';
  onResetBaselineToNone: () => void;
}

export const DataFlowDeltaPanel: React.FC<DataFlowDeltaPanelProps> = ({
  delta,
  filterMode,
  onSelectFilterMode,
  showGhostNodes,
  onToggleGhostNodes,
  onFocusVulnerability,
  onInspectNode,
  onSetCurrentAsBaseline,
  onSimulateCodeChanges,
  baselineType,
  onResetBaselineToNone
}) => {
  const [isExpanded, setIsExpanded] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<'NEW_VULNS' | 'MODIFIED_NODES' | 'RESOLVED'>('NEW_VULNS');
  const [selectedDeltaId, setSelectedDeltaId] = useState<string | null>(null);

  const { metrics, newVulnerabilities, resolvedVulnerabilities } = delta;

  // Status banner styling
  const isCriticalRegression = metrics.riskStatus === 'REGRESSION_CRITICAL';
  const isWarningRegression = metrics.riskStatus === 'REGRESSION_WARNING';
  const isImproved = metrics.riskStatus === 'IMPROVED';

  return (
    <div className="bg-[#0D0D0D]/95 border border-[#262626] rounded-xl shadow-2xl backdrop-blur-md overflow-hidden transition-all duration-200">
      {/* Top Banner Alert Bar */}
      <div
        className={`px-4 py-3 flex flex-wrap items-center justify-between gap-3 border-b ${
          isCriticalRegression
            ? 'bg-rose-950/40 border-rose-500/30'
            : isWarningRegression
            ? 'bg-amber-950/40 border-amber-500/30'
            : isImproved
            ? 'bg-emerald-950/40 border-emerald-500/30'
            : 'bg-[#141414] border-[#262626]'
        }`}
      >
        <div className="flex items-center gap-2.5">
          {isCriticalRegression ? (
            <div className="w-7 h-7 rounded-lg bg-rose-600/20 border border-rose-500/50 flex items-center justify-center text-rose-400 shrink-0 animate-pulse">
              <Flame className="w-4 h-4" />
            </div>
          ) : isWarningRegression ? (
            <div className="w-7 h-7 rounded-lg bg-amber-600/20 border border-amber-500/50 flex items-center justify-center text-amber-400 shrink-0">
              <AlertTriangle className="w-4 h-4" />
            </div>
          ) : isImproved ? (
            <div className="w-7 h-7 rounded-lg bg-emerald-600/20 border border-emerald-500/50 flex items-center justify-center text-emerald-400 shrink-0">
              <ShieldCheck className="w-4 h-4" />
            </div>
          ) : (
            <div className="w-7 h-7 rounded-lg bg-cyan-600/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0">
              <GitCommit className="w-4 h-4" />
            </div>
          )}

          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold tracking-wider uppercase text-zinc-300">
                Análise de Delta SAST
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border bg-black/40 text-zinc-400 border-zinc-700">
                Linha de Base: {delta.baselineName || 'Versão Anterior'}
              </span>
            </div>
            <h4 className="text-sm font-semibold text-white flex items-center gap-2">
              {metrics.newVulnerabilitiesCount > 0 ? (
                <span className="text-rose-400">
                  +{metrics.newVulnerabilitiesCount} Nova(s) Vulnerabilidade(s) Potencial(is) Introduzida(s) no Código Recente
                </span>
              ) : isImproved ? (
                <span className="text-emerald-400">
                  Melhoria de Segurança: -{metrics.resolvedVulnerabilitiesCount} Vulnerabilidade(s) Sanada(s)
                </span>
              ) : (
                <span className="text-zinc-200">
                  Nenhuma regressão ou nova vulnerabilidade detectada entre as versões
                </span>
              )}
            </h4>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          {/* Simulation & Baseline Presets */}
          <div className="flex items-center gap-1.5 bg-[#171717] border border-[#2A2A2A] rounded-lg p-1 text-[11px] font-mono">
            <button
              type="button"
              onClick={onSetCurrentAsBaseline}
              className="px-2 py-1 rounded hover:bg-[#262626] text-zinc-300 hover:text-white flex items-center gap-1 transition-colors"
              title="Fixar a versão atual como Linha de Base (Baseline) para comparar com futuros scans"
            >
              <Pin className="w-3 h-3 text-cyan-400" />
              <span>Fixar Baseline</span>
            </button>
            <span className="text-zinc-700">|</span>
            <button
              type="button"
              onClick={() => onSimulateCodeChanges('PARTIAL_TAINT')}
              className={`px-2 py-1 rounded flex items-center gap-1 transition-colors ${
                baselineType === 'SIMULATED'
                  ? 'bg-rose-950/60 text-rose-300 border border-rose-800/40'
                  : 'hover:bg-[#262626] text-zinc-400 hover:text-zinc-200'
              }`}
              title="Simula um commit anterior onde apenas 1 vulnerabilidade existia, evidenciando as novas introduzidas no commit recente"
            >
              <Sparkles className="w-3 h-3 text-amber-400" />
              <span>Simular Delta</span>
            </button>
            {baselineType !== 'NONE' && (
              <>
                <span className="text-zinc-700">|</span>
                <button
                  type="button"
                  onClick={onResetBaselineToNone}
                  className="px-1.5 py-1 rounded hover:bg-[#262626] text-zinc-500 hover:text-zinc-300 transition-colors"
                  title="Limpar comparação de baseline"
                >
                  <RefreshCw className="w-3 h-3" />
                </button>
              </>
            )}
          </div>

          <button
            type="button"
            onClick={() => setIsExpanded(prev => !prev)}
            className="p-1.5 rounded-lg bg-[#1F1F1F] hover:bg-[#2A2A2A] text-zinc-300 transition-colors cursor-pointer flex items-center gap-1 text-xs"
          >
            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {isExpanded && (
        <div className="p-4 space-y-4 text-xs">
          {/* Quick Metrics Bar & Filters */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-[#141414] border border-[#222] p-3 rounded-lg">
            {/* Metric counters (clickable to filter) */}
            <div className="flex flex-wrap items-center gap-2 font-mono">
              <button
                type="button"
                onClick={() => onSelectFilterMode(filterMode === 'NEW_VULNERABILITIES' ? 'ALL' : 'NEW_VULNERABILITIES')}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border text-xs font-semibold transition-all ${
                  filterMode === 'NEW_VULNERABILITIES'
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500 shadow-sm'
                    : 'bg-[#1C1C1C] text-zinc-300 border-[#333] hover:border-rose-500/50 hover:text-rose-300'
                }`}
              >
                <Flame className="w-3.5 h-3.5 text-rose-500" />
                <span>Novas Vulnerabilidades:</span>
                <span className="px-1.5 py-0.2 rounded bg-rose-950/80 text-rose-200 text-[11px] font-bold">
                  +{metrics.newVulnerabilitiesCount}
                </span>
              </button>

              <button
                type="button"
                onClick={() => onSelectFilterMode(filterMode === 'NEW_NODES' ? 'ALL' : 'NEW_NODES')}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border text-xs font-semibold transition-all ${
                  filterMode === 'NEW_NODES'
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500 shadow-sm'
                    : 'bg-[#1C1C1C] text-zinc-300 border-[#333] hover:border-cyan-500/50 hover:text-cyan-300'
                }`}
              >
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                <span>Novos Nós (+):</span>
                <span className="px-1.5 py-0.2 rounded bg-cyan-950/80 text-cyan-200 text-[11px] font-bold">
                  +{metrics.newNodesCount}
                </span>
              </button>

              <button
                type="button"
                onClick={() => onSelectFilterMode(filterMode === 'RESOLVED' ? 'ALL' : 'RESOLVED')}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border text-xs font-semibold transition-all ${
                  filterMode === 'RESOLVED'
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500 shadow-sm'
                    : 'bg-[#1C1C1C] text-zinc-300 border-[#333] hover:border-emerald-500/50 hover:text-emerald-300'
                }`}
              >
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>Sanadas (-):</span>
                <span className="px-1.5 py-0.2 rounded bg-emerald-950/80 text-emerald-200 text-[11px] font-bold">
                  -{metrics.resolvedVulnerabilitiesCount}
                </span>
              </button>

              <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-[#1C1C1C] text-zinc-400 border border-[#333] text-xs">
                <span>Nós Recém-Tainted:</span>
                <span className="text-amber-400 font-bold">+{metrics.newlyTaintedNodesCount}</span>
              </div>
            </div>

            {/* Ghost Nodes Toggle */}
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={onToggleGhostNodes}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-mono border transition-all ${
                  showGhostNodes
                    ? 'bg-zinc-800 text-zinc-200 border-zinc-600'
                    : 'bg-[#1A1A1A] text-zinc-400 border-[#2A2A2A] hover:text-zinc-200'
                }`}
                title="Exibe nós e rotas que foram deletados ou refatorados no código recente em modo fantasma translúcido"
              >
                <Ghost className="w-3.5 h-3.5 text-zinc-400" />
                <span>Exibir Nós Removidos ({delta.removedNodes.length})</span>
              </button>

              {filterMode !== 'ALL' && (
                <button
                  type="button"
                  onClick={() => onSelectFilterMode('ALL')}
                  className="px-2 py-1 rounded text-zinc-400 hover:text-white text-xs font-mono underline"
                >
                  Limpar Filtro
                </button>
              )}
            </div>
          </div>

          {/* Tab Navigation for Vulnerabilities Breakdown */}
          <div className="flex items-center gap-2 border-b border-[#262626] pb-1 font-mono text-xs">
            <button
              type="button"
              onClick={() => setActiveTab('NEW_VULNS')}
              className={`pb-1.5 px-2 flex items-center gap-1.5 font-bold transition-colors border-b-2 ${
                activeTab === 'NEW_VULNS'
                  ? 'border-rose-500 text-rose-400'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Flame className="w-3.5 h-3.5" />
              <span>Novas Vulnerabilidades ({newVulnerabilities.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('MODIFIED_NODES')}
              className={`pb-1.5 px-2 flex items-center gap-1.5 font-bold transition-colors border-b-2 ${
                activeTab === 'MODIFIED_NODES'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <TrendingUp className="w-3.5 h-3.5" />
              <span>Nós Afetados ({metrics.modifiedNodesCount + metrics.newNodesCount})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('RESOLVED')}
              className={`pb-1.5 px-2 flex items-center gap-1.5 font-bold transition-colors border-b-2 ${
                activeTab === 'RESOLVED'
                  ? 'border-emerald-500 text-emerald-400'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Vulnerabilidades Sanadas ({resolvedVulnerabilities.length})</span>
            </button>
          </div>

          {/* TAB 1: NEW VULNERABILITIES INTRODUCED */}
          {activeTab === 'NEW_VULNS' && (
            <div className="space-y-3">
              {newVulnerabilities.length === 0 ? (
                <div className="py-6 px-4 text-center rounded-lg bg-[#141414] border border-[#222] text-zinc-400">
                  <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-2" />
                  <p className="font-medium text-white">Nenhuma nova vulnerabilidade introduzida no commit recente!</p>
                  <p className="text-xs text-zinc-500 mt-1">
                    Todas as novas rotas e manipuladores estão adequadamente sanitizados ou não alcançam sinks perigosos.
                  </p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {newVulnerabilities.map(vuln => {
                    const isSelected = selectedDeltaId === vuln.id;
                    return (
                      <div
                        key={vuln.id}
                        onClick={() => setSelectedDeltaId(vuln.id)}
                        className={`p-3.5 rounded-xl border transition-all cursor-pointer space-y-2.5 ${
                          isSelected
                            ? 'bg-rose-950/30 border-rose-500 ring-1 ring-rose-500/50'
                            : 'bg-[#141414] border-[#2A2A2A] hover:border-rose-500/50'
                        }`}
                      >
                        {/* Header: Severity, Variable, CWE */}
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-600 text-white animate-pulse">
                              NOVA VULNERABILIDADE
                            </span>
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800/40">
                              {vuln.severity}
                            </span>
                            {vuln.cwe && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-zinc-800 text-zinc-300">
                                {vuln.cwe.id}
                              </span>
                            )}
                          </div>
                          <span className="text-[10px] font-mono text-zinc-500">
                            {vuln.introducedInFile}
                          </span>
                        </div>

                        {/* Variable flow path */}
                        <div className="bg-black/60 rounded-lg p-2 font-mono text-[11px] border border-white/5 space-y-1">
                          <div className="text-rose-300 flex items-center gap-1.5">
                            <span className="text-zinc-500">Variável Tainted:</span>
                            <span className="font-bold bg-rose-950/80 px-1 rounded text-rose-200">
                              ${vuln.variableName}
                            </span>
                          </div>
                          <div className="text-zinc-300 text-[10.5px] flex items-center gap-1 flex-wrap">
                            <span className="text-cyan-400 font-semibold">{vuln.sourceLabel}</span>
                            <span className="text-zinc-600">➔</span>
                            <span className="text-rose-400 font-semibold">{vuln.sinkLabel}</span>
                          </div>
                        </div>

                        {/* Reason / Impact */}
                        <p className="text-zinc-300 leading-relaxed text-[11.5px]">
                          {vuln.changeReason}
                        </p>

                        {/* Remediation Advice */}
                        <div className="text-[10.5px] bg-emerald-950/30 border border-emerald-800/30 rounded-lg p-2 text-emerald-300">
                          <span className="font-bold uppercase tracking-wide text-[9px] block text-emerald-400 mb-0.5">
                            Como Remediar:
                          </span>
                          <span>{vuln.remediationAdvice}</span>
                        </div>

                        {/* Action buttons */}
                        <div className="flex items-center gap-2 pt-1">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              onFocusVulnerability(vuln.flow);
                            }}
                            className="flex-1 py-1.5 px-2.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-semibold flex items-center justify-center gap-1.5 shadow-sm transition-colors cursor-pointer"
                          >
                            <Focus className="w-3.5 h-3.5" />
                            <span>Destacar no Grafo</span>
                          </button>

                          {vuln.introducedInFile && onInspectNode && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                onInspectNode(vuln.flow.sinkNodeId, vuln.introducedInFile, vuln.introducedAtLine);
                              }}
                              className="py-1.5 px-2.5 rounded-lg bg-[#222] hover:bg-[#333] text-zinc-200 font-mono text-xs flex items-center justify-center gap-1 transition-colors cursor-pointer"
                              title="Abrir arquivo de origem no analisador"
                            >
                              <ExternalLink className="w-3.5 h-3.5 text-zinc-400" />
                              <span>Código</span>
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: MODIFIED AND NEW NODES LIST */}
          {activeTab === 'MODIFIED_NODES' && (
            <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
              {Object.entries(delta.nodeDeltaMap)
                .filter(([_, info]) => info.status === 'NEW' || info.status === 'MODIFIED')
                .map(([nodeId, info]) => (
                  <div
                    key={nodeId}
                    className="p-2.5 rounded-lg bg-[#141414] border border-[#262626] flex items-center justify-between gap-3 font-mono text-xs"
                  >
                    <div className="flex items-center gap-2">
                      {info.status === 'NEW' ? (
                        <span className="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[10px] font-bold">
                          + NOVO NÓ
                        </span>
                      ) : info.isNewlyTainted ? (
                        <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-bold">
                          ! RECÉM TAINTED
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-bold">
                          ~ MODIFICADO
                        </span>
                      )}
                      <span className="text-zinc-200 font-semibold">{nodeId}</span>
                      <span className="text-zinc-400 text-[11px]">{info.changeDescription}</span>
                    </div>

                    {info.newlyAddedVariables && info.newlyAddedVariables.length > 0 && (
                      <div className="flex items-center gap-1 text-[10px] text-rose-300">
                        <span>Variáveis:</span>
                        <span className="bg-rose-950 px-1 py-0.5 rounded border border-rose-800">
                          {info.newlyAddedVariables.map(v => `$${v}`).join(', ')}
                        </span>
                      </div>
                    )}
                  </div>
                ))}
            </div>
          )}

          {/* TAB 3: RESOLVED VULNERABILITIES */}
          {activeTab === 'RESOLVED' && (
            <div className="space-y-2">
              {resolvedVulnerabilities.length === 0 ? (
                <div className="py-6 px-4 text-center rounded-lg bg-[#141414] border border-[#222] text-zinc-500">
                  <p>Nenhuma vulnerabilidade sanada nesta iteração comparativa.</p>
                </div>
              ) : (
                resolvedVulnerabilities.map(res => (
                  <div
                    key={res.id}
                    className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/40 text-xs space-y-1"
                  >
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-emerald-600 text-white font-mono text-[10px] font-bold">
                        SANADO
                      </span>
                      <span className="font-semibold text-emerald-300">
                        {res.sourceLabel} ➔ {res.sinkLabel}
                      </span>
                      <span className="text-zinc-400 font-mono text-[10.5px]">
                        (${res.variableName})
                      </span>
                    </div>
                    <p className="text-zinc-300 text-[11px]">{res.changeReason}</p>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
