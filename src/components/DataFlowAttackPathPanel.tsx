import React, { useState } from 'react';
import {
  Crosshair,
  ShieldAlert,
  ArrowRight,
  Play,
  Pause,
  ChevronRight,
  ChevronLeft,
  FileCode,
  ExternalLink,
  Copy,
  Check,
  AlertTriangle,
  Flame,
  Target,
  Zap,
  Radio,
  Eye,
  X
} from 'lucide-react';
import { AttackPath, AttackPathStep } from '../lib/attackPathEngine';

interface DataFlowAttackPathPanelProps {
  attackPaths: AttackPath[];
  activePath: AttackPath | null;
  activePathIndex: number;
  activeStepIndex: number;
  isPlayingFlow: boolean;
  onSelectPath: (index: number) => void;
  onSelectStep: (stepIndex: number) => void;
  onTogglePlay: () => void;
  onClose: () => void;
  onSelectFile?: (filePath: string, line?: number) => void;
  onNavigateToTab?: (tabId: string) => void;
}

export const DataFlowAttackPathPanel: React.FC<DataFlowAttackPathPanelProps> = ({
  attackPaths,
  activePath,
  activePathIndex,
  activeStepIndex,
  isPlayingFlow,
  onSelectPath,
  onSelectStep,
  onTogglePlay,
  onClose,
  onSelectFile,
  onNavigateToTab
}) => {
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [copiedProof, setCopiedProof] = useState(false);
  const [isDetailsExpanded, setIsDetailsExpanded] = useState(true);

  if (!activePath || attackPaths.length === 0) return null;

  const currentStep: AttackPathStep | undefined = activePath.steps[activeStepIndex] || activePath.steps[0];

  const handleCopyProof = () => {
    navigator.clipboard.writeText(activePath.technicalProof);
    setCopiedProof(true);
    setTimeout(() => setCopiedProof(false), 2000);
  };

  const sampleCurl = `curl -X ${activePath.entryEndpoint.method} "https://target-app.local${activePath.entryEndpoint.path}" \\
  -H "Content-Type: application/json" \\
  -d '{"exploit": "payload_test"}'`;

  const handleCopyCurl = () => {
    navigator.clipboard.writeText(sampleCurl);
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  return (
    <div className="bg-[#0A0608] border-2 border-rose-500/70 rounded-xl p-3.5 text-xs font-mono shadow-[0_0_30px_rgba(244,63,94,0.25)] space-y-3 animate-in fade-in duration-200">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2.5 border-b border-rose-900/40">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-7 h-7 rounded-lg bg-rose-500/20 border border-rose-500/60 flex items-center justify-center text-rose-400 shrink-0 shadow-[0_0_12px_rgba(244,63,94,0.3)]">
            <Crosshair className="w-4 h-4 text-rose-400 animate-pulse" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-bold text-white text-[13px] tracking-wide">
                Visualização do Vetor de Ataque (Attack Path)
              </span>
              <span className="inline-flex items-center gap-1 px-2 py-0.2 rounded text-[9px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/50">
                <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-ping" />
                <span>ATIVO</span>
              </span>
              <span className="text-[10px] text-zinc-400 hidden sm:inline">
                API Inspector ➔ Propagação ➔ Motor SAST
              </span>
            </div>
            <p className="text-[11px] text-zinc-400 truncate">
              Mapeamento de superfícies externas expostas que alcançam diretamente dados sensíveis identificados pelo motor SAST.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => setIsDetailsExpanded(prev => !prev)}
            className="px-2 py-1 rounded bg-[#160B0E] hover:bg-[#251015] border border-rose-900/50 text-zinc-300 hover:text-white transition-colors cursor-pointer text-[10px]"
          >
            {isDetailsExpanded ? 'Recolher Detalhes' : 'Expandir Detalhes'}
          </button>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-[#160B0E] hover:bg-rose-950/80 border border-rose-900/60 text-zinc-400 hover:text-rose-200 transition-colors cursor-pointer"
            title="Desativar visualização de vetor de ataque"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Path Selector Carousel */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-[10px] text-zinc-400">
          <span className="flex items-center gap-1 font-bold text-zinc-300">
            <Target className="w-3 h-3 text-rose-400" />
            <span>Caminhos de Ataque Descobertos ({attackPaths.length}):</span>
          </span>
          <span className="text-[9px] text-rose-400">
            Selecione um caminho para rastrear no grafo
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
          {attackPaths.map((path, idx) => {
            const isSelected = idx === activePathIndex;
            return (
              <button
                key={path.id}
                onClick={() => onSelectPath(idx)}
                className={`p-2 rounded-lg border text-left transition-all cursor-pointer flex flex-col justify-between gap-1.5 ${
                  isSelected
                    ? 'bg-gradient-to-r from-rose-950/90 to-[#2A0810] border-rose-500 shadow-[0_0_12px_rgba(244,63,94,0.3)] ring-1 ring-rose-500/50'
                    : 'bg-[#100709] border-[#2A1016] hover:border-rose-900/60 hover:bg-[#180A0E] text-zinc-400'
                }`}
              >
                <div className="flex items-center justify-between gap-1 w-full">
                  <span className={`px-1.5 py-0.2 rounded text-[8.5px] font-bold ${
                    path.entryEndpoint.method === 'POST' ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40' :
                    path.entryEndpoint.method === 'GET' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' :
                    'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                  }`}>
                    {path.entryEndpoint.method}
                  </span>
                  <span className={`px-1.5 py-0.2 rounded text-[8.5px] font-bold ${
                    path.severity === 'CRITICAL' ? 'bg-rose-500/30 text-rose-200 border border-rose-500/50' :
                    'bg-amber-500/30 text-amber-200 border border-amber-500/50'
                  }`}>
                    RISCO {path.riskScore}/100
                  </span>
                </div>

                <div className="truncate w-full text-[10.5px] font-bold text-white">
                  {path.entryEndpoint.path}
                </div>

                <div className="flex items-center gap-1 text-[9px] text-zinc-400 truncate">
                  <ArrowRight className="w-2.5 h-2.5 text-rose-400 shrink-0" />
                  <span className="truncate text-rose-300 font-bold">{path.targetSensitiveData.name.split('(')[0]}</span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {isDetailsExpanded && (
        <>
          {/* Active Path Stepper Walkthrough */}
          <div className="p-3 rounded-lg bg-[#0E070A] border border-rose-900/40 space-y-2.5">
            {/* Step Selector Badges */}
            <div className="flex items-center justify-between gap-2 overflow-x-auto pb-1 no-scrollbar text-[10px]">
              <div className="flex items-center gap-2">
                <span className="text-zinc-400 font-bold flex items-center gap-1 shrink-0">
                  <Radio className="w-3 h-3 text-rose-400 animate-pulse" />
                  <span>Cadeia de Exploração:</span>
                </span>
                <div className="flex items-center gap-1.5">
                  {activePath.steps.map((st, sIdx) => {
                    const isStepActive = sIdx === activeStepIndex;
                    return (
                      <React.Fragment key={st.stepIndex}>
                        <button
                          onClick={() => onSelectStep(sIdx)}
                          className={`px-2 py-1 rounded border transition-all cursor-pointer whitespace-nowrap flex items-center gap-1 font-bold ${
                            isStepActive
                              ? 'bg-rose-500/30 text-white border-rose-400 shadow-sm ring-1 ring-rose-400/40'
                              : 'bg-[#180A0E] text-zinc-400 border-rose-950/80 hover:text-zinc-200'
                          }`}
                        >
                          <span>Passo {st.stepIndex}:</span>
                          <span className={st.role === 'EXTERNAL_ENTRY' ? 'text-sky-300' : st.role === 'SENSITIVE_ASSET' ? 'text-rose-300' : 'text-amber-300'}>
                            {st.role === 'EXTERNAL_ENTRY' ? 'API Ingress' : st.role === 'SENSITIVE_ASSET' ? 'Dado Sensível' : 'Propagação'}
                          </span>
                        </button>
                        {sIdx < activePath.steps.length - 1 && (
                          <ArrowRight className="w-3 h-3 text-rose-500/60 shrink-0" />
                        )}
                      </React.Fragment>
                    );
                  })}
                </div>
              </div>

              {/* Stepper Playback Controls */}
              <div className="flex items-center gap-1.5 shrink-0">
                <button
                  onClick={() => onSelectStep(Math.max(0, activeStepIndex - 1))}
                  disabled={activeStepIndex === 0}
                  className="p-1 rounded bg-[#160B0E] hover:bg-[#251015] border border-rose-900/50 text-zinc-300 disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer"
                  title="Passo anterior"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={onTogglePlay}
                  className={`px-2 py-1 rounded border text-[10px] font-bold flex items-center gap-1 transition-all cursor-pointer ${
                    isPlayingFlow
                      ? 'bg-rose-500 text-white border-rose-400 shadow-[0_0_10px_rgba(244,63,94,0.4)]'
                      : 'bg-[#1F0A10] hover:bg-rose-950 text-rose-300 border-rose-700/60'
                  }`}
                  title={isPlayingFlow ? 'Pausar animação' : 'Simular trajetória de ataque no grafo'}
                >
                  {isPlayingFlow ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
                  <span>{isPlayingFlow ? 'Pausar' : 'Simular Rota'}</span>
                </button>
                <button
                  onClick={() => onSelectStep(Math.min(activePath.steps.length - 1, activeStepIndex + 1))}
                  disabled={activeStepIndex === activePath.steps.length - 1}
                  className="p-1 rounded bg-[#160B0E] hover:bg-[#251015] border border-rose-900/50 text-zinc-300 disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer"
                  title="Próximo passo"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Current Step Detailed Breakdown Card */}
            {currentStep && (
              <div className="p-3 rounded bg-[#070305] border border-rose-950/80 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase ${
                      currentStep.role === 'EXTERNAL_ENTRY' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40' :
                      currentStep.role === 'SENSITIVE_ASSET' ? 'bg-rose-500/30 text-rose-300 border border-rose-500/50 animate-pulse' :
                      'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                    }`}>
                      {currentStep.role === 'EXTERNAL_ENTRY' ? '🚨 Ponto de Entrada Externo (API Inspector)' :
                       currentStep.role === 'SENSITIVE_ASSET' ? '🎯 Ativo Sensível Comprometido (Motor SAST)' :
                       '⚙️ Propagador Lógico (Controller / Handler)'}
                    </span>
                    <span className="text-white font-bold text-xs font-mono">
                      {currentStep.label}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-[10px] text-zinc-400">
                    <span className="flex items-center gap-1">
                      <FileCode className="w-3 h-3 text-rose-400" />
                      <span>{currentStep.file}:{currentStep.line}</span>
                    </span>

                    {onSelectFile && (
                      <button
                        onClick={() => onSelectFile(currentStep.file, currentStep.line)}
                        className="text-sky-400 hover:text-sky-300 hover:underline flex items-center gap-0.5 font-bold cursor-pointer"
                        title="Abrir arquivo no editor"
                      >
                        <span>Abrir Código</span>
                        <ExternalLink className="w-2.5 h-2.5" />
                      </button>
                    )}
                  </div>
                </div>

                <p className="text-[11px] text-zinc-300 leading-relaxed font-sans">
                  {currentStep.description}
                </p>

                {/* Technical snippet or variable info */}
                {currentStep.snippet && (
                  <div className="p-2 rounded bg-[#030102] border border-[#230910] text-[10px] text-zinc-300 font-mono overflow-x-auto">
                    <span className="text-zinc-500 block mb-0.5">// Snippet em {currentStep.file}:{currentStep.line}:</span>
                    <pre className="text-rose-200/90 whitespace-pre-wrap">{currentStep.snippet}</pre>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Bottom Strip: Technical Proof, OWASP/CWE Taxonomy & Remediations */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 pt-1 text-[10px]">
            {/* Box 1: Entry Point Classification */}
            <div className="p-2.5 rounded-lg bg-[#0E070A] border border-rose-950/80 space-y-1">
              <span className="text-zinc-500 block font-bold uppercase text-[9px]">Superfície Externa (API Inspector):</span>
              <div className="text-white font-bold truncate">{activePath.entryEndpoint.path}</div>
              <div className="text-sky-300 font-bold truncate">
                {activePath.entryEndpoint.owaspCategory || 'API1:2023 BOLA'}
              </div>
              <p className="text-zinc-400 text-[9.5px]">Rota pública detectada pelo LinkFinder exposta a invasores sem autenticação suficiente.</p>
              {onNavigateToTab && (
                <button
                  onClick={() => onNavigateToTab('endpoints')}
                  className="text-sky-400 hover:text-sky-300 hover:underline flex items-center gap-1 font-bold pt-1 cursor-pointer"
                >
                  <span>Ver no API Security Inspector</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </button>
              )}
            </div>

            {/* Box 2: Sensitive Target Asset */}
            <div className="p-2.5 rounded-lg bg-[#0E070A] border border-rose-950/80 space-y-1">
              <span className="text-zinc-500 block font-bold uppercase text-[9px]">Ativo de Dados (Motor SAST):</span>
              <div className="text-rose-300 font-bold truncate">{activePath.targetSensitiveData.name}</div>
              <div className="text-amber-300 font-mono text-[9.5px]">
                {activePath.targetSensitiveData.cwe} • {activePath.targetSensitiveData.cweName}
              </div>
              {activePath.targetSensitiveData.matchedSecretMasked && (
                <div className="text-zinc-400 text-[9.5px]">
                  Valor: <code className="text-rose-400">{activePath.targetSensitiveData.matchedSecretMasked}</code>
                </div>
              )}
              {onNavigateToTab && (
                <button
                  onClick={() => onNavigateToTab('scanner')}
                  className="text-rose-400 hover:text-rose-300 hover:underline flex items-center gap-1 font-bold pt-1 cursor-pointer"
                >
                  <span>Ver Achado no Scanner SAST</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </button>
              )}
            </div>

            {/* Box 3: Technical Proof & Mitigation */}
            <div className="p-2.5 rounded-lg bg-[#0E070A] border border-rose-950/80 space-y-1">
              <div className="flex items-center justify-between text-[9px]">
                <span className="text-zinc-500 font-bold uppercase">Prova Técnica do Vetor:</span>
                <div className="flex items-center gap-1">
                  <button
                    onClick={handleCopyProof}
                    className="text-zinc-400 hover:text-white flex items-center gap-0.5 cursor-pointer"
                    title="Copiar prova técnica"
                  >
                    {copiedProof ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedProof ? 'Copiado' : 'Prova'}</span>
                  </button>
                  <span>•</span>
                  <button
                    onClick={handleCopyCurl}
                    className="text-zinc-400 hover:text-white flex items-center gap-0.5 cursor-pointer"
                    title="Copiar comando cURL de teste"
                  >
                    {copiedCurl ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedCurl ? 'cURL OK' : 'cURL'}</span>
                  </button>
                </div>
              </div>
              <p className="text-zinc-300 text-[9.5px] line-clamp-2 leading-relaxed">
                {activePath.attackVectorSummary}
              </p>
              <div className="pt-0.5 border-t border-rose-950/60 text-[9px] text-emerald-300">
                <strong>Remediação:</strong> {activePath.mitigation.slice(0, 90)}…
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
