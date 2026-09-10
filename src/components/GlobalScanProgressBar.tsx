import React, { useState, useEffect } from 'react';
import { 
  Loader2, 
  CheckCircle2, 
  ShieldAlert, 
  FileCode, 
  Clock, 
  ChevronUp, 
  ChevronDown, 
  Activity,
  Layers,
  X
} from 'lucide-react';
import { ScanProgress, ScanPhase } from '../types';

interface GlobalScanProgressBarProps {
  isScanning: boolean;
  progress: ScanProgress | null;
  onCancelScan?: () => void;
  onTriggerScan?: () => void;
}

export const GlobalScanProgressBar: React.FC<GlobalScanProgressBarProps> = ({
  isScanning,
  progress,
  onTriggerScan
}) => {
  const [isCompleted, setIsCompleted] = useState(false);
  const [isVisible, setIsVisible] = useState(false);
  const [isDetailsExpanded, setIsDetailsExpanded] = useState(true);
  const [displayPercentage, setDisplayPercentage] = useState(0);

  const percentage = progress ? Math.max(0, Math.min(100, progress.percentage)) : 0;

  // Synchronize smooth percentage display
  useEffect(() => {
    if (isScanning) {
      setIsVisible(true);
      setIsCompleted(false);
      setDisplayPercentage(percentage);
    } else if (progress && progress.percentage >= 100) {
      setDisplayPercentage(100);
      setIsCompleted(true);
      setIsVisible(true);

      // Auto dismiss completed banner after 3 seconds
      const timer = setTimeout(() => {
        setIsVisible(false);
        setIsCompleted(false);
      }, 3000);

      return () => clearTimeout(timer);
    } else {
      setIsVisible(false);
    }
  }, [isScanning, percentage, progress]);

  // Don't render anything if not scanning and not in completion state
  if (!isVisible && !isScanning) {
    return null;
  }

  const phaseConfig: Record<ScanPhase, { label: string; bg: string; text: string; border: string }> = {
    INITIALIZING: {
      label: 'Inicializando SAST',
      bg: 'bg-zinc-800/60',
      text: 'text-zinc-300',
      border: 'border-zinc-700'
    },
    SECRETS_SCAN: {
      label: 'Segredos & Entropia',
      bg: 'bg-amber-500/15',
      text: 'text-amber-300',
      border: 'border-amber-500/30'
    },
    LINK_FINDER: {
      label: 'LinkFinder APIs',
      bg: 'bg-purple-500/15',
      text: 'text-purple-300',
      border: 'border-purple-500/30'
    },
    JS_MINER: {
      label: 'JS-Miner Assets',
      bg: 'bg-blue-500/15',
      text: 'text-blue-300',
      border: 'border-blue-500/30'
    },
    DATA_FLOW: {
      label: 'Grafo D3 & Taint Flow',
      bg: 'bg-indigo-500/15',
      text: 'text-indigo-300',
      border: 'border-indigo-500/30'
    },
    FINALIZING: {
      label: 'Consolidando Score',
      bg: 'bg-cyan-500/15',
      text: 'text-cyan-300',
      border: 'border-cyan-500/30'
    },
    COMPLETED: {
      label: 'Varredura Concluída',
      bg: 'bg-emerald-500/15',
      text: 'text-emerald-300',
      border: 'border-emerald-500/30'
    }
  };

  const activePhase = progress?.phase || (isCompleted ? 'COMPLETED' : 'INITIALIZING');
  const currentPhaseStyle = phaseConfig[activePhase] || phaseConfig.INITIALIZING;

  return (
    <div 
      id="global-scan-progress-container"
      className="fixed top-0 left-0 right-0 z-50 pointer-events-none transition-all duration-300"
      role="progressbar"
      aria-valuenow={displayPercentage}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label="Progresso da Análise de Segurança SAST"
    >
      {/* 1. Global High-Precision Progress Bar Line */}
      <div className="w-full h-1 sm:h-1.5 bg-black/80 backdrop-blur-md relative overflow-hidden shadow-[0_2px_10px_rgba(0,0,0,0.5)]">
        {/* Track Line Fill */}
        <div 
          id="global-scan-progress-track"
          className={`h-full transition-all duration-200 ease-out relative ${
            isCompleted 
              ? 'bg-gradient-to-r from-emerald-500 via-teal-400 to-green-400 shadow-[0_0_12px_rgba(16,185,129,0.8)]' 
              : (progress?.findingsFoundCount ?? 0) > 0
              ? 'bg-gradient-to-r from-[#FF3E00] via-[#FF7A00] to-[#00F0FF] shadow-[0_0_12px_rgba(255,62,0,0.6)]'
              : 'bg-gradient-to-r from-[#3366FF] via-[#00F0FF] to-[#00FF41] shadow-[0_0_12px_rgba(0,240,255,0.7)]'
          }`}
          style={{ width: `${Math.max(2, Math.min(100, displayPercentage))}%` }}
        >
          {/* Glowing Leader Head */}
          <div className="absolute right-0 top-1/2 -translate-y-1/2 w-3 h-3 sm:w-4 sm:h-4 rounded-full bg-white blur-[1.5px] opacity-90 shadow-[0_0_8px_#FFFFFF]" />

          {/* Animated Light Shimmer */}
          {isScanning && (
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-[pulse_1.5s_cubic-bezier(0.4,0,0.6,1)_infinite]" />
          )}
        </div>
      </div>

      {/* 2. Global Cyber Telemetry Status Strip / HUD Card */}
      <div className="max-w-7xl mx-auto px-2 sm:px-6 lg:px-8 mt-1">
        <div 
          id="global-scan-progress-hud"
          className={`pointer-events-auto rounded-lg border transition-all duration-200 shadow-2xl backdrop-blur-md ${
            isCompleted
              ? 'bg-[#08150E]/95 border-emerald-500/40 text-emerald-200 shadow-emerald-950/40'
              : 'bg-[#0A0A0A]/95 border-[#2A2A2A] text-zinc-200 shadow-black/80'
          }`}
        >
          <div className="px-3 py-2 sm:py-2.5 flex flex-wrap items-center justify-between gap-2.5">
            {/* Left: Radar / Indicator + Status Label + Percentage */}
            <div className="flex items-center gap-2.5 shrink-0">
              <div className="flex items-center justify-center">
                {isCompleted ? (
                  <div className="w-6 h-6 rounded-full bg-emerald-500/20 border border-emerald-400/40 flex items-center justify-center text-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.4)]">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  </div>
                ) : (
                  <div className="w-6 h-6 rounded-full bg-sky-500/20 border border-sky-400/40 flex items-center justify-center text-sky-400 shadow-[0_0_8px_rgba(56,189,248,0.4)]">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  </div>
                )}
              </div>

              <div>
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] sm:text-[11px] font-mono font-bold uppercase tracking-wider ${
                    isCompleted ? 'text-emerald-400' : 'text-sky-400'
                  }`}>
                    {isCompleted ? 'Varredura Concluída' : 'Análise Estática em Execução'}
                  </span>

                  {/* Percentage Chip */}
                  <span 
                    id="global-scan-progress-percentage"
                    className={`px-1.5 py-0.5 rounded text-[11px] sm:text-xs font-mono font-black tracking-tight ${
                      isCompleted 
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        : 'bg-white/10 text-white border border-white/20'
                    }`}
                  >
                    {displayPercentage}%
                  </span>
                </div>

                {/* Subtitle / Micro status */}
                <div className="text-[10.5px] font-mono text-zinc-400 flex items-center gap-1.5 mt-0.5">
                  <span>
                    {isCompleted
                      ? `${progress?.totalFiles ?? 0} arquivos verificados com sucesso`
                      : progress?.currentFileName 
                        ? `Arquivo ${progress.currentFileIndex} de ${progress.totalFiles}` 
                        : 'Preparando workspace para análise profunda...'}
                  </span>
                </div>
              </div>
            </div>

            {/* Center: File Name & Phase details (Expandable or desktop visible) */}
            {isDetailsExpanded && (
              <div className="flex-1 min-w-[200px] max-w-xl mx-auto flex items-center gap-2 px-2 py-1 rounded bg-[#111]/80 border border-[#222]">
                {/* Phase Badge */}
                <span className={`px-2 py-0.5 rounded text-[9.5px] font-mono font-bold uppercase tracking-wider shrink-0 border ${currentPhaseStyle.bg} ${currentPhaseStyle.text} ${currentPhaseStyle.border}`}>
                  {currentPhaseStyle.label}
                </span>

                {/* Current File Path */}
                <div className="flex items-center gap-1.5 min-w-0 flex-1">
                  <FileCode className="w-3 h-3 text-zinc-500 shrink-0" />
                  <span 
                    id="global-scan-current-file"
                    className="text-[11px] font-mono text-zinc-300 truncate"
                    title={progress?.currentFilePath || progress?.currentFileName || ''}
                  >
                    {progress?.currentFilePath || progress?.currentFileName || (isCompleted ? 'Todos os módulos verificados' : 'Carregando arquivos...')}
                  </span>
                </div>
              </div>
            )}

            {/* Right: Telemetry metrics (Findings, Time, Controls) */}
            <div className="flex items-center gap-2 sm:gap-3 shrink-0 ml-auto sm:ml-0">
              {/* Findings detected so far */}
              <div 
                id="global-scan-findings-badge"
                className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10.5px] font-mono border ${
                  (progress?.findingsFoundCount ?? 0) > 0
                    ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                    : 'bg-zinc-800/60 border-zinc-700 text-zinc-300'
                }`}
                title="Achados e potenciais vulnerabilidades identificados em tempo real"
              >
                <ShieldAlert className="w-3 h-3 text-amber-400" />
                <span className="font-bold">{progress?.findingsFoundCount ?? 0}</span>
                <span className="hidden sm:inline opacity-80">achados</span>
              </div>

              {/* Elapsed Time */}
              {progress?.elapsedMs !== undefined && progress.elapsedMs > 0 && (
                <div 
                  className="hidden md:flex items-center gap-1 text-[10px] font-mono text-zinc-400"
                  title="Tempo decorrido da varredura"
                >
                  <Clock className="w-3 h-3 text-zinc-500" />
                  <span>{progress.elapsedMs}ms</span>
                </div>
              )}

              {/* Toggle Details Chevron */}
              <button
                type="button"
                id="btn-toggle-global-progress-details"
                onClick={() => setIsDetailsExpanded(prev => !prev)}
                className="p-1 rounded hover:bg-white/10 text-zinc-400 hover:text-white transition-colors cursor-pointer border border-transparent hover:border-zinc-700"
                title={isDetailsExpanded ? 'Recolher detalhes' : 'Expandir telemetria completa'}
                aria-expanded={isDetailsExpanded}
              >
                {isDetailsExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>

              {/* Close/Dismiss Button */}
              {isCompleted && (
                <button
                  type="button"
                  id="btn-dismiss-global-progress"
                  onClick={() => setIsVisible(false)}
                  className="p-1 rounded hover:bg-emerald-500/20 text-emerald-400 hover:text-emerald-200 transition-colors cursor-pointer"
                  title="Fechar notificação"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
