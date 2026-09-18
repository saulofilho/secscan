import React from 'react';
import { 
  ShieldAlert, 
  Trash2, 
  Play, 
  Sparkles, 
  Layers, 
  X,
  FileCode2,
  Lock,
  ArrowRight
} from 'lucide-react';

interface WelcomeWorkspaceModalProps {
  isOpen: boolean;
  onExploreWithMock: () => void;
  onStartCleanWorkspace: () => void;
  onClose?: () => void;
}

export const WelcomeWorkspaceModal: React.FC<WelcomeWorkspaceModalProps> = ({
  isOpen,
  onExploreWithMock,
  onStartCleanWorkspace,
  onClose
}) => {
  if (!isOpen) return null;

  return (
    <div 
      id="welcome-workspace-modal-overlay"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md p-3 sm:p-4 animate-in fade-in duration-200"
    >
      <div 
        id="welcome-workspace-modal-container"
        className="relative w-full max-w-xl max-h-[92vh] flex flex-col bg-[#0A0A0A] border border-[#2A2A2A] shadow-[0_0_50px_rgba(0,0,0,0.9),0_0_25px_rgba(255,62,0,0.15)] rounded-md overflow-hidden font-sans"
      >
        {/* Top accent line */}
        <div className="h-1 w-full shrink-0 bg-gradient-to-r from-[#FF3E00] via-[#FF7A00] to-[#00FF41]" />

        {/* Close Button */}
        {onClose && (
          <button
            id="btn-close-welcome-modal"
            type="button"
            onClick={onClose}
            className="absolute top-3 right-3 p-1.5 text-zinc-400 hover:text-white bg-zinc-900/80 hover:bg-zinc-800 border border-zinc-700/60 rounded transition-colors cursor-pointer z-10"
            title="Fechar (manter modo demonstrativo)"
            aria-label="Fechar"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}

        {/* Scrollable Container (Target Selector) */}
        <div className="p-4 sm:p-5 overflow-y-auto max-h-[calc(92vh-4px)] space-y-3.5 sm:space-y-4">
          {/* Header & Badges */}
          <div className="space-y-1.5 pr-6">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/30 font-mono text-[9px] font-black uppercase tracking-wider">
                <ShieldAlert className="w-2.5 h-2.5" />
                SECSCAN SAST
              </span>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 font-mono text-[9px]">
                <Sparkles className="w-2.5 h-2.5 text-[#00FF41]" />
                INICIALIZAÇÃO
              </span>
            </div>

            <h1 className="text-lg sm:text-xl font-black uppercase tracking-tight text-white flex items-center gap-2">
              <span>Bem-vindo à Plataforma</span>
            </h1>

            <p className="text-[11px] sm:text-xs text-zinc-300 leading-relaxed">
              O <strong className="text-white font-bold">SecScan</strong> analisa segurança de código (<strong className="text-[#FF3E00]">SAST</strong>), detecta segredos via entropia de Shannon, rastreia fluxo de dados (DataFlow/Taint) e integra conformidade e threat feeds OSINT.
            </p>
          </div>

          {/* Compact Feature Badges / Highlights */}
          <div className="grid grid-cols-3 gap-2">
            <div className="p-2 bg-[#121212] border border-[#222] rounded flex flex-col gap-0.5">
              <div className="flex items-center gap-1 text-[#FF3E00] text-[10px] font-bold font-mono">
                <FileCode2 className="w-3 h-3 shrink-0" />
                <span className="truncate">SAST & Secrets</span>
              </div>
              <p className="text-[9.5px] text-zinc-400 leading-tight">
                Tokens AWS, Stripe, JWT e credenciais.
              </p>
            </div>

            <div className="p-2 bg-[#121212] border border-[#222] rounded flex flex-col gap-0.5">
              <div className="flex items-center gap-1 text-[#00FF41] text-[10px] font-bold font-mono">
                <Layers className="w-3 h-3 shrink-0" />
                <span className="truncate">Taint Flow</span>
              </div>
              <p className="text-[9.5px] text-zinc-400 leading-tight">
                Origens inseguras até sinks críticos.
              </p>
            </div>

            <div className="p-2 bg-[#121212] border border-[#222] rounded flex flex-col gap-0.5">
              <div className="flex items-center gap-1 text-[#00F0FF] text-[10px] font-bold font-mono">
                <Lock className="w-3 h-3 shrink-0" />
                <span className="truncate">Compliance</span>
              </div>
              <p className="text-[9.5px] text-zinc-400 leading-tight">
                SOC 2, NIST, OWASP e feeds OSINT.
              </p>
            </div>
          </div>

          {/* Question / Choice Prompt */}
          <div className="px-3 py-2 bg-[#141414] border border-zinc-800 rounded text-center sm:text-left">
            <p className="text-[11px] text-zinc-300">
              Escolha como deseja iniciar: explore com arquivos vulneráveis de teste ou limpe o mock para analisar seu próprio código.
            </p>
          </div>

          {/* Action Buttons: prominently visible */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-0.5">
            {/* Option A: Explore with mock */}
            <button
              id="btn-welcome-explore-mock"
              type="button"
              onClick={onExploreWithMock}
              className="w-full group p-3 rounded bg-[#1A1A1A] hover:bg-[#222] border border-[#333] hover:border-[#FF3E00]/60 text-left transition-all cursor-pointer flex flex-col justify-between gap-1.5"
            >
              <div className="flex items-center justify-between w-full">
                <span className="inline-flex items-center gap-1.5 text-xs font-bold font-mono uppercase tracking-wider text-white group-hover:text-[#FF3E00] transition-colors">
                  <Play className="w-3 h-3 fill-current text-[#FF3E00]" />
                  Explorar com Mock
                </span>
                <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                  Demo
                </span>
              </div>
              <p className="text-[10px] text-zinc-400 leading-snug">
                Carrega arquivos de exemplo com alertas, gráficos e dados prontos.
              </p>
              <div className="flex items-center gap-1 text-[10px] font-mono font-bold text-[#FF3E00] pt-0.5">
                <span>Acessar demonstração</span>
                <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
              </div>
            </button>

            {/* Option B: Clean workspace and start from zero */}
            <button
              id="btn-welcome-clean-workspace"
              type="button"
              onClick={onStartCleanWorkspace}
              className="w-full group p-3 rounded bg-[#160a08] hover:bg-[#220e0a] border border-[#441a14] hover:border-rose-500/70 text-left transition-all cursor-pointer flex flex-col justify-between gap-1.5"
            >
              <div className="flex items-center justify-between w-full">
                <span className="inline-flex items-center gap-1.5 text-xs font-bold font-mono uppercase tracking-wider text-rose-300 group-hover:text-rose-200 transition-colors">
                  <Trash2 className="w-3 h-3 text-rose-400" />
                  Limpar Mock e Zerar
                </span>
                <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-rose-950/70 text-rose-300 border border-rose-800/60">
                  Limpo
                </span>
              </div>
              <p className="text-[10px] text-zinc-400 leading-snug">
                Remove os arquivos fictícios para você colar código ou subir arquivos.
              </p>
              <div className="flex items-center gap-1 text-[10px] font-mono font-bold text-rose-400 pt-0.5">
                <span>Começar zerado</span>
                <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
              </div>
            </button>
          </div>

          {/* Footer note */}
          <div className="text-center pt-1 border-t border-zinc-800/80">
            <span className="text-[9.5px] font-mono text-zinc-500">
              Você pode restaurar o mock quando quiser com o atalho <kbd className="px-1 py-0.5 bg-zinc-800 text-zinc-300 border border-zinc-700 text-[8.5px] rounded">⌘B</kbd> / <kbd className="px-1 py-0.5 bg-zinc-800 text-zinc-300 border border-zinc-700 text-[8.5px] rounded">Ctrl+B</kbd>.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
