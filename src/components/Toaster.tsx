import React, { useState } from 'react';
import { 
  AlertCircle, 
  CheckCircle2, 
  AlertTriangle, 
  Info, 
  X, 
  Copy, 
  Check, 
  ChevronDown, 
  ChevronUp,
  ShieldAlert
} from 'lucide-react';
import { useToast, ToastItem } from '../lib/toastContext';

export const Toaster: React.FC = () => {
  const { toasts, dismiss } = useToast();

  if (!toasts || toasts.length === 0) return null;

  return (
    <div 
      id="secscan-global-toaster"
      aria-live="polite"
      className="fixed bottom-5 right-5 z-[9999] flex flex-col gap-2.5 max-w-md w-full pointer-events-none px-4 sm:px-0"
    >
      {toasts.map(toast => (
        <ToastCard key={toast.id} toast={toast} onDismiss={() => dismiss(toast.id)} />
      ))}
    </div>
  );
};

interface ToastCardProps {
  toast: ToastItem;
  onDismiss: () => void;
}

const ToastCard: React.FC<ToastCardProps> = ({ toast, onDismiss }) => {
  const [copied, setCopied] = useState(false);
  const [showDetails, setShowDetails] = useState(false);

  const handleCopy = () => {
    const textToCopy = [
      toast.title ? `[${toast.title}]` : '',
      toast.message,
      toast.details ? `\n\nDetalhes:\n${toast.details}` : ''
    ].filter(Boolean).join(' ');

    navigator.clipboard.writeText(textToCopy).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      // Fallback
    });
  };

  const getTheme = () => {
    switch (toast.type) {
      case 'error':
        return {
          icon: <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />,
          borderColor: 'border-rose-500/50',
          bgGradient: 'bg-[#12080B]/95',
          titleColor: 'text-rose-200',
          badgeBg: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
          shadow: 'shadow-[0_8px_32px_rgba(244,63,94,0.22)]',
          barColor: 'bg-rose-500',
          defaultTitle: 'Erro Operacional'
        };
      case 'warning':
        return {
          icon: <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />,
          borderColor: 'border-amber-500/50',
          bgGradient: 'bg-[#140F06]/95',
          titleColor: 'text-amber-200',
          badgeBg: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
          shadow: 'shadow-[0_8px_32px_rgba(245,158,11,0.22)]',
          barColor: 'bg-amber-500',
          defaultTitle: 'Atenção'
        };
      case 'success':
        return {
          icon: <CheckCircle2 className="w-5 h-5 text-[#00FF41] shrink-0 mt-0.5" />,
          borderColor: 'border-[#00FF41]/40',
          bgGradient: 'bg-[#061208]/95',
          titleColor: 'text-emerald-200',
          badgeBg: 'bg-[#00FF41]/20 text-[#00FF41] border-[#00FF41]/40',
          shadow: 'shadow-[0_8px_32px_rgba(0,255,65,0.20)]',
          barColor: 'bg-[#00FF41]',
          defaultTitle: 'Sucesso'
        };
      case 'info':
      default:
        return {
          icon: <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />,
          borderColor: 'border-cyan-500/50',
          bgGradient: 'bg-[#061016]/95',
          titleColor: 'text-cyan-200',
          badgeBg: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
          shadow: 'shadow-[0_8px_32px_rgba(6,182,212,0.20)]',
          barColor: 'bg-cyan-500',
          defaultTitle: 'Informação'
        };
    }
  };

  const theme = getTheme();
  const displayTitle = toast.title || theme.defaultTitle;

  return (
    <div 
      className={`pointer-events-auto relative overflow-hidden rounded-xl border ${theme.borderColor} ${theme.bgGradient} backdrop-blur-md ${theme.shadow} p-4 transition-all duration-200 animate-in fade-in slide-in-from-bottom-3 flex flex-col gap-2`}
      role="alert"
    >
      {/* Top Header Row */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2.5 min-w-0">
          {theme.icon}
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className={`text-xs font-mono font-bold uppercase tracking-wider ${theme.titleColor}`}>
                {displayTitle}
              </span>
              <span className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border ${theme.badgeBg}`}>
                {toast.type.toUpperCase()}
              </span>
            </div>
            <p className="text-xs text-zinc-300 mt-0.5 leading-relaxed break-words font-sans">
              {toast.message}
            </p>
          </div>
        </div>

        {/* Close Button */}
        <button
          onClick={onDismiss}
          className="p-1 rounded-md text-zinc-400 hover:text-white hover:bg-white/10 transition-colors cursor-pointer shrink-0"
          title="Fechar notificação"
          aria-label="Fechar"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Expandable Details for stack traces or error logs */}
      {toast.details && (
        <div className="pt-1">
          <button
            onClick={() => setShowDetails(prev => !prev)}
            className="flex items-center gap-1.5 text-[11px] font-mono text-zinc-400 hover:text-zinc-200 transition-colors cursor-pointer"
          >
            {showDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            <span>{showDetails ? 'Ocultar detalhes técnicos' : 'Ver detalhes técnicos'}</span>
          </button>

          {showDetails && (
            <pre className="mt-2 p-2.5 bg-black/70 border border-white/10 rounded-lg text-[10px] font-mono text-zinc-300 overflow-x-auto max-h-36 whitespace-pre-wrap leading-tight shadow-inner">
              {toast.details}
            </pre>
          )}
        </div>
      )}

      {/* Action Footer for Error Toasts: Copy details */}
      <div className="flex items-center justify-between pt-1 border-t border-white/5 text-[11px] font-mono">
        <span className="text-[10px] text-zinc-500">
          {new Date(toast.timestamp).toLocaleTimeString()}
        </span>

        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 text-zinc-400 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 px-2.5 py-1 rounded-md transition-colors cursor-pointer text-[10px]"
          title="Copiar mensagem e detalhes para a área de transferência"
        >
          {copied ? (
            <>
              <Check className="w-3 h-3 text-[#00FF41]" />
              <span className="text-[#00FF41] font-bold">Copiado!</span>
            </>
          ) : (
            <>
              <Copy className="w-3 h-3 text-zinc-400" />
              <span>Copiar Erro</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
