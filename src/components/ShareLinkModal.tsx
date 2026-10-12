import React, { useState } from 'react';
import { 
  X, 
  Copy, 
  Check, 
  Share2, 
  ExternalLink, 
  Globe, 
  ShieldCheck, 
  Send, 
  MessageSquare, 
  Twitter, 
  Linkedin,
  Sparkles,
  Image as ImageIcon
} from 'lucide-react';
import { useLanguage } from '../lib/i18nContext';

interface ShareLinkModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ShareLinkModal: React.FC<ShareLinkModalProps> = ({ isOpen, onClose }) => {
  const { language } = useLanguage();
  const isPt = language === 'pt';
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const currentUrl = typeof window !== 'undefined' ? window.location.href : 'https://ais-pre-u2khb54vpo5u3jjg3wivmn-422976694894.us-east5.run.app';
  const displayHost = typeof window !== 'undefined' ? window.location.host : 'secscan.app';
  
  const shareTitle = 'SecScan AppSec Suite - Advanced SAST, Secret Matrix & DataFlow Platform';
  const shareDescription = isPt 
    ? 'Plataforma avançada de cibersegurança com Threat Heatmap AlienVault OTX, SAST, DAST, SCA e análise de código em tempo real.'
    : 'Advanced AppSec & Cyber Threat Intelligence platform with AlienVault OTX Heatmap, SAST, DAST, and SCA.';

  const handleCopy = () => {
    navigator.clipboard.writeText(currentUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  const whatsappUrl = `https://api.whatsapp.com/send?text=${encodeURIComponent(`${shareTitle}\n\n${currentUrl}`)}`;
  const telegramUrl = `https://t.me/share/url?url=${encodeURIComponent(currentUrl)}&text=${encodeURIComponent(shareTitle)}`;
  const twitterUrl = `https://twitter.com/intent/tweet?url=${encodeURIComponent(currentUrl)}&text=${encodeURIComponent(shareTitle)}`;
  const linkedinUrl = `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(currentUrl)}`;

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200"
      onClick={onClose}
    >
      <div 
        className="relative w-full max-w-xl bg-[#090A0F] border border-[#2A2B36] rounded-xl shadow-2xl p-5 sm:p-6 overflow-hidden text-zinc-200 font-sans"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Glow ambient background effect */}
        <div className="absolute top-0 right-0 w-64 h-64 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 w-64 h-64 bg-sky-500/10 rounded-full blur-3xl pointer-events-none" />

        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-[#1E1F29] relative z-10">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-[#00FF41]">
              <Share2 className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-black text-white tracking-tight flex items-center gap-2">
                <span>{isPt ? 'Compartilhar Link do Site' : 'Share Website Link'}</span>
                <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-[#00FF41]">
                  OG:IMAGE ACTIVE
                </span>
              </h3>
              <p className="text-xs text-zinc-400 font-mono mt-0.5">
                {isPt 
                  ? 'Pré-visualização do card com imagem thumbnail oficial ao compartilhar'
                  : 'Social card thumbnail preview when sharing link on networks'}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-md text-zinc-400 hover:text-white hover:bg-white/10 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Social Card Preview Frame */}
        <div className="mt-4 relative z-10">
          <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400 mb-2">
            <span className="flex items-center gap-1.5 font-bold text-zinc-300">
              <ImageIcon className="w-3.5 h-3.5 text-emerald-400" />
              <span>{isPt ? 'Card Gerado para WhatsApp, LinkedIn, Discord & X:' : 'Card Preview for WhatsApp, LinkedIn, Discord & X:'}</span>
            </span>
            <span className="text-[10px] text-zinc-500">1280 × 720 (16:9)</span>
          </div>

          <div className="rounded-lg border border-[#2C303E] bg-[#0E1117] overflow-hidden shadow-xl transition-all hover:border-[#3E4559]">
            {/* Generated Image Thumbnail */}
            <div className="relative aspect-[16/9] w-full overflow-hidden bg-black">
              <img 
                src="/og-image.jpg"
                alt="SecScan AppSec Suite Social Card Thumbnail"
                className="w-full h-full object-cover"
                referrerPolicy="no-referrer"
              />
              <div className="absolute top-2.5 left-2.5 px-2 py-0.5 rounded bg-black/80 backdrop-blur-md border border-white/20 text-[10px] font-mono text-[#00FF41] font-bold flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#00FF41] animate-ping" />
                <span>SecScan Social Thumbnail</span>
              </div>
            </div>

            {/* Social Card Text Block */}
            <div className="p-3.5 space-y-1 bg-[#13161F]">
              <div className="text-[10px] font-mono text-emerald-400 uppercase tracking-wider font-bold truncate">
                {displayHost}
              </div>
              <h4 className="text-sm font-bold text-white line-clamp-1 leading-snug">
                {shareTitle}
              </h4>
              <p className="text-xs text-zinc-400 line-clamp-2 leading-relaxed">
                {shareDescription}
              </p>
            </div>
          </div>
        </div>

        {/* Copy Link Input Bar */}
        <div className="mt-4 relative z-10">
          <label className="block text-[11px] font-mono text-zinc-400 mb-1 font-bold">
            {isPt ? 'URL do Link para Envio:' : 'Shareable URL:'}
          </label>
          <div className="flex items-center gap-2">
            <div className="flex-1 px-3 py-2 rounded bg-black/70 border border-[#2A2B36] text-xs font-mono text-zinc-300 truncate select-all">
              {currentUrl}
            </div>
            <button
              type="button"
              onClick={handleCopy}
              className={`h-9 px-3.5 rounded font-mono text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer shrink-0 ${
                copied 
                  ? 'bg-emerald-500 text-black font-black' 
                  : 'bg-[#00FF41] hover:bg-[#00DD38] text-black font-black shadow-lg shadow-emerald-500/10'
              }`}
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5" />
                  <span>{isPt ? 'Copiado!' : 'Copied!'}</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>{isPt ? 'Copiar Link' : 'Copy Link'}</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Quick Social Buttons */}
        <div className="mt-4 pt-4 border-t border-[#1E1F29] relative z-10">
          <div className="text-[10px] font-mono text-zinc-500 uppercase font-bold tracking-wider mb-2.5">
            {isPt ? 'Compartilhar Diretamente:' : 'Share Directly:'}
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <a
              href={whatsappUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="px-3 py-2 rounded bg-[#101F18] hover:bg-[#162C22] border border-emerald-600/30 text-emerald-300 text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-colors"
            >
              <MessageSquare className="w-3.5 h-3.5 text-emerald-400" />
              <span>WhatsApp</span>
            </a>
            <a
              href={telegramUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="px-3 py-2 rounded bg-[#0E1A29] hover:bg-[#14263D] border border-sky-600/30 text-sky-300 text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-colors"
            >
              <Send className="w-3.5 h-3.5 text-sky-400" />
              <span>Telegram</span>
            </a>
            <a
              href={linkedinUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="px-3 py-2 rounded bg-[#101B2E] hover:bg-[#162742] border border-blue-600/30 text-blue-300 text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-colors"
            >
              <Linkedin className="w-3.5 h-3.5 text-blue-400" />
              <span>LinkedIn</span>
            </a>
            <a
              href={twitterUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="px-3 py-2 rounded bg-[#141416] hover:bg-[#202024] border border-zinc-700/40 text-zinc-200 text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-colors"
            >
              <Twitter className="w-3.5 h-3.5 text-zinc-300" />
              <span>Twitter / X</span>
            </a>
          </div>
        </div>

        {/* Footer Technical Metadata Indicator */}
        <div className="mt-4 pt-3 border-t border-[#161720] flex flex-wrap items-center justify-between gap-2 text-[10px] font-mono text-zinc-500 relative z-10">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" />
            <span>OpenGraph & Twitter Cards: <code>og:image</code> &amp; <code>twitter:image</code></span>
          </div>
          <span className="text-zinc-600">/public/og-image.jpg</span>
        </div>
      </div>
    </div>
  );
};
