import React, { useState } from 'react';
import { 
  Globe, 
  X, 
  ArrowRight, 
  Loader2, 
  AlertTriangle, 
  CheckCircle2, 
  ShieldCheck, 
  ExternalLink,
  Code2,
  FileCode,
  Layers,
  Sparkles
} from 'lucide-react';
import { ScannedFile } from '../types';
import { useLanguage } from '../lib/i18nContext';

interface UrlIngestModalProps {
  isOpen: boolean;
  onClose: () => void;
  onIngestSuccess: (files: ScannedFile[], targetUrl: string) => void;
}

export const UrlIngestModal: React.FC<UrlIngestModalProps> = ({
  isOpen,
  onClose,
  onIngestSuccess
}) => {
  const { language } = useLanguage();
  const [targetUrl, setTargetUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [progressStep, setProgressStep] = useState<string | null>(null);

  if (!isOpen) return null;

  const presets = [
    {
      name: 'OWASP Juice Shop (Demo AppSec)',
      url: 'https://demo.owasp-juice.shop',
      desc: 'Aplicação intencionalmente vulnerável para testes de segurança'
    },
    {
      name: 'JSONPlaceholder REST API',
      url: 'https://jsonplaceholder.typicode.com',
      desc: 'API REST pública com endpoints /posts, /comments e /users'
    },
    {
      name: 'GitHub Public API',
      url: 'https://api.github.com',
      desc: 'API REST estruturada com cabeçalhos de segurança e rate limiting'
    },
    {
      name: 'Website Padrão (RFC 2606)',
      url: 'https://example.com',
      desc: 'Website simples para teste rápido de cabeçalhos e estrutura HTML'
    }
  ];

  const handleStartAudit = async (urlToScan?: string) => {
    const rawUrl = urlToScan || targetUrl;
    if (!rawUrl || !rawUrl.trim()) {
      setErrorMessage(language === 'en' ? 'Please provide a valid website or API URL.' : 'Por favor, informe a URL do site ou da API.');
      return;
    }

    let formattedUrl = rawUrl.trim();
    if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
      formattedUrl = 'https://' + formattedUrl;
    }

    setIsLoading(true);
    setErrorMessage(null);
    setProgressStep(language === 'en' ? 'Connecting to target and validating host...' : 'Conectando ao alvo e validando host...');

    try {
      const stepTimer1 = setTimeout(() => {
        setProgressStep(language === 'en' ? 'Fetching security headers (CSP, HSTS, CORS)...' : 'Extraindo cabeçalhos de segurança HTTP...');
      }, 1200);

      const stepTimer2 = setTimeout(() => {
        setProgressStep(language === 'en' ? 'Extracting HTML, scripts & mining API routes...' : 'Analisando HTML e minerando scripts/rotas...');
      }, 2500);

      const response = await fetch('/api/url-ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: formattedUrl })
      });

      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || (language === 'en' ? 'Failed to audit URL.' : 'Falha ao auditar URL.'));
      }

      setProgressStep(language === 'en' ? '✓ Ingestion complete! Loading workspace...' : '✓ Ingestão concluída! Carregando workspace...');

      setTimeout(() => {
        setIsLoading(false);
        onIngestSuccess(data.files, formattedUrl);
        onClose();
      }, 600);
    } catch (err: any) {
      setIsLoading(false);
      setProgressStep(null);
      setErrorMessage(
        err.message || 
        (language === 'en' 
          ? 'Unable to reach the specified URL. Please verify that the target is online and publicly reachable.' 
          : 'Não foi possível alcançar a URL especificada. Verifique se o site está online e acessível publicamente.')
      );
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div 
        data-no-translate="true"
        className="w-full max-w-2xl bg-[#0B0B0E] border border-[#2A2A38] rounded-xl shadow-[0_10px_50px_rgba(0,0,0,0.9)] overflow-hidden flex flex-col"
      >
        {/* Header */}
        <div className="p-5 bg-[#121218] border-b border-[#22222E] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[#FF3E00]/15 border border-[#FF3E00]/40 flex items-center justify-center text-[#FF3E00] shadow-[0_0_15px_rgba(255,62,0,0.25)]">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white uppercase tracking-tight flex items-center gap-2">
                <span>Auditar Site ou API via Link Web</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40 font-bold">
                  URL INGEST
                </span>
              </h3>
              <p className="text-xs text-zinc-400">
                Inicie um projeto de segurança a partir da URL de um site ao vivo, API pública ou documentação
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            disabled={isLoading}
            className="p-1.5 rounded hover:bg-white/10 text-zinc-400 hover:text-white transition-colors cursor-pointer disabled:opacity-50"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-6">
          {/* URL Input Form */}
          <div className="space-y-2">
            <label className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-300 flex items-center justify-between">
              <span>URL do Alvo (Website ou API)</span>
              <span className="text-[10px] text-zinc-500 font-normal">HTTP / HTTPS suportados</span>
            </label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Globe className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
                <input
                  type="url"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !isLoading) {
                      handleStartAudit();
                    }
                  }}
                  placeholder="https://exemplo.com ou https://api.meusite.com"
                  disabled={isLoading}
                  className="w-full pl-9 pr-3 py-2.5 bg-[#060608] border border-[#2D2D3B] focus:border-[#FF3E00] rounded-lg text-sm text-white placeholder-zinc-500 font-mono focus:outline-none transition-colors disabled:opacity-60 shadow-inner"
                />
              </div>

              <button
                id="btn-confirm-url-ingest"
                onClick={() => handleStartAudit()}
                disabled={isLoading || !targetUrl.trim()}
                className="px-5 py-2.5 rounded-lg bg-[#FF3E00] hover:bg-[#E03700] text-white font-mono text-xs font-bold uppercase tracking-wider shadow-[0_0_20px_rgba(255,62,0,0.35)] transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 shrink-0"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Auditando...</span>
                  </>
                ) : (
                  <>
                    <span>Auditar URL</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>

            {/* Error Banner */}
            {errorMessage && (
              <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-rose-200 text-xs flex items-start gap-2.5 animate-in fade-in">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <div className="leading-relaxed">
                  <strong>Erro ao processar: </strong>
                  <span>{errorMessage}</span>
                </div>
              </div>
            )}

            {/* Progress Step Live Indicator */}
            {isLoading && progressStep && (
              <div className="p-3 rounded-lg bg-[#14141E] border border-[#2B2B40] text-cyan-300 text-xs font-mono flex items-center gap-2.5 animate-pulse">
                <Loader2 className="w-4 h-4 text-cyan-400 animate-spin shrink-0" />
                <span>{progressStep}</span>
              </div>
            )}
          </div>

          {/* What happens during audit? */}
          <div className="p-4 rounded-lg bg-[#070709] border border-[#1C1C24] space-y-2">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-300 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-[#00FF41]" />
              <span>O que o SecScan extrai da URL:</span>
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1 text-xs text-zinc-400">
              <div className="flex items-start gap-2">
                <span className="text-[#FF3E00] font-bold">1.</span>
                <span>Cabeçalhos HTTP (CSP, HSTS, CORS, cookies e server info)</span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-[#FF3E00] font-bold">2.</span>
                <span>HTML principal e scripts JS vinculados para SAST</span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-[#FF3E00] font-bold">3.</span>
                <span>Mineração de rotas REST para auditoria no DAST Fuzzer</span>
              </div>
            </div>
          </div>

          {/* Quick Presets for 1-Click Testing */}
          <div className="space-y-2.5">
            <label className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-400 flex items-center justify-between">
              <span>Ou escolha um alvo de teste pronto:</span>
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {presets.map((preset) => (
                <button
                  key={preset.name}
                  onClick={() => {
                    setTargetUrl(preset.url);
                    handleStartAudit(preset.url);
                  }}
                  disabled={isLoading}
                  className="p-3 rounded-lg bg-[#0E0E14] hover:bg-[#181822] border border-[#20202C] hover:border-[#FF3E00]/60 text-left transition-all cursor-pointer group disabled:opacity-50"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white group-hover:text-[#FF3E00] transition-colors">
                      {preset.name}
                    </span>
                    <ExternalLink className="w-3 h-3 text-zinc-500 group-hover:text-white" />
                  </div>
                  <p className="text-[11px] font-mono text-zinc-400 truncate mt-0.5">
                    {preset.url}
                  </p>
                  <p className="text-[10.5px] text-zinc-500 mt-1 leading-tight">
                    {preset.desc}
                  </p>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 bg-[#0E0E14] border-t border-[#1C1C24] flex items-center justify-between text-xs font-mono text-zinc-500">
          <span className="flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-[#00FF41]" />
            <span>Processamento com isolamento seguro & CORS Proxy</span>
          </span>

          <button
            onClick={onClose}
            disabled={isLoading}
            className="px-4 py-1.5 rounded hover:bg-white/10 text-zinc-300 hover:text-white transition-colors cursor-pointer"
          >
            Cancelar
          </button>
        </div>
      </div>
    </div>
  );
};
