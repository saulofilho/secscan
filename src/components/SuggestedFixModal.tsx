import React, { useEffect, useState } from 'react';
import {
  Sparkles,
  X,
  Copy,
  Check,
  Zap,
  RotateCw,
  ShieldCheck,
  KeyRound,
  CheckCircle2,
  FileCode,
  Info
} from 'lucide-react';
import { ScanFinding, SuggestedFixResult } from '../types';
import { requestSuggestedFix } from '../lib/suggestedFixService';

interface SuggestedFixModalProps {
  isOpen: boolean;
  onClose: () => void;
  finding: ScanFinding | null;
  fileContent?: string;
  onApplyFix?: (finding: ScanFinding, newSnippet: string) => void;
}

export const SuggestedFixModal: React.FC<SuggestedFixModalProps> = ({
  isOpen,
  onClose,
  finding,
  fileContent,
  onApplyFix
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<SuggestedFixResult | null>(null);
  const [activeTab, setActiveTab] = useState<'diff' | 'code' | 'env' | 'steps'>('diff');
  const [copiedSnippet, setCopiedSnippet] = useState(false);
  const [copiedEnv, setCopiedEnv] = useState(false);
  const [applied, setApplied] = useState(false);

  useEffect(() => {
    if (isOpen && finding) {
      handleGenerate(finding);
    } else {
      setResult(null);
      setApplied(false);
    }
  }, [isOpen, finding?.id]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const handleGenerate = async (targetFinding: ScanFinding) => {
    setIsLoading(true);
    setApplied(false);
    try {
      const fixResult = await requestSuggestedFix(targetFinding, fileContent);
      setResult(fixResult);
    } catch (err) {
      console.error('Erro ao gerar Suggested Fix via modal:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = (text: string, type: 'snippet' | 'env') => {
    navigator.clipboard.writeText(text);
    if (type === 'snippet') {
      setCopiedSnippet(true);
      setTimeout(() => setCopiedSnippet(false), 2000);
    } else {
      setCopiedEnv(true);
      setTimeout(() => setCopiedEnv(false), 2000);
    }
  };

  const handleApply = () => {
    if (!result || !finding || !onApplyFix) return;
    onApplyFix(finding, result.replacementSnippet);
    setApplied(true);
  };

  if (!isOpen || !finding) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
      <div
        className="w-full max-w-4xl bg-[#080808] border border-[#00FF41]/40 shadow-[0_0_30px_rgba(0,255,65,0.15)] flex flex-col max-h-[90vh] overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="p-4 sm:p-5 bg-[#0C120C] border-b border-[#00FF41]/25 flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-[#00FF41]/15 text-[#00FF41] border border-[#00FF41]/40">
              <Sparkles className="w-5 h-5 text-[#00FF41] animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-mono text-base font-black text-white uppercase tracking-wider">
                  AI Suggested Fix
                </h3>
                <span className="px-2 py-0.5 bg-[#00FF41]/20 text-[#00FF41] text-[10px] font-mono font-bold">
                  GEMINI 3.1 PRO / FLASH
                </span>
              </div>
              <p className="font-mono text-xs text-[#88CC99] mt-0.5">
                Substituição segura gerada com inteligência artificial para {finding.ruleName}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => handleGenerate(finding)}
              disabled={isLoading}
              className="px-3 py-1.5 bg-[#142614] hover:bg-[#1E3A1E] text-[#00FF41] hover:text-white border border-[#00FF41]/40 text-xs font-mono font-bold inline-flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
              title="Regerar com IA"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">Regerar</span>
            </button>

            <button
              type="button"
              onClick={onClose}
              className="p-1.5 text-[#888] hover:text-white border border-[#222] hover:border-white bg-[#111] transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Target Finding Info Strip */}
        <div className="px-4 sm:px-5 py-2.5 bg-[#050A05] border-b border-[#142614] flex flex-wrap items-center justify-between gap-2 text-xs font-mono shrink-0">
          <div className="flex items-center gap-2.5">
            <span className={`px-2 py-0.5 text-[9px] font-black uppercase ${
              finding.severity === 'CRITICAL' ? 'bg-[#FF3E00] text-white' : 'bg-[#FF7A00] text-black font-bold'
            }`}>
              {finding.severity}
            </span>
            <span className="text-white font-bold">{finding.file}:{finding.line}</span>
            <span className="text-[#666] hidden sm:inline">•</span>
            <span className="text-[#AAA] font-mono text-[11px] bg-[#000] px-2 py-0.5 border border-[#222]">
              {finding.maskedSecret}
            </span>
          </div>

          {result && (
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-[#00FF41] bg-[#00FF41]/10 px-2 py-0.5 border border-[#00FF41]/30 font-bold">
                {result.securePattern}
              </span>
            </div>
          )}
        </div>

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto space-y-4 font-mono text-xs flex-1">
          {isLoading && (
            <div className="py-16 text-center space-y-4">
              <div className="w-10 h-10 border-3 border-[#00FF41] border-t-transparent rounded-full animate-spin mx-auto" />
              <p className="text-white font-bold text-sm tracking-wide">
                Consultando Gemini AI &amp; Motor de AppSec...
              </p>
              <p className="text-xs text-[#88CC99] max-w-md mx-auto">
                Analisando a tipologia da falha ({finding.ruleName}) e o contexto do código em {finding.file} para sintetizar o patch seguro.
              </p>
            </div>
          )}

          {!isLoading && result && (
            <>
              {/* Explanation card */}
              <div className="p-4 bg-[#0A180A] border border-[#00FF41]/30 text-xs text-[#D0EED0] leading-relaxed flex items-start gap-3">
                <Info className="w-4 h-4 text-[#00FF41] shrink-0 mt-0.5" />
                <div className="space-y-1 flex-1">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-bold text-white text-sm">{result.vulnerabilityType}</span>
                    <span className="text-[10px] text-[#AACCBB] bg-[#142614] px-2 py-0.5 border border-[#00FF41]/30">
                      {result.cweOwaspReference}
                    </span>
                  </div>
                  <p>{result.explanation}</p>
                </div>
              </div>

              {/* Tabs */}
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#142614] pb-2">
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => setActiveTab('diff')}
                    className={`px-3 py-1.5 text-xs font-bold uppercase tracking-wider transition-colors cursor-pointer border ${
                      activeTab === 'diff'
                        ? 'bg-[#00FF41] text-black border-[#00FF41]'
                        : 'bg-[#0A180A] text-[#88CC99] border-[#00FF41]/30 hover:text-white'
                    }`}
                  >
                    Diff Antes / Depois
                  </button>

                  <button
                    type="button"
                    onClick={() => setActiveTab('code')}
                    className={`px-3 py-1.5 text-xs font-bold uppercase tracking-wider transition-colors cursor-pointer border ${
                      activeTab === 'code'
                        ? 'bg-[#00FF41] text-black border-[#00FF41]'
                        : 'bg-[#0A180A] text-[#88CC99] border-[#00FF41]/30 hover:text-white'
                    }`}
                  >
                    Código de Substituição
                  </button>

                  {result.envConfig && (
                    <button
                      type="button"
                      onClick={() => setActiveTab('env')}
                      className={`px-3 py-1.5 text-xs font-bold uppercase tracking-wider transition-colors cursor-pointer border flex items-center gap-1.5 ${
                        activeTab === 'env'
                          ? 'bg-[#00FF41] text-black border-[#00FF41]'
                          : 'bg-[#0A180A] text-[#88CC99] border-[#00FF41]/30 hover:text-white'
                      }`}
                    >
                      <KeyRound className="w-3.5 h-3.5" />
                      <span>Configuração .env</span>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => setActiveTab('steps')}
                    className={`px-3 py-1.5 text-xs font-bold uppercase tracking-wider transition-colors cursor-pointer border ${
                      activeTab === 'steps'
                        ? 'bg-[#00FF41] text-black border-[#00FF41]'
                        : 'bg-[#0A180A] text-[#88CC99] border-[#00FF41]/30 hover:text-white'
                    }`}
                  >
                    Checklist de Segurança ({result.securityChecklist?.length || 0})
                  </button>
                </div>

                {applied && (
                  <div className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-[#00FF41]/20 border border-[#00FF41] text-[#00FF41] text-xs font-bold">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Aplicado ao arquivo</span>
                  </div>
                )}
              </div>

              {/* Tab Contents */}
              {activeTab === 'diff' && (
                <div className="border border-[#142614] bg-[#000] overflow-hidden">
                  <div className="px-3.5 py-2 bg-[#0C140C] border-b border-[#142614] flex items-center justify-between text-[11px] text-[#88CC99]">
                    <span className="font-bold text-rose-400 uppercase tracking-wider">- CÓDIGO ANTERIOR VULNERÁVEL:</span>
                    <span className="text-[#666]">L{finding.line}</span>
                  </div>
                  <div className="p-3.5 bg-[#170505] text-rose-300 overflow-x-auto whitespace-pre leading-relaxed border-l-3 border-rose-600">
                    {result.beforeSnippet || finding.snippet}
                  </div>

                  <div className="px-3.5 py-2 bg-[#0C140C] border-y border-[#142614] flex items-center justify-between text-[11px] text-[#88CC99]">
                    <span className="font-bold text-[#00FF41] uppercase tracking-wider">+ SUBSTITUIÇÃO SEGURA (PATCH):</span>
                    <span className="text-[#00FF41]">Drop-in Replacement</span>
                  </div>
                  <div className="p-3.5 bg-[#031503] text-[#A6FFA6] overflow-x-auto whitespace-pre leading-relaxed border-l-3 border-[#00FF41]">
                    {result.replacementSnippet}
                  </div>
                </div>
              )}

              {activeTab === 'code' && (
                <div className="space-y-2">
                  <pre className="p-4 bg-[#000] border border-[#00FF41]/40 text-[#00FF41] overflow-x-auto whitespace-pre leading-relaxed">
                    <code>{result.replacementSnippet}</code>
                  </pre>
                </div>
              )}

              {activeTab === 'env' && result.envConfig && (
                <div className="p-4 bg-[#051105] border border-[#00FF41]/30 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-xs uppercase tracking-wider">
                      Variável de Ambiente:
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopy(result.envConfig!.exampleLine, 'env')}
                      className="px-2.5 py-1 bg-[#000] text-[#00FF41] border border-[#00FF41]/40 text-[10px] font-bold uppercase inline-flex items-center gap-1 cursor-pointer"
                    >
                      {copiedEnv ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedEnv ? 'Copiado!' : 'Copiar .env'}</span>
                    </button>
                  </div>
                  <div className="p-3 bg-[#000] border border-[#142614] text-[#00FF41] select-all">
                    <code>{result.envConfig.exampleLine}</code>
                  </div>
                  <p className="text-xs text-[#99BBAA] leading-relaxed">
                    {result.envConfig.instructions}
                  </p>
                </div>
              )}

              {activeTab === 'steps' && (
                <div className="space-y-2">
                  {result.securityChecklist.map((step, idx) => (
                    <div
                      key={idx}
                      className="p-3 bg-[#071407] border border-[#142614] flex items-start gap-3 text-xs text-[#C0E0C0]"
                    >
                      <span className="w-5 h-5 rounded-full bg-[#00FF41]/20 border border-[#00FF41]/50 text-[#00FF41] flex items-center justify-center text-xs font-bold shrink-0">
                        {idx + 1}
                      </span>
                      <span className="mt-0.5">{step}</span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-[#0A120A] border-t border-[#142614] flex flex-wrap items-center justify-between gap-3 shrink-0">
          <div className="text-[11px] text-[#668877]">
            {result?.source === 'gemini' ? (
              <span>✨ Gerado via Gemini 3.1 Pro / 3.8 Flash com grounding em AppSec</span>
            ) : (
              <span>🛡️ Gerado via SecScan Deterministic Rule Engine</span>
            )}
          </div>

          <div className="flex items-center gap-2">
            {result && (
              <button
                type="button"
                onClick={() => handleCopy(result.replacementSnippet, 'snippet')}
                className="px-4 py-2 bg-[#142614] hover:bg-[#1C361C] text-white border border-[#00FF41]/40 text-xs font-mono font-bold uppercase tracking-wider inline-flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                {copiedSnippet ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedSnippet ? 'Código Copiado!' : 'Copiar Snippet'}</span>
              </button>
            )}

            {result && onApplyFix && (
              <button
                type="button"
                onClick={handleApply}
                className="px-4 py-2 bg-[#00FF41] hover:bg-white text-black text-xs font-mono font-black uppercase tracking-wider inline-flex items-center gap-1.5 transition-all shadow-[0_0_12px_rgba(0,255,65,0.3)] cursor-pointer"
              >
                <Zap className="w-3.5 h-3.5 fill-black" />
                <span>{applied ? 'Aplicar Novamente' : 'Aplicar ao Arquivo'}</span>
              </button>
            )}

            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 bg-[#111] hover:bg-[#222] text-[#AAA] hover:text-white border border-[#333] text-xs font-mono transition-colors cursor-pointer"
            >
              Fechar
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
