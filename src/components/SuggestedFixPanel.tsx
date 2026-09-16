import React, { useState } from 'react';
import {
  Sparkles,
  Copy,
  Check,
  Zap,
  RotateCw,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
  AlertTriangle,
  FileCode,
  KeyRound,
  ExternalLink,
  Info,
  CheckCircle2
} from 'lucide-react';
import { ScanFinding, SuggestedFixResult } from '../types';
import { requestSuggestedFix } from '../lib/suggestedFixService';

interface SuggestedFixPanelProps {
  finding: ScanFinding;
  fileContent?: string;
  onApplyFix?: (finding: ScanFinding, newSnippet: string) => void;
  defaultExpanded?: boolean;
}

export const SuggestedFixPanel: React.FC<SuggestedFixPanelProps> = ({
  finding,
  fileContent,
  onApplyFix,
  defaultExpanded = false
}) => {
  const [isOpen, setIsOpen] = useState(defaultExpanded);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<SuggestedFixResult | null>(null);
  const [activeTab, setActiveTab] = useState<'diff' | 'code' | 'env' | 'steps'>('diff');
  const [copiedSnippet, setCopiedSnippet] = useState(false);
  const [copiedEnv, setCopiedEnv] = useState(false);
  const [applied, setApplied] = useState(false);
  const [loadingStep, setLoadingStep] = useState(0);

  const handleTriggerFix = async () => {
    if (isLoading) return;
    setIsOpen(true);
    setIsLoading(true);
    setApplied(false);
    setLoadingStep(1);

    const stepInterval = setInterval(() => {
      setLoadingStep(prev => (prev < 3 ? prev + 1 : prev));
    }, 600);

    try {
      const fixResult = await requestSuggestedFix(finding, fileContent);
      setResult(fixResult);
    } catch (err) {
      console.error('Erro ao gerar Suggested Fix:', err);
    } finally {
      clearInterval(stepInterval);
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
    if (!result || !onApplyFix) return;
    onApplyFix(finding, result.replacementSnippet);
    setApplied(true);
  };

  return (
    <div className="border border-[#00FF41]/30 bg-[#040804]/90 overflow-hidden transition-all shadow-[0_0_15px_rgba(0,255,65,0.06)]">
      {/* Header bar / Trigger button */}
      <div className="px-3.5 py-2.5 bg-[#071207] border-b border-[#00FF41]/20 flex flex-wrap items-center justify-between gap-2.5">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[#00FF41]/15 text-[#00FF41] border border-[#00FF41]/40 text-[10px] font-mono font-black tracking-wider uppercase">
            <Sparkles className="w-3 h-3 text-[#00FF41] animate-pulse" />
            <span>AI Suggested Fix</span>
          </div>

          <span className="text-[11px] font-mono text-[#88CC99] hidden sm:inline">
            Patch seguro guiado pelo contexto sintático
          </span>
        </div>

        <div className="flex items-center gap-2">
          {!isOpen || !result ? (
            <button
              type="button"
              id={`btn-trigger-suggested-fix-${finding.id}`}
              onClick={handleTriggerFix}
              disabled={isLoading}
              className="inline-flex items-center gap-1.5 px-3 py-1 bg-[#00FF41] hover:bg-white text-black text-[11px] font-mono font-black uppercase tracking-wider transition-all shadow-[0_0_12px_rgba(0,255,65,0.3)] hover:shadow-[0_0_16px_rgba(255,255,255,0.5)] cursor-pointer disabled:opacity-50"
            >
              <Sparkles className="w-3.5 h-3.5 fill-black" />
              <span>{isLoading ? 'Analisando com IA...' : 'Suggested Fix'}</span>
            </button>
          ) : (
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={handleTriggerFix}
                disabled={isLoading}
                className="inline-flex items-center gap-1 px-2.5 py-1 bg-[#0d220d] hover:bg-[#143314] text-[#00FF41] hover:text-white border border-[#00FF41]/40 text-[10px] font-mono font-bold transition-colors cursor-pointer disabled:opacity-50"
                title="Regerar sugestão com IA"
              >
                <RotateCw className={`w-3 h-3 ${isLoading ? 'animate-spin' : ''}`} />
                <span>Regerar</span>
              </button>

              <button
                type="button"
                onClick={() => setIsOpen(!isOpen)}
                className="p-1 text-[#88CC99] hover:text-white border border-[#00FF41]/30 hover:border-[#00FF41] bg-[#071207] transition-colors"
                title={isOpen ? 'Recolher painel' : 'Expandir painel'}
              >
                {isOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Loading State */}
      {isOpen && isLoading && (
        <div className="p-6 bg-[#020502] font-mono text-xs space-y-4">
          <div className="flex items-center gap-3">
            <div className="w-4 h-4 rounded-full border-2 border-[#00FF41] border-t-transparent animate-spin" />
            <span className="text-[#00FF41] font-bold tracking-wide">
              {loadingStep === 1 && '1/3 Inspecionando vulnerabilidade e contexto do arquivo...'}
              {loadingStep === 2 && '2/3 Consultando modelo de segurança Gemini 3.1 / 3.8 Flash...'}
              {loadingStep === 3 && '3/3 Sintetizando código de substituição seguro e sanitização...'}
            </span>
          </div>

          <div className="w-full bg-[#0d220d] h-1.5 overflow-hidden">
            <div
              className="bg-gradient-to-r from-[#00FF41] to-[#00E5FF] h-full transition-all duration-500 ease-out"
              style={{ width: `${(loadingStep / 3) * 100}%` }}
            />
          </div>

          <div className="p-3 bg-[#000] border border-[#00FF41]/20 text-[11px] text-[#77AA88] space-y-1">
            <p>&gt; Alvo: <span className="text-white">{finding.file}:{finding.line}</span> ({finding.ruleName})</p>
            <p>&gt; Severidade: <span className="text-[#FF3E00] font-bold">{finding.severity}</span></p>
            <p>&gt; Arquitetura recomendada: Runtime Secrets Manager &amp; Fail-Safe Guards</p>
          </div>
        </div>
      )}

      {/* Result Container */}
      {isOpen && !isLoading && result && (
        <div className="p-4 sm:p-5 bg-[#030803] space-y-4 text-xs font-mono">
          {/* Metadata Badges & Pattern */}
          <div className="flex flex-wrap items-center justify-between gap-2.5 pb-3 border-b border-[#00FF41]/20">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-2 py-0.5 bg-[#00FF41]/20 text-[#00FF41] border border-[#00FF41]/40 text-[10px] font-bold">
                {result.source === 'gemini' ? `MODELO: ${result.model}` : `MOTOR: ${result.model}`}
              </span>

              <span className="px-2 py-0.5 bg-[#142614] text-[#AACCBB] border border-[#00FF41]/30 text-[10px]">
                {result.cweOwaspReference}
              </span>

              <span className="px-2 py-0.5 bg-[#0d1f0d] text-[#66FF99] border border-[#00FF41]/40 text-[10px] font-bold flex items-center gap-1">
                <ShieldCheck className="w-3 h-3 text-[#00FF41]" />
                <span>{result.securePattern}</span>
              </span>
            </div>

            {applied && (
              <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 bg-[#00FF41]/20 border border-[#00FF41] text-[#00FF41] text-[10px] font-bold animate-pulse">
                <CheckCircle2 className="w-3 h-3 text-[#00FF41]" />
                <span>PATCH APLICADO AO ARQUIVO</span>
              </div>
            )}
          </div>

          {/* Explanation Banner */}
          <div className="p-3 bg-[#081508] border border-[#00FF41]/25 text-[11px] text-[#C0E0C0] leading-relaxed flex items-start gap-2.5">
            <Info className="w-4 h-4 text-[#00FF41] shrink-0 mt-0.5" />
            <div>
              <p className="font-bold text-white mb-0.5">{result.vulnerabilityType}</p>
              <p>{result.explanation}</p>
            </div>
          </div>

          {/* Tab Navigation */}
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#142614] pb-2">
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => setActiveTab('diff')}
                className={`px-3 py-1 text-[11px] font-bold uppercase tracking-wider transition-colors cursor-pointer border ${
                  activeTab === 'diff'
                    ? 'bg-[#00FF41] text-black border-[#00FF41]'
                    : 'bg-[#071207] text-[#88CC99] border-[#00FF41]/30 hover:text-white'
                }`}
              >
                Diff (Antes vs Depois)
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('code')}
                className={`px-3 py-1 text-[11px] font-bold uppercase tracking-wider transition-colors cursor-pointer border ${
                  activeTab === 'code'
                    ? 'bg-[#00FF41] text-black border-[#00FF41]'
                    : 'bg-[#071207] text-[#88CC99] border-[#00FF41]/30 hover:text-white'
                }`}
              >
                Código Seguro
              </button>

              {result.envConfig && (
                <button
                  type="button"
                  onClick={() => setActiveTab('env')}
                  className={`px-3 py-1 text-[11px] font-bold uppercase tracking-wider transition-colors cursor-pointer border flex items-center gap-1.5 ${
                    activeTab === 'env'
                      ? 'bg-[#00FF41] text-black border-[#00FF41]'
                      : 'bg-[#071207] text-[#88CC99] border-[#00FF41]/30 hover:text-white'
                  }`}
                >
                  <KeyRound className="w-3 h-3" />
                  <span>.env Config</span>
                </button>
              )}

              <button
                type="button"
                onClick={() => setActiveTab('steps')}
                className={`px-3 py-1 text-[11px] font-bold uppercase tracking-wider transition-colors cursor-pointer border ${
                  activeTab === 'steps'
                    ? 'bg-[#00FF41] text-black border-[#00FF41]'
                    : 'bg-[#071207] text-[#88CC99] border-[#00FF41]/30 hover:text-white'
                }`}
              >
                Checklist ({result.securityChecklist?.length || 0})
              </button>
            </div>

            {/* Quick Actions */}
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => handleCopy(result.replacementSnippet, 'snippet')}
                className="px-2.5 py-1 bg-[#0d220d] hover:bg-[#143314] text-white border border-[#00FF41]/40 text-[10px] font-bold uppercase tracking-wider inline-flex items-center gap-1.5 transition-colors cursor-pointer"
                title="Copiar código de substituição para área de transferência"
              >
                {copiedSnippet ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                <span>{copiedSnippet ? 'Copiado!' : 'Copiar Código'}</span>
              </button>

              {onApplyFix && (
                <button
                  type="button"
                  onClick={handleApply}
                  className="px-3 py-1 bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-black text-[10px] font-black uppercase tracking-wider inline-flex items-center gap-1.5 transition-all shadow-[0_0_10px_rgba(16,185,129,0.3)] cursor-pointer"
                  title="Substituir código vulnerável diretamente no arquivo do workspace"
                >
                  <Zap className="w-3 h-3 fill-black" />
                  <span>{applied ? 'Re-aplicar' : 'Aplicar ao Arquivo'}</span>
                </button>
              )}
            </div>
          </div>

          {/* Tab 1: Diff View */}
          {activeTab === 'diff' && (
            <div className="space-y-3">
              <div className="border border-[#142614] bg-[#000] overflow-hidden text-xs">
                <div className="px-3 py-1.5 bg-[#071207] border-b border-[#142614] flex items-center justify-between text-[10px] text-[#88CC99]">
                  <span className="font-bold uppercase tracking-wider text-rose-400">- CÓDIGO VULNERÁVEL ANTERIOR (LINHA {finding.line}):</span>
                  <span className="text-[#666]">{finding.file}</span>
                </div>
                <div className="p-3 bg-[#170505] text-rose-300 font-mono overflow-x-auto whitespace-pre leading-relaxed border-l-2 border-rose-600">
                  {result.beforeSnippet || finding.snippet}
                </div>

                <div className="px-3 py-1.5 bg-[#071207] border-y border-[#142614] flex items-center justify-between text-[10px] text-[#88CC99]">
                  <span className="font-bold uppercase tracking-wider text-[#00FF41]">+ SUBSTITUIÇÃO SEGURA GERADA COM IA:</span>
                  <span className="text-[#00FF41]">Drop-in Secure Pattern</span>
                </div>
                <div className="p-3 bg-[#031503] text-[#A6FFA6] font-mono overflow-x-auto whitespace-pre leading-relaxed border-l-2 border-[#00FF41]">
                  {result.replacementSnippet}
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Full Code Snippet */}
          {activeTab === 'code' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-[11px] text-[#88CC99]">
                <span>Código pronto para substituição:</span>
                <span className="text-[10px] text-[#666]">Linguagem: TypeScript / JavaScript</span>
              </div>
              <pre className="p-4 bg-[#000] border border-[#00FF41]/40 text-[#00FF41] overflow-x-auto whitespace-pre leading-relaxed selection:bg-[#00FF41] selection:text-black">
                <code>{result.replacementSnippet}</code>
              </pre>
            </div>
          )}

          {/* Tab 3: .env Configuration */}
          {activeTab === 'env' && result.envConfig && (
            <div className="p-4 bg-[#051105] border border-[#00FF41]/30 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <KeyRound className="w-4 h-4 text-[#00FF41]" />
                  <span className="font-bold text-white text-xs uppercase tracking-wider">
                    Variável de Ambiente Recomendada:
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => handleCopy(result.envConfig!.exampleLine, 'env')}
                  className="px-2.5 py-1 bg-[#000] hover:bg-[#142614] text-[#00FF41] border border-[#00FF41]/40 text-[10px] font-bold uppercase inline-flex items-center gap-1 transition-colors cursor-pointer"
                >
                  {copiedEnv ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedEnv ? 'Copiado!' : 'Copiar .env'}</span>
                </button>
              </div>

              <div className="p-2.5 bg-[#000] border border-[#142614] text-[#00FF41] text-xs select-all">
                <code>{result.envConfig.exampleLine}</code>
              </div>

              <p className="text-[11px] text-[#99BBAA] leading-relaxed">
                {result.envConfig.instructions}
              </p>
            </div>
          )}

          {/* Tab 4: Security Hardening Checklist */}
          {activeTab === 'steps' && (
            <div className="space-y-2.5">
              <p className="text-[11px] text-[#88CC99] font-bold">
                Passos pós-remediação para garantir a eliminação do risco de exposição:
              </p>
              <div className="space-y-2">
                {result.securityChecklist.map((step, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 bg-[#061206] border border-[#142614] flex items-start gap-2.5 text-[11px] text-[#C0E0C0]"
                  >
                    <span className="w-4 h-4 rounded-full bg-[#00FF41]/20 border border-[#00FF41]/50 text-[#00FF41] flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">
                      {idx + 1}
                    </span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
