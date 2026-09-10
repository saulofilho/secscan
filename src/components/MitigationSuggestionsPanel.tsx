import React, { useState, useEffect, useMemo } from 'react';
import {
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Copy,
  Check,
  RefreshCw,
  FileCode,
  Download,
  Terminal,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Cpu,
  Layers,
  Flame,
  KeyRound,
  Database,
  Code2
} from 'lucide-react';
import { ScanReport, ScanFinding, GeminiMitigationReport, GeminiRefactorStep, SeverityLevel } from '../types';
import { safeGetItem, safeSetItem } from '../lib/storage';

interface MitigationSuggestionsPanelProps {
  report: ScanReport;
  qualityGateLimit?: number;
  onNavigateToFinding?: (findingId: string) => void;
  onNavigateToScanner?: () => void;
  onNavigateToQualityGate?: () => void;
}

const STORAGE_CACHE_KEY = 'secscan_gemini_mitigation_cache_v1';

const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export const MitigationSuggestionsPanel: React.FC<MitigationSuggestionsPanelProps> = ({
  report,
  qualityGateLimit = 50,
  onNavigateToFinding,
  onNavigateToScanner,
  onNavigateToQualityGate,
}) => {
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<GeminiMitigationReport | null>(null);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [copiedPlan, setCopiedPlan] = useState<boolean>(false);
  const [expandedCards, setExpandedCards] = useState<Record<string, boolean>>({
    'card-0': true,
    'card-1': true,
    'card-2': true,
  });
  const [completedActions, setCompletedActions] = useState<Record<number, boolean>>({});

  // 1. Identify Top-3 Highest Severity Findings
  const topFindings = useMemo(() => {
    const activeFindings = (report.findings || []).filter((f) => !f.isFalsePositive);
    return [...activeFindings]
      .sort((a, b) => {
        const sevDiff = (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0);
        if (sevDiff !== 0) return sevDiff;
        const scoreB = b.weightedScore || b.riskScore || 0;
        const scoreA = a.weightedScore || a.riskScore || 0;
        return scoreB - scoreA;
      })
      .slice(0, 3);
  }, [report.findings]);

  const currentRiskScore = report.metrics.riskScore ?? 0;

  // 2. Fetch or compute suggestions
  const fetchMitigationSuggestions = async (forceRefresh = false) => {
    if (topFindings.length === 0) {
      setData(null);
      return;
    }

    // Check cache if not forcing refresh
    if (!forceRefresh) {
      const cached = safeGetItem(STORAGE_CACHE_KEY);
      if (cached) {
        try {
          const parsed = JSON.parse(cached);
          // Check if cached suggestions match current top findings IDs
          const cachedIds = (parsed.suggestions || []).map((s: any) => s.findingId).join(',');
          const currentIds = topFindings.map((f) => f.id).join(',');
          if (cachedIds === currentIds) {
            setData(parsed);
            return;
          }
        } catch {
          // ignore cache error
        }
      }
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/mitigations', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          topFindings: topFindings.map((f) => ({
            id: f.id,
            ruleName: f.ruleName,
            category: f.category,
            severity: f.severity,
            file: f.file,
            line: f.line,
            snippet: f.snippet,
            maskedSecret: f.maskedSecret,
            remediation: f.remediation,
            description: f.description,
            entropy: f.entropy,
            riskScore: f.riskScore,
          })),
          currentRiskScore,
          qualityGateLimit,
        }),
      });

      if (!response.ok) {
        throw new Error(`Servidor retornou HTTP ${response.status}`);
      }

      const result: GeminiMitigationReport = await response.json();
      setData(result);
      safeSetItem(STORAGE_CACHE_KEY, JSON.stringify(result));
    } catch (err: any) {
      console.warn('Erro ao consultar /api/mitigations:', err?.message);
      // Construct fallback locally if network/API failed
      const fallbackReport: GeminiMitigationReport = {
        source: 'rule_engine',
        model: 'SecScan Deterministic AppSec Engine',
        timestamp: new Date().toISOString(),
        executiveSummary: `Análise estruturada dos ${topFindings.length} achados mais críticos. A aplicação das refatorações propostas reduz a exposição das credenciais e isola os pontos de injeção direta.`,
        totalPotentialRiskReduction: Math.min(currentRiskScore, 24),
        projectedNewRiskScore: Math.max(0, currentRiskScore - 24),
        willPassQualityGate: Math.max(0, currentRiskScore - 24) <= qualityGateLimit,
        suggestions: topFindings.map((f, idx) => ({
          findingId: f.id,
          ruleName: f.ruleName,
          category: f.category,
          severity: f.severity,
          file: f.file,
          line: f.line,
          riskImpact: `Vulnerabilidade ${f.severity} que impacta diretamente a pontuação acumulada do workspace.`,
          rootCauseAnalysis: `Exposição indevida no arquivo ${f.file}:${f.line}.`,
          securePattern: 'Environment Variable Injection & Secrets Manager',
          refactorSteps: [
            'Remover o valor fixo codificado no arquivo.',
            'Configurar variável de ambiente no servidor (.env ou Secret Manager).',
            'Validar ausência de credenciais no histórico do Git.',
          ],
          beforeCode: f.snippet || `const key = "${f.maskedSecret || 'secret'}";`,
          afterCode: `const key = process.env.${f.ruleName.replace(/[^A-Z0-9]/gi, '_').toUpperCase()};\nif (!key) throw new Error('Chave de configuração ausente');`,
          estimatedRiskReductionPoints: f.severity === 'CRITICAL' ? 22 : 14,
          mitigationPriority: idx === 0 ? 'P0 - BLOQUEANTE' : idx === 1 ? 'P1 - CRÍTICO' : 'P2 - ALTO',
        })),
        actionPlan: [
          'Rotacionar credenciais ativas nos consoles dos provedores.',
          'Substituir referências estáticas por variáveis de ambiente.',
          'Re-executar o scanner SAST para confirmar a redução do Risk Score.',
        ],
      };
      setData(fallbackReport);
      safeSetItem(STORAGE_CACHE_KEY, JSON.stringify(fallbackReport));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMitigationSuggestions(false);
  }, [topFindings, currentRiskScore, qualityGateLimit]);

  const toggleCard = (cardKey: string) => {
    setExpandedCards((prev) => ({
      ...prev,
      [cardKey]: !prev[cardKey],
    }));
  };

  const handleCopyCode = (code: string, index: number) => {
    navigator.clipboard.writeText(code);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleCopyFullPlan = () => {
    if (!data) return;
    const text = `# SecScan - Plano de Mitigação de Vulnerabilidades
Gerado em: ${new Date(data.timestamp).toLocaleString('pt-BR')}
Motor: ${data.model} (${data.source})

## Resumo Executivo
${data.executiveSummary}

## Impacto no Risk Score
- Score Atual: ${currentRiskScore}/100
- Score Projetado: ${data.projectedNewRiskScore}/100
- Redução Estimada: -${data.totalPotentialRiskReduction} pontos
- Conformidade com Quality Gate (&le; ${qualityGateLimit}): ${data.willPassQualityGate ? 'SIM (APROVADO)' : 'NÃO (VIOLAÇÃO)'}

## Plano de Ação Priorizado
${data.actionPlan.map((step, i) => `${i + 1}. ${step}`).join('\n')}

## Refatorações Sugeridas
${data.suggestions
  .map(
    (s, i) => `
### ${i + 1}. [${s.mitigationPriority}] ${s.ruleName}
- Arquivo: ${s.file}:${s.line}
- Severidade: ${s.severity}
- Padrão Seguro: ${s.securePattern}
- Causa Raiz: ${s.rootCauseAnalysis}
- Redução Estimada: -${s.estimatedRiskReductionPoints} pts

Passos:
${s.refactorSteps.map((st) => `  * ${st}`).join('\n')}

Antes (Vulnerável):
\`\`\`
${s.beforeCode}
\`\`\`

Depois (Refatorado):
\`\`\`
${s.afterCode}
\`\`\`
`
  )
  .join('\n')}
`;

    navigator.clipboard.writeText(text);
    setCopiedPlan(true);
    setTimeout(() => setCopiedPlan(false), 2000);
  };

  const handleDownloadMarkdown = () => {
    if (!data) return;
    const text = `# SecScan - Plano de Mitigação de Vulnerabilidades\nGerado: ${data.timestamp}\n\n${data.executiveSummary}\n\n` +
      data.suggestions.map((s, i) => `## #${i+1} ${s.ruleName} (${s.file}:${s.line})\n\n${s.securePattern}\n\n\`\`\`\n${s.afterCode}\n\`\`\``).join('\n\n');
    const blob = new Blob([text], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `secscan-mitigation-plan-${new Date().toISOString().split('T')[0]}.md`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // If no findings, render clean state
  if (topFindings.length === 0) {
    return (
      <div id="gemini-mitigation-suggestions-panel" className="bg-[#0A0A0A] border-2 border-[#2A2A2A] p-6 lg:p-8 space-y-4 font-mono">
        <div className="flex items-center gap-2.5">
          <Sparkles className="w-5 h-5 text-[#00FF41]" />
          <h2 className="text-xl font-black text-white uppercase tracking-tight">
            Sugestões de Mitigação & Refatoração Inteligente
          </h2>
        </div>
        <div className="bg-[#050505] border border-[#222] p-6 text-center space-y-3">
          <ShieldCheck className="w-12 h-12 text-[#00FF41] mx-auto" />
          <div className="text-white font-bold text-base">Nenhuma vulnerabilidade ativa no workspace!</div>
          <p className="text-xs text-[#888] max-w-md mx-auto">
            O código atual não apresenta exposições críticas ou segredos mapeados. O Cumulative Risk Score permanece no nível mínimo.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div
      id="gemini-mitigation-suggestions-panel"
      className="bg-[#0A0A0A] border-2 border-[#2A2A2A] p-6 lg:p-8 space-y-6 relative overflow-hidden font-mono"
    >
      {/* Decorative background glow */}
      <div className="absolute top-0 right-0 w-80 h-80 bg-gradient-to-bl from-[#3366FF]/10 via-[#FF3E00]/5 to-transparent rounded-bl-full pointer-events-none" />

      {/* Header section */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-[#222] relative z-10">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="text-[10px] text-[#3366FF] bg-[#3366FF]/10 px-2.5 py-0.5 border border-[#3366FF]/40 uppercase font-black tracking-widest flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-[#3366FF]" />
              IA APPSEC // GEMINI 3.8 FLASH & SAST ENGINE
            </span>

            {data && (
              <span className={`text-[10px] px-2 py-0.5 border font-bold flex items-center gap-1 ${
                data.source === 'gemini'
                  ? 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/40'
                  : 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/40'
              }`}>
                <Cpu className="w-3 h-3" />
                <span>{data.model}</span>
              </span>
            )}

            <span className="text-[10px] bg-[#141414] text-[#AAA] border border-[#333] px-2 py-0.5">
              TOP-{topFindings.length} VULNERABILIDADES PRIORIZADAS
            </span>
          </div>

          <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
            <span>Sugestões de Mitigação & Refatoração de Código</span>
          </h2>
          <p className="text-xs text-[#888] max-w-3xl leading-relaxed">
            Análise aprofundada das 3 vulnerabilidades que mais inflacionam o <strong className="text-white">Cumulative Risk Score</strong>. Fornece passos precisos de refatoração, padrões de arquitetura segura e snippets comparativos (Antes vs Depois) para desbloquear o deploy no Quality Gate.
          </p>
        </div>

        {/* Header Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            id="btn-refresh-mitigation-suggestions"
            type="button"
            onClick={() => fetchMitigationSuggestions(true)}
            disabled={loading}
            className="px-3.5 py-2 bg-[#3366FF] hover:bg-white hover:text-black text-white font-bold text-xs uppercase tracking-wider transition-all flex items-center gap-1.5 shadow-[0_0_15px_rgba(51,102,255,0.25)] cursor-pointer disabled:opacity-50"
            title="Requisitar nova análise com Gemini 3.8 Flash"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? 'Analisando...' : 'Atualizar Análise IA'}</span>
          </button>

          <button
            id="btn-copy-full-mitigation-plan"
            type="button"
            onClick={handleCopyFullPlan}
            disabled={!data}
            className="px-3 py-2 bg-[#141414] hover:bg-[#222] border border-[#333] hover:border-[#555] text-white text-xs uppercase tracking-wider transition-colors flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            title="Copiar plano completo de remediação para a área de transferência"
          >
            {copiedPlan ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5 text-[#888]" />}
            <span>{copiedPlan ? 'Copiado!' : 'Copiar Plano'}</span>
          </button>

          <button
            id="btn-download-mitigation-md"
            type="button"
            onClick={handleDownloadMarkdown}
            disabled={!data}
            className="p-2 bg-[#141414] hover:bg-[#222] border border-[#333] text-[#AAA] hover:text-white transition-colors cursor-pointer disabled:opacity-50"
            title="Baixar playbook de mitigação em Markdown"
          >
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Projection Banner: Current Risk Score -> Projected Risk Score */}
      {data && (
        <div className="bg-[#050505] border border-[#222] p-5 lg:p-6 space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#181818]">
            <div className="flex items-center gap-3">
              <Flame className="w-6 h-6 text-[#FF3E00] shrink-0" />
              <div>
                <span className="text-[10px] text-[#777] uppercase font-bold tracking-wider block">
                  Projeção de Impacto no Risk Score Cumulativo
                </span>
                <div className="text-white text-sm font-bold mt-0.5">
                  Refatoração Simultânea dos 3 Maiores Fatores de Risco
                </div>
              </div>
            </div>

            {/* Score Comparison Display */}
            <div className="flex items-center gap-4 bg-[#0E0E0E] px-4 py-2.5 border border-[#1F1F1F]">
              <div>
                <span className="text-[9px] text-[#888] uppercase block">Risk Score Atual</span>
                <div className="text-xl font-black text-[#FF3E00]">{currentRiskScore} <span className="text-[10px] text-[#666]">/100</span></div>
              </div>

              <ArrowRight className="w-4 h-4 text-[#666]" />

              <div>
                <span className="text-[9px] text-[#888] uppercase block">Score Projetado</span>
                <div className="text-xl font-black text-[#00FF41]">{data.projectedNewRiskScore} <span className="text-[10px] text-[#666]">/100</span></div>
              </div>

              <div className="pl-3 border-l border-[#262626]">
                <span className="text-[9px] text-[#888] uppercase block">Redução Potencial</span>
                <div className="text-base font-black text-[#00FF41]">-{data.totalPotentialRiskReduction} pts</div>
              </div>
            </div>
          </div>

          {/* Diagnosis & Quality Gate Compliance Status */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 text-xs">
            <p className="text-[#BBB] leading-relaxed max-w-3xl">
              {data.executiveSummary}
            </p>

            <div className="shrink-0 flex items-center gap-2">
              <span className={`px-3 py-1 border font-bold text-xs flex items-center gap-1.5 ${
                data.willPassQualityGate
                  ? 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/50'
                  : 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/50'
              }`}>
                {data.willPassQualityGate ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
                <span>
                  {data.willPassQualityGate
                    ? `CONFORME COM QUALITY GATE (&le; ${qualityGateLimit} PTS)`
                    : `APROXIMA DO LIMITE (TOLERÂNCIA: &le; ${qualityGateLimit} PTS)`}
                </span>
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Action Plan Checklist */}
      {data && data.actionPlan && data.actionPlan.length > 0 && (
        <div className="bg-[#050505] border border-[#222] p-4 lg:p-5 space-y-3">
          <div className="flex items-center justify-between text-xs font-bold text-white uppercase tracking-wider">
            <span className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-[#00FF41]" />
              <span>Plano de Ação Sequencial Recomendado pela IA</span>
            </span>
            <span className="text-[10px] text-[#666] font-normal">
              {Object.values(completedActions).filter(Boolean).length} de {data.actionPlan.length} concluídos
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
            {data.actionPlan.map((step, idx) => {
              const isDone = !!completedActions[idx];
              return (
                <div
                  key={idx}
                  onClick={() =>
                    setCompletedActions((prev) => ({
                      ...prev,
                      [idx]: !prev[idx],
                    }))
                  }
                  className={`p-3 border text-xs cursor-pointer transition-all flex items-start gap-2.5 select-none ${
                    isDone
                      ? 'bg-[#00FF41]/10 border-[#00FF41]/40 text-[#00FF41]'
                      : 'bg-[#0E0E0E] border-[#1F1F1F] text-[#CCC] hover:border-[#333]'
                  }`}
                >
                  <div
                    className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 mt-0.5 ${
                      isDone
                        ? 'bg-[#00FF41] border-[#00FF41] text-black font-bold'
                        : 'border-[#444] bg-[#141414]'
                    }`}
                  >
                    {isDone && <Check className="w-3 h-3 stroke-[3]" />}
                  </div>
                  <span className={`leading-relaxed text-[11px] ${isDone ? 'line-through text-[#888]' : ''}`}>
                    {step}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Loading Skeleton */}
      {loading && !data && (
        <div className="space-y-4 py-8 text-center bg-[#050505] border border-[#222]">
          <RefreshCw className="w-8 h-8 text-[#3366FF] animate-spin mx-auto" />
          <div className="text-white font-bold text-sm">Consultando Gemini 3.8 Flash para síntese de mitigação...</div>
          <p className="text-xs text-[#777]">Calculando refatorações otimizadas para redução do Risk Score</p>
        </div>
      )}

      {/* Cards for each of the Top-3 Vulnerabilities */}
      {data && data.suggestions && (
        <div className="space-y-5">
          <div className="flex items-center justify-between text-xs text-[#888] uppercase tracking-wider pb-1">
            <span>Refatorações Específicas para os 3 Maiores Fatores de Risco:</span>
            <span>Clique nos cards para expandir/recolher</span>
          </div>

          {data.suggestions.map((suggestion, index) => {
            const cardKey = `card-${index}`;
            const isExpanded = expandedCards[cardKey] ?? true;

            const priorityBadge =
              suggestion.mitigationPriority === 'P0 - BLOQUEANTE'
                ? 'bg-[#FF3E00] text-white'
                : suggestion.mitigationPriority === 'P1 - CRÍTICO'
                ? 'bg-[#FF7A00] text-black font-bold'
                : 'bg-[#EAB308] text-black font-bold';

            const sevBadge =
              suggestion.severity === 'CRITICAL'
                ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40'
                : suggestion.severity === 'HIGH'
                ? 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/40'
                : 'bg-[#EAB308]/15 text-[#EAB308] border-[#EAB308]/40';

            return (
              <div
                key={suggestion.findingId || index}
                className="bg-[#050505] border border-[#222] hover:border-[#333] transition-all overflow-hidden"
              >
                {/* Card Header Bar */}
                <div
                  onClick={() => toggleCard(cardKey)}
                  className="p-4 lg:p-5 flex flex-col md:flex-row md:items-center justify-between gap-3 cursor-pointer bg-[#0A0A0A] hover:bg-[#0E0E0E] transition-colors border-b border-[#181818]"
                >
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span className="w-6 h-6 rounded-full bg-[#181818] border border-[#333] flex items-center justify-center text-xs font-black text-white">
                      #{index + 1}
                    </span>

                    <span className={`text-[9px] font-mono px-2 py-0.5 uppercase tracking-wider ${priorityBadge}`}>
                      {suggestion.mitigationPriority}
                    </span>

                    <span className={`text-[9px] font-mono px-2 py-0.5 border uppercase font-bold ${sevBadge}`}>
                      {suggestion.severity}
                    </span>

                    <h3 className="text-sm font-bold text-white uppercase tracking-tight">
                      {suggestion.ruleName}
                    </h3>

                    <span className="text-[11px] text-[#888] font-normal">
                      em <code className="text-[#3366FF]">{suggestion.file}:{suggestion.line}</code>
                    </span>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-[10px] bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30 px-2 py-0.5 font-bold">
                      -{suggestion.estimatedRiskReductionPoints} PTS ESTIMADOS
                    </span>
                    {isExpanded ? <ChevronUp className="w-4 h-4 text-[#888]" /> : <ChevronDown className="w-4 h-4 text-[#888]" />}
                  </div>
                </div>

                {/* Collapsible Card Body */}
                {isExpanded && (
                  <div className="p-5 lg:p-6 space-y-5 text-xs">
                    {/* Architectural Pattern & Root Cause Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-[#0A0A0A] p-4 border border-[#1A1A1A]">
                      <div className="space-y-1.5">
                        <div className="text-[10px] text-[#777] uppercase font-bold flex items-center gap-1.5">
                          <Layers className="w-3.5 h-3.5 text-[#3366FF]" />
                          <span>Padrão de Arquitetura Segura Recomendado</span>
                        </div>
                        <div className="text-white font-bold text-xs bg-[#111] p-2 border border-[#222]">
                          {suggestion.securePattern}
                        </div>
                      </div>

                      <div className="space-y-1.5">
                        <div className="text-[10px] text-[#777] uppercase font-bold flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5 text-[#FF7A00]" />
                          <span>Diagnóstico de Causa Raiz</span>
                        </div>
                        <p className="text-[#AAA] text-[11px] leading-relaxed">
                          {suggestion.rootCauseAnalysis}
                        </p>
                      </div>
                    </div>

                    {/* Step-by-Step Refactoring Instructions */}
                    {suggestion.refactorSteps && suggestion.refactorSteps.length > 0 && (
                      <div className="space-y-2">
                        <div className="text-[10px] text-[#777] uppercase font-bold flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5 text-[#00FF41]" />
                          <span>Passo a Passo de Refatoração</span>
                        </div>
                        <ol className="list-decimal list-inside space-y-1 text-[#CCC] bg-[#0A0A0A] p-3 border border-[#1A1A1A] leading-relaxed">
                          {suggestion.refactorSteps.map((step, sIdx) => (
                            <li key={sIdx} className="text-[11px]">
                              {step}
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}

                    {/* Side-by-side or stacked code diff */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between text-[10px] text-[#777] uppercase font-bold">
                        <span className="flex items-center gap-1.5">
                          <Code2 className="w-3.5 h-3.5 text-[#3366FF]" />
                          <span>Refatoração de Código Comparativa (Antes vs Depois)</span>
                        </span>
                        <button
                          type="button"
                          onClick={() => handleCopyCode(suggestion.afterCode, index)}
                          className="text-[#00FF41] hover:text-white flex items-center gap-1 cursor-pointer transition-colors"
                          title="Copiar código remediado seguro"
                        >
                          {copiedIndex === index ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedIndex === index ? 'Copiado!' : 'Copiar Código Corrigido'}</span>
                        </button>
                      </div>

                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono text-[11px]">
                        {/* Before (Vulnerable) */}
                        <div className="border border-[#FF3E00]/30 bg-[#120502] overflow-hidden">
                          <div className="bg-[#240A04] px-3 py-1.5 text-[10px] font-bold text-[#FF3E00] border-b border-[#FF3E00]/30 flex items-center justify-between">
                            <span>✕ CÓDIGO VULNERÁVEL ATUAL (ANTES)</span>
                            <span className="text-[#888]">{suggestion.file}</span>
                          </div>
                          <pre className="p-3 text-[#FFA080] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                            {suggestion.beforeCode}
                          </pre>
                        </div>

                        {/* After (Secure Refactored) */}
                        <div className="border border-[#00FF41]/30 bg-[#021405] overflow-hidden">
                          <div className="bg-[#05280B] px-3 py-1.5 text-[10px] font-bold text-[#00FF41] border-b border-[#00FF41]/30 flex items-center justify-between">
                            <span>✓ CÓDIGO REMEDIADO E SEGURO (DEPOIS)</span>
                            <span className="text-[#888]">Boas Práticas AppSec</span>
                          </div>
                          <pre className="p-3 text-[#99FFB3] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                            {suggestion.afterCode}
                          </pre>
                        </div>
                      </div>
                    </div>

                    {/* Footer link to Scanner */}
                    <div className="pt-2 flex items-center justify-between border-t border-[#181818] text-[11px]">
                      <span className="text-[#666]">
                        Identificador da Regra: <code className="text-[#888]">{suggestion.ruleName}</code>
                      </span>
                      {onNavigateToFinding ? (
                        <button
                          type="button"
                          onClick={() => onNavigateToFinding(suggestion.findingId)}
                          className="text-[#3366FF] hover:text-white font-bold flex items-center gap-1 cursor-pointer transition-colors"
                        >
                          <span>Localizar no Inspetor de Código</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      ) : onNavigateToScanner ? (
                        <button
                          type="button"
                          onClick={onNavigateToScanner}
                          className="text-[#3366FF] hover:text-white font-bold flex items-center gap-1 cursor-pointer transition-colors"
                        >
                          <span>Ir para o Scanner SAST</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      ) : null}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
