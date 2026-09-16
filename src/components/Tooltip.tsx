import React, { useState, useRef, useEffect } from 'react';
import { Clock, ShieldAlert, Timer, Wrench, Sparkles } from 'lucide-react';
import { SecScanGlobalConfig } from '../types';
import { getSecScanConfig, DEFAULT_SECSCAN_CONFIG } from '../lib/secscanConfig';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'WARNING';

export interface SeverityRemediationDetails {
  severity: SeverityLevel;
  label: string;
  tier: string;
  badgeCode: string;
  averageRemediationTime: string; // MTTR
  slaTarget: string;
  urgencyLevel: string;
  description: string;
  recommendedAction: string;
  theme: {
    border: string;
    bg: string;
    titleColor: string;
    badgeBg: string;
    badgeText: string;
    dotColor: string;
    highlightBg: string;
    highlightBorder: string;
    arrowBorder: string;
  };
}

export const SEVERITY_REMEDIATION_DATA: Record<SeverityLevel, SeverityRemediationDetails> = {
  CRITICAL: {
    severity: 'CRITICAL',
    label: 'Crítico',
    tier: 'Tier 0 • Bloqueador Imediato',
    badgeCode: 'P0 - CRÍTICO',
    averageRemediationTime: '1.5h – 2h',
    slaTarget: '0h – 4h (Imediato)',
    urgencyLevel: 'Urgência Máxima • Bloqueio de Pipeline',
    description: 'Credenciais mestre de nuvem, chaves privadas e tokens de acesso irrestrito expostos diretamente no código.',
    recommendedAction: 'Inativar e revogar chave no IAM imediatamente, rotacionar segredo e purgar histórico com git-filter-repo.',
    theme: {
      border: 'border-rose-500/50',
      bg: 'bg-[#100507]',
      titleColor: 'text-rose-400',
      badgeBg: 'bg-rose-500/20',
      badgeText: 'text-rose-300',
      dotColor: 'bg-rose-500',
      highlightBg: 'bg-rose-950/40',
      highlightBorder: 'border-rose-500/30',
      arrowBorder: 'border-b-rose-500/50'
    }
  },
  HIGH: {
    severity: 'HIGH',
    label: 'Alto',
    tier: 'Tier 1 • Alta Prioridade',
    badgeCode: 'P1 - ALTO',
    averageRemediationTime: '4h – 6h',
    slaTarget: '≤ 24h (Próximo Dia Útil)',
    urgencyLevel: 'Alta Urgência • Risco Financeiro & Operacional',
    description: 'Chaves de API de terceiros (pagamentos, LLMs, emails), JWTs com assinaturas fracas ou tokens de escrita.',
    recommendedAction: 'Rotacionar no console do fornecedor terceiro, isolar em variáveis (.env) e auditar logs de requisições.',
    theme: {
      border: 'border-amber-500/50',
      bg: 'bg-[#120B04]',
      titleColor: 'text-amber-400',
      badgeBg: 'bg-amber-500/20',
      badgeText: 'text-amber-300',
      dotColor: 'bg-amber-500',
      highlightBg: 'bg-amber-950/40',
      highlightBorder: 'border-amber-500/30',
      arrowBorder: 'border-b-amber-500/50'
    }
  },
  WARNING: {
    severity: 'WARNING',
    label: 'Aviso',
    tier: 'Tier 2 • Risco Moderado & Higiene',
    badgeCode: 'P2 - AVISO',
    averageRemediationTime: '12h – 24h',
    slaTarget: '≤ 72h a 7 dias (Sprint Atual)',
    urgencyLevel: 'Higiene de Código & Débito Técnico',
    description: 'Segredos em ambiente de testes/staging, endpoints de debug, senhas em scripts locais ou boas práticas negligenciadas.',
    recommendedAction: 'Sanitizar variáveis locais, incluir arquivos no .gitignore e habilitar pre-commit hooks de auditoria.',
    theme: {
      border: 'border-yellow-500/50',
      bg: 'bg-[#121104]',
      titleColor: 'text-yellow-400',
      badgeBg: 'bg-yellow-500/20',
      badgeText: 'text-yellow-300',
      dotColor: 'bg-yellow-400',
      highlightBg: 'bg-yellow-950/40',
      highlightBorder: 'border-yellow-500/30',
      arrowBorder: 'border-b-yellow-500/50'
    }
  }
};

interface TooltipProps {
  content: React.ReactNode;
  children: React.ReactNode;
  position?: 'top' | 'bottom';
  align?: 'left' | 'center' | 'right';
  className?: string;
  delayMs?: number;
  id?: string;
}

/**
 * Generic accessible Tooltip component with smooth motion transitions and auto-dismiss
 */
export const Tooltip: React.FC<TooltipProps> = ({
  content,
  children,
  position = 'bottom',
  align = 'center',
  className = '',
  delayMs = 120,
  id
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);

  const handleMouseEnter = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    timeoutRef.current = setTimeout(() => {
      setIsVisible(true);
    }, delayMs);
  };

  const handleMouseLeave = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    setIsVisible(false);
  };

  const handleFocus = () => {
    setIsVisible(true);
  };

  const handleBlur = () => {
    setIsVisible(false);
  };

  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  const positionClasses = position === 'top'
    ? 'bottom-full mb-2'
    : 'top-full mt-2';

  const alignClasses = align === 'left'
    ? 'left-0'
    : align === 'right'
    ? 'right-0'
    : 'left-1/2 -translate-x-1/2';

  return (
    <div
      className={`relative inline-flex ${className}`}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      onFocus={handleFocus}
      onBlur={handleBlur}
    >
      {children}

      <div
        id={id}
        role="tooltip"
        aria-hidden={!isVisible}
        className={`absolute ${positionClasses} ${alignClasses} z-50 pointer-events-none transition-all duration-150 ease-out transform ${
          isVisible
            ? 'opacity-100 scale-100 translate-y-0'
            : 'opacity-0 scale-95 pointer-events-none ' + (position === 'top' ? 'translate-y-1' : '-translate-y-1')
        }`}
      >
        {isVisible && content}
      </div>
    </div>
  );
};

interface SeverityTooltipProps {
  severity: SeverityLevel;
  count?: number;
  isActive?: boolean;
  position?: 'top' | 'bottom';
  align?: 'left' | 'center' | 'right';
  remediationTime?: string; // Dynamic remediation time (MTTR) parameter from SecScan global config
  config?: SecScanGlobalConfig; // Optional SecScan global config object override
  children: React.ReactNode;
}

/**
 * Dedicated explanatory Tooltip component for severity badges, detailing:
 * - Tempo Médio de Remediação (MTTR) [Dinâmico via Configuração Global SecScan]
 * - SLA / Prazo Alvo
 * - Impacto e Ação de Resolução
 */
export const SeverityTooltip: React.FC<SeverityTooltipProps> = ({
  severity,
  count,
  isActive = true,
  position = 'bottom',
  align = 'center',
  remediationTime,
  config,
  children
}) => {
  const globalConfig = config || getSecScanConfig();
  const data = SEVERITY_REMEDIATION_DATA[severity];

  // Dynamic remediation time resolution:
  // 1. Explicit remediationTime parameter passed into component
  // 2. config.remediationTime[severity] or config.severityConfig[severity].remediationTime from SecScan global config
  // 3. Fallback to default averageRemediationTime
  const dynamicRemediationTime =
    remediationTime ||
    globalConfig.severityConfig?.[severity]?.remediationTime ||
    globalConfig.remediationTime?.[severity] ||
    data.averageRemediationTime;

  const dynamicSlaTarget =
    globalConfig.severityConfig?.[severity]?.slaTarget ||
    data.slaTarget;

  const content = (
    <div
      id={`tooltip-severity-${severity.toLowerCase()}`}
      className={`w-72 sm:w-80 rounded-md border ${data.theme.border} ${data.theme.bg} p-3 shadow-2xl backdrop-blur-md text-left font-mono text-[11px] leading-relaxed text-zinc-200 select-none`}
    >
      {/* Header with Severity Tag, Tier and Count */}
      <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-2 mb-2">
        <div className="flex items-center gap-1.5">
          <span className={`w-2 h-2 rounded-full ${data.theme.dotColor} animate-pulse`} />
          <span className={`font-bold tracking-wider uppercase text-[11px] ${data.theme.titleColor}`}>
            {data.label}
          </span>
          <span className="text-[9.5px] px-1.5 py-0.2 rounded border border-white/10 bg-white/5 text-zinc-400">
            {data.tier.split('•')[0].trim()}
          </span>
        </div>

        {count !== undefined && (
          <span className="text-[10px] text-zinc-400 bg-white/5 px-1.5 py-0.5 rounded border border-white/10">
            {count} achado{count === 1 ? '' : 's'}
          </span>
        )}
      </div>

      {/* Main Focus: Tempo Médio de Remediação (MTTR) & SLA Box */}
      <div className={`p-2 rounded border ${data.theme.highlightBorder} ${data.theme.highlightBg} mb-2.5 space-y-1.5`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-white/90">
            <Clock className={`w-3.5 h-3.5 ${data.theme.titleColor}`} />
            <span className="text-[10px] uppercase font-bold tracking-wider text-zinc-300">
              Tempo Médio de Remediação:
            </span>
          </div>
          <div className="flex items-center gap-1">
            <span className={`text-xs font-black tracking-wide ${data.theme.titleColor}`}>
              {dynamicRemediationTime}
            </span>
            {remediationTime && remediationTime !== data.averageRemediationTime && (
              <span className="text-[8px] uppercase tracking-wider px-1 py-0.2 rounded bg-white/10 text-zinc-300 border border-white/10" title="Valor dinâmico calculado">
                dinâmico
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center justify-between text-[10px] pt-1 border-t border-white/10 text-zinc-400">
          <span className="flex items-center gap-1">
            <Timer className="w-3 h-3 text-zinc-500" />
            <span>SLA Recomendado:</span>
          </span>
          <span className="font-semibold text-zinc-200">{dynamicSlaTarget}</span>
        </div>
      </div>

      {/* Description / Threat Scenario */}
      <div className="space-y-1 mb-2">
        <div className="flex items-center gap-1 text-[9.5px] uppercase font-bold text-zinc-400 tracking-wider">
          <ShieldAlert className="w-3 h-3 text-zinc-500" />
          <span>Impacto & Escopo:</span>
        </div>
        <p className="text-[10.5px] text-zinc-300 leading-snug">
          {data.description}
        </p>
      </div>

      {/* Recommended Action */}
      <div className="space-y-1 border-t border-white/10 pt-2 mb-2">
        <div className="flex items-center gap-1 text-[9.5px] uppercase font-bold text-zinc-400 tracking-wider">
          <Wrench className="w-3 h-3 text-zinc-500" />
          <span>Remediação Imediata:</span>
        </div>
        <p className="text-[10px] text-zinc-400 leading-tight">
          {data.recommendedAction}
        </p>
      </div>

      {/* Footer hint */}
      <div className="pt-1.5 border-t border-white/5 flex items-center justify-between text-[9px] text-zinc-500">
        <span>Estado do filtro: <strong className={isActive ? 'text-emerald-400' : 'text-zinc-500'}>{isActive ? 'Ativo' : 'Oculto'}</strong></span>
        <span className="italic">Clique no badge para alternar</span>
      </div>
    </div>
  );

  return (
    <Tooltip
      content={content}
      position={position}
      align={align}
      id={`tooltip-wrapper-${severity.toLowerCase()}`}
    >
      {children}
    </Tooltip>
  );
};
