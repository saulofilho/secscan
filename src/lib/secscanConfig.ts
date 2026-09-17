import { SecScanGlobalConfig, RemediationSeverityKey } from '../types';
import { safeGetItem, safeSetItem } from './storage';

export const SECSCAN_CONFIG_STORAGE_KEY = 'secscan_global_config_v1';

/**
 * Default global SecScan configuration containing the remediationTime (MTTR) parameters
 * for each severity level (CRITICAL, HIGH, WARNING).
 */
export const DEFAULT_SECSCAN_CONFIG: SecScanGlobalConfig = {
  version: '1.0.0',
  appName: 'SecScan AppSec Suite',
  // Direct parameter mapping for quick lookup: config.remediationTime[severity]
  remediationTime: {
    CRITICAL: '1.5h – 2h',
    HIGH: '4h – 6h',
    WARNING: '12h – 24h',
  },
  // Detailed severity configuration object: config.severityConfig[severity].remediationTime
  severityConfig: {
    CRITICAL: {
      remediationTime: '1.5h – 2h',
      slaTarget: '0h – 4h (Imediato)',
      tier: 'Tier 0 • Bloqueador Imediato',
      badgeCode: 'P0 - CRÍTICO',
      urgencyLevel: 'Urgência Máxima • Bloqueio de Pipeline',
      description: 'Credenciais mestre de nuvem, chaves privadas e tokens de acesso irrestrito expostos diretamente no código.',
      recommendedAction: 'Inativar e revogar chave no IAM imediatamente, rotacionar segredo e purgar histórico com git-filter-repo.',
    },
    HIGH: {
      remediationTime: '4h – 6h',
      slaTarget: '≤ 24h (Próximo Dia Útil)',
      tier: 'Tier 1 • Alta Prioridade',
      badgeCode: 'P1 - ALTO',
      urgencyLevel: 'Alta Urgência • Risco Financeiro & Operacional',
      description: 'Chaves de API de terceiros (pagamentos, LLMs, emails), JWTs com assinaturas fracas ou tokens de escrita.',
      recommendedAction: 'Rotacionar no console do fornecedor terceiro, isolar em variáveis (.env) e auditar logs de requisições.',
    },
    WARNING: {
      remediationTime: '12h – 24h',
      slaTarget: '≤ 72h a 7 dias (Sprint Atual)',
      tier: 'Tier 2 • Risco Moderado & Higiene',
      badgeCode: 'P2 - AVISO',
      urgencyLevel: 'Higiene de Código & Débito Técnico',
      description: 'Segredos em ambiente de testes/staging, endpoints de debug, senhas em scripts locais ou boas práticas negligenciadas.',
      recommendedAction: 'Sanitizar variáveis locais, incluir arquivos no .gitignore e habilitar pre-commit hooks de auditoria.',
    },
  },
  dynamicMttrCalculation: true,
  maxAllowedMttrHours: 4.0,
};

/**
 * Extracts the maximum (upper bound) hours from a remediation string.
 * E.g. "1.5h – 2h" -> 2.0, "30m – 1h" -> 1.0, "12h – 24h" -> 24.0, "4h" -> 4.0
 */
export function parseMaxRemediationHours(remediationStr?: string, fallbackHours: number = 4.0): number {
  if (!remediationStr) return fallbackHours;
  const matches = Array.from(remediationStr.matchAll(/([\d.]+)\s*(h|m|d)?/gi));
  if (matches.length === 0) return fallbackHours;

  const values: number[] = [];
  for (const match of matches) {
    const num = parseFloat(match[1]);
    const unit = (match[2] || 'h').toLowerCase();
    if (isNaN(num)) continue;
    if (unit === 'm') values.push(num / 60);
    else if (unit === 'd') values.push(num * 24);
    else values.push(num);
  }

  if (values.length === 0) return fallbackHours;
  return Number(Math.max(...values).toFixed(2));
}

/**
 * Retrieves the global SecScan configuration, merging saved overrides from storage
 * and ensuring window.SECSCAN_GLOBAL_CONFIG is synchronized.
 */
export function getSecScanConfig(): SecScanGlobalConfig {
  const raw = safeGetItem(SECSCAN_CONFIG_STORAGE_KEY);
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        const merged: SecScanGlobalConfig = {
          ...DEFAULT_SECSCAN_CONFIG,
          ...parsed,
          maxAllowedMttrHours:
            typeof parsed.maxAllowedMttrHours === 'number' && !isNaN(parsed.maxAllowedMttrHours)
              ? parsed.maxAllowedMttrHours
              : DEFAULT_SECSCAN_CONFIG.maxAllowedMttrHours,
          remediationTime: {
            ...DEFAULT_SECSCAN_CONFIG.remediationTime,
            ...(parsed.remediationTime || {}),
          },
          severityConfig: {
            CRITICAL: {
              ...DEFAULT_SECSCAN_CONFIG.severityConfig.CRITICAL,
              ...(parsed.severityConfig?.CRITICAL || {}),
              remediationTime:
                parsed.severityConfig?.CRITICAL?.remediationTime ||
                parsed.remediationTime?.CRITICAL ||
                DEFAULT_SECSCAN_CONFIG.severityConfig.CRITICAL.remediationTime,
            },
            HIGH: {
              ...DEFAULT_SECSCAN_CONFIG.severityConfig.HIGH,
              ...(parsed.severityConfig?.HIGH || {}),
              remediationTime:
                parsed.severityConfig?.HIGH?.remediationTime ||
                parsed.remediationTime?.HIGH ||
                DEFAULT_SECSCAN_CONFIG.severityConfig.HIGH.remediationTime,
            },
            WARNING: {
              ...DEFAULT_SECSCAN_CONFIG.severityConfig.WARNING,
              ...(parsed.severityConfig?.WARNING || {}),
              remediationTime:
                parsed.severityConfig?.WARNING?.remediationTime ||
                parsed.remediationTime?.WARNING ||
                DEFAULT_SECSCAN_CONFIG.severityConfig.WARNING.remediationTime,
            },
          },
        };

        if (typeof window !== 'undefined') {
          (window as unknown as { SECSCAN_GLOBAL_CONFIG?: SecScanGlobalConfig }).SECSCAN_GLOBAL_CONFIG = merged;
        }
        return merged;
      }
    } catch {
      // Return default on error
    }
  }

  if (typeof window !== 'undefined') {
    (window as unknown as { SECSCAN_GLOBAL_CONFIG?: SecScanGlobalConfig }).SECSCAN_GLOBAL_CONFIG = DEFAULT_SECSCAN_CONFIG;
  }
  return DEFAULT_SECSCAN_CONFIG;
}

/**
 * Updates the global SecScan configuration and persists it in storage.
 */
export function saveSecScanConfig(config: Partial<SecScanGlobalConfig>): SecScanGlobalConfig {
  const current = getSecScanConfig();
  const updated: SecScanGlobalConfig = {
    ...current,
    ...config,
    remediationTime: {
      ...current.remediationTime,
      ...(config.remediationTime || {}),
    },
    severityConfig: {
      CRITICAL: {
        ...current.severityConfig.CRITICAL,
        ...(config.severityConfig?.CRITICAL || {}),
        remediationTime:
          config.severityConfig?.CRITICAL?.remediationTime ||
          config.remediationTime?.CRITICAL ||
          current.severityConfig.CRITICAL.remediationTime,
      },
      HIGH: {
        ...current.severityConfig.HIGH,
        ...(config.severityConfig?.HIGH || {}),
        remediationTime:
          config.severityConfig?.HIGH?.remediationTime ||
          config.remediationTime?.HIGH ||
          current.severityConfig.HIGH.remediationTime,
      },
      WARNING: {
        ...current.severityConfig.WARNING,
        ...(config.severityConfig?.WARNING || {}),
        remediationTime:
          config.severityConfig?.WARNING?.remediationTime ||
          config.remediationTime?.WARNING ||
          current.severityConfig.WARNING.remediationTime,
      },
    },
  };

  safeSetItem(SECSCAN_CONFIG_STORAGE_KEY, JSON.stringify(updated));
  if (typeof window !== 'undefined') {
    (window as unknown as { SECSCAN_GLOBAL_CONFIG?: SecScanGlobalConfig }).SECSCAN_GLOBAL_CONFIG = updated;
    window.dispatchEvent(new CustomEvent('secscan-config-changed', { detail: updated }));
  }
  return updated;
}

/**
 * Updates the remediationTime parameter for a single severity level.
 */
export function updateSeverityRemediationTime(
  severity: RemediationSeverityKey,
  remediationTime: string
): SecScanGlobalConfig {
  const current = getSecScanConfig();
  const newRemediationTimes = {
    ...current.remediationTime,
    [severity]: remediationTime,
  };
  const newSeverityConfig = {
    ...current.severityConfig,
    [severity]: {
      ...current.severityConfig[severity],
      remediationTime,
    },
  };

  return saveSecScanConfig({
    remediationTime: newRemediationTimes,
    severityConfig: newSeverityConfig,
  });
}

/**
 * Returns dynamic remediation time based on findings count or configured defaults.
 */
export function calculateDynamicRemediationTime(
  severity: RemediationSeverityKey,
  count?: number,
  baseConfig?: SecScanGlobalConfig
): string {
  const config = baseConfig || getSecScanConfig();
  const configuredTime =
    config.severityConfig?.[severity]?.remediationTime ||
    config.remediationTime?.[severity] ||
    DEFAULT_SECSCAN_CONFIG.remediationTime[severity];

  if (!count || count <= 1) {
    return configuredTime;
  }

  // If there are multiple findings, dynamically compute backlog remediation time based on configured unit MTTR
  if (severity === 'CRITICAL') {
    const minHours = (1.5 * count * 0.85).toFixed(1);
    const maxHours = (2.0 * count * 0.95).toFixed(1);
    return `${minHours}h – ${maxHours}h (${count}x)`;
  } else if (severity === 'HIGH') {
    const minHours = Math.round(4 * count * 0.75);
    const maxHours = Math.round(6 * count * 0.85);
    return `${minHours}h – ${maxHours}h (${count}x)`;
  } else {
    const minHours = Math.round(12 * count * 0.7);
    const maxHours = Math.round(24 * count * 0.8);
    const daysMin = (minHours / 24).toFixed(1);
    const daysMax = (maxHours / 24).toFixed(1);
    return `${daysMin}d – ${daysMax}d (${count}x)`;
  }
}
