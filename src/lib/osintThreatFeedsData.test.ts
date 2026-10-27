import { describe, expect, it } from 'vitest';
import { getThreatIntelSummary, lookupThreatIndicator } from './osintThreatFeedsData';

describe('threat intel catalog', () => {
  it('não trata ausência no catálogo como alvo limpo', () => {
    const result = lookupThreatIndicator('indicador-que-nao-existe.example');
    expect(result.verdict).toBe('NOT_IN_LOCAL_CATALOG');
    expect(result.matched).toBe(false);
    expect(result.catalogMode).toBe('LOCAL_SAMPLE');
  });

  it('conta só os indicadores da amostra e marca a fonte como catálogo local', () => {
    const summary = getThreatIntelSummary();
    const listed = summary.sourcesOnline.reduce((total, source) => total + source.indicatorsCount, 0);
    expect(summary.catalogMode).toBe('LOCAL_SAMPLE');
    expect(summary.totalIndicators).toBe(listed);
    expect(summary.sourcesOnline.every((source) => source.status === 'LOCAL_CATALOG')).toBe(true);
    expect(summary.sourcesOnline.every((source) => source.latencyMs === 0)).toBe(true);
  });
});
