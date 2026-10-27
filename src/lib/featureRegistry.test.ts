import { describe, expect, it } from 'vitest';
import { FEATURE_REGISTRY } from './featureRegistry';

function categoryOf(id: string): string {
  return FEATURE_REGISTRY.find((item) => item.id === id)?.category || '';
}

describe('registro de analytics', () => {
  it('usa as mesmas gavetas do hub', () => {
    expect(categoryOf('iast')).toBe('API_DAST');
    expect(categoryOf('nmap')).toBe('API_DAST');
    expect(categoryOf('nikto')).toBe('API_DAST');
    expect(categoryOf('waf')).toBe('API_DAST');
    expect(categoryOf('edr')).toBe('SOC_EDR');
    expect(categoryOf('dnssec')).toBe('CLOUD_INFRA');
    expect(categoryOf('sdwan')).toBe('CLOUD_INFRA');
    expect(categoryOf('ngfw')).toBe('CLOUD_INFRA');
    expect(new Set(FEATURE_REGISTRY.map((item) => item.id)).size).toBe(FEATURE_REGISTRY.length);
  });
});
