import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { ThreatHeatmap } from '../ThreatHeatmap';

describe('ThreatHeatmap', () => {
  it('monta ThreatHeatmap com as props do contrato', () => {
    const view = renderWithProviders(<ThreatHeatmap {...({ findings: [{ id: 'unit-test-id', ruleId: 'teste', ruleName: 'teste', category: "API_KEY", severity: "HIGH", file: 'src/unit-test.ts', line: 1, column: 1, snippet: 'teste', matchedSecret: 'teste', maskedSecret: 'teste', entropy: 1, description: 'teste', remediation: 'teste', timestamp: '2026-01-15T12:00:00.000Z', isFalsePositive: false, fileCriticality: "CRITICAL", fileCriticalityWeight: 1, weightedScore: 1, riskScore: 1, documentationLinks: [{ provider: "OWASP", title: 'Teste unitário', url: 'teste', badge: 'teste' }] }], actors: [{ id: 'unit-test-id', name: 'Teste unitário', codeName: 'teste', aliases: ['teste'], origin: 'teste', motivation: "FINANCIAL", activeSectors: ['teste'], associatedMalware: ['teste'], targetedTechnologies: ['teste'], ttps: [{ techniqueId: 'teste', name: 'Teste unitário', tactic: 'teste' }], threatScore: 1, activeCampaigns: ['teste'], recentIocSignatures: ['teste'], description: 'teste', firstObserved: 'teste', lastActive: 'teste' }], pulses: [{ id: 'unit-test-id', name: 'Teste unitário', author: 'teste', description: 'teste', created: 'teste', modified: 'teste', tlp: "WHITE", tags: ['teste'], adversary: 'teste', targetedCountries: ['teste'], malwareFamilies: ['teste'], subscriberCount: 1, iocs: [{ id: 'unit-test-id', type: "IPv4", indicator: 'teste', confidence: 1, severity: "HIGH", firstSeen: 'teste', lastSeen: 'teste', sourceFeed: "ALIENVAULT_OTX", maliciousContext: 'teste' }], cves: ['teste'], referenceUrl: 'teste' }], onSelectFinding: (..._args) => {}, onNavigateToScanner: (..._args) => {}, onApplyTags: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
