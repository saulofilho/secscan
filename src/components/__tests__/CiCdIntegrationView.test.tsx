import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { CiCdIntegrationView } from '../CiCdIntegrationView';

describe('CiCdIntegrationView', () => {
  it('monta CiCdIntegrationView com as props do contrato', () => {
    const view = renderWithProviders(<CiCdIntegrationView {...({ report: { id: 'unit-test-id', timestamp: '2026-01-15T12:00:00.000Z', target: 'teste', totalFiles: 1, scannedFilesCount: 1, ignoredFilesCount: 1, findings: [{ id: 'unit-test-id', ruleId: 'teste', ruleName: 'teste', category: "API_KEY", severity: "HIGH", file: 'src/unit-test.ts', line: 1, column: 1, snippet: 'teste', matchedSecret: 'teste', maskedSecret: 'teste', entropy: 1, description: 'teste', remediation: 'teste', timestamp: '2026-01-15T12:00:00.000Z' }], apiEndpoints: [{ id: 'unit-test-id', file: 'src/unit-test.ts', line: 1, path: 'src/unit-test.ts', isInternalOrAdmin: false, snippet: 'teste' }], metrics: { criticalCount: 1, highCount: 1, mediumCount: 1, lowCount: 1, infoCount: 1, securityScore: 1, securityImpactScore: 1, impactLevel: "HIGH", totalWeightedRisk: 1, riskScore: 1, riskLevel: "HIGH", criticalityDistribution: { criticalFiles: 1, highFiles: 1, mediumFiles: 1, lowFiles: 1 }, averageEntropy: 1, averageRiskScore: 1, maxRiskScore: 1, linkFinderTotalEndpoints: 1, jsMinerTotalAssets: 1, jsMinerCloudBucketsCount: 1, jsMinerSourceMapsCount: 1, jsMinerDangerousSinksCount: 1 }, durationMs: 1 }, rules: [{ id: 'unit-test-id', name: 'Teste unitário', pattern: 'teste', flags: 'teste', category: "API_KEY", severity: "HIGH", description: 'teste', remediation: 'teste', minEntropy: 1, enabled: true, isCustom: false, tags: ['teste'], exampleMatch: 'teste' }], ignorePatterns: [{ id: 'unit-test-id', pattern: 'teste', enabled: true, description: 'teste', isBuiltIn: false, createdAt: '2026-01-15T12:00:00.000Z' }], onNavigateToPipelineFlow: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
