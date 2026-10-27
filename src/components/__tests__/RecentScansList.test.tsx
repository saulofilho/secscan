import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { FindingsTrendSparkline, RecentScansList } from '../RecentScansList';

describe('RecentScansList', () => {
  it('monta FindingsTrendSparkline com as props do contrato', () => {
    const view = renderWithProviders(<FindingsTrendSparkline {...({ currentCount: 1, previousCount: 1, historyPoints: [1], hasPredecessor: false, className: 'unit-test' } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });

  it('monta RecentScansList com as props do contrato', () => {
    const view = renderWithProviders(<RecentScansList {...({ scanHistory: [{ id: 'unit-test-id', timestamp: '2026-01-15T12:00:00.000Z', target: 'teste', totalFiles: 1, scannedFilesCount: 1, ignoredFilesCount: 1, findings: [{ id: 'unit-test-id', ruleId: 'teste', ruleName: 'teste', category: "API_KEY", severity: "HIGH", file: 'src/unit-test.ts', line: 1, column: 1, snippet: 'teste', matchedSecret: 'teste', maskedSecret: 'teste', entropy: 1, description: 'teste', remediation: 'teste', timestamp: '2026-01-15T12:00:00.000Z' }], apiEndpoints: [{ id: 'unit-test-id', file: 'src/unit-test.ts', line: 1, path: 'src/unit-test.ts', isInternalOrAdmin: false, snippet: 'teste' }], metrics: { criticalCount: 1, highCount: 1, mediumCount: 1, lowCount: 1, infoCount: 1, securityScore: 1, securityImpactScore: 1, impactLevel: "HIGH", totalWeightedRisk: 1, riskScore: 1, riskLevel: "HIGH", criticalityDistribution: { criticalFiles: 1, highFiles: 1, mediumFiles: 1, lowFiles: 1 }, averageEntropy: 1 }, durationMs: 1 }], onSelectFinding: (..._args) => {}, onNavigateToScanner: (..._args) => {}, onNavigateToTrends: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
