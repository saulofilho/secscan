import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { DataFlowGraphView } from '../DataFlowGraphView';

describe('DataFlowGraphView', () => {
  it('monta DataFlowGraphView com as props do contrato', () => {
    const view = renderWithProviders(<DataFlowGraphView {...({ files: [{ name: 'Teste unitário', path: 'src/unit-test.ts', content: 'teste', size: 1, extension: 'teste', isIgnored: false, ignoreReason: 'teste', findingsCount: 1 }], onSelectFile: (..._args) => {}, findings: [{ id: 'unit-test-id', ruleId: 'teste', ruleName: 'teste', category: "API_KEY", severity: "HIGH", file: 'src/unit-test.ts', line: 1, column: 1, snippet: 'teste', matchedSecret: 'teste', maskedSecret: 'teste', entropy: 1, description: 'teste', remediation: 'teste', timestamp: '2026-01-15T12:00:00.000Z', isFalsePositive: false, fileCriticality: "CRITICAL", fileCriticalityWeight: 1, weightedScore: 1, riskScore: 1, documentationLinks: [{ provider: "OWASP", title: 'Teste unitário', url: 'teste', badge: 'teste' }] }], apiEndpoints: [{ id: 'unit-test-id', file: 'src/unit-test.ts', line: 1, method: "GET", path: 'src/unit-test.ts', isInternalOrAdmin: false, snippet: 'teste', urlType: "RELATIVE_PATH", scope: "IN_SCOPE", params: ['teste'], sourceTool: "LINK_FINDER", curlCommand: 'teste' }], onNavigateToTab: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
