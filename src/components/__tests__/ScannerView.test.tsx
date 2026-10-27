import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { ScannerView } from '../ScannerView';

describe('ScannerView', () => {
  it('monta ScannerView com as props do contrato', () => {
    const view = renderWithProviders(<ScannerView {...({ files: [{ name: 'Teste unitário', path: 'src/unit-test.ts', content: 'teste', size: 1, extension: 'teste', isIgnored: false, ignoreReason: 'teste', findingsCount: 1 }], findings: [{ id: 'unit-test-id', ruleId: 'teste', ruleName: 'teste', category: "API_KEY", severity: "HIGH", file: 'src/unit-test.ts', line: 1, column: 1, snippet: 'teste', matchedSecret: 'teste', maskedSecret: 'teste', entropy: 1, description: 'teste', remediation: 'teste', timestamp: '2026-01-15T12:00:00.000Z', isFalsePositive: false, fileCriticality: "CRITICAL", fileCriticalityWeight: 1, weightedScore: 1, riskScore: 1, documentationLinks: [{ provider: "OWASP", title: 'Teste unitário', url: 'teste', badge: 'teste' }] }], selectedFile: { name: 'Teste unitário', path: 'src/unit-test.ts', content: 'teste', size: 1, extension: 'teste', isIgnored: false, ignoreReason: 'teste', findingsCount: 1 }, onSelectFile: (..._args) => {}, onFileUpload: (..._args) => {}, onAddCustomFile: (..._args) => {}, ignorePatterns: [{ id: 'unit-test-id', pattern: 'teste', enabled: true, description: 'teste', isBuiltIn: false, createdAt: '2026-01-15T12:00:00.000Z' }], onOpenIgnoreModal: (..._args) => {}, onQuickIgnore: (..._args) => {}, onOpenGlossary: (..._args) => {}, onOpenRemediationWiki: (..._args) => {}, onApplyFix: (..._args) => {}, onOpenUrlIngest: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
