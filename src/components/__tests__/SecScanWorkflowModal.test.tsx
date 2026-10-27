import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { SecScanWorkflowModal } from '../SecScanWorkflowModal';

describe('SecScanWorkflowModal', () => {
  it('monta SecScanWorkflowModal com as props do contrato', () => {
    const view = renderWithProviders(<SecScanWorkflowModal {...({ isOpen: true, onClose: (..._args) => {}, rules: [{ id: 'unit-test-id', name: 'Teste unitário', pattern: 'teste', flags: 'teste', category: "API_KEY", severity: "HIGH", description: 'teste', remediation: 'teste', minEntropy: 1, enabled: true, isCustom: false, tags: ['teste'], exampleMatch: 'teste' }], ignorePatterns: [{ id: 'unit-test-id', pattern: 'teste', enabled: true, description: 'teste', isBuiltIn: false, createdAt: '2026-01-15T12:00:00.000Z' }] } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
