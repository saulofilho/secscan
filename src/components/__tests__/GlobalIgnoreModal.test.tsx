import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { GlobalIgnoreModal } from '../GlobalIgnoreModal';

describe('GlobalIgnoreModal', () => {
  it('monta GlobalIgnoreModal com as props do contrato', () => {
    const view = renderWithProviders(<GlobalIgnoreModal {...({ isOpen: true, onClose: (..._args) => {}, patterns: [{ id: 'unit-test-id', pattern: 'teste', enabled: true, description: 'teste', isBuiltIn: false, createdAt: '2026-01-15T12:00:00.000Z' }], onUpdatePatterns: (..._args) => {}, onSavePatterns: (..._args) => {}, onTogglePattern: (..._args) => {}, workspaceFiles: [{ name: 'Teste unitário', path: 'src/unit-test.ts', content: 'teste', size: 1, extension: 'teste', isIgnored: false, ignoreReason: 'teste', findingsCount: 1 }], onTriggerRescan: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
