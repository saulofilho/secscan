import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { GitignoreAuditModal } from '../GitignoreAuditModal';

describe('GitignoreAuditModal', () => {
  it('monta GitignoreAuditModal com as props do contrato', () => {
    const view = renderWithProviders(<GitignoreAuditModal {...({ isOpen: true, onClose: (..._args) => {}, files: [{ name: 'Teste unitário', path: 'src/unit-test.ts', content: 'teste', size: 1, extension: 'teste', isIgnored: false, ignoreReason: 'teste', findingsCount: 1 }], onApplyGitignoreToWorkspace: (..._args) => {}, onRemoveFileFromWorkspace: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
