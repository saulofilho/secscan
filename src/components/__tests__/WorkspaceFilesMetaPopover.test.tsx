import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { WorkspaceFilesMetaPopover } from '../WorkspaceFilesMetaPopover';

describe('WorkspaceFilesMetaPopover', () => {
  it('monta WorkspaceFilesMetaPopover com as props do contrato', () => {
    const view = renderWithProviders(<WorkspaceFilesMetaPopover {...({ files: [{ name: 'Teste unitário', path: 'src/unit-test.ts', content: 'teste', size: 1, extension: 'teste', isIgnored: false, ignoreReason: 'teste', findingsCount: 1 }], isOpen: true, onClose: (..._args) => {}, onSelectFile: (..._args) => {}, onBatchQuickIgnore: (..._args) => {}, onBatchDeleteFiles: (..._args) => {}, previousWorkspaceSize: 1, onOpenGitignoreAudit: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
