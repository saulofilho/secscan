import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { WelcomeWorkspaceModal } from '../WelcomeWorkspaceModal';

describe('WelcomeWorkspaceModal', () => {
  it('monta WelcomeWorkspaceModal com as props do contrato', () => {
    const view = renderWithProviders(<WelcomeWorkspaceModal {...({ isOpen: true, onExploreWithMock: (..._args) => {}, onStartCleanWorkspace: (..._args) => {}, onClose: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
