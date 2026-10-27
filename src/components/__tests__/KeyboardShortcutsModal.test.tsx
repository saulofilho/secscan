import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { KeyboardShortcutsModal } from '../KeyboardShortcutsModal';

describe('KeyboardShortcutsModal', () => {
  it('monta KeyboardShortcutsModal com as props do contrato', () => {
    const view = renderWithProviders(<KeyboardShortcutsModal {...({ isOpen: true, onClose: (..._args) => {}, onOpenCommandPalette: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
