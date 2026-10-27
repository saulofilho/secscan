import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { QuickTourModal } from '../QuickTourModal';

describe('QuickTourModal', () => {
  it('monta QuickTourModal com as props do contrato', () => {
    const view = renderWithProviders(<QuickTourModal {...({ isOpen: true, onClose: (..._args) => {}, onNavigateToTab: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
