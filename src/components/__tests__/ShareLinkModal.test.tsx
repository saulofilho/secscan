import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { ShareLinkModal } from '../ShareLinkModal';

describe('ShareLinkModal', () => {
  it('monta ShareLinkModal com as props do contrato', () => {
    const view = renderWithProviders(<ShareLinkModal {...({ isOpen: true, onClose: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
