import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { UrlIngestModal } from '../UrlIngestModal';

describe('UrlIngestModal', () => {
  it('monta UrlIngestModal com as props do contrato', () => {
    const view = renderWithProviders(<UrlIngestModal {...({ isOpen: true, onClose: (..._args) => {}, onIngestSuccess: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
