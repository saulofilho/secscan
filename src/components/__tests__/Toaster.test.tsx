import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { Toaster } from '../Toaster';

describe('Toaster', () => {
  it('monta Toaster com as props do contrato', () => {
    const view = renderWithProviders(<Toaster {...({} as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
