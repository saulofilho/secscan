import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { SecurityHeadersView } from '../SecurityHeadersView';

describe('SecurityHeadersView', () => {
  it('monta SecurityHeadersView com as props do contrato', () => {
    const view = renderWithProviders(<SecurityHeadersView {...({ onNavigateToScanner: (..._args) => {}, onNavigateToEndpoints: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
