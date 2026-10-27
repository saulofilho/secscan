import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { SsrfValidatorView } from '../SsrfValidatorView';

describe('SsrfValidatorView', () => {
  it('monta SsrfValidatorView com as props do contrato', () => {
    const view = renderWithProviders(<SsrfValidatorView {...({ onNavigateToScanner: (..._args) => {}, onNavigateToEndpoints: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
