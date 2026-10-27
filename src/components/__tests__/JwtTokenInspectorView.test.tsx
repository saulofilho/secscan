import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { JwtTokenInspectorView } from '../JwtTokenInspectorView';

describe('JwtTokenInspectorView', () => {
  it('monta JwtTokenInspectorView com as props do contrato', () => {
    const view = renderWithProviders(<JwtTokenInspectorView {...({ onNavigateToScanner: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
