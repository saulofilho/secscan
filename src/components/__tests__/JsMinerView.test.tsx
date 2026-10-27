import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { JsMinerView } from '../JsMinerView';

describe('JsMinerView', () => {
  it('monta JsMinerView com as props do contrato', () => {
    const view = renderWithProviders(<JsMinerView {...({ onNavigateToDataFlow: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
