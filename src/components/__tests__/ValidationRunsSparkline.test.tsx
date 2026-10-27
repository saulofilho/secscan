import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { ValidationRunsSparkline } from '../ValidationRunsSparkline';

describe('ValidationRunsSparkline', () => {
  it('monta ValidationRunsSparkline com as props do contrato', () => {
    const view = renderWithProviders(<ValidationRunsSparkline {...({ distribution: { critical: 1, high: 1, warning: 1, total: 1 }, fileSetKey: 'teste' } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
