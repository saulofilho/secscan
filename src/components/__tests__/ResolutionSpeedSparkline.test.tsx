import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { ResolutionSpeedSparkline } from '../ResolutionSpeedSparkline';

describe('ResolutionSpeedSparkline', () => {
  it('monta ResolutionSpeedSparkline com as props do contrato', () => {
    const view = renderWithProviders(<ResolutionSpeedSparkline {...({ totalActiveCount: 1, averageTTRMinutes: 1 } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
