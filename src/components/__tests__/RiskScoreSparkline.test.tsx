import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { RiskScoreSparkline } from '../RiskScoreSparkline';

describe('RiskScoreSparkline', () => {
  it('monta RiskScoreSparkline com as props do contrato', () => {
    const view = renderWithProviders(<RiskScoreSparkline {...({ distribution: { critical: 1, high: 1, warning: 1, total: 1 }, riskScore: 1, qualityGateLimit: 1, fileSetKey: 'teste', onSelectScan: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
