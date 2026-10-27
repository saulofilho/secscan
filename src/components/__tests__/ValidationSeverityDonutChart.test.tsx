import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { ValidationSeverityDonutChart } from '../ValidationSeverityDonutChart';

describe('ValidationSeverityDonutChart', () => {
  it('monta ValidationSeverityDonutChart com as props do contrato', () => {
    const view = renderWithProviders(<ValidationSeverityDonutChart {...({ distribution: { critical: 1, high: 1, warning: 1, total: 1 }, onSelectSeverity: (..._args) => {}, fileSetKey: 'teste', riskScore: 1, qualityGateLimit: 1, onSelectScan: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
