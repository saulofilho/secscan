import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { BenchmarkInfoTooltip, MttrMiniTrendlineChart } from '../MttrMiniTrendlineChart';

describe('MttrMiniTrendlineChart', () => {
  it('monta BenchmarkInfoTooltip com as props do contrato', () => {
    const view = renderWithProviders(<BenchmarkInfoTooltip {...({ id: 'unit-test-id', suggestion: { title: 'Teste unitário', advice: 'teste', action: 'teste', level: "success" }, currentMttr: 1, benchmark: 1, maxLimit: 1, position: "top" } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });

  it('monta MttrMiniTrendlineChart com as props do contrato', () => {
    const view = renderWithProviders(<MttrMiniTrendlineChart {...({ distribution: { critical: 1, high: 1, warning: 1, total: 1 }, config: { version: 'teste', appName: 'teste', remediationTime: { CRITICAL: 'teste', HIGH: 'teste', WARNING: 'teste' }, severityConfig: { CRITICAL: { remediationTime: 'teste' }, HIGH: { remediationTime: 'teste' }, WARNING: { remediationTime: 'teste' } }, dynamicMttrCalculation: false, maxAllowedMttrHours: 1, idealBenchmarkMttrHours: 1 }, fileSetKey: 'teste', onOpenMttrConfig: (..._args) => {}, onSelectScan: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
