import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { SecScanMttrConfigModal } from '../SecScanMttrConfigModal';

describe('SecScanMttrConfigModal', () => {
  it('monta SecScanMttrConfigModal com as props do contrato', () => {
    const view = renderWithProviders(<SecScanMttrConfigModal {...({ isOpen: true, onClose: (..._args) => {}, config: { version: 'teste', appName: 'teste', remediationTime: { CRITICAL: 'teste', HIGH: 'teste', WARNING: 'teste' }, severityConfig: { CRITICAL: { remediationTime: 'teste' }, HIGH: { remediationTime: 'teste' }, WARNING: { remediationTime: 'teste' } }, dynamicMttrCalculation: false, maxAllowedMttrHours: 1, idealBenchmarkMttrHours: 1 }, onUpdateConfig: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
