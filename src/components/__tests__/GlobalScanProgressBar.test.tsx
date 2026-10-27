import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { GlobalScanProgressBar } from '../GlobalScanProgressBar';

describe('GlobalScanProgressBar', () => {
  it('monta GlobalScanProgressBar com as props do contrato', () => {
    const view = renderWithProviders(<GlobalScanProgressBar {...({ isScanning: false, progress: { percentage: 1, currentFileIndex: 1, totalFiles: 1, currentFileName: 'teste', currentFilePath: 'teste', phase: "LINK_FINDER", phaseLabel: 'teste', findingsFoundCount: 1, scannedCount: 1, ignoredCount: 1, elapsedMs: 1 }, onCancelScan: (..._args) => {}, onTriggerScan: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
