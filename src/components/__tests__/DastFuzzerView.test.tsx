import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { DastFuzzerView } from '../DastFuzzerView';

describe('DastFuzzerView', () => {
  it('monta DastFuzzerView com as props do contrato', () => {
    const view = renderWithProviders(<DastFuzzerView {...({ endpoints: [{ id: 'unit-test-id', file: 'src/unit-test.ts', line: 1, method: "GET", path: 'src/unit-test.ts', isInternalOrAdmin: false, snippet: 'teste', urlType: "RELATIVE_PATH", scope: "IN_SCOPE", params: ['teste'], sourceTool: "LINK_FINDER", curlCommand: 'teste' }], onLogAudit: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
