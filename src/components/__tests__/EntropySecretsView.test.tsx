import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { EntropySecretsView } from '../EntropySecretsView';

describe('EntropySecretsView', () => {
  it('monta EntropySecretsView com as props do contrato', () => {
    const view = renderWithProviders(<EntropySecretsView {...({ files: [{ name: 'Teste unitário', path: 'src/unit-test.ts', content: 'teste', size: 1, extension: 'teste', isIgnored: false, ignoreReason: 'teste', findingsCount: 1 }], onNavigateToFile: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
