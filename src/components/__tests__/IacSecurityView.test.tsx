import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { IacSecurityView } from '../IacSecurityView';

describe('IacSecurityView', () => {
  it('monta IacSecurityView com as props do contrato', () => {
    const view = renderWithProviders(<IacSecurityView {...({ files: [{ name: 'Teste unitário', path: 'src/unit-test.ts', content: 'teste', size: 1, extension: 'teste', isIgnored: false, ignoreReason: 'teste', findingsCount: 1 }], onNavigateToFile: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
