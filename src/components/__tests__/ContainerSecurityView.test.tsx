import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { ContainerSecurityView } from '../ContainerSecurityView';

describe('ContainerSecurityView', () => {
  it('monta ContainerSecurityView com as props do contrato', () => {
    const view = renderWithProviders(<ContainerSecurityView {...({ files: [{ name: 'Teste unitário', path: 'src/unit-test.ts', content: 'teste', size: 1, extension: 'teste', isIgnored: false, ignoreReason: 'teste', findingsCount: 1 }], onNavigateToScanner: (..._args) => {}, onApplyHardenedDockerfile: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
