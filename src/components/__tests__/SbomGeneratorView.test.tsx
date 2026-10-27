import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { SbomGeneratorView } from '../SbomGeneratorView';

describe('SbomGeneratorView', () => {
  it('monta SbomGeneratorView com as props do contrato', () => {
    const view = renderWithProviders(<SbomGeneratorView {...({ files: [{ name: 'Teste unitário', path: 'src/unit-test.ts', content: 'teste', size: 1, extension: 'teste', isIgnored: false, ignoreReason: 'teste', findingsCount: 1 }] } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
