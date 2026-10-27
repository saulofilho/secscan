import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { RegexUnitTestLibrary } from '../RegexUnitTestLibrary';

describe('RegexUnitTestLibrary', () => {
  it('monta RegexUnitTestLibrary com as props do contrato', () => {
    const view = renderWithProviders(<RegexUnitTestLibrary {...({ onLoadTestCaseToSandbox: (..._args) => {}, onClose: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
