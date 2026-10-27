import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { LanguageSwitcher } from '../LanguageSwitcher';

describe('LanguageSwitcher', () => {
  it('monta LanguageSwitcher com as props do contrato', () => {
    const view = renderWithProviders(<LanguageSwitcher {...({ className: 'unit-test', compact: false } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
