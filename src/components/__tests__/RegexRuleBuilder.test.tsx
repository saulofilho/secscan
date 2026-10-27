import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { RegexRuleBuilder } from '../RegexRuleBuilder';

describe('RegexRuleBuilder', () => {
  it('monta RegexRuleBuilder com as props do contrato', () => {
    const view = renderWithProviders(<RegexRuleBuilder {...({ onAddRule: (..._args) => {}, onSendToPlayground: (..._args) => {}, onOpenAdvancedModal: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
