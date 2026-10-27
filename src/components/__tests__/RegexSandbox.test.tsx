import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { RegexSandbox } from '../RegexSandbox';

describe('RegexSandbox', () => {
  it('monta RegexSandbox com as props do contrato', () => {
    const view = renderWithProviders(<RegexSandbox {...({ initialPattern: 'teste', initialFlags: 'teste', initialText: 'teste', activeRules: [{ id: 'unit-test-id', name: 'Teste unitário', pattern: 'teste', flags: 'teste', category: "API_KEY", severity: "HIGH", description: 'teste', remediation: 'teste', minEntropy: 1, enabled: true, isCustom: false, tags: ['teste'], exampleMatch: 'teste' }], onSaveRule: (..._args) => {}, onOpenManualModal: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
