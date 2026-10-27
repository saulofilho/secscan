import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { CustomRulesView } from '../CustomRulesView';

describe('CustomRulesView', () => {
  it('monta CustomRulesView com as props do contrato', () => {
    const view = renderWithProviders(<CustomRulesView {...({ rules: [{ id: 'unit-test-id', name: 'Teste unitário', pattern: 'teste', flags: 'teste', category: "API_KEY", severity: "HIGH", description: 'teste', remediation: 'teste', minEntropy: 1, enabled: true, isCustom: false, tags: ['teste'], exampleMatch: 'teste' }], onToggleRule: (..._args) => {}, onAddRule: (..._args) => {}, onDeleteRule: (..._args) => {}, onExportRules: (..._args) => {}, onImportRules: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
