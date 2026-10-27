import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { SecurityGlossaryTooltip, SecurityGlossaryInlineCard, SecurityGlossaryModal } from '../SecurityGlossary';

describe('SecurityGlossary', () => {
  it('monta SecurityGlossaryTooltip com as props do contrato', () => {
    const view = renderWithProviders(<SecurityGlossaryTooltip {...({ onOpenFullGlossary: (..._args) => {}, className: 'unit-test', variant: "badge" } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });

  it('monta SecurityGlossaryInlineCard com as props do contrato', () => {
    const view = renderWithProviders(<SecurityGlossaryInlineCard {...({ finding: { id: 'unit-test-id', ruleId: 'teste', ruleName: 'teste', category: "API_KEY", severity: "HIGH", file: 'src/unit-test.ts', line: 1, column: 1, snippet: 'teste', matchedSecret: 'teste', maskedSecret: 'teste', entropy: 1, description: 'teste', remediation: 'teste', timestamp: '2026-01-15T12:00:00.000Z', isFalsePositive: false, fileCriticality: "CRITICAL", fileCriticalityWeight: 1, weightedScore: 1, riskScore: 1, documentationLinks: [{ provider: "OWASP", title: 'Teste unitário', url: 'teste', badge: 'teste' }] }, onOpenFullGlossary: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });

  it('monta SecurityGlossaryModal com as props do contrato', () => {
    const view = renderWithProviders(<SecurityGlossaryModal {...({ isOpen: true, onClose: (..._args) => {}, initialSelectedId: 'teste', selectedEntryId: 'teste' } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
