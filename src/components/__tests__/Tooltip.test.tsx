import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { Tooltip, SeverityTooltip } from '../Tooltip';

describe('Tooltip', () => {
  it('monta Tooltip com as props do contrato', () => {
    const view = renderWithProviders(<Tooltip {...({ content: 'teste', children: 'conteudo', position: "top", align: "right", className: 'unit-test', delayMs: 1, id: 'unit-test-id' } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });

  it('monta SeverityTooltip com as props do contrato', () => {
    const view = renderWithProviders(<SeverityTooltip {...({ severity: "HIGH", count: 1, isActive: false, position: "top", align: "right", remediationTime: 'teste', children: 'conteudo' } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
