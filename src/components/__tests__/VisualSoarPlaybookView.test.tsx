import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { VisualSoarPlaybookView } from '../VisualSoarPlaybookView';

describe('VisualSoarPlaybookView', () => {
  it('monta VisualSoarPlaybookView com as props do contrato', () => {
    const view = renderWithProviders(<VisualSoarPlaybookView {...({ onNavigateToTab: (..._args) => {}, onLogAudit: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
