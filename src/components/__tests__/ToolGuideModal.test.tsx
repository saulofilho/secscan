import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { ToolGuideModal } from '../ToolGuideModal';

describe('ToolGuideModal', () => {
  it('monta ToolGuideModal com as props do contrato', () => {
    const view = renderWithProviders(<ToolGuideModal {...({ isOpen: true, onClose: (..._args) => {}, activeTab: 'dashboard', onNavigateToTab: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
