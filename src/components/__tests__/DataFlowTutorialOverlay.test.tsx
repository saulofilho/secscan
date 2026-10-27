import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { DataFlowTutorialOverlay } from '../DataFlowTutorialOverlay';

describe('DataFlowTutorialOverlay', () => {
  it('monta DataFlowTutorialOverlay com as props do contrato', () => {
    const view = renderWithProviders(<DataFlowTutorialOverlay {...({ isOpen: true, onClose: (..._args) => {}, onSelectLayoutMode: (..._args) => {}, onTriggerZoomToFit: (..._args) => {}, onTogglePanMode: (..._args) => {}, isPanMode: false } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
