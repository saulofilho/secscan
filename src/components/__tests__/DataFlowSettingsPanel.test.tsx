import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { DataFlowSettingsPanel } from '../DataFlowSettingsPanel';

describe('DataFlowSettingsPanel', () => {
  it('monta DataFlowSettingsPanel com as props do contrato', () => {
    const view = renderWithProviders(<DataFlowSettingsPanel {...({ isOpen: true, onClose: (..._args) => {}, settings: { layoutMode: "HIERARCHICAL", hierarchicalOrientation: "HORIZONTAL", rankSeparation: 1, nodeSeparation: 1, curveStyle: "BEZIER", alignSinksToEnd: false, chargeStrength: 1, linkDistance: 1, collisionRadius: 1, isPhysicsPaused: false, hideIsolatedNodes: false, showLevelGuides: false, highlightTaintEdges: false, highlightTaintedVariables: false, showVariableLabelsOnLinks: false }, onUpdateSettings: (..._args) => {}, onResetDefaults: (..._args) => {}, activeNodesCount: 1, activeLinksCount: 1, totalTaintFlows: 1 } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
