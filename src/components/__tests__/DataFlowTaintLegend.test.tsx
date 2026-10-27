import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { DataFlowTaintLegend } from '../DataFlowTaintLegend';

describe('DataFlowTaintLegend', () => {
  it('monta DataFlowTaintLegend com as props do contrato', () => {
    const view = renderWithProviders(<DataFlowTaintLegend {...({ taintFlows: [{ id: 'unit-test-id', variableName: 'teste', sourceNodeId: 'teste', sourceLabel: 'teste', sourceParamOrField: 'teste', intermediateNodeIds: ['teste'], sinkNodeId: 'teste', sinkLabel: 'teste', sinkType: 'teste', pathNodeIds: ['teste'], pathLinkIds: ['teste'], severity: "HIGH", riskCategory: 'teste', description: 'teste', variableTransformSummary: 'teste' }], selectedTaintFlow: { id: 'unit-test-id', variableName: 'teste', sourceNodeId: 'teste', sourceLabel: 'teste', sourceParamOrField: 'teste', intermediateNodeIds: ['teste'], sinkNodeId: 'teste', sinkLabel: 'teste', sinkType: 'teste', pathNodeIds: ['teste'], pathLinkIds: ['teste'], severity: "HIGH", riskCategory: 'teste', description: 'teste', variableTransformSummary: 'teste' }, onSelectTaintFlow: (..._args) => {}, activeStepIndex: 1, onSelectStepIndex: (..._args) => {}, isPlaying: false, onTogglePlay: (..._args) => {}, highlightAllTainted: false, onToggleHighlightAll: (..._args) => {}, showVariableLabels: false, onToggleShowVariableLabels: (..._args) => {}, filterNodeType: "ENDPOINT", onToggleFilterNodeType: (..._args) => {}, onZoomToPath: (..._args) => {}, onInspectNode: (..._args) => {}, nodesMap: {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
