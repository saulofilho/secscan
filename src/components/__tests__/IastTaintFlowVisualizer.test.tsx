import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { IastTaintFlowVisualizer } from '../IastTaintFlowVisualizer';

describe('IastTaintFlowVisualizer', () => {
  it('monta IastTaintFlowVisualizer com as props do contrato', () => {
    const view = renderWithProviders(<IastTaintFlowVisualizer {...({ finding: { id: 'unit-test-id', title: 'Teste unitário', cwe: { id: 'unit-test-id', name: 'Teste unitário' }, owaspCategory: 'teste', severity: "HIGH", confidence: 1, status: "CONFIRMED", sourceEndpoint: 'teste', httpMethod: "GET", taintedParameter: 'teste', simulatedPayload: 'teste', sinkFunction: 'teste', sinkFile: 'teste', sinkLine: 1, tracePath: [{ stepIndex: 1, hookId: 'teste', hookCategory: "HTTP_REQUEST_SOURCE", file: 'src/unit-test.ts', line: 1, functionName: 'teste', variableName: 'teste', runtimeValue: 'teste', isTainted: false, description: 'teste' }], runtimeCallStack: ['teste'], vulnerabilityExplanation: 'teste', runtimeEvidence: { executedQueryOrCommand: 'teste', unfilteredTaintSubstring: 'teste', sanitizerBypassed: 'teste', runtimeDurationMs: 1 }, remediationAdvice: 'teste', remediationCodeExample: { vulnerable: 'teste', secure: 'teste' } }, allHooks: [{ id: 'unit-test-id', name: 'Teste unitário', category: "HTTP_REQUEST_SOURCE", targetPackageOrGlobal: 'teste', active: true, interceptedCallsCount: 1, vulnerabilitiesTriggeredCount: 1, description: 'teste' }], onSelectFile: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
