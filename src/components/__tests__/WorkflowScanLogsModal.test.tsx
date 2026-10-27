import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { WorkflowScanLogsModal } from '../WorkflowScanLogsModal';

describe('WorkflowScanLogsModal', () => {
  it('monta WorkflowScanLogsModal com as props do contrato', () => {
    const view = renderWithProviders(<WorkflowScanLogsModal {...({ run: { id: 'unit-test-id', runNumber: 1, title: 'Teste unitário', event: "push", status: "completed", conclusion: "success", branch: 'teste', commitSha: 'teste', commitMessage: 'teste', actor: { name: 'Teste unitário', avatar: 'teste', isBot: false }, startedAt: 'teste', durationSeconds: 1, findingsCount: { critical: 1, high: 1, medium: 1, low: 1, total: 1 }, riskScore: 1, qualityGateStatus: "PASSED", sarifUploaded: false, workflowFile: 'teste', steps: [{ id: 'unit-test-id', name: 'Teste unitário', status: "success", durationSeconds: 1, lines: [{ timestamp: '2026-01-15T12:00:00.000Z', level: "INFO", message: 'teste' }] }], rawLogs: 'teste' }, isOpen: true, onClose: (..._args) => {}, onSelectFinding: (..._args) => {}, allFindings: [{ id: 'unit-test-id', ruleId: 'teste', ruleName: 'teste', category: "API_KEY", severity: "HIGH", file: 'src/unit-test.ts', line: 1, column: 1, snippet: 'teste', matchedSecret: 'teste', maskedSecret: 'teste', entropy: 1, description: 'teste', remediation: 'teste', timestamp: '2026-01-15T12:00:00.000Z', isFalsePositive: false, fileCriticality: "CRITICAL", fileCriticalityWeight: 1, weightedScore: 1, riskScore: 1, documentationLinks: [{ provider: "OWASP", title: 'Teste unitário', url: 'teste', badge: 'teste' }] }] } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
