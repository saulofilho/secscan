import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { LlmSecurityView } from '../LlmSecurityView';

describe('LlmSecurityView', () => {
  it('monta LlmSecurityView com as props do contrato', () => {
    const view = renderWithProviders(<LlmSecurityView {...({ onNavigateToScanner: (..._args) => {}, onLogAudit: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
