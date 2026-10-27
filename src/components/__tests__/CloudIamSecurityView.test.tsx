import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { CloudIamSecurityView } from '../CloudIamSecurityView';

describe('CloudIamSecurityView', () => {
  it('monta CloudIamSecurityView com as props do contrato', () => {
    const view = renderWithProviders(<CloudIamSecurityView {...({ onNavigateToScanner: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
