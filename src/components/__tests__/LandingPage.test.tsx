import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { LandingPage } from '../LandingPage';

describe('LandingPage', () => {
  it('monta LandingPage com as props do contrato', () => {
    const view = renderWithProviders(<LandingPage {...({ onEnterApp: (..._args) => {}, onOpenUrlIngest: (..._args) => {}, onIngestUrlFiles: (..._args) => {} } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });
});
