import { describe, expect, it, vi } from 'vitest';
import { renderWithProviders } from '../../test/renderWithProviders';
import { ErrorBoundary } from '../ErrorBoundary';

describe('ErrorBoundary', () => {
  it('monta ErrorBoundary com as props do contrato', () => {
    const view = renderWithProviders(<ErrorBoundary {...({ children: 'conteudo' } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });

  it('mostra a falha de renderização capturada', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const Bomb = () => {
      throw new Error('render-boundary-error');
    };
    const view = renderWithProviders(
      <ErrorBoundary>
        <Bomb />
      </ErrorBoundary>
    );
    expect(view.container).toHaveTextContent('SecScan Engine Error');
    expect(view.container).toHaveTextContent('render-boundary-error');
    view.unmount();
    spy.mockRestore();
  });
});
