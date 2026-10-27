import { describe, expect, it } from 'vitest';
import { act } from '@testing-library/react';
import { renderWithProviders } from '../../test/renderWithProviders';
import { GoogleAdBanner } from '../GoogleAdBanner';

describe('GoogleAdBanner', () => {
  it('monta GoogleAdBanner com as props do contrato', () => {
    const view = renderWithProviders(<GoogleAdBanner {...({ client: 'ca-pub-1234567890123456', slot: '1234567890', format: "auto", responsive: true, className: 'unit-test' } as any)} />);
    expect(view.container).toBeInstanceOf(HTMLElement);
    view.unmount();
  });

  it('não renderiza o anúncio sem credenciais', () => {
    const view = renderWithProviders(<GoogleAdBanner />);
    expect(view.container.querySelector('ins.adsbygoogle')).toBeNull();
    view.unmount();
  });

  it('renderiza o slot quando cliente e bloco são informados', () => {
    const view = renderWithProviders(
      <GoogleAdBanner client="ca-pub-1234567890123456" slot="1234567890" />
    );
    const slot = view.container.querySelector('ins.adsbygoogle');
    expect(slot).not.toBeNull();
    expect(slot?.getAttribute('data-ad-client')).toBe('ca-pub-1234567890123456');
    expect(slot?.getAttribute('data-ad-slot')).toBe('1234567890');
    view.unmount();
  });

  it('inicializa um novo slot ao reativar a exibição', () => {
    const view = renderWithProviders(
      <GoogleAdBanner client="ca-pub-1234567890123456" slot="1234567890" />
    );
    const pushesAntes = window.adsbygoogle?.length ?? 0;
    act(() => {
      window.dispatchEvent(new CustomEvent('secscan_ad_mode_changed', { detail: { adFree: true } }));
    });
    expect(view.container.querySelector('ins.adsbygoogle')).toBeNull();
    act(() => {
      window.dispatchEvent(new CustomEvent('secscan_ad_mode_changed', { detail: { adFree: false } }));
    });
    expect(view.container.querySelector('ins.adsbygoogle')).not.toBeNull();
    expect(window.adsbygoogle?.length ?? 0).toBeGreaterThan(pushesAntes);
    view.unmount();
  });
});
