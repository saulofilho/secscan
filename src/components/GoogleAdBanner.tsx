import React, { useEffect, useState } from 'react';
import { isAdFreeMode } from '../lib/adManager';

declare global {
  interface Window {
    adsbygoogle?: any[];
  }
}

interface GoogleAdBannerProps {
  client?: string; // opcional se configurado via VITE_ADSENSE_CLIENT_ID
  slot?: string;   // opcional se configurado via VITE_ADSENSE_SLOT_ID
  format?: 'auto' | 'fluid' | 'rectangle';
  responsive?: boolean;
  className?: string;
}

/**
 * Componente React seguro para exibição de anúncios do Google AdSense
 * em aplicações SPA sem conflitar com o ciclo de vida do React.
 * 
 * Suporta configuração via variáveis de ambiente (VITE_ADSENSE_CLIENT_ID / VITE_ADSENSE_SLOT_ID)
 * ou props diretas. Se não estiver configurado ou estiver no Modo Admin, retorna null.
 */
export const GoogleAdBanner: React.FC<GoogleAdBannerProps> = ({
  client,
  slot,
  format = 'auto',
  responsive = true,
  className = ''
}) => {
  const [adFree, setAdFree] = useState<boolean>(() => isAdFreeMode());

  const envObj = (typeof import.meta !== 'undefined' ? (import.meta as any).env : {}) || {};
  const effectiveClient = client || (envObj.VITE_ADSENSE_CLIENT_ID as string | undefined);
  const effectiveSlot = slot || (envObj.VITE_ADSENSE_SLOT_ID as string | undefined);

  useEffect(() => {
    const handleModeChange = (e: Event) => {
      const customEvent = e as CustomEvent<{ adFree: boolean }>;
      if (customEvent.detail) {
        setAdFree(customEvent.detail.adFree);
      }
    };

    window.addEventListener('secscan_ad_mode_changed', handleModeChange);
    return () => window.removeEventListener('secscan_ad_mode_changed', handleModeChange);
  }, []);

  useEffect(() => {
    if (adFree || !effectiveClient || !effectiveSlot || effectiveClient.includes('0000000000000000')) {
      return;
    }

    try {
      if (typeof window !== 'undefined') {
        (window.adsbygoogle = window.adsbygoogle || []).push({});
      }
    } catch (err) {
      console.debug('AdSense script status:', err);
    }
  }, [adFree, effectiveClient, effectiveSlot]);

  // Se o Modo Admin estiver ativo ou se ainda não foi configurada uma chave real, não renderiza
  if (adFree || !effectiveClient || !effectiveSlot || effectiveClient.includes('0000000000000000')) {
    return null;
  }

  return (
    <div className={`overflow-hidden my-4 flex justify-center items-center min-h-[90px] w-full ${className}`}>
      <ins
        className="adsbygoogle"
        style={{ display: 'block' }}
        data-ad-client={effectiveClient}
        data-ad-slot={effectiveSlot}
        data-ad-format={format}
        data-full-width-responsive={responsive ? 'true' : 'false'}
      />
    </div>
  );
};
