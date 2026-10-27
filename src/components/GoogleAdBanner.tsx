import React, { useEffect, useState, useRef, useMemo } from 'react';
import { isAdFreeMode } from '../lib/adManager';

declare global {
  interface Window {
    adsbygoogle?: any[];
  }
}

interface GoogleAdBannerProps {
  /**
   * Opcional: ID do cliente AdSense (ex: 'ca-pub-1234567890123456').
   * Se omitido, lê diretamente da variável de ambiente VITE_ADSENSE_CLIENT_ID.
   */
  client?: string;

  /**
   * Opcional: ID do bloco de anúncio / slot (ex: '1234567890').
   * Se omitido, lê diretamente da variável de ambiente VITE_ADSENSE_SLOT_ID.
   */
  slot?: string;

  /**
   * Formato do bloco de anúncio. Padrão: 'auto'.
   */
  format?: 'auto' | 'fluid' | 'rectangle';

  /**
   * Habilita design responsivo que preenche a largura do container. Padrão: true.
   */
  responsive?: boolean;

  /**
   * Classes CSS adicionais para o container do anúncio.
   */
  className?: string;
}

const ADSENSE_SCRIPT_ID = 'google-adsense-sdk-script';

/**
 * Validador estrito de credenciais do Google AdSense.
 * Garante que chaves nulas, vazias ou placeholders mockados (ex: ca-pub-0000000000000000)
 * nunca disparem chamadas de rede ou carreguem scripts externos.
 */
function isAdSenseKeyConfigured(clientId?: string, slotId?: string): boolean {
  if (!clientId || !slotId) return false;

  const cleanClient = clientId.trim();
  const cleanSlot = slotId.trim();

  // Verifica se as chaves estão vazias ou com placeholders inválidos
  if (
    cleanClient.length === 0 || 
    cleanSlot.length === 0 || 
    cleanClient.includes('0000000000000000') ||
    cleanClient === 'ca-pub-' ||
    cleanClient === 'undefined' ||
    cleanSlot === 'undefined'
  ) {
    return false;
  }

  return true;
}

/**
 * Injeta o script oficial do Google AdSense de forma singleton no <head>,
 * somente quando credenciais válidas forem verificadas.
 */
function loadAdSenseScript(clientId: string): void {
  if (typeof document === 'undefined') return;

  // Evita injeção duplicada se o script já estiver presente no DOM
  if (document.getElementById(ADSENSE_SCRIPT_ID) || document.querySelector('script[src*="pagead2.googlesyndication.com"]')) {
    return;
  }

  try {
    const script = document.createElement('script');
    script.id = ADSENSE_SCRIPT_ID;
    script.async = true;
    script.crossOrigin = 'anonymous';
    // Garante que o client ID esteja com o prefixo ca-pub- caso o usuário tenha informado apenas os dígitos
    const formattedClient = clientId.startsWith('ca-pub-') ? clientId : `ca-pub-${clientId}`;
    script.src = `https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=${encodeURIComponent(formattedClient)}`;
    
    document.head.appendChild(script);
  } catch (err) {
    console.debug('AdSense script injection prevented/failed:', err);
  }
}

/**
 * Componente React seguro e modular para exibição de anúncios do Google AdSense.
 * 
 * Pre-flight Checklist:
 * 1. Lê VITE_ADSENSE_CLIENT_ID e VITE_ADSENSE_SLOT_ID das variáveis de ambiente Vite.
 * 2. Se qualquer uma das chaves estiver ausente, vazia ou for placeholder, o script NÃO é carregado
 *    e o componente retorna null de forma silenciosa (zero overhead, zero chamadas de rede).
 * 3. Se o Modo Admin / Sem Anúncios estiver ativo (via URL secreta ou localStorage), retorna null.
 * 4. Carrega o SDK do AdSense sob demanda apenas quando as chaves forem confirmadas.
 */
export const GoogleAdBanner: React.FC<GoogleAdBannerProps> = ({
  client,
  slot,
  format = 'auto',
  responsive = true,
  className = ''
}) => {
  const [adFree, setAdFree] = useState<boolean>(() => isAdFreeMode());
  const adPushAttemptedRef = useRef(false);

  // Lê variáveis de ambiente do Vite de forma segura
  const envClient = import.meta.env.VITE_ADSENSE_CLIENT_ID || '';
  const envSlot = import.meta.env.VITE_ADSENSE_SLOT_ID || '';

  // Determina as credenciais efetivas (props têm precedência sobre env vars)
  const effectiveClient = (client || envClient).trim();
  const effectiveSlot = (slot || envSlot).trim();

  // Validação prévia: chaves devem existir e ser válidas antes de qualquer ação
  const isConfigured = useMemo(() => {
    return isAdSenseKeyConfigured(effectiveClient, effectiveSlot);
  }, [effectiveClient, effectiveSlot]);

  // Listener para sincronização de alternância do modo sem anúncios (Admin toggle)
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

  // Efeito responsável pelo carregamento condicional do script do AdSense e inicialização do slot
  useEffect(() => {
    // Se o modo sem anúncios estiver ativo ou as chaves não estiverem configuradas, ABORTA
    if (adFree || !isConfigured) {
      return;
    }

    // 1. Carrega o SDK externo somente quando as chaves estiverem presentes
    loadAdSenseScript(effectiveClient);

    // 2. Inicializa o bloco de anúncio uma única vez para este nó
    if (!adPushAttemptedRef.current) {
      adPushAttemptedRef.current = true;
      try {
        if (typeof window !== 'undefined') {
          (window.adsbygoogle = window.adsbygoogle || []).push({});
        }
      } catch (err) {
        console.debug('AdSense slot initialization:', err);
      }
    }
  }, [adFree, isConfigured, effectiveClient]);

  // Se o Modo Admin estiver ativo ou se as chaves de ambiente estiverem ausentes, NÃO renderiza nada
  if (adFree || !isConfigured) {
    return null;
  }

  const formattedClient = effectiveClient.startsWith('ca-pub-') ? effectiveClient : `ca-pub-${effectiveClient}`;

  return (
    <div className={`overflow-hidden my-4 flex justify-center items-center min-h-[90px] w-full ${className}`} data-ad-slot-active={effectiveSlot}>
      <ins
        className="adsbygoogle"
        style={{ display: 'block' }}
        data-ad-client={formattedClient}
        data-ad-slot={effectiveSlot}
        data-ad-format={format}
        data-full-width-responsive={responsive ? 'true' : 'false'}
      />
    </div>
  );
};

export const AdSenseBanner = GoogleAdBanner;
export default GoogleAdBanner;
