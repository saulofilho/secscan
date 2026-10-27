import { safeGetItem, safeSetItem } from './storage';

const STORAGE_KEY = 'secscan_ad_free_mode';
export const ADSENSE_DISABLE_STORAGE_KEY = 'secscan_disable_adsense';

/**
 * Verifica se os banners do Google AdSense estão desativados pelo usuário
 * ou se o Modo Sem Anúncios está ativo no navegador atual.
 * 
 * Modos de Ativação Suportados:
 * 1. Preferência salva no localStorage ('secscan_disable_adsense' ou 'secscan_ad_free_mode' = 'true')
 * 2. URL Secreta: acessar qualquer página com ?adfree=true, ?admin=true ou ?pro=true
 * 3. Ação programática ou via atalho/drawer de configurações do usuário
 */
export function isAdFreeMode(): boolean {
  if (typeof window === 'undefined') return false;

  try {
    const params = new URLSearchParams(window.location.search);
    
    // Ativação via Query Param Secreta
    if (params.get('adfree') === 'true' || params.get('admin') === 'true' || params.get('pro') === 'true') {
      safeSetItem(STORAGE_KEY, 'true');
      safeSetItem(ADSENSE_DISABLE_STORAGE_KEY, 'true');
      // Limpa discretamente o parâmetro da barra de endereços para não deixar rastros no histórico
      params.delete('adfree');
      params.delete('admin');
      params.delete('pro');
      const newQuery = params.toString() ? `?${params.toString()}` : '';
      window.history.replaceState(null, '', `${window.location.pathname}${newQuery}${window.location.hash}`);
      return true;
    }

    // Desativação via URL (para quando o admin quiser ver o site como usuário comum)
    if (params.get('adfree') === 'false') {
      safeSetItem(STORAGE_KEY, 'false');
      safeSetItem(ADSENSE_DISABLE_STORAGE_KEY, 'false');
      params.delete('adfree');
      const newQuery = params.toString() ? `?${params.toString()}` : '';
      window.history.replaceState(null, '', `${window.location.pathname}${newQuery}${window.location.hash}`);
      return false;
    }
  } catch {
    // Safe fallback
  }

  return (
    safeGetItem(STORAGE_KEY) === 'true' || 
    safeGetItem(ADSENSE_DISABLE_STORAGE_KEY) === 'true'
  );
}

/**
 * Alias explícito para verificação de desativação dos banners do Google AdSense
 */
export const isAdSenseDisabled = isAdFreeMode;

/**
 * Ativa ou desativa o bloqueio de anúncios do Google AdSense, persistindo no localStorage
 */
export function setAdFreeMode(enabled: boolean): void {
  const value = enabled ? 'true' : 'false';
  safeSetItem(STORAGE_KEY, value);
  safeSetItem(ADSENSE_DISABLE_STORAGE_KEY, value);
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('secscan_ad_mode_changed', { detail: { adFree: enabled } }));
  }
}

/**
 * Alias explícito para desativar/ativar os banners do Google AdSense
 */
export const setDisableAdSense = (disabled: boolean): void => {
  setAdFreeMode(disabled);
};

/**
 * Alterna entre Modo com e sem anúncios
 */
export function toggleAdFreeMode(): boolean {
  const next = !isAdFreeMode();
  setAdFreeMode(next);
  return next;
}

export const toggleDisableAdSense = toggleAdFreeMode;
