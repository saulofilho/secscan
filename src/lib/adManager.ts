import { safeGetItem, safeSetItem } from './storage';

const STORAGE_KEY = 'secscan_ad_free_mode';

/**
 * Verifica se o Modo Admin / Sem Anúncios está ativo no navegador atual.
 * 
 * Modos de Ativação Suportados:
 * 1. URL Secreta: acessar qualquer página com ?adfree=true, ?admin=true ou ?pro=true
 * 2. LocalStorage persistente (secscan_ad_free_mode = 'true')
 * 3. Ação programática ou via atalho/easter egg
 */
export function isAdFreeMode(): boolean {
  if (typeof window === 'undefined') return false;

  try {
    const params = new URLSearchParams(window.location.search);
    
    // Ativação via Query Param Secreta
    if (params.get('adfree') === 'true' || params.get('admin') === 'true' || params.get('pro') === 'true') {
      safeSetItem(STORAGE_KEY, 'true');
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
      params.delete('adfree');
      const newQuery = params.toString() ? `?${params.toString()}` : '';
      window.history.replaceState(null, '', `${window.location.pathname}${newQuery}${window.location.hash}`);
      return false;
    }
  } catch {
    // Safe fallback
  }

  return safeGetItem(STORAGE_KEY) === 'true';
}

/**
 * Ativa ou desativa o Modo Sem Anúncios manualmente
 */
export function setAdFreeMode(enabled: boolean): void {
  safeSetItem(STORAGE_KEY, enabled ? 'true' : 'false');
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('secscan_ad_mode_changed', { detail: { adFree: enabled } }));
  }
}

/**
 * Alterna entre Modo com e sem anúncios
 */
export function toggleAdFreeMode(): boolean {
  const next = !isAdFreeMode();
  setAdFreeMode(next);
  return next;
}
