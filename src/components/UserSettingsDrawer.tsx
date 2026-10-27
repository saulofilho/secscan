import React, { useState, useEffect } from 'react';
import { 
  X, 
  SlidersHorizontal, 
  ShieldCheck, 
  Eye, 
  EyeOff, 
  User, 
  Sparkles, 
  Check, 
  CheckCircle2, 
  AlertCircle, 
  Database, 
  Trash2, 
  ExternalLink, 
  Shield, 
  Info,
  Settings,
  Bell,
  HardDrive
} from 'lucide-react';
import { useLanguage } from '../lib/i18nContext';
import { 
  isAdFreeMode, 
  setAdFreeMode, 
  ADSENSE_DISABLE_STORAGE_KEY 
} from '../lib/adManager';
import { safeGetItem, safeSetItem } from '../lib/storage';

interface UserSettingsDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  onOpenMttrConfig?: () => void;
}

export const UserSettingsDrawer: React.FC<UserSettingsDrawerProps> = ({
  isOpen,
  onClose,
  onOpenMttrConfig
}) => {
  const { language } = useLanguage();
  
  // Google AdSense banners preference state (persisted in localStorage)
  const [adsDisabled, setAdsDisabled] = useState<boolean>(() => isAdFreeMode());
  
  // Profile settings persisted in localStorage
  const [userName, setUserName] = useState<string>(() => {
    return safeGetItem('secscan_profile_name') || 'SecOps Auditor';
  });
  const [userRole, setUserRole] = useState<string>(() => {
    return safeGetItem('secscan_profile_role') || 'Lead Security Architect';
  });
  const [userEmail] = useState<string>(() => {
    return safeGetItem('secscan_profile_email') || 'saulosilvaf@gmail.com';
  });
  
  // Additional app preferences
  const [autoScanOnUpload, setAutoScanOnUpload] = useState<boolean>(() => {
    return safeGetItem('secscan_pref_autoscan') !== 'false';
  });
  const [showShortcutToasts, setShowShortcutToasts] = useState<boolean>(() => {
    return safeGetItem('secscan_pref_shortcut_toasts') !== 'false';
  });
  
  // UI feedback states
  const [saveSuccessMsg, setSaveSuccessMsg] = useState<string | null>(null);

  // Sync with ad manager events
  useEffect(() => {
    const handleAdModeChanged = (e: Event) => {
      const customEvent = e as CustomEvent<{ adFree: boolean }>;
      if (customEvent.detail) {
        setAdsDisabled(customEvent.detail.adFree);
      }
    };

    window.addEventListener('secscan_ad_mode_changed', handleAdModeChanged);
    return () => window.removeEventListener('secscan_ad_mode_changed', handleAdModeChanged);
  }, []);

  // Sync state whenever drawer opens
  useEffect(() => {
    if (isOpen) {
      setAdsDisabled(isAdFreeMode());
      setUserName(safeGetItem('secscan_profile_name') || 'SecOps Auditor');
      setUserRole(safeGetItem('secscan_profile_role') || 'Lead Security Architect');
      setAutoScanOnUpload(safeGetItem('secscan_pref_autoscan') !== 'false');
      setShowShortcutToasts(safeGetItem('secscan_pref_shortcut_toasts') !== 'false');
    }
  }, [isOpen]);

  // Handle Escape key to close
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Prevent background scrolling when open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  // Toggle Google AdSense Banners
  const handleToggleAdSense = () => {
    const nextState = !adsDisabled;
    setAdsDisabled(nextState);
    setAdFreeMode(nextState); // Persists to both 'secscan_ad_free_mode' and 'secscan_disable_adsense' in localStorage

    const msg = nextState
      ? (language === 'pt' ? 'Banners do AdSense desativados! Salvo no localStorage.' : 'AdSense banners disabled! Saved in localStorage.')
      : (language === 'pt' ? 'Banners do AdSense habilitados! Salvo no localStorage.' : 'AdSense banners enabled! Saved in localStorage.');
    
    setSaveSuccessMsg(msg);
    setTimeout(() => setSaveSuccessMsg(null), 3000);
  };

  const handleSaveProfile = () => {
    safeSetItem('secscan_profile_name', userName.trim() || 'SecOps Auditor');
    safeSetItem('secscan_profile_role', userRole.trim() || 'Lead Security Architect');
    setSaveSuccessMsg(language === 'pt' ? 'Perfil atualizado com sucesso!' : 'Profile updated successfully!');
    setTimeout(() => setSaveSuccessMsg(null), 3000);
  };

  const handleToggleAutoScan = () => {
    const next = !autoScanOnUpload;
    setAutoScanOnUpload(next);
    safeSetItem('secscan_pref_autoscan', next ? 'true' : 'false');
  };

  const handleToggleShortcutToasts = () => {
    const next = !showShortcutToasts;
    setShowShortcutToasts(next);
    safeSetItem('secscan_pref_shortcut_toasts', next ? 'true' : 'false');
  };

  const handleClearPreferences = () => {
    if (typeof window !== 'undefined') {
      const confirmClear = window.confirm(
        language === 'pt' 
          ? 'Deseja redefinir todas as preferências do usuário salvas no localStorage?' 
          : 'Reset all user preferences saved in localStorage?'
      );
      if (confirmClear) {
        safeSetItem('secscan_profile_name', 'SecOps Auditor');
        safeSetItem('secscan_profile_role', 'Lead Security Architect');
        safeSetItem('secscan_pref_autoscan', 'true');
        safeSetItem('secscan_pref_shortcut_toasts', 'true');
        setAdFreeMode(false);
        setAdsDisabled(false);
        setUserName('SecOps Auditor');
        setUserRole('Lead Security Architect');
        setAutoScanOnUpload(true);
        setShowShortcutToasts(true);
        setSaveSuccessMsg(language === 'pt' ? 'Preferências redefinidas para o padrão!' : 'Preferences reset to defaults!');
        setTimeout(() => setSaveSuccessMsg(null), 3000);
      }
    }
  };

  if (!isOpen) return null;

  const envClientId = import.meta.env.VITE_ADSENSE_CLIENT_ID || '';
  const envSlotId = import.meta.env.VITE_ADSENSE_SLOT_ID || '';
  const isEnvConfigured = Boolean(envClientId.trim() && envSlotId.trim() && !envClientId.includes('0000000000000000'));

  return (
    <div className="fixed inset-0 z-50 overflow-hidden" role="dialog" aria-modal="true">
      {/* Dark Glassmorphic Backdrop */}
      <div 
        className="fixed inset-0 bg-black/70 backdrop-blur-sm transition-opacity animate-in fade-in duration-200" 
        onClick={onClose}
        aria-hidden="true"
      />

      <div className="fixed inset-y-0 right-0 max-w-full flex pl-8 sm:pl-10">
        <div className="w-screen max-w-md bg-[#0D0D14] border-l border-white/[0.12] shadow-2xl flex flex-col justify-between animate-in slide-in-from-right duration-300">
          
          {/* Drawer Header */}
          <div className="p-4 sm:p-5 border-b border-white/[0.08] flex items-center justify-between bg-gradient-to-r from-white/[0.02] to-transparent">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-[#00F0FF]/20 to-[#00FF41]/10 border border-[#00F0FF]/30 flex items-center justify-center text-[#00F0FF]">
                <Settings className="w-4.5 h-4.5" />
              </div>
              <div>
                <h2 className="font-sans font-bold text-base text-white tracking-tight flex items-center gap-2">
                  {language === 'pt' ? 'Configurações do Usuário' : 'User Settings & Profile'}
                  <span className="text-[10px] font-mono font-normal px-1.5 py-0.5 rounded bg-white/[0.06] text-zinc-400 border border-white/[0.08]">
                    AppSec
                  </span>
                </h2>
                <p className="text-[11px] font-mono text-zinc-400">
                  {language === 'pt' ? 'Preferências de ambiente, perfil e anúncios' : 'Environment preferences, profile & ads'}
                </p>
              </div>
            </div>

            <button
              id="btn-close-settings-drawer"
              type="button"
              onClick={onClose}
              className="w-8 h-8 rounded-lg flex items-center justify-center text-zinc-400 hover:text-white hover:bg-white/[0.08] transition-colors cursor-pointer border border-transparent hover:border-white/[0.1]"
              title="Fechar (Esc)"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Toast Notification inside Drawer */}
          {saveSuccessMsg && (
            <div className="mx-4 mt-3 p-2.5 rounded-lg bg-emerald-950/80 border border-emerald-500/40 text-emerald-200 text-xs font-mono flex items-center gap-2 animate-in fade-in duration-200">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{saveSuccessMsg}</span>
            </div>
          )}

          {/* Drawer Scrollable Content */}
          <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-5 divide-y divide-white/[0.06]">
            
            {/* 1. USER PROFILE IDENTITY CARD */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
                  <User className="w-3.5 h-3.5 text-[#00F0FF]" />
                  {language === 'pt' ? 'Perfil do Auditor' : 'Auditor Profile'}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950/70 text-emerald-300 border border-emerald-800/60 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  {language === 'pt' ? 'Sessão Local Isolada' : 'Local Session'}
                </span>
              </div>

              <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/[0.08] space-y-3">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-[#1B1B26] to-[#2B2B3E] border border-white/[0.15] flex items-center justify-center text-white font-black text-sm tracking-wider font-mono shadow-inner shrink-0">
                    {userName.slice(0, 2).toUpperCase()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <input
                      type="text"
                      value={userName}
                      onChange={(e) => setUserName(e.target.value)}
                      onBlur={handleSaveProfile}
                      placeholder="Nome do Usuário"
                      className="w-full bg-black/40 border border-white/[0.1] rounded-lg px-2.5 py-1 text-xs font-bold text-white focus:outline-none focus:border-[#00F0FF] transition-colors"
                    />
                    <input
                      type="text"
                      value={userRole}
                      onChange={(e) => setUserRole(e.target.value)}
                      onBlur={handleSaveProfile}
                      placeholder="Cargo / Especialidade"
                      className="w-full mt-1.5 bg-black/40 border border-white/[0.08] rounded-lg px-2.5 py-0.5 text-[11px] font-mono text-zinc-400 focus:outline-none focus:border-[#00F0FF] transition-colors"
                    />
                  </div>
                </div>

                <div className="pt-2 border-t border-white/[0.06] flex items-center justify-between text-[11px] font-mono text-zinc-400">
                  <span className="truncate">{userEmail}</span>
                  <span className="text-[10px] text-zinc-500">ID: SEC-{Math.abs(userEmail.split('').reduce((acc, c) => acc + c.charCodeAt(0), 1000))}</span>
                </div>
              </div>
            </div>

            {/* 2. GOOGLE ADSENSE BANNERS TOGGLE (MAIN FEATURE) */}
            <div className="pt-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-[#00FF41]" />
                  {language === 'pt' ? 'Controle de Anúncios (Google AdSense)' : 'Ad Banners (Google AdSense)'}
                </span>
                <span className={`text-[9.5px] font-mono font-bold px-2 py-0.5 rounded border ${
                  adsDisabled 
                    ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60 shadow-[0_0_8px_rgba(16,185,129,0.2)]' 
                    : 'bg-zinc-800/90 text-zinc-300 border-white/10'
                }`}>
                  {adsDisabled 
                    ? (language === 'pt' ? 'DESATIVADO (SEM ADS)' : 'DISABLED (NO ADS)') 
                    : (language === 'pt' ? 'ATIVO (EXIBIR ADS)' : 'ENABLED (SHOW ADS)')}
                </span>
              </div>

              {/* The Interactive AdSense Toggle Card */}
              <div className={`p-4 rounded-xl border transition-all ${
                adsDisabled 
                  ? 'bg-gradient-to-b from-emerald-950/20 to-black/30 border-emerald-500/30 shadow-[0_0_15px_rgba(16,185,129,0.08)]' 
                  : 'bg-white/[0.02] border-white/[0.08] hover:border-white/[0.14]'
              }`}>
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1 pr-2">
                    <div className="flex items-center gap-2">
                      <span className="font-sans font-bold text-xs text-white">
                        {language === 'pt' ? 'Desativar Banners do AdSense' : 'Disable Google AdSense Banners'}
                      </span>
                      {adsDisabled && (
                        <span className="inline-flex items-center gap-1 text-[9px] font-mono text-emerald-400 bg-emerald-950/90 px-1.5 py-0.2 rounded border border-emerald-800">
                          <EyeOff className="w-2.5 h-2.5" />
                          {language === 'pt' ? 'Ocultos' : 'Hidden'}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-zinc-400 leading-relaxed font-sans">
                      {language === 'pt' 
                        ? 'Oculta todos os blocos de anúncio e suspende o carregamento dos scripts externos do Google AdSense para uma interface totalmente limpa.' 
                        : 'Completely hides all ad banners and suspends loading external Google AdSense scripts for a clean interface.'}
                    </p>
                    <div className="pt-1 flex items-center gap-1.5 text-[10px] font-mono text-zinc-500">
                      <Database className="w-3 h-3 text-zinc-400 shrink-0" />
                      <span>{language === 'pt' ? 'Persistido no' : 'Persisted in'} <code className="text-[#00F0FF]">localStorage.{ADSENSE_DISABLE_STORAGE_KEY}</code></span>
                    </div>
                  </div>

                  {/* Toggle Switch Button */}
                  <button
                    id="btn-toggle-disable-adsense"
                    type="button"
                    role="switch"
                    aria-checked={adsDisabled}
                    onClick={handleToggleAdSense}
                    className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-[#00FF41]/40 focus:ring-offset-2 focus:ring-offset-[#0D0D14] ${
                      adsDisabled ? 'bg-[#00FF41]' : 'bg-zinc-700 hover:bg-zinc-600'
                    }`}
                    title={adsDisabled ? 'Clique para reativar anúncios' : 'Clique para desativar anúncios'}
                  >
                    <span
                      aria-hidden="true"
                      className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                        adsDisabled ? 'translate-x-5 bg-black' : 'translate-x-0'
                      }`}
                    />
                  </button>
                </div>

                {/* AdSense Environment Diagnostic Info */}
                <div className="mt-3.5 pt-3 border-t border-white/[0.06] bg-black/30 -mx-4 -mb-4 p-3 rounded-b-xl space-y-1.5 text-[10.5px] font-mono">
                  <div className="flex items-center justify-between text-zinc-400">
                    <span>VITE_ADSENSE_CLIENT_ID:</span>
                    <span className={isEnvConfigured ? 'text-emerald-400' : 'text-zinc-500'}>
                      {envClientId ? `${envClientId.slice(0, 10)}...` : (language === 'pt' ? '(vazio no .env)' : '(empty in .env)')}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-zinc-400">
                    <span>VITE_ADSENSE_SLOT_ID:</span>
                    <span className={isEnvConfigured ? 'text-emerald-400' : 'text-zinc-500'}>
                      {envSlotId ? `${envSlotId.slice(0, 8)}...` : (language === 'pt' ? '(vazio no .env)' : '(empty in .env)')}
                    </span>
                  </div>
                  <div className="pt-1 text-[9.5px] text-zinc-500 flex items-center gap-1.5">
                    <Info className="w-3 h-3 text-[#00F0FF] shrink-0" />
                    <span>
                      {isEnvConfigured 
                        ? (language === 'pt' ? 'Credenciais AdSense ativas no runtime.' : 'AdSense runtime credentials active.')
                        : (language === 'pt' ? 'Sem chaves configuradas: os anúncios permanecem suspensos por segurança.' : 'No keys in env: ads stay safely suspended.')}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* 3. WORKSPACE & APP PREFERENCES */}
            <div className="pt-5 space-y-3">
              <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
                <SlidersHorizontal className="w-3.5 h-3.5 text-[#FF3E00]" />
                {language === 'pt' ? 'Preferências do App' : 'App Preferences'}
              </span>

              <div className="space-y-2">
                {/* Auto-scan on upload toggle */}
                <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] flex items-center justify-between">
                  <div>
                    <div className="text-xs font-sans font-bold text-white">
                      {language === 'pt' ? 'Auto-scan ao Carregar Arquivos' : 'Auto-scan on File Upload'}
                    </div>
                    <div className="text-[10.5px] font-mono text-zinc-400">
                      {language === 'pt' ? 'Executa varredura SAST instantânea' : 'Runs SAST scan immediately'}
                    </div>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={autoScanOnUpload}
                    onClick={handleToggleAutoScan}
                    className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out ${
                      autoScanOnUpload ? 'bg-[#00FF41]' : 'bg-zinc-700'
                    }`}
                  >
                    <span
                      className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-lg transition duration-200 ease-in-out ${
                        autoScanOnUpload ? 'translate-x-4 bg-black' : 'translate-x-0'
                      }`}
                    />
                  </button>
                </div>

                {/* Shortcut toasts toggle */}
                <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] flex items-center justify-between">
                  <div>
                    <div className="text-xs font-sans font-bold text-white">
                      {language === 'pt' ? 'Toasts de Feedback de Atalhos' : 'Shortcut Feedback Toasts'}
                    </div>
                    <div className="text-[10.5px] font-mono text-zinc-400">
                      {language === 'pt' ? 'Exibe notificação flutuante ao usar atalhos' : 'Floating toast on keyboard shortcuts'}
                    </div>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={showShortcutToasts}
                    onClick={handleToggleShortcutToasts}
                    className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out ${
                      showShortcutToasts ? 'bg-[#00FF41]' : 'bg-zinc-700'
                    }`}
                  >
                    <span
                      className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-lg transition duration-200 ease-in-out ${
                        showShortcutToasts ? 'translate-x-4 bg-black' : 'translate-x-0'
                      }`}
                    />
                  </button>
                </div>

                {/* MTTR Config modal link button */}
                {onOpenMttrConfig && (
                  <button
                    type="button"
                    onClick={() => {
                      onClose();
                      onOpenMttrConfig();
                    }}
                    className="w-full p-3 rounded-xl bg-white/[0.02] hover:bg-white/[0.05] border border-white/[0.06] hover:border-white/[0.15] text-left flex items-center justify-between transition-colors cursor-pointer"
                  >
                    <div>
                      <div className="text-xs font-sans font-bold text-white flex items-center gap-1.5">
                        <span>{language === 'pt' ? 'Parâmetros de MTTR & SLA' : 'MTTR & SLA Parameters'}</span>
                        <ExternalLink className="w-3 h-3 text-[#FF3E00]" />
                      </div>
                      <div className="text-[10.5px] font-mono text-zinc-400">
                        {language === 'pt' ? 'Ajustar limites de tempo de remediação' : 'Tune remediation time limits'}
                      </div>
                    </div>
                    <span className="text-xs font-mono text-zinc-500">→</span>
                  </button>
                )}
              </div>
            </div>

            {/* 4. LOCALSTORAGE MANAGEMENT & RESET */}
            <div className="pt-5 space-y-3">
              <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
                <HardDrive className="w-3.5 h-3.5 text-zinc-400" />
                {language === 'pt' ? 'Armazenamento & Privacidade' : 'Storage & Privacy'}
              </span>

              <div className="p-3 rounded-xl bg-black/40 border border-white/[0.06] space-y-2 text-[11px] font-mono text-zinc-400">
                <div className="flex items-center justify-between">
                  <span>Modo Sem Anúncios:</span>
                  <span className={adsDisabled ? 'text-emerald-400' : 'text-zinc-500'}>
                    {adsDisabled ? 'true' : 'false'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Chave Storage:</span>
                  <span className="text-[#00F0FF]">{ADSENSE_DISABLE_STORAGE_KEY}</span>
                </div>
                <p className="text-[10px] text-zinc-500 font-sans leading-tight pt-1">
                  {language === 'pt' 
                    ? 'Todas as preferências ficam estritamente no seu navegador. Nenhum cookie rastreador é utilizado.'
                    : 'All preferences are strictly client-side. No tracking cookies are used.'}
                </p>

                <div className="pt-2">
                  <button
                    type="button"
                    onClick={handleClearPreferences}
                    className="w-full py-1.5 px-3 rounded-lg text-xs font-mono text-rose-300 hover:text-white bg-rose-950/20 hover:bg-rose-900/50 border border-rose-800/40 hover:border-rose-600 transition-colors flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <Trash2 className="w-3 h-3" />
                    <span>{language === 'pt' ? 'Redefinir Preferências Locais' : 'Reset Local Preferences'}</span>
                  </button>
                </div>
              </div>
            </div>

          </div>

          {/* Drawer Footer */}
          <div className="p-4 sm:p-5 border-t border-white/[0.08] bg-[#0A0A0F] flex items-center justify-between gap-3">
            <span className="text-[10px] font-mono text-zinc-500 truncate">
              SecScan Suite v4.2 • Safe Client Persistence
            </span>
            <button
              id="btn-settings-drawer-done"
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-xs font-mono font-bold uppercase tracking-wider text-black bg-[#00FF41] hover:bg-[#00FF41]/90 shadow-[0_0_12px_rgba(0,255,65,0.3)] transition-all cursor-pointer"
            >
              {language === 'pt' ? 'Concluir' : 'Done'}
            </button>
          </div>

        </div>
      </div>
    </div>
  );
};
