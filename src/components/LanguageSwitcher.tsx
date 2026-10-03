import React, { useState, useRef, useEffect } from 'react';
import { Globe, ChevronDown, Check } from 'lucide-react';
import { useLanguage, SUPPORTED_LANGUAGES, SupportedLanguage } from '../lib/i18nContext';

export interface LanguageSwitcherProps {
  className?: string;
  compact?: boolean;
}

export const LanguageSwitcher: React.FC<LanguageSwitcherProps> = ({
  className = '',
  compact = false
}) => {
  const { language, setLanguage, currentLanguageInfo, t } = useLanguage();
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('touchstart', handleClickOutside as any);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('touchstart', handleClickOutside as any);
    };
  }, [isOpen]);

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        setIsOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen]);

  const handleSelect = (langCode: SupportedLanguage) => {
    setLanguage(langCode);
    setIsOpen(false);
  };

  return (
    <div 
      ref={dropdownRef} 
      className={`relative inline-flex items-center gap-1.5 ${className}`}
      data-testid="language-switcher"
    >
      {/* 1-Click Segmented Language Switcher Bar (Always accessible, zero friction) */}
      <div 
        className="flex items-center p-0.5 bg-[#0C0C0E] border border-zinc-700/80 rounded-md font-mono text-[10px] shadow-sm select-none"
        title="Seletor Rápido de Idioma // Quick Language Selector"
      >
        <div className="px-1.5 py-0.5 text-zinc-400 flex items-center gap-1 border-r border-zinc-800/80 mr-0.5">
          <Globe className="w-3 h-3 text-[#00FF41]" />
          <span className="hidden xl:inline uppercase font-bold text-[9px] tracking-wider text-zinc-400">
            {t('app.language')}
          </span>
        </div>

        {SUPPORTED_LANGUAGES.map((lang) => {
          const isActive = lang.code === language;
          return (
            <button
              key={lang.code}
              id={`btn-switch-lang-${lang.code}`}
              type="button"
              onClick={() => handleSelect(lang.code)}
              className={`px-2 py-1 rounded transition-all flex items-center gap-1 font-bold cursor-pointer ${
                isActive
                  ? 'bg-[#1C1C22] text-[#00FF41] border border-[#00FF41]/60 shadow-[0_0_8px_rgba(0,255,65,0.25)]'
                  : 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/50 border border-transparent'
              }`}
              title={`${lang.name} (${lang.nativeName})`}
            >
              <span className="text-xs leading-none">{lang.flag}</span>
              <span className="uppercase tracking-wider">{lang.code}</span>
              {isActive && (
                <span className="w-1.5 h-1.5 rounded-full bg-[#00FF41] animate-pulse ml-0.5" />
              )}
            </button>
          );
        })}
      </div>

      {/* Optional Dropdown Menu for Detailed Native Selection */}
      <div className="relative">
        <button
          id="btn-language-dropdown-toggle"
          type="button"
          onClick={() => setIsOpen(prev => !prev)}
          className={`h-8 w-8 rounded flex items-center justify-center font-mono text-[11px] font-bold uppercase tracking-wider transition-all cursor-pointer border select-none ${
            isOpen
              ? 'bg-[#1F1F24] text-white border-[#FF3E00] shadow-[0_0_10px_rgba(255,62,0,0.25)]'
              : 'bg-[#0F0F0F] hover:bg-[#1A1A1A] text-zinc-400 hover:text-white border-[#2A2A2A] hover:border-[#444]'
          }`}
          title={`${t('app.change_language')}: ${currentLanguageInfo.nativeName}`}
          aria-haspopup="true"
          aria-expanded={isOpen}
        >
          <ChevronDown
            className={`w-3.5 h-3.5 transition-transform duration-200 ${
              isOpen ? 'rotate-180 text-[#FF3E00]' : 'text-zinc-400'
            }`}
          />
        </button>

        {isOpen && (
          <div 
            className="absolute right-0 mt-1.5 w-56 bg-[#0C0C0E] border-2 border-zinc-700 rounded-lg shadow-[0_10px_35px_rgba(0,0,0,0.8)] py-2 z-[999] font-mono text-xs animate-in fade-in zoom-in-95 duration-150 backdrop-blur-md"
            role="menu"
            aria-orientation="vertical"
          >
            <div className="px-3 py-1.5 text-[9.5px] uppercase font-bold text-zinc-400 tracking-wider border-b border-zinc-800 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-[#00FF41]" />
                <span className="text-zinc-200">{t('app.change_language')}</span>
              </span>
              <span className="text-[9px] text-[#00FF41] font-bold">i18n</span>
            </div>

            <div className="py-1">
              {SUPPORTED_LANGUAGES.map((lang) => {
                const isSelected = lang.code === language;
                return (
                  <button
                    key={lang.code}
                    id={`menu-item-lang-${lang.code}`}
                    type="button"
                    onClick={() => handleSelect(lang.code)}
                    className={`w-full px-3 py-2 text-left flex items-center justify-between gap-2.5 transition-colors cursor-pointer group ${
                      isSelected
                        ? 'bg-[#18181C] text-white font-bold'
                        : 'text-zinc-300 hover:bg-zinc-800/60 hover:text-white'
                    }`}
                    role="menuitem"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className="text-xl leading-none shrink-0">{lang.flag}</span>
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5 leading-tight">
                          <span className={`text-xs ${isSelected ? 'text-[#00FF41]' : 'text-zinc-200 group-hover:text-white'}`}>
                            {lang.name}
                          </span>
                          <span className="text-[9px] px-1 py-0.2 rounded bg-zinc-800 text-zinc-300 font-bold border border-zinc-700">
                            {lang.code.toUpperCase()}
                          </span>
                        </div>
                        <span className="text-[10px] text-zinc-400 block truncate mt-0.5">
                          {lang.nativeName}
                        </span>
                      </div>
                    </div>

                    {isSelected ? (
                      <div className="flex items-center gap-1 text-[#00FF41] shrink-0">
                        <Check className="w-4 h-4 stroke-[2.5]" />
                      </div>
                    ) : (
                      <span className="w-1.5 h-1.5 rounded-full bg-transparent group-hover:bg-zinc-600 transition-colors" />
                    )}
                  </button>
                );
              })}
            </div>

            <div className="px-3 py-1.5 mt-1 border-t border-zinc-800/80 bg-black/40 text-[9px] text-zinc-400 flex items-center justify-between">
              <span>SecScan AppSec Suite</span>
              <span className="text-[#00FF41] font-bold uppercase">{language}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default LanguageSwitcher;
