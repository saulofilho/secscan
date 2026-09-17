import React, { useState, useEffect } from 'react';
import { Clock, X, Check, RotateCcw, AlertTriangle, ShieldAlert, Timer, Sliders, Info, Sparkles } from 'lucide-react';
import { SecScanGlobalConfig } from '../types';
import { DEFAULT_SECSCAN_CONFIG, saveSecScanConfig } from '../lib/secscanConfig';

interface SecScanMttrConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  config: SecScanGlobalConfig;
  onUpdateConfig: (newConfig: SecScanGlobalConfig) => void;
}

export const SecScanMttrConfigModal: React.FC<SecScanMttrConfigModalProps> = ({
  isOpen,
  onClose,
  config,
  onUpdateConfig,
}) => {
  const [criticalTime, setCriticalTime] = useState<string>(
    config.severityConfig.CRITICAL.remediationTime || config.remediationTime.CRITICAL || '1.5h – 2h'
  );
  const [highTime, setHighTime] = useState<string>(
    config.severityConfig.HIGH.remediationTime || config.remediationTime.HIGH || '4h – 6h'
  );
  const [warningTime, setWarningTime] = useState<string>(
    config.severityConfig.WARNING.remediationTime || config.remediationTime.WARNING || '12h – 24h'
  );
  const [maxMttrHours, setMaxMttrHours] = useState<number | string>(
    config.maxAllowedMttrHours ?? 4.0
  );
  const [dynamicCalculation, setDynamicCalculation] = useState<boolean>(
    config.dynamicMttrCalculation !== false
  );
  const [savedSuccess, setSavedSuccess] = useState<boolean>(false);

  useEffect(() => {
    if (isOpen) {
      setCriticalTime(
        config.severityConfig.CRITICAL.remediationTime || config.remediationTime.CRITICAL || '1.5h – 2h'
      );
      setHighTime(
        config.severityConfig.HIGH.remediationTime || config.remediationTime.HIGH || '4h – 6h'
      );
      setWarningTime(
        config.severityConfig.WARNING.remediationTime || config.remediationTime.WARNING || '12h – 24h'
      );
      setMaxMttrHours(config.maxAllowedMttrHours ?? 4.0);
      setDynamicCalculation(config.dynamicMttrCalculation !== false);
      setSavedSuccess(false);
    }
  }, [isOpen, config]);

  if (!isOpen) return null;

  const handleSave = () => {
    const parsedMaxLimit = parseFloat(String(maxMttrHours));
    const finalMaxLimit = !isNaN(parsedMaxLimit) && parsedMaxLimit > 0 ? parsedMaxLimit : 4.0;

    const updated = saveSecScanConfig({
      maxAllowedMttrHours: finalMaxLimit,
      remediationTime: {
        CRITICAL: criticalTime.trim() || '1.5h – 2h',
        HIGH: highTime.trim() || '4h – 6h',
        WARNING: warningTime.trim() || '12h – 24h',
      },
      severityConfig: {
        CRITICAL: {
          ...config.severityConfig.CRITICAL,
          remediationTime: criticalTime.trim() || '1.5h – 2h',
        },
        HIGH: {
          ...config.severityConfig.HIGH,
          remediationTime: highTime.trim() || '4h – 6h',
        },
        WARNING: {
          ...config.severityConfig.WARNING,
          remediationTime: warningTime.trim() || '12h – 24h',
        },
      },
      dynamicMttrCalculation: dynamicCalculation,
    });
    onUpdateConfig(updated);
    setSavedSuccess(true);
    setTimeout(() => {
      setSavedSuccess(false);
      onClose();
    }, 600);
  };

  const handleResetDefaults = () => {
    const reset = saveSecScanConfig(DEFAULT_SECSCAN_CONFIG);
    setCriticalTime(DEFAULT_SECSCAN_CONFIG.remediationTime.CRITICAL);
    setHighTime(DEFAULT_SECSCAN_CONFIG.remediationTime.HIGH);
    setWarningTime(DEFAULT_SECSCAN_CONFIG.remediationTime.WARNING);
    setMaxMttrHours(DEFAULT_SECSCAN_CONFIG.maxAllowedMttrHours ?? 4.0);
    setDynamicCalculation(true);
    onUpdateConfig(reset);
  };

  const applyPreset = (preset: 'strict' | 'standard' | 'relaxed') => {
    if (preset === 'strict') {
      setCriticalTime('30m – 1h');
      setHighTime('2h – 4h');
      setWarningTime('6h – 12h');
      setMaxMttrHours(2.0);
    } else if (preset === 'standard') {
      setCriticalTime('1.5h – 2h');
      setHighTime('4h – 6h');
      setWarningTime('12h – 24h');
      setMaxMttrHours(4.0);
    } else {
      setCriticalTime('2h – 4h');
      setHighTime('8h – 16h');
      setWarningTime('24h – 48h');
      setMaxMttrHours(8.0);
    }
  };

  return (
    <div
      id="modal-secscan-mttr-config"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-lg rounded-xl border border-white/15 bg-[#0e0e11] p-6 shadow-2xl text-zinc-200 font-mono text-xs"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/10 pb-4 mb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <Clock className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-white tracking-wide flex items-center gap-2">
                Configuração Global SecScan
                <span className="text-[10px] font-normal px-2 py-0.5 rounded-full bg-white/10 text-zinc-300">
                  remediationTime (MTTR)
                </span>
              </h3>
              <p className="text-[11px] text-zinc-400 font-sans mt-0.5">
                Defina o parâmetro de Tempo Médio de Remediação exibido dinamicamente nos Tooltips.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded text-zinc-400 hover:text-white hover:bg-white/10 transition-colors"
            title="Fechar"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Preset Selector */}
        <div className="mb-4 p-2.5 rounded-lg bg-white/5 border border-white/10 space-y-1.5">
          <div className="flex items-center justify-between text-[11px] text-zinc-300 font-sans">
            <span className="font-semibold flex items-center gap-1.5">
              <Sliders className="w-3.5 h-3.5 text-sky-400" />
              Presets de SLAs Corporativos:
            </span>
          </div>
          <div className="grid grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => applyPreset('strict')}
              className="px-2 py-1.5 rounded border border-rose-500/30 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 text-[10px] font-bold text-center transition-colors cursor-pointer"
            >
              Rigoroso (Fintech / PCI)
            </button>
            <button
              type="button"
              onClick={() => applyPreset('standard')}
              className="px-2 py-1.5 rounded border border-emerald-500/30 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 text-[10px] font-bold text-center transition-colors cursor-pointer"
            >
              Padrão (AppSec Base)
            </button>
            <button
              type="button"
              onClick={() => applyPreset('relaxed')}
              className="px-2 py-1.5 rounded border border-amber-500/30 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 text-[10px] font-bold text-center transition-colors cursor-pointer"
            >
              Flexível (Staging)
            </button>
          </div>
        </div>

        {/* Severity Inputs */}
        <div className="space-y-3 mb-5">
          {/* CRITICAL */}
          <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-950/20 space-y-1.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
                <span className="font-bold text-rose-300 uppercase tracking-wider text-[11px]">
                  CRITICAL (Crítico)
                </span>
              </div>
              <span className="text-[10px] text-zinc-400">P0 • Bloqueador</span>
            </div>
            <div className="flex items-center gap-2">
              <label className="text-[11px] text-zinc-300 whitespace-nowrap">
                remediationTime:
              </label>
              <input
                id="input-remediation-time-critical"
                type="text"
                value={criticalTime}
                onChange={(e) => setCriticalTime(e.target.value)}
                placeholder="ex: 1.5h – 2h"
                className="flex-1 px-2.5 py-1 rounded bg-black/60 border border-rose-500/40 text-rose-200 font-mono text-xs focus:outline-none focus:border-rose-400"
              />
            </div>
          </div>

          {/* HIGH */}
          <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-950/20 space-y-1.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-500" />
                <span className="font-bold text-amber-300 uppercase tracking-wider text-[11px]">
                  HIGH (Alto)
                </span>
              </div>
              <span className="text-[10px] text-zinc-400">P1 • Alta Prioridade</span>
            </div>
            <div className="flex items-center gap-2">
              <label className="text-[11px] text-zinc-300 whitespace-nowrap">
                remediationTime:
              </label>
              <input
                id="input-remediation-time-high"
                type="text"
                value={highTime}
                onChange={(e) => setHighTime(e.target.value)}
                placeholder="ex: 4h – 6h"
                className="flex-1 px-2.5 py-1 rounded bg-black/60 border border-amber-500/40 text-amber-200 font-mono text-xs focus:outline-none focus:border-amber-400"
              />
            </div>
          </div>

          {/* WARNING */}
          <div className="p-3 rounded-lg border border-yellow-500/30 bg-yellow-950/20 space-y-1.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-yellow-400" />
                <span className="font-bold text-yellow-300 uppercase tracking-wider text-[11px]">
                  WARNING (Aviso)
                </span>
              </div>
              <span className="text-[10px] text-zinc-400">P2 • Higiene / Débito</span>
            </div>
            <div className="flex items-center gap-2">
              <label className="text-[11px] text-zinc-300 whitespace-nowrap">
                remediationTime:
              </label>
              <input
                id="input-remediation-time-warning"
                type="text"
                value={warningTime}
                onChange={(e) => setWarningTime(e.target.value)}
                placeholder="ex: 12h – 24h"
                className="flex-1 px-2.5 py-1 rounded bg-black/60 border border-yellow-500/40 text-yellow-200 font-mono text-xs focus:outline-none focus:border-yellow-400"
              />
            </div>
          </div>

          {/* Limite Máximo Tolerado de MTTR (SLA Threshold & Alert Trigger) */}
          <div className="p-3 rounded-lg border border-sky-500/30 bg-sky-950/20 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                <span className="font-bold text-sky-200 uppercase tracking-wider text-[11px]">
                  Limite Máximo de MTTR (SLA Target)
                </span>
              </div>
              <span className="text-[10px] text-zinc-400">Gatilho de Alerta no Gráfico</span>
            </div>
            <p className="text-[10.5px] text-zinc-400 font-sans leading-relaxed">
              Define o tempo médio de remediação máximo aceitável. Qualquer varredura no gráfico de tendência histórica cujo MTTR exceder este teto exibirá <strong className="text-rose-400">ícones de alerta destacados</strong> e marcação visual no ponto e legenda.
            </p>
            <div className="flex items-center gap-2.5 pt-1">
              <label htmlFor="input-max-allowed-mttr" className="text-[11px] text-zinc-300 font-semibold whitespace-nowrap">
                Limite Máximo:
              </label>
              <div className="relative inline-flex items-center">
                <input
                  id="input-max-allowed-mttr"
                  type="number"
                  step="0.5"
                  min="0.5"
                  max="100"
                  value={maxMttrHours}
                  onChange={(e) => setMaxMttrHours(e.target.value)}
                  placeholder="ex: 4.0"
                  className="w-28 pl-2.5 pr-7 py-1 rounded bg-black/70 border border-sky-500/40 text-sky-200 font-mono text-xs font-bold focus:outline-none focus:border-sky-400 focus:ring-1 focus:ring-sky-400/40"
                />
                <span className="absolute right-2 text-zinc-500 text-[10px] pointer-events-none">h</span>
              </div>
              <span className="text-[10px] text-zinc-400">
                (horas por achado • padrão: 4.0h)
              </span>
            </div>
          </div>
        </div>

        {/* Dynamic Backlog Toggle */}
        <div className="p-3 rounded-lg bg-black/40 border border-white/10 mb-5 flex items-start gap-3">
          <input
            id="checkbox-dynamic-mttr"
            type="checkbox"
            checked={dynamicCalculation}
            onChange={(e) => setDynamicCalculation(e.target.checked)}
            className="mt-0.5 rounded border-white/20 bg-black/50 text-emerald-500 focus:ring-0 cursor-pointer"
          />
          <label htmlFor="checkbox-dynamic-mttr" className="cursor-pointer">
            <span className="font-bold text-white text-[11px] block">
              Cálculo Dinâmico por Volume de Achados
            </span>
            <span className="text-[10px] text-zinc-400 font-sans block mt-0.5">
              Multiplica proporcionalmente o MTTR estimado no Tooltip quando múltiplos achados do mesmo nível forem identificados no workspace.
            </span>
          </label>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-3 border-t border-white/10">
          <button
            type="button"
            onClick={handleResetDefaults}
            className="px-3 py-1.5 rounded border border-white/10 bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white transition-colors cursor-pointer inline-flex items-center gap-1.5 text-[11px]"
          >
            <RotateCcw className="w-3 h-3" />
            <span>Restaurar Padrões</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded border border-white/10 bg-black/40 hover:bg-white/5 text-zinc-300 transition-colors cursor-pointer text-[11px]"
            >
              Cancelar
            </button>
            <button
              id="btn-save-mttr-config"
              type="button"
              onClick={handleSave}
              className="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold transition-all cursor-pointer inline-flex items-center gap-1.5 text-[11px] shadow-lg shadow-emerald-950/50"
            >
              {savedSuccess ? (
                <>
                  <Check className="w-3.5 h-3.5" />
                  <span>Salvo!</span>
                </>
              ) : (
                <>
                  <Check className="w-3.5 h-3.5" />
                  <span>Salvar Configuração</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
