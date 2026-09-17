import React, { useMemo } from 'react';
import {
  Keyboard,
  X,
  Command,
  Play,
  Download,
  BookOpen,
  Ban,
  RotateCcw,
  Sparkles,
  Layers,
  ArrowRight,
  ShieldAlert
} from 'lucide-react';

interface KeyboardShortcutsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onOpenCommandPalette: () => void;
}

export const KeyboardShortcutsModal: React.FC<KeyboardShortcutsModalProps> = ({
  isOpen,
  onClose,
  onOpenCommandPalette
}) => {
  const isMac = useMemo(() => {
    return typeof window !== 'undefined' && /Mac|iPod|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  }, []);

  const modKey = isMac ? '⌘' : 'Ctrl+';

  if (!isOpen) return null;

  const shortcutGroups = [
    {
      group: 'Ações Globais Principais',
      shortcuts: [
        {
          keys: [`${modKey}K`],
          description: 'Abrir Command Palette (Busca e comandos rápidos)',
          tag: 'Principal'
        },
        {
          keys: [`${modKey}S`],
          description: 'Executar Análise SAST de Segurança no Workspace',
          tag: 'Scap'
        },
        {
          keys: [`${modKey}E`],
          description: 'Exportar Relatório Consolidado (PDF / JSON / SARIF)',
          tag: 'Export'
        },
        {
          keys: [`${modKey}G`],
          description: 'Abrir Glossário de Vulnerabilidades & Ameaças (CWE / OWASP)',
          tag: 'Docs'
        },
        {
          keys: [`${modKey}I`],
          description: 'Abrir Configurações da Global Ignore List',
          tag: 'Filtros'
        },
        {
          keys: [`${modKey}/`, '?'],
          description: 'Abrir este painel de Atalhos de Teclado',
          tag: 'Ajuda'
        },
        {
          keys: [`${modKey}B`],
          description: 'Restaurar arquivos de exemplo do Workspace Demo',
          tag: 'Reset'
        },
        {
          keys: ['Esc'],
          description: 'Fechar qualquer modal, popover ou Command Palette aberto',
          tag: 'Fechar'
        }
      ]
    },
    {
      group: 'Navegação Direta entre Módulos',
      shortcuts: [
        {
          keys: [`${modKey}1`, '1'],
          description: 'Ir para Dashboard & Métricas Executivas',
          tag: 'Módulo'
        },
        {
          keys: [`${modKey}2`, '2'],
          description: 'Ir para Inspetor de Código & Vulnerabilidades',
          tag: 'Módulo'
        },
        {
          keys: [`${modKey}3`, '3'],
          description: 'Ir para LinkFinder (Rotas & Endpoints de API)',
          tag: 'Módulo'
        },
        {
          keys: [`${modKey}4`, '4'],
          description: 'Ir para JS Miner & Varredura de Bundles',
          tag: 'Módulo'
        },
        {
          keys: [`${modKey}5`, '5'],
          description: 'Ir para Fluxo de Dados & Taint Sinks D3',
          tag: 'Módulo'
        },
        {
          keys: [`${modKey}6`, '6'],
          description: 'Ir para Frameworks de Cibersegurança (MITRE/NIST/OWASP)',
          tag: 'Módulo'
        },
        {
          keys: [`${modKey}7`, '7'],
          description: 'Ir para Security Onion (SOC, Threat Hunting & Cases)',
          tag: 'Módulo'
        },
        {
          keys: [`${modKey}8`, '8'],
          description: 'Ir para CrowdStrike Falcon (EDR, IOA & Threat Graph)',
          tag: 'Módulo'
        },
        {
          keys: [`${modKey}9`, '9'],
          description: 'Ir para Editor de Regras Regex & Entropia',
          tag: 'Módulo'
        },
        {
          keys: [`${modKey}0`, '0'],
          description: 'Ir para Terminal CLI Interativo',
          tag: 'Módulo'
        },
        {
          keys: [`${modKey}-`, '-'],
          description: 'Ir para CI/CD & Integração Cloud',
          tag: 'Módulo'
        }
      ]
    },
    {
      group: 'Navegação no Command Palette (⌘K)',
      shortcuts: [
        {
          keys: ['↑', '↓'],
          description: 'Navegar entre comandos e arquivos listados'
        },
        {
          keys: ['Enter'],
          description: 'Executar o comando em foco ou abrir arquivo selecionado'
        },
        {
          keys: ['Esc'],
          description: 'Fechar o Command Palette e retornar ao workspace'
        }
      ]
    }
  ];

  return (
    <div
      id="keyboard-shortcuts-modal-backdrop"
      className="fixed inset-0 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4 z-50 animate-in fade-in duration-150"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        id="keyboard-shortcuts-modal-dialog"
        className="bg-[#0D0D0D] border border-[#2E2E2E] rounded-lg shadow-2xl w-full max-w-2xl overflow-hidden flex flex-col max-h-[85vh] animate-in zoom-in-95 duration-150"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#222] bg-[#121212]">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded bg-[#FF3E00]/15 border border-[#FF3E00]/40 flex items-center justify-center text-[#FF3E00]">
              <Keyboard className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-white font-mono font-bold text-base flex items-center gap-2">
                <span>Atalhos Globais de Teclado</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#1C1C1C] text-zinc-400 border border-[#333] font-normal">
                  PRO WORKFLOW
                </span>
              </h2>
              <p className="text-xs font-mono text-zinc-400 mt-0.5">
                Aumente a eficiência operacional com atalhos de alta produtividade
              </p>
            </div>
          </div>

          <button
            id="btn-close-shortcuts-modal"
            type="button"
            onClick={onClose}
            className="text-zinc-400 hover:text-white p-1.5 rounded hover:bg-[#1C1C1C] transition-colors cursor-pointer"
            title="Fechar (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="overflow-y-auto flex-1 p-5 space-y-6">
          {shortcutGroups.map((group) => (
            <div key={group.group} className="space-y-2">
              <h3 className="text-xs font-mono font-bold text-zinc-400 uppercase tracking-wider flex items-center gap-2 border-b border-[#1F1F1F] pb-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#FF3E00]" />
                <span>{group.group}</span>
              </h3>

              <div className="grid grid-cols-1 gap-1.5">
                {group.shortcuts.map((s, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between py-2 px-3 rounded bg-[#111] hover:bg-[#161616] border border-[#1E1E1E] transition-colors font-mono text-xs"
                  >
                    <span className="text-zinc-300 mr-3">{s.description}</span>
                    <div className="flex items-center gap-1.5 shrink-0">
                      {s.keys.map((k, kidx) => (
                        <kbd
                          key={kidx}
                          className="px-2 py-0.5 rounded bg-[#1C1C1C] border border-[#333] text-zinc-200 font-bold text-[11px] shadow-xs"
                        >
                          {k}
                        </kbd>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="px-5 py-3.5 bg-[#121212] border-t border-[#222] flex items-center justify-between">
          <button
            type="button"
            onClick={() => {
              onClose();
              onOpenCommandPalette();
            }}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-[#FF3E00]/15 hover:bg-[#FF3E00] text-[#FF3E00] hover:text-white border border-[#FF3E00]/40 transition-all font-mono text-xs font-bold cursor-pointer"
          >
            <Command className="w-3.5 h-3.5" />
            <span>Abrir Command Palette ({modKey}K)</span>
          </button>

          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 font-mono text-xs font-bold transition-colors cursor-pointer"
          >
            Entendido
          </button>
        </div>
      </div>
    </div>
  );
};
