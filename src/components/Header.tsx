import React from 'react';
import { 
  ShieldAlert, 
  Play, 
  Download, 
  FileCode2, 
  Terminal, 
  SlidersHorizontal, 
  Route, 
  CloudCog, 
  CheckCircle2, 
  AlertTriangle,
  RotateCcw,
  Compass,
  Ban,
  BookOpen
} from 'lucide-react';
import { ScanReport } from '../types';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  report: ScanReport;
  isScanning: boolean;
  onRunScan: () => void;
  onOpenExport: () => void;
  onResetWorkspace: () => void;
  onOpenTour: () => void;
  onOpenIgnoreModal?: () => void;
  activeIgnoreCount?: number;
  onOpenGlossary?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  report,
  isScanning,
  onRunScan,
  onOpenExport,
  onResetWorkspace,
  onOpenTour,
  onOpenIgnoreModal,
  activeIgnoreCount,
  onOpenGlossary
}) => {
  const criticalCount = report.metrics.criticalCount;
  const isHealthy = criticalCount === 0;

  const navItems = [
    { id: 'dashboard', label: 'Dashboard & Métricas', icon: ShieldAlert },
    { id: 'scanner', label: 'Inspetor de Código', icon: FileCode2, badge: report.findings.length },
    { id: 'endpoints', label: 'Caminhos de API', icon: Route, badge: report.apiEndpoints.length },
    { id: 'rules', label: 'Regras Regex', icon: SlidersHorizontal },
    { id: 'cli', label: 'Terminal CLI', icon: Terminal },
    { id: 'cicd', label: 'CI/CD & Cloud', icon: CloudCog },
  ];

  return (
    <header className="border-b border-[#222] bg-[#050505]/95 backdrop-blur sticky top-0 z-30">
      {/* Top Banner Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-20">
          {/* Brand Logo & Meta */}
          <div className="flex items-center gap-3.5">
            <div className="w-11 h-11 bg-[#111] border border-[#333] flex items-center justify-center text-[#FF3E00] shadow-none">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-baseline gap-2.5">
                <span className="font-black text-2xl sm:text-3xl tracking-tighter text-white uppercase">
                  SECSCAN<span className="text-[#FF3E00]">.JS</span>
                </span>
                <span className="text-[10px] font-mono bg-[#FF3E00] text-white px-2 py-0.5 rounded font-bold uppercase tracking-wider">
                  v1.0-STABLE
                </span>
                <span className="hidden sm:inline-flex items-center text-[10px] font-mono px-2 py-0.5 rounded bg-[#111] text-[#888] border border-[#222]">
                  NODE 22 LTS
                </span>
              </div>
              <p className="text-[11px] font-mono text-[#666] hidden sm:block tracking-wide uppercase mt-0.5">
                SAST Security Engine // Dependency Filter & Secret Matrix
              </p>
            </div>
          </div>

          {/* Quick Stats & Controls */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* Status indicator */}
            <div className={`hidden md:flex items-center gap-2 px-3 py-1.5 border font-mono text-xs font-bold uppercase tracking-wider ${
              isHealthy 
                ? 'bg-[#081f0e] text-[#00FF41] border-[#00FF41]/30' 
                : 'bg-[#220700] text-[#FF3E00] border-[#FF3E00]/40'
            }`}>
              {isHealthy ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-[#00FF41]" />
                  <span>CONFORME</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="w-3.5 h-3.5 text-[#FF3E00]" />
                  <span>{criticalCount} ALERTA{criticalCount > 1 ? 'S' : ''} CRÍTICO{criticalCount > 1 ? 'S' : ''}</span>
                </>
              )}
            </div>

            {/* Quick Tour Button */}
            <button
              id="btn-quick-tour"
              onClick={onOpenTour}
              title="Iniciar Guia Rápido do SecScan"
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-black uppercase tracking-[0.15em] text-[#FF3E00] bg-[#FF3E00]/10 hover:bg-[#FF3E00] hover:text-white border border-[#FF3E00]/30 hover:border-[#FF3E00] transition-all"
            >
              <Compass className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Guia Rápido</span>
            </button>

            {/* Reset Workspace */}
            <button
              id="btn-reset-demo"
              onClick={onResetWorkspace}
              title="Restaurar arquivos de exemplo"
              className="p-2.5 text-[#666] hover:text-white hover:bg-[#111] border border-transparent hover:border-[#222] transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
            </button>

            {/* Global Ignore List Button */}
            {onOpenIgnoreModal && (
              <button
                id="btn-header-open-ignore"
                onClick={onOpenIgnoreModal}
                className="inline-flex items-center gap-2 px-3.5 py-2.5 text-xs font-black uppercase tracking-[0.15em] text-[#AAA] hover:text-[#FF3E00] bg-[#0A0A0A] hover:bg-[#151515] border border-[#333] hover:border-[#FF3E00] transition-all cursor-pointer"
                title="Configurações da Global Ignore List"
              >
                <Ban className="w-3.5 h-3.5 text-[#FF3E00]" />
                <span className="hidden sm:inline">Exclusões</span>
                {activeIgnoreCount !== undefined && (
                  <span className="text-[10px] font-mono px-1.5 py-0.2 bg-[#1A1A1A] text-[#00FF41] border border-[#333] font-bold">
                    {activeIgnoreCount}
                  </span>
                )}
              </button>
            )}

            {/* Security Glossary Button */}
            {onOpenGlossary && (
              <button
                id="btn-header-open-glossary"
                onClick={onOpenGlossary}
                className="inline-flex items-center gap-2 px-3.5 py-2.5 text-xs font-black uppercase tracking-[0.15em] text-[#AAA] hover:text-white bg-[#0A0A0A] hover:bg-[#151515] border border-[#333] hover:border-white transition-all cursor-pointer"
                title="Glossário de Vulnerabilidades & Ameaças (CWE / OWASP)"
              >
                <BookOpen className="w-3.5 h-3.5 text-[#FF3E00]" />
                <span className="hidden sm:inline">Glossário</span>
              </button>
            )}

            {/* Export Button */}
            <button
              id="btn-export-report"
              onClick={onOpenExport}
              className="inline-flex items-center gap-2 px-3.5 py-2.5 text-xs font-black uppercase tracking-[0.15em] text-[#E0E0E0] bg-[#0A0A0A] hover:bg-[#151515] hover:text-white border border-[#333] hover:border-[#555] transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Exportar</span>
            </button>

            {/* Run Scan Action */}
            <button
              id="btn-run-scan"
              onClick={onRunScan}
              disabled={isScanning}
              className={`inline-flex items-center gap-2 px-4 py-2.5 text-xs font-black uppercase tracking-[0.2em] transition-all ${
                isScanning
                  ? 'bg-[#333] text-[#888] cursor-not-allowed'
                  : 'bg-white text-black hover:bg-[#FF3E00] hover:text-white active:scale-95'
              }`}
            >
              <Play className={`w-3.5 h-3.5 fill-current ${isScanning ? 'animate-spin' : ''}`} />
              <span>{isScanning ? 'ANALISANDO...' : 'EXECUTAR ANÁLISE'}</span>
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex space-x-1 sm:space-x-6 border-t border-[#222] pt-1 overflow-x-auto no-scrollbar">
          {navItems.map(item => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                id={`nav-tab-${item.id}`}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center gap-2.5 py-3 px-2 text-[11px] font-black tracking-widest uppercase border-b-2 whitespace-nowrap transition-all ${
                  isActive
                    ? 'border-[#FF3E00] text-[#FF3E00] bg-[#FF3E00]/5'
                    : 'border-transparent text-[#666] hover:text-[#E0E0E0] hover:border-[#333]'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-[#FF3E00]' : 'text-[#555]'}`} />
                <span>{item.label}</span>
                {item.badge !== undefined && (
                  <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
                    isActive 
                      ? 'bg-[#FF3E00] text-white' 
                      : 'bg-[#1A1A1A] text-[#888] border border-[#222]'
                  }`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
