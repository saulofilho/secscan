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
  Boxes,
  Network,
  CheckCircle2, 
  AlertTriangle,
  RotateCcw,
  Compass,
  Ban,
  BookOpen,
  Clock
} from 'lucide-react';
import { ScanReport, ScanProgress } from '../types';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  report: ScanReport;
  isScanning: boolean;
  scanProgress?: ScanProgress | null;
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
  scanProgress,
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
    { id: 'endpoints', label: 'LinkFinder (APIs)', icon: Route, badge: report.apiEndpoints.length },
    { id: 'jsminer', label: 'JS Miner', icon: Boxes, badge: report.jsMiner?.totalAssetsCount },
    { id: 'dataflow', label: 'Fluxo & Sinks (D3)', icon: Network, badge: report.dataFlowGraph?.metrics.totalTaintFlows },
    { id: 'rules', label: 'Regras Regex', icon: SlidersHorizontal },
    { id: 'cli', label: 'Terminal CLI', icon: Terminal },
    { id: 'cicd', label: 'CI/CD & Cloud', icon: CloudCog },
  ];

  return (
    <header className="w-full border-b border-[#222] bg-[#050505]/95 backdrop-blur-md sticky top-0 z-30">
      {/* Top Banner Bar & Navigation Container */}
      <div className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8">
        {/* Main Header Bar (Responsive Brand + Toolbar) */}
        <div className="w-full flex flex-wrap 2xl:flex-nowrap items-center justify-between py-2.5 sm:py-3.5 gap-2.5 sm:gap-3 border-b border-[#1A1A1A]">
          {/* Brand Logo & Meta */}
          <div className="flex items-center gap-2.5 sm:gap-3.5 shrink-0">
            <div className="w-10 h-10 sm:w-11 sm:h-11 bg-gradient-to-b from-[#1C1C1C] to-[#0A0A0A] border border-[#333] hover:border-[#FF3E00]/60 rounded-lg flex items-center justify-center text-[#FF3E00] shrink-0 shadow-[0_0_15px_rgba(255,62,0,0.15)] relative group transition-all">
              <ShieldAlert className="w-5 h-5 sm:w-6 sm:h-6 text-[#FF3E00] drop-shadow-[0_0_6px_rgba(255,62,0,0.5)] transition-transform group-hover:scale-110" />
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                  (report.metrics.riskScore ?? 0) >= 75 ? 'bg-[#FF3E00]' : (report.metrics.riskScore ?? 0) >= 50 ? 'bg-[#FF7A00]' : 'bg-[#00FF41]'
                }`} />
                <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                  (report.metrics.riskScore ?? 0) >= 75 ? 'bg-[#FF3E00]' : (report.metrics.riskScore ?? 0) >= 50 ? 'bg-[#FF7A00]' : 'bg-[#00FF41]'
                }`} />
              </span>
            </div>
            <div>
              <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
                <div className="flex items-center">
                  <span className="font-black text-lg sm:text-2xl tracking-tight text-white uppercase">
                    SECSCAN
                  </span>
                  <span className="text-[#FF3E00] font-black tracking-tight text-lg sm:text-2xl uppercase ml-1.5 drop-shadow-[0_0_8px_rgba(255,62,0,0.4)]">
                    APPSEC
                  </span>
                  <span className="ml-2 px-1.5 sm:px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-200 text-[9px] sm:text-[10px] font-black tracking-widest uppercase shadow-xs">
                    SUITE
                  </span>
                </div>
                <span className="text-[9px] sm:text-[9.5px] font-mono bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/30 px-1.5 py-0.5 rounded font-bold uppercase tracking-wider">
                  v2.5
                </span>
                <span className="hidden md:inline-flex items-center text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#111] text-zinc-400 border border-[#222]">
                  ENTERPRISE SAST
                </span>
              </div>
              <p className="text-[10px] font-mono text-[#777] hidden xl:flex items-center gap-2 tracking-wider uppercase mt-0.5">
                <span>SAST &amp; Secret Matrix // DataFlow Taint Platform</span>
                <span className="text-[#333]">•</span>
                <span className="text-zinc-400 flex items-center gap-1">
                  <Clock className="w-3 h-3 text-[#00FF41]" />
                  <span>Duração: <strong className="text-[#00FF41] font-mono">{report.durationMs ?? 0}ms</strong></span>
                </span>
                <span className="text-[#333] hidden 2xl:inline">•</span>
                <span className="text-zinc-400 hidden 2xl:flex items-center gap-1">
                  <span>Score Risco:</span>
                  <strong className={`font-mono font-bold ${
                    (report.metrics.riskScore ?? 0) >= 75 ? 'text-[#FF3E00]' :
                    (report.metrics.riskScore ?? 0) >= 50 ? 'text-[#FF7A00]' :
                    (report.metrics.riskScore ?? 0) >= 25 ? 'text-amber-400' : 'text-[#00FF41]'
                  }`}>
                    {report.metrics.riskScore ?? 0}/100 [{report.metrics.riskLevel ?? 'MINIMAL'}]
                  </strong>
                </span>
              </p>
            </div>
          </div>

          {/* Quick Stats & Action Toolbar */}
          <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap justify-end">
            {/* Cumulative Workspace Risk Score Pill */}
            <button
              id="header-workspace-risk-score-badge"
              type="button"
              onClick={() => {
                if (activeTab !== 'dashboard') {
                  setActiveTab('dashboard');
                }
                setTimeout(() => {
                  const el = document.getElementById('cumulative-risk-validation-section') || 
                             document.getElementById('metric-card-cumulative-risk-score') ||
                             document.getElementById('cumulative-risk-score-gauge-card');
                  if (el) el.scrollIntoView({ behavior: 'smooth' });
                }, 100);
              }}
              className={`flex items-center gap-1.5 h-8 px-2.5 sm:px-3 rounded border font-mono text-[11px] font-bold uppercase tracking-wider transition-all cursor-pointer ${
                (report.metrics.riskScore ?? 0) >= 75
                  ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40 hover:bg-[#FF3E00]/25'
                  : (report.metrics.riskScore ?? 0) >= 50
                  ? 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/40 hover:bg-[#FF7A00]/25'
                  : (report.metrics.riskScore ?? 0) >= 25
                  ? 'bg-amber-500/15 text-amber-400 border-amber-500/40 hover:bg-amber-500/25'
                  : 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/30 hover:bg-[#00FF41]/20'
              }`}
              title={`Score de Risco Cumulativo do Workspace: ${report.metrics.riskScore ?? 0}/100 [${report.metrics.riskLevel ?? 'MINIMAL'}]. Clique para visualizar detalhes de cálculo.`}
            >
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              <span className="text-zinc-400 text-[10px] uppercase tracking-wider hidden sm:inline">
                Risk Score:
              </span>
              <span className="font-mono font-black tracking-tight">
                {report.metrics.riskScore ?? 0}/100
              </span>
              <span className="text-[9px] px-1 py-0.2 rounded bg-black/40 border border-current hidden md:inline">
                {report.metrics.riskLevel ?? 'MINIMAL'}
              </span>
            </button>

            {/* Scan Duration Indicator */}
            <button
              id="header-scan-duration-badge"
              type="button"
              onClick={() => {
                if (activeTab !== 'dashboard') {
                  setActiveTab('dashboard');
                }
                setTimeout(() => {
                  const el = document.getElementById('scan-speedometer-gauge-section');
                  if (el) el.scrollIntoView({ behavior: 'smooth' });
                }, 100);
              }}
              className={`flex items-center gap-1.5 h-8 px-2.5 sm:px-3 rounded border font-mono text-[11px] font-bold uppercase tracking-wider transition-all cursor-pointer ${
                isScanning
                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                  : 'bg-[#0F0F0F] hover:bg-[#1A1A1A] text-[#00FF41] border-[#2A2A2A] hover:border-[#00FF41]/50 shadow-xs'
              }`}
              title={
                isScanning
                  ? 'Executando análise do código-fonte em tempo real...'
                  : `Duração total do último scan: ${report.durationMs ?? 0}ms. Clique para visualizar o velocímetro de execução.`
              }
            >
              <Clock className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin text-amber-400' : 'text-[#00FF41]'} shrink-0`} />
              <span className="text-zinc-400 text-[10px] uppercase tracking-wider hidden sm:inline">
                Scan:
              </span>
              <span className="font-mono font-bold tracking-tight">
                {isScanning ? 'MEDINDO...' : `${report.durationMs ?? 0}ms`}
              </span>
            </button>

            {/* Status indicator pill */}
            <div className={`flex items-center gap-1.5 h-8 px-2.5 rounded border font-mono text-[11px] font-bold uppercase tracking-wider ${
              isHealthy 
                ? 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/30' 
                : 'bg-[#FF3E00]/10 text-[#FF3E00] border-[#FF3E00]/40'
            }`}>
              {isHealthy ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-[#00FF41] animate-pulse" />
                  <span>CONFORME</span>
                </>
              ) : (
                <>
                  <span className="w-2 h-2 rounded-full bg-[#FF3E00] animate-pulse" />
                  <span>{criticalCount} CRÍTICO{criticalCount > 1 ? 'S' : ''}</span>
                </>
              )}
            </div>

            {/* Tutorial Button */}
            <button
              id="btn-quick-tour"
              onClick={onOpenTour}
              title="Abrir Tutorial Completo da Ferramenta SecScan"
              className="h-8 px-2.5 sm:px-3 rounded inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-[#FF3E00] bg-[#FF3E00]/15 hover:bg-[#FF3E00] hover:text-white border border-[#FF3E00]/40 hover:border-[#FF3E00] transition-all cursor-pointer shadow-[0_0_12px_rgba(255,62,0,0.15)]"
            >
              <Compass className="w-3.5 h-3.5 shrink-0 animate-spin-slow" />
              <span>Tutorial</span>
            </button>

            {/* Global Ignore List Button */}
            {onOpenIgnoreModal && (
              <button
                id="btn-header-open-ignore"
                onClick={onOpenIgnoreModal}
                className="h-8 px-2.5 sm:px-3 rounded inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-[#AAA] hover:text-white bg-[#0F0F0F] hover:bg-[#1A1A1A] border border-[#2A2A2A] hover:border-[#444] transition-all cursor-pointer"
                title="Configurações da Global Ignore List"
              >
                <Ban className="w-3.5 h-3.5 text-[#FF3E00] shrink-0" />
                <span className="hidden xl:inline">Exclusões</span>
                {activeIgnoreCount !== undefined && (
                  <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-[#1A1A1A] text-[#00FF41] border border-[#333] font-bold">
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
                className="h-8 px-2.5 sm:px-3 rounded inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-[#AAA] hover:text-white bg-[#0F0F0F] hover:bg-[#1A1A1A] border border-[#2A2A2A] hover:border-[#444] transition-all cursor-pointer"
                title="Glossário de Vulnerabilidades & Ameaças (CWE / OWASP)"
              >
                <BookOpen className="w-3.5 h-3.5 text-[#FF3E00] shrink-0" />
                <span className="hidden xl:inline">Glossário</span>
              </button>
            )}

            {/* Export Button */}
            <button
              id="btn-export-report"
              onClick={onOpenExport}
              className="h-8 px-2.5 sm:px-3 rounded inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-300 hover:text-white bg-[#0F0F0F] hover:bg-[#1A1A1A] border border-[#2A2A2A] hover:border-[#444] transition-all cursor-pointer"
              title="Exportar Relatório de Segurança"
            >
              <Download className="w-3.5 h-3.5 shrink-0" />
              <span className="hidden sm:inline">Exportar</span>
            </button>

            {/* Reset Workspace */}
            <button
              id="btn-reset-demo"
              onClick={onResetWorkspace}
              title="Restaurar arquivos de exemplo"
              className="h-8 w-8 rounded flex items-center justify-center text-[#777] hover:text-white bg-[#0F0F0F] hover:bg-[#1A1A1A] border border-[#2A2A2A] hover:border-[#444] transition-colors cursor-pointer shrink-0"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>

            {/* Primary Action: Run Scan */}
            <button
              id="btn-run-scan"
              onClick={onRunScan}
              disabled={isScanning}
              className={`h-8 px-3.5 sm:px-4 rounded inline-flex items-center gap-2 font-mono text-[11px] font-black uppercase tracking-wider transition-all cursor-pointer shadow-sm shrink-0 ${
                isScanning
                  ? 'bg-[#262626] text-[#777] cursor-not-allowed border border-[#333]'
                  : 'bg-white text-black hover:bg-[#FF3E00] hover:text-white hover:border-[#FF3E00] border border-white active:scale-95'
              }`}
            >
              <Play className={`w-3 h-3 fill-current ${isScanning ? 'animate-spin' : ''}`} />
              <span>
                {isScanning 
                  ? `ANALISANDO${scanProgress ? ` (${scanProgress.percentage}%)` : '...'}` 
                  : 'EXECUTAR ANÁLISE'}
              </span>
            </button>
          </div>
        </div>

        {/* Navigation Tabs Bar */}
        <nav className="flex items-center gap-1 sm:gap-2 pt-1.5 pb-2 overflow-x-auto no-scrollbar">
          {navItems.map(item => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                id={`nav-tab-${item.id}`}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center gap-2 py-2 px-3 rounded text-[11px] font-mono font-bold tracking-wide uppercase whitespace-nowrap transition-all cursor-pointer border ${
                  isActive
                    ? 'bg-[#141414] text-[#FF3E00] border-[#FF3E00]/40 shadow-sm'
                    : 'bg-transparent text-[#888] hover:text-white hover:bg-[#0F0F0F] border-transparent'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-[#FF3E00]' : 'text-[#666]'}`} />
                <span>{item.label}</span>
                {item.badge !== undefined && (
                  <span className={`text-[9.5px] font-mono px-1.5 py-0.2 rounded font-bold ${
                    isActive 
                      ? 'bg-[#FF3E00] text-white' 
                      : 'bg-[#181818] text-[#888] border border-[#262626]'
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
