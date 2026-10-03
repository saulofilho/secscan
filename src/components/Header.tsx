import React, { useMemo, useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck,
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
  Trash2,
  Compass,
  Ban,
  BookOpen,
  Clock,
  Command,
  Keyboard,
  Radio,
  Zap,
  Globe,
  FileSearch,
  Flame,
  Crosshair,
  Binary,
  Activity,
  Package,
  Container,
  FileSpreadsheet,
  Target,
  Wrench,
  Scale,
  Lock,
  Key,
  KeyRound,
  Layers,
  Sparkles,
  Workflow,
  FileCheck,
  Cpu,
  Search,
  TrendingDown,
  X
} from 'lucide-react';
import { ScanReport, ScanProgress } from '../types';
import { useLanguage } from '../lib/i18nContext';
import { LanguageSwitcher } from './LanguageSwitcher';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  report: ScanReport;
  isScanning: boolean;
  scanProgress?: ScanProgress | null;
  onRunScan: () => void;
  onOpenExport: () => void;
  onResetWorkspace: () => void;
  onClearWorkspace?: () => void;
  onOpenTour: () => void;
  onOpenIgnoreModal?: () => void;
  activeIgnoreCount?: number;
  onOpenGlossary?: () => void;
  onOpenCommandPalette?: () => void;
  onOpenShortcuts?: () => void;
  onOpenToolGuide?: (toolId?: string) => void;
  onOpenGitignoreAudit?: () => void;
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
  onClearWorkspace,
  onOpenTour,
  onOpenIgnoreModal,
  activeIgnoreCount,
  onOpenGlossary,
  onOpenCommandPalette,
  onOpenShortcuts,
  onOpenToolGuide,
  onOpenGitignoreAudit
}) => {
  const isMac = useMemo(() => {
    return typeof window !== 'undefined' && /Mac|iPod|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  }, []);

  const { t, language } = useLanguage();

  const [selectedCategory, setSelectedCategory] = useState<'ALL' | 'CODE_SAST' | 'CLOUD_INFRA' | 'API_DAST' | 'SOC_EDR' | 'GOV_AI'>('ALL');
  const [toolSearchTerm, setToolSearchTerm] = useState('');

  // Global shortcut '/' to focus tool search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === '/' && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)) {
        e.preventDefault();
        const input = document.getElementById('nav-tool-search-input');
        if (input) {
          input.focus();
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const criticalCount = report.metrics.criticalCount;
  const isHealthy = criticalCount === 0;

  const navItems = useMemo<{ id: string; category: 'CODE_SAST' | 'CLOUD_INFRA' | 'API_DAST' | 'SOC_EDR' | 'GOV_AI'; label: string; icon: any; badge?: any; tooltip: string }[]>(() => [
    { id: 'dashboard', category: 'GOV_AI', label: t('tab.dashboard'), icon: ShieldAlert, tooltip: t('tab.dashboard_tooltip') },
    { id: 'trenddashboard', category: 'GOV_AI', label: t('tab.trenddashboard'), icon: TrendingDown, badge: 'Trends', tooltip: t('tab.trenddashboard_tooltip') },
    { id: 'scanner', category: 'CODE_SAST', label: t('tab.scanner'), icon: FileCode2, badge: report.findings.length, tooltip: t('tab.scanner_tooltip') },
    { id: 'endpoints', category: 'CODE_SAST', label: t('tab.endpoints'), icon: Route, badge: report.apiEndpoints.length, tooltip: t('tab.endpoints_tooltip') },
    { id: 'jsminer', category: 'CODE_SAST', label: t('tab.jsminer'), icon: Boxes, badge: report.jsMiner?.totalAssetsCount, tooltip: t('tab.jsminer_tooltip') },
    { id: 'dataflow', category: 'CODE_SAST', label: t('tab.dataflow'), icon: Network, badge: report.dataFlowGraph?.metrics.totalTaintFlows, tooltip: t('tab.dataflow_tooltip') },
    { id: 'iast', category: 'CODE_SAST', label: t('tab.iast'), icon: Activity, badge: report.iastReport?.findings.length ? `${report.iastReport.findings.length} hooks` : 'IAST', tooltip: t('tab.iast_tooltip') },
    { id: 'sca', category: 'CODE_SAST', label: t('tab.sca'), icon: Package, badge: 'SCA', tooltip: t('tab.sca_tooltip') },
    { id: 'iac', category: 'CLOUD_INFRA', label: t('tab.iac'), icon: Container, badge: 'IaC', tooltip: t('tab.iac_tooltip') },
    { id: 'apisecurity', category: 'API_DAST', label: t('tab.apisecurity'), icon: Route, badge: 'OWASP', tooltip: t('tab.apisecurity_tooltip') },
    { id: 'asocsla', category: 'GOV_AI', label: t('tab.asocsla'), icon: Clock, badge: 'SLA', tooltip: t('tab.asocsla_tooltip') },
    { id: 'dast', category: 'API_DAST', label: t('tab.dast'), icon: Crosshair, badge: 'DAST', tooltip: t('tab.dast_tooltip') },
    { id: 'sbom', category: 'GOV_AI', label: t('tab.sbom'), icon: FileSpreadsheet, badge: 'CycloneDX', tooltip: t('tab.sbom_tooltip') },
    { id: 'entropy', category: 'CODE_SAST', label: t('tab.entropy'), icon: Binary, badge: 'Entropy', tooltip: t('tab.entropy_tooltip') },
    { id: 'threatmodel', category: 'GOV_AI', label: t('tab.threatmodel'), icon: Target, badge: 'STRIDE', tooltip: t('tab.threatmodel_tooltip') },
    { id: 'ctihub', category: 'GOV_AI', label: t('tab.ctihub'), icon: Globe, badge: 'OTX', tooltip: t('tab.ctihub_tooltip') },
    { id: 'autoremediation', category: 'CODE_SAST', label: t('tab.autoremediation'), icon: Wrench, badge: '1-Click', tooltip: t('tab.autoremediation_tooltip') },
    { id: 'refactoring', category: 'CODE_SAST', label: t('tab.refactoring'), icon: Sparkles, badge: 'Modernize', tooltip: t('tab.refactoring_tooltip') },
    { id: 'soarbuilder', category: 'GOV_AI', label: t('tab.soarbuilder'), icon: Workflow, badge: 'Flow', tooltip: t('tab.soarbuilder_tooltip') },
    { id: 'llmsecurity', category: 'GOV_AI', label: t('tab.llmsecurity'), icon: Cpu, badge: 'OWASP LLM', tooltip: t('tab.llmsecurity_tooltip') },
    { id: 'procyber', category: 'GOV_AI', label: t('tab.procyber'), icon: ShieldAlert, badge: '10 PRO', tooltip: t('tab.procyber_tooltip') },
    { id: 'policyascode', category: 'GOV_AI', label: t('tab.policyascode'), icon: FileCheck, badge: report.opaCompliance ? `${report.opaCompliance.complianceScore}%` : 'Rego', tooltip: t('tab.policyascode_tooltip') },
    { id: 'compliance', category: 'GOV_AI', label: t('tab.compliance'), icon: Scale, badge: 'SOC2', tooltip: t('tab.compliance_tooltip') },
    { id: 'frameworks', category: 'GOV_AI', label: t('tab.frameworks'), icon: ShieldCheck, tooltip: t('tab.frameworks_tooltip') },
    { id: 'soccommand', category: 'SOC_EDR', label: t('tab.soccommand'), icon: Radio, badge: 'LIVE', tooltip: t('tab.soccommand_tooltip') },
    { id: 'securityonion', category: 'SOC_EDR', label: t('tab.securityonion'), icon: Layers, badge: report.findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length, tooltip: t('tab.securityonion_tooltip') },
    { id: 'crowdstrike', category: 'SOC_EDR', label: t('tab.crowdstrike'), icon: Zap, badge: 3, tooltip: t('tab.crowdstrike_tooltip') },
    { id: 'edr', category: 'CLOUD_INFRA', label: t('tab.edr'), icon: Crosshair, badge: 'eBPF', tooltip: t('tab.edr_tooltip') },
    { id: 'nmap', category: 'SOC_EDR', label: t('tab.nmap'), icon: Globe, badge: 'Recon', tooltip: t('tab.nmap_tooltip') },
    { id: 'nikto', category: 'SOC_EDR', label: t('tab.nikto'), icon: FileSearch, badge: 'Audit', tooltip: t('tab.nikto_tooltip') },
    { id: 'ngfw', category: 'CLOUD_INFRA', label: t('tab.ngfw'), icon: Flame, badge: 'L7/IPS', tooltip: t('tab.ngfw_tooltip') },
    { id: 'idsips', category: 'CLOUD_INFRA', label: t('tab.idsips'), icon: Binary, badge: 'DPI', tooltip: t('tab.idsips_tooltip') },
    { id: 'dnssec', category: 'CLOUD_INFRA', label: t('tab.dnssec'), icon: Globe, badge: 'DoH', tooltip: t('tab.dnssec_tooltip') },
    { id: 'waf', category: 'SOC_EDR', label: t('tab.waf'), icon: ShieldCheck, badge: 'OWASP', tooltip: t('tab.waf_tooltip') },
    { id: 'sdwan', category: 'CLOUD_INFRA', label: t('tab.sdwan'), icon: Network, badge: 'Overlay', tooltip: t('tab.sdwan_tooltip') },
    { id: 'headers', category: 'API_DAST', label: t('tab.headers'), icon: Lock, badge: 'OWASP', tooltip: t('tab.headers_tooltip') },
    { id: 'containerscan', category: 'CLOUD_INFRA', label: t('tab.containerscan'), icon: Container, badge: 'CIS', tooltip: t('tab.containerscan_tooltip') },
    { id: 'cloudiam', category: 'CLOUD_INFRA', label: t('tab.cloudiam'), icon: Key, badge: 'IAM', tooltip: t('tab.cloudiam_tooltip') },
    { id: 'jwtinspector', category: 'API_DAST', label: t('tab.jwtinspector'), icon: KeyRound, badge: 'RFC7519', tooltip: t('tab.jwtinspector_tooltip') },
    { id: 'ssrfvalidator', category: 'API_DAST', label: t('tab.ssrfvalidator'), icon: Globe, badge: 'SSRF', tooltip: t('tab.ssrfvalidator_tooltip') },
    { id: 'rules', category: 'GOV_AI', label: t('tab.rules'), icon: SlidersHorizontal, tooltip: t('tab.rules_tooltip') },
    { id: 'cli', category: 'GOV_AI', label: t('tab.cli'), icon: Terminal, tooltip: t('tab.cli_tooltip') },
    { id: 'pipelineflow', category: 'GOV_AI', label: t('tab.pipelineflow'), icon: Workflow, badge: 'Flow', tooltip: t('tab.pipelineflow_tooltip') },
    { id: 'cicd', category: 'GOV_AI', label: t('tab.cicd'), icon: CloudCog, tooltip: t('tab.cicd_tooltip') },
  ], [t, language, report]);

  // Auto-switch domain category if activeTab belongs to a different domain
  useEffect(() => {
    const item = navItems.find(i => i.id === activeTab);
    if (item && selectedCategory !== 'ALL' && item.category !== selectedCategory) {
      setSelectedCategory('ALL');
    }
  }, [activeTab, navItems, selectedCategory]);

  const visibleNavItems = useMemo(() => {
    let items = selectedCategory === 'ALL' ? navItems : navItems.filter(item => item.category === selectedCategory);
    if (toolSearchTerm.trim()) {
      const q = toolSearchTerm.toLowerCase().trim();
      items = items.filter(item => 
        item.label.toLowerCase().includes(q) || 
        item.id.toLowerCase().includes(q) || 
        item.tooltip.toLowerCase().includes(q) ||
        (typeof item.badge === 'string' && item.badge.toLowerCase().includes(q))
      );
    }
    return items;
  }, [selectedCategory, navItems, toolSearchTerm]);

  const SECOPS_DOMAINS = useMemo(() => [
    { id: 'ALL' as const, label: t('nav.category_all'), count: navItems.length },
    { id: 'CODE_SAST' as const, label: t('nav.category_code_sast'), count: navItems.filter(i => i.category === 'CODE_SAST').length },
    { id: 'CLOUD_INFRA' as const, label: t('nav.category_cloud_infra'), count: navItems.filter(i => i.category === 'CLOUD_INFRA').length },
    { id: 'API_DAST' as const, label: t('nav.category_api_dast'), count: navItems.filter(i => i.category === 'API_DAST').length },
    { id: 'SOC_EDR' as const, label: t('nav.category_soc_edr'), count: navItems.filter(i => i.category === 'SOC_EDR').length },
    { id: 'GOV_AI' as const, label: t('nav.category_gov_ai'), count: navItems.filter(i => i.category === 'GOV_AI').length },
  ], [t, navItems]);

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
                <span>{t('app.tagline')}</span>
                <span className="text-[#333]">•</span>
                <span className="text-zinc-400 flex items-center gap-1">
                  <Clock className="w-3 h-3 text-[#00FF41]" />
                  <span>{t('app.duration')} <strong className="text-[#00FF41] font-mono">{report.durationMs ?? 0}ms</strong></span>
                </span>
                <span className="text-[#333] hidden 2xl:inline">•</span>
                <span className="text-zinc-400 hidden 2xl:flex items-center gap-1">
                  <span>{t('app.risk_score')}</span>
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
              title={`${t('app.risk_score')} ${report.metrics.riskScore ?? 0}/100 [${report.metrics.riskLevel ?? 'MINIMAL'}]`}
            >
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              <span className="text-zinc-400 text-[10px] uppercase tracking-wider hidden sm:inline">
                {t('app.risk_score')}
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
                  ? t('action.scanning')
                  : `${t('app.duration')} ${report.durationMs ?? 0}ms.`
              }
            >
              <Clock className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin text-amber-400' : 'text-[#00FF41]'} shrink-0`} />
              <span className="text-zinc-400 text-[10px] uppercase tracking-wider hidden sm:inline">
                {t('app.duration')}
              </span>
              <span className="font-mono font-bold tracking-tight">
                {isScanning ? t('app.scan_measuring') : `${report.durationMs ?? 0}ms`}
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
                  <span>{t('app.healthy')}</span>
                </>
              ) : (
                <>
                  <span className="w-2 h-2 rounded-full bg-[#FF3E00] animate-pulse" />
                  <span>{t('app.critical_findings', { count: criticalCount, plural: criticalCount > 1 ? 'S' : '' })}</span>
                </>
              )}
            </div>

            {/* Language Switcher */}
            <LanguageSwitcher />

            {/* Command Palette Button */}
            {onOpenCommandPalette && (
              <button
                id="btn-header-open-command-palette"
                onClick={onOpenCommandPalette}
                className="h-8 px-2.5 sm:px-3 rounded inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-white bg-[#181818] hover:bg-[#222] border border-[#333] hover:border-[#FF3E00]/60 transition-all cursor-pointer shadow-xs group"
                title={`Abrir Command Palette (${isMac ? '⌘K' : 'Ctrl+K'})`}
              >
                <Command className="w-3.5 h-3.5 text-[#FF3E00] group-hover:scale-110 transition-transform shrink-0" />
                <span className="hidden lg:inline text-zinc-200">{t('action.commands')}</span>
                <kbd className="hidden sm:inline-flex items-center text-[9px] font-mono px-1 py-0.2 rounded bg-[#0A0A0A] text-zinc-400 border border-[#333] font-semibold">
                  {isMac ? '⌘K' : 'Ctrl+K'}
                </kbd>
              </button>
            )}

            {/* Tutorial Button */}
            <button
              id="btn-quick-tour"
              onClick={onOpenTour}
              title="Abrir Tutorial Completo da Ferramenta SecScan"
              className="h-8 px-2.5 sm:px-3 rounded inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-[#FF3E00] bg-[#FF3E00]/15 hover:bg-[#FF3E00] hover:text-white border border-[#FF3E00]/40 hover:border-[#FF3E00] transition-all cursor-pointer shadow-[0_0_12px_rgba(255,62,0,0.15)]"
            >
              <Compass className="w-3.5 h-3.5 shrink-0 animate-spin-slow" />
              <span>{t('action.tutorial')}</span>
            </button>

            {/* Global Ignore List Button */}
            {onOpenIgnoreModal && (
              <button
                id="btn-header-open-ignore"
                onClick={onOpenIgnoreModal}
                className="h-8 px-2.5 sm:px-3 rounded inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-[#AAA] hover:text-white bg-[#0F0F0F] hover:bg-[#1A1A1A] border border-[#2A2A2A] hover:border-[#444] transition-all cursor-pointer"
                title={`Configurações da Global Ignore List (${isMac ? '⌘I' : 'Ctrl+I'})`}
              >
                <Ban className="w-3.5 h-3.5 text-[#FF3E00] shrink-0" />
                <span className="hidden xl:inline">{t('action.exclusions')}</span>
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
                title={`Glossário de Vulnerabilidades & Ameaças (${isMac ? '⌘G' : 'Ctrl+G'})`}
              >
                <BookOpen className="w-3.5 h-3.5 text-[#FF3E00] shrink-0" />
                <span className="hidden xl:inline">{t('action.glossary')}</span>
              </button>
            )}

            {/* Gitignore Security Audit Button */}
            {onOpenGitignoreAudit && (
              <button
                id="btn-header-open-gitignore-audit"
                onClick={onOpenGitignoreAudit}
                className="h-8 px-2.5 sm:px-3 rounded inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-emerald-300 hover:text-white bg-emerald-950/40 hover:bg-emerald-900/60 border border-emerald-500/40 hover:border-emerald-400 transition-all cursor-pointer shadow-xs"
                title="Auditoria de .gitignore & Práticas de Segurança: Verifique se o repositório possui .gitignore e arquivos sensíveis desprotegidos"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span className="hidden sm:inline">{t('action.gitignore')}</span>
              </button>
            )}

            {/* Export Button */}
            <button
              id="btn-export-report"
              onClick={onOpenExport}
              className="h-8 px-2.5 sm:px-3 rounded inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-300 hover:text-white bg-[#0F0F0F] hover:bg-[#1A1A1A] border border-[#2A2A2A] hover:border-[#444] transition-all cursor-pointer"
              title={`Exportar Relatório de Segurança (${isMac ? '⌘E' : 'Ctrl+E'})`}
            >
              <Download className="w-3.5 h-3.5 shrink-0" />
              <span className="hidden sm:inline">{t('action.export')}</span>
              <kbd className="hidden 2xl:inline-flex items-center text-[9px] font-mono px-1 py-0.2 rounded bg-[#1A1A1A] text-zinc-400 border border-[#333]">
                {isMac ? '⌘E' : 'Ctrl+E'}
              </kbd>
            </button>

            {/* Keyboard Shortcuts Cheat Sheet Button */}
            {onOpenShortcuts && (
              <button
                id="btn-header-open-shortcuts"
                onClick={onOpenShortcuts}
                title={`Atalhos Globais de Teclado (${isMac ? '⌘/' : 'Ctrl+/'} ou ?)`}
                className="h-8 w-8 rounded flex items-center justify-center text-zinc-400 hover:text-white bg-[#0F0F0F] hover:bg-[#1A1A1A] border border-[#2A2A2A] hover:border-[#444] transition-colors cursor-pointer shrink-0"
              >
                <Keyboard className="w-3.5 h-3.5 text-zinc-400" />
              </button>
            )}

            {/* Clear Workspace (Zerar Plataforma) */}
            {onClearWorkspace && (
              <button
                id="btn-header-clear-workspace"
                onClick={onClearWorkspace}
                title="Limpar workspace e começar com a plataforma zerada"
                className="h-8 w-8 rounded flex items-center justify-center text-rose-500/70 hover:text-rose-400 bg-[#0F0F0F] hover:bg-rose-950/40 border border-[#2A2A2A] hover:border-rose-800/60 transition-colors cursor-pointer shrink-0"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            )}

            {/* Reset Workspace */}
            <button
              id="btn-reset-demo"
              onClick={onResetWorkspace}
              title={`Restaurar arquivos de exemplo (${isMac ? '⌘B' : 'Ctrl+B'})`}
              className="h-8 w-8 rounded flex items-center justify-center text-[#777] hover:text-white bg-[#0F0F0F] hover:bg-[#1A1A1A] border border-[#2A2A2A] hover:border-[#444] transition-colors cursor-pointer shrink-0"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>

            {/* Primary Action: Run Scan */}
            <button
              id="btn-run-scan"
              onClick={onRunScan}
              disabled={isScanning}
              title={`Executar Análise SAST (${isMac ? '⌘S' : 'Ctrl+S'})`}
              className={`h-8 px-3.5 sm:px-4 rounded inline-flex items-center gap-2 font-mono text-[11px] font-black uppercase tracking-wider transition-all cursor-pointer shadow-sm shrink-0 ${
                isScanning
                  ? 'bg-[#262626] text-[#777] cursor-not-allowed border border-[#333]'
                  : 'bg-white text-black hover:bg-[#FF3E00] hover:text-white hover:border-[#FF3E00] border border-white active:scale-95'
              }`}
            >
              <Play className={`w-3 h-3 fill-current ${isScanning ? 'animate-spin' : ''}`} />
              <span>
                {isScanning 
                  ? `${t('action.scanning')}${scanProgress ? ` (${scanProgress.percentage}%)` : ''}` 
                  : t('action.run_scan')}
              </span>
              <kbd className="hidden sm:inline-flex items-center text-[9px] font-mono px-1.5 py-0.2 rounded bg-black/10 border border-current/25 font-bold">
                {isMac ? '⌘S' : 'Ctrl+S'}
              </kbd>
            </button>
          </div>
        </div>

        {/* SecOps Domain Category Selector Ribbon & Fast Search */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 pt-2 pb-1.5 border-b border-[#1A1A1A]">
          {/* Domain tabs */}
          <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar">
            <span className="text-[10px] font-mono text-[#555] uppercase font-bold tracking-wider shrink-0 mr-1 hidden sm:inline">
              Domínio:
            </span>
            {SECOPS_DOMAINS.map(domain => {
              const isSelected = selectedCategory === domain.id;
              return (
                <button
                  key={domain.id}
                  onClick={() => setSelectedCategory(domain.id)}
                  className={`flex items-center gap-1.5 py-1 px-2.5 rounded text-[10.5px] font-mono font-bold tracking-wide uppercase transition-all whitespace-nowrap cursor-pointer shrink-0 border ${
                    isSelected
                      ? 'bg-[#1C1C1C] text-[#00FF41] border-[#00FF41]/40 shadow-xs'
                      : 'bg-transparent text-[#777] hover:text-white border-transparent hover:border-[#222]'
                  }`}
                >
                  <span>{domain.label}</span>
                  <span className={`text-[9px] font-mono ${
                    isSelected ? 'text-[#00FF41]/75' : 'text-[#555]'
                  }`}>
                    ({domain.count})
                  </span>
                </button>
              );
            })}
          </div>

          {/* Quick Tool Search / Filter */}
          <div className="flex items-center gap-2 shrink-0">
            <div className="relative flex items-center">
              <Search className="w-3.5 h-3.5 absolute left-2.5 text-zinc-500 pointer-events-none" />
              <input
                id="nav-tool-search-input"
                type="text"
                value={toolSearchTerm}
                onChange={(e) => setToolSearchTerm(e.target.value)}
                placeholder={t('nav.search_placeholder')}
                className="w-44 sm:w-56 h-7.5 pl-8 pr-7 text-[11px] font-mono bg-[#0D0D10] border border-[#27272A] focus:border-[#FF3E00]/70 rounded text-zinc-200 placeholder-zinc-500 focus:outline-none focus:ring-1 focus:ring-[#FF3E00]/50 transition-all"
              />
              {toolSearchTerm ? (
                <button
                  onClick={() => setToolSearchTerm('')}
                  className="absolute right-2 text-zinc-400 hover:text-white cursor-pointer"
                  title="Limpar filtro"
                >
                  <X className="w-3 h-3" />
                </button>
              ) : (
                <kbd className="hidden sm:inline-block absolute right-2 text-[9px] font-mono px-1 py-0.2 bg-[#1A1A1E] text-zinc-500 border border-zinc-700/50 rounded pointer-events-none">
                  /
                </kbd>
              )}
            </div>
            {toolSearchTerm && (
              <span className="text-[10px] font-mono text-zinc-400 whitespace-nowrap">
                {visibleNavItems.length} encontrada{visibleNavItems.length !== 1 ? 's' : ''}
              </span>
            )}
          </div>
        </div>

        {/* Navigation Tabs Bar */}
        <nav className="flex items-center gap-1 sm:gap-2 pt-1.5 pb-2 overflow-x-auto no-scrollbar">
          {/* Tool Guide & Examples Button */}
          {onOpenToolGuide && (
            <button
              id="btn-nav-open-tool-guide"
              type="button"
              onClick={() => onOpenToolGuide(activeTab)}
              className="flex items-center gap-1.5 py-1.5 px-2.5 sm:px-3 text-[11px] font-mono font-bold tracking-wide uppercase whitespace-nowrap transition-all cursor-pointer bg-cyan-950/40 hover:bg-cyan-900/50 text-[#00F0FF] border border-cyan-500/40 hover:border-cyan-400 rounded shrink-0 shadow-xs mr-1"
              title="Abrir o Manual das Ferramentas com explicações, arquitetura, passo a passo e exemplos de código"
            >
              <BookOpen className="w-3.5 h-3.5 text-[#00F0FF] shrink-0" />
              <span>💡 Como Usar &amp; Exemplos</span>
            </button>
          )}

          {visibleNavItems.length === 0 ? (
            <div className="flex items-center gap-3 py-2 px-3 text-xs font-mono text-zinc-400 bg-[#0F0F12] border border-zinc-800 rounded w-full">
              <span>Nenhuma ferramenta encontrada com &ldquo;<strong className="text-white">{toolSearchTerm}</strong>&rdquo; no domínio selecionado.</span>
              <button
                onClick={() => { setToolSearchTerm(''); setSelectedCategory('ALL'); }}
                className="text-[#FF3E00] hover:underline font-bold cursor-pointer"
              >
                Limpar filtros
              </button>
            </div>
          ) : (
            visibleNavItems.map(item => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  id={`nav-tab-${item.id}`}
                  onClick={() => setActiveTab(item.id)}
                  title={item.tooltip}
                  className={`flex items-center gap-2 py-2 px-3 rounded text-[11px] font-mono font-bold tracking-wide uppercase whitespace-nowrap transition-all cursor-pointer border ${
                    isActive
                      ? 'bg-[#18181B] text-[#FF3E00] border-[#FF3E00]/60 shadow-[0_0_12px_rgba(255,62,0,0.18)] scale-[1.02]'
                      : 'bg-[#0A0A0C] text-[#888] hover:text-white hover:bg-[#141416] border-[#1E1E24] hover:border-[#383844]'
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-[#FF3E00]' : 'text-[#666]'}`} />
                  <span>{item.label}</span>
                  {item.badge !== undefined && (
                    <span className={`text-[9.5px] font-mono px-1.5 py-0.2 rounded font-bold ${
                      isActive 
                        ? 'bg-[#FF3E00] text-black font-black' 
                        : 'text-zinc-400 bg-[#141414] border border-[#2A2A30]'
                    }`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })
          )}
        </nav>
      </div>
    </header>
  );
};
