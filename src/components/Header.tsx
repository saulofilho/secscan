import React, { useMemo, useState, useEffect, useRef } from 'react';
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
  RotateCcw,
  Trash2,
  Compass,
  Ban,
  BookOpen,
  Clock,
  Command,
  Keyboard,
  ChevronLeft,
  ChevronDown,
  Layers,
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
  Sparkles,
  Workflow,
  FileCheck,
  Cpu,
  Search,
  TrendingDown,
  X,
  Share2,
  Check,
  BarChart3,
  MoreHorizontal,
  FolderCode,
  FlaskConical,
  ClipboardList,
  Settings,
  User
} from 'lucide-react';
import { ScanReport, ScanProgress, ScannedFile } from '../types';
import { useLanguage } from '../lib/i18nContext';
import { LanguageSwitcher } from './LanguageSwitcher';
import { getToolContextScope } from './AppModulesHub';
import { isAdFreeMode, toggleAdFreeMode } from '../lib/adManager';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  report: ScanReport;
  files?: ScannedFile[];
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
  onNavigateToLanding?: () => void;
  onOpenUrlIngest?: () => void;
  onOpenAnalytics?: () => void;
  onOpenSettings?: () => void;
}

interface NavToolItem {
  id: string;
  category: 'CODE_SAST' | 'CLOUD_INFRA' | 'API_DAST' | 'SOC_EDR' | 'GOV_AI';
  label: string;
  icon: any;
  badge?: any;
  tooltip: string;
}

interface SecOpsModuleGroup {
  id: 'CODE_SAST' | 'CLOUD_INFRA' | 'API_DAST' | 'SOC_EDR' | 'GOV_AI';
  label: string;
  icon: any;
  color: string;
  primaryTab: string;
  tools: NavToolItem[];
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  report,
  files = [],
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
  onOpenGitignoreAudit,
  onNavigateToLanding,
  onOpenUrlIngest,
  onOpenAnalytics,
  onOpenSettings
}) => {
  const isMac = useMemo(() => {
    return typeof window !== 'undefined' && /Mac|iPod|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  }, []);

  const activeToolScope = useMemo(() => {
    if (activeTab === 'hub') return null;
    return getToolContextScope(activeTab);
  }, [activeTab]);

  const { t, language } = useLanguage();

  const [toolSearchTerm, setToolSearchTerm] = useState('');
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isSearchFocused, setIsSearchFocused] = useState(false);
  const [selectedSearchIndex, setSelectedSearchIndex] = useState(0);
  const [isCopiedShare, setIsCopiedShare] = useState(false);
  const [isModuleMenuOpen, setIsModuleMenuOpen] = useState(false);
  const [isToolMenuOpen, setIsToolMenuOpen] = useState(false);
  const [isUtilsMenuOpen, setIsUtilsMenuOpen] = useState(false);
  const [localAdFree, setLocalAdFree] = useState<boolean>(() => isAdFreeMode());

  useEffect(() => {
    const handleAdChange = (e: Event) => {
      const customEvent = e as CustomEvent<{ adFree: boolean }>;
      if (customEvent.detail) {
        setLocalAdFree(customEvent.detail.adFree);
      }
    };
    window.addEventListener('secscan_ad_mode_changed', handleAdChange);
    return () => window.removeEventListener('secscan_ad_mode_changed', handleAdChange);
  }, []);

  const searchContainerRef = useRef<HTMLDivElement>(null);
  const moduleMenuRef = useRef<HTMLDivElement>(null);
  const toolMenuRef = useRef<HTMLDivElement>(null);
  const utilsMenuRef = useRef<HTMLDivElement>(null);

  // Close dropdowns on click outside or escape key
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      if (searchContainerRef.current && !searchContainerRef.current.contains(target)) {
        setIsSearchOpen(false);
        setIsSearchFocused(false);
      }
      if (moduleMenuRef.current && !moduleMenuRef.current.contains(target)) {
        setIsModuleMenuOpen(false);
      }
      if (toolMenuRef.current && !toolMenuRef.current.contains(target)) {
        setIsToolMenuOpen(false);
      }
      if (utilsMenuRef.current && !utilsMenuRef.current.contains(target)) {
        setIsUtilsMenuOpen(false);
      }
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsModuleMenuOpen(false);
        setIsToolMenuOpen(false);
        setIsUtilsMenuOpen(false);
        setIsSearchOpen(false);
        setIsSearchFocused(false);
      }
      if (e.key === '/' && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)) {
        e.preventDefault();
        const input = document.getElementById('nav-tool-search-input');
        if (input) {
          input.focus();
          setIsSearchOpen(true);
          setIsSearchFocused(true);
        }
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  const handleShareLink = async () => {
    const shareUrl = typeof window !== 'undefined' ? window.location.href : '';
    const shareData = {
      title: 'SecScan AppSec Suite',
      text: 'SecScan AppSec Suite - Plataforma Avançada de Cibersegurança, Threat Heatmap & SAST',
      url: shareUrl,
    };
    if (typeof navigator !== 'undefined' && navigator.share) {
      try {
        await navigator.share(shareData);
        return;
      } catch {
        // Fallback to clipboard
      }
    }
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(shareUrl);
        setIsCopiedShare(true);
        setTimeout(() => setIsCopiedShare(false), 2500);
      } catch {
        // Fallback
      }
    }
  };

  const criticalCount = report.metrics.criticalCount;
  const isHealthy = criticalCount === 0;

  // Catalog of all 44 tools classified into 5 core domains
  const navItems = useMemo<NavToolItem[]>(() => [
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
    { id: 'crowdstrike', category: 'SOC_EDR', label: t('tab.crowdstrike'), icon: Zap, badge: report.findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length || undefined, tooltip: t('tab.crowdstrike_tooltip') },
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

  // 5 Scoped Modules matching the AppModulesHub layout
  const SECOPS_MODULES = useMemo<SecOpsModuleGroup[]>(() => [
    {
      id: 'CODE_SAST',
      label: language === 'pt' ? 'Código & SAST' : language === 'es' ? 'Código y SAST' : 'Code & SAST',
      icon: FileCode2,
      color: '#00F0FF',
      primaryTab: 'scanner',
      tools: navItems.filter(i => i.category === 'CODE_SAST')
    },
    {
      id: 'API_DAST',
      label: language === 'pt' ? 'APIs & DAST' : language === 'es' ? 'APIs y DAST' : 'APIs & DAST',
      icon: Route,
      color: '#FF3E00',
      primaryTab: 'apisecurity',
      tools: navItems.filter(i => i.category === 'API_DAST')
    },
    {
      id: 'CLOUD_INFRA',
      label: language === 'pt' ? 'Nuvem & Infra' : language === 'es' ? 'Nube e Infra' : 'Cloud & Infra',
      icon: Container,
      color: '#38BDF8',
      primaryTab: 'iac',
      tools: navItems.filter(i => i.category === 'CLOUD_INFRA')
    },
    {
      id: 'SOC_EDR',
      label: language === 'pt' ? 'SOC & Resposta' : language === 'es' ? 'SOC y Respuesta' : 'SOC & Response',
      icon: Radio,
      color: '#A78BFA',
      primaryTab: 'soccommand',
      tools: navItems.filter(i => i.category === 'SOC_EDR')
    },
    {
      id: 'GOV_AI',
      label: language === 'pt' ? 'Governança & AI' : language === 'es' ? 'Gobernanza e IA' : 'Gov & AI',
      icon: Scale,
      color: '#F59E0B',
      primaryTab: 'dashboard',
      tools: navItems.filter(i => i.category === 'GOV_AI')
    }
  ], [navItems, language]);

  // Determine current active module and active tool item
  const activeToolItem = useMemo(() => {
    return navItems.find(i => i.id === activeTab) || null;
  }, [navItems, activeTab]);

  const currentModule = useMemo(() => {
    if (activeTab === 'hub') return null;
    if (!activeToolItem) return SECOPS_MODULES[0];
    return SECOPS_MODULES.find(m => m.id === activeToolItem.category) || SECOPS_MODULES[0];
  }, [SECOPS_MODULES, activeToolItem, activeTab]);

  // Search filtered results across all tools with accent normalization
  const searchResults = useMemo(() => {
    if (!toolSearchTerm.trim()) return [];
    const clean = (str: string) => str.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim();
    const q = clean(toolSearchTerm);

    return navItems.filter(item => {
      const matchLabel = clean(item.label).includes(q);
      const matchId = clean(item.id).includes(q);
      const matchTooltip = clean(item.tooltip || '').includes(q);
      const matchBadge = typeof item.badge === 'string' && clean(item.badge).includes(q);
      const mod = SECOPS_MODULES.find(m => m.id === item.category);
      const matchModule = mod ? clean(mod.label).includes(q) : false;

      return matchLabel || matchId || matchTooltip || matchBadge || matchModule;
    });
  }, [navItems, toolSearchTerm, SECOPS_MODULES]);

  useEffect(() => {
    setSelectedSearchIndex(0);
  }, [toolSearchTerm]);

  return (
    <header className="w-full border-b border-white/[0.08] bg-[#07070A]/95 backdrop-blur-xl sticky top-0 z-30 shadow-md">
      <div className="max-w-[1600px] 2xl:max-w-[1800px] w-full mx-auto px-3 sm:px-5 lg:px-8">
        {/* CONCENTRATED SINGLE-MENU BAR (Divided into 3 Scopes/Blocks) */}
        <div className="h-16 flex items-center justify-between gap-2 sm:gap-3 lg:gap-4 w-full min-w-0 relative">
          
          {/* =========================================================================
              BLOCO 1: IDENTIDADE & HUB (Brand & Core Hub Scope)
             ========================================================================= */}
          <div className="flex items-center gap-2 sm:gap-2.5 lg:gap-3 shrink-0">
            {/* Logo & Brand Name - Navigates directly to App Dashboard */}
            <div 
              id="header-brand-logo-btn"
              onClick={() => setActiveTab('dashboard')}
              className="flex items-center gap-2 sm:gap-2.5 cursor-pointer select-none group transition-opacity hover:opacity-90 active:scale-[0.98] shrink-0"
              title={language === 'pt' ? 'Ir para o Dashboard do App' : language === 'es' ? 'Ir al Dashboard del App' : 'Go to App Dashboard'}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  setActiveTab('dashboard');
                }
              }}
            >
              <div className="w-9 h-9 rounded-xl bg-gradient-to-b from-[#1C1C24] to-[#0A0A0E] border border-white/[0.1] group-hover:border-[#FF3E00]/60 flex items-center justify-center text-[#FF3E00] shadow-[0_0_12px_rgba(255,62,0,0.15)] relative transition-all shrink-0">
                <ShieldAlert className="w-4 h-4 text-[#FF3E00] group-hover:scale-110 transition-transform" />
                <span className="absolute -top-1 -right-1 flex h-2 w-2">
                  <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                    (report.metrics.riskScore ?? 0) >= 75 ? 'bg-[#FF3E00]' : (report.metrics.riskScore ?? 0) >= 50 ? 'bg-[#FF7A00]' : 'bg-[#00FF41]'
                  }`} />
                  <span className={`relative inline-flex rounded-full h-2 w-2 ${
                    (report.metrics.riskScore ?? 0) >= 75 ? 'bg-[#FF3E00]' : (report.metrics.riskScore ?? 0) >= 50 ? 'bg-[#FF7A00]' : 'bg-[#00FF41]'
                  }`} />
                </span>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <span className="font-black text-base sm:text-lg tracking-tight text-white uppercase font-sans">
                  SECSCAN
                </span>
                <span className="text-[#FF3E00] font-black text-base sm:text-lg uppercase font-sans hidden sm:inline">
                  APPSEC
                </span>
              </div>
            </div>

            {/* Subtle Vertical Divider */}
            <div className="h-5 w-px bg-white/10 hidden sm:block shrink-0" />

            {/* Central de Módulos (Hub) Button */}
            <button
              id="btn-header-modules-hub"
              onClick={() => setActiveTab('hub')}
              className={`h-8 px-2 sm:px-2.5 lg:px-3 rounded-lg inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider transition-all cursor-pointer border shrink-0 whitespace-nowrap ${
                activeTab === 'hub'
                  ? 'bg-[#00F0FF]/15 text-[#00F0FF] border-[#00F0FF]/50 shadow-[0_0_12px_rgba(0,240,255,0.2)]'
                  : 'text-zinc-300 hover:text-white bg-white/[0.03] hover:bg-white/[0.08] border-white/[0.08] hover:border-[#00F0FF]/40'
              }`}
              title="Central de Módulos: Navegação organizada por grupos de ferramentas em cards"
            >
              {activeTab === 'hub' ? (
                <Layers className="w-3.5 h-3.5 text-[#00F0FF] shrink-0" />
              ) : (
                <ChevronLeft className="w-3.5 h-3.5 text-[#00F0FF] shrink-0" />
              )}
              <span className="hidden md:inline">{t('tab.hub')}</span>
              <span className="md:hidden">Hub</span>
            </button>
          </div>

          {/* =========================================================================
              BLOCO 2: MÓDULOS & FERRAMENTAS DO ESCOPO (Scoped Module & Tool Selector)
             ========================================================================= */}
          <div className="flex items-center gap-2 flex-1 max-w-2xl mx-1 sm:mx-3 justify-center min-w-0">
            {/* Module Selector Dropdown */}
            <div className="relative" ref={moduleMenuRef}>
              <button
                id="header-btn-module-selector"
                onClick={() => setIsModuleMenuOpen(!isModuleMenuOpen)}
                className={`h-8 px-2.5 sm:px-3 rounded-lg inline-flex items-center gap-2 font-mono text-[11px] font-bold uppercase tracking-wider transition-all cursor-pointer whitespace-nowrap border ${
                  activeTab === 'hub'
                    ? 'bg-white/[0.03] text-zinc-300 hover:text-white border-white/[0.08] hover:border-white/[0.2]'
                    : 'bg-white/[0.06] text-white border-white/[0.15] hover:border-white/[0.3] shadow-xs'
                }`}
                title="Escolher Módulo de Segurança Especializado"
              >
                {currentModule ? (
                  <>
                    <currentModule.icon className="w-3.5 h-3.5" style={{ color: currentModule.color }} />
                    <span className="max-w-[100px] sm:max-w-none truncate">{currentModule.label}</span>
                  </>
                ) : (
                  <>
                    <Layers className="w-3.5 h-3.5 text-[#00F0FF]" />
                    <span className="hidden sm:inline">Módulos</span>
                  </>
                )}
                <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${isModuleMenuOpen ? 'rotate-180' : ''}`} />
              </button>

              {/* Module Dropdown Popover */}
              {isModuleMenuOpen && (
                <div className="absolute left-0 mt-2 w-72 rounded-2xl bg-[#0D0D14]/98 backdrop-blur-2xl border border-white/[0.12] shadow-2xl p-2 z-50 animate-in fade-in zoom-in-95 duration-150">
                  <div className="px-2.5 py-1.5 text-[10px] font-mono uppercase font-bold text-zinc-400 border-b border-white/[0.08] mb-1">
                    {language === 'pt' ? 'Módulos Especializados' : 'Specialized Modules'}
                  </div>
                  <button
                    onClick={() => { setActiveTab('hub'); setIsModuleMenuOpen(false); }}
                    className={`w-full flex items-center justify-between p-2 rounded-xl text-left font-mono text-xs transition-colors cursor-pointer ${
                      activeTab === 'hub' ? 'bg-[#00F0FF]/15 text-[#00F0FF]' : 'hover:bg-white/[0.06] text-zinc-300 hover:text-white'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <Layers className="w-4 h-4 text-[#00F0FF]" />
                      <span className="font-bold">Central de Módulos (Geral)</span>
                    </div>
                    <span className="text-[10px] font-mono text-zinc-500">5 Módulos</span>
                  </button>

                  {SECOPS_MODULES.map(mod => {
                    const ModIcon = mod.icon;
                    const isCurrentMod = currentModule?.id === mod.id && activeTab !== 'hub';
                    return (
                      <button
                        key={mod.id}
                        onClick={() => {
                          setActiveTab(mod.primaryTab);
                          setIsModuleMenuOpen(false);
                        }}
                        className={`w-full flex items-center justify-between p-2 rounded-xl text-left font-mono text-xs transition-colors cursor-pointer ${
                          isCurrentMod ? 'bg-white/[0.1] text-white font-bold' : 'hover:bg-white/[0.06] text-zinc-300 hover:text-white'
                        }`}
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <ModIcon className="w-4 h-4 shrink-0" style={{ color: mod.color }} />
                          <span className="truncate">{mod.label}</span>
                        </div>
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-black/40 text-zinc-400 border border-white/[0.08] shrink-0">
                          {mod.tools.length}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Active Tool Selector inside Module (only shown on wider viewports to avoid overlapping) */}
            {activeTab !== 'hub' && currentModule && (
              <div className="relative hidden xl:block shrink-0" ref={toolMenuRef}>
                <button
                  id="header-btn-tool-selector"
                  onClick={() => setIsToolMenuOpen(!isToolMenuOpen)}
                  className="h-8 px-2.5 sm:px-3 rounded-lg inline-flex items-center gap-2 font-mono text-[11px] font-bold uppercase tracking-wider bg-white/[0.03] hover:bg-white/[0.07] text-[#00FF41] border border-[#00FF41]/30 hover:border-[#00FF41]/60 transition-all cursor-pointer whitespace-nowrap shrink-0"
                  title="Ferramenta Ativa no Módulo"
                >
                  {activeToolItem ? (
                    <>
                      <activeToolItem.icon className="w-3.5 h-3.5 text-[#00FF41] shrink-0" />
                      <span className="max-w-[110px] sm:max-w-[140px] truncate">{activeToolItem.label}</span>
                    </>
                  ) : (
                    <span>Ferramenta</span>
                  )}
                  <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform shrink-0 ${isToolMenuOpen ? 'rotate-180' : ''}`} />
                </button>

                {/* Tool Dropdown Popover */}
                {isToolMenuOpen && (
                  <div className="absolute left-0 mt-2 w-72 max-h-80 overflow-y-auto rounded-2xl bg-[#0D0D14]/98 backdrop-blur-2xl border border-white/[0.12] shadow-2xl p-2 z-50 animate-in fade-in zoom-in-95 duration-150">
                    <div className="px-2.5 py-1.5 text-[10px] font-mono uppercase font-bold text-zinc-400 border-b border-white/[0.08] mb-1">
                      {currentModule.label} ({currentModule.tools.length} ferramentas)
                    </div>
                    {currentModule.tools.map(tool => {
                      const ToolIcon = tool.icon;
                      const isToolActive = activeTab === tool.id;
                      const toolScope = getToolContextScope(tool.id);
                      return (
                        <button
                          key={tool.id}
                          onClick={() => {
                            setActiveTab(tool.id);
                            setIsToolMenuOpen(false);
                          }}
                          className={`w-full flex items-center justify-between p-2 rounded-xl text-left font-mono text-xs transition-colors cursor-pointer ${
                            isToolActive ? 'bg-[#00FF41]/15 text-[#00FF41] font-bold' : 'hover:bg-white/[0.06] text-zinc-300 hover:text-white'
                          }`}
                        >
                          <div className="flex items-center gap-2.5 min-w-0 pr-2">
                            <ToolIcon className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
                            <div className="flex flex-col min-w-0">
                              <span className="truncate">{tool.label}</span>
                              <span className="text-[9px] font-sans text-zinc-500">
                                {toolScope === 'MY_CODE' ? '📁 Meu Código' : toolScope === 'SANDBOX' ? '🧪 Sandbox' : '📋 Governança'}
                              </span>
                            </div>
                          </div>
                          {tool.badge !== undefined && (
                            <span className="text-[9.5px] font-mono px-1.5 py-0.2 rounded bg-black/40 text-zinc-400 border border-white/[0.08] shrink-0">
                              {tool.badge}
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* Spotlight Search Box (Expanding on Focus / Selection) */}
            <div 
              ref={searchContainerRef} 
              className={`relative hidden md:flex items-center transition-all duration-300 ease-out z-20 shrink-1 min-w-[100px] ${
                isSearchFocused || toolSearchTerm.trim().length > 0 
                  ? 'w-48 sm:w-56 lg:w-64 xl:w-72 shadow-[0_0_20px_rgba(0,240,255,0.2)]' 
                  : 'w-24 sm:w-28 lg:w-36 xl:w-40'
              }`}
            >
              <Search className={`w-3.5 h-3.5 absolute left-2.5 transition-colors pointer-events-none shrink-0 ${
                isSearchFocused ? 'text-[#00F0FF]' : 'text-zinc-400'
              }`} />
              <input
                id="nav-tool-search-input"
                type="text"
                value={toolSearchTerm}
                onFocus={() => {
                  setIsSearchOpen(true);
                  setIsSearchFocused(true);
                }}
                onBlur={() => {
                  setTimeout(() => {
                    setIsSearchFocused(false);
                  }, 180);
                }}
                onChange={(e) => {
                  setToolSearchTerm(e.target.value);
                  setIsSearchOpen(true);
                }}
                onKeyDown={(e) => {
                  if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    if (searchResults.length > 0) {
                      setSelectedSearchIndex(prev => Math.min(searchResults.length - 1, prev + 1));
                    }
                  } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    if (searchResults.length > 0) {
                      setSelectedSearchIndex(prev => Math.max(0, prev - 1));
                    }
                  } else if (e.key === 'Enter') {
                    e.preventDefault();
                    if (searchResults.length > 0) {
                      const selected = searchResults[selectedSearchIndex] || searchResults[0];
                      setActiveTab(selected.id);
                      setToolSearchTerm('');
                      setIsSearchOpen(false);
                      setIsSearchFocused(false);
                    }
                  } else if (e.key === 'Escape') {
                    e.preventDefault();
                    setIsSearchOpen(false);
                    setIsSearchFocused(false);
                    setToolSearchTerm('');
                  }
                }}
                placeholder={isSearchFocused ? (t('nav.search_placeholder') || 'Buscar ferramentas (/)...') : 'Buscar...'}
                className={`w-full h-8 pl-8 text-[11px] font-mono border rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none transition-all duration-300 ${
                  toolSearchTerm ? 'pr-7' : 'pr-6'
                } ${
                  isSearchFocused
                    ? 'bg-[#0D0D14] border-[#00F0FF]/80 shadow-[0_0_14px_rgba(0,240,255,0.3)] ring-1 ring-[#00F0FF]/40'
                    : 'bg-white/[0.04] hover:bg-white/[0.07] border-white/[0.10]'
                }`}
              />
              {toolSearchTerm ? (
                <button
                  type="button"
                  onClick={() => {
                    setToolSearchTerm('');
                    setIsSearchOpen(false);
                    setIsSearchFocused(false);
                  }}
                  className="absolute right-2 text-zinc-400 hover:text-white cursor-pointer"
                  title="Limpar filtro"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              ) : (
                <kbd className="hidden lg:inline-block absolute right-2 text-[9px] font-mono px-1 py-0.2 bg-white/[0.06] text-zinc-500 border border-white/[0.08] rounded pointer-events-none">
                  /
                </kbd>
              )}

              {/* Spotlight Search Results Dropdown Popover */}
              {isSearchOpen && toolSearchTerm.trim().length > 0 && (
                <div 
                  id="nav-tool-search-results-popover"
                  className="absolute top-full mt-2 left-0 w-80 sm:w-96 max-h-[380px] overflow-y-auto bg-[#0A0A10]/98 border border-white/[0.12] rounded-xl shadow-[0_20px_50px_rgba(0,0,0,0.9)] backdrop-blur-2xl z-50 p-2 flex flex-col gap-1 animate-in fade-in slide-in-from-top-2 duration-150"
                >
                  <div className="flex items-center justify-between px-2.5 py-1 border-b border-white/[0.06] text-[10px] font-mono text-zinc-400">
                    <span>{searchResults.length} ferramenta(s) encontrada(s)</span>
                    <span className="text-zinc-500">↑↓ navegar • ↵ abrir</span>
                  </div>

                  {searchResults.length > 0 ? (
                    <div className="flex flex-col gap-0.5 mt-1">
                      {searchResults.map((tool, idx) => {
                        const ToolIcon = tool.icon;
                        const isSelected = idx === selectedSearchIndex;
                        const isCurrentActive = tool.id === activeTab;
                        const moduleItem = SECOPS_MODULES.find(m => m.id === tool.category);

                        return (
                          <button
                            key={tool.id}
                            type="button"
                            onMouseDown={(e) => e.preventDefault()}
                            onMouseEnter={() => setSelectedSearchIndex(idx)}
                            onClick={() => {
                              setActiveTab(tool.id);
                              setToolSearchTerm('');
                              setIsSearchOpen(false);
                              setIsSearchFocused(false);
                            }}
                            className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-left transition-all cursor-pointer ${
                              isSelected 
                                ? 'bg-[#00F0FF]/15 text-white border border-[#00F0FF]/30' 
                                : isCurrentActive
                                ? 'bg-white/[0.06] text-[#00FF41]'
                                : 'hover:bg-white/[0.05] text-zinc-300'
                            }`}
                          >
                            <div className="flex items-center gap-2.5 min-w-0 pr-2">
                              <div className={`p-1.5 rounded-md shrink-0 ${isSelected ? 'bg-[#00F0FF]/20 text-[#00F0FF]' : 'bg-white/[0.05] text-zinc-400'}`}>
                                <ToolIcon className="w-3.5 h-3.5" />
                              </div>
                              <div className="min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="text-xs font-semibold text-white truncate">
                                    {tool.label}
                                  </span>
                                  {isCurrentActive && (
                                    <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-[#00FF41]/20 text-[#00FF41] border border-[#00FF41]/40 font-bold">
                                      ATIVO
                                    </span>
                                  )}
                                  {(() => {
                                    const s = getToolContextScope(tool.id);
                                    if (s === 'MY_CODE') return <span className="text-[8.5px] font-mono px-1 py-0.2 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/50">Código</span>;
                                    if (s === 'SANDBOX') return <span className="text-[8.5px] font-mono px-1 py-0.2 rounded bg-purple-950/60 text-purple-300 border border-purple-800/50">Sandbox</span>;
                                    return <span className="text-[8.5px] font-mono px-1 py-0.2 rounded bg-amber-950/60 text-amber-300 border border-amber-800/50">Governança</span>;
                                  })()}
                                  {moduleItem && (
                                    <span className="text-[9px] font-mono text-zinc-500 hidden sm:inline">
                                      • {moduleItem.label}
                                    </span>
                                  )}
                                </div>
                                <p className="text-[10.5px] text-zinc-400 truncate mt-0.5">
                                  {tool.tooltip}
                                </p>
                              </div>
                            </div>

                            {tool.badge !== undefined && (
                              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-black/50 text-zinc-400 border border-white/[0.08] shrink-0">
                                {tool.badge}
                              </span>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="py-6 px-4 text-center space-y-1.5">
                      <Search className="w-5 h-5 text-zinc-600 mx-auto" />
                      <p className="text-xs text-zinc-400">
                        Nenhuma ferramenta para <strong className="text-zinc-200">"{toolSearchTerm}"</strong>
                      </p>
                      <p className="text-[10px] text-zinc-500 font-mono">
                        Tente termos como "scanner", "dast", "api", "grafo", "compliance" ou pressione ⌘K.
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* =========================================================================
              BLOCO 3: TELEMETRIA, UTILIDADES & AÇÕES (Telemetry & Actions Scope)
             ========================================================================= */}
          <div className="flex items-center gap-1.5 sm:gap-2 shrink-0 justify-end min-w-0">
            {/* Risk Score Pill - Only shown on 2xl to preserve space and avoid overlap */}
            <button
              id="header-workspace-risk-score-badge"
              type="button"
              onClick={() => {
                if (activeTab !== 'dashboard') setActiveTab('dashboard');
                setTimeout(() => {
                  const el = document.getElementById('cumulative-risk-validation-section') || 
                             document.getElementById('metric-card-cumulative-risk-score');
                  if (el) el.scrollIntoView({ behavior: 'smooth' });
                }, 100);
              }}
              className="hidden 2xl:flex items-center gap-1.5 h-8.5 px-2.5 rounded-lg border font-mono text-[11px] font-bold uppercase transition-all cursor-pointer bg-white/[0.03] hover:bg-white/[0.06] border-white/[0.08] shrink-0 whitespace-nowrap select-none"
              title="Score de Risco do Workspace"
            >
              <span className={`w-2 h-2 rounded-full shrink-0 ${
                (report.metrics.riskScore ?? 0) >= 75 ? 'bg-[#FF3E00]' : (report.metrics.riskScore ?? 0) >= 50 ? 'bg-[#FF7A00]' : 'bg-[#00FF41]'
              }`} />
              <span className="text-zinc-400 text-[10px]">Score:</span>
              <span className="text-white font-mono font-bold">{report.metrics.riskScore ?? 0}/100</span>
            </button>

            {/* User Profile & Settings Drawer Button */}
            {onOpenSettings && (
              <button
                id="btn-header-user-settings-drawer"
                type="button"
                onClick={onOpenSettings}
                className="h-8.5 px-2.5 rounded-lg inline-flex items-center gap-2 font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-300 hover:text-white bg-white/[0.03] hover:bg-white/[0.07] border border-white/[0.08] hover:border-[#00F0FF]/40 transition-all cursor-pointer shrink-0 whitespace-nowrap select-none"
                title={language === 'pt' ? 'Configurações do Usuário, Perfil & Banners do AdSense' : 'User Settings, Profile & AdSense Banners'}
              >
                <div className="w-5 h-5 rounded-md bg-gradient-to-tr from-cyan-950 to-blue-900 border border-cyan-400/40 flex items-center justify-center text-[9px] font-mono text-cyan-300 font-bold shrink-0">
                  SE
                </div>
                <span className="hidden xl:inline">{language === 'pt' ? 'Configurações' : 'Settings'}</span>
                {localAdFree && (
                  <span className="w-1.5 h-1.5 rounded-full bg-[#00FF41] shadow-[0_0_6px_#00FF41]" title="Modo Sem Anúncios Ativo (Ad-Free)" />
                )}
              </button>
            )}

            {/* Consolidated Utilities Dropdown ([⚙️ Utilidades ▾]) */}
            <div className="relative shrink-0" ref={utilsMenuRef}>
              <button
                id="btn-header-utilities-menu"
                onClick={() => setIsUtilsMenuOpen(!isUtilsMenuOpen)}
                className="h-8.5 px-2.5 rounded-lg inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-300 hover:text-white bg-white/[0.03] hover:bg-white/[0.07] border border-white/[0.08] hover:border-white/[0.2] transition-all cursor-pointer shrink-0 whitespace-nowrap select-none"
                title="Utilidades e Ferramentas Auxiliares"
              >
                <MoreHorizontal className="w-4 h-4 text-zinc-400 shrink-0" />
                <span className="hidden 2xl:inline">{language === 'pt' ? 'Utilidades' : 'Tools'}</span>
                <ChevronDown className={`w-3 h-3 text-zinc-500 transition-transform shrink-0 ${isUtilsMenuOpen ? 'rotate-180' : ''}`} />
              </button>

              {/* Utilities Popover */}
              {isUtilsMenuOpen && (
                <div className="absolute right-0 mt-2 w-64 rounded-2xl bg-[#0D0D14]/98 backdrop-blur-2xl border border-white/[0.12] shadow-2xl p-2 z-50 animate-in fade-in zoom-in-95 duration-150">
                  <div className="px-2.5 py-1 text-[10px] font-mono uppercase font-bold text-zinc-400 border-b border-white/[0.08] mb-1">
                    {language === 'pt' ? 'Recursos & Suporte' : 'Resources & Tools'}
                  </div>

                  {onOpenToolGuide && (
                    <button
                      onClick={() => { onOpenToolGuide(activeTab); setIsUtilsMenuOpen(false); }}
                      className="w-full flex items-center gap-2.5 p-2 rounded-xl text-left font-mono text-xs hover:bg-white/[0.06] text-zinc-300 hover:text-white cursor-pointer"
                    >
                      <BookOpen className="w-3.5 h-3.5 text-[#00F0FF]" />
                      <span>💡 {language === 'pt' ? 'Como Usar & Exemplos' : 'How to Use & Examples'}</span>
                    </button>
                  )}

                  <button
                    onClick={() => { onOpenTour(); setIsUtilsMenuOpen(false); }}
                    className="w-full flex items-center gap-2.5 p-2 rounded-xl text-left font-mono text-xs hover:bg-white/[0.06] text-zinc-300 hover:text-white cursor-pointer"
                  >
                    <Compass className="w-3.5 h-3.5 text-[#FF3E00]" />
                    <span>{t('action.tutorial')}</span>
                  </button>

                  {onOpenCommandPalette && (
                    <button
                      onClick={() => { onOpenCommandPalette(); setIsUtilsMenuOpen(false); }}
                      className="w-full flex items-center justify-between p-2 rounded-xl text-left font-mono text-xs hover:bg-white/[0.06] text-zinc-300 hover:text-white cursor-pointer"
                    >
                      <div className="flex items-center gap-2.5">
                        <Command className="w-3.5 h-3.5 text-[#FF3E00]" />
                        <span>{t('action.commands')}</span>
                      </div>
                      <kbd className="text-[9px] px-1 py-0.2 rounded bg-black/40 text-zinc-400 border border-white/10 font-mono">
                        {isMac ? '⌘K' : 'Ctrl+K'}
                      </kbd>
                    </button>
                  )}

                  {onOpenGlossary && (
                    <button
                      onClick={() => { onOpenGlossary(); setIsUtilsMenuOpen(false); }}
                      className="w-full flex items-center gap-2.5 p-2 rounded-xl text-left font-mono text-xs hover:bg-white/[0.06] text-zinc-300 hover:text-white cursor-pointer"
                    >
                      <BookOpen className="w-3.5 h-3.5 text-zinc-400" />
                      <span>{t('action.glossary')}</span>
                    </button>
                  )}

                  {onOpenIgnoreModal && (
                    <button
                      onClick={() => { onOpenIgnoreModal(); setIsUtilsMenuOpen(false); }}
                      className="w-full flex items-center justify-between p-2 rounded-xl text-left font-mono text-xs hover:bg-white/[0.06] text-zinc-300 hover:text-white cursor-pointer"
                    >
                      <div className="flex items-center gap-2.5">
                        <Ban className="w-3.5 h-3.5 text-zinc-400" />
                        <span>{t('action.exclusions')}</span>
                      </div>
                      {activeIgnoreCount !== undefined && (
                        <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30">
                          {activeIgnoreCount}
                        </span>
                      )}
                    </button>
                  )}

                  {onOpenGitignoreAudit && (
                    <button
                      onClick={() => { onOpenGitignoreAudit(); setIsUtilsMenuOpen(false); }}
                      className="w-full flex items-center gap-2.5 p-2 rounded-xl text-left font-mono text-xs hover:bg-white/[0.06] text-emerald-300 hover:text-white cursor-pointer"
                    >
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                      <span>{t('action.gitignore')}</span>
                    </button>
                  )}

                  {onOpenUrlIngest && (
                    <button
                      onClick={() => { onOpenUrlIngest(); setIsUtilsMenuOpen(false); }}
                      className="w-full flex items-center gap-2.5 p-2 rounded-xl text-left font-mono text-xs hover:bg-white/[0.06] text-[#00F0FF] hover:text-white cursor-pointer"
                    >
                      <Globe className="w-3.5 h-3.5 text-[#00F0FF]" />
                      <span>Auditar URL Direta</span>
                    </button>
                  )}

                  {onOpenAnalytics && (
                    <button
                      onClick={() => { onOpenAnalytics(); setIsUtilsMenuOpen(false); }}
                      className="w-full flex items-center gap-2.5 p-2 rounded-xl text-left font-mono text-xs hover:bg-white/[0.06] text-emerald-300 hover:text-white cursor-pointer"
                    >
                      <BarChart3 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Analytics & Telemetria</span>
                    </button>
                  )}

                  {onOpenShortcuts && (
                    <button
                      onClick={() => { onOpenShortcuts(); setIsUtilsMenuOpen(false); }}
                      className="w-full flex items-center gap-2.5 p-2 rounded-xl text-left font-mono text-xs hover:bg-white/[0.06] text-zinc-400 hover:text-white cursor-pointer"
                    >
                      <Keyboard className="w-3.5 h-3.5 text-zinc-400" />
                      <span>Atalhos de Teclado</span>
                    </button>
                  )}

                  <button
                    onClick={() => { handleShareLink(); setIsUtilsMenuOpen(false); }}
                    className="w-full flex items-center gap-2.5 p-2 rounded-xl text-left font-mono text-xs hover:bg-white/[0.06] text-zinc-400 hover:text-white cursor-pointer"
                  >
                    <Share2 className="w-3.5 h-3.5 text-[#00FF41]" />
                    <span>Compartilhar Link</span>
                  </button>

                  {onOpenSettings && (
                    <button
                      onClick={() => { onOpenSettings(); setIsUtilsMenuOpen(false); }}
                      className="w-full flex items-center justify-between p-2 rounded-xl text-left font-mono text-xs hover:bg-white/[0.06] text-[#00F0FF] hover:text-white cursor-pointer"
                    >
                      <div className="flex items-center gap-2.5">
                        <Settings className="w-3.5 h-3.5 text-[#00F0FF]" />
                        <span>{language === 'pt' ? 'Configurações & Anúncios' : 'Settings & AdSense'}</span>
                      </div>
                      <span className="text-[9.5px] px-1.5 py-0.2 rounded bg-[#00F0FF]/15 text-[#00F0FF] border border-[#00F0FF]/30 font-mono">
                        ⚙️ Drawer
                      </span>
                    </button>
                  )}

                  <button
                    onClick={() => {
                      const next = toggleAdFreeMode();
                      setLocalAdFree(next);
                      setIsUtilsMenuOpen(false);
                    }}
                    className="w-full flex items-center justify-between p-2 rounded-xl text-left font-mono text-xs hover:bg-white/[0.06] text-zinc-300 hover:text-white cursor-pointer"
                    title="Alternar visibilidade de anúncios do Google Ads para testes ou modo admin"
                  >
                    <div className="flex items-center gap-2.5">
                      <ShieldCheck className={`w-3.5 h-3.5 ${localAdFree ? 'text-[#00FF41]' : 'text-zinc-400'}`} />
                      <span>{localAdFree ? 'Modo Sem Anúncios (Ativo)' : 'Modo Sem Anúncios (Admin)'}</span>
                    </div>
                    <span className={`text-[9px] px-1.5 py-0.2 rounded font-mono font-bold ${
                      localAdFree 
                        ? 'bg-emerald-950/70 text-emerald-300 border border-emerald-800/60' 
                        : 'bg-zinc-800 text-zinc-400 border border-white/10'
                    }`}>
                      {localAdFree ? 'ATIVO' : 'OFF'}
                    </span>
                  </button>

                  <div className="border-t border-white/[0.08] my-1" />

                  <button
                    onClick={() => { onResetWorkspace(); setIsUtilsMenuOpen(false); }}
                    className="w-full flex items-center gap-2.5 p-2 rounded-xl text-left font-mono text-xs hover:bg-white/[0.06] text-zinc-400 hover:text-white cursor-pointer"
                  >
                    <RotateCcw className="w-3.5 h-3.5 text-zinc-400" />
                    <span>Restaurar Demo</span>
                  </button>

                  {onClearWorkspace && (
                    <button
                      onClick={() => { onClearWorkspace(); setIsUtilsMenuOpen(false); }}
                      className="w-full flex items-center gap-2.5 p-2 rounded-xl text-left font-mono text-xs hover:bg-rose-950/40 text-rose-400 hover:text-rose-300 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>Limpar Workspace</span>
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* Language Switcher */}
            <div className="shrink-0">
              <LanguageSwitcher />
            </div>

            {/* Clear All / Start New Test Button */}
            {onClearWorkspace && (
              <button
                id="btn-header-clean-new-test"
                onClick={onClearWorkspace}
                className="h-8.5 px-2.5 sm:px-3 rounded-xl inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-rose-300 hover:text-white bg-rose-950/30 hover:bg-rose-900/60 border border-rose-800/50 hover:border-rose-600/70 transition-all cursor-pointer shadow-sm active:scale-95 shrink-0 whitespace-nowrap select-none"
                title={language === 'pt' ? 'Limpar todos os dados e arquivos para iniciar um novo teste do zero' : language === 'es' ? 'Limpiar datos e iniciar nueva prueba' : 'Clear all data to start a new test'}
              >
                <Trash2 className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                <span className="hidden 2xl:inline">{language === 'pt' ? 'Limpar' : language === 'es' ? 'Limpiar' : 'Clear'}</span>
              </button>
            )}

            {/* Export Button */}
            <button
              id="btn-export-report"
              onClick={onOpenExport}
              className="h-8.5 px-2.5 sm:px-3 rounded-xl inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-300 hover:text-white bg-white/[0.03] hover:bg-white/[0.07] border border-white/[0.08] hover:border-white/[0.2] transition-all cursor-pointer shrink-0 whitespace-nowrap select-none"
              title="Exportar Relatório"
            >
              <Download className="w-3.5 h-3.5 shrink-0" />
              <span className="hidden 2xl:inline">{t('action.export')}</span>
            </button>

            {/* Primary Action: Run Scan */}
            <button
              id="btn-run-scan"
              onClick={onRunScan}
              disabled={isScanning}
              title={`Executar Análise SAST (${isMac ? '⌘S' : 'Ctrl+S'})`}
              className={`h-8.5 px-3.5 sm:px-4 rounded-xl inline-flex items-center gap-2 font-mono text-[11px] font-black uppercase tracking-wider transition-all cursor-pointer shadow-md shrink-0 whitespace-nowrap select-none ${
                isScanning
                  ? 'bg-[#262626] text-[#777] cursor-not-allowed border border-[#333]'
                  : 'bg-gradient-to-r from-[#FF3E00] via-[#FF551C] to-[#E03700] hover:from-[#FF551C] hover:to-[#FF3E00] text-white active:scale-95 shadow-[0_0_16px_rgba(255,62,0,0.35)] border border-[#FF3E00]/80'
              }`}
            >
              <Play className={`w-3.5 h-3.5 fill-current shrink-0 ${isScanning ? 'animate-spin' : ''}`} />
              <span className="whitespace-nowrap font-bold">
                {isScanning 
                  ? `${t('action.scanning')}${scanProgress ? ` (${scanProgress.percentage}%)` : ''}` 
                  : t('action.run_scan')}
              </span>
            </button>
          </div>

        </div>
      </div>

      {/* Workspace Status & Testing Context Sub-Bar */}
      <div className="border-t border-white/[0.06] bg-[#050508]/90 py-1.5 px-3 sm:px-5 lg:px-8">
        <div className="max-w-[1600px] 2xl:max-w-[1800px] w-full mx-auto flex flex-wrap items-center justify-between gap-2.5 text-xs font-mono">
          {/* Left: Workspace Clean / Active state indicator */}
          <div className="flex items-center gap-2 min-w-0">
            {(!files || files.length === 0) ? (
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-950/60 text-emerald-300 border border-emerald-800/50 text-[10px] font-bold tracking-tight">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Workspace Limpo (0 arquivos | 0 falsos-positivos)
                </span>
                <span className="text-zinc-500 text-[10.5px] hidden md:inline">
                  Ambiente zerado sem dados mockados. Pronto para analisar código real.
                </span>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-cyan-950/60 text-cyan-300 border border-cyan-800/50 text-[10px] font-bold tracking-tight">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                  Workspace Ativo ({files.length} {files.length === 1 ? 'arquivo' : 'arquivos'})
                </span>
                <span className="text-zinc-400 text-[10.5px]">
                  • {report.findings.length} achados ({report.metrics.criticalCount} críticos)
                </span>
              </div>
            )}
          </div>

          {/* Right: Active Tool Context badge and workspace quick-actions */}
          <div className="flex items-center gap-2 shrink-0">
            {activeTab !== 'hub' && (
              <div className="flex items-center gap-1.5 text-[10px]">
                <span className="text-zinc-500 hidden lg:inline">Escopo do Teste:</span>
                {activeToolScope === 'MY_CODE' && (
                  <span className="px-2 py-0.5 rounded bg-cyan-950/70 text-cyan-300 border border-cyan-800/60 font-semibold flex items-center gap-1">
                    <FolderCode className="w-3 h-3 text-cyan-400" />
                    Meu Código Real
                  </span>
                )}
                {activeToolScope === 'SANDBOX' && (
                  <span className="px-2 py-0.5 rounded bg-purple-950/70 text-purple-300 border border-purple-800/60 font-semibold flex items-center gap-1">
                    <FlaskConical className="w-3 h-3 text-purple-400" />
                    Sandbox de Teste
                  </span>
                )}
                {activeToolScope === 'GOV_POSTURE' && (
                  <span className="px-2 py-0.5 rounded bg-amber-950/70 text-amber-300 border border-amber-800/60 font-semibold flex items-center gap-1">
                    <ClipboardList className="w-3 h-3 text-amber-400" />
                    Governança & Postura
                  </span>
                )}
              </div>
            )}

            {/* Quick action buttons depending on workspace state */}
            {(!files || files.length === 0) ? (
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setActiveTab('scanner')}
                  className="px-2 py-0.5 rounded bg-white/[0.06] hover:bg-white/[0.12] text-zinc-300 hover:text-white border border-white/[0.1] text-[10px] transition-colors cursor-pointer"
                  title="Ir ao Scanner SAST para adicionar ou carregar código"
                >
                  + Carregar Código
                </button>
                {onOpenUrlIngest && (
                  <button
                    type="button"
                    onClick={onOpenUrlIngest}
                    className="px-2 py-0.5 rounded bg-[#00F0FF]/10 hover:bg-[#00F0FF]/20 text-[#00F0FF] border border-[#00F0FF]/30 text-[10px] transition-colors cursor-pointer"
                    title="Auditar URL ou repositório remoto diretamente"
                  >
                    Auditar URL
                  </button>
                )}
                <button
                  type="button"
                  onClick={onResetWorkspace}
                  className="px-2 py-0.5 rounded bg-white/[0.04] hover:bg-white/[0.08] text-zinc-400 hover:text-zinc-200 border border-white/[0.08] text-[10px] transition-colors cursor-pointer"
                  title="Carregar repositório de teste demo"
                >
                  Restaurar Demo
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-1.5">
                {onClearWorkspace && (
                  <button
                    type="button"
                    onClick={onClearWorkspace}
                    className="px-2 py-0.5 rounded bg-rose-950/40 hover:bg-rose-900/50 text-rose-300 hover:text-rose-200 border border-rose-800/40 text-[10px] transition-colors cursor-pointer flex items-center gap-1"
                    title="Remover todos os arquivos e zerar o workspace"
                  >
                    <Trash2 className="w-2.5 h-2.5" />
                    Limpar Workspace
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
