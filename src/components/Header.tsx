import React, { useMemo } from 'react';
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
  Cpu
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

  const criticalCount = report.metrics.criticalCount;
  const isHealthy = criticalCount === 0;

  const navItems = [
    { id: 'dashboard', label: 'Dashboard & Métricas', icon: ShieldAlert, tooltip: 'Visão executiva com Risk Score cumulativo (0-100), velocímetro de scan e gráficos de criticidade' },
    { id: 'scanner', label: 'Inspetor de Código', icon: FileCode2, badge: report.findings.length, tooltip: 'Auditoria de código linha a linha com destaque de segredos, CWEs e remediação inline' },
    { id: 'endpoints', label: 'LinkFinder (APIs)', icon: Route, badge: report.apiEndpoints.length, tooltip: 'Mapeamento de rotas REST, GraphQL, métodos HTTP e endpoints internos desprotegidos' },
    { id: 'jsminer', label: 'JS Miner', icon: Boxes, badge: report.jsMiner?.totalAssetsCount, tooltip: 'Mineração de bundles JS, verificação de vazamento de Source Maps (.map) e buckets de nuvem' },
    { id: 'dataflow', label: 'Fluxo & Sinks (D3)', icon: Network, badge: report.dataFlowGraph?.metrics.totalTaintFlows, tooltip: 'Grafo D3 de fluxo de dados não confiáveis: Sources ➔ Consumidores ➔ Sinks (Taint Analysis)' },
    { id: 'iast', label: 'IAST (Runtime Hooks)', icon: Activity, badge: report.iastReport?.findings.length ? `${report.iastReport.findings.length} hooks` : 'IAST', tooltip: 'Testes de segurança interativos em tempo de execução com ganchos em sinks dinâmicos' },
    { id: 'sca', label: 'SCA (Dependências & CVEs)', icon: Package, badge: 'SCA', tooltip: 'Auditoria de dependências open-source contra base de CVEs/NVD e risco de licença copyleft' },
    { id: 'iac', label: 'IaC Security (Docker/K8s)', icon: Container, badge: 'IaC', tooltip: 'Análise estática de infraestrutura: Dockerfile root, pods K8s privilegiados e workflows CI/CD' },
    { id: 'apisecurity', label: 'API Security (BOLA/OWASP)', icon: Route, badge: 'OWASP', tooltip: 'Auditoria especializada de APIs: BOLA/IDOR, Mass Assignment, BFLA e Rate Limiting' },
    { id: 'asocsla', label: 'ASOC & SLA Manager', icon: Clock, badge: 'SLA', tooltip: 'Gestão de Débito Técnico e cumprimento de SLAs de remediação corporativos (P0/P1/P2)' },
    { id: 'dast', label: 'DAST (Fuzzer & Headers)', icon: Crosshair, badge: 'DAST', tooltip: 'Fuzzer de injeção em APIs (SQLi/XSS), auditoria de headers HTTP (CSP/HSTS) e comandos cURL' },
    { id: 'sbom', label: 'SBOM Generator', icon: FileSpreadsheet, badge: 'CycloneDX', tooltip: 'Geração de inventário SBOM nos padrões oficiais OWASP CycloneDX v1.5 e SPDX v2.3' },
    { id: 'entropy', label: 'Entropia & Segredos Git', icon: Binary, badge: 'Entropy', tooltip: 'Cálculo de Entropia de Shannon (H) para segredos e varredura forense no histórico Git' },
    { id: 'threatmodel', label: 'Modelagem STRIDE & CVSS', icon: Target, badge: 'STRIDE', tooltip: 'Matriz STRIDE da Microsoft, checklist OWASP ASVS v4 e calculadora oficial CVSS v3.1' },
    { id: 'ctihub', label: 'Threat Intel (CTI)', icon: Globe, badge: 'OTX', tooltip: 'Cyber Threat Intelligence Hub: feeds AlienVault OTX, CISA KEV e correlação com Threat Actors' },
    { id: 'autoremediation', label: 'Auto-Remediação (Patches)', icon: Wrench, badge: '1-Click', tooltip: 'Geração automática de Git Unified Diffs e aplicação direta de patches corretivos no código' },
    { id: 'refactoring', label: 'Refactoring Assistant', icon: Sparkles, badge: 'Modernize', tooltip: 'Sugestões guiadas de refatoração para vulnerabilidades comuns (ex: crypto legada) com preview comparativo antes/depois' },
    { id: 'soarbuilder', label: 'SOAR Visual Studio', icon: Workflow, badge: 'Flow', tooltip: 'Construtor visual drag-and-drop de playbooks SOAR com simulação em tempo real e orquestração de resposta' },
    { id: 'llmsecurity', label: 'AI & LLM Security (OWASP)', icon: Cpu, badge: 'OWASP LLM', tooltip: 'Auditoria de segurança para modelos de IA Generativa, fuzzer de prompt injection e guardrails NeMo/Llama' },
    { id: 'procyber', label: 'Pro Cyber Suite', icon: ShieldAlert, badge: '10 PRO', tooltip: 'Suíte profissional com SOAR Playbooks, BAS MITRE, Sigma Transpiler, Malware Sandbox, KMS Vault, Supply Chain SLSA, EASM, Dark Web, CSPM e PKI' },
    { id: 'policyascode', label: 'Policy-as-Code (OPA)', icon: FileCheck, badge: report.opaCompliance ? `${report.opaCompliance.complianceScore}%` : 'Rego', tooltip: 'Policy-as-Code OPA: defina e teste regras Rego para verificação automática de conformidade contra padrões organizacionais' },
    { id: 'compliance', label: 'Auditoria Compliance (SOC2/ISO/HIPAA)', icon: Scale, badge: 'SOC2', tooltip: 'Score de prontidão determinístico e mapeamento formal para SOC 2 Type II, ISO 27001 e HIPAA' },
    { id: 'frameworks', label: 'Frameworks (MITRE/NIST/OWASP)', icon: ShieldCheck, tooltip: 'Mapeamento cruzado para MITRE ATT&CK, NIST CSF 2.0 e OWASP Web Security Testing Guide' },
    { id: 'soccommand', label: 'SOC Command View', icon: Radio, badge: 'LIVE', tooltip: 'Consolidação em tempo real de logs de auditoria, curvas de MTTR, telemetria e alertas críticos' },
    { id: 'securityonion', label: 'Security Onion (SOC)', icon: Layers, badge: report.findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length, tooltip: 'Console de operações SOC e monitoramento de alertas de segurança' },
    { id: 'crowdstrike', label: 'CrowdStrike (EDR/IOA)', icon: Zap, badge: 3, tooltip: 'Indicadores de Ataque (IOA) comportamentais e inteligência de ameaças Falcon' },
    { id: 'edr', label: 'EDR (Detection & Response)', icon: Crosshair, badge: 'eBPF', tooltip: 'Sensor de endpoint com telemetria de processos, contenção Zero Trust e terminal RTR' },
    { id: 'nmap', label: 'Nmap (Network Suite)', icon: Globe, badge: 'Recon', tooltip: 'Varredura de portas de rede, serviços ativos e fingerprinting de SO' },
    { id: 'nikto', label: 'Nikto (Web Scanner)', icon: FileSearch, badge: 'Audit', tooltip: 'Scanner web de arquivos perigosos, versões obsoletas e configurações vulneráveis' },
    { id: 'ngfw', label: 'NGFW (Next-Gen Firewall)', icon: Flame, badge: 'L7/IPS', tooltip: 'Firewall de aplicação L7 com inspeção profunda de pacotes e regras de tráfego' },
    { id: 'idsips', label: 'IDS/IPS (Snort/Suricata)', icon: Binary, badge: 'DPI', tooltip: 'Sistema de detecção e prevenção de intrusões com assinaturas Snort/Suricata' },
    { id: 'dnssec', label: 'DNS Security (RPZ/DNSSEC)', icon: Globe, badge: 'DoH', tooltip: 'Filtragem de DNS malicioso, Response Policy Zones (RPZ) e validação DNSSEC' },
    { id: 'waf', label: 'WAF (ModSecurity CRS)', icon: ShieldCheck, badge: 'OWASP', tooltip: 'Web Application Firewall com simulador de ataques em tempo real e regras CRS' },
    { id: 'sdwan', label: 'SD-WAN (Fabric & Steering)', icon: Network, badge: 'Overlay', tooltip: 'Malha de túneis IPsec e roteamento inteligente por SLA de latência/jitter' },
    { id: 'headers', label: 'Security Headers (CSP)', icon: Lock, badge: 'OWASP', tooltip: 'Auditoria de cabeçalhos de resposta HTTP, conformidade OWASP e gerador de Content-Security-Policy (CSP)' },
    { id: 'containerscan', label: 'Container (Trivy/CIS)', icon: Container, badge: 'CIS', tooltip: 'Varredura de Dockerfiles contra benchmarks CIS Docker, execução não-root e vulnerabilidades de base' },
    { id: 'cloudiam', label: 'Cloud IAM / CSPM', icon: Key, badge: 'IAM', tooltip: 'Auditoria de privilégio mínimo em políticas AWS IAM, escalada de privilégio e exposição pública' },
    { id: 'jwtinspector', label: 'JWT & Token Forensics', icon: KeyRound, badge: 'RFC7519', tooltip: 'Decodificador e inspetor forense de tokens JWT, detecção de alg: none e senhas HMAC fracas' },
    { id: 'ssrfvalidator', label: 'SSRF & Webhook Validator', icon: Globe, badge: 'SSRF', tooltip: 'Validador de requisições de saída contra SSRF, proteção de metadados de nuvem e evasões de IP' },
    { id: 'rules', label: 'Regras Regex', icon: SlidersHorizontal, tooltip: 'Editor e testador interativo de expressões regulares corporativas customizadas' },
    { id: 'cli', label: 'Terminal CLI', icon: Terminal, tooltip: 'Emulador de console para testar comandos do bin/secscan.js e flags de quality gate' },
    { id: 'pipelineflow', label: 'Pipeline Architect', icon: Workflow, badge: 'Flow', tooltip: 'Pipeline Flow Architect: mapeie achados locais para Pre-commit, Build e Deploy com drag-and-drop no GitHub Actions' },
    { id: 'cicd', label: 'CI/CD & Cloud', icon: CloudCog, tooltip: 'Gerador de pipelines de automação para GitHub Actions, GitLab CI com SARIF 2.1.0' },
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

            {/* Command Palette Button */}
            {onOpenCommandPalette && (
              <button
                id="btn-header-open-command-palette"
                onClick={onOpenCommandPalette}
                className="h-8 px-2.5 sm:px-3 rounded inline-flex items-center gap-1.5 font-mono text-[11px] font-bold uppercase tracking-wider text-white bg-[#181818] hover:bg-[#222] border border-[#333] hover:border-[#FF3E00]/60 transition-all cursor-pointer shadow-xs group"
                title={`Abrir Command Palette (${isMac ? '⌘K' : 'Ctrl+K'})`}
              >
                <Command className="w-3.5 h-3.5 text-[#FF3E00] group-hover:scale-110 transition-transform shrink-0" />
                <span className="hidden lg:inline text-zinc-200">Comandos</span>
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
              <span>Tutorial</span>
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
                title={`Glossário de Vulnerabilidades & Ameaças (${isMac ? '⌘G' : 'Ctrl+G'})`}
              >
                <BookOpen className="w-3.5 h-3.5 text-[#FF3E00] shrink-0" />
                <span className="hidden xl:inline">Glossário</span>
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
                <span className="hidden sm:inline">.gitignore</span>
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
              <span className="hidden sm:inline">Exportar</span>
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
                  ? `ANALISANDO${scanProgress ? ` (${scanProgress.percentage}%)` : '...'}` 
                  : 'EXECUTAR ANÁLISE'}
              </span>
              <kbd className="hidden sm:inline-flex items-center text-[9px] font-mono px-1.5 py-0.2 rounded bg-black/10 border border-current/25 font-bold">
                {isMac ? '⌘S' : 'Ctrl+S'}
              </kbd>
            </button>
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
              className="flex items-center gap-1.5 py-1.5 px-2.5 sm:px-3 rounded text-[11px] font-mono font-bold tracking-wide uppercase whitespace-nowrap transition-all cursor-pointer bg-cyan-950/40 hover:bg-cyan-900/50 text-[#00F0FF] border border-cyan-500/40 hover:border-cyan-400 shrink-0 shadow-xs mr-1"
              title="Abrir o Manual das Ferramentas com explicações, arquitetura, passo a passo e exemplos de código"
            >
              <BookOpen className="w-3.5 h-3.5 text-[#00F0FF] shrink-0" />
              <span>💡 Como Usar &amp; Exemplos</span>
            </button>
          )}

          {navItems.map(item => {
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
