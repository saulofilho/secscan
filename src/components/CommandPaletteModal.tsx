import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Search,
  Command,
  Play,
  Download,
  BookOpen,
  Ban,
  RotateCcw,
  Trash2,
  Compass,
  FileCode2,
  ShieldAlert,
  Terminal,
  Network,
  Route,
  Boxes,
  SlidersHorizontal,
  CloudCog,
  Keyboard,
  ArrowRight,
  CornerDownLeft,
  X,
  FileText,
  AlertTriangle,
  CheckCircle2,
  Filter,
  Sparkles,
  History,
  ListOrdered,
  Activity,
  ShieldCheck,
  Crosshair,
  Radio,
  Zap,
  Globe,
  FileSearch,
  Flame,
  Binary,
  Lock,
  Container,
  Key,
  KeyRound,
  Clock,
  Workflow,
  FileCheck,
  Cpu
} from 'lucide-react';
import { ScannedFile, RegexRule, ScanReport } from '../types';

export interface CommandItem {
  id: string;
  title: string;
  subtitle?: string;
  category: 'Ações Rápidas' | 'Navegação' | 'Arquivos' | 'Regras & Filtros';
  icon: React.ComponentType<{ className?: string }>;
  shortcut?: string;
  badge?: string;
  badgeColor?: string;
  action: () => void;
  keywords?: string[];
}

interface CommandPaletteModalProps {
  isOpen: boolean;
  onClose: () => void;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onRunScan: () => void;
  onOpenExport: () => void;
  onOpenIgnoreModal: () => void;
  onOpenGlossary: () => void;
  onOpenTour: () => void;
  onOpenWelcomeModal?: () => void;
  onResetWorkspace: () => void;
  onClearWorkspace?: () => void;
  onOpenShortcuts: () => void;
  onOpenGitignoreAudit?: () => void;
  files: ScannedFile[];
  onSelectFile: (file: ScannedFile) => void;
  rules: RegexRule[];
  report: ScanReport;
  isScanning: boolean;
}

export const CommandPaletteModal: React.FC<CommandPaletteModalProps> = ({
  isOpen,
  onClose,
  activeTab,
  setActiveTab,
  onRunScan,
  onOpenExport,
  onOpenIgnoreModal,
  onOpenGlossary,
  onOpenTour,
  onOpenWelcomeModal,
  onResetWorkspace,
  onClearWorkspace,
  onOpenShortcuts,
  onOpenGitignoreAudit,
  files,
  onSelectFile,
  rules,
  report,
  isScanning
}) => {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const isMac = useMemo(() => {
    return typeof window !== 'undefined' && /Mac|iPod|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  }, []);

  const modKey = isMac ? '⌘' : 'Ctrl+';

  // Build the list of commands
  const allCommands = useMemo<CommandItem[]>(() => {
    const list: CommandItem[] = [
      // Quick Actions
      {
        id: 'cmd-run-scan',
        title: isScanning ? 'Análise SAST em Execução...' : 'Executar Análise SAST de Segurança',
        subtitle: 'Varre todos os arquivos por segredos, credenciais e vulnerabilidades',
        category: 'Ações Rápidas',
        icon: Play,
        shortcut: `${modKey}S`,
        badge: isScanning ? 'Em andamento' : 'Principal',
        badgeColor: 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/30',
        action: () => {
          onClose();
          onRunScan();
        },
        keywords: ['scan', 'analise', 'executar', 'iniciar', 'verificar', 'segredos', 'vulnerabilidades', 'sast']
      },
      {
        id: 'cmd-export-report',
        title: 'Exportar Relatório de Segurança',
        subtitle: 'Baixe em formato PDF Executivo, JSON, CSV, SARIF ou Markdown',
        category: 'Ações Rápidas',
        icon: Download,
        shortcut: `${modKey}E`,
        badge: 'Exportar',
        badgeColor: 'bg-[#3366FF]/15 text-[#3366FF] border-[#3366FF]/30',
        action: () => {
          onClose();
          onOpenExport();
        },
        keywords: ['exportar', 'download', 'pdf', 'json', 'csv', 'sarif', 'relatorio', 'report']
      },
      {
        id: 'cmd-strategic-remediation-plan',
        title: 'Strategic Remediation Plan (Tarefas de Desenvolvedor)',
        subtitle: 'Plano priorizado de tarefas (P0-P3) com links diretos para docs de mitigação e scripts',
        category: 'Ações Rápidas',
        icon: ListOrdered,
        badge: 'Dev Tasks',
        badgeColor: 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/30',
        action: () => {
          onClose();
          setActiveTab('dashboard');
          setTimeout(() => {
            const el = document.getElementById('strategic-remediation-plan');
            if (el) el.scrollIntoView({ behavior: 'smooth' });
          }, 100);
        },
        keywords: ['strategic', 'remediation', 'plan', 'plano', 'tarefas', 'developer', 'p0', 'p1', 'prioridade', 'docs']
      },
      {
        id: 'cmd-open-glossary',
        title: 'Glossário de Vulnerabilidades & Ameaças',
        subtitle: 'Consulte referências CWE, OWASP Top 10 e guias de mitigação',
        category: 'Ações Rápidas',
        icon: BookOpen,
        shortcut: `${modKey}G`,
        badge: 'CWE / OWASP',
        badgeColor: 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/30',
        action: () => {
          onClose();
          onOpenGlossary();
        },
        keywords: ['glossario', 'cwe', 'owasp', 'mitigacao', 'ameacas', 'vulnerabilidades', 'wiki']
      },
      {
        id: 'cmd-open-ignore',
        title: 'Gerenciar Global Ignore List',
        subtitle: 'Configure regras globais para ignorar arquivos ou padrões sensíveis',
        category: 'Ações Rápidas',
        icon: Ban,
        shortcut: `${modKey}I`,
        badge: 'Filtros',
        badgeColor: 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/30',
        action: () => {
          onClose();
          onOpenIgnoreModal();
        },
        keywords: ['ignore', 'exclusoes', 'desconsiderar', 'filtro', 'padroes', 'regras']
      },
      {
        id: 'cmd-open-shortcuts',
        title: 'Ver Atalhos de Teclado',
        subtitle: 'Lista completa de todos os atalhos globais e comandos de navegação',
        category: 'Ações Rápidas',
        icon: Keyboard,
        shortcut: `${modKey}/`,
        action: () => {
          onClose();
          onOpenShortcuts();
        },
        keywords: ['atalhos', 'shortcuts', 'teclado', 'keyboard', 'hotkeys', 'ajuda']
      },
      ...(onOpenGitignoreAudit ? [{
        id: 'cmd-audit-gitignore',
        title: 'Auditar .gitignore & Segurança do Diretório',
        subtitle: 'Verificar se o repositório possui .gitignore e detectar arquivos sensíveis desprotegidos',
        category: 'Ações Rápidas' as const,
        icon: ShieldCheck,
        badge: 'Higiene Git',
        badgeColor: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
        action: () => {
          onClose();
          onOpenGitignoreAudit();
        },
        keywords: ['gitignore', 'git', 'auditoria', 'chaves', 'secrets', 'env', 'credenciais', 'seguranca', 'diretorio', 'ignore']
      }] : []),
      {
        id: 'cmd-open-tour',
        title: 'Iniciar Tutorial Guiado do SecScan',
        subtitle: 'Tour passo a passo pelos recursos de SAST e AppSec',
        category: 'Ações Rápidas',
        icon: Compass,
        action: () => {
          onClose();
          onOpenTour();
        },
        keywords: ['tutorial', 'tour', 'guia', 'passo a passo', 'ajuda', 'introducao']
      },
      ...(onOpenWelcomeModal ? [{
        id: 'cmd-open-welcome',
        title: 'Modal de Boas-Vindas & Configuração do Workspace',
        subtitle: 'Alternar entre dados demonstrativos de mock ou começar zerado',
        category: 'Ações Rápidas' as const,
        icon: Sparkles,
        action: () => {
          onClose();
          onOpenWelcomeModal();
        },
        keywords: ['welcome', 'boas vindas', 'mock', 'zerar', 'configuracao', 'inicio', 'apresentacao']
      }] : []),
      {
        id: 'cmd-reset-demo',
        title: 'Restaurar Arquivos de Exemplo (Workspace Demo)',
        subtitle: 'Restaura a lista padrão de arquivos vulneráveis para testes',
        category: 'Ações Rápidas',
        icon: RotateCcw,
        shortcut: `${modKey}B`,
        action: () => {
          onClose();
          onResetWorkspace();
        },
        keywords: ['reset', 'restaurar', 'demo', 'exemplo', 'padrao', 'workspace']
      },
      ...(onClearWorkspace ? [{
        id: 'cmd-clear-workspace',
        title: 'Limpar Workspace (Zerar Plataforma)',
        subtitle: 'Remove todos os arquivos e dados de mock para iniciar limpo',
        category: 'Ações Rápidas' as const,
        icon: Trash2,
        action: () => {
          onClose();
          onClearWorkspace();
        },
        keywords: ['limpar', 'zerar', 'clean', 'clear', 'remover', 'vazio', 'novo']
      }] : []),

      // Navigation Modules
      {
        id: 'nav-dashboard',
        title: 'Módulo: Dashboard & Métricas Executivas',
        subtitle: 'Score de Risco, distribuição de severidade, sparkline e roadmap',
        category: 'Navegação',
        icon: ShieldAlert,
        shortcut: `${modKey}1`,
        action: () => {
          onClose();
          setActiveTab('dashboard');
        },
        keywords: ['dashboard', 'metricas', 'graficos', 'score', 'risco', 'roadmap', 'sparkline', 'executivo']
      },
      {
        id: 'nav-cicd-pipeline-health',
        title: 'Widget: CI/CD Pipeline Health & GitHub Actions',
        subtitle: 'Status em tempo real do GitHub Actions, execuções de workflow, taxas de sucesso e logs de scan',
        category: 'Navegação',
        icon: Activity,
        badge: 'Real-Time',
        badgeColor: 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/30',
        action: () => {
          onClose();
          setActiveTab('dashboard');
          setTimeout(() => {
            const el = document.getElementById('cicd-pipeline-health-widget');
            if (el) el.scrollIntoView({ behavior: 'smooth' });
          }, 100);
        },
        keywords: ['cicd', 'pipeline', 'health', 'github actions', 'workflows', 'runs', 'logs', 'success rate', 'actions']
      },
      {
        id: 'nav-threat-intel',
        title: 'Módulo: Cyber Threat Intelligence (CTI) Hub',
        subtitle: 'AlienVault OTX, CISA KEV, MISP e correlação automática com Threat Actors (Scattered Spider, Lazarus, etc.)',
        category: 'Navegação',
        icon: Globe,
        badge: 'CTI Live',
        badgeColor: 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/30',
        action: () => {
          onClose();
          setActiveTab('ctihub');
        },
        keywords: ['threat', 'intelligence', 'cti', 'alienvault', 'otx', 'cisa', 'kev', 'threat actors', 'scattered spider', 'lazarus', 'iocs', 'misp']
      },
      {
        id: 'nav-scan-history',
        title: 'Gráfico: Scan History (Últimos 10 Scans)',
        subtitle: 'Visualização Recharts de progresso e remediação ao longo dos últimos 10 ciclos',
        category: 'Navegação',
        icon: History,
        badge: '10 Scans',
        badgeColor: 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/30',
        action: () => {
          onClose();
          setActiveTab('dashboard');
          setTimeout(() => {
            const el = document.getElementById('dashboard-scan-history-chart-card');
            if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }, 150);
        },
        keywords: ['scan history', 'historico', '10 scans', 'recharts', 'remediacao', 'progresso', 'grafico']
      },
      {
        id: 'nav-scanner',
        title: 'Módulo: Inspetor de Código & Vulnerabilidades',
        subtitle: 'Editor de código interativo, destaque de snippets e triagem',
        category: 'Navegação',
        icon: FileCode2,
        shortcut: `${modKey}2`,
        badge: `${report.findings.length} achados`,
        badgeColor: 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/30',
        action: () => {
          onClose();
          setActiveTab('scanner');
        },
        keywords: ['scanner', 'codigo', 'inspetor', 'editor', 'findings', 'achados', 'segredos']
      },
      {
        id: 'nav-endpoints',
        title: 'Módulo: LinkFinder (Rotas & Endpoints de API)',
        subtitle: 'Mapeamento de rotas REST, GraphQL, endpoints internos e públicos',
        category: 'Navegação',
        icon: Route,
        shortcut: `${modKey}3`,
        badge: `${report.apiEndpoints.length} rotas`,
        badgeColor: 'bg-[#3366FF]/15 text-[#3366FF] border-[#3366FF]/30',
        action: () => {
          onClose();
          setActiveTab('endpoints');
        },
        keywords: ['endpoints', 'rotas', 'linkfinder', 'api', 'urls', 'rest', 'graphql']
      },
      {
        id: 'nav-jsminer',
        title: 'Módulo: JS Miner & Asset Discovery',
        subtitle: 'Varredura estática profunda de bundles e dependências client-side',
        category: 'Navegação',
        icon: Boxes,
        shortcut: `${modKey}4`,
        badge: report.jsMiner?.totalAssetsCount ? `${report.jsMiner.totalAssetsCount} assets` : undefined,
        badgeColor: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
        action: () => {
          onClose();
          setActiveTab('jsminer');
        },
        keywords: ['jsminer', 'javascript', 'miner', 'assets', 'bundles', 'sourcemap']
      },
      {
        id: 'nav-dataflow',
        title: 'Módulo: Fluxo de Dados & Taint Sinks (D3)',
        subtitle: 'Grafo vetorial de propagação de dados não confiáveis e pontos vulneráveis',
        category: 'Navegação',
        icon: Network,
        shortcut: `${modKey}5`,
        badge: report.dataFlowGraph?.metrics.totalTaintFlows ? `${report.dataFlowGraph.metrics.totalTaintFlows} fluxos` : undefined,
        badgeColor: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
        action: () => {
          onClose();
          setActiveTab('dataflow');
        },
        keywords: ['fluxo', 'taint', 'dataflow', 'grafo', 'd3', 'sinks', 'sources']
      },
      {
        id: 'nav-iast',
        title: 'Módulo: IAST (Interactive Application Security Testing)',
        subtitle: 'Hooks de instrumentação em runtime, emulação dinâmica de taint, validação em sinks e zero falsos positivos',
        category: 'Navegação',
        icon: Activity,
        badge: report.iastReport?.findings.length ? `${report.iastReport.findings.length} hooks` : 'IAST',
        badgeColor: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
        action: () => {
          onClose();
          setActiveTab('iast');
        },
        keywords: ['iast', 'runtime', 'hooks', 'taint', 'emulacao', 'dynamic', 'execucao', 'sinks', 'interceptor', 'sqli', 'rce', 'contrast', 'synopsys', 'seeker']
      },
      {
        id: 'nav-frameworks',
        title: 'Módulo: Frameworks de Cibersegurança (MITRE / NIST / OWASP)',
        subtitle: 'Mapeamento tático MITRE ATT&CK/D3FEND, auditoria NIST CSF 2.0 e checklist defensivo OWASP WSTG',
        category: 'Navegação',
        icon: ShieldCheck,
        badge: 'Novo',
        badgeColor: 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/30',
        action: () => {
          onClose();
          setActiveTab('frameworks');
        },
        keywords: ['frameworks', 'mitre', 'attack', 'd3fend', 'nist', 'csf', 'owasp', 'wstg', 'red team', 'purple team', 'auditoria', 'contramedidas']
      },
      {
        id: 'nav-apisecurity',
        title: 'Módulo: API Security & BOLA/IDOR Inspector',
        subtitle: 'Auditoria especializada OWASP API Top 10 (2023), BOLA/IDOR, Mass Assignment e Rate Limiting',
        category: 'Navegação',
        icon: Route,
        badge: 'OWASP API',
        badgeColor: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
        action: () => {
          onClose();
          setActiveTab('apisecurity');
        },
        keywords: ['api', 'bola', 'idor', 'owasp api', 'mass assignment', 'bfla', 'rate limit', 'rest', 'graphql', 'endpoints', 'json', 'postman']
      },
      {
        id: 'nav-asocsla',
        title: 'Módulo: ASOC & Vulnerability SLA Manager',
        subtitle: 'Gestão de Débito Técnico e cumprimento de SLAs corporativos por criticidade (P0/P1/P2/P3)',
        category: 'Navegação',
        icon: Clock,
        badge: 'SLA / ASOC',
        badgeColor: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
        action: () => {
          onClose();
          setActiveTab('asocsla');
        },
        keywords: ['asoc', 'sla', 'debito tecnico', 'vulnerabilidades', 'p0', 'p1', 'p2', 'breached', 'compliance', 'mttr', 'engineering', 'teams']
      },
      {
        id: 'nav-refactoring',
        title: 'Módulo: Security Refactoring Assistant',
        subtitle: 'Sugestões de refatoração para vulnerabilidades comuns (crypto legada -> moderna) com Preview comparativo antes/depois',
        category: 'Navegação',
        icon: Sparkles,
        badge: 'Modernize',
        badgeColor: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30',
        action: () => {
          onClose();
          setActiveTab('refactoring');
        },
        keywords: ['refactoring', 'refatoracao', 'assistant', 'preview', 'crypto', 'md5', 'argon2', 'aes-256-gcm', 'diff', 'patch', 'antes depois', 'modernizacao']
      },
      {
        id: 'nav-policyascode',
        title: 'Módulo: Policy-as-Code (OPA Rego)',
        subtitle: 'Defina guardrails e avalie políticas declarativas OPA Rego contra conformidade corporativa em tempo real',
        category: 'Navegação',
        icon: FileCheck,
        badge: 'Rego OPA',
        badgeColor: 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/30',
        action: () => {
          onClose();
          setActiveTab('policyascode');
        },
        keywords: ['policy', 'opa', 'rego', 'compliance', 'guardrail', 'gate', 'pci', 'soc2', 'nist', 'cis', 'open policy agent', 'declarative']
      },
      {
        id: 'nav-procyber',
        title: 'Módulo: Pro Cyber Defense Suite (10 Ferramentas Pro)',
        subtitle: 'SOAR Playbooks, BAS Purple Team, Sigma Transpiler, Malware Sandbox, KMS Vault, Supply Chain SLSA, EASM, Dark Web, CSPM e PKI',
        category: 'Navegação',
        icon: ShieldAlert,
        badge: '10 PRO',
        badgeColor: 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/30',
        action: () => {
          onClose();
          setActiveTab('procyber');
        },
        keywords: ['soar', 'playbook', 'bas', 'purple team', 'atomic red team', 'sigma', 'siem', 'splunk', 'elastic', 'sentinel', 'sandbox', 'malware', 'vault', 'kms', 'envelope', 'slsa', 'cosign', 'sigstore', 'supply chain', 'easm', 'osint', 'shodan', 'dark web', 'stealer', 'cspm', 'aws', 'pki', 'tls', 'ssl', 'cert']
      },
      {
        id: 'nav-pipelineflow',
        title: 'Módulo: Pipeline Flow Architect (DevSecOps Visualizer)',
        subtitle: 'Mapeie achados de scan locais para Pre-commit, Build e Deploy com drag-and-drop para workflows GitHub Actions',
        category: 'Navegação',
        icon: Workflow,
        badge: 'Flow CI/CD',
        badgeColor: 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/30',
        action: () => {
          onClose();
          setActiveTab('pipelineflow');
        },
        keywords: ['pipeline', 'flow', 'architect', 'github actions', 'yaml', 'workflow', 'pre-commit', 'build', 'deploy', 'drag drop', 'shift-left', 'quality gate', 'ci/cd']
      },
      {
        id: 'nav-soccommand',
        title: 'Módulo: SOC Command View & Real-Time Operations',
        subtitle: 'Console unificado com streaming de logs de auditoria, curvas de MTTR e alertas críticos da suíte',
        category: 'Navegação',
        icon: Radio,
        badge: 'SOC LIVE',
        badgeColor: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
        action: () => {
          onClose();
          setActiveTab('soccommand');
        },
        keywords: ['soc', 'command view', 'mttr', 'audit logs', 'alertas', 'telemetria', 'operacoes', 'incidentes', 'tempo real', 'graficos', 'tendencia', 'siem']
      },
      {
        id: 'nav-securityonion',
        title: 'Módulo: Security Onion (SOC & Threat Hunting Suite)',
        subtitle: 'Caça a ameaças (Hunt), triagem de casos, gerador de regras (Sigma/Suricata/Zeek), PCAP e SOPs',
        category: 'Navegação',
        icon: Radio,
        badge: 'SOC / Hunt',
        badgeColor: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
        action: () => {
          onClose();
          setActiveTab('securityonion');
        },
        keywords: ['security onion', 'soc', 'hunt', 'threat hunting', 'cases', 'triagem', 'sigma', 'suricata', 'zeek', 'modsecurity', 'pcap', 'playbooks', 'blue team']
      },
      {
        id: 'nav-crowdstrike',
        title: 'Módulo: CrowdStrike Falcon (EDR & Threat Graph)',
        subtitle: 'Visibilidade de endpoints, Indicadores de Ataque (IOA), contenção de rede e inteligência de adversários',
        category: 'Navegação',
        icon: Zap,
        badge: 'EDR / IOA',
        badgeColor: 'bg-red-500/15 text-red-400 border-red-500/30',
        action: () => {
          onClose();
          setActiveTab('crowdstrike');
        },
        keywords: ['crowdstrike', 'falcon', 'edr', 'xdr', 'ioa', 'indicadores de ataque', 'process tree', 'containment', 'isolamento', 'rtr', 'threat intel', 'adversarios', 'overwatch']
      },
      {
        id: 'nav-nmap',
        title: 'Módulo: Nmap (Network Discovery & Port Recon Suite)',
        subtitle: 'Auditoria de portas abertas, fingerprint de SO, banners, scripts NSE e topologia de rede',
        category: 'Navegação',
        icon: Globe,
        badge: 'Port / Host Recon',
        badgeColor: 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/30',
        action: () => {
          onClose();
          setActiveTab('nmap');
        },
        keywords: ['nmap', 'portas', 'scan', 'network', 'rede', 'recon', 'banner', 'nse', 'fingerprint', 'os', 'topologia', 'port scanner']
      },
      {
        id: 'nav-nikto',
        title: 'Módulo: Nikto (Web Server Misconfiguration & Header Scanner)',
        subtitle: 'Auditoria de servidores web, arquivos perigosos, métodos HTTP de risco e cabeçalhos de segurança',
        category: 'Navegação',
        icon: FileSearch,
        badge: 'Web Audit',
        badgeColor: 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/30',
        action: () => {
          onClose();
          setActiveTab('nikto');
        },
        keywords: ['nikto', 'web', 'servidor', 'headers', 'misconfiguration', 'hsts', 'csp', 'x-frame-options', 'methods', 'trace', 'arquivos', 'tuning']
      },
      {
        id: 'nav-ngfw',
        title: 'Módulo: NGFW (Next-Gen Firewall Suite & Zero Trust)',
        subtitle: 'Políticas L7, inspeção App-ID, prevenção de intrusão inline (IPS), zonas de segurança e decriptação SSL',
        category: 'Navegação',
        icon: Flame,
        badge: 'L7 / IPS',
        badgeColor: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
        action: () => {
          onClose();
          setActiveTab('ngfw');
        },
        keywords: ['ngfw', 'firewall', 'app-id', 'ips', 'zero-trust', 'ssl', 'decriptacao', 'regras', 'zonas', 'dmz', 'untrust', 'palo alto', 'fortinet', 'checkpoint']
      },
      {
        id: 'nav-edr',
        title: 'Módulo: EDR (Endpoint Detection and Response)',
        subtitle: 'Árvore de processos parent-child, Live Response Shell (RTR), Playbooks SOAR, Cofre de IOCs, Threat Hunting KQL e contenção Zero Trust',
        category: 'Navegação',
        icon: Crosshair,
        badge: 'eBPF / EDR',
        badgeColor: 'bg-red-500/15 text-red-400 border-red-500/30',
        action: () => {
          onClose();
          setActiveTab('edr');
        },
        keywords: ['edr', 'endpoint', 'processo', 'tree', 'rtr', 'real-time response', 'threat hunting', 'hunting', 'playbook', 'soar', 'ioc', 'yara', 'dump', 'memoria', 'mitre', 'ioa', 'kql', 'containment', 'quarantine', 'sentinelone', 'crowdstrike', 'carbon black', 'defender']
      },
      {
        id: 'nav-idsips',
        title: 'Módulo: IDS/IPS (Snort & Suricata Signature Engine)',
        subtitle: 'Inspeção profunda de pacotes (DPI), regras Snort/Suricata, alertas e drops inline, decodificador PCAP e detecção de anomalias',
        category: 'Navegação',
        icon: Binary,
        badge: 'IDS / IPS',
        badgeColor: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
        action: () => {
          onClose();
          setActiveTab('idsips');
        },
        keywords: ['ids', 'ips', 'snort', 'suricata', 'dpi', 'pcap', 'hex', 'drop', 'reject', 'inline', 'signature', 'anomalia', 'zeek', 'bro']
      },
      {
        id: 'nav-dnssec',
        title: 'Módulo: DNS Security (RPZ, Sinkhole & DNSSEC)',
        subtitle: 'Proteção contra exfiltração por tunelamento DNS, detecção heurística DGA via ML, Response Policy Zones (RPZ) e validação de cadeia DNSSEC',
        category: 'Navegação',
        icon: Globe,
        badge: 'DNS Security',
        badgeColor: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
        action: () => {
          onClose();
          setActiveTab('dnssec');
        },
        keywords: ['dns', 'dnssec', 'sinkhole', 'rpz', 'dga', 'tunnel', 'tunelamento', 'exfiltracao', 'doh', 'dot', 'rrsig', 'dnskey', 'ksk', 'zsk', 'shannon']
      },
      {
        id: 'nav-waf',
        title: 'Módulo: WAF (Web Application Firewall - L7)',
        subtitle: 'Proteção OWASP CRS v3.3, mitigação de SQLi, XSS, RCE, SSRF, Virtual Patching de CVEs, Rate Limiting e gestão de bots',
        category: 'Navegação',
        icon: ShieldCheck,
        badge: 'WAF L7',
        badgeColor: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
        action: () => {
          onClose();
          setActiveTab('waf');
        },
        keywords: ['waf', 'modsecurity', 'coreruleset', 'crs', 'sqli', 'xss', 'rce', 'ssrf', 'rate limit', 'virtual patch', 'cloudflare', 'akamai', 'imperva', 'bot']
      },
      {
        id: 'nav-sdwan',
        title: 'Módulo: SD-WAN (Orchestrator, Steering & Overlay Mesh)',
        subtitle: 'Roteamento dinâmico App-Aware SLA, agregação multi-link (MPLS/Fibra/5G), malha IPsec de filiais, FEC e duplicação de pacotes',
        category: 'Navegação',
        icon: Network,
        badge: 'SD-WAN',
        badgeColor: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
        action: () => {
          onClose();
          setActiveTab('sdwan');
        },
        keywords: ['sdwan', 'sd-wan', 'mpls', 'dia', 'fibra', '5g', 'ipsec', 'fec', 'sla', 'jitter', 'latency', 'cisco viptela', 'fortigate', 'velocloud', 'failover']
      },
      {
        id: 'nav-headers',
        title: 'Módulo: Security Headers & CSP Studio',
        subtitle: 'Auditoria de cabeçalhos HTTP, nota OWASP (A+ a F), simulador e gerador de Content-Security-Policy (CSP)',
        category: 'Navegação',
        icon: Lock,
        badge: 'OWASP Headers',
        badgeColor: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
        action: () => {
          onClose();
          setActiveTab('headers');
        },
        keywords: ['headers', 'cabecalhos', 'csp', 'content-security-policy', 'hsts', 'x-frame-options', 'cors', 'owasp', 'nginx', 'apache', 'caddy', 'express']
      },
      {
        id: 'nav-containerscan',
        title: 'Módulo: Trivy & Container Security Scanner',
        subtitle: 'Auditoria de Dockerfile contra benchmarks CIS Docker, execução não-root e vulnerabilidades de base',
        category: 'Navegação',
        icon: Container,
        badge: 'CIS Benchmark',
        badgeColor: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
        action: () => {
          onClose();
          setActiveTab('containerscan');
        },
        keywords: ['container', 'docker', 'dockerfile', 'trivy', 'cis', 'root', 'hadolint', 'multistage', 'cve', 'alpine']
      },
      {
        id: 'nav-cloudiam',
        title: 'Módulo: Cloud IAM & CSPM Least-Privilege Auditor',
        subtitle: 'Análise de políticas AWS IAM, privilégios excessivos (wildcard *), escalada de privilégios e exposição pública',
        category: 'Navegação',
        icon: Key,
        badge: 'AWS IAM / CSPM',
        badgeColor: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
        action: () => {
          onClose();
          setActiveTab('cloudiam');
        },
        keywords: ['iam', 'aws', 'cspm', 'cloud', 'politica', 'passrole', 'wildcard', 'least privilege', 's3', 'privilegio minimo']
      },
      {
        id: 'nav-jwtinspector',
        title: 'Módulo: JWT & API Token Forensic Inspector',
        subtitle: 'Decodificador e inspetor forense de tokens JWT, detecção de alg: none, senhas fracas e claims canônicas',
        category: 'Navegação',
        icon: KeyRound,
        badge: 'RFC 7519',
        badgeColor: 'bg-violet-500/15 text-violet-400 border-violet-500/30',
        action: () => {
          onClose();
          setActiveTab('jwtinspector');
        },
        keywords: ['jwt', 'token', 'bearer', 'forensics', 'alg none', 'hs256', 'rs256', 'hmac', 'segredo', 'expirado', 'claims', 'auth']
      },
      {
        id: 'nav-ssrfvalidator',
        title: 'Módulo: SSRF & Webhook Safety Validator',
        subtitle: 'Validador de requisições de saída contra SSRF, proteção de metadados de nuvem (169.254.169.254) e IPs privados',
        category: 'Navegação',
        icon: Globe,
        badge: 'SSRF Defense',
        badgeColor: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
        action: () => {
          onClose();
          setActiveTab('ssrfvalidator');
        },
        keywords: ['ssrf', 'webhook', 'request forgery', '169.254.169.254', 'metadata', 'imds', 'rfc1918', 'localhost', 'outbound', 'axios']
      },
      {
        id: 'nav-rules',
        title: 'Módulo: Regras Regex & Entropia de Shannon',
        subtitle: 'Configuração e teste de expressões regulares para detecção SAST',
        category: 'Navegação',
        icon: SlidersHorizontal,
        shortcut: `${modKey}6`,
        badge: `${rules.length} regras`,
        badgeColor: 'bg-zinc-800 text-zinc-300 border-zinc-700',
        action: () => {
          onClose();
          setActiveTab('rules');
        },
        keywords: ['regras', 'regex', 'entropia', 'shannon', 'padroes', 'rules', 'custom']
      },
      {
        id: 'nav-cli',
        title: 'Módulo: Terminal CLI Interativo',
        subtitle: 'Console headless para automação de scans e scripts de segurança',
        category: 'Navegação',
        icon: Terminal,
        shortcut: `${modKey}7`,
        action: () => {
          onClose();
          setActiveTab('cli');
        },
        keywords: ['cli', 'terminal', 'linha de comando', 'bash', 'console', 'automacao']
      },
      {
        id: 'nav-cicd',
        title: 'Módulo: CI/CD & Integração Cloud',
        subtitle: 'Templates para GitHub Actions, GitLab CI, Jenkins e quality gates',
        category: 'Navegação',
        icon: CloudCog,
        shortcut: `${modKey}8`,
        action: () => {
          onClose();
          setActiveTab('cicd');
        },
        keywords: ['cicd', 'github actions', 'gitlab', 'pipeline', 'devops', 'cloud', 'quality gate']
      },
      {
        id: 'nav-soarbuilder',
        title: 'Módulo: SOAR Visual Studio (Orquestração & Playbooks)',
        subtitle: 'Construtor visual drag-and-drop de playbooks SOAR com simulação em tempo real e orquestração de resposta',
        category: 'Navegação',
        icon: Workflow,
        badge: 'Visual Flow',
        badgeColor: 'bg-[#00FF41]/15 text-[#00FF41] border-[#00FF41]/30',
        action: () => {
          onClose();
          setActiveTab('soarbuilder');
        },
        keywords: ['soar', 'playbook', 'visual', 'orquestracao', 'workflow', 'automacao', 'aws iam', 'firewall', 'incidentes']
      },
      {
        id: 'nav-llmsecurity',
        title: 'Módulo: AI & LLM Security Suite (OWASP Top 10 for LLMs)',
        subtitle: 'Auditoria de IA Generativa, fuzzer de prompt injection, jailbreaks e guardrails NeMo/Llama',
        category: 'Navegação',
        icon: Cpu,
        badge: 'OWASP LLM',
        badgeColor: 'bg-[#00F0FF]/15 text-[#00F0FF] border-[#00F0FF]/30',
        action: () => {
          onClose();
          setActiveTab('llmsecurity');
        },
        keywords: ['llm', 'ia', 'ai', 'owasp', 'prompt injection', 'jailbreak', 'fuzzer', 'guardrails', 'nemo', 'rag', 'genai']
      }
    ];

    // Workspace Files (Quick Jump)
    files.forEach((file) => {
      const fileFindingsCount = report.findings.filter(f => f.file === file.name).length;
      const fileExt = file.extension || file.name.split('.').pop() || 'código';
      list.push({
        id: `file-${file.name}`,
        title: `Abrir: ${file.name}`,
        subtitle: file.path ? `${file.path} • ${fileExt}` : `Arquivo do Workspace • ${fileExt}`,
        category: 'Arquivos',
        icon: FileCode2,
        badge: fileFindingsCount > 0 ? `${fileFindingsCount} achado${fileFindingsCount > 1 ? 's' : ''}` : 'Limpo',
        badgeColor: fileFindingsCount > 0 ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/30' : 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/30',
        action: () => {
          onClose();
          onSelectFile(file);
          setActiveTab('scanner');
        },
        keywords: [file.name, fileExt, 'arquivo', 'file', 'source', 'abrir']
      });
    });

    // Rules & Filters Quick Jumps
    rules.slice(0, 8).forEach((r) => {
      list.push({
        id: `rule-${r.id}`,
        title: `Regra: ${r.name}`,
        subtitle: `[${r.severity}] ${r.description}`,
        category: 'Regras & Filtros',
        icon: SlidersHorizontal,
        badge: r.severity,
        badgeColor: r.severity === 'CRITICAL' ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/30' : 'bg-amber-500/15 text-amber-400 border-amber-500/30',
        action: () => {
          onClose();
          setActiveTab('rules');
        },
        keywords: [r.name, r.id, r.category, r.severity, 'regra', 'regex']
      });
    });

    return list;
  }, [files, rules, report, isScanning, modKey, onClose, onRunScan, onOpenExport, onOpenGlossary, onOpenIgnoreModal, onOpenShortcuts, onOpenTour, onResetWorkspace, onSelectFile, setActiveTab]);

  // Filter commands by search query
  const filteredCommands = useMemo(() => {
    if (!query.trim()) {
      return allCommands;
    }
    const cleanQuery = query.toLowerCase().trim();
    return allCommands.filter((cmd) => {
      const matchTitle = cmd.title.toLowerCase().includes(cleanQuery);
      const matchSubtitle = cmd.subtitle?.toLowerCase().includes(cleanQuery);
      const matchCategory = cmd.category.toLowerCase().includes(cleanQuery);
      const matchKeywords = cmd.keywords?.some(k => k.toLowerCase().includes(cleanQuery));
      return matchTitle || matchSubtitle || matchCategory || matchKeywords;
    });
  }, [allCommands, query]);

  // Reset selected index when query changes or opens
  useEffect(() => {
    setSelectedIndex(0);
  }, [query, isOpen]);

  // Focus input on open
  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setTimeout(() => {
        inputRef.current?.focus();
      }, 50);
    }
  }, [isOpen]);

  // Handle keyboard navigation inside the palette
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex((prev) => (prev < filteredCommands.length - 1 ? prev + 1 : 0));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex((prev) => (prev > 0 ? prev - 1 : filteredCommands.length - 1));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (filteredCommands[selectedIndex]) {
          filteredCommands[selectedIndex].action();
        }
      } else if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, filteredCommands, selectedIndex, onClose]);

  // Keep selected item in view
  useEffect(() => {
    if (!listRef.current) return;
    const selectedEl = listRef.current.querySelector(`[data-index="${selectedIndex}"]`);
    if (selectedEl) {
      selectedEl.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex]);

  if (!isOpen) return null;

  return (
    <div
      id="command-palette-backdrop"
      className="fixed inset-0 bg-black/80 backdrop-blur-xs flex items-start justify-center pt-[10vh] px-4 z-50 animate-in fade-in duration-150"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        id="command-palette-dialog"
        className="bg-[#0A0A0A] border border-[#333] rounded-lg shadow-[0_0_50px_rgba(0,0,0,0.8)] w-full max-w-2xl overflow-hidden flex flex-col max-h-[75vh] animate-in zoom-in-95 duration-150"
      >
        {/* Search Header */}
        <div className="flex items-center px-4 py-3.5 border-b border-[#222] bg-[#0E0E0E] relative">
          <Command className="w-5 h-5 text-[#FF3E00] shrink-0 mr-3 animate-pulse" />
          <input
            ref={inputRef}
            id="command-palette-search-input"
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Digite um comando, arquivo, regra ou atalho... (ex: scan, exportar, authController, d3)"
            className="w-full bg-transparent text-white placeholder-zinc-500 font-mono text-sm focus:outline-hidden"
            autoComplete="off"
            spellCheck="false"
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery('')}
              className="text-[#666] hover:text-white p-1 mr-1 transition-colors cursor-pointer"
              title="Limpar busca"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
          <kbd className="hidden sm:inline-flex items-center text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#1A1A1A] text-zinc-400 border border-[#333]">
            ESC
          </kbd>
        </div>

        {/* Results List */}
        <div ref={listRef} className="overflow-y-auto flex-1 p-2 space-y-1 divide-y divide-[#1A1A1A]">
          {filteredCommands.length === 0 ? (
            <div className="py-12 px-4 text-center text-zinc-500 font-mono text-xs">
              <Search className="w-8 h-8 text-[#333] mx-auto mb-2" />
              <p className="text-zinc-400 font-semibold">Nenhum comando ou arquivo correspondente.</p>
              <p className="text-zinc-600 mt-1">Tente pesquisar por &quot;scan&quot;, &quot;exportar&quot;, &quot;dashboard&quot; ou o nome de um arquivo.</p>
            </div>
          ) : (
            filteredCommands.map((cmd, index) => {
              const Icon = cmd.icon;
              const isSelected = index === selectedIndex;

              return (
                <div
                  key={cmd.id}
                  data-index={index}
                  onClick={() => cmd.action()}
                  onMouseEnter={() => setSelectedIndex(index)}
                  className={`flex items-center justify-between p-2.5 rounded-md cursor-pointer transition-colors font-mono text-xs ${
                    isSelected
                      ? 'bg-[#181818] border border-[#FF3E00]/40 text-white'
                      : 'hover:bg-[#121212] text-zinc-300 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0 pr-2">
                    <div
                      className={`w-7 h-7 rounded flex items-center justify-center shrink-0 border ${
                        isSelected
                          ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/40'
                          : 'bg-[#141414] text-zinc-400 border-[#222]'
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                    </div>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className={`font-bold truncate ${isSelected ? 'text-white' : 'text-zinc-200'}`}>
                          {cmd.title}
                        </span>
                        {cmd.badge && (
                          <span className={`text-[9px] px-1.5 py-0.2 rounded border font-semibold shrink-0 ${cmd.badgeColor || 'bg-zinc-800 text-zinc-300 border-zinc-700'}`}>
                            {cmd.badge}
                          </span>
                        )}
                      </div>
                      {cmd.subtitle && (
                        <p className="text-[10.5px] text-zinc-500 truncate mt-0.5">
                          {cmd.subtitle}
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {cmd.shortcut && (
                      <kbd className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#161616] text-zinc-400 border border-[#2E2E2E] shadow-xs">
                        {cmd.shortcut}
                      </kbd>
                    )}
                    {isSelected && (
                      <CornerDownLeft className="w-3.5 h-3.5 text-[#FF3E00] hidden sm:inline shrink-0" />
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer Navigation Hints */}
        <div className="px-4 py-2.5 bg-[#080808] border-t border-[#1C1C1C] flex flex-wrap items-center justify-between text-[10px] font-mono text-zinc-500 gap-2">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1">
              <kbd className="px-1 py-0.2 bg-[#1A1A1A] border border-[#333] rounded text-zinc-400">↑</kbd>
              <kbd className="px-1 py-0.2 bg-[#1A1A1A] border border-[#333] rounded text-zinc-400">↓</kbd>
              <span>Navegar</span>
            </span>
            <span className="flex items-center gap-1">
              <kbd className="px-1.5 py-0.2 bg-[#1A1A1A] border border-[#333] rounded text-zinc-400">↵</kbd>
              <span>Executar</span>
            </span>
            <span className="flex items-center gap-1">
              <kbd className="px-1.5 py-0.2 bg-[#1A1A1A] border border-[#333] rounded text-zinc-400">esc</kbd>
              <span>Fechar</span>
            </span>
          </div>

          <div className="flex items-center gap-2">
            <span>SecScan AppSec Quick Command Engine</span>
          </div>
        </div>
      </div>
    </div>
  );
};
