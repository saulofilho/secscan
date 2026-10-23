import React, { useState, useMemo } from 'react';
import { 
  FileCode2, 
  Route, 
  Container, 
  Radio, 
  Scale, 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  ArrowRight, 
  Play, 
  Download, 
  Sparkles, 
  Network, 
  Boxes, 
  Activity, 
  Package, 
  Binary, 
  Wrench, 
  Crosshair, 
  Lock, 
  KeyRound, 
  Globe, 
  CloudCog, 
  Key, 
  Flame, 
  Layers, 
  Zap, 
  FileSearch, 
  Clock, 
  Target, 
  Workflow, 
  Cpu, 
  FileCheck, 
  TrendingDown, 
  SlidersHorizontal, 
  Terminal, 
  FileSpreadsheet, 
  Compass, 
  Check, 
  AlertTriangle,
  ExternalLink,
  ChevronRight,
  Loader2
} from 'lucide-react';
import { ScanReport, ScannedFile, ScanProgress } from '../types';
import { useLanguage } from '../lib/i18nContext';

interface AppModulesHubProps {
  report: ScanReport;
  files: ScannedFile[];
  onNavigateToTab: (tab: string) => void;
  onRunScan: () => void;
  isScanning: boolean;
  scanProgress?: ScanProgress | null;
  onOpenExport?: () => void;
  onOpenTour?: () => void;
  onOpenCommandPalette?: () => void;
  onOpenGlossary?: () => void;
  onOpenGitignoreAudit?: () => void;
}

interface ToolDefinition {
  id: string;
  nameKey: string;
  defaultName: string;
  descKey: string;
  defaultDesc: string;
  icon: any;
  badge?: string | number;
  badgeType?: 'count' | 'label' | 'highlight';
}

interface ModuleDefinition {
  id: 'CODE_SAST' | 'API_DAST' | 'CLOUD_INFRA' | 'SOC_EDR' | 'GOV_AI';
  title: string;
  subtitle: string;
  scopeBadge: string;
  description: string;
  accentColor: string; // e.g. '#00F0FF'
  bgGradient: string;
  borderColor: string;
  icon: any;
  primaryTab: string;
  tools: ToolDefinition[];
}

export type TestingContextScope = 'ALL' | 'MY_CODE' | 'SANDBOX' | 'GOV_POSTURE';

export function getToolContextScope(toolId: string): 'MY_CODE' | 'SANDBOX' | 'GOV_POSTURE' {
  if (['scanner', 'dataflow', 'endpoints', 'entropy', 'jsminer', 'sca', 'iast', 'iac', 'autoremediation', 'refactoring'].includes(toolId)) {
    return 'MY_CODE';
  }
  if (['apisecurity', 'dast', 'headers', 'jwtinspector', 'ssrfvalidator', 'containerscan', 'cloudiam', 'ngfw', 'idsips', 'dnssec', 'sdwan', 'edr', 'soccommand', 'securityonion', 'crowdstrike', 'waf', 'nmap', 'nikto'].includes(toolId)) {
    return 'SANDBOX';
  }
  return 'GOV_POSTURE';
}

export const AppModulesHub: React.FC<AppModulesHubProps> = ({
  report,
  files,
  onNavigateToTab,
  onRunScan,
  isScanning,
  scanProgress,
  onOpenExport,
  onOpenTour,
  onOpenCommandPalette,
  onOpenGlossary,
  onOpenGitignoreAudit
}) => {
  const { t, language } = useLanguage();
  const [searchTerm, setSearchTerm] = useState('');
  const [contextFilter, setContextFilter] = useState<TestingContextScope>('ALL');

  const criticalCount = report.metrics.criticalCount;
  const highCount = report.metrics.highCount;
  const isHealthy = criticalCount === 0;

  // 5 Specialized Modules Definition
  const MODULES: ModuleDefinition[] = useMemo(() => [
    {
      id: 'CODE_SAST',
      title: language === 'pt' ? 'Análise de Código & SAST' : language === 'es' ? 'Análisis de Código y SAST' : 'Code Security & SAST',
      subtitle: language === 'pt' ? 'Segurança Estática, Fluxo de Dados & Remediação' : language === 'es' ? 'Seguridad Estática, Flujo de Datos y Remediación' : 'Static Security, Data Flow & Remediation',
      scopeBadge: language === 'pt' ? 'Mapeia Seu Código' : language === 'es' ? 'Analiza Su Código' : 'Analyzes Your Code',
      description: language === 'pt' 
        ? 'Inspeção profunda de AST em JavaScript/TypeScript, caçador de segredos por entropia, grafo de contaminação (taint) com visualização de caminhos de ataque e auto-remediação em 1 clique.'
        : language === 'es'
        ? 'Inspección profunda de AST en JS/TS, detector de secretos por entropía, grafo de taint interactivo con rutas de ataque y remediación automática en 1 clic.'
        : 'Deep JS/TS AST parsing, Shannon entropy secret detection, interactive taint data flow graph with attack path visualization, and 1-click remediation.',
      accentColor: '#00F0FF',
      bgGradient: 'from-[#00F0FF]/15 via-transparent to-transparent',
      borderColor: 'group-hover:border-[#00F0FF]/40',
      icon: FileCode2,
      primaryTab: 'scanner',
      tools: [
        {
          id: 'scanner',
          nameKey: 'tab.scanner',
          defaultName: 'Scanner SAST',
          descKey: 'tab.scanner_tooltip',
          defaultDesc: 'Análise estática profunda de código e segredos',
          icon: FileCode2,
          badge: report.findings.length > 0 ? report.findings.length : undefined,
          badgeType: 'count'
        },
        {
          id: 'dataflow',
          nameKey: 'tab.dataflow',
          defaultName: 'DataFlow & Ataque',
          descKey: 'tab.dataflow_tooltip',
          defaultDesc: 'Grafo D3 de fluxo de variáveis, taint e caminhos de ataque',
          icon: Network,
          badge: report.dataFlowGraph?.metrics.totalTaintFlows ? `${report.dataFlowGraph.metrics.totalTaintFlows} fluxos` : 'D3 Graph',
          badgeType: 'label'
        },
        {
          id: 'endpoints',
          nameKey: 'tab.endpoints',
          defaultName: 'Endpoints & Rotas',
          descKey: 'tab.endpoints_tooltip',
          defaultDesc: 'Mapeamento de rotas e APIs no código com LinkFinder',
          icon: Route,
          badge: report.apiEndpoints.length > 0 ? report.apiEndpoints.length : undefined,
          badgeType: 'count'
        },
        {
          id: 'entropy',
          nameKey: 'tab.entropy',
          defaultName: 'Caçador de Segredos',
          descKey: 'tab.entropy_tooltip',
          defaultDesc: 'Análise de Entropia de Shannon para chaves e tokens vazados',
          icon: Binary,
          badge: 'Shannon',
          badgeType: 'label'
        },
        {
          id: 'jsminer',
          nameKey: 'tab.jsminer',
          defaultName: 'JSMiner Assets',
          descKey: 'tab.jsminer_tooltip',
          defaultDesc: 'Mineração de bundles JS, sourcemaps e rotas ocultas',
          icon: Boxes,
          badge: report.jsMiner?.totalAssetsCount || 'Assets',
          badgeType: 'label'
        },
        {
          id: 'sca',
          nameKey: 'tab.sca',
          defaultName: 'Dependências SCA',
          descKey: 'tab.sca_tooltip',
          defaultDesc: 'Software Composition Analysis e checagem de CVEs conhecidas',
          icon: Package,
          badge: 'CVEs',
          badgeType: 'label'
        },
        {
          id: 'iast',
          nameKey: 'tab.iast',
          defaultName: 'IAST Runtime',
          descKey: 'tab.iast_tooltip',
          defaultDesc: 'Instrumentação interativa em tempo de execução',
          icon: Activity,
          badge: 'Hooks',
          badgeType: 'label'
        },
        {
          id: 'autoremediation',
          nameKey: 'tab.autoremediation',
          defaultName: 'Auto-Remediação',
          descKey: 'tab.autoremediation_tooltip',
          defaultDesc: 'Geração automatizada de patches de correção com 1 clique',
          icon: Wrench,
          badge: '1-Click',
          badgeType: 'highlight'
        },
        {
          id: 'refactoring',
          nameKey: 'tab.refactoring',
          defaultName: 'Refatoração Segura',
          descKey: 'tab.refactoring_tooltip',
          defaultDesc: 'Modernização arquitetural e padrões de código limpo',
          icon: Sparkles,
          badge: 'AI Refactor',
          badgeType: 'label'
        }
      ]
    },
    {
      id: 'API_DAST',
      title: language === 'pt' ? 'APIs, DAST & Perímetro' : language === 'es' ? 'APIs, DAST y Perímetro' : 'APIs, DAST & Perimeter',
      subtitle: language === 'pt' ? 'OWASP API Top 10, Fuzzing & Análise Dinâmica' : language === 'es' ? 'OWASP API Top 10, Fuzzing y Análisis Dinámico' : 'OWASP API Top 10, Fuzzing & Dynamic Testing',
      scopeBadge: language === 'pt' ? 'Suas APIs & Perímetro' : language === 'es' ? 'Sus APIs y Perímetro' : 'Your APIs & Perimeter',
      description: language === 'pt'
        ? 'Varredura dinâmica de vulnerabilidades (DAST), auditoria de conformidade com OWASP API Security Top 10, validação SSRF para metadados de nuvem e inspeção criptográfica de tokens JWT.'
        : language === 'es'
        ? 'Escaneo dinámico DAST, auditoría contra OWASP API Security Top 10, validación de SSRF contra metadatos cloud e inspección profunda de tokens JWT.'
        : 'Dynamic application security testing (DAST), OWASP API Security Top 10 compliance audits, SSRF cloud metadata defense, and RFC 7519 JWT verification.',
      accentColor: '#FF3E00',
      bgGradient: 'from-[#FF3E00]/15 via-transparent to-transparent',
      borderColor: 'group-hover:border-[#FF3E00]/40',
      icon: Route,
      primaryTab: 'apisecurity',
      tools: [
        {
          id: 'apisecurity',
          nameKey: 'tab.apisecurity',
          defaultName: 'API Security Inspector',
          descKey: 'tab.apisecurity_tooltip',
          defaultDesc: 'Auditoria de BOLA, BFLA, Broken Auth e rate limits OWASP',
          icon: Route,
          badge: 'OWASP 10',
          badgeType: 'highlight'
        },
        {
          id: 'dast',
          nameKey: 'tab.dast',
          defaultName: 'DAST Web Fuzzer',
          descKey: 'tab.dast_tooltip',
          defaultDesc: 'Injeção dinâmica de payloads defensivos e detecção de bypass',
          icon: Crosshair,
          badge: 'Fuzzer',
          badgeType: 'label'
        },
        {
          id: 'headers',
          nameKey: 'tab.headers',
          defaultName: 'Headers de Segurança',
          descKey: 'tab.headers_tooltip',
          defaultDesc: 'Auditoria de CSP, HSTS, X-Frame-Options e cabeçalhos HTTP',
          icon: Lock,
          badge: 'HTTP Sec',
          badgeType: 'label'
        },
        {
          id: 'jwtinspector',
          nameKey: 'tab.jwtinspector',
          defaultName: 'Inspetor de Tokens JWT',
          descKey: 'tab.jwtinspector_tooltip',
          defaultDesc: 'Análise de assinaturas, algoritmos fracos e claims RFC 7519',
          icon: KeyRound,
          badge: 'RFC 7519',
          badgeType: 'label'
        },
        {
          id: 'ssrfvalidator',
          nameKey: 'tab.ssrfvalidator',
          defaultName: 'Validador SSRF',
          descKey: 'tab.ssrfvalidator_tooltip',
          defaultDesc: 'Proteção contra requisições forjadas a metadados de nuvem',
          icon: Globe,
          badge: 'Cloud Meta',
          badgeType: 'label'
        }
      ]
    },
    {
      id: 'CLOUD_INFRA',
      title: language === 'pt' ? 'Nuvem, Infraestrutura & Redes' : language === 'es' ? 'Nube, Infraestructura y Redes' : 'Cloud, Infra & Network',
      subtitle: language === 'pt' ? 'IaC, Containers, Firewall L7 & Zero-Trust' : language === 'es' ? 'IaC, Contenedores, Firewall L7 y Zero-Trust' : 'IaC, Containers, L7 Firewall & Zero-Trust',
      scopeBadge: language === 'pt' ? 'Seus Manifestos IaC' : language === 'es' ? 'Sus Manifiestos IaC' : 'Your IaC Manifests',
      description: language === 'pt'
        ? 'Auditoria de manifestos Terraform e Kubernetes, verificação de Dockerfile contra padrões CIS, privilégios mínimos no Cloud IAM e simulação de arquitetura perimetral NGFW/SD-WAN.'
        : language === 'es'
        ? 'Auditoría de manifiestos Terraform y K8s, verificación Dockerfile CIS, Cloud IAM de privilegio mínimo y simulación de NGFW/SD-WAN.'
        : 'Infrastructure-as-Code audit for Terraform and Kubernetes, CIS Dockerfile hardening, least-privilege Cloud IAM, and Next-Gen Firewall simulation.',
      accentColor: '#38BDF8',
      bgGradient: 'from-[#38BDF8]/15 via-transparent to-transparent',
      borderColor: 'group-hover:border-[#38BDF8]/40',
      icon: Container,
      primaryTab: 'iac',
      tools: [
        {
          id: 'iac',
          nameKey: 'tab.iac',
          defaultName: 'IaC Terraform & K8s',
          descKey: 'tab.iac_tooltip',
          defaultDesc: 'Auditoria de manifestos Terraform, PodSecurity e K8s',
          icon: Container,
          badge: 'IaC CIS',
          badgeType: 'highlight'
        },
        {
          id: 'containerscan',
          nameKey: 'tab.containerscan',
          defaultName: 'Segurança de Containers',
          descKey: 'tab.containerscan_tooltip',
          defaultDesc: 'Análise de imagens Docker e Dockerfile rootless',
          icon: Container,
          badge: 'Docker CIS',
          badgeType: 'label'
        },
        {
          id: 'cloudiam',
          nameKey: 'tab.cloudiam',
          defaultName: 'Cloud IAM & Privilégios',
          descKey: 'tab.cloudiam_tooltip',
          defaultDesc: 'Auditoria de menor privilégio e permissões excessivas (*)',
          icon: Key,
          badge: 'IAM Least',
          badgeType: 'label'
        },
        {
          id: 'ngfw',
          nameKey: 'tab.ngfw',
          defaultName: 'Next-Gen Firewall (NGFW)',
          descKey: 'tab.ngfw_tooltip',
          defaultDesc: 'Inspeção de pacotes na camada 7 e políticas IPS defensivas',
          icon: Flame,
          badge: 'L7 / IPS',
          badgeType: 'label'
        },
        {
          id: 'idsips',
          nameKey: 'tab.idsips',
          defaultName: 'IDS/IPS Snort Engine',
          descKey: 'tab.idsips_tooltip',
          defaultDesc: 'Deep Packet Inspection e assinaturas de intrusão',
          icon: Binary,
          badge: 'DPI',
          badgeType: 'label'
        },
        {
          id: 'dnssec',
          nameKey: 'tab.dnssec',
          defaultName: 'DNS & DNSSEC',
          descKey: 'tab.dnssec_tooltip',
          defaultDesc: 'Validação de resolução criptográfica DNS e DNS over HTTPS',
          icon: Globe,
          badge: 'DoH',
          badgeType: 'label'
        },
        {
          id: 'sdwan',
          nameKey: 'tab.sdwan',
          defaultName: 'SD-WAN & SASE',
          descKey: 'tab.sdwan_tooltip',
          defaultDesc: 'Malha de túneis criptografados e arquitetura Zero-Trust',
          icon: Network,
          badge: 'Zero-Trust',
          badgeType: 'label'
        },
        {
          id: 'edr',
          nameKey: 'tab.edr',
          defaultName: 'Sensor EDR & eBPF',
          descKey: 'tab.edr_tooltip',
          defaultDesc: 'Monitoramento comportamental no kernel Linux com eBPF',
          icon: Crosshair,
          badge: 'eBPF',
          badgeType: 'label'
        }
      ]
    },
    {
      id: 'SOC_EDR',
      title: language === 'pt' ? 'SOC, Detecção & Resposta' : language === 'es' ? 'SOC, Detección y Respuesta' : 'SOC, Detection & Incident Response',
      subtitle: language === 'pt' ? 'Centro de Operações 24/7, SIEM & Threat Hunting' : language === 'es' ? 'Centro de Operaciones 24/7, SIEM y Threat Hunting' : '24/7 Command Center, SIEM & Threat Hunting',
      scopeBadge: language === 'pt' ? 'Laboratório de Resposta & SIEM' : language === 'es' ? 'Laboratorio de Respuesta' : 'Response Lab & SIEM',
      description: language === 'pt'
        ? 'Centro de comando para operações de segurança em tempo real, correlação de logs com Security Onion, telemetria CrowdStrike Falcon, regras WAF ModSecurity e varreduras de reconhecimento.'
        : language === 'es'
        ? 'Centro de comando SOC en tiempo real, correlación SIEM con Security Onion, respuesta Falcon EDR, firewall WAF y escaneos de red.'
        : 'Real-time Security Operations Center dashboard, Security Onion SIEM correlation, CrowdStrike telemetry, WAF ModSecurity engine, and network discovery.',
      accentColor: '#A78BFA',
      bgGradient: 'from-[#A78BFA]/15 via-transparent to-transparent',
      borderColor: 'group-hover:border-[#A78BFA]/40',
      icon: Radio,
      primaryTab: 'soccommand',
      tools: [
        {
          id: 'soccommand',
          nameKey: 'tab.soccommand',
          defaultName: 'SOC Command Center 24/7',
          descKey: 'tab.soccommand_tooltip',
          defaultDesc: 'Visão centralizada de alertas, telemetria e feeds em tempo real',
          icon: Radio,
          badge: 'LIVE SIEM',
          badgeType: 'highlight'
        },
        {
          id: 'securityonion',
          nameKey: 'tab.securityonion',
          defaultName: 'Security Onion NSM',
          descKey: 'tab.securityonion_tooltip',
          defaultDesc: 'Correlação de segurança de rede e telemetria Zeek/Suricata',
          icon: Layers,
          badge: 'Zeek / NSM',
          badgeType: 'label'
        },
        {
          id: 'crowdstrike',
          nameKey: 'tab.crowdstrike',
          defaultName: 'CrowdStrike Falcon IR',
          descKey: 'tab.crowdstrike_tooltip',
          defaultDesc: 'Telemetria de endpoint e fluxo de resposta a incidentes',
          icon: Zap,
          badge: 'Falcon EDR',
          badgeType: 'label'
        },
        {
          id: 'waf',
          nameKey: 'tab.waf',
          defaultName: 'WAF ModSecurity Engine',
          descKey: 'tab.waf_tooltip',
          defaultDesc: 'Regras de firewall de aplicação web contra ataques OWASP',
          icon: ShieldCheck,
          badge: 'ModSec CRS',
          badgeType: 'label'
        },
        {
          id: 'nmap',
          nameKey: 'tab.nmap',
          defaultName: 'Reconhecimento Nmap',
          descKey: 'tab.nmap_tooltip',
          defaultDesc: 'Mapeamento de portas abertas, serviços e banners de rede',
          icon: Globe,
          badge: 'Port Scan',
          badgeType: 'label'
        },
        {
          id: 'nikto',
          nameKey: 'tab.nikto',
          defaultName: 'Auditoria Web Nikto',
          descKey: 'tab.nikto_tooltip',
          defaultDesc: 'Varredura de configurações incorretas e arquivos perigosos',
          icon: FileSearch,
          badge: 'Web Audit',
          badgeType: 'label'
        }
      ]
    },
    {
      id: 'GOV_AI',
      title: language === 'pt' ? 'Governança, Threat Intel & Compliance' : language === 'es' ? 'Gobernanza, Threat Intel y Cumplimiento' : 'Governance, Threat Intel & Compliance',
      subtitle: language === 'pt' ? 'Postura Executiva, OPA Rego, SBOM & IA Segura' : language === 'es' ? 'Postura Ejecutiva, OPA Rego, SBOM e IA Segura' : 'Executive Posture, OPA Rego, SBOM & Secure AI',
      scopeBadge: language === 'pt' ? 'Conformidade & Postura' : language === 'es' ? 'Conformidad y Postura' : 'Compliance & Posture',
      description: language === 'pt'
        ? 'Painel executivo com matriz de risco e métricas de MTTR, inteligência CTI ao vivo com CISA KEV & OTX, governança declarativa com Open Policy Agent, geração SBOM e auditoria regulatória.'
        : language === 'es'
        ? 'Panel ejecutivo con matriz de riesgo y MTTR, feeds CTI en vivo (CISA KEV), gobernanza declarativa OPA Rego, SBOM y auditoría regulatoria.'
        : 'Executive risk dashboard and MTTR trends, live CTI feeds (CISA KEV & OTX), declarative Rego Policy-as-Code, SBOM generation, and regulatory compliance.',
      accentColor: '#F59E0B',
      bgGradient: 'from-[#F59E0B]/15 via-transparent to-transparent',
      borderColor: 'group-hover:border-[#F59E0B]/40',
      icon: Scale,
      primaryTab: 'dashboard',
      tools: [
        {
          id: 'dashboard',
          nameKey: 'tab.dashboard',
          defaultName: 'Dashboard Executivo',
          descKey: 'tab.dashboard_tooltip',
          defaultDesc: 'Matriz de risco, logs de auditoria e métricas executivas',
          icon: ShieldAlert,
          badge: `Score ${report.metrics.riskScore}`,
          badgeType: 'highlight'
        },
        {
          id: 'trenddashboard',
          nameKey: 'tab.trenddashboard',
          defaultName: 'Tendências & MTTR',
          descKey: 'tab.trenddashboard_tooltip',
          defaultDesc: 'Evolução histórica do Risk Score e velocidade de resolução',
          icon: TrendingDown,
          badge: 'Trends',
          badgeType: 'label'
        },
        {
          id: 'ctihub',
          nameKey: 'tab.ctihub',
          defaultName: 'CTI Threat Intel Hub',
          descKey: 'tab.ctihub_tooltip',
          defaultDesc: 'Feeds de inteligência CISA KEV, AlienVault OTX e IoCs ativos',
          icon: Globe,
          badge: 'CISA / OTX',
          badgeType: 'highlight'
        },
        {
          id: 'threatmodel',
          nameKey: 'tab.threatmodel',
          defaultName: 'Modelagem STRIDE',
          descKey: 'tab.threatmodel_tooltip',
          defaultDesc: 'Modelagem automatizada de ameaças STRIDE e árvore de mitigação',
          icon: Target,
          badge: 'STRIDE',
          badgeType: 'label'
        },
        {
          id: 'policyascode',
          nameKey: 'tab.policyascode',
          defaultName: 'Policy-as-Code (OPA)',
          descKey: 'tab.policyascode_tooltip',
          defaultDesc: 'Governança declarativa com políticas Rego e quality gates',
          icon: FileCheck,
          badge: report.opaCompliance ? `${report.opaCompliance.complianceScore}%` : 'Rego',
          badgeType: 'label'
        },
        {
          id: 'sbom',
          nameKey: 'tab.sbom',
          defaultName: 'Gerador SBOM',
          descKey: 'tab.sbom_tooltip',
          defaultDesc: 'Inventário formal Software Bill of Materials (CycloneDX e SPDX)',
          icon: FileSpreadsheet,
          badge: 'CycloneDX',
          badgeType: 'label'
        },
        {
          id: 'compliance',
          nameKey: 'tab.compliance',
          defaultName: 'Auditoria de Conformidade',
          descKey: 'tab.compliance_tooltip',
          defaultDesc: 'Auditoria de preparação para SOC 2, ISO 27001, HIPAA e PCI-DSS',
          icon: Scale,
          badge: 'SOC2 / ISO',
          badgeType: 'label'
        },
        {
          id: 'frameworks',
          nameKey: 'tab.frameworks',
          defaultName: 'Frameworks & Matriz CIS',
          descKey: 'tab.frameworks_tooltip',
          defaultDesc: 'Mapeamento contra controles NIST CSF, CIS v8 e MITRE ATT&CK',
          icon: ShieldCheck,
          badge: 'NIST / CIS',
          badgeType: 'label'
        },
        {
          id: 'asocsla',
          nameKey: 'tab.asocsla',
          defaultName: 'SLA & ASOC MTTR',
          descKey: 'tab.asocsla_tooltip',
          defaultDesc: 'Gestão de prazos de remediação e triagem de vulnerabilidades',
          icon: Clock,
          badge: 'SLA',
          badgeType: 'label'
        },
        {
          id: 'llmsecurity',
          nameKey: 'tab.llmsecurity',
          defaultName: 'OWASP LLM & IA',
          descKey: 'tab.llmsecurity_tooltip',
          defaultDesc: 'Segurança contra injeção de prompt, vazamento de dados e IA',
          icon: Cpu,
          badge: 'OWASP LLM',
          badgeType: 'label'
        },
        {
          id: 'soarbuilder',
          nameKey: 'tab.soarbuilder',
          defaultName: 'Playbooks SOAR',
          descKey: 'tab.soarbuilder_tooltip',
          defaultDesc: 'Arquiteto visual de playbooks de automação de resposta a incidentes',
          icon: Workflow,
          badge: 'Automate',
          badgeType: 'label'
        },
        {
          id: 'procyber',
          nameKey: 'tab.procyber',
          defaultName: '10 Ferramentas Pro Cyber',
          descKey: 'tab.procyber_tooltip',
          defaultDesc: 'Utilitários avançados de criptografia, hash, codificação e análise',
          icon: ShieldAlert,
          badge: '10 PRO',
          badgeType: 'label'
        },
        {
          id: 'rules',
          nameKey: 'tab.rules',
          defaultName: 'Regras Customizadas',
          descKey: 'tab.rules_tooltip',
          defaultDesc: 'Editor de expressões regulares, sandbox e testes unitários',
          icon: SlidersHorizontal,
          badge: 'Regex Lab',
          badgeType: 'label'
        },
        {
          id: 'cli',
          nameKey: 'tab.cli',
          defaultName: 'Terminal CLI',
          descKey: 'tab.cli_tooltip',
          defaultDesc: 'Linha de comando interativa para automação de scans',
          icon: Terminal,
          badge: 'CLI',
          badgeType: 'label'
        },
        {
          id: 'pipelineflow',
          nameKey: 'tab.pipelineflow',
          defaultName: 'Pipeline Flow DevSecOps',
          descKey: 'tab.pipelineflow_tooltip',
          defaultDesc: 'Diagrama visual de esteira de integração e gates de segurança',
          icon: Workflow,
          badge: 'DevSecOps',
          badgeType: 'label'
        },
        {
          id: 'cicd',
          nameKey: 'tab.cicd',
          defaultName: 'Integrações CI/CD',
          descKey: 'tab.cicd_tooltip',
          defaultDesc: 'Templates de automação para GitHub Actions, GitLab CI e Azure',
          icon: CloudCog,
          badge: 'Actions',
          badgeType: 'label'
        }
      ]
    }
  ], [language, report]);

  // Filter modules and tools based on search term AND testing context
  const filteredModules = useMemo(() => {
    const q = searchTerm.toLowerCase().trim();

    return MODULES.map(module => {
      const titleMatch = q ? (module.title.toLowerCase().includes(q) || module.description.toLowerCase().includes(q)) : false;
      const matchingTools = module.tools.filter(tool => {
        // 1. Context Filter check
        if (contextFilter !== 'ALL' && getToolContextScope(tool.id) !== contextFilter) {
          return false;
        }

        // 2. Search query check
        if (!q) return true;
        const label = t(tool.nameKey) || tool.defaultName;
        const desc = t(tool.descKey) || tool.defaultDesc;
        const badge = typeof tool.badge === 'string' ? tool.badge.toLowerCase() : '';
        return (
          label.toLowerCase().includes(q) ||
          desc.toLowerCase().includes(q) ||
          tool.id.toLowerCase().includes(q) ||
          badge.includes(q) ||
          titleMatch
        );
      });

      if (matchingTools.length > 0) {
        return {
          ...module,
          tools: matchingTools
        };
      }
      return null;
    }).filter(Boolean) as ModuleDefinition[];
  }, [MODULES, searchTerm, contextFilter, t]);

  const myCodeCount = useMemo(() => {
    return MODULES.reduce((acc, m) => acc + m.tools.filter(t => getToolContextScope(t.id) === 'MY_CODE').length, 0);
  }, [MODULES]);

  const sandboxCount = useMemo(() => {
    return MODULES.reduce((acc, m) => acc + m.tools.filter(t => getToolContextScope(t.id) === 'SANDBOX').length, 0);
  }, [MODULES]);

  const govCount = useMemo(() => {
    return MODULES.reduce((acc, m) => acc + m.tools.filter(t => getToolContextScope(t.id) === 'GOV_POSTURE').length, 0);
  }, [MODULES]);

  const totalToolsCount = useMemo(() => {
    return MODULES.reduce((acc, m) => acc + m.tools.length, 0);
  }, [MODULES]);

  return (
    <div className="w-full flex-1 bg-[#060608] text-white selection:bg-[#FF3E00] selection:text-white pb-24">
      {/* Apple-style subtle ambient glow background */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden opacity-30 z-0">
        <div className="absolute -top-[20%] left-1/2 -translate-x-1/2 w-[900px] h-[500px] bg-gradient-to-b from-[#00F0FF]/10 via-[#FF3E00]/5 to-transparent blur-[140px] rounded-full" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-8 sm:pt-12">
        {/* Apple-Style Minimalist Workspace Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 pb-8 border-b border-white/[0.08]">
          <div className="space-y-2.5 max-w-2xl">
            {/* Anti-Slop Unboxed Kicker */}
            <div className="flex items-center gap-2 text-xs font-mono font-bold tracking-widest text-[#00F0FF] uppercase">
              <span className="w-2 h-2 rounded-full bg-[#00F0FF] shadow-[0_0_8px_#00F0FF] animate-pulse" />
              <span>{language === 'pt' ? 'Workspace Operacional' : language === 'es' ? 'Espacio de Trabajo Operativo' : 'Operational Workspace'}</span>
              <span className="text-zinc-600">·</span>
              <span className="text-zinc-400 font-normal">{language === 'pt' ? '5 Módulos Especializados' : language === 'es' ? '5 Módulos Especializados' : '5 Specialized Modules'}</span>
            </div>

            <h1 className="text-3xl sm:text-4xl lg:text-5xl font-black text-white tracking-tight uppercase font-sans">
              {language === 'pt' ? 'Central de Módulos' : language === 'es' ? 'Centro de Módulos' : 'Modules Hub'}
            </h1>

            <p className="text-sm sm:text-base text-zinc-400 leading-relaxed font-sans">
              {language === 'pt' 
                ? 'Arquitetura organizada por domínio de cibersegurança. Selecione um módulo especializado para executar análises aprofundadas, gerenciar controles e visualizar defesas.'
                : language === 'es'
                ? 'Arquitectura organizada por dominio de ciberseguridad. Seleccione un módulo especializado para ejecutar análisis y gestionar controles con enfoque total.'
                : 'Clean domain-driven cybersecurity architecture. Select a dedicated module to run deep scans, inspect vulnerabilities, and orchestrate defenses.'}
            </p>
          </div>

          {/* Quick Actions & Overview Controls */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            {/* Run Full Scan */}
            <button
              id="hub-btn-run-full-scan"
              onClick={onRunScan}
              disabled={isScanning}
              className={`relative overflow-hidden h-10 px-4 rounded-xl inline-flex items-center gap-2.5 font-mono text-xs font-bold uppercase tracking-wider transition-all shadow-[0_0_20px_rgba(255,62,0,0.25)] ${
                isScanning
                  ? 'bg-zinc-950/90 text-zinc-100 border border-[#00F0FF]/50 shadow-[0_0_25px_rgba(0,240,255,0.25)] cursor-wait select-none'
                  : 'bg-gradient-to-r from-[#FF3E00] via-[#FF551C] to-[#E03700] hover:from-[#FF551C] hover:to-[#FF3E00] text-white border border-[#FF3E00]/80 hover:shadow-[0_0_30px_rgba(255,62,0,0.55)] cursor-pointer active:scale-95 group'
              }`}
              title={
                isScanning
                  ? (scanProgress ? `Progresso: ${scanProgress.percentage}% - ${scanProgress.phaseLabel || 'Analisando...'}` : 'Varredura em andamento...')
                  : (language === 'pt' ? 'Executar varredura completa de todos os módulos' : language === 'es' ? 'Ejecutar escaneo completo de todos los módulos' : 'Run full scan across all modules')
              }
            >
              {isScanning && (
                <>
                  {/* Real-time fluid progress bar fill */}
                  <span
                    className="absolute inset-0 bg-gradient-to-r from-[#00F0FF]/20 via-[#FF3E00]/25 to-[#00F0FF]/25 transition-all duration-300 ease-out pointer-events-none"
                    style={{ width: `${Math.min(100, Math.max(4, scanProgress?.percentage ?? 0))}%` }}
                  />
                  {/* Crisp bottom neon track indicator */}
                  <span
                    className="absolute bottom-0 left-0 h-[2px] bg-gradient-to-r from-[#00F0FF] via-[#FF3E00] to-[#00F0FF] transition-all duration-300 ease-out shadow-[0_0_8px_#00F0FF] pointer-events-none"
                    style={{ width: `${Math.min(100, Math.max(4, scanProgress?.percentage ?? 0))}%` }}
                  />
                </>
              )}

              <span className="relative z-10 flex items-center gap-2">
                {isScanning ? (
                  <Loader2 className="w-3.5 h-3.5 text-[#00F0FF] animate-spin shrink-0" />
                ) : (
                  <Play className="w-3.5 h-3.5 fill-current text-white group-hover:scale-110 transition-transform shrink-0" />
                )}

                <span>
                  {isScanning 
                    ? (scanProgress ? `Escaneando (${scanProgress.percentage}%)` : 'Escaneando...') 
                    : (language === 'pt' ? 'Scan Completo' : language === 'es' ? 'Escaneo Total' : 'Run Full Scan')}
                </span>

                {isScanning && scanProgress?.percentage === 100 && (
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399] animate-ping" />
                )}

                {!isScanning && (
                  <span className="hidden sm:inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_#34d399]" />
                )}
              </span>
            </button>

            {/* Jump to Executive Dashboard */}
            <button
              id="hub-btn-view-dashboard"
              onClick={() => onNavigateToTab('dashboard')}
              className="h-10 px-4 rounded-xl inline-flex items-center gap-2 font-mono text-xs font-bold uppercase tracking-wider bg-white/[0.05] hover:bg-white/[0.1] text-zinc-200 hover:text-white border border-white/[0.1] hover:border-white/[0.25] transition-all cursor-pointer"
              title="Abrir o Dashboard Executivo com métricas consolidadas"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-[#FF3E00]" />
              <span>{language === 'pt' ? 'Dashboard' : 'Dashboard'}</span>
            </button>

            {/* Export Report */}
            {onOpenExport && (
              <button
                id="hub-btn-export-report"
                onClick={onOpenExport}
                className="h-10 px-3.5 rounded-xl inline-flex items-center gap-1.5 font-mono text-xs font-bold uppercase tracking-wider bg-white/[0.05] hover:bg-white/[0.1] text-zinc-300 hover:text-white border border-white/[0.1] transition-all cursor-pointer"
                title="Exportar Relatório Consolidado"
              >
                <Download className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">{language === 'pt' ? 'Exportar' : 'Export'}</span>
              </button>
            )}

            {/* Quick Tour */}
            {onOpenTour && (
              <button
                id="hub-btn-open-tour"
                onClick={onOpenTour}
                className="h-10 px-3 rounded-xl inline-flex items-center justify-center text-zinc-400 hover:text-white bg-white/[0.05] hover:bg-white/[0.1] border border-white/[0.1] transition-all cursor-pointer"
                title="Tutorial Completo da Plataforma"
              >
                <Compass className="w-4 h-4 text-[#00F0FF]" />
              </button>
            )}
          </div>
        </div>

        {/* Apple Spotlight-style Quick Search & Live Filter Bar */}
        <div className="pt-6 pb-8">
          <div className="relative max-w-2xl">
            <Search className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 text-zinc-400 pointer-events-none" />
            <input
              id="hub-tool-search-input"
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder={
                language === 'pt' 
                  ? 'Buscar entre as 44 ferramentas (ex: SAST, OWASP, Docker, SIEM, Rego)...'
                  : language === 'es'
                  ? 'Buscar entre las 44 herramientas (ej: SAST, OWASP, Docker, SIEM)...'
                  : 'Search across all 44 tools (e.g., SAST, OWASP, Docker, SIEM, Rego)...'
              }
              className="w-full h-12 pl-11 pr-24 rounded-2xl bg-white/[0.04] hover:bg-white/[0.06] focus:bg-white/[0.08] border border-white/[0.1] focus:border-[#00F0FF]/60 text-sm font-sans text-white placeholder-zinc-500 focus:outline-none transition-all shadow-inner backdrop-blur-md"
            />
            {searchTerm ? (
              <button
                onClick={() => setSearchTerm('')}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-xs font-mono text-zinc-400 hover:text-white bg-white/10 px-2 py-1 rounded-md cursor-pointer transition-colors"
              >
                {language === 'pt' ? 'Limpar' : 'Clear'}
              </button>
            ) : (
              <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-1.5 pointer-events-none">
                <kbd className="px-2 py-0.5 rounded bg-white/[0.06] border border-white/[0.1] text-[10px] font-mono text-zinc-400">
                  {typeof navigator !== 'undefined' && /Mac|iPad|iPhone/.test(navigator.userAgent) ? '⌘K' : 'Ctrl+K'}
                </kbd>
              </div>
            )}
          </div>

          {/* Quick Metrics Bar (Clean Unboxed Typography) */}
          <div className="flex flex-wrap items-center gap-4 sm:gap-6 mt-4 text-xs font-mono text-zinc-400">
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${isHealthy ? 'bg-[#00FF41]' : 'bg-[#FF3E00] animate-pulse'}`} />
              <span className="text-zinc-500">{language === 'pt' ? 'Postura:' : 'Posture:'}</span>
              <span className={isHealthy ? 'text-[#00FF41] font-bold' : 'text-[#FF3E00] font-bold'}>
                {isHealthy 
                  ? (language === 'pt' ? 'Protegido (0 críticos)' : 'Healthy (0 critical)') 
                  : `${criticalCount} ${language === 'pt' ? 'crítico(s)' : 'critical'}`}
              </span>
            </div>

            <span className="text-zinc-700">·</span>

            <div>
              <span className="text-zinc-500">{language === 'pt' ? 'Score de Risco:' : 'Risk Score:'} </span>
              <span className="text-white font-bold">{report.metrics.riskScore}</span>
              <span className="text-zinc-600"> / 100</span>
            </div>

            <span className="text-zinc-700">·</span>

            <div>
              <span className="text-zinc-500">{language === 'pt' ? 'Arquivos no Workspace:' : 'Files Scanned:'} </span>
              <span className="text-white font-bold">{files.length}</span>
            </div>

            <span className="text-zinc-700">·</span>

            <div>
              <span className="text-zinc-500">{language === 'pt' ? 'Ferramentas Integradas:' : 'Total Tools:'} </span>
              <span className="text-[#00F0FF] font-bold">{totalToolsCount}</span>
            </div>
          </div>
        </div>

        {/* Guia de Contextos de Teste (Transparência Total: O que é do Seu Repositório vs Laboratório) */}
        <div className="mb-6 p-4 sm:p-5 rounded-2xl bg-[#09090E]/90 border border-white/[0.08] backdrop-blur-md shadow-lg space-y-4">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="flex items-start sm:items-center gap-3">
              <span className={`w-3 h-3 rounded-full shrink-0 mt-1 sm:mt-0 ${files.length > 0 ? 'bg-[#00F0FF] shadow-[0_0_10px_#00F0FF] animate-pulse' : 'bg-[#00FF41] shadow-[0_0_10px_#00FF41]'}`} />
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs sm:text-sm font-bold text-white font-mono uppercase tracking-wider">
                    {files.length > 0 
                      ? `Workspace Ativo: ${files.length} arquivo(s) real(is) analisado(s)`
                      : 'Workspace Limpo: 0 arquivos (Pronto para Ingestão)'}
                  </span>
                  <span className={`text-[9.5px] font-mono px-2 py-0.5 rounded font-bold uppercase ${files.length > 0 ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-700/60' : 'bg-emerald-950/80 text-emerald-300 border border-emerald-700/60'}`}>
                    {files.length > 0 ? 'Inspeção do Seu Código' : '100% Zerado · Zero Mock'}
                  </span>
                </div>
                <p className="text-xs text-zinc-400 mt-1">
                  {files.length > 0 
                    ? 'SAST, IAST em Runtime, Segredos por Entropia e Rotas LinkFinder são extraídos estritamente dos seus arquivos carregados.' 
                    : 'A plataforma está operando em modo real e limpo. Nenhuma vulnerabilidade falsa ou mockada é gerada.'}
                </p>
              </div>
            </div>

            {/* Quick Filter Buttons by Testing Context */}
            <div className="flex items-center gap-2 shrink-0 text-xs font-mono flex-wrap">
              <span className="text-zinc-500 text-[11px] hidden sm:inline">Filtrar por Contexto:</span>
              <button
                type="button"
                onClick={() => setContextFilter('ALL')}
                className={`px-3 py-1.5 rounded-lg border font-bold transition-all cursor-pointer ${
                  contextFilter === 'ALL'
                    ? 'bg-white/15 text-white border-white/30 shadow-xs'
                    : 'bg-white/[0.03] text-zinc-400 border-white/[0.08] hover:text-white hover:bg-white/[0.07]'
                }`}
              >
                Todas ({totalToolsCount})
              </button>

              <button
                type="button"
                onClick={() => setContextFilter('MY_CODE')}
                className={`px-3 py-1.5 rounded-lg border font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                  contextFilter === 'MY_CODE'
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-[0_0_12px_rgba(6,182,212,0.25)]'
                    : 'bg-cyan-950/30 text-cyan-400/80 border-cyan-800/40 hover:bg-cyan-950/60 hover:text-cyan-200'
                }`}
                title="Mostrar apenas ferramentas que analisam diretamente o seu código fonte e dependências"
              >
                <span>📁 Meu Código Real ({myCodeCount})</span>
              </button>

              <button
                type="button"
                onClick={() => setContextFilter('SANDBOX')}
                className={`px-3 py-1.5 rounded-lg border font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                  contextFilter === 'SANDBOX'
                    ? 'bg-purple-500/20 text-purple-300 border-purple-500/50 shadow-[0_0_12px_rgba(168,85,247,0.25)]'
                    : 'bg-purple-950/30 text-purple-400/80 border-purple-800/40 hover:bg-purple-950/60 hover:text-purple-200'
                }`}
                title="Mostrar apenas utilitários de teste ativo e sandboxes de simulação"
              >
                <span>🧪 Sandboxes de Teste ({sandboxCount})</span>
              </button>

              <button
                type="button"
                onClick={() => setContextFilter('GOV_POSTURE')}
                className={`px-3 py-1.5 rounded-lg border font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                  contextFilter === 'GOV_POSTURE'
                    ? 'bg-amber-500/20 text-amber-300 border-amber-500/50 shadow-[0_0_12px_rgba(245,158,11,0.25)]'
                    : 'bg-amber-950/30 text-amber-400/80 border-amber-800/40 hover:bg-amber-950/60 hover:text-amber-200'
                }`}
                title="Mostrar painéis executivos, métricas, conformidade e modelagem de ameaças"
              >
                <span>📋 Governança &amp; Postura ({govCount})</span>
              </button>
            </div>
          </div>

          {/* Context Helper Hint Banner when filtered */}
          {contextFilter !== 'ALL' && (
            <div className="pt-2 border-t border-white/[0.06] flex items-center justify-between text-xs font-mono text-zinc-400">
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                <span>
                  {contextFilter === 'MY_CODE' && 'Exibindo apenas ferramentas de análise direta do seu código (SAST, Taint, Endpoints, IAST, SCA, Segredos e IaC). 0 dados sintéticos.'}
                  {contextFilter === 'SANDBOX' && 'Exibindo ferramentas utilitárias e simuladores de teste interativo (DAST, JWT, SSRF, Headers, Firewall L7, IDS, Nmap, Nikto, SOC).'}
                  {contextFilter === 'GOV_POSTURE' && 'Exibindo módulos de governança, conformidade regulatória (SOC2/ISO), políticas OPA Rego, SBOM e matriz de risco.'}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setContextFilter('ALL')}
                className="text-zinc-400 hover:text-white underline cursor-pointer shrink-0 ml-3"
              >
                Ver todas ({totalToolsCount})
              </button>
            </div>
          )}
        </div>

        {/* 5 Modular Domain Cards Grid (Apple Bento Layout) */}
        {filteredModules.length === 0 ? (
          <div className="p-12 text-center rounded-2xl bg-white/[0.02] border border-white/[0.08] space-y-4">
            <Search className="w-8 h-8 text-zinc-500 mx-auto" />
            <h3 className="text-lg font-bold text-white">
              {language === 'pt' ? 'Nenhuma ferramenta encontrada' : 'No tools matched your search'}
            </h3>
            <p className="text-xs text-zinc-400 max-w-md mx-auto">
              {language === 'pt'
                ? `Não encontramos resultados para "${searchTerm}". Tente pesquisar por termos como SAST, OWASP, Docker, SIEM ou CVE.`
                : `No results found for "${searchTerm}". Try searching for terms like SAST, OWASP, Docker, SIEM, or CVE.`}
            </p>
            <button
              onClick={() => setSearchTerm('')}
              className="px-4 py-2 rounded-xl bg-white/10 hover:bg-white/20 text-white font-mono text-xs uppercase tracking-wider cursor-pointer"
            >
              {language === 'pt' ? 'Limpar Busca' : 'Clear Search'}
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 lg:gap-8">
            {filteredModules.map((module, index) => {
              const Icon = module.icon;
              // Make Governance card span full width on large screens to display its rich tool suite
              const isFullWidth = module.id === 'GOV_AI' && filteredModules.length % 2 !== 0;

              return (
                <div
                  key={module.id}
                  id={`hub-module-card-${module.id.toLowerCase()}`}
                  className={`group relative rounded-3xl bg-[#0B0B10]/90 hover:bg-[#0E0E16]/95 border border-white/[0.08] hover:border-white/[0.18] shadow-[0_20px_50px_rgba(0,0,0,0.5)] transition-all duration-300 p-6 sm:p-8 flex flex-col justify-between overflow-hidden ${
                    isFullWidth ? 'lg:col-span-2' : ''
                  }`}
                >
                  {/* Subtle Apple-style accent gradient glow at top corner */}
                  <div 
                    className={`absolute -top-24 -right-24 w-64 h-64 rounded-full blur-[80px] pointer-events-none opacity-20 transition-opacity duration-300 group-hover:opacity-40`}
                    style={{ backgroundColor: module.accentColor }}
                  />

                  {/* Card Content Top */}
                  <div className="space-y-5">
                    {/* Module Header Bar */}
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-center gap-3.5">
                        {/* Apple Squircle Icon Box */}
                        <div 
                          className="w-12 h-12 rounded-2xl flex items-center justify-center shrink-0 border shadow-inner transition-transform duration-300 group-hover:scale-105"
                          style={{ 
                            backgroundColor: `${module.accentColor}15`, 
                            borderColor: `${module.accentColor}35`,
                            color: module.accentColor 
                          }}
                        >
                          <Icon className="w-6 h-6" />
                        </div>

                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <h2 className="text-xl sm:text-2xl font-black text-white tracking-tight uppercase font-sans">
                              {module.title}
                            </h2>
                            <span 
                              className="text-[9.5px] font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider border shadow-sm"
                              style={{ 
                                backgroundColor: `${module.accentColor}18`, 
                                borderColor: `${module.accentColor}40`,
                                color: module.accentColor 
                              }}
                            >
                              {module.scopeBadge}
                            </span>
                          </div>
                          <div className="text-xs font-mono text-zinc-400 mt-0.5">
                            {module.subtitle}
                          </div>
                        </div>
                      </div>

                      {/* Tool count unboxed */}
                      <div className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider shrink-0 hidden sm:block">
                        <span className="font-bold text-white">{module.tools.length}</span> {language === 'pt' ? 'ferramentas' : 'tools'}
                      </div>
                    </div>

                    {/* Module Description */}
                    <p className="text-xs sm:text-sm text-zinc-300/80 leading-relaxed font-sans">
                      {module.description}
                    </p>

                    {/* Tools Grid inside this Module */}
                    <div className="pt-2">
                      <div className="text-[10.5px] font-mono uppercase font-bold tracking-wider text-zinc-400 mb-2.5 flex items-center gap-2">
                        <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: module.accentColor }} />
                        <span>{language === 'pt' ? 'Ferramentas do Módulo:' : 'Module Tools:'}</span>
                      </div>

                      <div className={`grid gap-2 ${isFullWidth ? 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-4' : 'grid-cols-1 sm:grid-cols-2'}`}>
                        {module.tools.map((tool) => {
                          const ToolIcon = tool.icon;
                          const toolLabel = t(tool.nameKey) || tool.defaultName;
                          const toolTooltip = t(tool.descKey) || tool.defaultDesc;

                          return (
                            <button
                              key={tool.id}
                              id={`hub-tool-btn-${tool.id}`}
                              onClick={() => onNavigateToTab(tool.id)}
                              title={toolTooltip}
                              className="group/tool flex items-center justify-between p-2.5 rounded-xl bg-white/[0.02] hover:bg-white/[0.07] border border-white/[0.05] hover:border-white/[0.15] text-left transition-all cursor-pointer"
                            >
                              <div className="flex items-center gap-2.5 min-w-0 pr-2">
                                <ToolIcon className="w-4 h-4 text-zinc-400 group-hover/tool:text-white transition-colors shrink-0" />
                                <span className="text-xs font-mono font-medium text-zinc-300 group-hover/tool:text-white truncate">
                                  {toolLabel}
                                </span>
                              </div>

                              <div className="flex items-center gap-1.5 shrink-0">
                                {(() => {
                                  const toolScope = getToolContextScope(tool.id);
                                  return (
                                    <span 
                                      className={`text-[8px] font-mono px-1.5 py-0.2 rounded font-bold uppercase hidden sm:inline ${
                                        toolScope === 'MY_CODE' ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-800/40' :
                                        toolScope === 'SANDBOX' ? 'bg-purple-950/70 text-purple-300 border border-purple-800/40' :
                                        'bg-amber-950/70 text-amber-300 border border-amber-800/40'
                                      }`}
                                      title={
                                        toolScope === 'MY_CODE' ? 'Analisa diretamente o código do seu workspace' :
                                        toolScope === 'SANDBOX' ? 'Sandbox e utilitário de teste dinâmico' :
                                        'Módulo executivo de governança e postura'
                                      }
                                    >
                                      {toolScope === 'MY_CODE' ? 'Código' : toolScope === 'SANDBOX' ? 'Sandbox' : 'Postura'}
                                    </span>
                                  );
                                })()}
                                {tool.badge !== undefined && (
                                  <span 
                                    className={`text-[9.5px] font-mono px-1.5 py-0.2 rounded font-bold ${
                                      tool.badgeType === 'count'
                                        ? 'bg-rose-950/80 text-rose-300 border border-rose-800/50'
                                        : tool.badgeType === 'highlight'
                                        ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-700/50'
                                        : 'bg-white/[0.06] text-zinc-400 border border-white/[0.08]'
                                    }`}
                                  >
                                    {tool.badge}
                                  </span>
                                )}
                                <ChevronRight className="w-3.5 h-3.5 text-zinc-600 group-hover/tool:text-white group-hover/tool:translate-x-0.5 transition-all" />
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  </div>

                  {/* Card Footer / Primary CTA */}
                  <div className="pt-6 mt-6 border-t border-white/[0.06] flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
                    <div className="text-[11px] font-mono text-zinc-400 flex items-center gap-2">
                      <span className="text-zinc-600">#</span>
                      <span>
                        {language === 'pt' 
                          ? `${module.tools.length} recursos especializados integrados`
                          : `${module.tools.length} integrated specialized tools`}
                      </span>
                    </div>

                    <button
                      id={`hub-btn-open-module-${module.id.toLowerCase()}`}
                      onClick={() => onNavigateToTab(module.primaryTab)}
                      className="px-5 py-2.5 rounded-xl font-mono text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition-all cursor-pointer group/cta border shadow-sm"
                      style={{
                        backgroundColor: `${module.accentColor}18`,
                        borderColor: `${module.accentColor}40`,
                        color: module.accentColor
                      }}
                    >
                      <span>
                        {language === 'pt'
                          ? `Acessar Módulo`
                          : language === 'es'
                          ? `Entrar al Módulo`
                          : `Enter Module`}
                      </span>
                      <ArrowRight className="w-3.5 h-3.5 group-hover/cta:translate-x-1 transition-transform" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Apple-style Bottom Philosophy & System Status Strip */}
        <div className="mt-16 pt-8 border-t border-white/[0.08] flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-zinc-400">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#00FF41]" />
            <span className="text-zinc-400">
              {language === 'pt' 
                ? 'SecScan AppSec Engine · Análise Estática & Dinâmica Unificada' 
                : 'SecScan AppSec Engine · Unified Static & Dynamic Analysis'}
            </span>
          </div>

          <div className="flex items-center gap-4 text-[11px] text-zinc-400">
            <button
              onClick={() => onNavigateToTab('dashboard')}
              className="hover:text-white transition-colors cursor-pointer"
            >
              Dashboard Executivo
            </button>
            <span>·</span>
            <button
              onClick={() => onNavigateToTab('rules')}
              className="hover:text-white transition-colors cursor-pointer"
            >
              Regras Customizadas
            </button>
            <span>·</span>
            <button
              onClick={() => onNavigateToTab('compliance')}
              className="hover:text-white transition-colors cursor-pointer"
            >
              Compliance SOC2/ISO
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
