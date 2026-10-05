import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  FileCode2, 
  Container, 
  Route, 
  Radio, 
  Layers, 
  ArrowRight, 
  Lock, 
  Terminal, 
  CheckCircle2, 
  Zap, 
  Cpu, 
  Activity, 
  FileCheck, 
  Network, 
  Crosshair, 
  Workflow, 
  ChevronRight, 
  Play, 
  HelpCircle, 
  Binary, 
  Scale, 
  Key, 
  RefreshCw, 
  FileText, 
  AlertTriangle,
  Flame,
  Search,
  BookOpen,
  Boxes,
  Code2,
  Database,
  Globe,
  Loader2
} from 'lucide-react';
import { useLanguage } from '../lib/i18nContext';
import { LanguageSwitcher } from './LanguageSwitcher';
import { ScannedFile } from '../types';

interface LandingPageProps {
  onEnterApp: (loadDemoData?: boolean) => void;
  onOpenUrlIngest?: () => void;
  onIngestUrlFiles?: (files: ScannedFile[], targetUrl: string) => void;
}

export const LandingPage: React.FC<LandingPageProps> = ({ 
  onEnterApp,
  onOpenUrlIngest,
  onIngestUrlFiles
}) => {
  const { language } = useLanguage();
  const [activeDomainTab, setActiveDomainTab] = useState<'sast' | 'iac' | 'dast' | 'soc' | 'gov'>('sast');
  const [openFaqIndex, setOpenFaqIndex] = useState<number | null>(0);
  const [heroUrlInput, setHeroUrlInput] = useState('');
  const [isHeroLoading, setIsHeroLoading] = useState(false);
  const [heroError, setHeroError] = useState<string | null>(null);

  const handleHeroUrlSubmit = async (customUrl?: string) => {
    const rawUrl = customUrl || heroUrlInput;
    if (!rawUrl || !rawUrl.trim()) return;

    let targetUrl = rawUrl.trim();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'https://' + targetUrl;
    }

    setIsHeroLoading(true);
    setHeroError(null);

    try {
      const res = await fetch('/api/url-ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl })
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Falha ao auditar URL.');
      }

      setIsHeroLoading(false);
      if (onIngestUrlFiles) {
        onIngestUrlFiles(data.files, targetUrl);
      } else {
        onEnterApp(false);
      }
    } catch (err: any) {
      setIsHeroLoading(false);
      setHeroError(err.message || 'Não foi possível conectar ao host.');
    }
  };

  // Content localized for PT, EN, and ES
  const content = {
    pt: {
      badge: "PLATAFORMA ENTERPRISE DE DEVSECOPS & APPSEC INTELLIGENCE · CLIENT-SIDE & ZERO-LEAK",
      heroTitle: "Segurança Cibernética Total: Do Código ao SOC em Tempo Real",
      heroSub: "O SecScan AppSec Suite unifica mais de 30 módulos especializados de cibersegurança em uma única interface ultrarrápida: análise estática (SAST) com fluxo de dados D3, caçador de segredos por Entropia de Shannon, CTI Hub com feeds CISA KEV & AlienVault OTX, auditoria de Cloud IaC, DAST fuzzer e auto-remediação com 1 clique.",
      ctaPrimary: "Acessar Plataforma SecOps",
      ctaSecondary: "Explorar com Workspace Demo",
      stats: [
        { label: "Módulos Especializados", value: "30+" },
        { label: "Privacidade Garantida", value: "100% Client-Side" },
        { label: "Frameworks de Compliance", value: "6 Padrões Globais" },
        { label: "Tempo Médio de Varredura", value: "<250ms" },
      ],
      interactiveTitle: "Conheça os 5 Pilares de Defesa do SecScan",
      interactiveSub: "Selecione um domínio abaixo para visualizar capacidades em ação antes de entrar no sistema:",
      domains: {
        sast: {
          name: "SAST & Análise de Código",
          tag: "Varredura Estática & Fluxo de Dados",
          desc: "Identificação profunda de vulnerabilidades com 45+ regras heurísticas, rastreamento de tainted data de ponta a ponta e cálculo de entropia criptográfica.",
          features: [
            "Grafo D3 de fluxo de dados não confiáveis (Source → Sanitizer → Sink)",
            "Caçador de chaves de API e segredos via Entropia de Shannon no Git",
            "Assistente de Refatoração de Código Seguro com comparação visual de diff",
            "Suporte nativo para TypeScript, JavaScript, Python, Go, Java, PHP e C#"
          ],
          codeTitle: "scanner_engine.ts · Taint Analysis & Shannon Entropy",
          codeSnippet: `// [SecScan Engine] Análise Taint detectada em /api/query.ts:
const userInput = req.query.target; // [SOURCE] Parâmetro não confiável
const rawQuery = \`SELECT * FROM users WHERE id = '\${userInput}'\`; // [TAINTED SINK]
// Regra Violada: SEC-SQLI-001 (High / CVSS 8.6)
// Remediação 1-Clique: Aplicar parametrização segura Prepared Statement`
        },
        iac: {
          name: "Cloud & Infraestrutura (IaC)",
          tag: "Hardening de Nuvem & Contêineres",
          desc: "Audite previamente manifestos Terraform, configurações do Kubernetes e Dockerfiles antes que cheguem a ambientes de produção.",
          features: [
            "Auditoria de PodSecurityStandards, privilégios root e capabilities Linux no K8s",
            "Detecção de configurações inseguras de IAM e buckets abertos em Terraform",
            "Auditoria preventiva de arquivo .gitignore para evitar vazamento acidental de .env",
            "Inspeção de camadas Dockerfile com recomendações CIS Benchmark"
          ],
          codeTitle: "k8s_deployment.yaml · Misconfiguration Check",
          codeSnippet: `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: payment-api
        securityContext:
          privileged: true # ❌ CRITICAL: Container rodando em modo privilegiado!
          readOnlyRootFilesystem: false # ⚠️ WARNING: Sistema de arquivos não é somente-leitura
          runAsNonRoot: false # ❌ HIGH: Executando como usuário root UID 0`
        },
        dast: {
          name: "API Security & DAST Fuzzer",
          tag: "Testes Dinâmicos & Superfície de Ataque",
          desc: "Descubra rotas ocultas em bundles minificados, execute fuzzing controlado e inspecione tokens de autenticação.",
          features: [
            "JS Miner: extração automática de endpoints REST, GraphQL e rotas internas",
            "Fuzzer DAST em tempo real com injeção de payloads para SQLi, NoSQLi e XSS",
            "Inspetor de tokens JWT: detecção de algoritmo 'none' e expirações forjadas",
            "Validador de SSRF e auditor de cabeçalhos de segurança HTTP (CSP, HSTS)"
          ],
          codeTitle: "jwt_inspector.ts · Token Security Audit",
          codeSnippet: `// [JWT Security Inspector] Análise de cabeçalho e payload:
{
  "alg": "none", // 🚨 ALERTA CRÍTICO: Algoritmo 'none' aceito sem verificação de assinatura!
  "typ": "JWT"
}
// Impacto: Qualquer ator malicioso pode forjar identidades administrativas
// Remediação: Forçar verificação criptográfica com RS256 ou HS256 com chave forte`
        },
        soc: {
          name: "Cyber Threat Intel (CTI) & SOC",
          tag: "Inteligência contra Ameaças & SOAR",
          desc: "Centro de operações unificado com feeds ao vivo da CISA KEV e AlienVault OTX, correlação com grupos APT e playbooks automatizados.",
          features: [
            "Feeds em tempo real da CISA KEV (Known Exploited Vulnerabilities)",
            "Atribuição e etiquetagem com Threat Actors (Scattered Spider, Lazarus, Fancy Bear)",
            "Playbooks SOAR visuais interativos para orquestração de resposta a incidentes",
            "Simulador de telemetria integrada com Security Onion SIEM e CrowdStrike EDR"
          ],
          codeTitle: "threat_intel_feed.json · CISA KEV & AlienVault OTX",
          codeSnippet: `[
  {
    "cveID": "CVE-2024-3400",
    "vendorProject": "Palo Alto Networks",
    "product": "PAN-OS GlobalProtect Gateway",
    "vulnerabilityName": "Command Injection Vulnerability",
    "threatActor": "Scattered Spider (UNC3886)",
    "dateAdded": "2024-04-12",
    "knownRansomwareUse": "Known Active Exploit",
    "remediationAction": "Aplicar hotfix imediatamente conforme diretiva CISA BOD 22-01"
  }
]`
        },
        gov: {
          name: "Governança, OPA & Compliance",
          tag: "Policy-as-Code & Auditoria Executiva",
          desc: "Garanta conformidade contínua com regras Rego avaliadas no cliente, geração de SBOM e relatórios para SOC 2, ISO 27001 e HIPAA.",
          features: [
            "Motor Policy-as-Code Open Policy Agent (OPA) com execução nativa de Rego",
            "Gerador de Software Bill of Materials (SBOM) nos padrões CycloneDX e SPDX",
            "Auditoria automatizada com 6 frameworks globais (SOC 2, ISO 27001, HIPAA, PCI-DSS)",
            "Métricas ASOC de MTTR dinâmico e estimativa de esforço de remediação"
          ],
          codeTitle: "secscan_policy.rego · Open Policy Agent",
          codeSnippet: `package secscan.compliance

# Violação se existirem achados críticos não remediados em branches principais
default allow = false

allow {
    count(critical_findings) == 0
    count(unencrypted_secrets) == 0
}

critical_findings[f] {
    f := input.findings[_]
    f.severity == "CRITICAL"
}`
        }
      },
      pipelineTitle: "Arquitetura DevSecOps: Do Commit ao SOC",
      pipelineSub: "O SecScan cobre todo o ciclo de vida de desenvolvimento seguro sem exigir configurações complexas:",
      pipelineSteps: [
        {
          step: "01",
          title: "Pre-Commit & Validação Local",
          desc: "Verificação pré-voo no navegador, detecção de arquivos sensíveis (.env, chaves privadas) e auditoria de .gitignore."
        },
        {
          step: "02",
          title: "Análise Estática & SBOM",
          desc: "Varredura profunda com 45+ regras SAST, grafo D3 de fluxo de dados, árvore de dependências e regras OPA Rego."
        },
        {
          step: "03",
          title: "Testes Dinâmicos & APIs",
          desc: "Mineração de endpoints em arquivos JS/TS, fuzzer de injeção, verificação de cabeçalhos de segurança e SSRF."
        },
        {
          step: "04",
          title: "Hardening de Nuvem & IaC",
          desc: "Auditoria de manifestos Kubernetes, arquivos Terraform, configurações Dockerfile e privilégios mínimos no Cloud IAM."
        },
        {
          step: "05",
          title: "Threat Intel & Telemetria SOC",
          desc: "Correlação automática com feeds CISA KEV e AlienVault OTX, simulação EDR e execução de playbooks SOAR."
        }
      ],
      privacyTitle: "Privacidade Absoluta e Zero Exfiltração de Dados",
      privacySub: "Por que empresas e times de engenharia confiam no SecScan para auditar seus repositórios mais confidenciais:",
      privacyCards: [
        {
          title: "Processamento 100% no Navegador",
          desc: "Nenhum arquivo, trecho de código ou segredo é enviado para a nuvem. Todo o motor de análise roda localmente no seu computador através da V8 Engine do navegador."
        },
        {
          title: "Zero Instalação ou Dependências",
          desc: "Sem necessidade de `npm install`, sem instalar daemons do Docker ou criar contas de nuvem. Basta abrir a plataforma e iniciar a inspeção de segurança instantaneamente."
        },
        {
          title: "Exportações Padrão da Indústria",
          desc: "Exporte relatórios completos em formato SARIF (compatível com GitHub Advanced Security), JSON estruturado para pipelines de CI/CD, CSV e resumos executivos."
        }
      ],
      faqTitle: "Perguntas Frequentes sobre o SecScan",
      faqList: [
        {
          q: "O que é o SecScan AppSec Suite?",
          a: "É uma suíte completa e integrada de cibersegurança que combina análise de código estático (SAST), análise dinâmica (DAST), inteligência contra ameaças cibernéticas (CTI), auditoria de infraestrutura como código (IaC) e governança com Policy-as-Code em uma única plataforma."
        },
        {
          q: "Meus arquivos ou códigos são enviados para algum servidor?",
          a: "Não. O SecScan foi construído com arquitetura Privacy-First e Zero-Exfiltration. Toda a leitura de arquivos, execução de expressões regulares, cálculo de entropia e avaliação de políticas Rego ocorrem exclusivamente dentro do navegador na sua máquina local."
        },
        {
          q: "Como posso testar o sistema se não tiver arquivos agora?",
          a: "Você pode clicar no botão 'Explorar com Workspace Demo' logo acima. O sistema carregará automaticamente arquivos de amostra com vulnerabilidades comuns intencionais (SQL Injection, chaves AWS expostas, Dockerfile inseguro) para você explorar todos os recursos e relatórios."
        },
        {
          q: "Quais formatos de exportação são suportados?",
          a: "O SecScan suporta exportação em formato padrão SARIF v2.1.0 (Static Analysis Results Interchange Format, compatível com GitHub Security Tab), JSON completo, CSV para planilhas e relatórios executivos em texto/PDF."
        },
        {
          q: "O que é o CTI Hub integrado com CISA KEV e AlienVault?",
          a: "É um módulo de inteligência de ameaças cibernéticas que monitora vulnerabilidades ativamente exploradas no mundo real (Known Exploited Vulnerabilities) e correlaciona automaticamente achados com grupos de cibercriminosos conhecidos, como Lazarus, Scattered Spider e APT28."
        }
      ],
      ctaBannerTitle: "Pronto para proteger seus sistemas com o SecScan?",
      ctaBannerSub: "Acesse o sistema completo com um clique. Explore o dashboard com métricas ao vivo, gerencie seus arquivos e execute varreduras instantâneas.",
      btnEnterHome: "Ir para a Home do App",
      btnEnterDemo: "Carregar com Projeto Demo",
      footerTagline: "SecScan AppSec Enterprise Suite · Plataforma Avançada de Cibersegurança e Inteligência de Ameaças",
      navFeatures: "Recursos",
      navArchitecture: "Arquitetura",
      navDomains: "Domínios SecOps",
      navFaq: "FAQ",
      navLaunch: "Acessar Sistema"
    },
    en: {
      badge: "ENTERPRISE DEVSECOPS & APPSEC INTELLIGENCE PLATFORM · CLIENT-SIDE & ZERO-LEAK",
      heroTitle: "Total Cybersecurity Defense: From Source Code to SOC in Real-Time",
      heroSub: "SecScan AppSec Suite brings together over 30 specialized cybersecurity modules in a single high-performance interface: static analysis (SAST) with D3 data flow, Shannon entropy secret hunter, CTI Hub with live CISA KEV & AlienVault OTX feeds, Cloud IaC audit, DAST fuzzer, and 1-click automated remediation.",
      ctaPrimary: "Launch SecOps Platform",
      ctaSecondary: "Explore with Demo Workspace",
      stats: [
        { label: "Specialized Modules", value: "30+" },
        { label: "Guaranteed Privacy", value: "100% Client-Side" },
        { label: "Compliance Frameworks", value: "6 Global Standards" },
        { label: "Average Scan Time", value: "<250ms" },
      ],
      interactiveTitle: "Discover SecScan's 5 Defense Pillars",
      interactiveSub: "Select a security domain below to preview its live capabilities before launching the system:",
      domains: {
        sast: {
          name: "SAST & Code Security",
          tag: "Static Scanning & Data Flow",
          desc: "In-depth vulnerability identification using 45+ heuristic rules, end-to-end untrusted tainted data tracing, and cryptographic Shannon entropy calculation.",
          features: [
            "D3 untrusted data flow graph (Source → Sanitizer → Sink)",
            "Git Shannon entropy hunter for exposed API keys and credentials",
            "Security Refactoring Assistant with modern side-by-side diff previews",
            "Native support for TypeScript, JavaScript, Python, Go, Java, PHP, and C#"
          ],
          codeTitle: "scanner_engine.ts · Taint Analysis & Shannon Entropy",
          codeSnippet: `// [SecScan Engine] Taint Analysis detected in /api/query.ts:
const userInput = req.query.target; // [SOURCE] Untrusted user parameter
const rawQuery = \`SELECT * FROM users WHERE id = '\${userInput}'\`; // [TAINTED SINK]
// Violated Rule: SEC-SQLI-001 (High / CVSS 8.6)
// 1-Click Remediation: Apply secure parameterized Prepared Statement`
        },
        iac: {
          name: "Cloud & Infrastructure (IaC)",
          tag: "Cloud Hardening & Containers",
          desc: "Pre-audit Terraform manifests, Kubernetes configurations, and Dockerfiles before they reach production clusters.",
          features: [
            "Audit PodSecurityStandards, root privileges, and Linux capabilities in K8s",
            "Detect insecure IAM policies and open storage buckets in Terraform",
            "Preventive .gitignore auditing to prevent accidental .env and key commits",
            "Dockerfile layer inspection with CIS Benchmark recommendations"
          ],
          codeTitle: "k8s_deployment.yaml · Misconfiguration Check",
          codeSnippet: `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: payment-api
        securityContext:
          privileged: true # ❌ CRITICAL: Container running in privileged mode!
          readOnlyRootFilesystem: false # ⚠️ WARNING: Root filesystem is not read-only
          runAsNonRoot: false # ❌ HIGH: Running as root UID 0`
        },
        dast: {
          name: "API Security & DAST Fuzzer",
          tag: "Dynamic Testing & Attack Surface",
          desc: "Discover hidden routes in minified JS bundles, run targeted fuzzing, and inspect authentication tokens.",
          features: [
            "JS Miner: automated extraction of REST, GraphQL, and internal endpoints",
            "Real-time DAST fuzzer with payload injection for SQLi, NoSQLi, and XSS",
            "JWT token inspector: detect 'none' algorithm bypass and forged expirations",
            "SSRF validator and HTTP security headers auditor (CSP, HSTS, X-Frame)"
          ],
          codeTitle: "jwt_inspector.ts · Token Security Audit",
          codeSnippet: `// [JWT Security Inspector] Header & payload inspection:
{
  "alg": "none", // 🚨 CRITICAL ALERT: 'none' algorithm accepted without signature verification!
  "typ": "JWT"
}
// Impact: Any malicious attacker can forge administrative privileges
// Remediation: Enforce cryptographic verification with RS256 or strong HS256`
        },
        soc: {
          name: "Cyber Threat Intel (CTI) & SOC",
          tag: "Threat Intelligence & SOAR",
          desc: "Unified SecOps center with live feeds from CISA KEV and AlienVault OTX, APT threat actor correlation, and automated response playbooks.",
          features: [
            "Real-time CISA KEV (Known Exploited Vulnerabilities) threat feeds",
            "Attribution and tagging for global Threat Actors (Scattered Spider, Lazarus)",
            "Visual interactive SOAR playbooks for orchestrated incident response",
            "Telemetry simulator integrating Security Onion SIEM and CrowdStrike EDR"
          ],
          codeTitle: "threat_intel_feed.json · CISA KEV & AlienVault OTX",
          codeSnippet: `[
  {
    "cveID": "CVE-2024-3400",
    "vendorProject": "Palo Alto Networks",
    "product": "PAN-OS GlobalProtect Gateway",
    "vulnerabilityName": "Command Injection Vulnerability",
    "threatActor": "Scattered Spider (UNC3886)",
    "dateAdded": "2024-04-12",
    "knownRansomwareUse": "Known Active Exploit",
    "remediationAction": "Apply emergency hotfix immediately per CISA BOD 22-01"
  }
]`
        },
        gov: {
          name: "Governance, OPA & Compliance",
          tag: "Policy-as-Code & Executive Audits",
          desc: "Ensure continuous compliance with Rego policies evaluated in the browser, automated SBOM generation, and audits for SOC 2, ISO 27001, and HIPAA.",
          features: [
            "Open Policy Agent (OPA) Policy-as-Code engine with native Rego evaluation",
            "Software Bill of Materials (SBOM) generator in CycloneDX and SPDX standards",
            "Automated audit across 6 global frameworks (SOC 2, ISO 27001, HIPAA, PCI-DSS)",
            "ASOC dynamic MTTR metrics and calculated remediation effort"
          ],
          codeTitle: "secscan_policy.rego · Open Policy Agent",
          codeSnippet: `package secscan.compliance

# Violation if unresolved critical findings exist in target branch
default allow = false

allow {
    count(critical_findings) == 0
    count(unencrypted_secrets) == 0
}

critical_findings[f] {
    f := input.findings[_]
    f.severity == "CRITICAL"
}`
        }
      },
      pipelineTitle: "DevSecOps Architecture: From Commit to SOC",
      pipelineSub: "SecScan secures the entire software delivery pipeline without complicated setups:",
      pipelineSteps: [
        {
          step: "01",
          title: "Pre-Commit & Local Checks",
          desc: "In-browser pre-flight checks, sensitive file detection (.env, private keys), and .gitignore audit."
        },
        {
          step: "02",
          title: "Static Analysis & SBOM",
          desc: "Deep scan with 45+ SAST rules, D3 data flow graph, dependency tree, and OPA Rego policies."
        },
        {
          step: "03",
          title: "Dynamic Testing & APIs",
          desc: "Endpoint mining in JS/TS bundles, injection fuzzer, security headers, and SSRF verification."
        },
        {
          step: "04",
          title: "Cloud & IaC Hardening",
          desc: "Kubernetes manifests audit, Terraform files, Dockerfile settings, and Cloud IAM least privilege."
        },
        {
          step: "05",
          title: "Threat Intel & SOC Telemetry",
          desc: "Real-time CISA KEV feeds, threat actor correlation, EDR simulation, and SOAR playbooks."
        }
      ],
      privacyTitle: "Absolute Privacy and Zero Data Exfiltration",
      privacySub: "Why engineering and security teams trust SecScan to audit their most confidential source code:",
      privacyCards: [
        {
          title: "100% In-Browser Execution",
          desc: "No code files, snippets, or tokens are ever sent to external cloud servers. The entire analysis engine runs locally on your machine via the browser's V8 engine."
        },
        {
          title: "Zero Installation & Dependencies",
          desc: "No `npm install` needed, no Docker daemons to start, and no cloud access keys required. Simply launch the app and start scanning immediately."
        },
        {
          title: "Industry Standard Exports",
          desc: "Export comprehensive reports in standard SARIF v2.1.0 format (GitHub Security Tab compatible), structured JSON for CI/CD, CSV, and executive summaries."
        }
      ],
      faqTitle: "Frequently Asked Questions",
      faqList: [
        {
          q: "What is SecScan AppSec Suite?",
          a: "It is a unified cybersecurity platform combining static analysis (SAST), dynamic testing (DAST), cyber threat intelligence (CTI), infrastructure-as-code (IaC) audit, and Policy-as-Code governance into a single cohesive interface."
        },
        {
          q: "Are my files or code sent to any remote server?",
          a: "Never. SecScan is architected from the ground up with a Privacy-First, Zero-Exfiltration model. All parsing, regular expressions, entropy calculations, and Rego policies run strictly inside your local browser."
        },
        {
          q: "How can I try the platform if I don't have files right now?",
          a: "Click the 'Explore with Demo Workspace' button above. The system will automatically load sample files containing intentional real-world vulnerabilities so you can explore all dashboards, graphs, and reports immediately."
        },
        {
          q: "Which export formats are supported?",
          a: "SecScan supports exports in industry-standard SARIF v2.1.0 (compatible with GitHub Advanced Security), complete JSON, CSV for spreadsheets, and executive reports."
        },
        {
          q: "How does the CTI Hub with CISA KEV and AlienVault work?",
          a: "It is a threat intelligence module that tracks active real-world exploited vulnerabilities and automatically correlates discovered weaknesses with known threat actors like Lazarus, Scattered Spider, and APT28."
        }
      ],
      ctaBannerTitle: "Ready to secure your workspace and pipelines?",
      ctaBannerSub: "Access the full platform with a single click. Explore live metrics on the dashboard, manage workspace files, and run instant security audits.",
      btnEnterHome: "Go to System Home",
      btnEnterDemo: "Launch with Demo Project",
      footerTagline: "SecScan AppSec Enterprise Suite · Advanced Application Security & Threat Intelligence",
      navFeatures: "Features",
      navArchitecture: "Architecture",
      navDomains: "SecOps Domains",
      navFaq: "FAQ",
      navLaunch: "Launch App"
    },
    es: {
      badge: "PLATAFORMA ENTERPRISE DE DEVSECOPS & APPSEC INTELLIGENCE · CLIENT-SIDE & ZERO-LEAK",
      heroTitle: "Ciberseguridad Total: Del Código Fuente al SOC en Tiempo Real",
      heroSub: "SecScan AppSec Suite unifica más de 30 módulos especializados de ciberseguridad en una única interfaz de alto rendimiento: análisis estático (SAST) con flujo de datos D3, cazador de secretos por Entropía de Shannon, CTI Hub con feeds en vivo CISA KEV y AlienVault OTX, auditoría Cloud IaC, fuzzer DAST y autorremediación con 1 clic.",
      ctaPrimary: "Acceder a la Plataforma SecOps",
      ctaSecondary: "Explorar con Workspace Demo",
      stats: [
        { label: "Módulos Especializados", value: "30+" },
        { label: "Privacidad Garantizada", value: "100% Client-Side" },
        { label: "Marcos de Cumplimiento", value: "6 Estándares Globales" },
        { label: "Tiempo Medio de Análisis", value: "<250ms" },
      ],
      interactiveTitle: "Conozca los 5 Pilares de Defensa de SecScan",
      interactiveSub: "Seleccione un dominio a continuación para visualizar sus capacidades antes de ingresar al sistema:",
      domains: {
        sast: {
          name: "SAST & Seguridad de Código",
          tag: "Escaneo Estático & Flujo de Datos",
          desc: "Identificación profunda de vulnerabilidades con más de 45 reglas heurísticas, seguimiento de datos no confiables y cálculo de entropía criptográfica.",
          features: [
            "Grafo D3 de flujo de datos no confiables (Source → Sanitizer → Sink)",
            "Cazador de secretos y claves de API por Entropía de Shannon en Git",
            "Asistente de Refactorización de Código Seguro con diff visual comparativo",
            "Soporte nativo para TypeScript, JavaScript, Python, Go, Java, PHP y C#"
          ],
          codeTitle: "scanner_engine.ts · Taint Analysis & Shannon Entropy",
          codeSnippet: `// [SecScan Engine] Análisis Taint detectado en /api/query.ts:
const userInput = req.query.target; // [SOURCE] Parámetro no confiable
const rawQuery = \`SELECT * FROM users WHERE id = '\${userInput}'\`; // [TAINTED SINK]
// Regla Violada: SEC-SQLI-001 (Alta / CVSS 8.6)
// Remediación 1-Clic: Aplicar Prepared Statement parametrizado`
        },
        iac: {
          name: "Cloud & Infraestructura (IaC)",
          tag: "Hardening de Nube & Contenedores",
          desc: "Audite previamente manifiestos Terraform, configuraciones de Kubernetes y Dockerfiles antes de que lleguen a producción.",
          features: [
            "Auditoría de PodSecurityStandards, privilegios root y capabilities Linux en K8s",
            "Detección de políticas IAM inseguras y buckets abiertos en Terraform",
            "Auditoría preventiva de .gitignore para evitar fuga de .env o claves privadas",
            "Inspección de capas Dockerfile con recomendaciones CIS Benchmark"
          ],
          codeTitle: "k8s_deployment.yaml · Misconfiguration Check",
          codeSnippet: `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: payment-api
        securityContext:
          privileged: true # ❌ CRITICAL: ¡Contenedor en modo privilegiado!
          readOnlyRootFilesystem: false # ⚠️ WARNING: Sistema de archivos no es de solo lectura
          runAsNonRoot: false # ❌ HIGH: Ejecutándose como root UID 0`
        },
        dast: {
          name: "API Security & DAST Fuzzer",
          tag: "Pruebas Dinámicas & Superficie de Ataque",
          desc: "Descubra rutas ocultas en bundles minificados, ejecute fuzzing controlado e inspeccione tokens de autenticación.",
          features: [
            "JS Miner: extracción automática de endpoints REST, GraphQL y rutas internas",
            "Fuzzer DAST en tiempo real con inyección de payloads para SQLi, NoSQLi y XSS",
            "Inspector de tokens JWT: detección de algoritmo 'none' y expiración falsificada",
            "Validador de SSRF y auditor de encabezados de seguridad HTTP (CSP, HSTS)"
          ],
          codeTitle: "jwt_inspector.ts · Token Security Audit",
          codeSnippet: `// [JWT Security Inspector] Inspección de encabezado y payload:
{
  "alg": "none", // 🚨 ALERTA CRÍTICA: ¡Algoritmo 'none' aceptado sin verificar firma!
  "typ": "JWT"
}
// Impacto: Cualquier atacante puede falsificar identidades administrativas
// Remediación: Forzar verificación criptográfica con RS256 o HS256 robusto`
        },
        soc: {
          name: "Cyber Threat Intel (CTI) & SOC",
          tag: "Inteligencia contra Amenazas & SOAR",
          desc: "Centro de operaciones unificado con feeds en vivo de CISA KEV y AlienVault OTX, correlación de actores APT y playbooks automatizados.",
          features: [
            "Feeds en tiempo real de CISA KEV (Known Exploited Vulnerabilities)",
            "Atribución y etiquetado con Threat Actors (Scattered Spider, Lazarus, APT28)",
            "Playbooks SOAR interactivos para orquestación de respuesta a incidentes",
            "Simulador de telemetría integrado con Security Onion SIEM y CrowdStrike EDR"
          ],
          codeTitle: "threat_intel_feed.json · CISA KEV & AlienVault OTX",
          codeSnippet: `[
  {
    "cveID": "CVE-2024-3400",
    "vendorProject": "Palo Alto Networks",
    "product": "PAN-OS GlobalProtect Gateway",
    "vulnerabilityName": "Command Injection Vulnerability",
    "threatActor": "Scattered Spider (UNC3886)",
    "dateAdded": "2024-04-12",
    "knownRansomwareUse": "Known Active Exploit",
    "remediationAction": "Aplicar hotfix inmediatamente según directiva CISA BOD 22-01"
  }
]`
        },
        gov: {
          name: "Gobernanza, OPA & Compliance",
          tag: "Policy-as-Code & Auditoría Ejecutiva",
          desc: "Garantice cumplimiento continuo con políticas Rego en el navegador, generación de SBOM y auditorías para SOC 2, ISO 27001 e HIPAA.",
          features: [
            "Motor Policy-as-Code Open Policy Agent (OPA) con ejecución nativa de Rego",
            "Generador de Software Bill of Materials (SBOM) en estándares CycloneDX y SPDX",
            "Auditoría automatizada con 6 marcos globales (SOC 2, ISO 27001, HIPAA, PCI-DSS)",
            "Métricas ASOC de MTTR dinámico y cálculo de esfuerzo de remediación"
          ],
          codeTitle: "secscan_policy.rego · Open Policy Agent",
          codeSnippet: `package secscan.compliance

# Violación si existen hallazgos críticos sin resolver en la rama de destino
default allow = false

allow {
    count(critical_findings) == 0
    count(unencrypted_secrets) == 0
}

critical_findings[f] {
    f := input.findings[_]
    f.severity == "CRITICAL"
}`
        }
      },
      pipelineTitle: "Arquitectura DevSecOps: Del Commit al SOC",
      pipelineSub: "SecScan protege todo el ciclo de entrega de software sin configuraciones complejas:",
      pipelineSteps: [
        {
          step: "01",
          title: "Pre-Commit & Validación Local",
          desc: "Verificación previa en el navegador, detección de archivos sensibles (.env, claves privadas) y auditoría de .gitignore."
        },
        {
          step: "02",
          title: "Análisis Estático & SBOM",
          desc: "Escaneo profundo con más de 45 reglas SAST, grafo D3 de flujo de datos, árbol de dependencias y políticas OPA Rego."
        },
        {
          step: "03",
          title: "Pruebas Dinámicas & APIs",
          desc: "Minería de endpoints en paquetes JS/TS, fuzzer de inyección, encabezados de seguridad y verificación de SSRF."
        },
        {
          step: "04",
          title: "Hardening de Nube & IaC",
          desc: "Auditoría de manifiestos Kubernetes, archivos Terraform, configuraciones Dockerfile y privilegios mínimos en Cloud IAM."
        },
        {
          step: "05",
          title: "Threat Intel & Telemetría SOC",
          desc: "Feeds CISA KEV en vivo, correlación de threat actors, simulación EDR y ejecución de playbooks SOAR."
        }
      ],
      privacyTitle: "Privacidad Absoluta y Cero Exfiltración de Datos",
      privacySub: "Por qué equipos de ingeniería y seguridad confían en SecScan para auditar su código más confidencial:",
      privacyCards: [
        {
          title: "Ejecución 100% en el Navegador",
          desc: "Ningún archivo, fragmento de código o secreto se envía a servidores en la nube. Todo el motor corre localmente en su máquina con el motor V8 del navegador."
        },
        {
          title: "Cero Instalación o Dependencias",
          desc: "Sin necesidad de `npm install`, sin daemons de Docker ni cuentas en la nube requeridas. Abra la aplicación y comience a analizar al instante."
        },
        {
          title: "Exportaciones Estándar de la Industria",
          desc: "Exporte informes completos en formato SARIF v2.1.0 (compatible con GitHub Security Tab), JSON estructurado para CI/CD, CSV y resúmenes ejecutivos."
        }
      ],
      faqTitle: "Preguntas Frecuentes",
      faqList: [
        {
          q: "¿Qué es SecScan AppSec Suite?",
          a: "Es una suite completa de ciberseguridad que combina análisis de código estático (SAST), dinámico (DAST), inteligencia de amenazas (CTI), auditoría de infraestructura (IaC) y gobernanza Policy-as-Code en una sola plataforma."
        },
        {
          q: "¿Mis archivos o código se envían a algún servidor remoto?",
          a: "Nunca. SecScan fue concebido bajo el principio Privacy-First y Zero-Exfiltration. Todo el procesamiento se realiza exclusivamente en su navegador local."
        },
        {
          q: "¿Cómo puedo probar el sistema si no tengo archivos ahora?",
          a: "Haga clic en 'Explorar con Workspace Demo' arriba. El sistema cargará automáticamente archivos de muestra con vulnerabilidades intencionales para que explore todos los módulos y gráficos."
        },
        {
          q: "¿Qué formatos de exportación son compatibles?",
          a: "SecScan admite exportaciones en formato estándar SARIF v2.1.0 (compatible con GitHub Advanced Security), JSON completo, CSV para hojas de cálculo e informes ejecutivos."
        },
        {
          q: "¿Cómo funciona el CTI Hub con CISA KEV y AlienVault?",
          a: "Es un módulo de inteligencia de amenazas que rastrea vulnerabilidades explotadas activamente en el mundo real y correlaciona automáticamente los hallazgos con actores maliciosos conocidos como Lazarus o Scattered Spider."
        }
      ],
      ctaBannerTitle: "¿Listo para proteger sus sistemas con SecScan?",
      ctaBannerSub: "Acceda al sistema completo con un solo clic. Explore el panel de control con métricas en tiempo real, gestione archivos y ejecute análisis instantáneos.",
      btnEnterHome: "Ir a la Home del Sistema",
      btnEnterDemo: "Iniciar con Proyecto Demo",
      footerTagline: "SecScan AppSec Enterprise Suite · Plataforma Avanzada de Ciberseguridad e Inteligencia de Amenazas",
      navFeatures: "Recursos",
      navArchitecture: "Arquitectura",
      navDomains: "Dominios SecOps",
      navFaq: "FAQ",
      navLaunch: "Acceder al Sistema"
    }
  };

  const t = content[language as 'pt' | 'en' | 'es'] || content.pt;
  const currentDomain = t.domains[activeDomainTab];

  return (
    <div data-no-translate="true" className="min-h-screen bg-[#050505] text-[#E0E0E0] font-sans selection:bg-[#FF3E00] selection:text-white flex flex-col relative overflow-x-hidden">
      {/* Background cyber grid & glow effects */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#121214_1px,transparent_1px),linear-gradient(to_bottom,#121214_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none opacity-40" />
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[350px] bg-gradient-to-b from-[#FF3E00]/10 via-[#FF7A00]/5 to-transparent blur-3xl pointer-events-none" />

      {/* Top Navbar */}
      <header className="sticky top-0 z-50 bg-[#070709]/90 backdrop-blur-md border-b border-[#1A1A1E]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-b from-[#1C1C1C] to-[#0A0A0A] border border-[#333] rounded-lg flex items-center justify-center text-[#FF3E00] shadow-[0_0_15px_rgba(255,62,0,0.2)] relative">
              <ShieldAlert className="w-5 h-5 text-[#FF3E00]" />
              <span className="absolute -top-1 -right-1 flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00FF41] opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[#00FF41]" />
              </span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-black text-xl tracking-tight text-white uppercase">SECSCAN</span>
                <span className="text-[#FF3E00] font-black tracking-tight text-xl uppercase">APPSEC</span>
                <span className="px-1.5 py-0.2 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 text-[10px] font-mono font-bold tracking-wider">v2.5</span>
              </div>
              <p className="text-[10.5px] font-mono text-zinc-400 hidden sm:block">Enterprise DevSecOps & CTI Platform</p>
            </div>
          </div>

          {/* Nav links */}
          <nav className="hidden md:flex items-center gap-6 text-xs font-mono uppercase tracking-wider text-zinc-400">
            <a href="#features" className="hover:text-white transition-colors">{t.navFeatures}</a>
            <a href="#domains" className="hover:text-white transition-colors">{t.navDomains}</a>
            <a href="#pipeline" className="hover:text-white transition-colors">{t.navArchitecture}</a>
            <a href="#faq" className="hover:text-white transition-colors">{t.navFaq}</a>
          </nav>

          {/* Right actions: Language switcher + Enter button */}
          <div className="flex items-center gap-3">
            <LanguageSwitcher />

            {onOpenUrlIngest && (
              <button
                id="landing-btn-nav-audit-url"
                onClick={onOpenUrlIngest}
                className="hidden sm:inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#00F0FF]/10 hover:bg-[#00F0FF]/20 text-[#00F0FF] border border-[#00F0FF]/30 font-mono text-xs font-bold uppercase tracking-wider transition-colors cursor-pointer"
                title="Auditar website ou API pública via link direto"
              >
                <Globe className="w-3.5 h-3.5 text-[#00F0FF]" />
                <span>Auditar URL</span>
              </button>
            )}
            
            <button
              id="landing-btn-enter-app-nav"
              onClick={() => onEnterApp(false)}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#FF3E00] hover:bg-[#E03700] text-white font-mono text-xs font-bold uppercase tracking-wider shadow-[0_0_20px_rgba(255,62,0,0.35)] transition-all cursor-pointer hover:scale-[1.02] active:scale-[0.98]"
            >
              <span>{t.navLaunch}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative pt-12 pb-16 md:pt-20 md:pb-24 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex-1 flex flex-col justify-center">
        <div className="max-w-4xl mx-auto text-center space-y-6">
          {/* Unboxed Metadata Kicker (Anti-slop compliant) */}
          <div className="inline-flex items-center gap-2 text-xs font-mono font-semibold tracking-widest text-[#FF3E00] uppercase">
            <span className="w-2 h-2 rounded-full bg-[#FF3E00] animate-pulse" />
            <span>{t.badge}</span>
          </div>

          {/* Main Headline */}
          <h1 className="text-3xl sm:text-5xl md:text-6xl font-black text-white tracking-tight leading-[1.1] uppercase">
            {t.heroTitle.includes(':') ? (
              <>
                <span>{t.heroTitle.split(':')[0]}: </span>
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#FF3E00] via-[#FF7A00] to-[#00F0FF]">
                  {t.heroTitle.split(':')[1].trim()}
                </span>
              </>
            ) : (
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#FF3E00] via-[#FF7A00] to-[#00F0FF]">
                {t.heroTitle}
              </span>
            )}
          </h1>

          {/* Subtitle */}
          <p className="text-sm sm:text-base md:text-lg text-zinc-300 leading-relaxed max-w-3xl mx-auto">
            {t.heroSub}
          </p>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
            <button
              id="landing-hero-cta-primary"
              onClick={() => onEnterApp(false)}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2.5 px-7 py-3.5 rounded-lg bg-gradient-to-r from-[#FF3E00] to-[#FF5500] hover:from-[#E03700] hover:to-[#E04400] text-white font-mono text-sm font-bold uppercase tracking-wider shadow-[0_0_30px_rgba(255,62,0,0.4)] transition-all cursor-pointer hover:scale-[1.03] active:scale-[0.98]"
            >
              <ShieldCheck className="w-5 h-5 text-white" />
              <span>{t.ctaPrimary}</span>
              <ArrowRight className="w-4 h-4 ml-1" />
            </button>

            <button
              id="landing-hero-cta-secondary"
              onClick={() => onEnterApp(true)}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-lg bg-[#141418] hover:bg-[#1E1E24] text-zinc-200 hover:text-white border border-[#2E2E38] hover:border-[#FF3E00]/60 font-mono text-xs font-semibold uppercase tracking-wider transition-all cursor-pointer shadow-sm"
              title="Carregar workspace pronto com arquivos de teste e vulnerabilidades de exemplo"
            >
              <Play className="w-4 h-4 text-[#00FF41]" />
              <span>{t.ctaSecondary}</span>
            </button>
          </div>

          {/* Direct URL Audit Ingestion Bar */}
          <div className="pt-2 max-w-xl mx-auto w-full">
            <div className="p-2 rounded-xl bg-[#0B0B12] border border-[#232332] focus-within:border-[#00F0FF] shadow-lg flex flex-col sm:flex-row items-center gap-2 transition-all">
              <div className="relative flex-1 w-full">
                <Globe className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="url"
                  value={heroUrlInput}
                  onChange={(e) => setHeroUrlInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleHeroUrlSubmit();
                  }}
                  placeholder="Ou audite via link (ex: https://meusite.com)"
                  disabled={isHeroLoading}
                  className="w-full pl-9 pr-3 py-2 bg-transparent text-xs text-white placeholder-zinc-500 font-mono focus:outline-none disabled:opacity-50"
                />
              </div>
              <button
                id="landing-btn-hero-audit-url"
                onClick={() => handleHeroUrlSubmit()}
                disabled={isHeroLoading || !heroUrlInput.trim()}
                className="w-full sm:w-auto px-4 py-2 rounded-lg bg-[#00F0FF]/15 hover:bg-[#00F0FF]/25 text-[#00F0FF] border border-[#00F0FF]/40 hover:border-[#00F0FF] font-mono text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 transition-all cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
              >
                {isHeroLoading ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Auditando...</span>
                  </>
                ) : (
                  <>
                    <span>Auditar Link</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </>
                )}
              </button>
            </div>
            {heroError && (
              <div className="mt-2 text-rose-400 text-[11px] font-mono flex items-center justify-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                <span>{heroError}</span>
              </div>
            )}
          </div>

          {/* Clean Unboxed Metadata Strip (Zero-Pill Discipline) */}
          <div className="pt-8 flex flex-wrap items-center justify-center gap-y-3 gap-x-6 text-xs font-mono text-zinc-400">
            {t.stats.map((stat, i) => (
              <React.Fragment key={stat.label}>
                {i > 0 && <span className="text-zinc-600 hidden sm:inline" aria-hidden="true">·</span>}
                <div className="flex items-center gap-1.5">
                  <span className="font-bold text-white tracking-tight">{stat.value}</span>
                  <span className="text-zinc-400">{stat.label}</span>
                </div>
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* Live Interactive Preview Terminal (Interactive Domain Explorer) */}
        <div id="domains" className="mt-14 max-w-5xl mx-auto w-full">
          <div className="rounded-xl bg-[#09090C] border border-[#22222A] overflow-hidden shadow-[0_10px_40px_rgba(0,0,0,0.8)]">
            {/* Terminal Top Bar */}
            <div className="bg-[#121217] px-4 py-3 border-b border-[#22222A] flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
                <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
                <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
                <span className="ml-2 font-mono text-xs text-zinc-400 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-[#FF3E00]" />
                  <span>SecScan Interactive Domain Matrix</span>
                </span>
              </div>

              {/* Domain Switcher Buttons */}
              <div className="flex items-center gap-1 bg-[#060608] p-1 rounded-lg border border-[#22222A] overflow-x-auto max-w-full">
                {(['sast', 'iac', 'dast', 'soc', 'gov'] as const).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveDomainTab(tab)}
                    className={`px-2.5 py-1 rounded text-xs font-mono font-medium transition-all cursor-pointer whitespace-nowrap ${
                      activeDomainTab === tab
                        ? 'bg-[#FF3E00] text-white shadow-xs'
                        : 'text-zinc-400 hover:text-white hover:bg-white/5'
                    }`}
                  >
                    {tab === 'sast' ? 'SAST' : tab === 'iac' ? 'Cloud & IaC' : tab === 'dast' ? 'API & DAST' : tab === 'soc' ? 'CTI & SOC' : 'OPA & Rego'}
                  </button>
                ))}
              </div>
            </div>

            {/* Terminal Body Content */}
            <div className="p-5 sm:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left Column: Domain info */}
              <div className="lg:col-span-5 space-y-4 flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-2 text-xs font-mono text-[#00F0FF]">
                    <Activity className="w-3.5 h-3.5" />
                    <span>{currentDomain.tag}</span>
                  </div>
                  <h3 className="text-xl font-bold text-white mt-1">
                    {currentDomain.name}
                  </h3>
                  <p className="text-xs text-zinc-300 leading-relaxed mt-2">
                    {currentDomain.desc}
                  </p>
                </div>

                <div className="space-y-2 pt-2 border-t border-[#1C1C24]">
                  {currentDomain.features.map((feat, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-xs text-zinc-300">
                      <CheckCircle2 className="w-3.5 h-3.5 text-[#00FF41] shrink-0 mt-0.5" />
                      <span>{feat}</span>
                    </div>
                  ))}
                </div>

                <button
                  onClick={() => onEnterApp(true)}
                  className="mt-4 w-full py-2.5 px-4 rounded bg-[#1A1A22] hover:bg-[#252532] text-white border border-[#333344] hover:border-[#FF3E00]/60 font-mono text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition-all cursor-pointer"
                >
                  <span>Abrir Este Módulo no App</span>
                  <ChevronRight className="w-4 h-4 text-[#FF3E00]" />
                </button>
              </div>

              {/* Right Column: Code & Telemetry Preview */}
              <div className="lg:col-span-7 bg-[#050507] rounded-lg border border-[#1F1F28] p-4 flex flex-col justify-between overflow-hidden">
                <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400 pb-2 border-b border-[#181822]">
                  <span className="flex items-center gap-1.5 text-zinc-300">
                    <FileCode2 className="w-3.5 h-3.5 text-[#FF3E00]" />
                    <span>{currentDomain.codeTitle}</span>
                  </span>
                  <span className="text-[10px] text-[#00FF41]">● REAL-TIME ENGINE</span>
                </div>

                <pre className="font-mono text-xs text-zinc-300 overflow-x-auto p-3 bg-black/40 rounded my-3 border border-white/5 leading-relaxed selection:bg-[#FF3E00]">
                  <code>{currentDomain.codeSnippet}</code>
                </pre>

                <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400 pt-2 border-t border-[#181822]">
                  <span>Status: <strong className="text-[#00FF41]">Ready for Workspace Ingestion</strong></span>
                  <span className="text-zinc-500">Latency: ~4ms</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Core Features & Capabilities Section */}
      <section id="features" className="py-16 md:py-20 bg-[#070709] border-t border-b border-[#16161C] relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12">
          <div className="max-w-3xl mx-auto text-center space-y-3">
            <h2 className="text-2xl sm:text-4xl font-black text-white uppercase tracking-tight">
              Tudo O Que Sua Equipe Precisa em Uma Única Suíte
            </h2>
            <p className="text-sm sm:text-base text-zinc-400">
              Elimine a necessidade de assinar dezenas de ferramentas isoladas e fragmentadas. O SecScan oferece cobertura completa de DevSecOps, AppSec e SOC.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* Card 1 */}
            <div className="p-6 rounded-xl bg-[#0B0B0F] border border-[#1E1E26] hover:border-[#FF3E00]/50 transition-all space-y-3 group">
              <div className="w-10 h-10 rounded-lg bg-[#FF3E00]/10 border border-[#FF3E00]/30 flex items-center justify-center text-[#FF3E00] group-hover:scale-110 transition-transform">
                <FileCode2 className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-bold text-white group-hover:text-[#FF3E00] transition-colors">
                Análise SAST & Taint Analysis
              </h3>
              <p className="text-xs text-zinc-400 leading-relaxed">
                Mais de 45 regras cobrindo injeções SQL, NoSQL, Cross-Site Scripting (XSS), Path Traversal e Command Injection com visualização em grafo de fluxo D3 interativo.
              </p>
            </div>

            {/* Card 2 */}
            <div className="p-6 rounded-xl bg-[#0B0B0F] border border-[#1E1E26] hover:border-[#FF3E00]/50 transition-all space-y-3 group">
              <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 group-hover:scale-110 transition-transform">
                <Key className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-bold text-white group-hover:text-emerald-400 transition-colors">
                Caçador de Segredos por Entropia
              </h3>
              <p className="text-xs text-zinc-400 leading-relaxed">
                Cálculo de Entropia de Shannon em strings para capturar chaves de API da AWS, tokens do GitHub, certificados e hashes antes que cheguem ao repositório público.
              </p>
            </div>

            {/* Card 3 */}
            <div className="p-6 rounded-xl bg-[#0B0B0F] border border-[#1E1E26] hover:border-[#FF3E00]/50 transition-all space-y-3 group">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 group-hover:scale-110 transition-transform">
                <Radio className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-bold text-white group-hover:text-cyan-400 transition-colors">
                CTI Hub & Feeds CISA KEV
              </h3>
              <p className="text-xs text-zinc-400 leading-relaxed">
                Feeds em tempo real com vulnerabilidades ativamente exploradas (CISA KEV e AlienVault OTX) e atribuição de Threat Actors conhecidos (Lazarus, Scattered Spider, etc.).
              </p>
            </div>

            {/* Card 4 */}
            <div className="p-6 rounded-xl bg-[#0B0B0F] border border-[#1E1E26] hover:border-[#FF3E00]/50 transition-all space-y-3 group">
              <div className="w-10 h-10 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400 group-hover:scale-110 transition-transform">
                <Container className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-bold text-white group-hover:text-indigo-400 transition-colors">
                IaC, K8s & Docker Hardening
              </h3>
              <p className="text-xs text-zinc-400 leading-relaxed">
                Verificação automatizada de scripts Terraform, manifestos Kubernetes contra PodSecurity Standards e auditoria de Dockerfile rootless com boas práticas CIS.
              </p>
            </div>

            {/* Card 5 */}
            <div className="p-6 rounded-xl bg-[#0B0B0F] border border-[#1E1E26] hover:border-[#FF3E00]/50 transition-all space-y-3 group">
              <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 group-hover:scale-110 transition-transform">
                <Route className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-bold text-white group-hover:text-amber-400 transition-colors">
                API Security & DAST Fuzzer
              </h3>
              <p className="text-xs text-zinc-400 leading-relaxed">
                Mineração de rotas REST e GraphQL ocultas em bundles JS, fuzzer de requisições web com injeção de parâmetros, teste de SSRF e inspeção profunda de tokens JWT.
              </p>
            </div>

            {/* Card 6 */}
            <div className="p-6 rounded-xl bg-[#0B0B0F] border border-[#1E1E26] hover:border-[#FF3E00]/50 transition-all space-y-3 group">
              <div className="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 group-hover:scale-110 transition-transform">
                <Scale className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-bold text-white group-hover:text-rose-400 transition-colors">
                Policy-as-Code (Rego OPA) & SBOM
              </h3>
              <p className="text-xs text-zinc-400 leading-relaxed">
                Validação de conformidade corporativa com Open Policy Agent, geração de Software Bill of Materials (SBOM CycloneDX/SPDX) e relatórios de auditoria executiva.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* DevSecOps Pipeline Flow Architecture */}
      <section id="pipeline" className="py-16 md:py-20 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12">
        <div className="max-w-3xl mx-auto text-center space-y-3">
          <h2 className="text-2xl sm:text-4xl font-black text-white uppercase tracking-tight">
            {t.pipelineTitle}
          </h2>
          <p className="text-sm sm:text-base text-zinc-400">
            {t.pipelineSub}
          </p>
        </div>

        {/* 5-Step Pipeline Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          {t.pipelineSteps.map((item, idx) => (
            <div 
              key={item.step} 
              className="p-5 rounded-xl bg-[#09090C] border border-[#1D1D24] relative flex flex-col justify-between hover:border-[#FF3E00]/50 transition-all"
            >
              <div>
                <span className="font-mono text-2xl font-black text-[#FF3E00] tracking-tight">
                  {item.step}
                </span>
                <h4 className="text-sm font-bold text-white mt-2 mb-1.5">
                  {item.title}
                </h4>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  {item.desc}
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-[#181820] flex items-center justify-between text-[10px] font-mono text-zinc-500">
                <span>STAGE {idx + 1}</span>
                <span className="text-[#00FF41]">● ACTIVE</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Privacy & Zero-Exfiltration Guarantee */}
      <section className="py-16 md:py-20 bg-[#070709] border-t border-b border-[#16161C]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12">
          <div className="max-w-3xl mx-auto text-center space-y-3">
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono font-bold uppercase tracking-wider">
              <Lock className="w-3.5 h-3.5" />
              <span>Zero Data Exfiltration Architecture</span>
            </div>
            <h2 className="text-2xl sm:text-4xl font-black text-white uppercase tracking-tight">
              {t.privacyTitle}
            </h2>
            <p className="text-sm sm:text-base text-zinc-400">
              {t.privacySub}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {t.privacyCards.map((card, i) => (
              <div key={i} className="p-6 rounded-xl bg-[#0B0B0F] border border-[#1E1E26] space-y-3">
                <div className="w-8 h-8 rounded bg-[#1C1C24] flex items-center justify-center text-white font-mono font-bold text-sm">
                  0{i + 1}
                </div>
                <h3 className="text-base font-bold text-white">
                  {card.title}
                </h3>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  {card.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section id="faq" className="py-16 md:py-20 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8 w-full">
        <div className="text-center space-y-2">
          <h2 className="text-2xl sm:text-3xl font-black text-white uppercase tracking-tight">
            {t.faqTitle}
          </h2>
          <p className="text-xs sm:text-sm text-zinc-400">
            Respostas diretas sobre como o SecScan funciona na prática
          </p>
        </div>

        <div className="space-y-3">
          {t.faqList.map((item, index) => {
            const isOpen = openFaqIndex === index;
            return (
              <div 
                key={index}
                className="rounded-lg bg-[#0A0A0E] border border-[#1E1E26] overflow-hidden transition-all"
              >
                <button
                  onClick={() => setOpenFaqIndex(isOpen ? null : index)}
                  className="w-full p-4 text-left flex items-center justify-between gap-4 cursor-pointer hover:bg-white/5 transition-colors"
                >
                  <span className="font-semibold text-sm text-white">{item.q}</span>
                  <span className={`text-[#FF3E00] font-mono text-sm transform transition-transform ${isOpen ? 'rotate-90' : ''}`}>
                    ›
                  </span>
                </button>
                {isOpen && (
                  <div className="px-4 pb-4 pt-1 text-xs text-zinc-300 border-t border-[#16161E] leading-relaxed">
                    {item.a}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* Final High-Impact CTA Banner */}
      <section className="py-16 md:py-24 bg-gradient-to-b from-[#09090D] to-[#040406] border-t border-[#1C1C24] relative overflow-hidden">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 text-center space-y-6 relative z-10">
          <div className="w-12 h-12 bg-[#FF3E00]/15 border border-[#FF3E00]/40 rounded-xl mx-auto flex items-center justify-center text-[#FF3E00] shadow-[0_0_20px_rgba(255,62,0,0.3)]">
            <ShieldAlert className="w-6 h-6" />
          </div>

          <h2 className="text-2xl sm:text-4xl md:text-5xl font-black text-white uppercase tracking-tight">
            {t.ctaBannerTitle}
          </h2>

          <p className="text-sm sm:text-base text-zinc-300 max-w-2xl mx-auto leading-relaxed">
            {t.ctaBannerSub}
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
            <button
              id="landing-bottom-cta-enter"
              onClick={() => onEnterApp(false)}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-3 px-8 py-4 rounded-xl bg-[#FF3E00] hover:bg-[#E03700] text-white font-mono text-sm font-bold uppercase tracking-wider shadow-[0_0_35px_rgba(255,62,0,0.5)] transition-all cursor-pointer hover:scale-[1.03] active:scale-[0.98]"
            >
              <Zap className="w-5 h-5 text-white" />
              <span>{t.btnEnterHome}</span>
              <ArrowRight className="w-4 h-4 ml-1" />
            </button>

            <button
              id="landing-bottom-cta-demo"
              onClick={() => onEnterApp(true)}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-4 rounded-xl bg-[#141418] hover:bg-[#1E1E24] text-zinc-200 hover:text-white border border-[#2E2E38] hover:border-[#FF3E00]/60 font-mono text-xs font-semibold uppercase tracking-wider transition-all cursor-pointer shadow-sm"
            >
              <Play className="w-4 h-4 text-[#00FF41]" />
              <span>{t.btnEnterDemo}</span>
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-[#040405] border-t border-[#141418] py-8 text-xs font-mono text-zinc-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-bold text-zinc-300">SECSCAN APPSEC SUITE</span>
            <span>·</span>
            <span>v2.5 ENTERPRISE</span>
          </div>

          <div className="text-center sm:text-right">
            <span>{t.footerTagline}</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
