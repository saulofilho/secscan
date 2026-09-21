import React, { useState, useMemo, useEffect } from 'react';
import {
  Radio,
  Search,
  Filter,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Terminal,
  Activity,
  FileCode,
  Download,
  Copy,
  Check,
  ExternalLink,
  RefreshCw,
  Clock,
  Layers,
  Crosshair,
  CheckCircle2,
  XCircle,
  Eye,
  Lock,
  ChevronDown,
  ChevronUp,
  FileText,
  Sliders,
  Play,
  Lightbulb,
  Workflow,
  Plus,
  Trash2,
  Sparkles,
  ArrowRight,
  Database,
  Network,
  Flame
} from 'lucide-react';
import { ScanReport, ScanFinding, ApiEndpointFinding } from '../types';
import { safeGetItem, safeSetItem } from '../lib/storage';

export interface SocCase {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'TRIAGE' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';
  assignee: string;
  findingId?: string;
  category: string;
  sourceFile: string;
  line: number;
  mitreTechnique: string;
  createdAt: string;
  updatedAt: string;
  notes: string;
  checklist: {
    id: string;
    text: string;
    completed: boolean;
  }[];
}

interface SecurityOnionSocViewProps {
  report: ScanReport;
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToScanner?: () => void;
  onNavigateToEndpoints?: () => void;
  onNavigateToDataFlow?: () => void;
}

type OnionSubTool = 'HUNT' | 'CASES' | 'DETECTIONS' | 'PCAP' | 'PLAYBOOKS';

const CASES_STORAGE_KEY = 'secscan_soc_cases_v1';

export const SecurityOnionSocView: React.FC<SecurityOnionSocViewProps> = ({
  report,
  onSelectFinding,
  onNavigateToScanner,
  onNavigateToEndpoints,
  onNavigateToDataFlow
}) => {
  const [activeTool, setActiveTool] = useState<OnionSubTool>('HUNT');

  // =========================================================================
  // 1. HUNT CONSOLE STATE & LOGIC
  // =========================================================================
  const [huntQuery, setHuntQuery] = useState<string>('');
  const [huntSeverityFilter, setHuntSeverityFilter] = useState<string>('ALL');
  const [huntCategoryFilter, setHuntCategoryFilter] = useState<string>('ALL');
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Pre-configured threat hunts inspired by Security Onion Hunt queries
  const PRESET_HUNTS = [
    {
      id: 'exposed-secrets',
      label: 'Credenciais & Chaves em Código',
      query: 'category:CLOUD_CREDENTIAL OR category:API_KEY OR category:AUTH_TOKEN',
      desc: 'Localiza tokens de nuvem, chaves mestras e segredos expostos nos arquivos.',
      icon: Lock,
      color: 'text-rose-400 bg-rose-500/10 border-rose-500/30'
    },
    {
      id: 'admin-apis',
      label: 'Rotas de API Internas & Admin',
      query: 'path:admin OR path:internal OR path:debug OR path:v1',
      desc: 'Varre superfícies de ataque em endpoints não autenticados ou de debug.',
      icon: Network,
      color: 'text-amber-400 bg-amber-500/10 border-amber-500/30'
    },
    {
      id: 'rce-sinks',
      label: 'Sinks Críticos & Injeção (RCE/SQLi)',
      query: 'rule:sink OR rule:eval OR rule:child_process OR rule:exec',
      desc: 'Detecta pontos de entrada que alcançam execuções perigosas sem sanitização.',
      icon: Flame,
      color: 'text-purple-400 bg-purple-500/10 border-purple-500/30'
    },
    {
      id: 'high-entropy',
      label: 'Anomalias de Alta Entropia (Cifras/Blobs)',
      query: 'entropy:>4.5',
      desc: 'Filtra strings aleatórias densas que sugerem certificados ou senhas cifradas.',
      icon: Activity,
      color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30'
    }
  ];

  // Filter findings for Hunt console
  const huntResults = useMemo(() => {
    return report.findings.filter(f => {
      if (huntSeverityFilter !== 'ALL' && f.severity !== huntSeverityFilter) {
        return false;
      }
      if (huntCategoryFilter !== 'ALL' && f.category !== huntCategoryFilter) {
        return false;
      }

      if (!huntQuery.trim()) return true;

      const q = huntQuery.toLowerCase().trim();

      // Advanced query filters (inspired by Security Onion Kibana/Elastic query syntax)
      if (q.startsWith('severity:')) {
        const val = q.replace('severity:', '').trim().toUpperCase();
        return f.severity === val;
      }
      if (q.startsWith('category:')) {
        const val = q.replace('category:', '').trim().toUpperCase();
        return f.category.toUpperCase().includes(val);
      }
      if (q.startsWith('file:')) {
        const val = q.replace('file:', '').trim();
        return f.file.toLowerCase().includes(val);
      }
      if (q.startsWith('rule:')) {
        const val = q.replace('rule:', '').trim();
        return f.ruleName.toLowerCase().includes(val) || f.ruleId.toLowerCase().includes(val);
      }
      if (q.startsWith('entropy:>')) {
        const threshold = parseFloat(q.replace('entropy:>', '').trim());
        return !isNaN(threshold) && f.entropy >= threshold;
      }

      // General text matching
      return (
        f.ruleName.toLowerCase().includes(q) ||
        f.file.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q) ||
        f.snippet.toLowerCase().includes(q) ||
        f.category.toLowerCase().includes(q)
      );
    });
  }, [report.findings, huntQuery, huntSeverityFilter, huntCategoryFilter]);

  // Aggregation metrics for Hunt dashboard
  const huntMetrics = useMemo(() => {
    const total = huntResults.length;
    const critical = huntResults.filter(f => f.severity === 'CRITICAL').length;
    const high = huntResults.filter(f => f.severity === 'HIGH').length;
    const medium = huntResults.filter(f => f.severity === 'MEDIUM').length;
    const low = huntResults.filter(f => f.severity === 'LOW' || f.severity === 'INFO').length;

    // Group by rules
    const ruleCounts: Record<string, number> = {};
    huntResults.forEach(f => {
      ruleCounts[f.ruleName] = (ruleCounts[f.ruleName] || 0) + 1;
    });

    const topRules = Object.entries(ruleCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    // Group by file extensions
    const extCounts: Record<string, number> = {};
    huntResults.forEach(f => {
      const ext = f.file.split('.').pop() || 'unknown';
      extCounts[ext] = (extCounts[ext] || 0) + 1;
    });

    return { total, critical, high, medium, low, topRules, extCounts };
  }, [huntResults]);

  // =========================================================================
  // 2. CASES / TRIAGE WORKBENCH STATE & LOGIC
  // =========================================================================
  const [cases, setCases] = useState<SocCase[]>(() => {
    const saved = safeGetItem(CASES_STORAGE_KEY);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) return parsed;
      } catch (err) {
        console.error('Failed to parse saved SOC cases', err);
      }
    }

    // Default seeded cases generated from current critical/high findings
    const initialCases: SocCase[] = [
      {
        id: 'CASE-2026-001',
        title: 'Vazamento de Credencial AWS IAM em Código Fonte',
        severity: 'CRITICAL',
        status: 'INVESTIGATING',
        assignee: 'SecOps L2 (Incident Team)',
        category: 'CLOUD_CREDENTIAL',
        sourceFile: 'src/config/aws.ts',
        line: 14,
        mitreTechnique: 'T1552.001 - Credentials In Files',
        createdAt: '2026-09-17 07:15:00',
        updatedAt: '2026-09-17 07:22:10',
        notes: 'Chave com privilégio de escrita detectada. Necessário rotacionar no AWS IAM e verificar logs no CloudTrail.',
        checklist: [
          { id: 'c1', text: 'Validar se a chave estava ativa na AWS', completed: true },
          { id: 'c2', text: 'Inativar credencial e gerar nova no Vault', completed: true },
          { id: 'c3', text: 'Consultar CloudTrail por chamadas anômalas nas últimas 72h', completed: false },
          { id: 'c4', text: 'Substituir por variável de ambiente segura no CI/CD', completed: false }
        ]
      },
      {
        id: 'CASE-2026-002',
        title: 'Assinatura JWT Fraca e Chave Secreta Exposta',
        severity: 'HIGH',
        status: 'TRIAGE',
        assignee: 'AppSec Analyst (Tier 1)',
        category: 'AUTH_TOKEN',
        sourceFile: 'src/auth/jwt.js',
        line: 22,
        mitreTechnique: 'T1552.004 - Private Keys',
        createdAt: '2026-09-17 07:20:00',
        updatedAt: '2026-09-17 07:25:00',
        notes: 'O segredo JWT "super-secret-key-123" permite falsificação de tokens de autenticação por atores externos.',
        checklist: [
          { id: 'c1', text: 'Revogar tokens existentes emitidos com chave legada', completed: false },
          { id: 'c2', text: 'Migrar para chave assimétrica RSA/ECDSA com rotação KMS', completed: false },
          { id: 'c3', text: 'Atualizar testes de integração de autenticação', completed: false }
        ]
      }
    ];
    return initialCases;
  });

  const [selectedCaseId, setSelectedCaseId] = useState<string>(cases[0]?.id || '');
  const [caseFilterStatus, setCaseFilterStatus] = useState<string>('ALL');

  useEffect(() => {
    safeSetItem(CASES_STORAGE_KEY, JSON.stringify(cases));
  }, [cases]);

  const selectedCase = useMemo(() => {
    return cases.find(c => c.id === selectedCaseId) || cases[0] || null;
  }, [cases, selectedCaseId]);

  const handleCreateCaseFromFinding = (finding: ScanFinding) => {
    const newCaseId = `CASE-${new Date().getFullYear()}-${String(cases.length + 1).padStart(3, '0')}`;
    const newCase: SocCase = {
      id: newCaseId,
      title: `${finding.ruleName} em ${finding.file}:${finding.line}`,
      severity: finding.severity as any,
      status: 'NEW' as any,
      assignee: 'Analista de Plantão (SOC L1)',
      findingId: finding.id,
      category: finding.category,
      sourceFile: finding.file,
      line: finding.line,
      mitreTechnique: finding.category === 'CLOUD_CREDENTIAL' ? 'T1552 - Unsecured Credentials' : 'T1059 - Command & Scripting',
      createdAt: new Date().toLocaleString(),
      updatedAt: new Date().toLocaleString(),
      notes: `Achado reportado pelo motor SAST SecScan. Trecho do código: ${finding.snippet}`,
      checklist: [
        { id: 'c1', text: 'Validar se é falso-positivo ou credencial ativa', completed: false },
        { id: 'c2', text: 'Aplicar quarentena ou rotação de segredo', completed: false },
        { id: 'c3', text: 'Atualizar regras de pre-commit e .secscanignore', completed: false }
      ]
    };

    setCases(prev => [newCase, ...prev]);
    setSelectedCaseId(newCaseId);
    setActiveTool('CASES');
  };

  const handleUpdateCaseStatus = (caseId: string, status: SocCase['status']) => {
    setCases(prev => prev.map(c => c.id === caseId ? { ...c, status, updatedAt: new Date().toLocaleString() } : c));
  };

  const handleToggleChecklistItem = (caseId: string, checkId: string) => {
    setCases(prev => prev.map(c => {
      if (c.id !== caseId) return c;
      const updatedCheck = c.checklist.map(item => item.id === checkId ? { ...item, completed: !item.completed } : item);
      return { ...c, checklist: updatedCheck, updatedAt: new Date().toLocaleString() };
    }));
  };

  const handleAddChecklistItem = (caseId: string, text: string) => {
    if (!text.trim()) return;
    setCases(prev => prev.map(c => {
      if (c.id !== caseId) return c;
      const newItem = { id: `c-${Date.now()}`, text: text.trim(), completed: false };
      return { ...c, checklist: [...c.checklist, newItem], updatedAt: new Date().toLocaleString() };
    }));
  };

  const handleDeleteCase = (caseId: string) => {
    setCases(prev => {
      const remaining = prev.filter(c => c.id !== caseId);
      if (selectedCaseId === caseId && remaining.length > 0) {
        setSelectedCaseId(remaining[0].id);
      }
      return remaining;
    });
  };

  // =========================================================================
  // 3. DETECTION ENGINEERING STUDIO (Sigma, Suricata, Zeek, ModSec, YARA)
  // =========================================================================
  const [detectionFormat, setDetectionFormat] = useState<'SIGMA' | 'SURICATA' | 'ZEEK' | 'MODSEC' | 'YARA'>('SIGMA');
  const [selectedFindingForDetection, setSelectedFindingForDetection] = useState<ScanFinding>(report.findings[0] || null);

  const generatedDetectionRule = useMemo(() => {
    const f = selectedFindingForDetection || report.findings[0];
    if (!f) {
      return '// Nenhum achado disponível para gerar regras de detecção.';
    }

    const cleanName = f.ruleName.replace(/[^a-zA-Z0-9_]/g, '_').toLowerCase();
    const cleanPattern = f.matchedSecret || f.ruleId;

    switch (detectionFormat) {
      case 'SIGMA':
        return `title: Detecção de ${f.ruleName} em Logs de Aplicação
id: ${f.id || 'secscan-rule-001'}
status: production
description: Identifica vazamento ou uso indevido de ${f.ruleName} (Categoria: ${f.category})
references:
  - https://attack.mitre.org/techniques/T1552/
author: SecScan Onion Defense Engine
date: 2026-09-17
modified: 2026-09-17
tags:
  - attack.credential_access
  - attack.t1552
  - secscan.${f.category.toLowerCase()}
logsource:
  category: application
  product: webserver
detection:
  selection_file:
    file.path|contains:
      - '${f.file}'
  selection_pattern:
    message|contains:
      - '${cleanPattern.slice(0, 20)}'
  condition: selection_file and selection_pattern
falsepositives:
  - Mock files em testes unitários (.test.js)
  - Variáveis mascaradas em logs de CI/CD
level: ${f.severity === 'CRITICAL' ? 'critical' : f.severity === 'HIGH' ? 'high' : 'medium'}`;

      case 'SURICATA':
        return `# Regra de Detecção de Tráfego de Rede (NIDS Suricata 7.x)
# Detecta trânsito de credenciais ou assinaturas não criptografadas
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any ( \\
  msg:"SECSCAN ONION ALERT: Exposição de ${f.ruleName} em Trânsito"; \\
  flow:established,to_server; \\
  content:"${cleanPattern.slice(0, 16)}"; nocase; http_client_body; \\
  classtype:policy-violation; \\
  reference:cwe,${f.category === 'CLOUD_CREDENTIAL' ? '798' : '200'}; \\
  metadata:created_at 2026_09_17, rule_id ${f.ruleId}; \\
  sid:9100${Math.floor(Math.random() * 899 + 100)}; rev:1; \\
)`;

      case 'ZEEK':
        return `# Script de Telemetria de Rede Zeek (Bro IDS)
@load base/frameworks/notice
@load base/protocols/http

module SecScanOnion;

export {
    redef enum Notice::Type += {
        SecScan_Credential_Exposed,
    };
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
    if ( is_orig && /${f.category === 'CLOUD_CREDENTIAL' ? 'AKIA[0-9A-Z]{16}' : 'Bearer [A-Za-z0-9-_.]+'}/ in data ) {
        NOTICE([$note=SecScan_Credential_Exposed,
                $msg=fmt("SecScan: Padrão sensível '%s' detectado no fluxo HTTP de %s", "${f.ruleName}", c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h)]);
    }
}`;

      case 'MODSEC':
        return `# Regra WAF OWASP ModSecurity v3 (Proteção de Borda)
SecRule REQUEST_URI|REQUEST_BODY "@rx ${f.category === 'CLOUD_CREDENTIAL' ? '(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}' : '(?i)bearer\\s+[a-z0-9-_=]+\\.[a-z0-9-_=]+'}" \\
    "id:950123,\\
    phase:2,\\
    block,\\
    capture,\\
    t:none,t:urlDecodeUni,\\
    msg:'SecScan WAF: Tentativa de exfiltração ou envio de ${f.ruleName}',\\
    logdata:'Correspondência: %{TX.0}',\\
    tag:'application-security',\\
    tag:'SECSCAN-ONION',\\
    severity:'${f.severity === 'CRITICAL' ? 'CRITICAL' : 'ERROR'}',\\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"`;

      case 'YARA':
        return `/* Regra YARA de Varredura Estática em Repositórios e Artefatos */
rule SecScan_${cleanName}_Detection {
    meta:
        author = "SecScan Onion Detection Engine"
        date = "2026-09-17"
        description = "Detecta ocorrência estática de ${f.ruleName}"
        severity = "${f.severity}"
        category = "${f.category}"
    strings:
        $token_pattern = /${f.category === 'CLOUD_CREDENTIAL' ? 'AKIA[0-9A-Z]{16}' : 'ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+'}/
        $context_kw = "${f.file.split('/').pop()?.split('.')[0] || 'secret'}" nocase
    condition:
        $token_pattern and $context_kw and filesize < 5MB
}`;
    }
  }, [selectedFindingForDetection, report.findings, detectionFormat]);

  // =========================================================================
  // 4. PCAP & ARTIFACT INSPECTOR (Network Stream & Hex Dump)
  // =========================================================================
  const [selectedEndpointIndex, setSelectedEndpointIndex] = useState<number>(0);
  const [pcapViewMode, setPcapViewMode] = useState<'STREAM' | 'HEX' | 'HEADERS'>('STREAM');

  const activeEndpoint = report.apiEndpoints[selectedEndpointIndex] || report.apiEndpoints[0] || null;

  // Simulated raw hex dump for the inspected network packet / payload
  const simulatedHexDump = useMemo(() => {
    if (!activeEndpoint) return [];
    const rawPayload = `POST ${activeEndpoint.path} HTTP/1.1\r\nHost: api.secscan.internal\r\nUser-Agent: SecScan-Sensor/4.2 (OnionEngine)\r\nAuthorization: Bearer DEMO_JWT_SESSION_TOKEN_SAMPLE...\r\nContent-Type: application/json\r\nContent-Length: 54\r\n\r\n{"username":"admin","client_nonce":"f8e91024bcda"}`;

    const lines: { offset: string; hex: string; ascii: string }[] = [];
    const bytes = new TextEncoder().encode(rawPayload);

    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.slice(i, i + 16);
      const offset = i.toString(16).padStart(8, '0');

      let hexPart = '';
      let asciiPart = '';

      for (let j = 0; j < 16; j++) {
        if (j < slice.length) {
          hexPart += slice[j].toString(16).padStart(2, '0') + ' ';
          // Printable ASCII
          const charCode = slice[j];
          asciiPart += charCode >= 32 && charCode <= 126 ? String.fromCharCode(charCode) : '.';
        } else {
          hexPart += '   ';
        }
      }

      lines.push({ offset, hex: hexPart.trim(), ascii: asciiPart });
    }

    return lines;
  }, [activeEndpoint]);

  // =========================================================================
  // 5. SOC INCIDENT RESPONSE PLAYBOOKS (NIST SP 800-61 Rev 2)
  // =========================================================================
  const PLAYBOOKS = [
    {
      id: 'pb-cloud-secrets',
      title: 'Vazamento de Credenciais em Nuvem (AWS/GCP/Azure)',
      severity: 'CRITICAL',
      cveMitre: 'MITRE T1552.001 | CWE-798',
      description: 'Procedimento operacional padrão (SOP) para contenção, invalidação de chaves e purga de histórico git em caso de vazamento.',
      phases: [
        {
          name: 'Fase 1: Identificação & Análise de Escopo',
          tasks: [
            { id: 't1', text: 'Identificar usuário ou serviço IAM associado ao token vazado', done: true },
            { id: 't2', text: 'Checar escopo de permissões associadas (ex: AdministratorAccess vs ReadOnly)', done: true },
            { id: 't3', text: 'Inspecionar logs do CloudTrail / Cloud Audit Logs por acessos IP desconhecidos', done: false }
          ]
        },
        {
          name: 'Fase 2: Contenção Imediata',
          tasks: [
            { id: 't4', text: 'Inativar a chave de acesso diretamente no painel IAM (Status: Inactive)', done: true },
            { id: 't5', text: 'Aplicar política explícita de negação (Deny All) temporária para o usuário afetado', done: false },
            { id: 't6', text: 'Remover o arquivo ou commit vulnerável via git-filter-repo / BFG Repo-Cleaner', done: false }
          ]
        },
        {
          name: 'Fase 3: Erradicação & Rotação',
          tasks: [
            { id: 't7', text: 'Provisionar novo par de chaves armazenado exclusivamente no HashiCorp Vault / AWS Secrets Manager', done: false },
            { id: 't8', text: 'Substituir chamadas estáticas por papéis assumidos (IAM Roles / Workload Identity Federation)', done: false },
            { id: 't9', text: 'Deletar permanentemente a chave de acesso antiga inativada', done: false }
          ]
        },
        {
          name: 'Fase 4: Recuperação & Lições Aprendidas',
          tasks: [
            { id: 't10', text: 'Configurar pre-commit hook obrigatório com SecScan CLI no repositório', done: false },
            { id: 't11', text: 'Publicar relatório pós-incidente e atualizar matriz de riscos corporativa', done: false }
          ]
        }
      ]
    },
    {
      id: 'pb-jwt-forgery',
      title: 'Chave de Assinatura JWT Comprometida ou Fraca',
      severity: 'HIGH',
      cveMitre: 'MITRE T1552.004 | CWE-347',
      description: 'SOP defensivo para mitigação de falsificação de identidade de usuário e privilégios administrativos.',
      phases: [
        {
          name: 'Fase 1: Avaliação de Impacto',
          tasks: [
            { id: 'j1', text: 'Confirmar algoritmo de assinatura em uso (HS256 vulnerável vs RS256/ES256 assimétrico)', done: true },
            { id: 'j2', text: 'Avaliar tempo de expiração dos tokens ativos (TTL)', done: true }
          ]
        },
        {
          name: 'Fase 2: Revogação em Massa & Bloqueio',
          tasks: [
            { id: 'j3', text: 'Invalidar cache de sessões em Redis / Memcached', done: false },
            { id: 'j4', text: 'Incrementar versão de época de token (token_version) para forçar novo login geral', done: false }
          ]
        },
        {
          name: 'Fase 3: Endurecimento Criptográfico',
          tasks: [
            { id: 'j5', text: 'Migrar chave secreta para rotação automática via JWKS endpoint com chaves assimétricas', done: false }
          ]
        }
      ]
    },
    {
      id: 'pb-ssrf-internal',
      title: 'Exposição de Endpoints Internos e Potencial SSRF',
      severity: 'HIGH',
      cveMitre: 'MITRE T1071 | CWE-918',
      description: 'Roteiro de mitigação de requisições maliciosas enviadas do servidor para serviços internos ou metadata de cloud.',
      phases: [
        {
          name: 'Fase 1: Mapeamento da Superfície',
          tasks: [
            { id: 's1', text: 'Inspecionar chamadas HTTP outbound identificadas pelo LinkFinder e Taint Analysis', done: true },
            { id: 's2', text: 'Verificar se URLs de entrada são aceitas sem validação de whitelist estrita', done: true }
          ]
        },
        {
          name: 'Fase 2: Bloqueio de Rede',
          tasks: [
            { id: 's3', text: 'Bloquear tráfego de saída para 169.254.169.254 (Cloud Metadata Service)', done: false },
            { id: 's4', text: 'Isolar subredes privadas através de Security Groups e egress firewalls', done: false }
          ]
        }
      ]
    }
  ];

  const [activePlaybookId, setActivePlaybookId] = useState<string>(PLAYBOOKS[0].id);
  const activePlaybook = useMemo(() => {
    return PLAYBOOKS.find(p => p.id === activePlaybookId) || PLAYBOOKS[0];
  }, [activePlaybookId]);

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Top Banner: Security Onion SOC & Threat Hunting Suite */}
      <div className="p-4 sm:p-5 rounded-xl border border-emerald-500/30 bg-gradient-to-r from-[#041a11]/90 via-[#03140e]/95 to-[#020b08] shadow-[0_0_25px_rgba(16,185,129,0.1)] relative overflow-hidden">
        <div className="absolute -right-8 -bottom-8 opacity-10 pointer-events-none">
          <Radio className="w-56 h-56 text-emerald-400" />
        </div>

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5 flex-wrap">
              <div className="p-2 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 shadow-sm">
                <Radio className="w-5 h-5 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-lg sm:text-xl font-bold font-mono text-white tracking-tight">
                    Security Onion // SOC & Threat Hunting Suite
                  </h1>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 uppercase">
                    Defesa Ativa • Blue Team
                  </span>
                </div>
                <p className="text-xs text-zinc-300 mt-0.5">
                  Módulo defensivo inspirado no ecossistema Security Onion: caça a ameaças (Hunt), triagem de casos, gerador de assinaturas (Sigma / Suricata / Zeek), inspeção de tráfego e playbooks de resposta a incidentes.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3 flex-wrap font-mono text-xs">
            <div className="px-3 py-1.5 rounded-lg bg-black/50 border border-emerald-500/20 text-zinc-300 flex items-center gap-2">
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              <span>Eventos Monitorados:</span>
              <strong className="text-white">{report.findings.length + report.apiEndpoints.length}</strong>
            </div>

            <div className="px-3 py-1.5 rounded-lg bg-black/50 border border-rose-500/20 text-zinc-300 flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
              <span>Casos Abertos:</span>
              <strong className="text-rose-300">{cases.filter(c => c.status !== 'RESOLVED').length}</strong>
            </div>
          </div>
        </div>
      </div>

      {/* Sub-tool Navigation Bar (Hunt, Cases, Detections, PCAP, Playbooks) */}
      <div className="flex items-center gap-1.5 p-1.5 rounded-xl bg-[#0d0f12] border border-white/10 overflow-x-auto text-xs font-mono">
        <button
          type="button"
          onClick={() => setActiveTool('HUNT')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
            activeTool === 'HUNT'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm'
              : 'text-zinc-400 hover:text-white hover:bg-white/5 border border-transparent'
          }`}
        >
          <Search className="w-3.5 h-3.5 text-emerald-400" />
          <span>Hunt (Threat Hunting)</span>
          <span className="px-1.5 py-0.2 rounded bg-emerald-500/30 text-emerald-200 text-[10px]">
            {huntResults.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTool('CASES')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
            activeTool === 'CASES'
              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-sm'
              : 'text-zinc-400 hover:text-white hover:bg-white/5 border border-transparent'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-rose-400" />
          <span>Casos & Triagem (Cases)</span>
          <span className="px-1.5 py-0.2 rounded bg-rose-500/30 text-rose-200 text-[10px]">
            {cases.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTool('DETECTIONS')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
            activeTool === 'DETECTIONS'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-zinc-400 hover:text-white hover:bg-white/5 border border-transparent'
          }`}
        >
          <Sliders className="w-3.5 h-3.5 text-cyan-400" />
          <span>Detections Engine (Sigma/Suricata/Zeek)</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTool('PCAP')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
            activeTool === 'PCAP'
              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm'
              : 'text-zinc-400 hover:text-white hover:bg-white/5 border border-transparent'
          }`}
        >
          <Terminal className="w-3.5 h-3.5 text-amber-400" />
          <span>PCAP & Stream Inspector</span>
          <span className="px-1.5 py-0.2 rounded bg-amber-500/30 text-amber-200 text-[10px]">
            {report.apiEndpoints.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTool('PLAYBOOKS')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
            activeTool === 'PLAYBOOKS'
              ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm'
              : 'text-zinc-400 hover:text-white hover:bg-white/5 border border-transparent'
          }`}
        >
          <Workflow className="w-3.5 h-3.5 text-purple-400" />
          <span>Playbooks de Resposta (SOPs)</span>
          <span className="px-1.5 py-0.2 rounded bg-purple-500/30 text-purple-200 text-[10px]">
            {PLAYBOOKS.length}
          </span>
        </button>
      </div>

      {/* =================================================================== */}
      {/* 1. THREAT HUNTING (HUNT CONSOLE) VIEW                                */}
      {/* =================================================================== */}
      {activeTool === 'HUNT' && (
        <div className="space-y-4">
          {/* Query Bar & Presets */}
          <div className="p-4 rounded-xl bg-[#0A0A0A] border border-white/10 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center gap-2">
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-zinc-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={huntQuery}
                  onChange={(e) => setHuntQuery(e.target.value)}
                  placeholder="Pesquisar por observables (ex: severity:CRITICAL, file:aws, category:CLOUD_CREDENTIAL, entropy:>4.0)..."
                  className="w-full bg-[#111] border border-white/15 focus:border-emerald-500/70 rounded-lg pl-9 pr-8 py-2 text-xs font-mono text-zinc-100 placeholder:text-zinc-600 focus:outline-none transition-colors"
                />
                {huntQuery && (
                  <button
                    type="button"
                    onClick={() => setHuntQuery('')}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 p-0.5"
                  >
                    <XCircle className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <select
                  value={huntSeverityFilter}
                  onChange={(e) => setHuntSeverityFilter(e.target.value)}
                  className="bg-[#111] border border-white/15 rounded-lg px-2.5 py-2 text-xs font-mono text-zinc-300 focus:outline-none focus:border-emerald-500/70"
                >
                  <option value="ALL">Todas as Severidades</option>
                  <option value="CRITICAL">Crítico (P0)</option>
                  <option value="HIGH">Alto (P1)</option>
                  <option value="MEDIUM">Médio (P2)</option>
                  <option value="LOW">Baixo / Info</option>
                </select>

                <select
                  value={huntCategoryFilter}
                  onChange={(e) => setHuntCategoryFilter(e.target.value)}
                  className="bg-[#111] border border-white/15 rounded-lg px-2.5 py-2 text-xs font-mono text-zinc-300 focus:outline-none focus:border-emerald-500/70"
                >
                  <option value="ALL">Todas as Categorias</option>
                  <option value="CLOUD_CREDENTIAL">Cloud Credentials</option>
                  <option value="API_KEY">API Keys</option>
                  <option value="AUTH_TOKEN">Auth Tokens / JWT</option>
                  <option value="DATABASE_URI">Database URIs</option>
                  <option value="TAINT_SINK">Taint Sinks</option>
                  <option value="PRIVATE_KEY">Private Keys</option>
                </select>

                <button
                  type="button"
                  onClick={() => {
                    setHuntQuery('');
                    setHuntSeverityFilter('ALL');
                    setHuntCategoryFilter('ALL');
                  }}
                  className="px-2.5 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white border border-white/10 text-xs font-mono transition-colors"
                  title="Redefinir filtros"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Hunt Presets Pills */}
            <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-white/5">
              <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider font-semibold">
                Pivots Rápidos:
              </span>
              {PRESET_HUNTS.map(preset => {
                const IconComponent = preset.icon;
                return (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => setHuntQuery(preset.query)}
                    className={`px-2 py-1 rounded text-[10.5px] font-mono border inline-flex items-center gap-1.5 transition-all hover:scale-102 cursor-pointer ${preset.color}`}
                    title={preset.desc}
                  >
                    <IconComponent className="w-3 h-3 shrink-0" />
                    <span>{preset.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Hunt Metrics & Aggregations Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
            <div className="p-3 rounded-lg bg-[#0E0E0E] border border-white/10">
              <span className="text-[10px] text-zinc-400 uppercase block">Total Encontrado</span>
              <strong className="text-lg text-white font-bold">{huntMetrics.total}</strong>
              <span className="text-[9.5px] text-zinc-500 block">observables em workspace</span>
            </div>

            <div className="p-3 rounded-lg bg-[#0E0E0E] border border-rose-500/20">
              <span className="text-[10px] text-rose-400 uppercase block">Crítico (P0)</span>
              <strong className="text-lg text-rose-300 font-bold">{huntMetrics.critical}</strong>
              <span className="text-[9.5px] text-zinc-500 block">requerem ação imediata</span>
            </div>

            <div className="p-3 rounded-lg bg-[#0E0E0E] border border-amber-500/20">
              <span className="text-[10px] text-amber-400 uppercase block">Alto (P1)</span>
              <strong className="text-lg text-amber-300 font-bold">{huntMetrics.high}</strong>
              <span className="text-[9.5px] text-zinc-500 block">alto risco de exploração</span>
            </div>

            <div className="p-3 rounded-lg bg-[#0E0E0E] border border-cyan-500/20">
              <span className="text-[10px] text-cyan-400 uppercase block">Média / Baixa</span>
              <strong className="text-lg text-cyan-300 font-bold">{huntMetrics.medium + huntMetrics.low}</strong>
              <span className="text-[9.5px] text-zinc-500 block">avisos e telemetria</span>
            </div>
          </div>

          {/* Hunt Events Table */}
          <div className="p-4 rounded-xl bg-[#0A0A0A] border border-white/10 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                <Search className="w-3.5 h-3.5 text-emerald-400" />
                <span>Fluxo de Eventos e Observables ({huntResults.length})</span>
              </h2>

              <button
                type="button"
                onClick={() => {
                  const json = JSON.stringify(huntResults, null, 2);
                  handleCopy(json, 'hunt-export');
                }}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/15 text-zinc-300 hover:text-white font-mono text-[11px] transition-colors cursor-pointer"
              >
                {copiedText === 'hunt-export' ? <Check className="w-3 h-3 text-emerald-400" /> : <Download className="w-3 h-3" />}
                <span>{copiedText === 'hunt-export' ? 'Copiado!' : 'Exportar JSON'}</span>
              </button>
            </div>

            {huntResults.length === 0 ? (
              <div className="py-10 text-center text-zinc-500 font-mono text-xs">
                Nenhum evento corresponde à consulta "{huntQuery}". Tente limpar os filtros.
              </div>
            ) : (
              <div className="overflow-x-auto border border-white/5 rounded-lg">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-[#121417] text-zinc-400 text-[10px] uppercase border-b border-white/10">
                    <tr>
                      <th className="py-2.5 px-3">Severidade</th>
                      <th className="py-2.5 px-3">Regra / Tipo</th>
                      <th className="py-2.5 px-3">Arquivo / Local</th>
                      <th className="py-2.5 px-3">Observable / Trecho</th>
                      <th className="py-2.5 px-3">Entropia</th>
                      <th className="py-2.5 px-3 text-right">Ações</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {huntResults.map(finding => {
                      const isCritical = finding.severity === 'CRITICAL';
                      const isHigh = finding.severity === 'HIGH';

                      return (
                        <tr key={finding.id} className="hover:bg-white/5 transition-colors group">
                          <td className="py-2.5 px-3 whitespace-nowrap">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${
                                isCritical
                                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                                  : isHigh
                                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                                  : 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                              }`}
                            >
                              {finding.severity}
                            </span>
                          </td>

                          <td className="py-2.5 px-3">
                            <span className="font-bold text-white block truncate max-w-[180px]">
                              {finding.ruleName}
                            </span>
                            <span className="text-[9px] text-zinc-500 block truncate">
                              {finding.category}
                            </span>
                          </td>

                          <td className="py-2.5 px-3 text-zinc-300">
                            <span className="truncate block max-w-[190px]" title={finding.file}>
                              {finding.file}:{finding.line}
                            </span>
                          </td>

                          <td className="py-2.5 px-3 font-mono text-zinc-300">
                            <code className="bg-black/60 px-1.5 py-0.5 rounded text-[10px] text-emerald-300 border border-white/5 block max-w-[260px] truncate">
                              {finding.maskedSecret || finding.snippet.trim() || '—'}
                            </code>
                          </td>

                          <td className="py-2.5 px-3 text-zinc-400">
                            <span className={finding.entropy >= 4.0 ? 'text-amber-400 font-bold' : ''}>
                              {finding.entropy.toFixed(2)}
                            </span>
                          </td>

                          <td className="py-2.5 px-3 text-right whitespace-nowrap">
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                type="button"
                                onClick={() => handleCreateCaseFromFinding(finding)}
                                className="px-2 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-[10px] transition-colors cursor-pointer"
                                title="Abrir caso de resposta a incidentes"
                              >
                                + Caso
                              </button>

                              <button
                                type="button"
                                onClick={() => {
                                  setSelectedFindingForDetection(finding);
                                  setActiveTool('DETECTIONS');
                                }}
                                className="px-2 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[10px] transition-colors cursor-pointer"
                                title="Gerar regra de detecção defensiva"
                              >
                                Detecção
                              </button>

                              {onSelectFinding && (
                                <button
                                  type="button"
                                  onClick={() => onSelectFinding(finding)}
                                  className="p-1 rounded bg-white/5 hover:bg-white/15 text-zinc-300 hover:text-white border border-white/10 transition-colors cursor-pointer"
                                  title="Ver no Inspetor de Código"
                                >
                                  <FileCode className="w-3.5 h-3.5" />
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* 2. CASES & TRIAGE WORKBENCH VIEW                                    */}
      {/* =================================================================== */}
      {activeTool === 'CASES' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Left Column: Cases List */}
          <div className="lg:col-span-5 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-rose-400" />
                <span>Fila de Casos e Alertas ({cases.length})</span>
              </h2>

              <div className="flex items-center gap-1">
                <select
                  value={caseFilterStatus}
                  onChange={(e) => setCaseFilterStatus(e.target.value)}
                  className="bg-[#111] border border-white/15 rounded px-2 py-1 text-[11px] font-mono text-zinc-300"
                >
                  <option value="ALL">Todos os Status</option>
                  <option value="TRIAGE">Triagem</option>
                  <option value="INVESTIGATING">Em Investigação</option>
                  <option value="CONTAINED">Contido</option>
                  <option value="RESOLVED">Resolvido</option>
                </select>
              </div>
            </div>

            <div className="space-y-2 max-h-[680px] overflow-y-auto pr-1">
              {cases
                .filter(c => caseFilterStatus === 'ALL' || c.status === caseFilterStatus)
                .map(c => {
                  const isSelected = c.id === selectedCase?.id;
                  const isCritical = c.severity === 'CRITICAL';
                  const isResolved = c.status === 'RESOLVED';

                  return (
                    <div
                      key={c.id}
                      onClick={() => setSelectedCaseId(c.id)}
                      className={`p-3 rounded-lg border transition-all cursor-pointer ${
                        isSelected
                          ? 'bg-[#15171c] border-emerald-500/60 shadow-lg'
                          : 'bg-[#0d0d0f] border-white/10 hover:border-white/20 hover:bg-[#121215]'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <span className="text-[10px] font-mono text-zinc-500 font-bold">
                          {c.id}
                        </span>

                        <div className="flex items-center gap-1.5">
                          <span
                            className={`px-1.5 py-0.2 rounded text-[8.5px] font-mono font-bold border ${
                              isCritical
                                ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                                : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                            }`}
                          >
                            {c.severity}
                          </span>

                          <span
                            className={`px-1.5 py-0.2 rounded text-[8.5px] font-mono font-bold ${
                              isResolved
                                ? 'bg-emerald-500/20 text-emerald-300'
                                : c.status === 'CONTAINED'
                                ? 'bg-cyan-500/20 text-cyan-300'
                                : 'bg-purple-500/20 text-purple-300'
                            }`}
                          >
                            {c.status}
                          </span>
                        </div>
                      </div>

                      <h4 className="text-xs font-bold text-white mt-1 leading-snug">
                        {c.title}
                      </h4>

                      <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400 mt-2 pt-2 border-t border-white/5">
                        <span className="truncate max-w-[160px]">{c.sourceFile}:{c.line}</span>
                        <span>{c.checklist.filter(i => i.completed).length}/{c.checklist.length} tarefas</span>
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>

          {/* Right Column: Case Details & Investigation Workbench */}
          <div className="lg:col-span-7">
            {selectedCase ? (
              <div className="p-4 sm:p-5 rounded-xl bg-[#0d0f12] border border-white/10 space-y-4">
                <div className="flex flex-wrap items-start justify-between gap-2 border-b border-white/10 pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-emerald-400">{selectedCase.id}</span>
                      <span className="text-zinc-500">•</span>
                      <span className="text-xs font-mono text-zinc-400">{selectedCase.category}</span>
                    </div>
                    <h3 className="text-sm sm:text-base font-bold text-white mt-0.5">
                      {selectedCase.title}
                    </h3>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => handleDeleteCase(selectedCase.id)}
                      className="p-1.5 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 transition-colors cursor-pointer"
                      title="Excluir caso"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Workflow Status Bar */}
                <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                  <span className="text-zinc-500 text-[11px]">Transição de Estado:</span>
                  {(['TRIAGE', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'] as const).map(st => (
                    <button
                      key={st}
                      type="button"
                      onClick={() => handleUpdateCaseStatus(selectedCase.id, st)}
                      className={`px-2.5 py-1 rounded text-[10px] font-bold border transition-all cursor-pointer ${
                        selectedCase.status === st
                          ? 'bg-emerald-500/30 text-emerald-200 border-emerald-500 shadow-sm'
                          : 'bg-black/30 text-zinc-400 border-white/10 hover:text-white hover:bg-white/5'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>

                {/* Case Meta Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 p-3 rounded-lg bg-black/40 border border-white/5 text-xs font-mono">
                  <div>
                    <span className="text-[10px] text-zinc-500 uppercase block">Responsável:</span>
                    <strong className="text-zinc-200 text-[11px]">{selectedCase.assignee}</strong>
                  </div>
                  <div>
                    <span className="text-[10px] text-zinc-500 uppercase block">Arquivo Alvo:</span>
                    <strong className="text-zinc-200 text-[11px] truncate block" title={selectedCase.sourceFile}>
                      {selectedCase.sourceFile}:{selectedCase.line}
                    </strong>
                  </div>
                  <div>
                    <span className="text-[10px] text-zinc-500 uppercase block">Técnica MITRE:</span>
                    <strong className="text-emerald-300 text-[11px] truncate block">
                      {selectedCase.mitreTechnique}
                    </strong>
                  </div>
                </div>

                {/* Incident Checklist (Remediation SOP) */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Checklist de Resposta e Remediação</span>
                    </h4>
                    <span className="text-[10px] font-mono text-zinc-400">
                      {selectedCase.checklist.filter(c => c.completed).length} de {selectedCase.checklist.length} concluídas
                    </span>
                  </div>

                  <div className="space-y-1.5 bg-black/30 p-2.5 rounded-lg border border-white/5">
                    {selectedCase.checklist.map(item => (
                      <label
                        key={item.id}
                        className="flex items-start gap-2.5 p-1.5 rounded hover:bg-white/5 cursor-pointer text-xs font-mono text-zinc-300 select-none transition-colors"
                      >
                        <input
                          type="checkbox"
                          checked={item.completed}
                          onChange={() => handleToggleChecklistItem(selectedCase.id, item.id)}
                          className="mt-0.5 rounded border-white/20 bg-black text-emerald-500 focus:ring-emerald-400"
                        />
                        <span className={item.completed ? 'line-through text-zinc-500' : ''}>
                          {item.text}
                        </span>
                      </label>
                    ))}
                  </div>

                  {/* Add Task Input */}
                  <div className="flex items-center gap-2 pt-1">
                    <input
                      type="text"
                      id="input-new-checklist-task"
                      placeholder="Adicionar nova etapa de investigação/remediação..."
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          handleAddChecklistItem(selectedCase.id, e.currentTarget.value);
                          e.currentTarget.value = '';
                        }
                      }}
                      className="flex-1 bg-[#121215] border border-white/15 rounded px-2.5 py-1 text-xs font-mono text-zinc-200 focus:outline-none focus:border-emerald-500/60"
                    />
                    <button
                      type="button"
                      onClick={() => {
                        const el = document.getElementById('input-new-checklist-task') as HTMLInputElement | null;
                        if (el && el.value) {
                          handleAddChecklistItem(selectedCase.id, el.value);
                          el.value = '';
                        }
                      }}
                      className="px-2.5 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-xs font-mono transition-colors"
                    >
                      Adicionar
                    </button>
                  </div>
                </div>

                {/* Notes & Evidence */}
                <div className="space-y-1.5">
                  <span className="text-[10px] font-mono text-zinc-500 uppercase block font-semibold">
                    Anotações do Analista & Evidências:
                  </span>
                  <div className="p-3 rounded-lg bg-black/60 border border-white/10 font-mono text-xs text-zinc-300 whitespace-pre-wrap leading-relaxed">
                    {selectedCase.notes}
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-20 text-center text-zinc-500 font-mono text-xs">
                Selecione um caso na fila para visualizar os detalhes.
              </div>
            )}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* 3. DETECTION ENGINEERING STUDIO (Sigma / Suricata / Zeek / YARA)    */}
      {/* =================================================================== */}
      {activeTool === 'DETECTIONS' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-[#0A0A0A] border border-white/10 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-cyan-400" />
                  <span>Detections Engine // Conversor Automático de Assinaturas</span>
                </h3>
                <p className="text-xs text-zinc-400 mt-0.5">
                  Transforme vulnerabilidades e credenciais descobertas no repositório em regras operacionais de SIEM (Sigma), NIDS (Suricata), Zeek, ModSecurity WAF ou YARA.
                </p>
              </div>

              {/* Format Switcher */}
              <div className="flex items-center gap-1 p-1 rounded-lg bg-[#14161B] border border-white/10 font-mono text-xs overflow-x-auto">
                {(['SIGMA', 'SURICATA', 'ZEEK', 'MODSEC', 'YARA'] as const).map(fmt => (
                  <button
                    key={fmt}
                    type="button"
                    onClick={() => setDetectionFormat(fmt)}
                    className={`px-3 py-1.5 rounded font-bold transition-all cursor-pointer ${
                      detectionFormat === fmt
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                        : 'text-zinc-400 hover:text-white'
                    }`}
                  >
                    {fmt}
                  </button>
                ))}
              </div>
            </div>

            {/* Target Finding Selector */}
            <div className="flex items-center gap-2 pt-2 border-t border-white/5 text-xs font-mono">
              <span className="text-zinc-400 shrink-0">Achado Alvo:</span>
              <select
                value={selectedFindingForDetection?.id || ''}
                onChange={(e) => {
                  const target = report.findings.find(f => f.id === e.target.value);
                  if (target) setSelectedFindingForDetection(target);
                }}
                className="flex-1 bg-[#111] border border-white/15 rounded-lg px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-500"
              >
                {report.findings.map(f => (
                  <option key={f.id} value={f.id}>
                    [{f.severity}] {f.ruleName} — {f.file}:{f.line}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Rule Preview & Actions */}
          <div className="p-4 rounded-xl bg-[#08090C] border border-cyan-500/30 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
                <span className="font-mono text-xs font-bold text-white uppercase">
                  Regra Gerada ({detectionFormat})
                </span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => handleCopy(generatedDetectionRule, 'detection-rule')}
                  className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/15 text-zinc-200 font-mono text-xs transition-colors cursor-pointer"
                >
                  {copiedText === 'detection-rule' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedText === 'detection-rule' ? 'Copiado!' : 'Copiar Regra'}</span>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    const blob = new Blob([generatedDetectionRule], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `secscan-detection-${detectionFormat.toLowerCase()}-${Date.now()}.txt`;
                    a.click();
                  }}
                  className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-200 font-mono text-xs transition-colors cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Baixar Arquivo</span>
                </button>
              </div>
            </div>

            <pre className="p-4 rounded-lg bg-[#040507] border border-white/10 font-mono text-xs text-cyan-200 overflow-x-auto leading-relaxed max-h-[500px]">
              {generatedDetectionRule}
            </pre>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* 4. PCAP & STREAM ARTIFACT INSPECTOR VIEW                            */}
      {/* =================================================================== */}
      {activeTool === 'PCAP' && (
        report.apiEndpoints.length === 0 ? (
          <div className="p-12 rounded-xl bg-black/40 border border-white/10 text-center space-y-3">
            <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
            <h3 className="text-base font-bold text-white">Nenhum Endpoint ou Tráfego de API no Workspace</h3>
            <p className="text-xs text-zinc-400 max-w-md mx-auto">
              Nenhum endpoint de API foi identificado nos arquivos atuais. Adicione arquivos com rotas ou endpoints para inspecionar tráfego de rede e pacotes PCAP.
            </p>
          </div>
        ) : activeEndpoint ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Endpoint / Stream Selector */}
          <div className="lg:col-span-4 space-y-3">
            <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <Network className="w-3.5 h-3.5 text-amber-400" />
              <span>Sessões & Endpoints Mapeados ({report.apiEndpoints.length})</span>
            </h3>

            <div className="space-y-1.5 max-h-[600px] overflow-y-auto pr-1">
              {report.apiEndpoints.map((ep, idx) => {
                const isSelected = idx === selectedEndpointIndex;

                return (
                  <div
                    key={ep.id || idx}
                    onClick={() => setSelectedEndpointIndex(idx)}
                    className={`p-2.5 rounded-lg border font-mono text-xs cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-amber-500/15 border-amber-500/60 text-white shadow-sm'
                        : 'bg-[#0E0E10] border-white/10 hover:border-white/20 text-zinc-300'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className="px-1.5 py-0.2 rounded bg-white/10 text-[9px] font-bold text-amber-300">
                        {ep.method || 'ALL'}
                      </span>
                      <span className="text-[9px] text-zinc-500 truncate">{ep.file.split('/').pop()}</span>
                    </div>

                    <div className="font-bold text-[11px] truncate mt-1">
                      {ep.path}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Hex Dump & Stream Analyzer */}
          <div className="lg:col-span-8 space-y-3">
            <div className="p-4 rounded-xl bg-[#0A0A0A] border border-white/10 space-y-3">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold">
                    {activeEndpoint.method || 'GET'}
                  </span>
                  <span className="text-white font-bold">{activeEndpoint.path}</span>
                </div>

                <div className="flex items-center gap-1 p-0.5 rounded bg-black/50 border border-white/10 font-mono text-xs">
                  <button
                    type="button"
                    onClick={() => setPcapViewMode('STREAM')}
                    className={`px-2.5 py-1 rounded ${pcapViewMode === 'STREAM' ? 'bg-amber-500/20 text-amber-300' : 'text-zinc-400'}`}
                  >
                    Stream ASCII
                  </button>
                  <button
                    type="button"
                    onClick={() => setPcapViewMode('HEX')}
                    className={`px-2.5 py-1 rounded ${pcapViewMode === 'HEX' ? 'bg-amber-500/20 text-amber-300' : 'text-zinc-400'}`}
                  >
                    Hex Dump
                  </button>
                  <button
                    type="button"
                    onClick={() => setPcapViewMode('HEADERS')}
                    className={`px-2.5 py-1 rounded ${pcapViewMode === 'HEADERS' ? 'bg-amber-500/20 text-amber-300' : 'text-zinc-400'}`}
                  >
                    Metadados de Rede
                  </button>
                </div>
              </div>

              {/* View Modes */}
              {pcapViewMode === 'HEX' && (
                <div className="p-3 rounded-lg bg-[#040405] border border-white/10 font-mono text-[11px] text-zinc-300 overflow-x-auto">
                  <div className="grid grid-cols-12 gap-2 text-zinc-500 border-b border-white/10 pb-1 mb-1 font-bold">
                    <span className="col-span-3">Offset</span>
                    <span className="col-span-6">Hex Bytes (16-byte words)</span>
                    <span className="col-span-3 text-right">ASCII Decodificado</span>
                  </div>
                  <div className="space-y-0.5">
                    {simulatedHexDump.map((row, i) => (
                      <div key={i} className="grid grid-cols-12 gap-2 hover:bg-white/5 font-mono py-0.5">
                        <span className="col-span-3 text-cyan-400">{row.offset}</span>
                        <span className="col-span-6 text-zinc-200 tracking-wider">{row.hex}</span>
                        <span className="col-span-3 text-emerald-300 text-right truncate">{row.ascii}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {pcapViewMode === 'STREAM' && (
                <div className="p-4 rounded-lg bg-[#040405] border border-white/10 font-mono text-xs text-amber-200 whitespace-pre-wrap leading-relaxed max-h-[480px] overflow-y-auto">
                  {`POST ${activeEndpoint.path} HTTP/1.1\r\nHost: api.secscan.internal:443\r\nUser-Agent: Mozilla/5.0 (SecurityOnion-Sensor/4.2)\r\nAuthorization: Bearer [REDACTED_SEC_TOKEN]\r\nContent-Type: application/json\r\nAccept: */*\r\n\r\n{\r\n  "action": "QUERY_SECRETS",\r\n  "endpoint": "${activeEndpoint.path}",\r\n  "source": "${activeEndpoint.file}"\r\n}\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nServer: Envoy/1.24\r\nX-Security-Audit: SECSCAN-ONION-PASSED\r\n\r\n{\r\n  "status": "monitored",\r\n  "trace_id": "soc-flow-${Date.now()}",\r\n  "alert_trigger": false\r\n}`}
                </div>
              )}

              {pcapViewMode === 'HEADERS' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
                  <div className="p-3 rounded-lg bg-black/40 border border-white/5 space-y-1.5">
                    <span className="text-zinc-500 uppercase text-[10px] block font-bold">Camada de Transporte & IP</span>
                    <div><span className="text-zinc-400">Origem:</span> <strong className="text-white">192.168.10.45:54210</strong></div>
                    <div><span className="text-zinc-400">Destino:</span> <strong className="text-white">10.0.1.5:443 (HTTPS)</strong></div>
                    <div><span className="text-zinc-400">Protocolo:</span> <strong className="text-emerald-400">TCP / TLS 1.3</strong></div>
                    <div><span className="text-zinc-400">JA3 Fingerprint:</span> <strong className="text-zinc-300">b32309a26ce516158d71ef17b70e44f2</strong></div>
                  </div>

                  <div className="p-3 rounded-lg bg-black/40 border border-white/5 space-y-1.5">
                    <span className="text-zinc-500 uppercase text-[10px] block font-bold">Assinaturas de Rede & NIDS</span>
                    <div><span className="text-zinc-400">Suricata SID:</span> <strong className="text-amber-300">910042</strong></div>
                    <div><span className="text-zinc-400">Zeek Conn UID:</span> <strong className="text-zinc-300">CHrTeL2k98Z1mQ7a</strong></div>
                    <div><span className="text-zinc-400">Classificação:</span> <strong className="text-white">Web Application Ingestion</strong></div>
                    <div><span className="text-zinc-400">Ação Recomendada:</span> <strong className="text-emerald-400">Inspeção Ativa WAF</strong></div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
        ) : null
      )}

      {/* =================================================================== */}
      {/* 5. SOC INCIDENT RESPONSE PLAYBOOKS VIEW                             */}
      {/* =================================================================== */}
      {activeTool === 'PLAYBOOKS' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Playbook Selection */}
          <div className="lg:col-span-4 space-y-3">
            <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <Workflow className="w-3.5 h-3.5 text-purple-400" />
              <span>Procedimentos Operacionais (SOPs)</span>
            </h3>

            <div className="space-y-2">
              {PLAYBOOKS.map(pb => {
                const isSelected = pb.id === activePlaybook.id;

                return (
                  <div
                    key={pb.id}
                    onClick={() => setActivePlaybookId(pb.id)}
                    className={`p-3 rounded-xl border transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-purple-500/15 border-purple-500/60 shadow-lg'
                        : 'bg-[#0E0E10] border-white/10 hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="px-1.5 py-0.2 rounded text-[8.5px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                        {pb.severity}
                      </span>
                      <span className="text-[9px] font-mono text-purple-300">{pb.cveMitre}</span>
                    </div>

                    <h4 className="text-xs font-bold text-white mt-1.5 leading-snug">
                      {pb.title}
                    </h4>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Interactive Playbook Execution View */}
          <div className="lg:col-span-8">
            <div className="p-5 rounded-xl bg-[#0A0A0E] border border-purple-500/30 space-y-5">
              <div>
                <div className="flex items-center gap-2 text-xs font-mono text-purple-300">
                  <span>{activePlaybook.cveMitre}</span>
                  <span>•</span>
                  <span className="text-zinc-500">NIST SP 800-61 Rev 2</span>
                </div>
                <h2 className="text-base font-bold text-white mt-1">
                  {activePlaybook.title}
                </h2>
                <p className="text-xs text-zinc-400 mt-1">
                  {activePlaybook.description}
                </p>
              </div>

              {/* Phases and Tasks */}
              <div className="space-y-4">
                {activePlaybook.phases.map((phase, idx) => (
                  <div key={idx} className="p-3.5 rounded-lg bg-black/50 border border-white/10 space-y-2">
                    <h4 className="text-xs font-mono font-bold text-purple-300 uppercase flex items-center gap-2">
                      <span className="w-5 h-5 rounded bg-purple-500/20 flex items-center justify-center text-[10px] text-purple-200">
                        {idx + 1}
                      </span>
                      <span>{phase.name}</span>
                    </h4>

                    <div className="space-y-1.5 pl-7">
                      {phase.tasks.map(task => (
                        <label
                          key={task.id}
                          className="flex items-start gap-2.5 p-1 rounded hover:bg-white/5 cursor-pointer text-xs font-mono text-zinc-300 select-none"
                        >
                          <input
                            type="checkbox"
                            defaultChecked={task.done}
                            className="mt-0.5 rounded border-white/20 bg-black text-purple-500 focus:ring-purple-400"
                          />
                          <span>{task.text}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
