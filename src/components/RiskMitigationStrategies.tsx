import React, { useState, useMemo, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Ticket,
  ExternalLink,
  GitPullRequest,
  CheckCircle2,
  Clock,
  AlertTriangle,
  Copy,
  Check,
  RotateCcw,
  Plus,
  Filter,
  Search,
  Download,
  Layers,
  Terminal,
  KeyRound,
  Database,
  Lock,
  GitBranch,
  FileCode,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Share2,
  Sliders,
  AlertOctagon,
  Eye,
  CheckSquare,
  Square,
  RefreshCw,
  User,
  Tag
} from 'lucide-react';
import { ScanFinding, ScanReport, SeverityLevel, FindingCategory } from '../types';
import { safeGetItem, safeSetItem } from '../lib/storage';

export type TicketPlatform = 'JIRA' | 'GITHUB' | 'GITLAB' | 'SERVICENOW' | 'LINEAR';

export type TicketStatus = 'UNASSIGNED' | 'TICKET_CREATED' | 'IN_PROGRESS' | 'CODE_REVIEW' | 'REMEDIATED' | 'RISK_ACCEPTED';

export type StrategyType = 
  | 'SECRET_REVOCATION_KMS' 
  | 'GIT_HISTORY_PURGE' 
  | 'IAM_TOKEN_SCOPING' 
  | 'DATABASE_URI_SANITIZATION' 
  | 'PRIVATE_KEY_ROTATION' 
  | 'TAINT_SINK_REFACTOR';

export interface RemediationWorkflowPhase {
  id: string;
  title: string;
  description: string;
  cliCommand?: string;
  completed: boolean;
}

export interface SecurityTicketInfo {
  id: string; // e.g. "SEC-4091"
  platform: TicketPlatform;
  url: string;
  status: TicketStatus;
  priority: 'P0_BLOCKER' | 'P1_URGENT' | 'P2_HIGH' | 'P3_MEDIUM';
  assignee: string;
  slaHours: number;
  slaRemainingHours: number;
  createdAt: string;
  updatedAt: string;
}

export interface RiskMitigationMapping {
  findingId: string;
  findingRule: string;
  findingSeverity: SeverityLevel;
  findingFile: string;
  findingLine: number;
  findingCategory: FindingCategory;
  findingEntropy: number;
  riskScore: number;
  maskedSecret?: string;
  snippet?: string;
  // Strategy
  strategyType: StrategyType;
  strategyTitle: string;
  strategySummary: string;
  estimatedEffortHours: number;
  workflowPhases: RemediationWorkflowPhase[];
  // External Ticket
  ticket: SecurityTicketInfo;
}

interface RiskMitigationStrategiesProps {
  report: ScanReport;
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToFinding?: (findingId: string) => void;
  onNavigateToScanner?: () => void;
  onNavigateToFile?: (filePath: string) => void;
}

const STORAGE_KEY = 'secscan_risk_mitigation_strategies_v1';

const PLATFORM_CONFIG: Record<TicketPlatform, { label: string; badgeClass: string; urlTemplate: (id: string) => string }> = {
  JIRA: {
    label: 'Jira Software',
    badgeClass: 'bg-[#0052CC]/20 text-[#2684FF] border-[#0052CC]/50',
    urlTemplate: (id) => `https://jira.corp.internal/browse/${id}`
  },
  GITHUB: {
    label: 'GitHub Issues',
    badgeClass: 'bg-[#24292e] text-[#f0f6fc] border-[#444d56]',
    urlTemplate: (id) => `https://github.com/company/repo/issues/${id.replace(/\D/g, '') || '101'}`
  },
  GITLAB: {
    label: 'GitLab Security',
    badgeClass: 'bg-[#E24329]/20 text-[#FC6D26] border-[#E24329]/50',
    urlTemplate: (id) => `https://gitlab.corp.internal/security/issues/${id}`
  },
  SERVICENOW: {
    label: 'ServiceNow SecOps',
    badgeClass: 'bg-[#81B5A1]/20 text-[#81B5A1] border-[#81B5A1]/50',
    urlTemplate: (id) => `https://service-now.internal/nav_to.do?uri=sn_si_incident.do?sysparm_id=${id}`
  },
  LINEAR: {
    label: 'Linear App',
    badgeClass: 'bg-[#5E6AD2]/20 text-[#5E6AD2] border-[#5E6AD2]/50',
    urlTemplate: (id) => `https://linear.app/team/issue/${id}`
  }
};

const STATUS_CONFIG: Record<TicketStatus, { label: string; colorClass: string; bgClass: string }> = {
  UNASSIGNED: { label: 'Sem Ticket', colorClass: 'text-[#888]', bgClass: 'bg-[#181818] border-[#333]' },
  TICKET_CREATED: { label: 'Ticket Criado', colorClass: 'text-[#3399FF]', bgClass: 'bg-[#3399FF]/10 border-[#3399FF]/30' },
  IN_PROGRESS: { label: 'Em Progresso', colorClass: 'text-[#FFB800]', bgClass: 'bg-[#FFB800]/10 border-[#FFB800]/30' },
  CODE_REVIEW: { label: 'Code Review (PR)', colorClass: 'text-[#A855F7]', bgClass: 'bg-[#A855F7]/10 border-[#A855F7]/30' },
  REMEDIATED: { label: 'Mitigado / Resolvido', colorClass: 'text-[#00FF66]', bgClass: 'bg-[#00FF66]/10 border-[#00FF66]/30' },
  RISK_ACCEPTED: { label: 'Risco Aceito (SecOps)', colorClass: 'text-[#888]', bgClass: 'bg-[#222] border-[#444]' }
};

/**
 * Maps a finding to an authoritative remediation strategy and workflow phases.
 */
function deriveStrategyForFinding(finding: ScanFinding): {
  strategyType: StrategyType;
  strategyTitle: string;
  strategySummary: string;
  estimatedEffortHours: number;
  workflowPhases: RemediationWorkflowPhase[];
} {
  const cat = finding.category || 'API_KEY';
  const rule = (finding.ruleName || '').toLowerCase();
  const file = finding.file || '';

  if (cat === 'DATABASE_URI' || rule.includes('postgres') || rule.includes('mongo') || rule.includes('mysql')) {
    return {
      strategyType: 'DATABASE_URI_SANITIZATION',
      strategyTitle: 'Isolamento de Credencial de Banco & Rotação Dinâmica',
      strategySummary: 'Remoção de strings de conexão com usuário/senha embutidos no código. Configuração do motor de credenciais dinâmicas do Vault com lease transitório de curta duração.',
      estimatedEffortHours: 4,
      workflowPhases: [
        {
          id: 'p1',
          title: 'Fase 1: Rotação de Senha do Banco de Dados',
          description: 'Acessar o console do banco (AWS RDS / Cloud SQL) e redefinir a senha do usuário comprometido.',
          cliCommand: 'ALTER USER "db_user" WITH PASSWORD "novo_segredo_criptografado_vault";',
          completed: false
        },
        {
          id: 'p2',
          title: 'Fase 2: Substituição da URI Hardcoded por Variável de Ambiente',
          description: `Atualizar o arquivo "${file}" para carregar DATABASE_URL exclusivamente via process.env.DATABASE_URL.`,
          cliCommand: 'sed -i \'s/postgres:\\/\\/.*@/postgres:\\/\\/${DB_CREDS}@/g\' ' + file,
          completed: false
        },
        {
          id: 'p3',
          title: 'Fase 3: Provisionamento de Engine Dinâmico (HashiCorp Vault)',
          description: 'Habilitar o secret engine de database no Vault para gerar credenciais transitórias com TTL de 1 hora.',
          cliCommand: 'vault write database/config/my-postgresql plugin_name=postgresql-database-plugin allowed_roles="app-role"',
          completed: false
        },
        {
          id: 'p4',
          title: 'Fase 4: Validação em Quality Gate & Git Purge',
          description: 'Confirmar zero ocorrências de credenciais em plain-text nos commits anteriores do repositório.',
          cliCommand: 'git log -S "postgres://" --oneline',
          completed: false
        }
      ]
    };
  }

  if (cat === 'PRIVATE_KEY' || rule.includes('private key') || rule.includes('rsa') || rule.includes('ssh')) {
    return {
      strategyType: 'PRIVATE_KEY_ROTATION',
      strategyTitle: 'Revogação de Chave Privada & Reemissão PKI / SSH',
      strategySummary: 'Invalidação imediata da chave assimétrica no servidor e provedor de identidade. Reemissão via autoridade certificadora (CA) ou Vault PKI com chaves efêmeras.',
      estimatedEffortHours: 3,
      workflowPhases: [
        {
          id: 'p1',
          title: 'Fase 1: Revogação da Chave em Servidores / authorized_keys',
          description: 'Remover a chave pública correspondente de todos os servidores de produção e chaves de implantação.',
          cliCommand: 'ssh-keygen -R hostname && sed -i \'/COMPROMISED_KEY/d\' ~/.ssh/authorized_keys',
          completed: false
        },
        {
          id: 'p2',
          title: 'Fase 2: Geração de Novo Par de Chaves Criptográficas (ED25519)',
          description: 'Gerar novo par de chaves com senha de proteção (passphrase) forte.',
          cliCommand: 'ssh-keygen -t ed25519 -C "secops-remediation@company.internal" -f ~/.ssh/id_ed25519_new',
          completed: false
        },
        {
          id: 'p3',
          title: 'Fase 3: Git Filter-Repo para Eliminação Histórica',
          description: 'Remover o arquivo de chave privada de todo o histórico git utilizando git filter-repo.',
          cliCommand: `git filter-repo --invert-paths --path "${file}" --force`,
          completed: false
        },
        {
          id: 'p4',
          title: 'Fase 4: Verificação de Validade & Auditoria de Logs',
          description: 'Reescanear o repositório e auditar logs de autenticação dos últimos 7 dias em busca de uso anômalo da chave antiga.',
          cliCommand: 'journalctl -u sshd --since "7 days ago" | grep "Accepted publickey"',
          completed: false
        }
      ]
    };
  }

  if (cat === 'TAINT_SINK' || rule.includes('injection') || rule.includes('eval') || rule.includes('sink')) {
    return {
      strategyType: 'TAINT_SINK_REFACTOR',
      strategyTitle: 'Sanitização de Taint Sink & Refatoração Segura',
      strategySummary: 'Refatoração da chamada vulnerável para uso de API parametrizada ou biblioteca de sanitização contextual (DOMPurify, prepared statements).',
      estimatedEffortHours: 5,
      workflowPhases: [
        {
          id: 'p1',
          title: 'Fase 1: Identificação de Fontes de Entrada de Usuário (Sources)',
          description: 'Rastrear a propagação dos dados não confiáveis até o sink de execução.',
          cliCommand: `grep -rnI --color=always "req.body" "${file}"`,
          completed: false
        },
        {
          id: 'p2',
          title: 'Fase 2: Implementação de Validação de Schema (Zod / Joi)',
          description: 'Adicionar validação estrita de tipos e sanitização de caracteres antes do processamento.',
          cliCommand: 'npm install zod && cat <<EOF >> src/schemas/validator.ts',
          completed: false
        },
        {
          id: 'p3',
          title: 'Fase 3: Parametrização da Chamada Vulnerável',
          description: `Refatorar a linha ${finding.line} para utilizar query parametrizada em vez de interpolação de strings.`,
          cliCommand: '# Substitua interpolações $1 por prepared parameters',
          completed: false
        },
        {
          id: 'p4',
          title: 'Fase 4: Teste de Regressão & Verificação de Taint AST',
          description: 'Executar testes de unidade cobrindo payloads de injeção e reexecutar a análise estática AST.',
          cliCommand: 'npm test && npm run sec:audit',
          completed: false
        }
      ]
    };
  }

  // Default: Secret Revocation + KMS Migration (API_KEY, CLOUD_CREDENTIAL, AUTH_TOKEN, PASSWORD)
  return {
    strategyType: 'SECRET_REVOCATION_KMS',
    strategyTitle: 'Revogação de Credencial de Nuvem & Migração para KMS',
    strategySummary: 'Invalidação imediata da credencial no provedor (AWS IAM, GCP, GitHub, Slack) e migração para injeção em runtime via AWS Secrets Manager ou Vault.',
    estimatedEffortHours: 2,
    workflowPhases: [
      {
        id: 'p1',
        title: 'Fase 1: Invalidação & Rotação no Provedor Cloud',
        description: 'Revogar a chave ativa no portal do provedor e gerar nova credencial sem permissões desnecessárias.',
        cliCommand: 'aws iam update-access-key --access-key-id AKIA_EXPOSED --status Inactive',
        completed: false
      },
      {
        id: 'p2',
        title: 'Fase 2: Armazenamento Seguro no Gerenciador de Segredos',
        description: 'Criar o registro do segredo no AWS Secrets Manager ou HashiCorp Vault.',
        cliCommand: 'aws secretsmanager create-secret --name "app/production/api_key" --secret-string "NOVO_SEGREDO"',
        completed: false
      },
      {
        id: 'p3',
        title: 'Fase 3: Sanitização de Código & Injeção em Variável de Ambiente',
        description: `Remover a constante estática do arquivo "${file}" e carregar dinamicamente via process.env.`,
        cliCommand: `git diff "${file}"`,
        completed: false
      },
      {
        id: 'p4',
        title: 'Fase 4: Expurgar Histórico Git com BFG Repo Cleaner',
        description: 'Executar limpeza definitiva de blobs no repositório git para evitar clone leaks.',
        cliCommand: 'bfg --replace-text compromised-secrets.txt .git && git reflog expire --expire=now --all && git gc --prune=now --aggressive',
        completed: false
      }
    ]
  };
}

/**
 * Builds baseline mappings for high-risk findings.
 */
function generateDefaultMappings(report: ScanReport): RiskMitigationMapping[] {
  const allFindings = report?.findings || [];
  
  // Prioritize Critical, High, and highest-weighted findings
  const highRiskFindings = allFindings.filter(
    (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH' || (f.riskScore && f.riskScore >= 70)
  );

  // If there are few or zero high-risk findings, include other findings or synthesized high-impact scenarios
  const targets = highRiskFindings.length > 0 ? highRiskFindings : allFindings.slice(0, 5);

  return targets.map((f, idx) => {
    const strategy = deriveStrategyForFinding(f);
    const platforms: TicketPlatform[] = ['JIRA', 'GITHUB', 'GITLAB', 'SERVICENOW', 'LINEAR'];
    const platform = platforms[idx % platforms.length];
    const ticketId = platform === 'JIRA' ? `SEC-${4100 + idx * 13}` :
                     platform === 'GITHUB' ? `GH-#${120 + idx * 7}` :
                     platform === 'SERVICENOW' ? `SN-INC-${8800 + idx * 21}` :
                     platform === 'LINEAR' ? `LIN-SEC-${300 + idx * 9}` :
                     `GL-SEC-${500 + idx * 11}`;

    const priority = f.severity === 'CRITICAL' ? 'P0_BLOCKER' : 'P1_URGENT';
    const slaHours = f.severity === 'CRITICAL' ? 24 : 72;
    const slaRemainingHours = Math.max(2, Math.round(slaHours - (idx * 6.5)));

    const assignees = ['@secops-lead', '@appsec-champion', '@devops-engineer', '@backend-core', '@infra-team'];
    const assignee = assignees[idx % assignees.length];

    const initialStatus: TicketStatus = idx === 0 ? 'IN_PROGRESS' : idx === 1 ? 'TICKET_CREATED' : 'UNASSIGNED';

    return {
      findingId: f.id,
      findingRule: f.ruleName || 'Sensitive Pattern Exposure',
      findingSeverity: f.severity,
      findingFile: f.file,
      findingLine: f.line,
      findingCategory: f.category,
      findingEntropy: f.entropy || 3.8,
      riskScore: f.riskScore || (f.severity === 'CRITICAL' ? 95 : 80),
      maskedSecret: f.maskedSecret,
      snippet: f.snippet,
      strategyType: strategy.strategyType,
      strategyTitle: strategy.strategyTitle,
      strategySummary: strategy.strategySummary,
      estimatedEffortHours: strategy.estimatedEffortHours,
      workflowPhases: strategy.workflowPhases,
      ticket: {
        id: ticketId,
        platform,
        url: PLATFORM_CONFIG[platform].urlTemplate(ticketId),
        status: initialStatus,
        priority,
        assignee,
        slaHours,
        slaRemainingHours,
        createdAt: new Date(Date.now() - (idx * 14400000)).toISOString(),
        updatedAt: new Date().toISOString()
      }
    };
  });
}

export const RiskMitigationStrategies: React.FC<RiskMitigationStrategiesProps> = ({
  report,
  onSelectFinding,
  onNavigateToFinding,
  onNavigateToScanner,
  onNavigateToFile
}) => {
  // Master mappings state with localStorage persistence
  const [mappings, setMappings] = useState<RiskMitigationMapping[]>(() => {
    try {
      const saved = safeGetItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed;
        }
      }
    } catch {
      // Storage fallback
    }
    return generateDefaultMappings(report);
  });

  // Keep mappings aligned if new scan report findings are injected
  useEffect(() => {
    setMappings((prev) => {
      if (!prev || prev.length === 0) {
        return generateDefaultMappings(report);
      }
      return prev;
    });
  }, [report?.findings?.length]);

  // Persist changes
  const saveMappings = (updated: RiskMitigationMapping[]) => {
    setMappings(updated);
    try {
      safeSetItem(STORAGE_KEY, JSON.stringify(updated));
    } catch {
      // Storage fail-safe
    }
  };

  // Reset to initial baseline
  const handleResetToDefaults = () => {
    const fresh = generateDefaultMappings(report);
    saveMappings(fresh);
  };

  // UI Filter states
  const [severityFilter, setSeverityFilter] = useState<'ALL' | SeverityLevel>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | TicketStatus>('ALL');
  const [strategyFilter, setStrategyFilter] = useState<'ALL' | StrategyType>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Expanded items (accordion state)
  const [expandedFindingIds, setExpandedFindingIds] = useState<Set<string>>(() => {
    const initial = new Set<string>();
    if (mappings[0]) initial.add(mappings[0].findingId);
    return initial;
  });

  // Copied feedback states
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const toggleExpand = (findingId: string) => {
    setExpandedFindingIds((prev) => {
      const next = new Set(prev);
      if (next.has(findingId)) {
        next.delete(findingId);
      } else {
        next.add(findingId);
      }
      return next;
    });
  };

  // Interactive toggle of workflow phase checkbox
  const handleToggleWorkflowPhase = (findingId: string, phaseId: string) => {
    const updated = mappings.map((m) => {
      if (m.findingId !== findingId) return m;

      const newPhases = m.workflowPhases.map((phase) => {
        if (phase.id === phaseId) {
          return { ...phase, completed: !phase.completed };
        }
        return phase;
      });

      // Auto-advance ticket status if all phases completed
      const allDone = newPhases.every((p) => p.completed);
      let updatedStatus = m.ticket.status;
      if (allDone && m.ticket.status !== 'REMEDIATED') {
        updatedStatus = 'REMEDIATED';
      } else if (!allDone && m.ticket.status === 'REMEDIATED') {
        updatedStatus = 'IN_PROGRESS';
      }

      return {
        ...m,
        workflowPhases: newPhases,
        ticket: {
          ...m.ticket,
          status: updatedStatus,
          updatedAt: new Date().toISOString()
        }
      };
    });

    saveMappings(updated);
  };

  // Interactive change of ticket status
  const handleChangeTicketStatus = (findingId: string, newStatus: TicketStatus) => {
    const updated = mappings.map((m) => {
      if (m.findingId !== findingId) return m;
      return {
        ...m,
        ticket: {
          ...m.ticket,
          status: newStatus,
          updatedAt: new Date().toISOString()
        }
      };
    });
    saveMappings(updated);
  };

  // Interactive change of ticket platform
  const handleChangeTicketPlatform = (findingId: string, newPlatform: TicketPlatform) => {
    const updated = mappings.map((m) => {
      if (m.findingId !== findingId) return m;
      const newUrl = PLATFORM_CONFIG[newPlatform].urlTemplate(m.ticket.id);
      return {
        ...m,
        ticket: {
          ...m.ticket,
          platform: newPlatform,
          url: newUrl,
          updatedAt: new Date().toISOString()
        }
      };
    });
    saveMappings(updated);
  };

  // Copy Ticket payload (Markdown formatted for Jira/GitHub/ServiceNow)
  const handleCopyTicketPayload = (mapping: RiskMitigationMapping) => {
    const text = `
# [${mapping.ticket.priority}] ${mapping.findingRule} em ${mapping.findingFile}
**ID do Ticket:** ${mapping.ticket.id} (${mapping.ticket.platform})
**Severidade:** ${mapping.findingSeverity} | **Calculated Risk Score:** ${mapping.riskScore}/100
**Arquivo:** \`${mapping.findingFile}\` (Linha ${mapping.findingLine})
**Responsável:** ${mapping.ticket.assignee} | **SLA:** ${mapping.ticket.slaHours}h (${mapping.ticket.slaRemainingHours}h restantes)

## 📋 Estratégia de Mitigação: ${mapping.strategyTitle}
${mapping.strategySummary}

### 🛠️ Fases do Workflow de Remediação:
${mapping.workflowPhases.map((p, idx) => `${idx + 1}. [${p.completed ? 'x' : ' '}] **${p.title}**: ${p.description}${p.cliCommand ? `\n   \`\`\`bash\n   ${p.cliCommand}\n   \`\`\`` : ''}`).join('\n')}

### 🔍 Evidência Encontrada:
\`\`\`
${mapping.snippet || mapping.maskedSecret || '// Trecho identificado pelo SecScan AST'}
\`\`\`

---
*Gerado automaticamente pelo SecScan Engine - Painel de Estratégias de Mitigação de Risco*
    `.trim();

    navigator.clipboard.writeText(text);
    setCopiedKey(mapping.findingId);
    setTimeout(() => setCopiedKey(null), 2500);
  };

  // Filtered dataset
  const filteredMappings = useMemo(() => {
    return mappings.filter((m) => {
      // Severity
      if (severityFilter !== 'ALL' && m.findingSeverity !== severityFilter) return false;
      // Status
      if (statusFilter !== 'ALL' && m.ticket.status !== statusFilter) return false;
      // Strategy
      if (strategyFilter !== 'ALL' && m.strategyType !== strategyFilter) return false;
      // Search
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesFile = m.findingFile.toLowerCase().includes(q);
        const matchesRule = m.findingRule.toLowerCase().includes(q);
        const matchesTicket = m.ticket.id.toLowerCase().includes(q);
        const matchesAssignee = m.ticket.assignee.toLowerCase().includes(q);
        const matchesStrategy = m.strategyTitle.toLowerCase().includes(q);
        if (!matchesFile && !matchesRule && !matchesTicket && !matchesAssignee && !matchesStrategy) {
          return false;
        }
      }
      return true;
    });
  }, [mappings, severityFilter, statusFilter, strategyFilter, searchQuery]);

  // Aggregate KPI metrics
  const kpis = useMemo(() => {
    const total = mappings.length;
    const ticketCount = mappings.filter((m) => m.ticket.status !== 'UNASSIGNED').length;
    const inProgressCount = mappings.filter((m) => m.ticket.status === 'IN_PROGRESS' || m.ticket.status === 'CODE_REVIEW').length;
    const remediatedCount = mappings.filter((m) => m.ticket.status === 'REMEDIATED').length;
    const criticalCount = mappings.filter((m) => m.findingSeverity === 'CRITICAL').length;
    const totalWorkflowPhases = mappings.reduce((acc, m) => acc + m.workflowPhases.length, 0);
    const completedPhases = mappings.reduce((acc, m) => acc + m.workflowPhases.filter((p) => p.completed).length, 0);
    const overallProgressPercent = totalWorkflowPhases > 0 ? Math.round((completedPhases / totalWorkflowPhases) * 100) : 0;

    return {
      total,
      ticketCount,
      inProgressCount,
      remediatedCount,
      criticalCount,
      overallProgressPercent
    };
  }, [mappings]);

  // Export tickets to CSV
  const handleExportCSV = () => {
    const headers = ['Ticket_ID', 'Platform', 'Status', 'Priority', 'Severity', 'Rule', 'File', 'Line', 'Assignee', 'SLA_Hours', 'Risk_Score', 'Strategy'];
    const rows = mappings.map((m) => [
      m.ticket.id,
      m.ticket.platform,
      m.ticket.status,
      m.ticket.priority,
      m.findingSeverity,
      `"${m.findingRule.replace(/"/g, '""')}"`,
      `"${m.findingFile.replace(/"/g, '""')}"`,
      m.findingLine,
      m.ticket.assignee,
      m.ticket.slaHours,
      m.riskScore,
      `"${m.strategyTitle.replace(/"/g, '""')}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `secscan_risk_mitigation_tickets_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div
      id="risk-mitigation-strategies-section"
      className="bg-[#080808] border-2 border-[#262626] p-6 lg:p-8 space-y-6 relative overflow-hidden transition-all shadow-2xl"
    >
      {/* Background Ambience */}
      <div className="absolute top-0 left-1/3 w-96 h-96 bg-[#FF3E00]/5 rounded-full blur-3xl pointer-events-none -mt-32" />
      <div className="absolute bottom-0 right-10 w-96 h-96 bg-[#00FF66]/5 rounded-full blur-3xl pointer-events-none -mb-32" />

      {/* ========================================================================= */}
      {/* 1. SECTION HEADER                                                        */}
      {/* ========================================================================= */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-[#1C1C1C] relative z-10">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="text-[10px] font-mono text-[#FF3E00] bg-[#FF3E00]/10 px-2.5 py-0.5 border border-[#FF3E00]/40 uppercase font-black tracking-widest flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-[#FF3E00]" />
              REMEDIATION ARCHITECTURE // WORKFLOW & TICKET MAPPING
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 border border-[#333] bg-[#121212] text-[#AAA] uppercase">
              DEVOPS & APPSec ORCHESTRATION
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/30 uppercase font-bold flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-[#00FF66]" />
              {kpis.remediatedCount}/{kpis.total} RESOLVIDOS ({kpis.overallProgressPercent}%)
            </span>
          </div>

          <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
            <span>Risk Mitigation Strategies</span>
          </h2>
          <p className="text-xs font-mono text-[#888] max-w-4xl leading-relaxed">
            Mapeamento direto de <strong>achados de alto risco (Crítico / Alto)</strong> para <strong>playbooks de remediação em 4 fases</strong> e <strong>tickets de segurança externos</strong> (Jira, GitHub Issues, ServiceNow, Linear). Gerencie status de contenção, SLA de mitigação e execute comandos de expurgo com controle de progresso interativo.
          </p>
        </div>

        {/* Global Action Toolbar */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            id="btn-export-tickets-csv"
            type="button"
            onClick={handleExportCSV}
            className="px-3.5 py-2 bg-[#121212] hover:bg-[#1C1C1C] border border-[#2E2E2E] text-white text-xs font-mono font-bold uppercase tracking-wider rounded flex items-center gap-2 transition-all cursor-pointer"
            title="Exportar tabela de tickets para CSV"
          >
            <Download className="w-3.5 h-3.5 text-[#00FF66]" />
            <span>Exportar CSV</span>
          </button>

          <button
            id="btn-reset-mitigation-mappings"
            type="button"
            onClick={handleResetToDefaults}
            className="p-2 bg-[#121212] hover:bg-[#1C1C1C] border border-[#2E2E2E] text-[#888] hover:text-white rounded transition-colors cursor-pointer"
            title="Restaurar estratégias para o estado padrão"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 2. KPI STRIP: STRATEGIES & TICKETS STATUS METRICS                        */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
        {/* KPI 1: High-Risk Findings Mapped */}
        <div className="p-4 bg-[#0C0C0C] border border-[#222] space-y-1.5">
          <div className="text-[10px] font-mono text-[#888] uppercase tracking-wider flex items-center justify-between">
            <span>Achados Mapeados</span>
            <AlertOctagon className="w-3.5 h-3.5 text-[#FF3E00]" />
          </div>
          <div className="text-2xl font-black font-mono text-white flex items-baseline gap-2">
            <span>{kpis.total}</span>
            <span className="text-xs text-[#FF3E00] font-bold">({kpis.criticalCount} Críticos)</span>
          </div>
          <div className="text-[10px] font-mono text-[#666]">
            Priorizados para contenção imediata
          </div>
        </div>

        {/* KPI 2: Active External Tickets */}
        <div className="p-4 bg-[#0C0C0C] border border-[#222] space-y-1.5">
          <div className="text-[10px] font-mono text-[#888] uppercase tracking-wider flex items-center justify-between">
            <span>Tickets Externos</span>
            <Ticket className="w-3.5 h-3.5 text-[#3399FF]" />
          </div>
          <div className="text-2xl font-black font-mono text-[#3399FF] flex items-baseline gap-2">
            <span>{kpis.ticketCount}</span>
            <span className="text-xs text-[#888] font-normal">vinculados</span>
          </div>
          <div className="text-[10px] font-mono text-[#777]">
            Jira, GitHub, ServiceNow & Linear
          </div>
        </div>

        {/* KPI 3: In Remediation Progress */}
        <div className="p-4 bg-[#0C0C0C] border border-[#222] space-y-1.5">
          <div className="text-[10px] font-mono text-[#888] uppercase tracking-wider flex items-center justify-between">
            <span>Em Andamento</span>
            <Clock className="w-3.5 h-3.5 text-[#FFB800]" />
          </div>
          <div className="text-2xl font-black font-mono text-[#FFB800] flex items-baseline gap-2">
            <span>{kpis.inProgressCount}</span>
            <span className="text-xs text-[#888] font-normal">workfows ativos</span>
          </div>
          <div className="text-[10px] font-mono text-[#666]">
            Mitigações sob execução de squads
          </div>
        </div>

        {/* KPI 4: Workflows Remediated */}
        <div className="p-4 bg-[#041409] border border-[#00FF66]/40 space-y-1.5">
          <div className="text-[10px] font-mono text-[#00FF66] uppercase tracking-wider flex items-center justify-between font-bold">
            <span>Mitigados / Fechados</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-[#00FF66]" />
          </div>
          <div className="text-2xl font-black font-mono text-[#00FF66] flex items-baseline gap-2">
            <span>{kpis.remediatedCount}</span>
            <span className="text-xs text-[#00FF66]/80 font-normal">concluídos</span>
          </div>
          <div className="w-full bg-[#1A1A1A] h-1.5 rounded-none overflow-hidden mt-1">
            <div
              className="bg-[#00FF66] h-full transition-all duration-500"
              style={{ width: `${kpis.overallProgressPercent}%` }}
            />
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 3. FILTERS & SEARCH CONTROL BAR                                          */}
      {/* ========================================================================= */}
      <div className="p-4 bg-[#0C0C0C] border border-[#222] space-y-3 font-mono text-xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          {/* Search Field */}
          <div className="relative flex-1 max-w-md">
            <Search className="w-3.5 h-3.5 text-[#777] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              id="input-mitigation-search"
              type="text"
              placeholder="Buscar por arquivo, regra, ticket (SEC-...) ou responsável..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#141414] border border-[#333] pl-9 pr-3 py-2 text-white placeholder-[#666] text-xs focus:border-[#00FF66] focus:outline-none transition-colors"
            />
          </div>

          {/* Quick Filter Pills */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Severity Filter */}
            <div className="flex items-center gap-1 bg-[#141414] border border-[#2C2C2C] p-1 rounded">
              <span className="text-[10px] text-[#777] px-1.5 uppercase font-bold">Severidade:</span>
              <button
                type="button"
                onClick={() => setSeverityFilter('ALL')}
                className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded cursor-pointer ${
                  severityFilter === 'ALL' ? 'bg-white text-black font-black' : 'text-[#888] hover:text-white'
                }`}
              >
                Todas
              </button>
              <button
                type="button"
                onClick={() => setSeverityFilter('CRITICAL')}
                className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded cursor-pointer ${
                  severityFilter === 'CRITICAL' ? 'bg-[#FF3E00] text-black font-black' : 'text-[#FF3E00] hover:bg-[#FF3E00]/20'
                }`}
              >
                Crítico
              </button>
              <button
                type="button"
                onClick={() => setSeverityFilter('HIGH')}
                className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded cursor-pointer ${
                  severityFilter === 'HIGH' ? 'bg-[#FF7A00] text-black font-black' : 'text-[#FF7A00] hover:bg-[#FF7A00]/20'
                }`}
              >
                Alto
              </button>
            </div>

            {/* Ticket Status Filter */}
            <div className="flex items-center gap-1 bg-[#141414] border border-[#2C2C2C] p-1 rounded">
              <span className="text-[10px] text-[#777] px-1.5 uppercase font-bold">Status:</span>
              <button
                type="button"
                onClick={() => setStatusFilter('ALL')}
                className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded cursor-pointer ${
                  statusFilter === 'ALL' ? 'bg-white text-black font-black' : 'text-[#888] hover:text-white'
                }`}
              >
                Todos
              </button>
              <button
                type="button"
                onClick={() => setStatusFilter('IN_PROGRESS')}
                className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded cursor-pointer ${
                  statusFilter === 'IN_PROGRESS' ? 'bg-[#FFB800] text-black font-black' : 'text-[#FFB800] hover:bg-[#FFB800]/20'
                }`}
              >
                Em Progresso
              </button>
              <button
                type="button"
                onClick={() => setStatusFilter('REMEDIATED')}
                className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded cursor-pointer ${
                  statusFilter === 'REMEDIATED' ? 'bg-[#00FF66] text-black font-black' : 'text-[#00FF66] hover:bg-[#00FF66]/20'
                }`}
              >
                Resolvidos
              </button>
            </div>

            {/* Expand / Collapse All */}
            <button
              type="button"
              onClick={() => {
                if (expandedFindingIds.size === filteredMappings.length) {
                  setExpandedFindingIds(new Set());
                } else {
                  setExpandedFindingIds(new Set(filteredMappings.map((m) => m.findingId)));
                }
              }}
              className="px-2.5 py-1.5 border border-[#333] hover:border-[#666] bg-[#141414] text-[#AAA] hover:text-white text-[11px] rounded transition-colors cursor-pointer"
            >
              {expandedFindingIds.size === filteredMappings.length ? 'Recolher Todos' : 'Expandir Todos'}
            </button>
          </div>
        </div>

        {/* Counter Summary */}
        <div className="flex items-center justify-between text-[11px] text-[#777] pt-2 border-t border-[#1C1C1C]">
          <span>Mostrando {filteredMappings.length} de {mappings.length} achados prioritários</span>
          <span className="text-[#00FF66]">✓ Clique nas etapas para marcar progresso da remediação</span>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 4. MAPPINGS LIST: FINDINGS TO WORKFLOWS & TICKETS                        */}
      {/* ========================================================================= */}
      <div className="space-y-4">
        {filteredMappings.length === 0 ? (
          <div className="p-8 bg-[#0C0C0C] border border-[#222] text-center space-y-3">
            <CheckCircle2 className="w-8 h-8 text-[#00FF66] mx-auto" />
            <div className="font-mono text-sm font-bold text-white">
              Nenhum achado encontrado com os filtros selecionados
            </div>
            <p className="text-xs font-mono text-[#888]">
              Tente redefinir os filtros ou utilize o botão de reset para recarregar o mapeamento padrão.
            </p>
          </div>
        ) : (
          filteredMappings.map((mapping, idx) => {
            const isExpanded = expandedFindingIds.has(mapping.findingId);
            const statusStyle = STATUS_CONFIG[mapping.ticket.status];
            const platformStyle = PLATFORM_CONFIG[mapping.ticket.platform];
            const completedCount = mapping.workflowPhases.filter((p) => p.completed).length;
            const totalPhases = mapping.workflowPhases.length;
            const progressRatio = totalPhases > 0 ? (completedCount / totalPhases) * 100 : 0;
            const isCopied = copiedKey === mapping.findingId;

            return (
              <div
                key={mapping.findingId}
                id={`mitigation-card-${mapping.findingId}`}
                className={`border transition-all relative overflow-hidden ${
                  isExpanded ? 'bg-[#0A0A0A] border-[#383838] shadow-lg' : 'bg-[#090909] border-[#202020] hover:border-[#303030]'
                }`}
              >
                {/* Accent line on left */}
                <div
                  className={`absolute top-0 left-0 bottom-0 w-1 ${
                    mapping.findingSeverity === 'CRITICAL'
                      ? 'bg-[#FF3E00]'
                      : mapping.findingSeverity === 'HIGH'
                      ? 'bg-[#FF7A00]'
                      : 'bg-[#00FF66]'
                  }`}
                />

                {/* Card Main Row (Always Visible) */}
                <div className="p-4 sm:p-5 pl-5 sm:pl-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  {/* Left: Finding & Strategy Overview */}
                  <div className="space-y-2 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      {/* Severity Pill */}
                      <span
                        className={`text-[10px] font-mono font-black uppercase px-2 py-0.5 border ${
                          mapping.findingSeverity === 'CRITICAL'
                            ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/50'
                            : 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/50'
                        }`}
                      >
                        {mapping.findingSeverity}
                      </span>

                      {/* Risk Score */}
                      <span className="text-[10px] font-mono bg-[#141414] text-[#AAA] border border-[#333] px-2 py-0.5">
                        RISK SCORE: <strong className="text-white">{mapping.riskScore}</strong>
                      </span>

                      {/* File badge */}
                      <button
                        type="button"
                        onClick={() => onNavigateToFile?.(mapping.findingFile)}
                        className="text-[11px] font-mono text-[#DDD] hover:text-[#00FF66] flex items-center gap-1 hover:underline cursor-pointer"
                        title="Abrir arquivo no editor"
                      >
                        <FileCode className="w-3.5 h-3.5 text-[#00FF66]" />
                        <span>{mapping.findingFile}:{mapping.findingLine}</span>
                      </button>
                    </div>

                    {/* Rule title & Strategy Name */}
                    <div>
                      <h3 className="text-sm sm:text-base font-black font-mono text-white flex items-center gap-2">
                        <span>{mapping.findingRule}</span>
                        <ArrowRight className="w-3.5 h-3.5 text-[#666]" />
                        <span className="text-[#00FF66] font-bold">{mapping.strategyTitle}</span>
                      </h3>
                      <p className="text-xs font-mono text-[#888] line-clamp-1 mt-0.5">
                        {mapping.strategySummary}
                      </p>
                    </div>

                    {/* Workflow Progress Bar */}
                    <div className="flex items-center gap-3 pt-1">
                      <div className="w-32 bg-[#1C1C1C] h-1.5 rounded-none overflow-hidden">
                        <div
                          className="bg-[#00FF66] h-full transition-all duration-300"
                          style={{ width: `${progressRatio}%` }}
                        />
                      </div>
                      <span className="text-[10px] font-mono text-[#AAA]">
                        {completedCount}/{totalPhases} etapas concluídas ({Math.round(progressRatio)}%)
                      </span>
                      <span className="text-[10px] font-mono text-[#666]">
                        • Esforço est.: ~{mapping.estimatedEffortHours}h
                      </span>
                    </div>
                  </div>

                  {/* Right: External Ticket Badges & Actions */}
                  <div className="flex flex-wrap items-center gap-3 shrink-0">
                    {/* Platform + Ticket ID Badge */}
                    <div className="flex items-center gap-1.5">
                      <span className={`text-[10px] font-mono px-2 py-1 border font-bold uppercase rounded ${platformStyle.badgeClass}`}>
                        {mapping.ticket.platform} • {mapping.ticket.id}
                      </span>

                      {/* Ticket Status Select Dropdown */}
                      <select
                        id={`select-status-${mapping.findingId}`}
                        value={mapping.ticket.status}
                        onChange={(e) => handleChangeTicketStatus(mapping.findingId, e.target.value as TicketStatus)}
                        className={`text-[10px] font-mono font-bold uppercase px-2 py-1 border rounded bg-[#121212] focus:outline-none cursor-pointer ${statusStyle.colorClass} ${statusStyle.bgClass}`}
                        title="Alterar status do ticket de segurança"
                      >
                        <option value="UNASSIGNED">Sem Ticket</option>
                        <option value="TICKET_CREATED">Ticket Criado</option>
                        <option value="IN_PROGRESS">Em Progresso</option>
                        <option value="CODE_REVIEW">Code Review (PR)</option>
                        <option value="REMEDIATED">Mitigado / Resolvido</option>
                        <option value="RISK_ACCEPTED">Risco Aceito</option>
                      </select>
                    </div>

                    {/* SLA Countdown Badge */}
                    <div className="text-[10px] font-mono px-2 py-1 bg-[#121212] border border-[#2C2C2C] text-[#CCC] flex items-center gap-1">
                      <Clock className="w-3 h-3 text-[#FFB800]" />
                      <span>SLA: {mapping.ticket.slaRemainingHours}h restantes</span>
                    </div>

                    {/* Copy Ticket Payload Button */}
                    <button
                      id={`btn-copy-ticket-${mapping.findingId}`}
                      type="button"
                      onClick={() => handleCopyTicketPayload(mapping)}
                      className={`p-2 border text-xs font-mono rounded transition-colors cursor-pointer flex items-center gap-1 ${
                        isCopied
                          ? 'bg-[#00FF66]/20 text-[#00FF66] border-[#00FF66]'
                          : 'bg-[#141414] hover:bg-[#1E1E1E] text-[#888] hover:text-white border-[#333]'
                      }`}
                      title="Copiar especificação de ticket formatada em Markdown para Jira/GitHub"
                    >
                      {isCopied ? <Check className="w-3.5 h-3.5 text-[#00FF66]" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>

                    {/* Deep Link to Ticket (simulated) */}
                    <a
                      id={`link-ticket-${mapping.findingId}`}
                      href={mapping.ticket.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-2 bg-[#141414] hover:bg-[#1E1E1E] border border-[#333] hover:border-[#555] text-[#888] hover:text-white rounded transition-colors cursor-pointer"
                      title={`Abrir ticket ${mapping.ticket.id} no ${platformStyle.label}`}
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>

                    {/* Expand/Collapse Toggle Button */}
                    <button
                      id={`btn-expand-card-${mapping.findingId}`}
                      type="button"
                      onClick={() => toggleExpand(mapping.findingId)}
                      className="p-2 bg-[#181818] hover:bg-[#242424] border border-[#383838] text-white rounded transition-colors cursor-pointer"
                      title={isExpanded ? 'Recolher detalhes do workflow' : 'Expandir etapas do workflow'}
                    >
                      {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                {/* Expanded Accordion: Remediation Workflow Execution & Ticket Details */}
                {isExpanded && (
                  <div className="p-5 pl-6 sm:p-6 sm:pl-8 bg-[#060606] border-t border-[#1C1C1C] space-y-6">
                    {/* Top Detail Bar: Assignee & Platform Config */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3.5 bg-[#0C0C0C] border border-[#222] font-mono text-xs">
                      <div className="space-y-1">
                        <span className="text-[10px] text-[#777] uppercase flex items-center gap-1">
                          <User className="w-3 h-3 text-[#3399FF]" />
                          Responsável (Security Champion):
                        </span>
                        <div className="text-white font-bold">{mapping.ticket.assignee}</div>
                      </div>

                      <div className="space-y-1">
                        <span className="text-[10px] text-[#777] uppercase flex items-center gap-1">
                          <Ticket className="w-3 h-3 text-[#00FF66]" />
                          Plataforma de Tickets:
                        </span>
                        <select
                          value={mapping.ticket.platform}
                          onChange={(e) => handleChangeTicketPlatform(mapping.findingId, e.target.value as TicketPlatform)}
                          className="bg-[#141414] border border-[#333] text-white text-xs px-2 py-0.5 rounded cursor-pointer"
                        >
                          <option value="JIRA">Jira Software</option>
                          <option value="GITHUB">GitHub Issues</option>
                          <option value="GITLAB">GitLab Security</option>
                          <option value="SERVICENOW">ServiceNow SecOps</option>
                          <option value="LINEAR">Linear App</option>
                        </select>
                      </div>

                      <div className="space-y-1">
                        <span className="text-[10px] text-[#777] uppercase flex items-center gap-1">
                          <Clock className="w-3 h-3 text-[#FFB800]" />
                          Tempo Limite de Mitigação:
                        </span>
                        <div className="text-white font-bold">
                          {mapping.ticket.slaHours} horas (restam {mapping.ticket.slaRemainingHours}h)
                        </div>
                      </div>
                    </div>

                    {/* Workflow Checklist: 4-Phase Strategy Execution */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between text-xs font-mono text-[#888]">
                        <span className="uppercase font-bold text-white flex items-center gap-2">
                          <Layers className="w-3.5 h-3.5 text-[#00FF66]" />
                          Playbook de Remediação & Checklist de Execução
                        </span>
                        <span className="text-[11px] text-[#00FF66]">
                          {completedCount} de {totalPhases} fases validadas
                        </span>
                      </div>

                      <div className="space-y-2.5">
                        {mapping.workflowPhases.map((phase) => (
                          <div
                            key={phase.id}
                            className={`p-3.5 border transition-all ${
                              phase.completed
                                ? 'bg-[#041409] border-[#00FF66]/30'
                                : 'bg-[#0C0C0C] border-[#222]'
                            }`}
                          >
                            <div className="flex items-start gap-3">
                              <button
                                type="button"
                                onClick={() => handleToggleWorkflowPhase(mapping.findingId, phase.id)}
                                className="mt-0.5 text-[#00FF66] hover:scale-110 transition-transform cursor-pointer"
                                title={phase.completed ? 'Marcar fase como pendente' : 'Marcar fase como concluída'}
                              >
                                {phase.completed ? (
                                  <CheckSquare className="w-4 h-4 text-[#00FF66]" />
                                ) : (
                                  <Square className="w-4 h-4 text-[#666]" />
                                )}
                              </button>

                              <div className="space-y-1 flex-1 font-mono text-xs">
                                <div className="flex items-center justify-between">
                                  <span className={`font-bold ${phase.completed ? 'text-[#00FF66] line-through' : 'text-white'}`}>
                                    {phase.title}
                                  </span>
                                  {phase.completed && (
                                    <span className="text-[10px] text-[#00FF66] font-mono uppercase bg-[#00FF66]/10 px-1.5 py-0.2 border border-[#00FF66]/30">
                                      Concluído
                                    </span>
                                  )}
                                </div>
                                <p className="text-[11px] text-[#888] leading-relaxed">
                                  {phase.description}
                                </p>

                                {/* CLI Command block if present */}
                                {phase.cliCommand && (
                                  <div className="mt-2 bg-[#000] border border-[#242424] p-2 flex items-center justify-between gap-2">
                                    <div className="flex items-center gap-2 overflow-x-auto text-[11px] text-[#00FF66]">
                                      <Terminal className="w-3 h-3 text-[#777] shrink-0" />
                                      <code>{phase.cliCommand}</code>
                                    </div>
                                    <button
                                      type="button"
                                      onClick={() => {
                                        navigator.clipboard.writeText(phase.cliCommand || '');
                                        setCopiedKey(`${mapping.findingId}-${phase.id}`);
                                        setTimeout(() => setCopiedKey(null), 2000);
                                      }}
                                      className="p-1 text-[#888] hover:text-white shrink-0 cursor-pointer"
                                      title="Copiar comando de terminal"
                                    >
                                      {copiedKey === `${mapping.findingId}-${phase.id}` ? (
                                        <Check className="w-3 h-3 text-[#00FF66]" />
                                      ) : (
                                        <Copy className="w-3 h-3" />
                                      )}
                                    </button>
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Bottom Action Footer for this Finding */}
                    <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-[#1C1C1C] font-mono text-xs">
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => {
                            if (onSelectFinding) {
                              const target = report.findings.find((f) => f.id === mapping.findingId);
                              if (target) onSelectFinding(target);
                            }
                            onNavigateToScanner?.();
                          }}
                          className="px-3 py-1.5 bg-[#141414] hover:bg-[#1F1F1F] border border-[#333] text-white rounded flex items-center gap-1.5 transition-colors cursor-pointer"
                        >
                          <Eye className="w-3.5 h-3.5 text-[#00FF66]" />
                          <span>Inspecionar no Scanner</span>
                        </button>

                        <button
                          type="button"
                          onClick={() => onNavigateToFile?.(mapping.findingFile)}
                          className="px-3 py-1.5 bg-[#141414] hover:bg-[#1F1F1F] border border-[#333] text-[#AAA] hover:text-white rounded flex items-center gap-1.5 transition-colors cursor-pointer"
                        >
                          <FileCode className="w-3.5 h-3.5 text-[#3399FF]" />
                          <span>Abrir Arquivo ({mapping.findingFile})</span>
                        </button>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => handleCopyTicketPayload(mapping)}
                          className="px-3 py-1.5 bg-[#00FF66] hover:bg-[#00D655] text-black font-black uppercase text-[11px] rounded flex items-center gap-1.5 transition-all cursor-pointer shadow-[0_0_10px_rgba(0,255,102,0.2)]"
                        >
                          <Share2 className="w-3.5 h-3.5" />
                          <span>Copiar Payload para {platformStyle.label}</span>
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
