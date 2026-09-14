import React, { useState, useMemo, useEffect, useCallback } from 'react';
import {
  ListOrdered,
  CheckCircle2,
  Clock,
  ExternalLink,
  BookOpen,
  FileCode,
  Terminal,
  Copy,
  Check,
  Search,
  Filter,
  ArrowRight,
  ShieldAlert,
  Flame,
  AlertOctagon,
  AlertTriangle,
  RotateCcw,
  Download,
  Share2,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Zap,
  Code2,
  Info,
  ShieldCheck,
  CheckSquare,
  Square,
  Layers,
  FileText
} from 'lucide-react';
import { ScanReport, ScanFinding, SeverityLevel, FindingCategory } from '../types';
import { 
  getRemediationGuideForFinding, 
  getOfficialDocLinksForFinding, 
  RemediationWikiGuide, 
  OfficialDocLink 
} from '../lib/remediationWikiData';
import { 
  getGlossaryEntryForFinding, 
  SecurityGlossaryEntry 
} from '../lib/securityGlossary';
import { safeGetItem, safeSetItem } from '../lib/storage';

export type TaskPriority = 'P0' | 'P1' | 'P2' | 'P3';
export type TaskStatus = 'TODO' | 'IN_PROGRESS' | 'DONE';

export interface DeveloperRemediationTask {
  id: string;
  taskNumber: number;
  priority: TaskPriority;
  priorityLabel: string;
  slaTargetHours: string;
  title: string;
  description: string;
  category: FindingCategory;
  severity: SeverityLevel;
  primaryFinding: ScanFinding;
  allFindings: ScanFinding[];
  estimatedHours: number;
  riskReductionPoints: number;
  remediationPhase: 'IMMEDIATE_ROTATION' | 'HISTORY_PURGE' | 'VAULT_MIGRATION' | 'PIPELINE_GUARD';
  phaseLabel: string;
  cliCommand?: string;
  cliLanguage?: 'bash' | 'typescript' | 'env';
  cliDescription?: string;
  officialDocLinks: OfficialDocLink[];
  glossaryEntry?: SecurityGlossaryEntry;
  wikiGuide?: RemediationWikiGuide;
  remediationSteps: string[];
  safeCodePattern?: {
    bad: string;
    good: string;
    explanation: string;
  };
}

export interface StrategicRemediationPlanProps {
  report: ScanReport;
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToFinding?: (findingId: string) => void;
  onNavigateToScanner?: () => void;
  onNavigateToFile?: (filePath: string) => void;
  onOpenGlossary?: (entry?: SecurityGlossaryEntry) => void;
}

const STORAGE_KEY_TASKS_STATUS = 'secscan_strategic_plan_tasks_status_v1';

const PRIORITY_THEMES: Record<
  TaskPriority,
  {
    badgeBg: string;
    badgeText: string;
    borderColor: string;
    accentColor: string;
    dotColor: string;
  }
> = {
  P0: {
    badgeBg: 'bg-[#FF3E00]/15',
    badgeText: 'text-[#FF3E00]',
    borderColor: 'border-[#FF3E00]/50',
    accentColor: '#FF3E00',
    dotColor: 'bg-[#FF3E00]'
  },
  P1: {
    badgeBg: 'bg-[#FF7A00]/15',
    badgeText: 'text-[#FF7A00]',
    borderColor: 'border-[#FF7A00]/50',
    accentColor: '#FF7A00',
    dotColor: 'bg-[#FF7A00]'
  },
  P2: {
    badgeBg: 'bg-[#EAB308]/15',
    badgeText: 'text-[#EAB308]',
    borderColor: 'border-[#EAB308]/50',
    accentColor: '#EAB308',
    dotColor: 'bg-[#EAB308]'
  },
  P3: {
    badgeBg: 'bg-[#3366FF]/15',
    badgeText: 'text-[#3366FF]',
    borderColor: 'border-[#3366FF]/50',
    accentColor: '#3366FF',
    dotColor: 'bg-[#3366FF]'
  }
};

/**
 * Builds developer-centric tasks from active scan findings,
 * grouping correlated vulnerabilities into strategic engineering items.
 */
function buildDeveloperTasks(findings: ScanFinding[]): DeveloperRemediationTask[] {
  const activeFindings = findings.filter((f) => !f.isFalsePositive);

  if (activeFindings.length === 0) {
    return [];
  }

  // Group findings by rule/category pattern to prevent fragmented duplicate tasks
  const groups = new Map<string, ScanFinding[]>();

  activeFindings.forEach((finding) => {
    // Generate a cohesive group key
    let groupKey = `${finding.category}__${finding.ruleId}`;
    if (finding.ruleId.startsWith('sec-aws')) {
      groupKey = 'CLOUD_CREDENTIAL__aws-iam';
    } else if (finding.ruleId.startsWith('sec-stripe')) {
      groupKey = 'API_KEY__stripe-payment';
    } else if (finding.ruleId.startsWith('sec-github') || finding.ruleId.startsWith('sec-gitlab')) {
      groupKey = 'AUTH_TOKEN__vcs-pat';
    } else if (finding.ruleId.startsWith('sec-jwt')) {
      groupKey = 'AUTH_TOKEN__jwt-hardcoded';
    } else if (finding.category === 'DATABASE_URI') {
      groupKey = 'DATABASE_URI__db-credentials';
    } else if (finding.category === 'PRIVATE_KEY') {
      groupKey = 'PRIVATE_KEY__crypto-keys';
    }

    if (!groups.has(groupKey)) {
      groups.set(groupKey, []);
    }
    groups.get(groupKey)!.push(finding);
  });

  const tasks: DeveloperRemediationTask[] = [];
  let taskCounter = 1;

  groups.forEach((groupFindings) => {
    // Sort highest severity first
    groupFindings.sort((a, b) => {
      const order: Record<SeverityLevel, number> = {
        CRITICAL: 4,
        HIGH: 3,
        MEDIUM: 2,
        LOW: 1,
        INFO: 0
      };
      return order[b.severity] - order[a.severity];
    });

    const primary = groupFindings[0];
    const wikiGuide = getRemediationGuideForFinding(primary);
    const glossaryEntry = getGlossaryEntryForFinding(primary);
    const officialDocLinks = getOfficialDocLinksForFinding(primary);

    // Determine priority based on severity & blast radius
    let priority: TaskPriority = 'P2';
    let priorityLabel = 'P2 • Médio Risco';
    let slaTargetHours = '72h (Sprint Atual)';
    let estimatedHours = 2.0;
    let riskReductionPoints = 12;
    let remediationPhase: DeveloperRemediationTask['remediationPhase'] = 'VAULT_MIGRATION';
    let phaseLabel = 'Fase 3 • Migração para Vault';
    let taskTitle = `Remediar ${primary.ruleName}`;
    let taskDescription = primary.description;
    let cliCommand = '';
    let cliLanguage: 'bash' | 'typescript' | 'env' = 'bash';
    let cliDescription = '';

    const firstStep = wikiGuide?.stepByStepPatching?.[0];
    const safePattern = wikiGuide?.beforeAfterCode || glossaryEntry?.safePattern;

    if (primary.severity === 'CRITICAL') {
      priority = 'P0';
      priorityLabel = 'P0 • Bloqueador Crítico';
      slaTargetHours = '0-4h (Imediato)';
      remediationPhase = 'IMMEDIATE_ROTATION';
      phaseLabel = 'Fase 1 • Rotação Imediata';
      estimatedHours = 1.5;
      riskReductionPoints = Math.min(30, 18 + groupFindings.length * 4);

      if (primary.category === 'CLOUD_CREDENTIAL') {
        taskTitle = 'Revogar Credenciais de Nuvem e Rotacionar IAM Access Keys';
        taskDescription =
          'Chaves de infraestrutura de nuvem foram detectadas no repositório. Revogue as chaves no console do provedor, verifique logs de auditoria (ex: CloudTrail) e substitua por Workload Identity ou IAM Roles temporárias.';
        cliCommand = `# 1. Desativar chave exposta no IAM\naws iam update-access-key --access-key-id ${primary.maskedSecret || 'AKIA...'} --status Inactive\n\n# 2. Gerar novo par de chaves temporárias para desenvolvimento local\naws iam create-access-key --user-name svc-backend-app\n\n# 3. Purgar arquivo do histórico do Git\ngit-filter-repo --path ${primary.file} --invert-paths --force`;
        cliDescription = 'CLI AWS & Git Filter para rotação e expurgo';
      } else if (primary.category === 'DATABASE_URI') {
        taskTitle = 'Sanitizar Strings de Conexão com Banco de Dados e Rotacionar Senhas';
        taskDescription =
          'URIs contendo senhas em texto plano foram encontradas. Force a rotação da senha no banco de dados e migre a conexão para variáveis de ambiente protegidas em runtime.';
        cliCommand = `# Injetar connection string em tempo de execução via variável de ambiente\nexport DATABASE_URL="postgresql://\${DB_USER}:\${DB_PASSWORD}@\${DB_HOST}:5432/\${DB_NAME}?sslmode=require"`;
        cliDescription = 'Template de injeção em runtime via variáveis seguras';
      } else if (primary.category === 'PRIVATE_KEY') {
        taskTitle = 'Substituir Chaves Privadas Criptográficas (RSA/SSH) e Revogar Certificados';
        taskDescription =
          'Chave privada comprometida no código permite interceptação TLS e falsificação de assinaturas. Revogue o certificado associado e gere novo par de chaves via HSM/KMS.';
        cliCommand = `# Gerar novo par de chaves RSA 4096-bits em arquivo seguro fora da raiz do repositório\nssh-keygen -t rsa -b 4096 -f ~/.ssh/id_production_app -C "deploy@security.corp"`;
        cliDescription = 'Geração segura de par de chaves criptográficas';
      } else {
        taskTitle = `Revogar Segredo Crítico Ativo: ${primary.ruleName}`;
        taskDescription =
          'Credencial sensível exposta no código-fonte. Realize rotação imediata no provedor do serviço e invalide tokens ativos.';
        cliCommand = `# Rotação imediata via console do provedor e expurgo do histórico\ngit filter-branch --force --index-filter "git rm --cached --ignore-unmatch ${primary.file}" HEAD`;
        cliDescription = 'Comando de contenção rápida no histórico Git';
      }
    } else if (primary.severity === 'HIGH') {
      priority = 'P1';
      priorityLabel = 'P1 • Alto Risco';
      slaTargetHours = '24h (Dia Seguinte)';
      remediationPhase = 'HISTORY_PURGE';
      phaseLabel = 'Fase 2 • Expurgo & Isolamento';
      estimatedHours = 2.0;
      riskReductionPoints = Math.min(22, 12 + groupFindings.length * 3);

      if (primary.category === 'API_KEY') {
        taskTitle = `Rotacionar Chaves de API de Serviços Terceiros (${primary.ruleName})`;
        taskDescription =
          'Chaves de produção para provedores de pagamento ou serviços de IA detectadas. Crie novas credenciais restritas por IP/origem e remova do controle de versão.';
        cliCommand = `# Configurar no gerenciador local seguro (.env ignorado)\nSTRIPE_SECRET_KEY=sk_live_...\nOPENAI_API_KEY=sk-proj-...\n\n# Verificar se .env está no .gitignore\ngrep -q '^\\.env$' .gitignore || echo '.env' >> .gitignore`;
        cliDescription = 'Configuração segura com .env e garantia de .gitignore';
      } else if (primary.category === 'AUTH_TOKEN') {
        taskTitle = 'Revogar Tokens de Autenticação Pessoal (PAT) e Sessões JWT';
        taskDescription =
          'Tokens com escopo de escrita ou tokens JWT com assinaturas fracas estão expostos. Invalide no GitHub/GitLab e adote expiração curta com chaves assimétricas RS256.';
        cliCommand = `# Revogar token pessoal e migrar para GitHub App ou Secret Scanning com push protection\ngh secret set API_AUTH_TOKEN --body "\${SECURE_TOKEN}"`;
        cliDescription = 'Injeção de segredos via GitHub CLI';
      } else {
        taskTitle = `Mitigar Risco Alto: ${primary.ruleName}`;
        taskDescription = primary.description;
        cliCommand = `# Sanitizar arquivo de configuração\ngit rm --cached ${primary.file}\necho "${primary.file}" >> .gitignore`;
        cliDescription = 'Remover do tracking do Git e proteger no .gitignore';
      }
    } else if (primary.severity === 'MEDIUM') {
      priority = 'P2';
      priorityLabel = 'P2 • Médio Risco';
      slaTargetHours = '7 dias (Próxima Release)';
      remediationPhase = 'VAULT_MIGRATION';
      phaseLabel = 'Fase 3 • Centralização em Vault';
      estimatedHours = 1.0;
      riskReductionPoints = 8;
      taskTitle = `Desacoplar Configurações Sensíveis (${primary.ruleName})`;
      taskDescription =
        'Parâmetros e senhas de ambiente ou chaves secundárias gravadas estaticamente. Centralize em Secrets Manager / Doppler para injeção limpa.';
      cliCommand = `# Instalar Doppler CLI ou AWS Secrets Manager SDK para injeção em runtime\nnpm install @aws-sdk/client-secrets-manager`;
      cliDescription = 'Adição de SDK de Vault';
    } else {
      priority = 'P3';
      priorityLabel = 'P3 • Higiene Contínua';
      slaTargetHours = 'Contínuo (Higiene de Código)';
      remediationPhase = 'PIPELINE_GUARD';
      phaseLabel = 'Fase 4 • Governança & CI/CD';
      estimatedHours = 0.5;
      riskReductionPoints = 4;
      taskTitle = `Padronizar Políticas e Pre-Commit Hooks (${primary.ruleName})`;
      taskDescription =
        'Evitar reincidência de vulnerabilidades de baixa severidade e endpoints administrativos através de quality gates automatizados no pipeline.';
      cliCommand = `# Instalar pre-commit hook com detecção automatizada de segredos\nnpx husky add .husky/pre-commit "npm run lint && npm run scan:secrets"`;
      cliDescription = 'Quality Gate em Pre-Commit Hook via Husky';
    }

    // Default remediation steps from wiki or glossary
    const steps: string[] = [];
    if (wikiGuide?.stepByStepPatching && wikiGuide.stepByStepPatching.length > 0) {
      wikiGuide.stepByStepPatching.forEach((s) => steps.push(`${s.title}: ${s.description}`));
    } else if (glossaryEntry?.remediationSteps && glossaryEntry.remediationSteps.length > 0) {
      steps.push(...glossaryEntry.remediationSteps);
    } else {
      steps.push('Revogar a credencial exposta no provedor de identidade ou nuvem.');
      steps.push('Remover o valor em texto plano do arquivo de código-fonte.');
      steps.push('Adicionar a variável de ambiente no arquivo .env seguro.');
      steps.push('Validar que o histórico do Git não contém o commit com o segredo.');
    }

    tasks.push({
      id: `task-${primary.ruleId}-${primary.line}`,
      taskNumber: taskCounter++,
      priority,
      priorityLabel,
      slaTargetHours,
      title: taskTitle,
      description: taskDescription,
      category: primary.category,
      severity: primary.severity,
      primaryFinding: primary,
      allFindings: groupFindings,
      estimatedHours,
      riskReductionPoints,
      remediationPhase,
      phaseLabel,
      cliCommand,
      cliLanguage,
      cliDescription,
      officialDocLinks,
      glossaryEntry,
      wikiGuide,
      remediationSteps: steps,
      safeCodePattern: safePattern
        ? {
            bad: 'bad' in safePattern ? safePattern.bad : ('before' in safePattern ? safePattern.before : ''),
            good: 'good' in safePattern ? safePattern.good : ('after' in safePattern ? safePattern.after : ''),
            explanation: safePattern.explanation || ''
          }
        : undefined
    });
  });

  // Sort tasks strictly: P0 first, then P1, then P2, then P3
  const priorityWeight: Record<TaskPriority, number> = {
    P0: 4,
    P1: 3,
    P2: 2,
    P3: 1
  };

  tasks.sort((a, b) => {
    if (priorityWeight[b.priority] !== priorityWeight[a.priority]) {
      return priorityWeight[b.priority] - priorityWeight[a.priority];
    }
    return b.allFindings.length - a.allFindings.length;
  });

  // Re-number sequentially for developers
  tasks.forEach((t, idx) => {
    t.taskNumber = idx + 1;
  });

  return tasks;
}

export const StrategicRemediationPlan: React.FC<StrategicRemediationPlanProps> = ({
  report,
  onSelectFinding,
  onNavigateToFinding,
  onNavigateToScanner,
  onNavigateToFile,
  onOpenGlossary
}) => {
  const [copiedTaskId, setCopiedTaskId] = useState<string | null>(null);
  const [copiedPlanMarkdown, setCopiedPlanMarkdown] = useState(false);
  const [expandedTaskId, setExpandedTaskId] = useState<string | null>(null);

  // Filters
  const [priorityFilter, setPriorityFilter] = useState<'ALL' | TaskPriority>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | TaskStatus>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Persisted task status map (taskId -> 'TODO' | 'IN_PROGRESS' | 'DONE')
  const [taskStatusMap, setTaskStatusMap] = useState<Record<string, TaskStatus>>(() => {
    const saved = safeGetItem(STORAGE_KEY_TASKS_STATUS);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (typeof parsed === 'object' && parsed !== null) {
          return parsed;
        }
      } catch {
        // fallback
      }
    }
    return {};
  });

  // Save status changes to local storage
  const handleToggleTaskStatus = useCallback((taskId: string, currentStatus: TaskStatus) => {
    setTaskStatusMap((prev) => {
      let nextStatus: TaskStatus = 'IN_PROGRESS';
      if (currentStatus === 'TODO') {
        nextStatus = 'IN_PROGRESS';
      } else if (currentStatus === 'IN_PROGRESS') {
        nextStatus = 'DONE';
      } else {
        nextStatus = 'TODO';
      }

      const updated = {
        ...prev,
        [taskId]: nextStatus
      };
      safeSetItem(STORAGE_KEY_TASKS_STATUS, JSON.stringify(updated));
      return updated;
    });
  }, []);

  const handleSetDirectStatus = useCallback((taskId: string, status: TaskStatus) => {
    setTaskStatusMap((prev) => {
      const updated = {
        ...prev,
        [taskId]: status
      };
      safeSetItem(STORAGE_KEY_TASKS_STATUS, JSON.stringify(updated));
      return updated;
    });
  }, []);

  const handleResetAllTasks = useCallback(() => {
    setTaskStatusMap({});
    safeSetItem(STORAGE_KEY_TASKS_STATUS, JSON.stringify({}));
  }, []);

  // Generate developer tasks from scan findings
  const allTasks = useMemo(() => {
    return buildDeveloperTasks(report?.findings || []);
  }, [report?.findings]);

  // Compute summary metrics
  const stats = useMemo(() => {
    const totalCount = allTasks.length;
    let completedCount = 0;
    let inProgressCount = 0;
    let totalHours = 0;
    let completedHours = 0;
    let totalRiskPoints = 0;
    let mitigatedRiskPoints = 0;

    const priorityCounts: Record<TaskPriority, number> = {
      P0: 0,
      P1: 0,
      P2: 0,
      P3: 0
    };

    allTasks.forEach((task) => {
      priorityCounts[task.priority]++;
      totalHours += task.estimatedHours;
      totalRiskPoints += task.riskReductionPoints;

      const status = taskStatusMap[task.id] || 'TODO';
      if (status === 'DONE') {
        completedCount++;
        completedHours += task.estimatedHours;
        mitigatedRiskPoints += task.riskReductionPoints;
      } else if (status === 'IN_PROGRESS') {
        inProgressCount++;
      }
    });

    const completionPercent = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 100;
    const remainingHours = Math.max(0, Math.round((totalHours - completedHours) * 10) / 10);

    return {
      totalCount,
      completedCount,
      inProgressCount,
      todoCount: totalCount - completedCount - inProgressCount,
      completionPercent,
      totalHours: Math.round(totalHours * 10) / 10,
      completedHours: Math.round(completedHours * 10) / 10,
      remainingHours,
      totalRiskPoints,
      mitigatedRiskPoints,
      priorityCounts
    };
  }, [allTasks, taskStatusMap]);

  // Filter tasks
  const filteredTasks = useMemo(() => {
    return allTasks.filter((task) => {
      const status = taskStatusMap[task.id] || 'TODO';

      if (priorityFilter !== 'ALL' && task.priority !== priorityFilter) {
        return false;
      }

      if (statusFilter !== 'ALL' && status !== statusFilter) {
        return false;
      }

      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesTitle = task.title.toLowerCase().includes(query);
        const matchesDesc = task.description.toLowerCase().includes(query);
        const matchesRule = task.primaryFinding.ruleName.toLowerCase().includes(query);
        const matchesFile = task.allFindings.some((f) => f.file.toLowerCase().includes(query));
        const matchesDocs = task.officialDocLinks.some((d) => d.title.toLowerCase().includes(query));

        if (!matchesTitle && !matchesDesc && !matchesRule && !matchesFile && !matchesDocs) {
          return false;
        }
      }

      return true;
    });
  }, [allTasks, taskStatusMap, priorityFilter, statusFilter, searchQuery]);

  // Copy CLI command
  const handleCopyCommand = useCallback((taskId: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedTaskId(taskId);
    setTimeout(() => {
      setCopiedTaskId(null);
    }, 2000);
  }, []);

  // Export Developer Plan as Markdown
  const handleExportMarkdown = useCallback(() => {
    const timestamp = new Date().toLocaleString('pt-BR');
    let md = `# Strategic Remediation Plan — Developer Task List\n\n`;
    md += `**Gerado em:** ${timestamp}\n`;
    md += `**Repositório Analisado:** ${report.scannedFilesCount} arquivos escaneados\n`;
    md += `**Progresso Atual:** ${stats.completedCount}/${stats.totalCount} tarefas concluídas (${stats.completionPercent}%)\n`;
    md += `**Esforço Restante Estimado:** ${stats.remainingHours} horas\n`;
    md += `**Redução Potencial de Risco:** -${stats.totalRiskPoints} pontos no Risk Score\n\n`;
    md += `---\n\n`;

    allTasks.forEach((t) => {
      const status = taskStatusMap[t.id] || 'TODO';
      const checkIcon = status === 'DONE' ? '[x]' : '[ ]';
      md += `### ${checkIcon} [${t.priority}] Tarefa #${t.taskNumber}: ${t.title}\n\n`;
      md += `- **Status:** ${status === 'DONE' ? '✅ CONCLUÍDA' : status === 'IN_PROGRESS' ? '⏳ EM ANDAMENTO' : '⭕ PENDENTE'}\n`;
      md += `- **SLA / Prazo:** ${t.slaTargetHours}\n`;
      md += `- **Esforço Estimado:** ${t.estimatedHours}h | **Impacto no Risco:** -${t.riskReductionPoints} pts\n`;
      md += `- **Descrição:** ${t.description}\n\n`;

      md += `#### Arquivos e Linhas Afetadas:\n`;
      t.allFindings.forEach((f) => {
        md += `- \`${f.file}:${f.line}\` — Regra: *${f.ruleName}* (Segredo Mascarado: \`${f.maskedSecret}\`)\n`;
      });
      md += `\n`;

      if (t.cliCommand) {
        md += `#### Passos Práticos de Mitigação (CLI):\n`;
        md += `\`\`\`${t.cliLanguage || 'bash'}\n${t.cliCommand}\n\`\`\`\n\n`;
      }

      if (t.officialDocLinks && t.officialDocLinks.length > 0) {
        md += `#### Documentação Oficial de Segurança:\n`;
        t.officialDocLinks.forEach((doc) => {
          md += `- [${doc.badge}: ${doc.title}](${doc.url})${doc.description ? ` — ${doc.description}` : ''}\n`;
        });
        md += `\n`;
      }

      md += `---\n\n`;
    });

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `strategic-remediation-plan-${new Date().toISOString().slice(0, 10)}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }, [allTasks, stats, taskStatusMap, report.scannedFilesCount]);

  // Copy Markdown to Clipboard
  const handleCopyMarkdown = useCallback(() => {
    let md = `# Strategic Remediation Plan\n\n`;
    allTasks.forEach((t) => {
      const status = taskStatusMap[t.id] || 'TODO';
      const checkIcon = status === 'DONE' ? '[x]' : '[ ]';
      md += `${checkIcon} **[${t.priority}]** #${t.taskNumber} ${t.title} (${t.estimatedHours}h, SLA: ${t.slaTargetHours})\n`;
      t.allFindings.forEach((f) => {
        md += `   - ${f.file}:${f.line} (\`${f.maskedSecret}\`)\n`;
      });
      if (t.officialDocLinks[0]) {
        md += `   - Docs: ${t.officialDocLinks[0].title} (${t.officialDocLinks[0].url})\n`;
      }
    });

    navigator.clipboard.writeText(md);
    setCopiedPlanMarkdown(true);
    setTimeout(() => {
      setCopiedPlanMarkdown(false);
    }, 2500);
  }, [allTasks, taskStatusMap]);

  return (
    <div
      id="strategic-remediation-plan"
      className="bg-[#0A0A0A] border border-[#262626] p-5 sm:p-7 space-y-6 relative overflow-hidden"
    >
      {/* Visual Accent Top Line */}
      <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-[#FF3E00] via-[#00E5FF] to-[#00FF66]" />

      {/* Header Section */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-[#1F1F1F]">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="p-2 bg-[#FF3E00]/10 border border-[#FF3E00]/30 text-[#FF3E00]">
              <ListOrdered className="w-5 h-5" />
            </div>
            <h2 className="text-xl sm:text-2xl font-black tracking-wider text-white uppercase flex items-center gap-2.5">
              Strategic Remediation Plan
              <span className="text-xs px-2.5 py-0.5 bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40 font-mono font-bold tracking-normal">
                {stats.totalCount} TAREFAS PRIORIZADAS
              </span>
            </h2>
          </div>
          <p className="text-xs text-[#888] font-mono max-w-4xl leading-relaxed">
            Plano estratégico de remediação para desenvolvedores, estruturado por ordem de impacto e SLA de entrega. Cada tarefa consolida vulnerabilidades detectadas com comandos de mitigação e links diretos para a documentação técnica oficial (OWASP, CWE, NIST, Snyk e provedores de nuvem).
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5 self-start lg:self-auto">
          <button
            type="button"
            id="btn-copy-plan-markdown"
            onClick={handleCopyMarkdown}
            className="px-3 py-2 bg-[#141414] hover:bg-[#222] border border-[#333] hover:border-[#666] text-white text-xs font-mono font-bold uppercase transition-all flex items-center gap-1.5 cursor-pointer"
            title="Copiar checklist em formato Markdown para Jira/GitHub"
          >
            {copiedPlanMarkdown ? (
              <>
                <Check className="w-3.5 h-3.5 text-[#00FF66]" />
                <span className="text-[#00FF66]">Copiado!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-[#AAA]" />
                <span>Copiar (.md)</span>
              </>
            )}
          </button>

          <button
            type="button"
            id="btn-export-plan-markdown"
            onClick={handleExportMarkdown}
            className="px-3.5 py-2 bg-[#FF3E00] hover:bg-[#FF3E00]/90 text-white text-xs font-mono font-bold tracking-wider uppercase transition-all flex items-center gap-2 cursor-pointer shadow-[0_0_15px_rgba(255,62,0,0.2)]"
            title="Exportar plano de trabalho em formato Markdown"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Exportar Plano (.md)</span>
          </button>

          {stats.completedCount > 0 && (
            <button
              type="button"
              id="btn-reset-plan-status"
              onClick={handleResetAllTasks}
              className="px-2.5 py-2 bg-[#111] hover:bg-[#202020] border border-[#333] text-[#777] hover:text-[#FF3E00] text-xs font-mono transition-all cursor-pointer"
              title="Resetar status de conclusão das tarefas"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Developer Sprint Burn-Down & Progress Telemetry */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-5 gap-3">
        {/* Total Tasks & Completion */}
        <div className="bg-[#111] border border-[#222] p-3 space-y-1">
          <div className="flex items-center justify-between text-[#888]">
            <span className="text-[10px] font-mono uppercase">Progresso Sprint</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-[#00FF66]" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-black font-mono text-white">
              {stats.completedCount}
            </span>
            <span className="text-xs font-mono text-[#666]">/ {stats.totalCount} tarefas</span>
            <span className="text-[10px] font-mono text-[#00FF66] font-bold ml-auto">
              {stats.completionPercent}%
            </span>
          </div>
          <div className="w-full bg-[#222] h-1.5 mt-2 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-[#FF3E00] via-[#00E5FF] to-[#00FF66] transition-all duration-300"
              style={{ width: `${stats.completionPercent}%` }}
            />
          </div>
        </div>

        {/* Estimated Developer Effort */}
        <div className="bg-[#111] border border-[#222] p-3 space-y-1">
          <div className="flex items-center justify-between text-[#888]">
            <span className="text-[10px] font-mono uppercase">Tempo Restante</span>
            <Clock className="w-3.5 h-3.5 text-[#00E5FF]" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-black font-mono text-[#00E5FF]">
              {stats.remainingHours}h
            </span>
            <span className="text-xs font-mono text-[#666]">de {stats.totalHours}h totais</span>
          </div>
          <p className="text-[9px] text-[#888] font-mono mt-1">
            {stats.completedHours}h de esforço já concluído
          </p>
        </div>

        {/* Risk Burn-Down */}
        <div className="bg-[#111] border border-[#222] p-3 space-y-1">
          <div className="flex items-center justify-between text-[#888]">
            <span className="text-[10px] font-mono uppercase">Queima de Risco</span>
            <Zap className="w-3.5 h-3.5 text-[#FF7A00]" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-black font-mono text-[#00FF66]">
              -{stats.mitigatedRiskPoints}
            </span>
            <span className="text-xs font-mono text-[#666]">de -{stats.totalRiskPoints} pts</span>
          </div>
          <p className="text-[9px] text-[#888] font-mono mt-1">
            Impacto acumulado no Risk Score
          </p>
        </div>

        {/* Critical P0 Blockers */}
        <div className="bg-[#111] border border-[#222] p-3 space-y-1">
          <div className="flex items-center justify-between text-[#888]">
            <span className="text-[10px] font-mono uppercase text-[#FF3E00]">P0 Bloqueadores</span>
            <AlertOctagon className="w-3.5 h-3.5 text-[#FF3E00]" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-black font-mono text-[#FF3E00]">
              {stats.priorityCounts.P0}
            </span>
            <span className="text-xs font-mono text-[#888]">tarefas críticas</span>
          </div>
          <p className="text-[9px] text-[#FF3E00]/80 font-mono mt-1">
            SLA de remediação: 0-4h
          </p>
        </div>

        {/* P1 High Severity Tasks */}
        <div className="bg-[#111] border border-[#222] p-3 space-y-1 col-span-2 sm:col-span-4 lg:col-span-1">
          <div className="flex items-center justify-between text-[#888]">
            <span className="text-[10px] font-mono uppercase text-[#FF7A00]">P1 Alto Risco</span>
            <Flame className="w-3.5 h-3.5 text-[#FF7A00]" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-black font-mono text-[#FF7A00]">
              {stats.priorityCounts.P1}
            </span>
            <span className="text-xs font-mono text-[#888]">tarefas P1</span>
          </div>
          <p className="text-[9px] text-[#888] font-mono mt-1">
            P2: {stats.priorityCounts.P2} | P3: {stats.priorityCounts.P3}
          </p>
        </div>
      </div>

      {/* Filters and Search Bar */}
      <div className="bg-[#111] border border-[#222] p-3 flex flex-col md:flex-row items-center justify-between gap-3">
        {/* Search */}
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-[#666] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            id="input-strategic-plan-search"
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Buscar por tarefa, arquivo, regra ou doc..."
            className="w-full bg-[#080808] border border-[#333] pl-9 pr-3 py-1.5 text-xs font-mono text-white placeholder-[#555] focus:outline-none focus:border-[#FF3E00]"
          />
        </div>

        {/* Priority & Status Filter Pills */}
        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto justify-start md:justify-end">
          {/* Priority Filter */}
          <div className="flex items-center bg-[#080808] border border-[#333] p-0.5 text-[11px] font-mono">
            <button
              onClick={() => setPriorityFilter('ALL')}
              className={`px-2 py-1 transition-all cursor-pointer ${
                priorityFilter === 'ALL'
                  ? 'bg-[#222] text-white font-bold'
                  : 'text-[#777] hover:text-white'
              }`}
            >
              Todas Prioridades
            </button>
            <button
              onClick={() => setPriorityFilter('P0')}
              className={`px-2 py-1 transition-all cursor-pointer ${
                priorityFilter === 'P0'
                  ? 'bg-[#FF3E00] text-black font-bold'
                  : 'text-[#FF3E00] hover:text-white'
              }`}
            >
              P0 ({stats.priorityCounts.P0})
            </button>
            <button
              onClick={() => setPriorityFilter('P1')}
              className={`px-2 py-1 transition-all cursor-pointer ${
                priorityFilter === 'P1'
                  ? 'bg-[#FF7A00] text-black font-bold'
                  : 'text-[#FF7A00] hover:text-white'
              }`}
            >
              P1 ({stats.priorityCounts.P1})
            </button>
            <button
              onClick={() => setPriorityFilter('P2')}
              className={`px-2 py-1 transition-all cursor-pointer ${
                priorityFilter === 'P2'
                  ? 'bg-[#EAB308] text-black font-bold'
                  : 'text-[#EAB308] hover:text-white'
              }`}
            >
              P2 ({stats.priorityCounts.P2})
            </button>
          </div>

          {/* Status Filter */}
          <div className="flex items-center bg-[#080808] border border-[#333] p-0.5 text-[11px] font-mono">
            <button
              onClick={() => setStatusFilter('ALL')}
              className={`px-2 py-1 transition-all cursor-pointer ${
                statusFilter === 'ALL'
                  ? 'bg-[#222] text-white font-bold'
                  : 'text-[#777] hover:text-white'
              }`}
            >
              Todos Status
            </button>
            <button
              onClick={() => setStatusFilter('TODO')}
              className={`px-2 py-1 transition-all cursor-pointer ${
                statusFilter === 'TODO'
                  ? 'bg-[#222] text-white font-bold'
                  : 'text-[#777] hover:text-white'
              }`}
            >
              Pendentes ({stats.todoCount})
            </button>
            <button
              onClick={() => setStatusFilter('IN_PROGRESS')}
              className={`px-2 py-1 transition-all cursor-pointer ${
                statusFilter === 'IN_PROGRESS'
                  ? 'bg-[#00E5FF] text-black font-bold'
                  : 'text-[#00E5FF] hover:text-white'
              }`}
            >
              Em Curso ({stats.inProgressCount})
            </button>
            <button
              onClick={() => setStatusFilter('DONE')}
              className={`px-2 py-1 transition-all cursor-pointer ${
                statusFilter === 'DONE'
                  ? 'bg-[#00FF66] text-black font-bold'
                  : 'text-[#00FF66] hover:text-white'
              }`}
            >
              Concluídas ({stats.completedCount})
            </button>
          </div>
        </div>
      </div>

      {/* Tasks List */}
      {filteredTasks.length === 0 ? (
        <div className="bg-[#111] border border-[#222] p-8 text-center space-y-2 font-mono">
          <CheckCircle2 className="w-8 h-8 text-[#00FF66] mx-auto" />
          <h3 className="text-sm font-bold text-white uppercase">
            Nenhuma tarefa encontrada com os filtros selecionados
          </h3>
          <p className="text-xs text-[#777]">
            Tente ajustar os filtros de prioridade, status ou termo de busca.
          </p>
        </div>
      ) : (
        <div className="space-y-3.5">
          {filteredTasks.map((task) => {
            const status = taskStatusMap[task.id] || 'TODO';
            const theme = PRIORITY_THEMES[task.priority];
            const isExpanded = expandedTaskId === task.id;

            return (
              <div
                key={task.id}
                id={`task-card-${task.id}`}
                className={`bg-[#0D0D0D] border transition-all ${
                  status === 'DONE'
                    ? 'border-[#222] opacity-75'
                    : isExpanded
                    ? `${theme.borderColor} shadow-[0_0_15px_rgba(0,0,0,0.5)]`
                    : 'border-[#222] hover:border-[#444]'
                }`}
              >
                {/* Task Header Row */}
                <div className="p-4 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-3">
                  <div className="flex items-start gap-3 w-full lg:w-auto">
                    {/* Checkbox status toggle button */}
                    <button
                      type="button"
                      onClick={() => handleToggleTaskStatus(task.id, status)}
                      className={`p-1 mt-0.5 transition-colors cursor-pointer shrink-0 ${
                        status === 'DONE'
                          ? 'text-[#00FF66]'
                          : status === 'IN_PROGRESS'
                          ? 'text-[#00E5FF]'
                          : 'text-[#555] hover:text-white'
                      }`}
                      title={
                        status === 'DONE'
                          ? 'Concluída! Clique para reabrir'
                          : status === 'IN_PROGRESS'
                          ? 'Em andamento. Clique para concluir'
                          : 'Pendente. Clique para iniciar'
                      }
                    >
                      {status === 'DONE' ? (
                        <CheckSquare className="w-5 h-5" />
                      ) : status === 'IN_PROGRESS' ? (
                        <div className="w-5 h-5 rounded-xs border-2 border-[#00E5FF] flex items-center justify-center">
                          <span className="w-2 h-2 bg-[#00E5FF] rounded-xs animate-pulse" />
                        </div>
                      ) : (
                        <Square className="w-5 h-5" />
                      )}
                    </button>

                    {/* Priority Badge & Title */}
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        {/* Priority Badge */}
                        <span
                          className={`px-2 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wider border ${theme.badgeBg} ${theme.badgeText} ${theme.borderColor}`}
                        >
                          {task.priorityLabel}
                        </span>

                        {/* Phase Tag */}
                        <span className="px-2 py-0.5 text-[10px] font-mono text-[#AAA] bg-[#1A1A1A] border border-[#2A2A2A]">
                          {task.phaseLabel}
                        </span>

                        {/* SLA Target */}
                        <span className="text-[10px] font-mono text-[#888] flex items-center gap-1">
                          <Clock className="w-3 h-3 text-[#00E5FF]" />
                          <span>SLA: {task.slaTargetHours}</span>
                        </span>

                        {/* Status Label */}
                        <span
                          className={`text-[9px] font-mono font-bold uppercase px-1.5 py-0.5 border ${
                            status === 'DONE'
                              ? 'bg-[#00FF66]/10 text-[#00FF66] border-[#00FF66]/40'
                              : status === 'IN_PROGRESS'
                              ? 'bg-[#00E5FF]/10 text-[#00E5FF] border-[#00E5FF]/40'
                              : 'bg-[#181818] text-[#777] border-[#333]'
                          }`}
                        >
                          {status === 'DONE'
                            ? '✓ CONCLUÍDA'
                            : status === 'IN_PROGRESS'
                            ? '⏳ EM ANDAMENTO'
                            : '○ PENDENTE'}
                        </span>
                      </div>

                      <h3
                        className={`text-sm sm:text-base font-black font-mono tracking-tight ${
                          status === 'DONE' ? 'text-[#888] line-through' : 'text-white'
                        }`}
                      >
                        <span className="text-[#666] font-normal mr-1.5">#{task.taskNumber}.</span>
                        {task.title}
                      </h3>

                      <p className="text-xs font-mono text-[#888] leading-relaxed max-w-3xl">
                        {task.description}
                      </p>
                    </div>
                  </div>

                  {/* Task Meta & Controls */}
                  <div className="flex items-center gap-2 self-end lg:self-center shrink-0 pt-2 lg:pt-0 border-t lg:border-t-0 border-[#1C1C1C] w-full lg:w-auto justify-between lg:justify-end">
                    <div className="text-right font-mono text-[11px] pr-2">
                      <div className="text-white font-bold">~{task.estimatedHours}h esforço</div>
                      <div className="text-[#00FF66]">-{task.riskReductionPoints} pts de risco</div>
                    </div>

                    <button
                      type="button"
                      onClick={() => setExpandedTaskId(isExpanded ? null : task.id)}
                      className="px-3 py-1.5 bg-[#141414] hover:bg-[#222] border border-[#333] hover:border-white text-white text-xs font-mono flex items-center gap-1.5 transition-all cursor-pointer"
                    >
                      <span>{isExpanded ? 'Recolher' : 'Instruções & Docs'}</span>
                      {isExpanded ? (
                        <ChevronUp className="w-3.5 h-3.5" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Primary Docs Quick-Strip (Always Visible) */}
                <div className="px-4 py-2 bg-[#080808] border-t border-[#1A1A1A] flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono">
                  {/* Direct Security Docs Links */}
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[#666] uppercase text-[10px] flex items-center gap-1">
                      <BookOpen className="w-3 h-3 text-[#A855F7]" />
                      Docs Recomendados:
                    </span>

                    {task.officialDocLinks.slice(0, 3).map((doc, idx) => (
                      <a
                        key={`doc-link-${task.id}-${idx}`}
                        href={doc.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="inline-flex items-center gap-1 px-2 py-0.5 bg-[#121212] hover:bg-[#1A1A1A] border border-[#2A2A2A] hover:border-[#666] text-zinc-300 hover:text-white transition-all group"
                        title={doc.description || doc.title}
                      >
                        <span className="text-[9px] font-bold text-[#A855F7] group-hover:text-[#C084FC]">
                          [{doc.badge}]
                        </span>
                        <span className="max-w-[180px] truncate">{doc.title}</span>
                        <ExternalLink className="w-2.5 h-2.5 text-[#666] group-hover:text-white shrink-0" />
                      </a>
                    ))}

                    {task.glossaryEntry && onOpenGlossary && (
                      <button
                        type="button"
                        onClick={() => onOpenGlossary(task.glossaryEntry)}
                        className="inline-flex items-center gap-1 px-2 py-0.5 bg-[#141414] hover:bg-[#202020] border border-[#333] text-[#00E5FF] text-[10px] font-bold cursor-pointer"
                        title="Ver no Glossário de Ameaças de Segurança"
                      >
                        <Sparkles className="w-2.5 h-2.5 text-[#00E5FF]" />
                        <span>Glossário ({task.glossaryEntry.cwe.id})</span>
                      </button>
                    )}
                  </div>

                  {/* Findings count & locations */}
                  <div className="flex items-center gap-2 text-[#777]">
                    <span>
                      <strong className="text-white">{task.allFindings.length}</strong> ocorrência(s)
                    </span>
                    <span>•</span>
                    <button
                      type="button"
                      onClick={() => {
                        if (onSelectFinding) onSelectFinding(task.primaryFinding);
                        if (onNavigateToScanner) onNavigateToScanner();
                      }}
                      className="text-[#FF3E00] hover:underline cursor-pointer flex items-center gap-1"
                    >
                      <FileCode className="w-3 h-3" />
                      <span>Ver no Scanner</span>
                    </button>
                  </div>
                </div>

                {/* Expanded Remediation Guide & Engineering Deep-Dive */}
                {isExpanded && (
                  <div className="p-4 sm:p-5 bg-[#080808] border-t border-[#1C1C1C] space-y-4 font-mono text-xs">
                    {/* Associated Vulnerabilities Table */}
                    <div className="space-y-1.5">
                      <h4 className="text-[11px] font-bold uppercase text-[#AAA] flex items-center gap-1.5">
                        <FileCode className="w-3.5 h-3.5 text-[#FF7A00]" />
                        Arquivos e Ocorrências Mapeadas:
                      </h4>
                      <div className="border border-[#222] divide-y divide-[#1A1A1A] bg-[#0E0E0E]">
                        {task.allFindings.map((finding) => (
                          <div
                            key={finding.id}
                            className="p-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-[#141414] transition-colors"
                          >
                            <div className="space-y-0.5">
                              <div className="flex items-center gap-2">
                                <button
                                  type="button"
                                  onClick={() => {
                                    if (onNavigateToFile) onNavigateToFile(finding.file);
                                  }}
                                  className="text-white hover:text-[#00E5FF] font-bold underline cursor-pointer text-left"
                                >
                                  {finding.file} : Linha {finding.line}
                                </button>
                                <span className="text-[9px] px-1 py-0.2 bg-[#222] text-[#888] border border-[#333]">
                                  {finding.ruleName}
                                </span>
                              </div>
                              <div className="text-[10px] text-[#777] font-mono truncate max-w-xl">
                                Segredo mascarado: <span className="text-[#FF3E00] font-bold">{finding.maskedSecret}</span>
                              </div>
                            </div>

                            <button
                              type="button"
                              onClick={() => {
                                if (onSelectFinding) onSelectFinding(finding);
                                if (onNavigateToScanner) onNavigateToScanner();
                              }}
                              className="px-2.5 py-1 bg-[#1A1A1A] hover:bg-[#2A2A2A] text-[#CCC] hover:text-white border border-[#333] text-[10px] font-bold uppercase transition-all flex items-center gap-1 self-start sm:self-auto cursor-pointer"
                            >
                              <span>Inspecionar</span>
                              <ArrowRight className="w-3 h-3" />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Step-by-Step Remediation Action Plan */}
                    <div className="space-y-2">
                      <h4 className="text-[11px] font-bold uppercase text-[#AAA] flex items-center gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-[#00FF66]" />
                        Passos Recomendados para Desenvolvedores:
                      </h4>
                      <div className="bg-[#0E0E0E] border border-[#222] p-3 space-y-2">
                        {task.remediationSteps.map((step, sIdx) => (
                          <div key={`step-${task.id}-${sIdx}`} className="flex items-start gap-2.5 text-zinc-300">
                            <span className="w-5 h-5 rounded-full bg-[#1A1A1A] border border-[#333] text-[10px] font-bold text-white flex items-center justify-center shrink-0 mt-0.5">
                              {sIdx + 1}
                            </span>
                            <p className="text-[11px] leading-relaxed pt-0.5">{step}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Code & CLI Snippets */}
                    {task.cliCommand && (
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <h4 className="text-[11px] font-bold uppercase text-[#AAA] flex items-center gap-1.5">
                            <Terminal className="w-3.5 h-3.5 text-[#00E5FF]" />
                            {task.cliDescription || 'Script / Comando de Remediação:'}
                          </h4>
                          <button
                            type="button"
                            onClick={() => handleCopyCommand(task.id, task.cliCommand!)}
                            className="text-[10px] text-[#888] hover:text-white flex items-center gap-1 transition-colors cursor-pointer"
                          >
                            {copiedTaskId === task.id ? (
                              <>
                                <Check className="w-3 h-3 text-[#00FF66]" />
                                <span className="text-[#00FF66] font-bold">Copiado!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                <span>Copiar Script</span>
                              </>
                            )}
                          </button>
                        </div>

                        <pre className="p-3 bg-[#050505] border border-[#222] text-[#00FF66] text-[11px] overflow-x-auto leading-relaxed font-mono">
                          <code>{task.cliCommand}</code>
                        </pre>
                      </div>
                    )}

                    {/* Safe Pattern Before vs After */}
                    {task.safeCodePattern && task.safeCodePattern.good && (
                      <div className="space-y-1.5">
                        <h4 className="text-[11px] font-bold uppercase text-[#AAA] flex items-center gap-1.5">
                          <Code2 className="w-3.5 h-3.5 text-[#A855F7]" />
                          Padrão de Código Seguro (Antes vs Depois):
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[10px]">
                          <div className="border border-[#FF3E00]/30 bg-[#160604] p-2.5 space-y-1">
                            <span className="text-[#FF3E00] font-bold uppercase">❌ Inseguro (Hardcoded)</span>
                            <pre className="text-zinc-300 overflow-x-auto p-1.5 bg-black/40 border border-[#FF3E00]/20 font-mono">
                              <code>{task.safeCodePattern.bad}</code>
                            </pre>
                          </div>
                          <div className="border border-[#00FF66]/30 bg-[#061408] p-2.5 space-y-1">
                            <span className="text-[#00FF66] font-bold uppercase">✓ Seguro (Vault / Runtime)</span>
                            <pre className="text-zinc-300 overflow-x-auto p-1.5 bg-black/40 border border-[#00FF66]/20 font-mono">
                              <code>{task.safeCodePattern.good}</code>
                            </pre>
                          </div>
                        </div>
                        {task.safeCodePattern.explanation && (
                          <p className="text-[10px] text-[#888] italic pt-0.5">
                            {task.safeCodePattern.explanation}
                          </p>
                        )}
                      </div>
                    )}

                    {/* Official Documentation References Deep Links */}
                    <div className="space-y-2 pt-2 border-t border-[#1C1C1C]">
                      <h4 className="text-[11px] font-bold uppercase text-[#AAA] flex items-center gap-1.5">
                        <BookOpen className="w-3.5 h-3.5 text-[#00E5FF]" />
                        Documentação Oficial de Segurança & Normas (Links Diretos):
                      </h4>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {task.officialDocLinks.map((doc, docIdx) => (
                          <a
                            key={`expanded-doc-${task.id}-${docIdx}`}
                            href={doc.url}
                            target="_blank"
                            rel="noreferrer noopener"
                            className="p-2.5 bg-[#0D0D0D] border border-[#222] hover:border-[#555] transition-all flex items-start justify-between gap-2 group"
                          >
                            <div className="space-y-0.5">
                              <div className="flex items-center gap-1.5">
                                <span className="text-[9px] font-bold px-1.5 py-0.2 bg-[#1A1A1A] text-[#00E5FF] border border-[#00E5FF]/30">
                                  {doc.badge}
                                </span>
                                <span className="text-[11px] font-bold text-white group-hover:text-[#00E5FF] transition-colors">
                                  {doc.title}
                                </span>
                              </div>
                              {doc.description && (
                                <p className="text-[10px] text-[#888] line-clamp-2 leading-relaxed">
                                  {doc.description}
                                </p>
                              )}
                            </div>
                            <ExternalLink className="w-3.5 h-3.5 text-[#555] group-hover:text-white shrink-0 mt-0.5" />
                          </a>
                        ))}
                      </div>
                    </div>

                    {/* Quick Task Status Setter */}
                    <div className="pt-2 border-t border-[#1C1C1C] flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2 text-[10px] text-[#888]">
                        <span>Marcar status da tarefa:</span>
                        <button
                          type="button"
                          onClick={() => handleSetDirectStatus(task.id, 'TODO')}
                          className={`px-2 py-0.5 border cursor-pointer ${
                            status === 'TODO'
                              ? 'bg-white text-black font-bold border-white'
                              : 'bg-[#141414] text-[#888] border-[#333] hover:text-white'
                          }`}
                        >
                          Pendente
                        </button>
                        <button
                          type="button"
                          onClick={() => handleSetDirectStatus(task.id, 'IN_PROGRESS')}
                          className={`px-2 py-0.5 border cursor-pointer ${
                            status === 'IN_PROGRESS'
                              ? 'bg-[#00E5FF] text-black font-bold border-[#00E5FF]'
                              : 'bg-[#141414] text-[#888] border-[#333] hover:text-[#00E5FF]'
                          }`}
                        >
                          Em Andamento
                        </button>
                        <button
                          type="button"
                          onClick={() => handleSetDirectStatus(task.id, 'DONE')}
                          className={`px-2 py-0.5 border cursor-pointer ${
                            status === 'DONE'
                              ? 'bg-[#00FF66] text-black font-bold border-[#00FF66]'
                              : 'bg-[#141414] text-[#888] border-[#333] hover:text-[#00FF66]'
                          }`}
                        >
                          Concluída
                        </button>
                      </div>

                      <button
                        type="button"
                        onClick={() => setExpandedTaskId(null)}
                        className="text-[10px] text-[#777] hover:text-white underline cursor-pointer"
                      >
                        Fechar detalhes
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Footer Insight Strip */}
      <div className="pt-4 border-t border-[#1C1C1C] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono text-[#888]">
        <div className="flex items-center gap-2 text-zinc-400">
          <ShieldCheck className="w-4 h-4 text-[#00FF66] shrink-0" />
          <span>
            Ao concluir tarefas <strong>P0</strong> e <strong>P1</strong>, execute novamente o scan para validar que o <strong>Critical Finding Threshold</strong> e as regras SAST estão 100% conformes.
          </span>
        </div>

        <div className="flex items-center gap-3 shrink-0 text-[11px]">
          <span className="text-white font-bold">{stats.completedCount} de {stats.totalCount} concluídas</span>
          <span>•</span>
          <span className="text-[#00FF66] font-bold">-{stats.mitigatedRiskPoints} pts mitigados</span>
        </div>
      </div>
    </div>
  );
};
