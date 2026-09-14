import React, { useState, useMemo, useEffect } from 'react';
import {
  ListOrdered,
  Clock,
  BookOpen,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  Code2,
  Copy,
  Check,
  Search,
  Filter,
  Sparkles,
  Download,
  AlertCircle,
  Zap,
  RotateCcw,
  ChevronDown,
  ChevronUp,
  FileCode,
  Lock,
  Layers,
  CheckSquare,
  Square,
  Terminal,
  HelpCircle,
  Tag
} from 'lucide-react';
import { ScanFinding, ScanReport, SeverityLevel, FindingCategory } from '../types';
import {
  SecurityGlossaryEntry,
  getGlossaryEntryForFinding
} from '../lib/securityGlossary';
import { safeGetItem, safeSetItem } from '../lib/storage';
import { ResolutionSpeedSparkline } from './ResolutionSpeedSparkline';

export interface RemediationRoadmapCardProps {
  report: ScanReport;
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToFinding?: (findingId: string) => void;
  onNavigateToScanner?: () => void;
  onNavigateToFile?: (filePath: string) => void;
  onOpenGlossary?: (entry?: SecurityGlossaryEntry) => void;
}

export type TTRCategory = 'QUICK' | 'STANDARD' | 'COMPLEX';

export interface RemediationItem {
  finding: ScanFinding;
  priorityRank: number;
  priorityLabel: string;
  priorityTier: 'P0' | 'P1' | 'P2' | 'P3' | 'P4';
  calculatedScore: number;
  ttr: {
    minutes: number;
    formatted: string;
    category: TTRCategory;
    complexityLabel: string;
    factors: string[];
  };
  glossaryEntry: SecurityGlossaryEntry;
  recommendedSteps: {
    id: string;
    stepNumber: number;
    title: string;
    action: string;
    cliCommand?: string;
  }[];
}

const STORAGE_ROADMAP_KEY = 'secscan_remediation_roadmap_checklist_v1';

// Calculate realistic Time-To-Remediate (TTR) based on secret type and contextual blast radius
function calculateFindingTTR(finding: ScanFinding): {
  minutes: number;
  formatted: string;
  category: TTRCategory;
  complexityLabel: string;
  factors: string[];
} {
  const cat = finding.category;
  const sev = finding.severity;
  const isEnvOrConfig =
    finding.file.includes('.env') ||
    finding.file.includes('config') ||
    finding.file.includes('server') ||
    finding.file.includes('auth');

  let baseMinutes = 25;
  const factors: string[] = [];

  switch (cat) {
    case 'CLOUD_CREDENTIAL':
      baseMinutes = 75;
      factors.push('Revogação em console IAM de nuvem (AWS/GCP/Azure)');
      factors.push('Criação de IAM Role / Workload Identity temporária');
      factors.push('Varredura e expurgo do histórico Git com git-filter-repo');
      break;

    case 'PRIVATE_KEY':
      baseMinutes = 90;
      factors.push('Revogação e reemissão de par de chaves PKI/SSH');
      factors.push('Atualização de authorized_keys nos servidores e bastions');
      factors.push('Publicação de lista de revogação de certificados (CRL)');
      break;

    case 'DATABASE_URI':
      baseMinutes = 45;
      factors.push('Troca de senha de usuário no motor de banco de dados');
      factors.push('Migração da connection string para Secrets Manager');
      factors.push('Reboot graceful do pool de conexões da aplicação');
      break;

    case 'AUTH_TOKEN':
      baseMinutes = 35;
      factors.push('Invalidação de refresh tokens e blacklist de JWT');
      factors.push('Rotação do segredo de assinatura (JWT_SECRET)');
      break;

    case 'PASSWORD':
      baseMinutes = 35;
      factors.push('Redefinição de senha de conta mestra ou serviço');
      factors.push('Substituição por injeção via variáveis de ambiente seguras');
      break;

    case 'API_KEY':
      baseMinutes = 25;
      factors.push('Geração de nova chave de API no painel do provedor');
      factors.push('Injeção dinâmica via .env ou Vault');
      break;

    case 'TAINT_SINK':
      baseMinutes = 60;
      factors.push('Refatoração do fluxo de taint AST e sanitização');
      factors.push('Implementação de queries parametrizadas / Zod schema');
      factors.push('Elaboração de testes de regressão de segurança');
      break;

    default:
      baseMinutes = sev === 'CRITICAL' ? 45 : sev === 'HIGH' ? 30 : sev === 'MEDIUM' ? 20 : 15;
      factors.push('Isolamento e extração de constante sensível');
      break;
  }

  // Adjust for critical file context
  if (isEnvOrConfig && baseMinutes < 60) {
    baseMinutes += 15;
    factors.push('Arquivo de infraestrutura central (requer deploy em staging)');
  }

  const category: TTRCategory =
    baseMinutes <= 25 ? 'QUICK' : baseMinutes <= 55 ? 'STANDARD' : 'COMPLEX';

  const complexityLabel =
    category === 'QUICK'
      ? 'Quick Win (≤ 25m)'
      : category === 'STANDARD'
      ? 'Padrão (30m - 55m)'
      : 'Complexo (≥ 60m)';

  const hours = Math.floor(baseMinutes / 60);
  const remMinutes = baseMinutes % 60;
  const formatted = hours > 0 ? `${hours}h${remMinutes > 0 ? ` ${remMinutes}m` : ''}` : `${baseMinutes} min`;

  return {
    minutes: baseMinutes,
    formatted,
    category,
    complexityLabel,
    factors
  };
}

// Generate tailored recommended fix steps
function generateRecommendedSteps(
  finding: ScanFinding,
  glossaryEntry: SecurityGlossaryEntry
) {
  const steps: {
    id: string;
    stepNumber: number;
    title: string;
    action: string;
    cliCommand?: string;
  }[] = [];

  const cat = finding.category;

  // Step 1: Immediate Containment & Invalidation
  if (cat === 'CLOUD_CREDENTIAL') {
    steps.push({
      id: `${finding.id}-step-1`,
      stepNumber: 1,
      title: 'Contenção Imediata & Revogação IAM',
      action: 'Acesse o console do provedor (AWS IAM / GCP Cloud Console / Azure) e desative imediatamente a chave comprometida.',
      cliCommand: finding.ruleName.toLowerCase().includes('aws')
        ? `aws iam update-access-key --access-key-id ${finding.maskedSecret.replace(/[*]/g, 'X')} --status Inactive`
        : undefined
    });
  } else if (cat === 'DATABASE_URI') {
    steps.push({
      id: `${finding.id}-step-1`,
      stepNumber: 1,
      title: 'Isolamento do Banco de Dados',
      action: 'Revogue a senha do usuário do banco de dados e encerre as conexões ativas associadas às credenciais vazadas.',
      cliCommand: 'ALTER USER app_service WITH PASSWORD \'<NOVA_SENHA_GERADA_VAULT>\';'
    });
  } else if (cat === 'PRIVATE_KEY') {
    steps.push({
      id: `${finding.id}-step-1`,
      stepNumber: 1,
      title: 'Revogação da Chave Criptográfica',
      action: 'Remova a chave pública correspondente de ~/.ssh/authorized_keys e revogue o certificado na Autoridade Certificadora.',
      cliCommand: `ssh-keygen -t ed25519 -C "secops-rotated-${new Date().toISOString().slice(0, 10)}"`
    });
  } else {
    steps.push({
      id: `${finding.id}-step-1`,
      stepNumber: 1,
      title: 'Revogação da Credencial Ativa',
      action: `Invalide imediatamente o token/chave no painel do fornecedor da regra "${finding.ruleName}".`
    });
  }

  // Step 2: Codebase Refactoring & Environment Injection
  steps.push({
    id: `${finding.id}-step-2`,
    stepNumber: 2,
    title: 'Migração do Código para Variável de Ambiente',
    action: `Remova o valor hardcoded da linha ${finding.line} em ${finding.file}. Substitua por process.env ou Secrets Manager.`,
    cliCommand: `echo "${finding.ruleName.toUpperCase().replace(/[^A-Z0-9]/g, '_')}=<NOVO_SEGREDO>" >> .env.local`
  });

  // Step 3: Git History Purging (if committed)
  steps.push({
    id: `${finding.id}-step-3`,
    stepNumber: 3,
    title: 'Expurgo do Histórico Git (Commit Blobs)',
    action: 'Remova a referência do arquivo ou da string de todos os commits anteriores para evitar extração via clones.',
    cliCommand: `git filter-repo --invert-paths --path ${finding.file} --force`
  });

  // Step 4: Verification with SecScan & Regression Test
  steps.push({
    id: `${finding.id}-step-4`,
    stepNumber: 4,
    title: 'Validação de Segurança & Teste de Regressão',
    action: 'Execute o SecScan para garantir que nenhuma nova detecção seja disparada e teste o serviço em ambiente de staging.'
  });

  return steps;
}

export const RemediationRoadmapCard: React.FC<RemediationRoadmapCardProps> = ({
  report,
  onSelectFinding,
  onNavigateToFinding,
  onNavigateToScanner,
  onNavigateToFile,
  onOpenGlossary
}) => {
  // State for search, filters, and sorting
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [effortFilter, setEffortFilter] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'PRIORITY' | 'TTR_ASC' | 'TTR_DESC'>('PRIORITY');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeGlossaryDrawerId, setActiveGlossaryDrawerId] = useState<string | null>(null);

  // Local checklist progress state: Record<stepId, boolean>
  const [completedSteps, setCompletedSteps] = useState<Record<string, boolean>>(() => {
    const saved = safeGetItem(STORAGE_ROADMAP_KEY);
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        // Fallback on parse error
      }
    }
    return {};
  });

  // Persist completed steps
  useEffect(() => {
    safeSetItem(STORAGE_ROADMAP_KEY, JSON.stringify(completedSteps));
  }, [completedSteps]);

  // Toggle step completion
  const handleToggleStep = (stepId: string) => {
    setCompletedSteps((prev) => ({
      ...prev,
      [stepId]: !prev[stepId]
    }));
  };

  // Copy helper
  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Build and prioritize active vulnerability roadmap items
  const roadmapItems = useMemo<RemediationItem[]>(() => {
    const rawFindings = report?.findings || [];
    // Only active findings (exclude false positives)
    const active = rawFindings.filter((f) => !f.isFalsePositive);

    // Compute priority weight
    const withScores = active.map((f) => {
      let severityWeight = 10;
      let priorityTier: 'P0' | 'P1' | 'P2' | 'P3' | 'P4' = 'P4';

      if (f.severity === 'CRITICAL') {
        severityWeight = 1000;
        priorityTier = 'P0';
      } else if (f.severity === 'HIGH') {
        severityWeight = 500;
        priorityTier = 'P1';
      } else if (f.severity === 'MEDIUM') {
        severityWeight = 200;
        priorityTier = 'P2';
      } else if (f.severity === 'LOW') {
        severityWeight = 50;
        priorityTier = 'P3';
      }

      const fileWeight =
        f.file.includes('.env') || f.file.includes('config') || f.file.includes('server')
          ? 150
          : 0;
      const entropyWeight = Math.round((f.entropy || 0) * 10);
      const findingScore = f.riskScore || f.weightedScore || 50;

      const totalScore = severityWeight + fileWeight + entropyWeight + findingScore;
      const ttr = calculateFindingTTR(f);
      const glossaryEntry = getGlossaryEntryForFinding(f);
      const recommendedSteps = generateRecommendedSteps(f, glossaryEntry);

      return {
        finding: f,
        priorityRank: 0, // Assigned after sorting
        priorityLabel: '',
        priorityTier,
        calculatedScore: totalScore,
        ttr,
        glossaryEntry,
        recommendedSteps
      };
    });

    // Sort by calculated score descending by default
    withScores.sort((a, b) => b.calculatedScore - a.calculatedScore);

    // Assign sequential priority ranks (#1, #2, #3...)
    return withScores.map((item, index) => {
      const rank = index + 1;
      return {
        ...item,
        priorityRank: rank,
        priorityLabel: `#${rank} ${item.priorityTier} ${item.finding.severity}`
      };
    });
  }, [report?.findings]);

  // Expand the top priority item by default on first load
  useEffect(() => {
    if (roadmapItems.length > 0 && expandedFindingId === null) {
      setExpandedFindingId(roadmapItems[0].finding.id);
    }
  }, [roadmapItems, expandedFindingId]);

  // Aggregate roadmap metrics
  const stats = useMemo(() => {
    const totalCount = roadmapItems.length;
    const criticalHighCount = roadmapItems.filter(
      (i) => i.finding.severity === 'CRITICAL' || i.finding.severity === 'HIGH'
    ).length;

    const totalMinutes = roadmapItems.reduce((acc, curr) => acc + curr.ttr.minutes, 0);
    const totalHours = Math.floor(totalMinutes / 60);
    const remMinutes = totalMinutes % 60;
    const totalTTRFormatted = `${totalHours}h ${remMinutes}m`;

    const quickWinsCount = roadmapItems.filter((i) => i.ttr.category === 'QUICK').length;
    const standardCount = roadmapItems.filter((i) => i.ttr.category === 'STANDARD').length;
    const complexCount = roadmapItems.filter((i) => i.ttr.category === 'COMPLEX').length;

    // Overall checklist progress
    let allStepsCount = 0;
    let completedStepsCount = 0;
    roadmapItems.forEach((item) => {
      item.recommendedSteps.forEach((step) => {
        allStepsCount++;
        if (completedSteps[step.id]) {
          completedStepsCount++;
        }
      });
    });

    const completionPercent = allStepsCount > 0 ? Math.round((completedStepsCount / allStepsCount) * 100) : 0;

    return {
      totalCount,
      criticalHighCount,
      totalMinutes,
      totalTTRFormatted,
      quickWinsCount,
      standardCount,
      complexCount,
      allStepsCount,
      completedStepsCount,
      completionPercent
    };
  }, [roadmapItems, completedSteps]);

  // Apply filters and sorting
  const filteredItems = useMemo(() => {
    let result = [...roadmapItems];

    // Search filter
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      result = result.filter(
        (item) =>
          item.finding.file.toLowerCase().includes(q) ||
          item.finding.ruleName.toLowerCase().includes(q) ||
          item.finding.category.toLowerCase().includes(q) ||
          item.glossaryEntry.title.toLowerCase().includes(q) ||
          item.glossaryEntry.cwe.id.toLowerCase().includes(q) ||
          item.glossaryEntry.owasp.code.toLowerCase().includes(q)
      );
    }

    // Severity filter
    if (severityFilter !== 'ALL') {
      result = result.filter((item) => item.finding.severity === severityFilter);
    }

    // Effort filter
    if (effortFilter !== 'ALL') {
      result = result.filter((item) => item.ttr.category === effortFilter);
    }

    // Sort
    if (sortBy === 'TTR_ASC') {
      result.sort((a, b) => a.ttr.minutes - b.ttr.minutes);
    } else if (sortBy === 'TTR_DESC') {
      result.sort((a, b) => b.ttr.minutes - a.ttr.minutes);
    } else {
      // PRIORITY
      result.sort((a, b) => a.priorityRank - b.priorityRank);
    }

    return result;
  }, [roadmapItems, searchTerm, severityFilter, effortFilter, sortBy]);

  // Export roadmap as Markdown
  const handleExportMarkdown = () => {
    const lines: string[] = [];
    lines.push('# SECSCAN REMEDIATION ROADMAP');
    lines.push(`Generated: ${new Date().toISOString()}`);
    lines.push(`Total Active Vulnerabilities: ${stats.totalCount}`);
    lines.push(`Total Estimated Time-to-Remediate (TTR): ${stats.totalTTRFormatted}`);
    lines.push(`Roadmap Checklist Completion: ${stats.completionPercent}% (${stats.completedStepsCount}/${stats.allStepsCount})`);
    lines.push('');
    lines.push('---');
    lines.push('');

    roadmapItems.forEach((item) => {
      lines.push(`## [Prioridade #${item.priorityRank}] ${item.finding.severity} - ${item.finding.ruleName}`);
      lines.push(`- **Arquivo:** \`${item.finding.file}:${item.finding.line}\``);
      lines.push(`- **Tempo Estimado (TTR):** ${item.ttr.formatted} (${item.ttr.complexityLabel})`);
      lines.push(`- **Verbete no Glossário:** ${item.glossaryEntry.title} (${item.glossaryEntry.cwe.id} / OWASP ${item.glossaryEntry.owasp.code})`);
      lines.push(`- **CVSS:** ${item.glossaryEntry.cvssScore}`);
      lines.push('');
      lines.push('### Etapas Recomendadas de Correção:');
      item.recommendedSteps.forEach((step) => {
        const isDone = completedSteps[step.id] ? '[x]' : '[ ]';
        lines.push(`- ${isDone} **Passo ${step.stepNumber}: ${step.title}**`);
        lines.push(`  ${step.action}`);
        if (step.cliCommand) {
          lines.push(`  \`\`\`bash\n  ${step.cliCommand}\n  \`\`\``);
        }
      });
      lines.push('');
      lines.push('---');
      lines.push('');
    });

    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secscan-remediation-roadmap-${new Date().toISOString().slice(0, 10)}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Reset all roadmap checklist steps
  const handleResetChecklist = () => {
    if (window.confirm('Deseja resetar todo o progresso do checklist do Roadmap de Remediação?')) {
      setCompletedSteps({});
    }
  };

  return (
    <div
      id="remediation-roadmap-card"
      className="bg-[#0A0A0A] border-2 border-[#2A2A2A] p-6 lg:p-8 space-y-6 relative overflow-hidden transition-all"
    >
      {/* Top Accent Indicator */}
      <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-[#FF3E00] via-[#FF7A00] to-[#00FF66]" />

      {/* Card Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-[#222]">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="p-2 bg-[#FF3E00]/10 border border-[#FF3E00]/30 text-[#FF3E00]">
              <ListOrdered className="w-5 h-5" />
            </div>
            <h2 className="text-xl font-black tracking-wider text-white uppercase flex items-center gap-2">
              Remediation Roadmap
              <span className="text-xs px-2.5 py-0.5 bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40 font-mono font-bold tracking-normal">
                {stats.totalCount} VULNERABILIDADES ATIVAS
              </span>
            </h2>
          </div>
          <p className="text-xs text-[#888] font-mono max-w-3xl leading-relaxed">
            Lista priorizada de vulnerabilidades ativas com análise dual-axis de correlação entre Taxa de Descoberta e Tempo de Resolução (MTTR), identificação de gargalos operacionais no ciclo de vida e passos práticos de remediação.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            id="btn-roadmap-export-md"
            onClick={handleExportMarkdown}
            className="px-3.5 py-2 bg-[#141414] hover:bg-[#202020] border border-[#333] hover:border-[#666] text-white text-xs font-mono font-bold tracking-wider uppercase transition-all flex items-center gap-2 group cursor-pointer"
            title="Exportar plano de remediação em formato Markdown"
          >
            <Download className="w-3.5 h-3.5 text-[#00FF66] group-hover:scale-110 transition-transform" />
            <span>Exportar Roadmap (.md)</span>
          </button>

          {stats.completedStepsCount > 0 && (
            <button
              id="btn-roadmap-reset-steps"
              onClick={handleResetChecklist}
              className="px-3 py-2 bg-[#141414] hover:bg-[#1A1A1A] border border-[#333] text-[#888] hover:text-[#FF3E00] text-xs font-mono transition-all flex items-center gap-1.5 cursor-pointer"
              title="Resetar progresso do checklist local"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Resetar Checklist</span>
            </button>
          )}

          <button
            id="btn-goto-strategic-plan"
            type="button"
            onClick={() => {
              const el = document.getElementById('strategic-remediation-plan');
              if (el) el.scrollIntoView({ behavior: 'smooth' });
            }}
            className="px-3.5 py-2 bg-[#FF3E00]/15 hover:bg-[#FF3E00] text-[#FF3E00] hover:text-white border border-[#FF3E00]/40 text-xs font-mono font-bold tracking-wider uppercase transition-all flex items-center gap-2 cursor-pointer"
            title="Ir para o Plano Estratégico de Tarefas de Desenvolvedores (P0-P3)"
          >
            <ListOrdered className="w-3.5 h-3.5" />
            <span>Plano Estratégico (P0-P3)</span>
          </button>

          {onNavigateToScanner && (
            <button
              id="btn-roadmap-goto-scanner"
              onClick={onNavigateToScanner}
              className="px-3.5 py-2 bg-[#FF3E00] hover:bg-[#E03700] text-white text-xs font-black uppercase tracking-widest transition-all flex items-center gap-1.5 shadow-[0_0_12px_rgba(255,62,0,0.25)] cursor-pointer"
            >
              <span>Ir para Scanner</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Summary KPI Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
        {/* Total Time-to-Remediate (TTR) */}
        <div className="bg-[#111] border border-[#262626] p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-[#888]">
            <span className="text-[11px] font-mono uppercase tracking-wider">Tempo Total Estimado</span>
            <Clock className="w-4 h-4 text-[#FF7A00]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-black font-mono text-white tracking-tight">
              {stats.totalTTRFormatted}
            </span>
          </div>
          <p className="mt-1 text-[10px] text-[#666] font-mono">
            Soma dos tempos para mitigar todas as {stats.totalCount} falhas ativas
          </p>
        </div>

        {/* Critical / High Priority */}
        <div className="bg-[#111] border border-[#262626] p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-[#888]">
            <span className="text-[11px] font-mono uppercase tracking-wider">Prioridade Crítica / Alta</span>
            <ShieldAlert className="w-4 h-4 text-[#FF3E00]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-black font-mono text-[#FF3E00] tracking-tight">
              {stats.criticalHighCount}
            </span>
            <span className="text-xs font-mono text-[#888]">/ {stats.totalCount}</span>
          </div>
          <p className="mt-1 text-[10px] text-[#666] font-mono">
            Falhas P0/P1 que exigem remediação dentro de 24h a 72h
          </p>
        </div>

        {/* Quick Wins */}
        <div className="bg-[#111] border border-[#262626] p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-[#888]">
            <span className="text-[11px] font-mono uppercase tracking-wider">Quick Wins (≤ 25 min)</span>
            <Zap className="w-4 h-4 text-[#00FF66]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-black font-mono text-[#00FF66] tracking-tight">
              {stats.quickWinsCount}
            </span>
            <span className="text-xs font-mono text-[#888]">itens</span>
          </div>
          <p className="mt-1 text-[10px] text-[#666] font-mono">
            Ganhos rápidos de segurança com esforço mínimo de engenharia
          </p>
        </div>

        {/* Checklist Completion */}
        <div className="bg-[#111] border border-[#262626] p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-[#888]">
            <span className="text-[11px] font-mono uppercase tracking-wider">Progresso do Checklist</span>
            <CheckCircle2 className="w-4 h-4 text-[#3366FF]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-black font-mono text-[#3366FF] tracking-tight">
              {stats.completionPercent}%
            </span>
            <span className="text-xs font-mono text-[#888]">
              ({stats.completedStepsCount}/{stats.allStepsCount})
            </span>
          </div>
          {/* Mini progress bar */}
          <div className="w-full bg-[#222] h-1.5 mt-2 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-[#3366FF] to-[#00FF66] transition-all duration-300"
              style={{ width: `${stats.completionPercent}%` }}
            />
          </div>
        </div>
      </div>

      {/* 30-Day Vulnerability Resolution Speed Sparkline Chart */}
      <ResolutionSpeedSparkline
        report={report}
        totalActiveCount={stats.totalCount}
        averageTTRMinutes={
          stats.totalCount > 0 ? Math.round(stats.totalMinutes / stats.totalCount) : 35
        }
      />

      {/* Filter and Search Bar */}
      <div className="bg-[#141414] border border-[#222] p-3.5 flex flex-col md:flex-row items-center justify-between gap-3">
        {/* Search */}
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-[#666] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            id="input-roadmap-search"
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Buscar por arquivo, regra ou CWE/OWASP..."
            className="w-full bg-[#0A0A0A] border border-[#333] pl-9 pr-3 py-1.5 text-xs font-mono text-white placeholder-[#555] focus:outline-none focus:border-[#FF3E00]"
          />
        </div>

        {/* Filter Pills and Sorters */}
        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto justify-start md:justify-end">
          {/* Severity filter */}
          <div className="flex items-center gap-1 bg-[#0A0A0A] border border-[#262626] p-1 text-[11px] font-mono">
            <span className="text-[#666] px-1.5 uppercase">Severidade:</span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-0.5 transition-all uppercase ${
                  severityFilter === sev
                    ? 'bg-[#FF3E00] text-white font-bold'
                    : 'text-[#888] hover:text-white'
                }`}
              >
                {sev === 'ALL' ? 'Todas' : sev}
              </button>
            ))}
          </div>

          {/* Effort filter */}
          <div className="flex items-center gap-1 bg-[#0A0A0A] border border-[#262626] p-1 text-[11px] font-mono">
            <span className="text-[#666] px-1.5 uppercase">Esforço:</span>
            {[
              { key: 'ALL', label: 'Todos' },
              { key: 'QUICK', label: 'Quick' },
              { key: 'STANDARD', label: 'Padrão' },
              { key: 'COMPLEX', label: 'Complexo' }
            ].map((eff) => (
              <button
                key={eff.key}
                onClick={() => setEffortFilter(eff.key)}
                className={`px-2 py-0.5 transition-all ${
                  effortFilter === eff.key
                    ? 'bg-[#FF7A00] text-black font-bold'
                    : 'text-[#888] hover:text-white'
                }`}
              >
                {eff.label}
              </button>
            ))}
          </div>

          {/* Sort selector */}
          <div className="flex items-center gap-1 bg-[#0A0A0A] border border-[#262626] px-2 py-1 text-[11px] font-mono">
            <span className="text-[#666] uppercase">Ordem:</span>
            <select
              id="select-roadmap-sort"
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="bg-transparent text-white font-mono focus:outline-none cursor-pointer"
            >
              <option value="PRIORITY" className="bg-[#111] text-white">
                Prioridade (P0 → P4)
              </option>
              <option value="TTR_ASC" className="bg-[#111] text-white">
                Menor TTR (Quick Wins)
              </option>
              <option value="TTR_DESC" className="bg-[#111] text-white">
                Maior TTR (Complexos)
              </option>
            </select>
          </div>
        </div>
      </div>

      {/* Prioritized Vulnerabilities List */}
      <div className="space-y-4">
        {filteredItems.length === 0 ? (
          <div className="bg-[#111] border border-[#262626] p-8 text-center space-y-3">
            <CheckCircle2 className="w-8 h-8 text-[#00FF66] mx-auto opacity-70" />
            <p className="text-sm font-mono text-white">
              Nenhuma vulnerabilidade ativa encontrada para os filtros selecionados.
            </p>
            <button
              onClick={() => {
                setSearchTerm('');
                setSeverityFilter('ALL');
                setEffortFilter('ALL');
              }}
              className="text-xs font-mono text-[#FF3E00] hover:underline"
            >
              Limpar todos os filtros
            </button>
          </div>
        ) : (
          filteredItems.map((item) => {
            const isExpanded = expandedFindingId === item.finding.id;
            const finding = item.finding;
            const entry = item.glossaryEntry;

            // Check how many recommended steps are completed for this finding
            const completedCount = item.recommendedSteps.filter(
              (step) => completedSteps[step.id]
            ).length;
            const allCompleted = completedCount === item.recommendedSteps.length;

            const severityBorder =
              finding.severity === 'CRITICAL'
                ? 'border-l-4 border-l-[#FF3E00]'
                : finding.severity === 'HIGH'
                ? 'border-l-4 border-l-[#FF7A00]'
                : finding.severity === 'MEDIUM'
                ? 'border-l-4 border-l-[#EAB308]'
                : 'border-l-4 border-l-[#3366FF]';

            return (
              <div
                key={finding.id}
                id={`roadmap-item-${finding.id}`}
                className={`bg-[#111] border border-[#262626] ${severityBorder} transition-all duration-200 hover:border-[#444]`}
              >
                {/* Collapsed / Header Bar */}
                <div className="p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                  <div className="flex items-start gap-3 flex-1 min-w-0">
                    {/* Priority Badge */}
                    <div className="flex flex-col items-center justify-center shrink-0">
                      <span
                        className={`px-2 py-1 text-[11px] font-black font-mono uppercase tracking-wider border ${
                          item.priorityTier === 'P0'
                            ? 'bg-[#FF3E00]/20 text-[#FF3E00] border-[#FF3E00]/40'
                            : item.priorityTier === 'P1'
                            ? 'bg-[#FF7A00]/20 text-[#FF7A00] border-[#FF7A00]/40'
                            : item.priorityTier === 'P2'
                            ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                            : 'bg-blue-500/20 text-blue-400 border-blue-500/40'
                        }`}
                      >
                        {item.priorityLabel}
                      </span>
                    </div>

                    {/* Finding Info */}
                    <div className="space-y-1 min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-bold text-white tracking-wide truncate">
                          {finding.ruleName}
                        </span>
                        <span className="text-[11px] font-mono px-2 py-0.5 bg-[#1A1A1A] border border-[#333] text-[#AAA]">
                          {finding.category}
                        </span>
                        {allCompleted && (
                          <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-[#00FF66]/20 text-[#00FF66] border border-[#00FF66]/40 flex items-center gap-1">
                            <Check className="w-3 h-3" />
                            100% REMEDIADO
                          </span>
                        )}
                      </div>

                      {/* File location and link */}
                      <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-[#777]">
                        <span className="flex items-center gap-1 text-[#AAA] truncate">
                          <FileCode className="w-3.5 h-3.5 text-[#888] shrink-0" />
                          <button
                            onClick={() => onNavigateToFile && onNavigateToFile(finding.file)}
                            className="hover:text-[#FF3E00] hover:underline transition-colors text-left truncate"
                            title="Abrir arquivo no editor"
                          >
                            {finding.file}
                          </button>
                          <span className="text-[#555]">:L{finding.line}</span>
                        </span>
                        <span className="text-[#444]">•</span>
                        <span className="text-[#666]">
                          Passos: {completedCount}/{item.recommendedSteps.length}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Right side: TTR & Security Glossary Link & Toggle */}
                  <div className="flex flex-wrap items-center gap-2.5 shrink-0 justify-between lg:justify-end border-t lg:border-t-0 pt-2 lg:pt-0 border-[#222]">
                    {/* Time to Remediate Pill */}
                    <div
                      className="px-2.5 py-1 bg-[#181818] border border-[#333] flex items-center gap-1.5 text-xs font-mono text-white"
                      title={`Fatores de esforço:\n${item.ttr.factors.join('\n')}`}
                    >
                      <Clock className="w-3.5 h-3.5 text-[#FF7A00]" />
                      <span className="font-bold">{item.ttr.formatted}</span>
                      <span className="text-[10px] text-[#888] uppercase hidden sm:inline">
                        ({item.ttr.complexityLabel})
                      </span>
                    </div>

                    {/* Direct Security Glossary Link Button */}
                    <button
                      id={`btn-open-glossary-${finding.id}`}
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        if (onOpenGlossary) {
                          onOpenGlossary(entry);
                        }
                      }}
                      className="px-2.5 py-1 bg-[#181818] hover:bg-[#222] border border-[#333] hover:border-[#00FF66] text-[#CCC] hover:text-[#00FF66] text-xs font-mono transition-all flex items-center gap-1.5 group cursor-pointer"
                      title={`Abrir verbete "${entry.title}" no Glossário de Ameaças (CWE/OWASP/CVSS)`}
                    >
                      <BookOpen className="w-3.5 h-3.5 text-[#00FF66] group-hover:scale-110 transition-transform" />
                      <span className="font-bold">Glossário:</span>
                      <span className="text-[11px] text-[#00FF66] underline decoration-dotted underline-offset-2">
                        {entry.cwe.id}
                      </span>
                      <ExternalLink className="w-3 h-3 opacity-60 group-hover:opacity-100" />
                    </button>

                    {/* Expand / Collapse Button */}
                    <button
                      id={`btn-toggle-roadmap-item-${finding.id}`}
                      onClick={() =>
                        setExpandedFindingId(isExpanded ? null : finding.id)
                      }
                      className="p-1.5 bg-[#181818] hover:bg-[#222] border border-[#333] text-[#888] hover:text-white transition-colors cursor-pointer"
                      title={isExpanded ? 'Recolher detalhes' : 'Expandir passos de remediação'}
                    >
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Expanded Details: Fix Steps & Glossary Card & Actions */}
                {isExpanded && (
                  <div className="border-t border-[#222] bg-[#0D0D0D] p-4 lg:p-6 space-y-6">
                    {/* Security Glossary Deep-Link Banner */}
                    <div className="bg-[#141414] border border-[#2A2A2A] p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3">
                      <div className="flex items-start gap-2.5">
                        <BookOpen className="w-4 h-4 text-[#00FF66] shrink-0 mt-0.5" />
                        <div className="space-y-0.5">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-xs font-bold text-white">
                              Verbete Associado: {entry.title}
                            </span>
                            <span className="text-[10px] font-mono px-1.5 py-0.2 bg-[#222] text-[#00FF66] border border-[#333]">
                              {entry.cwe.id} ({entry.cwe.name})
                            </span>
                            <span className="text-[10px] font-mono px-1.5 py-0.2 bg-[#222] text-[#FF7A00] border border-[#333]">
                              OWASP {entry.owasp.code}
                            </span>
                            <span className="text-[10px] font-mono px-1.5 py-0.2 bg-[#222] text-white border border-[#333]">
                              CVSS {entry.cvssScore}
                            </span>
                          </div>
                          <p className="text-[11px] text-[#888] font-mono line-clamp-2">
                            {entry.summary}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          onClick={() => {
                            setActiveGlossaryDrawerId(
                              activeGlossaryDrawerId === finding.id ? null : finding.id
                            );
                          }}
                          className="px-2.5 py-1 bg-[#1A1A1A] hover:bg-[#252525] border border-[#333] text-[#BBB] hover:text-white text-[11px] font-mono transition-colors cursor-pointer"
                        >
                          {activeGlossaryDrawerId === finding.id
                            ? 'Ocultar Prévia'
                            : 'Prévia Rápida'}
                        </button>
                        <button
                          id={`btn-roadmap-modal-glossary-${finding.id}`}
                          onClick={() => onOpenGlossary && onOpenGlossary(entry)}
                          className="px-3 py-1 bg-[#00FF66]/15 hover:bg-[#00FF66] text-[#00FF66] hover:text-black border border-[#00FF66]/40 text-[11px] font-black font-mono uppercase tracking-wider transition-all flex items-center gap-1.5 cursor-pointer"
                        >
                          <span>Abrir Verbete Completo</span>
                          <ExternalLink className="w-3 h-3" />
                        </button>
                      </div>
                    </div>

                    {/* Optional Quick Glossary Drawer */}
                    {activeGlossaryDrawerId === finding.id && (
                      <div className="bg-[#090909] border border-[#00FF66]/30 p-4 space-y-3 animate-fadeIn">
                        <div className="flex items-center justify-between text-xs text-[#00FF66] font-mono font-bold uppercase tracking-wider">
                          <span>Cenário de Ameaça & Blast Radius ({entry.cwe.id})</span>
                          <span className="text-[10px] text-[#777]">Fonte: NIST / MITRE CWE</span>
                        </div>
                        <p className="text-xs text-[#AAA] font-mono leading-relaxed">
                          <strong className="text-white">Cenário de Ataque:</strong>{' '}
                          {entry.threatScenario}
                        </p>
                        <p className="text-xs text-[#AAA] font-mono leading-relaxed">
                          <strong className="text-white">Objetivo do Atacante:</strong>{' '}
                          {entry.attackerObjective}
                        </p>
                        <div className="pt-2 border-t border-[#222]">
                          <div className="text-[11px] font-mono text-[#888] mb-1">
                            Padrão Seguro Recomendado ({entry.safePattern.language}):
                          </div>
                          <pre className="p-2.5 bg-[#000] border border-[#222] text-[11px] font-mono text-[#00FF66] overflow-x-auto">
                            {entry.safePattern.good}
                          </pre>
                        </div>
                      </div>
                    )}

                    {/* Actionable Recommended Fix Steps Timeline */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <h4 className="text-xs font-black uppercase tracking-wider text-white flex items-center gap-2">
                          <Terminal className="w-3.5 h-3.5 text-[#FF3E00]" />
                          Passos Recomendados de Correção (Checklist Interativo)
                        </h4>
                        <span className="text-xs font-mono text-[#888]">
                          {completedCount} de {item.recommendedSteps.length} concluídos (
                          {Math.round((completedCount / item.recommendedSteps.length) * 100)}%)
                        </span>
                      </div>

                      {/* Step items */}
                      <div className="space-y-2.5">
                        {item.recommendedSteps.map((step) => {
                          const isDone = Boolean(completedSteps[step.id]);

                          return (
                            <div
                              key={step.id}
                              className={`p-3 border transition-all ${
                                isDone
                                  ? 'bg-[#00FF66]/5 border-[#00FF66]/30'
                                  : 'bg-[#141414] border-[#222]'
                              }`}
                            >
                              <div className="flex items-start gap-3">
                                <button
                                  type="button"
                                  id={`checkbox-step-${step.id}`}
                                  onClick={() => handleToggleStep(step.id)}
                                  className="mt-0.5 text-[#888] hover:text-[#00FF66] transition-colors cursor-pointer shrink-0"
                                  title={isDone ? 'Desmarcar etapa' : 'Marcar etapa como concluída'}
                                >
                                  {isDone ? (
                                    <CheckSquare className="w-4 h-4 text-[#00FF66]" />
                                  ) : (
                                    <Square className="w-4 h-4" />
                                  )}
                                </button>

                                <div className="space-y-1 flex-1 min-w-0">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span
                                      className={`text-xs font-bold font-mono ${
                                        isDone ? 'line-through text-[#666]' : 'text-white'
                                      }`}
                                    >
                                      Passo {step.stepNumber}: {step.title}
                                    </span>
                                    {isDone && (
                                      <span className="text-[10px] font-mono text-[#00FF66] bg-[#00FF66]/10 px-1.5 py-0.2 border border-[#00FF66]/20">
                                        Concluído
                                      </span>
                                    )}
                                  </div>

                                  <p
                                    className={`text-xs font-mono ${
                                      isDone ? 'text-[#555]' : 'text-[#999]'
                                    }`}
                                  >
                                    {step.action}
                                  </p>

                                  {/* Optional CLI Command snippet */}
                                  {step.cliCommand && (
                                    <div className="mt-2 pt-2 border-t border-[#222] flex items-center justify-between gap-2 bg-[#000] p-2 border border-[#1A1A1A]">
                                      <code className="text-[11px] font-mono text-[#FF7A00] truncate flex-1">
                                        $ {step.cliCommand}
                                      </code>
                                      <button
                                        onClick={() => handleCopy(step.cliCommand!, step.id)}
                                        className="px-2 py-0.5 bg-[#141414] hover:bg-[#222] border border-[#333] text-[#AAA] hover:text-white text-[10px] font-mono transition-colors flex items-center gap-1 shrink-0 cursor-pointer"
                                        title="Copiar comando"
                                      >
                                        {copiedId === step.id ? (
                                          <>
                                            <Check className="w-3 h-3 text-[#00FF66]" />
                                            <span>Copiado</span>
                                          </>
                                        ) : (
                                          <>
                                            <Copy className="w-3 h-3" />
                                            <span>Copiar</span>
                                          </>
                                        )}
                                      </button>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Bottom Utility Actions */}
                    <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-[#222]">
                      <div className="flex items-center gap-2 text-xs font-mono text-[#888]">
                        <span>Segredo mascarado:</span>
                        <code className="bg-[#000] px-2 py-0.5 border border-[#222] text-[#FF7A00]">
                          {finding.maskedSecret}
                        </code>
                      </div>

                      <div className="flex items-center gap-2">
                        {onNavigateToFinding && (
                          <button
                            onClick={() => onNavigateToFinding(finding.id)}
                            className="px-3 py-1.5 bg-[#141414] hover:bg-[#202020] border border-[#333] hover:border-[#FF3E00] text-white text-xs font-mono transition-colors flex items-center gap-1.5 cursor-pointer"
                          >
                            <Search className="w-3.5 h-3.5 text-[#FF3E00]" />
                            <span>Inspecionar no Scanner</span>
                          </button>
                        )}
                        {onNavigateToFile && (
                          <button
                            onClick={() => onNavigateToFile(finding.file)}
                            className="px-3 py-1.5 bg-[#141414] hover:bg-[#202020] border border-[#333] hover:border-[#666] text-white text-xs font-mono transition-colors flex items-center gap-1.5 cursor-pointer"
                          >
                            <FileCode className="w-3.5 h-3.5 text-[#888]" />
                            <span>Ver Arquivo</span>
                          </button>
                        )}
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
