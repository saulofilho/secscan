import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  FileCheck,
  FileCode2,
  Play,
  RotateCcw,
  Download,
  Upload,
  Plus,
  Trash2,
  Copy,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Terminal,
  Filter,
  Search,
  ExternalLink,
  Code2,
  Sparkles,
  Layers,
  ChevronDown,
  ChevronRight,
  HelpCircle,
  Tag,
  BookOpen,
  Eye,
  Sliders,
  Check,
  Workflow
} from 'lucide-react';
import {
  OpaRegoPolicy,
  OpaPolicyStandard,
  OpaEnforcementLevel,
  OpaPolicyViolation,
  OpaEvaluationResult,
  OpaEvaluationSummary,
  ScanFinding,
  ScanReport
} from '../types';
import {
  DEFAULT_OPA_POLICIES,
  OPA_POLICY_TEMPLATES,
  evaluateSingleOpaPolicy,
  evaluateAllOpaPolicies,
  exportPoliciesToRegoBundle,
  exportOpaEvaluationJson
} from '../lib/opaPolicyEngine';

interface PolicyAsCodeViewProps {
  report: ScanReport;
  policies: OpaRegoPolicy[];
  onUpdatePolicies: (updatedPolicies: OpaRegoPolicy[]) => void;
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToScanner?: () => void;
  onLogAudit?: (event: any) => void;
}

export const PolicyAsCodeView: React.FC<PolicyAsCodeViewProps> = ({
  report,
  policies,
  onUpdatePolicies,
  onSelectFinding,
  onNavigateToScanner,
  onLogAudit
}) => {
  // Navigation sub-tabs
  const [subTab, setSubTab] = useState<'policies' | 'editor' | 'audit' | 'cicd'>('policies');

  // Search & Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [standardFilter, setStandardFilter] = useState<string>('ALL');
  const [enforcementFilter, setEnforcementFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'PASSED' | 'VIOLATED'>('ALL');

  // Expanded code view in list
  const [expandedPolicyIds, setExpandedPolicyIds] = useState<Record<string, boolean>>({});

  // Active policy in Editor
  const [editingPolicy, setEditingPolicy] = useState<OpaRegoPolicy>(() => policies[0] || DEFAULT_OPA_POLICIES[0]);
  const [editorTitle, setEditorTitle] = useState(editingPolicy.name);
  const [editorDesc, setEditorDesc] = useState(editingPolicy.description);
  const [editorStandard, setEditorStandard] = useState<OpaPolicyStandard>(editingPolicy.standard);
  const [editorEnforcement, setEditorEnforcement] = useState<OpaEnforcementLevel>(editingPolicy.enforcementLevel);
  const [editorRego, setEditorRego] = useState(editingPolicy.regoCode);
  const [editorSaveSuccess, setEditorSaveSuccess] = useState(false);

  // Sandbox testing state
  const [sandboxInputMode, setSandboxInputMode] = useState<'scan' | 'custom'>('scan');
  const [customInputJson, setCustomInputJson] = useState(() => JSON.stringify({
    findings: report.findings.slice(0, 3),
    metrics: report.metrics,
    apiEndpoints: report.apiEndpoints.slice(0, 3)
  }, null, 2));
  const [sandboxResult, setSandboxResult] = useState<OpaEvaluationResult | null>(null);

  // Re-evaluate whenever policies or report change
  const currentEvaluation: OpaEvaluationSummary = useMemo(() => {
    return evaluateAllOpaPolicies(policies, report);
  }, [policies, report]);

  // Handle toggling single policy
  const handleTogglePolicy = (policyId: string) => {
    const updated = policies.map(p => {
      if (p.id === policyId) {
        return { ...p, enabled: !p.enabled };
      }
      return p;
    });
    onUpdatePolicies(updated);
    onLogAudit?.({
      id: `audit-opa-toggle-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString(),
      type: 'POLICY_UPDATE',
      message: `Política OPA alterada: ID ${policyId}`
    });
  };

  // Handle changing enforcement level
  const handleChangeEnforcement = (policyId: string, level: OpaEnforcementLevel) => {
    const updated = policies.map(p => {
      if (p.id === policyId) {
        return { ...p, enforcementLevel: level };
      }
      return p;
    });
    onUpdatePolicies(updated);
  };

  // Handle opening policy in editor
  const handleEditPolicy = (policy: OpaRegoPolicy) => {
    setEditingPolicy(policy);
    setEditorTitle(policy.name);
    setEditorDesc(policy.description);
    setEditorStandard(policy.standard);
    setEditorEnforcement(policy.enforcementLevel);
    setEditorRego(policy.regoCode);
    setSubTab('editor');
  };

  // Handle saving policy changes from editor
  const handleSaveEditor = () => {
    const pkgMatch = editorRego.match(/^package\s+([a-zA-Z0-9_.]+)/m);
    const packageName = pkgMatch ? pkgMatch[1] : 'secscan.custom.policy';

    const isExisting = policies.some(p => p.id === editingPolicy.id);
    let updated: OpaRegoPolicy[];

    if (isExisting) {
      updated = policies.map(p => {
        if (p.id === editingPolicy.id) {
          return {
            ...p,
            name: editorTitle,
            description: editorDesc,
            standard: editorStandard,
            enforcementLevel: editorEnforcement,
            regoCode: editorRego,
            packageName
          };
        }
        return p;
      });
    } else {
      const newPolicy: OpaRegoPolicy = {
        ...editingPolicy,
        name: editorTitle,
        description: editorDesc,
        standard: editorStandard,
        enforcementLevel: editorEnforcement,
        regoCode: editorRego,
        packageName
      };
      updated = [newPolicy, ...policies];
    }

    onUpdatePolicies(updated);
    setEditorSaveSuccess(true);
    setTimeout(() => setEditorSaveSuccess(false), 2500);

    onLogAudit?.({
      id: `audit-opa-save-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString(),
      type: 'POLICY_UPDATE',
      message: `Política OPA Rego salva: '${editorTitle}'`
    });
  };

  // Create new blank policy
  const handleCreateNewPolicy = () => {
    const newId = `custom-policy-${Date.now()}`;
    const freshPolicy: OpaRegoPolicy = {
      id: newId,
      name: 'Nova Política Customizada OPA',
      description: 'Regra de conformidade organizacional baseada em Open Policy Agent (Rego).',
      standard: 'CUSTOM',
      packageName: 'secscan.custom.guardrail',
      enabled: true,
      enforcementLevel: 'BLOCKING',
      tags: ['Custom', 'OPA', 'Rego'],
      author: 'Security Admin',
      version: '1.0.0',
      isBuiltIn: false,
      regoCode: `package secscan.custom.guardrail

default allow = false

# Defina condições para deny
deny[msg] {
    some finding in input.findings
    finding.severity == "CRITICAL"
    msg := sprintf("Guardrail Violado: Achado crítico '%v' em '%v'", [finding.ruleName, finding.file])
}

allow {
    count(deny) == 0
}
`
    };
    setEditingPolicy(freshPolicy);
    setEditorTitle(freshPolicy.name);
    setEditorDesc(freshPolicy.description);
    setEditorStandard(freshPolicy.standard);
    setEditorEnforcement(freshPolicy.enforcementLevel);
    setEditorRego(freshPolicy.regoCode);
    setSubTab('editor');
  };

  // Load template into editor
  const handleLoadTemplate = (templateTitle: string) => {
    const template = OPA_POLICY_TEMPLATES.find(t => t.title === templateTitle);
    if (!template) return;

    setEditorTitle(template.title);
    setEditorDesc(template.description);
    setEditorStandard(template.category);
    setEditorEnforcement(template.defaultEnforcement);
    setEditorRego(template.regoCode);
  };

  // Run test in Sandbox
  const handleRunSandbox = () => {
    let testInput: any;
    if (sandboxInputMode === 'scan') {
      testInput = {
        findings: report.findings,
        metrics: report.metrics,
        apiEndpoints: report.apiEndpoints,
        totalFiles: report.totalFiles,
        environment: { branch: 'main', ciStage: 'testing' }
      };
    } else {
      try {
        testInput = JSON.parse(customInputJson);
      } catch (err: any) {
        alert('JSON customizado inválido: ' + err.message);
        return;
      }
    }

    const testPolicy: OpaRegoPolicy = {
      ...editingPolicy,
      name: editorTitle,
      regoCode: editorRego,
      enforcementLevel: editorEnforcement,
      standard: editorStandard
    };

    const res = evaluateSingleOpaPolicy(testPolicy, testInput);
    setSandboxResult(res);
  };

  // Export bundle
  const handleExportBundle = () => {
    const bundle = exportPoliciesToRegoBundle(policies);
    const blob = new Blob([bundle], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secscan-opa-policies-${new Date().toISOString().split('T')[0]}.rego`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Export evaluation JSON (OPA CLI format)
  const handleExportEvaluationJson = () => {
    const jsonStr = exportOpaEvaluationJson(currentEvaluation);
    const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `opa-eval-report-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Reset to default policies
  const handleResetDefaults = () => {
    if (window.confirm('Deseja restaurar as políticas OPA padrão? Quaisquer alterações locais serão substituídas.')) {
      onUpdatePolicies(DEFAULT_OPA_POLICIES);
    }
  };

  // Toggle code expand
  const toggleCodeExpand = (id: string) => {
    setExpandedPolicyIds(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  // Filtered policies
  const filteredPolicies = useMemo(() => {
    return policies.filter(p => {
      // Search
      const matchesSearch =
        p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.packageName.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));

      // Standard
      const matchesStandard = standardFilter === 'ALL' || p.standard === standardFilter;

      // Enforcement
      const matchesEnforcement = enforcementFilter === 'ALL' || p.enforcementLevel === enforcementFilter;

      // Status
      const evaluationResult = currentEvaluation.policyResults.find(r => r.policyId === p.id);
      let matchesStatus = true;
      if (statusFilter === 'PASSED') {
        matchesStatus = evaluationResult ? evaluationResult.status === 'PASSED' : true;
      } else if (statusFilter === 'VIOLATED') {
        matchesStatus = evaluationResult ? evaluationResult.status === 'VIOLATED' : false;
      }

      return matchesSearch && matchesStandard && matchesEnforcement && matchesStatus;
    });
  }, [policies, searchQuery, standardFilter, enforcementFilter, statusFilter, currentEvaluation]);

  return (
    <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="bg-[#0A0A0A] border border-[#222] rounded-xl p-5 sm:p-6 relative overflow-hidden shadow-2xl">
        <div className="absolute -right-16 -top-16 w-64 h-64 bg-[#00FF41]/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="px-2 py-0.5 rounded bg-[#00FF41]/10 border border-[#00FF41]/30 text-[#00FF41] text-[11px] font-mono font-bold tracking-wider uppercase flex items-center gap-1.5">
                <FileCheck className="w-3.5 h-3.5" />
                OPA Engine 0.68.0
              </span>
              <span className="px-2 py-0.5 rounded bg-zinc-800/80 border border-zinc-700 text-zinc-300 text-[11px] font-mono tracking-wider uppercase">
                Rego Declarative Language
              </span>
              <span className="px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/30 text-blue-400 text-[11px] font-mono tracking-wider uppercase">
                Shift-Left Guardrails
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight flex items-center gap-2">
              <span>Policy-as-Code Engine</span>
              <span className="text-zinc-500 font-normal text-base sm:text-lg">// Governança OPA & Rego</span>
            </h1>
            <p className="text-xs sm:text-sm text-zinc-400 max-w-3xl leading-relaxed">
              Defina, teste e aplique políticas de conformidade contínua escritas em <strong>Rego (Open Policy Agent)</strong>.
              Validação determinística contra PCI-DSS 4.0, SOC 2 Type II, NIST SP 800-53, CIS Benchmark e guardrails customizados durante todas as varreduras de código.
            </p>
          </div>

          {/* Action Buttons Toolbar */}
          <div className="flex items-center gap-2 flex-wrap">
            <button
              type="button"
              onClick={handleCreateNewPolicy}
              className="px-3 py-2 bg-[#00FF41] hover:bg-[#00FF41]/90 text-black font-bold text-xs rounded-lg flex items-center gap-1.5 transition-all shadow-[0_0_12px_rgba(0,255,65,0.2)] cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              <span>Nova Regra Rego</span>
            </button>
            <button
              type="button"
              onClick={handleExportBundle}
              className="px-3 py-2 bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-700 text-xs rounded-lg flex items-center gap-1.5 transition-all cursor-pointer"
              title="Exportar todas as políticas como arquivo .rego para o pipeline"
            >
              <Download className="w-3.5 h-3.5 text-zinc-400" />
              <span>Exportar .rego</span>
            </button>
            <button
              type="button"
              onClick={handleExportEvaluationJson}
              className="px-3 py-2 bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-700 text-xs rounded-lg flex items-center gap-1.5 transition-all cursor-pointer"
              title="Exportar avaliação no formato JSON compatível com OPA CLI"
            >
              <Terminal className="w-3.5 h-3.5 text-[#00FF41]" />
              <span>OPA JSON</span>
            </button>
            <button
              type="button"
              onClick={handleResetDefaults}
              className="p-2 bg-zinc-900 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 border border-zinc-800 rounded-lg transition-all cursor-pointer"
              title="Restaurar padrões de fábrica OPA"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Real-time OPA Evaluation Status Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mt-6 pt-5 border-t border-zinc-800/80">
          <div className="bg-[#111] p-3 rounded-lg border border-zinc-800">
            <span className="text-[10px] font-mono uppercase text-zinc-400 tracking-wider block">Conformidade OPA</span>
            <div className="flex items-baseline gap-1.5 mt-1">
              <span className={`text-xl font-black font-mono ${
                currentEvaluation.complianceScore >= 80 ? 'text-[#00FF41]' :
                currentEvaluation.complianceScore >= 50 ? 'text-[#FF7A00]' : 'text-[#FF3E00]'
              }`}>
                {currentEvaluation.complianceScore}%
              </span>
              <span className="text-[10px] text-zinc-500 font-mono">índice</span>
            </div>
          </div>

          <div className="bg-[#111] p-3 rounded-lg border border-zinc-800">
            <span className="text-[10px] font-mono uppercase text-zinc-400 tracking-wider block">Veredito do Gate</span>
            <div className="mt-1">
              <span className={`inline-flex items-center gap-1 text-[11px] font-mono font-bold px-2 py-0.5 rounded border ${
                currentEvaluation.verdict === 'PASSED'
                  ? 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/30'
                  : currentEvaluation.verdict === 'WARNING'
                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                  : 'bg-[#FF3E00]/10 text-[#FF3E00] border-[#FF3E00]/30'
              }`}>
                {currentEvaluation.verdict === 'PASSED' && <CheckCircle2 className="w-3 h-3" />}
                {currentEvaluation.verdict === 'WARNING' && <AlertTriangle className="w-3 h-3" />}
                {currentEvaluation.verdict === 'FAILED_BLOCKING' && <XCircle className="w-3 h-3" />}
                {currentEvaluation.verdict === 'PASSED' ? 'PASS (APROVADO)' : currentEvaluation.verdict === 'WARNING' ? 'AVISO (WARN)' : 'FAIL (BLOQUEADO)'}
              </span>
            </div>
          </div>

          <div className="bg-[#111] p-3 rounded-lg border border-zinc-800">
            <span className="text-[10px] font-mono uppercase text-zinc-400 tracking-wider block">Políticas Ativas</span>
            <div className="flex items-baseline gap-1.5 mt-1">
              <span className="text-xl font-black font-mono text-white">
                {currentEvaluation.enabledPolicies}
              </span>
              <span className="text-[10px] text-zinc-500 font-mono">/ {currentEvaluation.totalPolicies} total</span>
            </div>
          </div>

          <div className="bg-[#111] p-3 rounded-lg border border-zinc-800">
            <span className="text-[10px] font-mono uppercase text-zinc-400 tracking-wider block">Violações Bloqueantes</span>
            <div className="flex items-baseline gap-1.5 mt-1">
              <span className={`text-xl font-black font-mono ${
                currentEvaluation.blockingViolationsCount > 0 ? 'text-[#FF3E00]' : 'text-[#00FF41]'
              }`}>
                {currentEvaluation.blockingViolationsCount}
              </span>
              <span className="text-[10px] text-zinc-500 font-mono">críticas</span>
            </div>
          </div>

          <div className="bg-[#111] p-3 rounded-lg border border-zinc-800">
            <span className="text-[10px] font-mono uppercase text-zinc-400 tracking-wider block">Total de Violações</span>
            <div className="flex items-baseline gap-1.5 mt-1">
              <span className="text-xl font-black font-mono text-amber-400">
                {currentEvaluation.allViolations.length}
              </span>
              <span className="text-[10px] text-zinc-500 font-mono">achados</span>
            </div>
          </div>

          <div className="bg-[#111] p-3 rounded-lg border border-zinc-800">
            <span className="text-[10px] font-mono uppercase text-zinc-400 tracking-wider block">Tempo OPA Eval</span>
            <div className="flex items-baseline gap-1.5 mt-1">
              <span className="text-xl font-black font-mono text-[#00FF41]">
                {currentEvaluation.totalExecutionTimeMs}ms
              </span>
              <span className="text-[10px] text-zinc-500 font-mono">tempo real</span>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs Bar */}
      <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setSubTab('policies')}
            className={`px-3.5 py-2 text-xs font-bold font-mono rounded-lg transition-all flex items-center gap-2 cursor-pointer ${
              subTab === 'policies'
                ? 'bg-zinc-800 text-white border border-zinc-700 shadow-xs'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
            }`}
          >
            <Layers className="w-3.5 h-3.5 text-[#00FF41]" />
            <span>Políticas &amp; Padrões</span>
            <span className="px-1.5 py-0.2 bg-zinc-700 rounded text-[10px] text-zinc-300">
              {policies.length}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setSubTab('editor')}
            className={`px-3.5 py-2 text-xs font-bold font-mono rounded-lg transition-all flex items-center gap-2 cursor-pointer ${
              subTab === 'editor'
                ? 'bg-zinc-800 text-white border border-zinc-700 shadow-xs'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
            }`}
          >
            <Code2 className="w-3.5 h-3.5 text-blue-400" />
            <span>Editor Rego &amp; Sandbox</span>
            <span className="px-1.5 py-0.2 bg-blue-500/20 text-blue-300 rounded text-[10px]">
              Live IDE
            </span>
          </button>

          <button
            type="button"
            onClick={() => setSubTab('audit')}
            className={`px-3.5 py-2 text-xs font-bold font-mono rounded-lg transition-all flex items-center gap-2 cursor-pointer ${
              subTab === 'audit'
                ? 'bg-zinc-800 text-white border border-zinc-700 shadow-xs'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            <span>Auditoria &amp; Violações</span>
            {currentEvaluation.allViolations.length > 0 && (
              <span className="px-1.5 py-0.2 bg-amber-500/20 text-amber-300 rounded text-[10px]">
                {currentEvaluation.allViolations.length}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setSubTab('cicd')}
            className={`px-3.5 py-2 text-xs font-bold font-mono rounded-lg transition-all flex items-center gap-2 cursor-pointer ${
              subTab === 'cicd'
                ? 'bg-zinc-800 text-white border border-zinc-700 shadow-xs'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
            }`}
          >
            <Workflow className="w-3.5 h-3.5 text-purple-400" />
            <span>Simulador CI/CD Guardrail</span>
          </button>
        </div>

        <div className="hidden sm:flex items-center gap-2 text-xs text-zinc-500 font-mono">
          <Clock className="w-3.5 h-3.5 text-zinc-400" />
          <span>Última avaliação: {new Date(currentEvaluation.timestamp).toLocaleTimeString()}</span>
        </div>
      </div>

      {/* --------------------------------------------------------------------- */}
      {/* TAB 1: POLICIES & STANDARDS LIST */}
      {/* --------------------------------------------------------------------- */}
      {subTab === 'policies' && (
        <div className="space-y-4">
          {/* Filters Bar */}
          <div className="bg-[#0D0D0D] border border-zinc-800 p-3.5 rounded-xl flex flex-col md:flex-row items-center gap-3 justify-between">
            <div className="relative w-full md:w-80">
              <Search className="w-4 h-4 text-zinc-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Filtrar por nome, package ou tag..."
                className="w-full bg-[#161616] border border-zinc-700 text-xs text-zinc-200 pl-9 pr-3 py-1.5 rounded-lg focus:outline-none focus:border-[#00FF41]"
              />
            </div>

            <div className="flex items-center gap-2 flex-wrap w-full md:w-auto">
              <select
                value={standardFilter}
                onChange={e => setStandardFilter(e.target.value)}
                className="bg-[#161616] border border-zinc-700 text-zinc-200 text-xs px-2.5 py-1.5 rounded-lg focus:outline-none"
              >
                <option value="ALL">Todos os Padrões</option>
                <option value="PCI_DSS_4_0">PCI-DSS 4.0</option>
                <option value="SOC_2_TYPE_II">SOC 2 Type II</option>
                <option value="NIST_SP_800_53">NIST SP 800-53</option>
                <option value="CIS_BENCHMARK">CIS Benchmark</option>
                <option value="DEVSECOPS_GUARDRAIL">DevSecOps Guardrail</option>
                <option value="ISO_27001">ISO 27001</option>
                <option value="OWASP_TOP_10">OWASP Top 10</option>
                <option value="HIPAA">HIPAA</option>
                <option value="CUSTOM">Customizadas</option>
              </select>

              <select
                value={enforcementFilter}
                onChange={e => setEnforcementFilter(e.target.value)}
                className="bg-[#161616] border border-zinc-700 text-zinc-200 text-xs px-2.5 py-1.5 rounded-lg focus:outline-none"
              >
                <option value="ALL">Todos os Níveis</option>
                <option value="BLOCKING">Blocking (Quebra Pipeline)</option>
                <option value="WARNING">Warning (Aviso)</option>
                <option value="ADVISORY">Advisory (Informativo)</option>
              </select>

              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value as any)}
                className="bg-[#161616] border border-zinc-700 text-zinc-200 text-xs px-2.5 py-1.5 rounded-lg focus:outline-none"
              >
                <option value="ALL">Todos os Resultados</option>
                <option value="PASSED">Conforme (Passed)</option>
                <option value="VIOLATED">Com Violação (Violated)</option>
              </select>
            </div>
          </div>

          {/* Policy Cards Grid */}
          <div className="space-y-3">
            {filteredPolicies.length === 0 ? (
              <div className="p-8 text-center bg-[#0D0D0D] border border-zinc-800 rounded-xl text-zinc-500 text-xs">
                Nenhuma política OPA corresponde aos filtros selecionados.
              </div>
            ) : (
              filteredPolicies.map(policy => {
                const evalResult = currentEvaluation.policyResults.find(r => r.policyId === policy.id);
                const hasViolations = evalResult && evalResult.violations.length > 0;
                const isExpanded = Boolean(expandedPolicyIds[policy.id]);

                return (
                  <div
                    key={policy.id}
                    className={`bg-[#0D0D0D] border rounded-xl p-4 transition-all ${
                      !policy.enabled
                        ? 'opacity-60 border-zinc-800/60'
                        : hasViolations
                        ? policy.enforcementLevel === 'BLOCKING'
                          ? 'border-[#FF3E00]/40 bg-[#FF3E00]/5'
                          : 'border-amber-500/40 bg-amber-500/5'
                        : 'border-zinc-800 hover:border-zinc-700'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-mono font-bold text-white">
                            {policy.name}
                          </span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                            {policy.standard.replace(/_/g, ' ')}
                          </span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-800">
                            pkg: {policy.packageName}
                          </span>
                          {policy.version && (
                            <span className="text-[9px] font-mono text-zinc-500">
                              v{policy.version}
                            </span>
                          )}
                        </div>

                        <p className="text-xs text-zinc-400 line-clamp-2">
                          {policy.description}
                        </p>

                        <div className="flex items-center gap-2 pt-1">
                          {policy.tags.map(tag => (
                            <span
                              key={tag}
                              className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-zinc-900/90 text-zinc-400 border border-zinc-800"
                            >
                              #{tag}
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* Right controls: status, enforcement dropdown, toggle, actions */}
                      <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
                        {/* Status Badge */}
                        {policy.enabled && evalResult && (
                          <span className={`px-2 py-1 rounded text-[10px] font-mono font-bold border flex items-center gap-1 ${
                            hasViolations
                              ? policy.enforcementLevel === 'BLOCKING'
                                ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/30'
                                : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                              : 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/30'
                          }`}>
                            {hasViolations ? (
                              <>
                                <AlertTriangle className="w-3 h-3" />
                                <span>{evalResult.violations.length} Violação(ões)</span>
                              </>
                            ) : (
                              <>
                                <CheckCircle2 className="w-3 h-3" />
                                <span>Conforme (Pass)</span>
                              </>
                            )}
                          </span>
                        )}

                        {/* Enforcement Level Selector */}
                        <select
                          value={policy.enforcementLevel}
                          onChange={e => handleChangeEnforcement(policy.id, e.target.value as OpaEnforcementLevel)}
                          className={`text-[10px] font-mono font-bold px-2 py-1 rounded border focus:outline-none ${
                            policy.enforcementLevel === 'BLOCKING'
                              ? 'bg-[#FF3E00]/10 border-[#FF3E00]/40 text-[#FF3E00]'
                              : policy.enforcementLevel === 'WARNING'
                              ? 'bg-amber-500/10 border-amber-500/40 text-amber-400'
                              : 'bg-blue-500/10 border-blue-500/40 text-blue-400'
                          }`}
                        >
                          <option value="BLOCKING">BLOCKING (Gate)</option>
                          <option value="WARNING">WARNING (Aviso)</option>
                          <option value="ADVISORY">ADVISORY (Info)</option>
                        </select>

                        {/* Active Toggle Switch */}
                        <button
                          type="button"
                          onClick={() => handleTogglePolicy(policy.id)}
                          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors cursor-pointer ${
                            policy.enabled ? 'bg-[#00FF41]' : 'bg-zinc-800'
                          }`}
                          title={policy.enabled ? 'Desativar política' : 'Ativar política'}
                        >
                          <span
                            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-black transition-transform ${
                              policy.enabled ? 'translate-x-4.5' : 'translate-x-1'
                            }`}
                          />
                        </button>

                        {/* Expand Code Button */}
                        <button
                          type="button"
                          onClick={() => toggleCodeExpand(policy.id)}
                          className="p-1.5 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 rounded transition-all cursor-pointer"
                          title={isExpanded ? 'Ocultar código Rego' : 'Visualizar código Rego'}
                        >
                          {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                        </button>

                        {/* Edit Button */}
                        <button
                          type="button"
                          onClick={() => handleEditPolicy(policy)}
                          className="p-1.5 text-zinc-400 hover:text-[#00FF41] hover:bg-zinc-800 rounded transition-all cursor-pointer"
                          title="Abrir no Editor Rego"
                        >
                          <Code2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>

                    {/* Expandable Rego Code & Violations Detail */}
                    {isExpanded && (
                      <div className="mt-4 pt-3 border-t border-zinc-800 space-y-3">
                        <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400">
                          <span className="flex items-center gap-1.5">
                            <Terminal className="w-3.5 h-3.5 text-[#00FF41]" />
                            <span>Definição Declarativa OPA Rego</span>
                          </span>
                          <button
                            type="button"
                            onClick={() => {
                              navigator.clipboard.writeText(policy.regoCode);
                              alert('Código Rego copiado para a área de transferência!');
                            }}
                            className="text-[10px] text-zinc-400 hover:text-white flex items-center gap-1 cursor-pointer"
                          >
                            <Copy className="w-3 h-3" />
                            <span>Copiar Rego</span>
                          </button>
                        </div>

                        <pre className="bg-[#050505] p-3 rounded-lg border border-zinc-800 text-[11px] font-mono text-zinc-300 overflow-x-auto max-h-56 leading-relaxed">
                          <code>{policy.regoCode}</code>
                        </pre>

                        {/* Violations associated with this policy */}
                        {evalResult && evalResult.violations.length > 0 && (
                          <div className="space-y-1.5 pt-2">
                            <span className="text-[11px] font-mono font-bold text-[#FF3E00] block">
                              Achados em violação ({evalResult.violations.length}):
                            </span>
                            <div className="space-y-1">
                              {evalResult.violations.map(violation => (
                                <div
                                  key={violation.id}
                                  className="bg-black/60 p-2 rounded border border-[#FF3E00]/30 flex items-center justify-between text-[11px] font-mono text-zinc-300"
                                >
                                  <div className="flex items-center gap-2">
                                    <span className="text-[#FF3E00] font-bold">[{violation.severity}]</span>
                                    <span>{violation.message}</span>
                                  </div>
                                  {violation.targetFile && (
                                    <button
                                      type="button"
                                      onClick={() => {
                                        if (violation.targetFindingId) {
                                          const found = report.findings.find(f => f.id === violation.targetFindingId);
                                          if (found && onSelectFinding) {
                                            onSelectFinding(found);
                                          }
                                        }
                                        onNavigateToScanner?.();
                                      }}
                                      className="text-[#00FF41] hover:underline text-[10px] shrink-0 ml-2"
                                    >
                                      {violation.targetFile}:{violation.targetLine}
                                    </button>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* TAB 2: REGO EDITOR & TEST SANDBOX */}
      {/* --------------------------------------------------------------------- */}
      {subTab === 'editor' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Left Column: Code Editor */}
          <div className="lg:col-span-7 bg-[#0D0D0D] border border-zinc-800 rounded-xl p-4 sm:p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800 flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <Code2 className="w-4 h-4 text-[#00FF41]" />
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                  Editor de Políticas OPA Rego
                </span>
              </div>

              {/* Template Presets Dropdown */}
              <div className="flex items-center gap-2">
                <select
                  onChange={e => {
                    if (e.target.value) {
                      handleLoadTemplate(e.target.value);
                      e.target.value = '';
                    }
                  }}
                  className="bg-[#181818] border border-zinc-700 text-zinc-300 text-[11px] px-2.5 py-1 rounded-lg focus:outline-none"
                >
                  <option value="">Carregar Template OPA...</option>
                  {OPA_POLICY_TEMPLATES.map(t => (
                    <option key={t.title} value={t.title}>
                      {t.title}
                    </option>
                  ))}
                </select>

                <button
                  type="button"
                  onClick={handleSaveEditor}
                  className="px-3 py-1.5 bg-[#00FF41] hover:bg-[#00FF41]/90 text-black font-bold text-xs rounded-lg flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
                >
                  {editorSaveSuccess ? (
                    <>
                      <Check className="w-3.5 h-3.5" />
                      <span>Salvo!</span>
                    </>
                  ) : (
                    <>
                      <FileCheck className="w-3.5 h-3.5" />
                      <span>Salvar Política</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Metadata inputs */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] font-mono text-zinc-400 block mb-1 uppercase">Nome da Política</label>
                <input
                  type="text"
                  value={editorTitle}
                  onChange={e => setEditorTitle(e.target.value)}
                  className="w-full bg-[#161616] border border-zinc-700 text-xs text-white px-3 py-1.5 rounded-lg focus:outline-none focus:border-[#00FF41]"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-[10px] font-mono text-zinc-400 block mb-1 uppercase">Padrão</label>
                  <select
                    value={editorStandard}
                    onChange={e => setEditorStandard(e.target.value as OpaPolicyStandard)}
                    className="w-full bg-[#161616] border border-zinc-700 text-xs text-zinc-200 px-2.5 py-1.5 rounded-lg focus:outline-none"
                  >
                    <option value="PCI_DSS_4_0">PCI-DSS 4.0</option>
                    <option value="SOC_2_TYPE_II">SOC 2 Type II</option>
                    <option value="NIST_SP_800_53">NIST SP 800-53</option>
                    <option value="CIS_BENCHMARK">CIS Benchmark</option>
                    <option value="DEVSECOPS_GUARDRAIL">DevSecOps Guardrail</option>
                    <option value="ISO_27001">ISO 27001</option>
                    <option value="OWASP_TOP_10">OWASP Top 10</option>
                    <option value="HIPAA">HIPAA</option>
                    <option value="CUSTOM">Custom</option>
                  </select>
                </div>

                <div>
                  <label className="text-[10px] font-mono text-zinc-400 block mb-1 uppercase">Enforcement</label>
                  <select
                    value={editorEnforcement}
                    onChange={e => setEditorEnforcement(e.target.value as OpaEnforcementLevel)}
                    className="w-full bg-[#161616] border border-zinc-700 text-xs text-zinc-200 px-2.5 py-1.5 rounded-lg focus:outline-none"
                  >
                    <option value="BLOCKING">BLOCKING</option>
                    <option value="WARNING">WARNING</option>
                    <option value="ADVISORY">ADVISORY</option>
                  </select>
                </div>
              </div>
            </div>

            <div>
              <label className="text-[10px] font-mono text-zinc-400 block mb-1 uppercase">Descrição &amp; Propósito</label>
              <input
                type="text"
                value={editorDesc}
                onChange={e => setEditorDesc(e.target.value)}
                className="w-full bg-[#161616] border border-zinc-700 text-xs text-zinc-300 px-3 py-1.5 rounded-lg focus:outline-none focus:border-[#00FF41]"
              />
            </div>

            {/* Rego Code Area */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-[10px] font-mono text-zinc-400 uppercase">
                  Código Rego (.rego)
                </label>
                <span className="text-[10px] font-mono text-zinc-500">
                  {editorRego.split('\n').length} linhas
                </span>
              </div>
              <textarea
                value={editorRego}
                onChange={e => setEditorRego(e.target.value)}
                rows={16}
                spellCheck={false}
                className="w-full bg-[#050505] border border-zinc-800 text-xs font-mono text-[#00FF41] p-3 rounded-lg focus:outline-none focus:border-[#00FF41] leading-relaxed resize-y"
              />
            </div>

            {/* Syntax Help Cheatsheet */}
            <div className="bg-[#111] p-3 rounded-lg border border-zinc-800 text-[10px] font-mono text-zinc-400 space-y-1">
              <span className="text-white font-bold block flex items-center gap-1">
                <HelpCircle className="w-3 h-3 text-[#00FF41]" />
                <span>Rego Syntax Quick Reference</span>
              </span>
              <p>• Iteração em achados: <code className="text-zinc-200">some finding in input.findings</code></p>
              <p>• Campos disponíveis: <code className="text-zinc-200">finding.severity</code>, <code className="text-zinc-200">finding.category</code>, <code className="text-zinc-200">finding.riskScore</code>, <code className="text-zinc-200">finding.entropy</code>, <code className="text-zinc-200">finding.file</code></p>
              <p>• Funções built-in: <code className="text-zinc-200">contains(str, substr)</code>, <code className="text-zinc-200">sprintf(fmt, [args])</code>, <code className="text-zinc-200">count(list)</code>, <code className="text-zinc-200">regex.match(pattern, str)</code></p>
            </div>
          </div>

          {/* Right Column: Interactive Test Sandbox */}
          <div className="lg:col-span-5 bg-[#0D0D0D] border border-zinc-800 rounded-xl p-4 sm:p-5 space-y-4 flex flex-col justify-between">
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-blue-400" />
                  <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                    Test Sandbox (OPA Eval)
                  </span>
                </div>

                <div className="flex items-center gap-1 text-[10px] font-mono">
                  <button
                    type="button"
                    onClick={() => setSandboxInputMode('scan')}
                    className={`px-2 py-1 rounded transition-colors ${
                      sandboxInputMode === 'scan'
                        ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30 font-bold'
                        : 'text-zinc-400 hover:text-white'
                    }`}
                  >
                    Scan Atual ({report.findings.length} achados)
                  </button>
                  <button
                    type="button"
                    onClick={() => setSandboxInputMode('custom')}
                    className={`px-2 py-1 rounded transition-colors ${
                      sandboxInputMode === 'custom'
                        ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30 font-bold'
                        : 'text-zinc-400 hover:text-white'
                    }`}
                  >
                    JSON Custom
                  </button>
                </div>
              </div>

              {/* Custom Input Editor if mode is custom */}
              {sandboxInputMode === 'custom' && (
                <div>
                  <label className="text-[10px] font-mono text-zinc-400 block mb-1 uppercase">
                    input document (JSON)
                  </label>
                  <textarea
                    value={customInputJson}
                    onChange={e => setCustomInputJson(e.target.value)}
                    rows={6}
                    className="w-full bg-[#050505] border border-zinc-800 text-[11px] font-mono text-zinc-300 p-2.5 rounded-lg focus:outline-none focus:border-blue-400 resize-y"
                  />
                </div>
              )}

              {sandboxInputMode === 'scan' && (
                <div className="bg-[#121212] p-3 rounded-lg border border-zinc-800 text-[11px] font-mono text-zinc-400 space-y-1">
                  <p>• <strong>input.findings</strong>: {report.findings.length} achados locais</p>
                  <p>• <strong>input.metrics.riskScore</strong>: {report.metrics.riskScore}/100</p>
                  <p>• <strong>input.metrics.criticalCount</strong>: {report.metrics.criticalCount}</p>
                  <p>• <strong>input.apiEndpoints</strong>: {report.apiEndpoints.length} rotas mapeadas</p>
                </div>
              )}

              {/* Action Button: Run Sandbox */}
              <button
                type="button"
                onClick={handleRunSandbox}
                className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs rounded-lg flex items-center justify-center gap-2 transition-all cursor-pointer shadow-lg shadow-blue-600/20"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>Avaliar Rego Agora (OPA Eval)</span>
              </button>

              {/* Results Console */}
              {sandboxResult && (
                <div className="space-y-3 pt-2">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-zinc-400">Resultado da Avaliação:</span>
                    <span className={`px-2 py-0.5 rounded font-bold ${
                      sandboxResult.status === 'PASSED'
                        ? 'bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30'
                        : 'bg-[#FF3E00]/10 text-[#FF3E00] border border-[#FF3E00]/30'
                    }`}>
                      {sandboxResult.status === 'PASSED' ? 'ALLOW: TRUE' : 'DENY: ACTIVATED'}
                    </span>
                  </div>

                  <div className="bg-[#050505] border border-zinc-800 rounded-lg p-3 font-mono text-[11px] space-y-2 max-h-72 overflow-y-auto">
                    <div className="flex items-center justify-between text-zinc-400 border-b border-zinc-800 pb-1">
                      <span>Pacote: {sandboxResult.packageName}</span>
                      <span>Execução: {sandboxResult.executionTimeMs}ms</span>
                    </div>

                    {sandboxResult.denyReasons.length === 0 ? (
                      <div className="text-[#00FF41] py-2 flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4" />
                        <span>Nenhuma negação (deny) acionada. O input está em conformidade.</span>
                      </div>
                    ) : (
                      <div className="space-y-1.5">
                        <span className="text-[#FF3E00] font-bold block">
                          Negações ({sandboxResult.denyReasons.length}):
                        </span>
                        {sandboxResult.denyReasons.map((reason, idx) => (
                          <div
                            key={idx}
                            className="bg-[#111] p-2 rounded border border-[#FF3E00]/30 text-zinc-200 text-[10.5px]"
                          >
                            {reason}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            <p className="text-[10px] font-mono text-zinc-500 text-center pt-2">
              Em conformidade com OPA v0.68 e especificações formais Rego da Cloud Native Computing Foundation (CNCF).
            </p>
          </div>
        </div>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* TAB 3: AUDIT REPORT & QUALITY GATE VIOLATIONS */}
      {/* --------------------------------------------------------------------- */}
      {subTab === 'audit' && (
        <div className="space-y-5">
          {/* Executive Gate Verdict Banner */}
          <div className={`p-5 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
            currentEvaluation.verdict === 'PASSED'
              ? 'bg-[#00FF41]/5 border-[#00FF41]/30 text-zinc-200'
              : currentEvaluation.verdict === 'WARNING'
              ? 'bg-amber-500/5 border-amber-500/30 text-zinc-200'
              : 'bg-[#FF3E00]/5 border-[#FF3E00]/30 text-zinc-200'
          }`}>
            <div className="flex items-center gap-3">
              <div className={`p-3 rounded-xl ${
                currentEvaluation.verdict === 'PASSED'
                  ? 'bg-[#00FF41]/20 text-[#00FF41]'
                  : currentEvaluation.verdict === 'WARNING'
                  ? 'bg-amber-500/20 text-amber-400'
                  : 'bg-[#FF3E00]/20 text-[#FF3E00]'
              }`}>
                {currentEvaluation.verdict === 'PASSED' && <ShieldCheck className="w-8 h-8" />}
                {currentEvaluation.verdict === 'WARNING' && <AlertTriangle className="w-8 h-8" />}
                {currentEvaluation.verdict === 'FAILED_BLOCKING' && <ShieldAlert className="w-8 h-8" />}
              </div>

              <div>
                <h2 className="text-base sm:text-lg font-black tracking-tight text-white flex items-center gap-2">
                  <span>
                    {currentEvaluation.verdict === 'PASSED'
                      ? 'Conformidade Aprovada (Quality Gate Passed)'
                      : currentEvaluation.verdict === 'WARNING'
                      ? 'Conformidade com Avisos (Review Recommended)'
                      : 'Quality Gate Bloqueado (Pipeline Break Enforced)'}
                  </span>
                </h2>
                <p className="text-xs text-zinc-400 mt-0.5">
                  {currentEvaluation.verdict === 'PASSED'
                    ? 'Todos os guardrails organizacionais e requisitos de auditoria foram atendidos com sucesso.'
                    : currentEvaluation.verdict === 'WARNING'
                    ? 'Existem avisos de governança que exigem atenção, mas o deploy não foi bloqueado.'
                    : `Detectadas ${currentEvaluation.blockingViolationsCount} violação(ões) com nível BLOCKING. O código viola os padrões corporativos.`}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3 w-full md:w-auto justify-end">
              <button
                type="button"
                onClick={handleExportEvaluationJson}
                className="px-3 py-2 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-200 text-xs font-mono rounded-lg flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Exportar Relatório OPA</span>
              </button>
            </div>
          </div>

          {/* All Violations Table */}
          <div className="bg-[#0D0D0D] border border-zinc-800 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-zinc-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                  Registro Consolidado de Violações ({currentEvaluation.allViolations.length})
                </span>
              </div>
              <span className="text-[11px] font-mono text-zinc-400">
                {currentEvaluation.blockingViolationsCount} Bloqueantes / {currentEvaluation.warningViolationsCount} Avisos
              </span>
            </div>

            {currentEvaluation.allViolations.length === 0 ? (
              <div className="p-12 text-center text-zinc-500 font-mono text-xs space-y-2">
                <CheckCircle2 className="w-8 h-8 text-[#00FF41] mx-auto opacity-80" />
                <p>Nenhuma violação de política detectada no repositório.</p>
                <p className="text-zinc-600 text-[11px]">Todos os arquivos analisados estão em total conformidade com as regras Rego ativas.</p>
              </div>
            ) : (
              <div className="divide-y divide-zinc-800/80">
                {currentEvaluation.allViolations.map((violation, idx) => (
                  <div key={violation.id || idx} className="p-4 hover:bg-[#111] transition-colors space-y-2">
                    <div className="flex items-center justify-between gap-3 flex-wrap">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                          violation.enforcementLevel === 'BLOCKING'
                            ? 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/30'
                            : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                        }`}>
                          {violation.enforcementLevel}
                        </span>
                        <span className="text-xs font-mono font-bold text-white">
                          {violation.policyName}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-800">
                          {violation.standard.replace(/_/g, ' ')}
                        </span>
                      </div>

                      {violation.targetFile && (
                        <button
                          type="button"
                          onClick={() => {
                            if (violation.targetFindingId) {
                              const found = report.findings.find(f => f.id === violation.targetFindingId);
                              if (found && onSelectFinding) {
                                onSelectFinding(found);
                              }
                            }
                            onNavigateToScanner?.();
                          }}
                          className="text-[#00FF41] hover:underline text-xs font-mono flex items-center gap-1 cursor-pointer"
                        >
                          <span>{violation.targetFile}:{violation.targetLine ?? 1}</span>
                          <ExternalLink className="w-3 h-3" />
                        </button>
                      )}
                    </div>

                    <p className="text-xs text-zinc-300 font-mono bg-black/40 p-2 rounded border border-zinc-800">
                      {violation.message}
                    </p>

                    {violation.remediation && (
                      <p className="text-[11px] text-zinc-400 font-mono">
                        <strong className="text-[#00FF41]">Remediação recomendada:</strong> {violation.remediation}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* TAB 4: CI/CD PIPELINE GUARDRAIL SIMULATOR */}
      {/* --------------------------------------------------------------------- */}
      {subTab === 'cicd' && (
        <div className="space-y-4">
          <div className="bg-[#0D0D0D] border border-zinc-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center gap-2">
              <Workflow className="w-4 h-4 text-purple-400" />
              <h2 className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                Integração do OPA com Pipelines CI/CD (GitHub Actions / GitLab CI)
              </h2>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Incorpore as políticas Rego definidas no SecScan diretamente ao seu pipeline de integração contínua.
              O comando abaixo avalia o arquivo <code className="text-[#00FF41]">secscan-report.json</code> contra o bundle de políticas <code className="text-[#00FF41]">policies/</code> e retorna código de saída 1 caso qualquer regra de negação (deny) seja ativada.
            </p>
          </div>

          <div className="bg-[#050505] border border-zinc-800 rounded-xl p-4 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
              <span className="flex items-center gap-1.5 text-zinc-300">
                <Terminal className="w-3.5 h-3.5 text-[#00FF41]" />
                <span>GitHub Actions Step (.github/workflows/security.yml)</span>
              </span>
              <button
                type="button"
                onClick={() => {
                  const yml = `- name: Setup Open Policy Agent (OPA)
  uses: open-policy-agent/setup-opa@v2
  with:
    version: '0.68.0'

- name: Run SecScan SAST Scanner
  run: npx secscan --target ./src --sarif secscan-report.sarif --json secscan-report.json

- name: Evaluate Policy-as-Code Guardrails
  run: |
    opa eval --data .opa/policies/ \\
      --input secscan-report.json \\
      --fail-defined "data.secscan.compliance.deny"
`;
                  navigator.clipboard.writeText(yml);
                  alert('Snippet YAML copiado!');
                }}
                className="text-xs text-zinc-400 hover:text-white flex items-center gap-1 cursor-pointer font-mono"
              >
                <Copy className="w-3 h-3" />
                <span>Copiar YAML</span>
              </button>
            </div>

            <pre className="bg-[#0A0A0A] p-3 rounded-lg border border-zinc-800 text-[11px] font-mono text-[#00FF41] overflow-x-auto leading-relaxed">
{`- name: Setup Open Policy Agent (OPA)
  uses: open-policy-agent/setup-opa@v2
  with:
    version: '0.68.0'

- name: Run SecScan SAST Scanner
  run: npx secscan --target ./src --sarif secscan-report.sarif --json secscan-report.json

- name: Evaluate Policy-as-Code Guardrails
  run: |
    # Avalia políticas OPA Rego contra o relatório de varredura
    opa eval --data .opa/policies/ \\
      --input secscan-report.json \\
      --fail-defined "data.secscan.compliance.deny"
`}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
