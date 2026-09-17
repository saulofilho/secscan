import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Crosshair,
  Layers,
  FileCheck2,
  ExternalLink,
  Search,
  Filter,
  Download,
  Copy,
  Check,
  RotateCcw,
  Terminal,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ChevronDown,
  ChevronUp,
  BookOpen,
  ArrowRight,
  Sparkles,
  Zap,
  Info,
  Shield,
  Activity,
  FileCode,
  Lock
} from 'lucide-react';
import {
  ScanReport,
  ScanFinding,
  NistAuditStatus,
  WstgTestStatus,
  NistCsfFunctionId
} from '../types';
import {
  MITRE_ATTACK_TECHNIQUES,
  NIST_CSF_SUBCATEGORIES,
  OWASP_WSTG_TEST_CASES,
  correlateFindingsToMitre,
  evaluateAutoNistStatus,
  correlateFindingsToWstg
} from '../lib/frameworksData';
import { safeGetItem, safeSetItem } from '../lib/storage';

interface SecurityFrameworksHubProps {
  report: ScanReport;
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToScanner?: () => void;
}

type MainFrameworkTab = 'MITRE' | 'NIST' | 'WSTG' | 'CORRELATION';

export const SecurityFrameworksHub: React.FC<SecurityFrameworksHubProps> = ({
  report,
  onSelectFinding,
  onNavigateToScanner
}) => {
  const [activeFramework, setActiveFramework] = useState<MainFrameworkTab>('MITRE');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [mitreTacticFilter, setMitreTacticFilter] = useState<string>('ALL');
  const [nistFunctionFilter, setNistFunctionFilter] = useState<NistCsfFunctionId | 'ALL'>('ALL');
  const [wstgCategoryFilter, setWstgCategoryFilter] = useState<string>('ALL');

  const [expandedCards, setExpandedCards] = useState<Record<string, boolean>>({});
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);

  // User-persisted audit states for NIST and WSTG
  const [nistAuditState, setNistAuditState] = useState<Record<string, NistAuditStatus>>(() => {
    const saved = safeGetItem('secscan_nist_csf_audit');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        return {};
      }
    }
    return {};
  });

  const [wstgAuditState, setWstgAuditState] = useState<Record<string, WstgTestStatus>>(() => {
    const saved = safeGetItem('secscan_owasp_wstg_audit');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        return {};
      }
    }
    return {};
  });

  const findings = report.findings || [];

  // 1. MITRE ATT&CK & D3FEND Correlation
  const mitreCorrelations = useMemo(() => {
    return correlateFindingsToMitre(findings);
  }, [findings]);

  const activeMitreExposures = useMemo(() => {
    return mitreCorrelations.filter(c => c.matchedFindings.length > 0);
  }, [mitreCorrelations]);

  // 2. NIST CSF 2.0 Evaluation
  const evaluatedNist = useMemo(() => {
    return NIST_CSF_SUBCATEGORIES.map(sub => {
      const evaluation = evaluateAutoNistStatus(sub, findings, nistAuditState[sub.id]);
      return {
        subcategory: sub,
        status: evaluation.status,
        violatingFindings: evaluation.violatingFindings,
        isAutoComputed: evaluation.isAutoComputed
      };
    });
  }, [findings, nistAuditState]);

  const nistStats = useMemo(() => {
    const total = evaluatedNist.length;
    const compliant = evaluatedNist.filter(e => e.status === 'COMPLIANT').length;
    const partial = evaluatedNist.filter(e => e.status === 'PARTIAL').length;
    const nonCompliant = evaluatedNist.filter(e => e.status === 'NON_COMPLIANT').length;
    const underReview = evaluatedNist.filter(e => e.status === 'UNDER_REVIEW').length;
    
    // Weight: Compliant = 1.0, Partial = 0.5, Non-Compliant = 0, Under Review = 0.25
    const score = Math.round(
      ((compliant * 1.0 + partial * 0.5 + underReview * 0.25) / total) * 100
    );

    let tier = 'Tier 1: Parcial';
    if (score >= 85) tier = 'Tier 4: Adaptativo';
    else if (score >= 65) tier = 'Tier 3: Repetível';
    else if (score >= 45) tier = 'Tier 2: Informado por Risco';

    return { total, compliant, partial, nonCompliant, underReview, score, tier };
  }, [evaluatedNist]);

  // 3. OWASP WSTG Evaluation
  const evaluatedWstg = useMemo(() => {
    return OWASP_WSTG_TEST_CASES.map(tc => {
      const correlated = correlateFindingsToWstg(tc, findings);
      const userStatus = wstgAuditState[tc.id];
      // Auto-fallback: if findings exist for this test case, default to FAILED if not manually set
      const defaultStatus: WstgTestStatus =
        userStatus || (correlated.length > 0 ? 'FAILED' : 'NOT_TESTED');

      return {
        testCase: tc,
        status: defaultStatus,
        isOverridden: !!userStatus,
        correlatedFindings: correlated
      };
    });
  }, [findings, wstgAuditState]);

  const wstgStats = useMemo(() => {
    const total = evaluatedWstg.length;
    const passed = evaluatedWstg.filter(w => w.status === 'PASSED').length;
    const failed = evaluatedWstg.filter(w => w.status === 'FAILED').length;
    const inProgress = evaluatedWstg.filter(w => w.status === 'IN_PROGRESS').length;
    const notTested = evaluatedWstg.filter(w => w.status === 'NOT_TESTED').length;
    const passRate = total > 0 ? Math.round((passed / total) * 100) : 0;
    return { total, passed, failed, inProgress, notTested, passRate };
  }, [evaluatedWstg]);

  // Toggles and persistence
  const toggleExpanded = (id: string) => {
    setExpandedCards(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleUpdateNistStatus = (subId: string, status: NistAuditStatus) => {
    const updated = { ...nistAuditState, [subId]: status };
    setNistAuditState(updated);
    safeSetItem('secscan_nist_csf_audit', JSON.stringify(updated));
  };

  const handleUpdateWstgStatus = (testId: string, status: WstgTestStatus) => {
    const updated = { ...wstgAuditState, [testId]: status };
    setWstgAuditState(updated);
    safeSetItem('secscan_owasp_wstg_audit', JSON.stringify(updated));
  };

  const handleResetAudits = () => {
    if (window.confirm('Deseja resetar as anotações e status manuais de auditoria para os padrões automáticos?')) {
      setNistAuditState({});
      setWstgAuditState({});
      safeSetItem('secscan_nist_csf_audit', JSON.stringify({}));
      safeSetItem('secscan_owasp_wstg_audit', JSON.stringify({}));
    }
  };

  const handleCopyCode = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCodeId(id);
    setTimeout(() => setCopiedCodeId(null), 2000);
  };

  // Generate full markdown audit report
  const handleExportMarkdownReport = () => {
    const lines = [
      `# SECSCAN // RELATÓRIO DE AUDITORIA DE CIBERSEGURANÇA`,
      `**Data de Emissão:** ${new Date().toLocaleString('pt-BR')}`,
      `**Repositório / Workspace:** ${report.scannedFilesCount || report.totalFiles || 0} arquivos analisados | ${findings.length} achados`,
      ``,
      `---`,
      `## 1. MATRIZ MITRE ATT&CK & D3FEND`,
      `- **Técnicas Ativas Expostas:** ${activeMitreExposures.length} de ${MITRE_ATTACK_TECHNIQUES.length}`,
      ...activeMitreExposures.map(
        e =>
          `- [${e.technique.id}] ${e.technique.name} (${e.technique.tacticName}): ${e.matchedFindings.length} achados associados. Contramedidas D3FEND: ${e.technique.d3fendCountermeasures.map(d => d.id).join(', ')}`
      ),
      ``,
      `---`,
      `## 2. NIST CYBERSECURITY FRAMEWORK (CSF 2.0)`,
      `- **Pontuação Geral de Maturidade:** ${nistStats.score}% (${nistStats.tier})`,
      `- Conforme: ${nistStats.compliant} | Parcial: ${nistStats.partial} | Não Conforme: ${nistStats.nonCompliant} | Em Revisão: ${nistStats.underReview}`,
      ...evaluatedNist.map(
        n => `- [${n.status}] ${n.subcategory.id} - ${n.subcategory.title}`
      ),
      ``,
      `---`,
      `## 3. OWASP WEB SECURITY TESTING GUIDE (WSTG v4.2)`,
      `- **Taxa de Aprovação nos Testes:** ${wstgStats.passRate}% (${wstgStats.passed}/${wstgStats.total})`,
      `- Aprovados: ${wstgStats.passed} | Reprovados: ${wstgStats.failed} | Em Andamento: ${wstgStats.inProgress} | Não Testados: ${wstgStats.notTested}`,
      ...evaluatedWstg.map(
        w => `- [${w.status}] ${w.testCase.id} - ${w.testCase.title} (${w.testCase.severity})`
      ),
      ``,
      `*Gerado automaticamente pelo SecScan Engine.*`
    ];

    const content = lines.join('\n');
    navigator.clipboard.writeText(content);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2500);
  };

  const handleExportJson = () => {
    const payload = {
      timestamp: new Date().toISOString(),
      reportMetrics: report.metrics,
      mitre: {
        totalTechniques: MITRE_ATTACK_TECHNIQUES.length,
        activeExposures: activeMitreExposures.map(e => ({
          techniqueId: e.technique.id,
          techniqueName: e.technique.name,
          findingsCount: e.matchedFindings.length,
          countermeasures: e.technique.d3fendCountermeasures.map(d => d.id)
        }))
      },
      nistCsf: {
        score: nistStats.score,
        tier: nistStats.tier,
        breakdown: evaluatedNist.map(n => ({
          id: n.subcategory.id,
          status: n.status,
          title: n.subcategory.title
        }))
      },
      owaspWstg: {
        passRate: wstgStats.passRate,
        tests: evaluatedWstg.map(w => ({
          id: w.testCase.id,
          title: w.testCase.title,
          status: w.status,
          severity: w.testCase.severity
        }))
      }
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secscan-security-frameworks-audit-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Filtered lists
  const filteredMitre = useMemo(() => {
    return mitreCorrelations.filter(c => {
      if (mitreTacticFilter !== 'ALL' && c.technique.tacticId !== mitreTacticFilter) {
        return false;
      }
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        c.technique.id.toLowerCase().includes(q) ||
        c.technique.name.toLowerCase().includes(q) ||
        c.technique.tacticName.toLowerCase().includes(q) ||
        c.technique.description.toLowerCase().includes(q) ||
        c.technique.d3fendCountermeasures.some(d => d.id.toLowerCase().includes(q) || d.name.toLowerCase().includes(q))
      );
    });
  }, [mitreCorrelations, mitreTacticFilter, searchQuery]);

  const filteredNist = useMemo(() => {
    return evaluatedNist.filter(item => {
      if (nistFunctionFilter !== 'ALL' && item.subcategory.functionId !== nistFunctionFilter) {
        return false;
      }
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        item.subcategory.id.toLowerCase().includes(q) ||
        item.subcategory.title.toLowerCase().includes(q) ||
        item.subcategory.requirement.toLowerCase().includes(q) ||
        item.subcategory.categoryName.toLowerCase().includes(q)
      );
    });
  }, [evaluatedNist, nistFunctionFilter, searchQuery]);

  const filteredWstg = useMemo(() => {
    return evaluatedWstg.filter(item => {
      if (wstgCategoryFilter !== 'ALL' && item.testCase.categoryCode !== wstgCategoryFilter) {
        return false;
      }
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        item.testCase.id.toLowerCase().includes(q) ||
        item.testCase.title.toLowerCase().includes(q) ||
        item.testCase.objective.toLowerCase().includes(q) ||
        item.testCase.categoryTitle.toLowerCase().includes(q)
      );
    });
  }, [evaluatedWstg, wstgCategoryFilter, searchQuery]);

  return (
    <div id="security-frameworks-hub" className="space-y-6">
      {/* 1. Top Executive Banner & Stats Dashboard */}
      <div className="p-5 rounded-2xl bg-gradient-to-b from-[#121217] to-[#0A0A0D] border border-white/10 shadow-2xl relative overflow-hidden">
        {/* Subtle decorative glow */}
        <div className="absolute -right-20 -top-20 w-80 h-80 bg-[#FF3E00]/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -left-20 -bottom-20 w-80 h-80 bg-sky-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 pb-4 border-b border-white/10">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="p-1.5 rounded-lg bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/30 shadow-xs">
                <Crosshair className="w-5 h-5" />
              </span>
              <h1 className="text-xl font-black tracking-tight text-white flex items-center gap-2">
                Centro de Frameworks de Cibersegurança
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-white/10 text-zinc-300 uppercase tracking-widest">
                  Workbench
                </span>
              </h1>
            </div>
            <p className="mt-1 text-xs text-zinc-400 max-w-3xl leading-relaxed">
              Mapeamento tático contra ameaças com <strong className="text-zinc-200">MITRE ATT&CK & D3FEND</strong>, auditoria de governança pelo <strong className="text-zinc-200">NIST CSF 2.0</strong> e testes práticos de validação defensiva com o <strong className="text-zinc-200">OWASP WSTG v4.2</strong>.
            </p>
          </div>

          {/* Quick Action Buttons */}
          <div className="flex items-center gap-2 shrink-0 flex-wrap">
            <button
              type="button"
              onClick={handleExportMarkdownReport}
              className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/15 text-zinc-200 text-xs font-mono font-semibold flex items-center gap-1.5 transition-all active:scale-95 shadow-xs"
              title="Copiar relatório completo formatado em Markdown"
            >
              {copiedReport ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-zinc-400" />}
              <span>{copiedReport ? 'Copiado!' : 'Copiar Relatório (MD)'}</span>
            </button>

            <button
              type="button"
              onClick={handleExportJson}
              className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/15 text-zinc-200 text-xs font-mono font-semibold flex items-center gap-1.5 transition-all active:scale-95 shadow-xs"
              title="Baixar auditoria estruturada em JSON"
            >
              <Download className="w-3.5 h-3.5 text-zinc-400" />
              <span>Exportar JSON</span>
            </button>

            <button
              type="button"
              onClick={handleResetAudits}
              className="px-2.5 py-1.5 rounded-lg bg-white/5 hover:bg-rose-950/40 border border-white/10 hover:border-rose-500/30 text-zinc-400 hover:text-rose-300 text-xs transition-all"
              title="Resetar anotações e status manuais de auditoria"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Executive KPI Cards */}
        <div className="relative z-10 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-4">
          {/* Card 1: MITRE ATT&CK */}
          <div
            onClick={() => setActiveFramework('MITRE')}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              activeFramework === 'MITRE'
                ? 'bg-[#FF3E00]/10 border-[#FF3E00]/40 shadow-xs ring-1 ring-[#FF3E00]/30'
                : 'bg-black/40 border-white/10 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase font-bold text-zinc-400">MITRE ATT&CK / D3FEND</span>
              <Crosshair className="w-3.5 h-3.5 text-[#FF3E00]" />
            </div>
            <div className="mt-1.5 flex items-baseline gap-2">
              <span className="text-xl font-mono font-bold text-white">
                {activeMitreExposures.length}
              </span>
              <span className="text-[11px] text-zinc-400">
                / {MITRE_ATTACK_TECHNIQUES.length} Técnicas Ativas
              </span>
            </div>
            <div className="mt-2 text-[10px] text-zinc-400 flex items-center gap-1 truncate">
              {activeMitreExposures.length > 0 ? (
                <span className="text-rose-400 font-semibold flex items-center gap-1">
                  <AlertTriangle className="w-2.5 h-2.5 shrink-0" />
                  Achados no código expõem técnicas
                </span>
              ) : (
                <span className="text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-2.5 h-2.5 shrink-0" />
                  Nenhuma técnica explorada
                </span>
              )}
            </div>
          </div>

          {/* Card 2: NIST CSF 2.0 */}
          <div
            onClick={() => setActiveFramework('NIST')}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              activeFramework === 'NIST'
                ? 'bg-sky-500/10 border-sky-500/40 shadow-xs ring-1 ring-sky-500/30'
                : 'bg-black/40 border-white/10 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase font-bold text-zinc-400">NIST CSF 2.0</span>
              <Shield className="w-3.5 h-3.5 text-sky-400" />
            </div>
            <div className="mt-1.5 flex items-baseline gap-2">
              <span className="text-xl font-mono font-bold text-sky-300">
                {nistStats.score}%
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-950/60 border border-sky-500/30 text-sky-200">
                {nistStats.tier.split(':')[0]}
              </span>
            </div>
            <div className="mt-2 text-[10px] text-zinc-400 flex items-center gap-1.5">
              <span className="text-emerald-400">{nistStats.compliant} Conforme</span>
              <span>•</span>
              <span className="text-amber-400">{nistStats.partial} Parcial</span>
              <span>•</span>
              <span className="text-rose-400">{nistStats.nonCompliant} Não Conf.</span>
            </div>
          </div>

          {/* Card 3: OWASP WSTG v4.2 */}
          <div
            onClick={() => setActiveFramework('WSTG')}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              activeFramework === 'WSTG'
                ? 'bg-emerald-500/10 border-emerald-500/40 shadow-xs ring-1 ring-emerald-500/30'
                : 'bg-black/40 border-white/10 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase font-bold text-zinc-400">OWASP WSTG v4.2</span>
              <FileCheck2 className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <div className="mt-1.5 flex items-baseline gap-2">
              <span className="text-xl font-mono font-bold text-emerald-300">
                {wstgStats.passRate}%
              </span>
              <span className="text-[11px] text-zinc-400">
                Taxa de Aprovação ({wstgStats.passed}/{wstgStats.total})
              </span>
            </div>
            <div className="mt-2 text-[10px] text-zinc-400 flex items-center gap-1.5">
              <span className="text-emerald-400">{wstgStats.passed} Pass</span>
              <span>•</span>
              <span className="text-rose-400">{wstgStats.failed} Fail</span>
              <span>•</span>
              <span className="text-zinc-500">{wstgStats.notTested} Pendentes</span>
            </div>
          </div>

          {/* Card 4: Unified Purple Team Correlation */}
          <div
            onClick={() => setActiveFramework('CORRELATION')}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              activeFramework === 'CORRELATION'
                ? 'bg-purple-500/10 border-purple-500/40 shadow-xs ring-1 ring-purple-500/30'
                : 'bg-black/40 border-white/10 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase font-bold text-zinc-400">Visão Purple Team</span>
              <Layers className="w-3.5 h-3.5 text-purple-400" />
            </div>
            <div className="mt-1.5 flex items-baseline gap-2">
              <span className="text-xl font-mono font-bold text-purple-300">
                {findings.length}
              </span>
              <span className="text-[11px] text-zinc-400">
                Achados Correlacionados
              </span>
            </div>
            <div className="mt-2 text-[10px] text-zinc-400 flex items-center gap-1 truncate">
              <span className="text-purple-300 font-semibold">
                Matriz cruzada unificada (3-em-1)
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Navigation Tabs & Search Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pb-1 border-b border-white/10">
        {/* Framework Selector Tabs */}
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-[#0F0F13] border border-white/10 shrink-0 overflow-x-auto">
          <button
            type="button"
            onClick={() => setActiveFramework('MITRE')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-all whitespace-nowrap ${
              activeFramework === 'MITRE'
                ? 'bg-[#FF3E00] text-white shadow-[0_0_12px_rgba(255,62,0,0.4)]'
                : 'text-zinc-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>MITRE ATT&CK & D3FEND</span>
            {activeMitreExposures.length > 0 && (
              <span className="ml-1 px-1.5 py-0.2 rounded-full bg-black/40 text-[9px]">
                {activeMitreExposures.length}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setActiveFramework('NIST')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-all whitespace-nowrap ${
              activeFramework === 'NIST'
                ? 'bg-sky-600 text-white shadow-[0_0_12px_rgba(2,132,199,0.4)]'
                : 'text-zinc-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>NIST CSF 2.0</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full bg-black/40 text-[9px]">
              {nistStats.score}%
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveFramework('WSTG')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-all whitespace-nowrap ${
              activeFramework === 'WSTG'
                ? 'bg-emerald-600 text-white shadow-[0_0_12px_rgba(5,150,105,0.4)]'
                : 'text-zinc-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <FileCheck2 className="w-3.5 h-3.5" />
            <span>OWASP WSTG v4.2</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full bg-black/40 text-[9px]">
              {wstgStats.passed}/{wstgStats.total}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveFramework('CORRELATION')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-all whitespace-nowrap ${
              activeFramework === 'CORRELATION'
                ? 'bg-purple-600 text-white shadow-[0_0_12px_rgba(147,51,234,0.4)]'
                : 'text-zinc-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Matriz Cruzada</span>
          </button>
        </div>

        {/* Global Search Input */}
        <div className="relative min-w-[240px] flex-1 max-w-md">
          <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Filtrar por ID, técnica, palavra-chave..."
            className="w-full pl-9 pr-8 py-1.5 rounded-xl bg-[#0e0e13] border border-white/10 text-zinc-200 text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-white/30 focus:ring-1 focus:ring-white/20 transition-all"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 text-xs"
            >
              ×
            </button>
          )}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 3. VIEW 1: MITRE ATT&CK & D3FEND MATRIX                                  */}
      {/* ========================================================================= */}
      {activeFramework === 'MITRE' && (
        <div className="space-y-4 animate-fadeIn">
          {/* Tactic Filters & Header */}
          <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-xl bg-black/40 border border-white/10 text-xs">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-zinc-400 font-mono text-[11px] font-semibold">Táticas ATT&CK:</span>
              {(['ALL', 'TA0001', 'TA0002', 'TA0006', 'TA0007', 'TA0009', 'TA0010'] as const).map(tactic => {
                const labelMap: Record<string, string> = {
                  ALL: 'Todas as Táticas',
                  TA0001: 'Acesso Inicial (TA0001)',
                  TA0002: 'Execução (TA0002)',
                  TA0006: 'Acesso a Credenciais (TA0006)',
                  TA0007: 'Descoberta (TA0007)',
                  TA0009: 'Coleta (TA0009)',
                  TA0010: 'Exfiltração (TA0010)'
                };
                return (
                  <button
                    key={tactic}
                    type="button"
                    onClick={() => setMitreTacticFilter(tactic)}
                    className={`px-2.5 py-1 rounded-md text-[11px] font-mono transition-all ${
                      mitreTacticFilter === tactic
                        ? 'bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/50 font-bold'
                        : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/5 border border-transparent'
                    }`}
                  >
                    {labelMap[tactic]}
                  </button>
                );
              })}
            </div>
            <span className="text-[11px] font-mono text-zinc-500">
              Exibindo {filteredMitre.length} técnicas catalogadas
            </span>
          </div>

          {/* Cards List */}
          <div className="space-y-3">
            {filteredMitre.map(({ technique, matchedFindings }) => {
              const isExpanded = expandedCards[technique.id] ?? (matchedFindings.length > 0);
              const isExposed = matchedFindings.length > 0;

              return (
                <div
                  key={technique.id}
                  id={`mitre-card-${technique.id}`}
                  className={`rounded-xl border transition-all duration-200 overflow-hidden ${
                    isExposed
                      ? 'bg-[#120D0D]/90 border-rose-500/40 shadow-[0_0_20px_rgba(244,63,94,0.08)]'
                      : 'bg-[#0E0E12] border-white/10 hover:border-white/20'
                  }`}
                >
                  {/* Card Header Bar */}
                  <div
                    onClick={() => toggleExpanded(technique.id)}
                    className="p-4 cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 select-none"
                  >
                    <div className="flex items-start sm:items-center gap-3">
                      <div
                        className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 border ${
                          isExposed
                            ? 'bg-rose-500/20 text-rose-400 border-rose-500/40 animate-pulse'
                            : 'bg-white/5 text-zinc-400 border-white/10'
                        }`}
                      >
                        {isExposed ? <ShieldAlert className="w-4.5 h-4.5" /> : <Crosshair className="w-4.5 h-4.5" />}
                      </div>

                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-xs font-bold text-white bg-white/10 px-2 py-0.5 rounded border border-white/10">
                            {technique.id}
                          </span>
                          <span className="text-xs font-mono text-[#FF3E00] uppercase tracking-wider font-semibold">
                            {technique.tacticName} ({technique.tacticId})
                          </span>
                          {isExposed && (
                            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/25 border border-rose-500/50 text-rose-300 flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3" />
                              {matchedFindings.length} {matchedFindings.length === 1 ? 'Achado Ativo' : 'Achados Ativos'} no Workspace
                            </span>
                          )}
                        </div>
                        <h3 className="text-sm font-bold text-zinc-100 mt-1">
                          {technique.name}
                        </h3>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 self-end sm:self-center">
                      <a
                        href={technique.docUrl}
                        target="_blank"
                        rel="noreferrer"
                        onClick={e => e.stopPropagation()}
                        className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white border border-white/10 transition-colors"
                        title="Ver documentação oficial no MITRE ATT&CK"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                      <button
                        type="button"
                        className="p-1.5 rounded-lg bg-white/5 text-zinc-400 hover:text-white transition-colors"
                      >
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Expanded Content: Attack details + D3FEND Countermeasures */}
                  {isExpanded && (
                    <div className="p-4 pt-0 border-t border-white/5 space-y-4">
                      {/* Adversary details */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-3">
                        <div className="p-3 rounded-lg bg-black/50 border border-white/5 space-y-1.5">
                          <span className="text-[10.5px] font-mono uppercase font-bold text-zinc-400 flex items-center gap-1">
                            <Crosshair className="w-3 h-3 text-[#FF3E00]" />
                            Descrição da Técnica Ofensiva
                          </span>
                          <p className="text-xs text-zinc-300 leading-relaxed font-sans">
                            {technique.description}
                          </p>
                        </div>

                        <div className="p-3 rounded-lg bg-black/50 border border-white/5 space-y-1.5">
                          <span className="text-[10.5px] font-mono uppercase font-bold text-zinc-400 flex items-center gap-1">
                            <Activity className="w-3 h-3 text-amber-400" />
                            Objetivo do Adversário
                          </span>
                          <p className="text-xs text-zinc-300 leading-relaxed font-sans">
                            {technique.adversaryObjective}
                          </p>
                        </div>
                      </div>

                      {/* Active Workspace Findings Correlation Alert */}
                      {isExposed && (
                        <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-500/30 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-mono font-bold text-rose-300 flex items-center gap-1.5">
                              <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                              Arquivos e Segredos Afetados no Projeto:
                            </span>
                            {onNavigateToScanner && (
                              <button
                                type="button"
                                onClick={onNavigateToScanner}
                                className="text-[11px] font-mono text-rose-300 hover:underline flex items-center gap-1"
                              >
                                Abrir no Inspetor de Código <ArrowRight className="w-3 h-3" />
                              </button>
                            )}
                          </div>
                          <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                            {matchedFindings.map((f, idx) => (
                              <div
                                key={`${f.id}-${idx}`}
                                onClick={() => onSelectFinding && onSelectFinding(f)}
                                className="p-2 rounded bg-black/60 border border-white/5 hover:border-rose-500/40 cursor-pointer flex items-center justify-between text-xs font-mono transition-colors"
                              >
                                <div className="flex items-center gap-2 truncate">
                                  <span className="text-rose-400 font-bold">{f.severity}</span>
                                  <span className="text-zinc-200 truncate">{f.file}:{f.line}</span>
                                  <span className="text-zinc-500 truncate">({f.ruleName})</span>
                                </div>
                                <span className="text-[10px] text-zinc-400 shrink-0">Ver linha</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* D3FEND Defensive Countermeasures (Defensive Engineering) */}
                      <div className="space-y-2.5 pt-1">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-mono uppercase font-bold text-sky-400 flex items-center gap-1.5">
                            <ShieldCheck className="w-4 h-4 text-sky-400" />
                            Contramedidas Defensivas (MITRE D3FEND Matrix)
                          </span>
                          <span className="text-[10px] font-mono text-zinc-500">
                            {technique.d3fendCountermeasures.length} controles defensivos recomendados
                          </span>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                          {technique.d3fendCountermeasures.map(def => {
                            const categoryColorMap: Record<string, string> = {
                              Model: 'text-purple-400 bg-purple-950/40 border-purple-500/30',
                              Harden: 'text-sky-400 bg-sky-950/40 border-sky-500/30',
                              Detect: 'text-amber-400 bg-amber-950/40 border-amber-500/30',
                              Isolate: 'text-indigo-400 bg-indigo-950/40 border-indigo-500/30',
                              Deceive: 'text-pink-400 bg-pink-950/40 border-pink-500/30',
                              Evict: 'text-rose-400 bg-rose-950/40 border-rose-500/30'
                            };

                            return (
                              <div
                                key={def.id}
                                className="p-3 rounded-lg bg-[#0a0a0e] border border-sky-500/20 hover:border-sky-400/40 transition-colors flex flex-col justify-between space-y-2.5"
                              >
                                <div className="space-y-1.5">
                                  <div className="flex items-center justify-between gap-1">
                                    <span className="text-xs font-mono font-bold text-white">
                                      {def.id}
                                    </span>
                                    <span
                                      className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border uppercase ${
                                        categoryColorMap[def.category] || 'text-zinc-300 bg-zinc-800'
                                      }`}
                                    >
                                      {def.category}
                                    </span>
                                  </div>

                                  <h4 className="text-xs font-bold text-sky-200">
                                    {def.name}
                                  </h4>

                                  <p className="text-[11px] text-zinc-400 font-sans leading-relaxed">
                                    {def.description}
                                  </p>
                                </div>

                                <div className="space-y-1.5 pt-2 border-t border-white/5 text-[10.5px]">
                                  <div>
                                    <span className="text-zinc-500 font-mono">Implementação: </span>
                                    <span className="text-zinc-300">{def.implementationGuide}</span>
                                  </div>
                                  <div>
                                    <span className="text-zinc-500 font-mono">Verificação: </span>
                                    <span className="text-emerald-300">{def.verificationMethod}</span>
                                  </div>
                                  <div className="pt-1">
                                    <a
                                      href={def.docUrl}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="text-[10px] font-mono text-sky-400 hover:underline inline-flex items-center gap-1"
                                    >
                                      Ver na Base D3FEND <ExternalLink className="w-2.5 h-2.5" />
                                    </a>
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 4. VIEW 2: NIST CYBERSECURITY FRAMEWORK (CSF 2.0)                        */}
      {/* ========================================================================= */}
      {activeFramework === 'NIST' && (
        <div className="space-y-4 animate-fadeIn">
          {/* Function Filter Pills */}
          <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-xl bg-black/40 border border-white/10 text-xs">
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-zinc-400 font-mono text-[11px] font-semibold">Funções CSF 2.0:</span>
              {(['ALL', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC'] as const).map(fnId => {
                const fnMap: Record<string, string> = {
                  ALL: 'Todas as Funções',
                  GV: 'Govern (GV)',
                  ID: 'Identify (ID)',
                  PR: 'Protect (PR)',
                  DE: 'Detect (DE)',
                  RS: 'Respond (RS)',
                  RC: 'Recover (RC)'
                };
                return (
                  <button
                    key={fnId}
                    type="button"
                    onClick={() => setNistFunctionFilter(fnId)}
                    className={`px-2.5 py-1 rounded-md text-[11px] font-mono transition-all ${
                      nistFunctionFilter === fnId
                        ? 'bg-sky-600/30 text-sky-300 border border-sky-500/60 font-bold'
                        : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/5 border border-transparent'
                    }`}
                  >
                    {fnMap[fnId]}
                  </button>
                );
              })}
            </div>

            <div className="flex items-center gap-2 font-mono text-[11px]">
              <span className="text-zinc-400">Score de Maturidade:</span>
              <span className="text-sky-300 font-bold">{nistStats.score}%</span>
              <span className="px-1.5 py-0.5 rounded bg-sky-950 border border-sky-500/40 text-sky-200 font-bold text-[10px]">
                {nistStats.tier}
              </span>
            </div>
          </div>

          {/* Subcategories List */}
          <div className="space-y-3">
            {filteredNist.map(({ subcategory, status, violatingFindings, isAutoComputed }) => {
              const isExpanded = expandedCards[subcategory.id] ?? false;

              const statusBadgeMap: Record<
                NistAuditStatus,
                { label: string; color: string; border: string; bg: string }
              > = {
                COMPLIANT: {
                  label: 'Conforme',
                  color: 'text-emerald-300',
                  border: 'border-emerald-500/40',
                  bg: 'bg-emerald-950/40'
                },
                PARTIAL: {
                  label: 'Parcial',
                  color: 'text-amber-300',
                  border: 'border-amber-500/40',
                  bg: 'bg-amber-950/40'
                },
                NON_COMPLIANT: {
                  label: 'Não Conforme',
                  color: 'text-rose-300',
                  border: 'border-rose-500/50',
                  bg: 'bg-rose-950/40'
                },
                UNDER_REVIEW: {
                  label: 'Em Auditoria',
                  color: 'text-sky-300',
                  border: 'border-sky-500/40',
                  bg: 'bg-sky-950/40'
                }
              };

              const badge = statusBadgeMap[status];

              return (
                <div
                  key={subcategory.id}
                  id={`nist-card-${subcategory.id}`}
                  className="rounded-xl border border-white/10 bg-[#0E0E12] hover:border-white/20 transition-all overflow-hidden"
                >
                  <div
                    onClick={() => toggleExpanded(subcategory.id)}
                    className="p-4 cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 select-none"
                  >
                    <div className="flex items-start sm:items-center gap-3">
                      <div className="w-9 h-9 rounded-lg bg-sky-950/40 border border-sky-500/30 flex items-center justify-center text-sky-400 font-mono font-bold text-xs shrink-0">
                        {subcategory.functionId}
                      </div>

                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-xs font-bold text-sky-200 bg-sky-950/50 px-2 py-0.5 rounded border border-sky-500/30">
                            {subcategory.id}
                          </span>
                          <span className="text-xs font-mono text-zinc-400">
                            {subcategory.functionName} • {subcategory.categoryName}
                          </span>
                        </div>
                        <h3 className="text-sm font-bold text-zinc-100 mt-1">
                          {subcategory.title}
                        </h3>
                      </div>
                    </div>

                    {/* Status switcher & controls */}
                    <div className="flex items-center gap-3 self-end sm:self-center" onClick={e => e.stopPropagation()}>
                      {/* Status Dropdown */}
                      <div className="flex items-center gap-1.5">
                        <select
                          value={status}
                          onChange={e => handleUpdateNistStatus(subcategory.id, e.target.value as NistAuditStatus)}
                          className={`px-2.5 py-1 rounded-lg text-xs font-mono font-bold border focus:outline-none transition-all ${badge.bg} ${badge.border} ${badge.color}`}
                        >
                          <option value="COMPLIANT">Conforme</option>
                          <option value="PARTIAL">Parcial</option>
                          <option value="NON_COMPLIANT">Não Conforme</option>
                          <option value="UNDER_REVIEW">Em Auditoria</option>
                        </select>
                        {isAutoComputed && (
                          <span
                            className="text-[9px] font-mono text-zinc-500 px-1 py-0.5 rounded bg-white/5"
                            title="Status calculado automaticamente pelo SecScan com base nos achados de código"
                          >
                            Auto
                          </span>
                        )}
                      </div>

                      <a
                        href={subcategory.docUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white border border-white/10 transition-colors"
                        title="Ver padrão oficial no NIST CSF"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>

                      <button
                        type="button"
                        onClick={() => toggleExpanded(subcategory.id)}
                        className="p-1.5 rounded-lg bg-white/5 text-zinc-400 hover:text-white transition-colors"
                      >
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Expanded Content */}
                  {isExpanded && (
                    <div className="p-4 pt-0 border-t border-white/5 space-y-3">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-3">
                        <div className="p-3 rounded-lg bg-black/50 border border-white/5 space-y-1">
                          <span className="text-[10px] font-mono uppercase font-bold text-zinc-400">
                            Requisito do Framework (NIST CSF 2.0)
                          </span>
                          <p className="text-xs text-zinc-300 font-sans leading-relaxed">
                            {subcategory.requirement}
                          </p>
                        </div>

                        <div className="p-3 rounded-lg bg-black/50 border border-white/5 space-y-1">
                          <span className="text-[10px] font-mono uppercase font-bold text-sky-400">
                            Ação Recomendada de DevSecOps
                          </span>
                          <p className="text-xs text-zinc-300 font-sans leading-relaxed">
                            {subcategory.devSecOpsAction}
                          </p>
                        </div>
                      </div>

                      <div className="p-3 rounded-lg bg-black/40 border border-white/5 flex items-center justify-between text-xs font-mono">
                        <div className="flex items-center gap-2">
                          <span className="text-zinc-500">Evidência de Auditoria:</span>
                          <span className="text-zinc-300">{subcategory.verificationEvidence}</span>
                        </div>
                        {violatingFindings.length > 0 && (
                          <span className="text-rose-400 font-bold">
                            {violatingFindings.length} achados em desacordo
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 5. VIEW 3: OWASP WEB SECURITY TESTING GUIDE (WSTG v4.2)                  */}
      {/* ========================================================================= */}
      {activeFramework === 'WSTG' && (
        <div className="space-y-4 animate-fadeIn">
          {/* Category Filter Pills */}
          <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-xl bg-black/40 border border-white/10 text-xs">
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-zinc-400 font-mono text-[11px] font-semibold">Categorias WSTG:</span>
              {(['ALL', 'INFO', 'CONF', 'ATHN', 'ATHZ', 'CRYP', 'INPV', 'BUSL'] as const).map(cat => {
                const catMap: Record<string, string> = {
                  ALL: 'Todas',
                  INFO: 'Info Gathering',
                  CONF: 'Config & Deploy',
                  ATHN: 'Authentication',
                  ATHZ: 'Authorization',
                  CRYP: 'Cryptography',
                  INPV: 'Input Validation',
                  BUSL: 'Business Logic'
                };
                return (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => setWstgCategoryFilter(cat)}
                    className={`px-2.5 py-1 rounded-md text-[11px] font-mono transition-all ${
                      wstgCategoryFilter === cat
                        ? 'bg-emerald-600/30 text-emerald-300 border border-emerald-500/60 font-bold'
                        : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/5 border border-transparent'
                    }`}
                  >
                    {catMap[cat]}
                  </button>
                );
              })}
            </div>

            <div className="flex items-center gap-2 font-mono text-[11px]">
              <span className="text-zinc-400">Aprovação em Testes:</span>
              <span className="text-emerald-300 font-bold">{wstgStats.passRate}%</span>
              <span className="text-zinc-500">({wstgStats.passed} de {wstgStats.total} verificados)</span>
            </div>
          </div>

          {/* Test Cases List */}
          <div className="space-y-3">
            {filteredWstg.map(({ testCase, status, correlatedFindings, isOverridden }) => {
              const isExpanded = expandedCards[testCase.id] ?? (status === 'FAILED');

              const statusBadgeMap: Record<
                WstgTestStatus,
                { label: string; color: string; border: string; bg: string }
              > = {
                PASSED: {
                  label: 'Aprovado (Pass)',
                  color: 'text-emerald-300',
                  border: 'border-emerald-500/40',
                  bg: 'bg-emerald-950/40'
                },
                FAILED: {
                  label: 'Falha (Fail)',
                  color: 'text-rose-300',
                  border: 'border-rose-500/50',
                  bg: 'bg-rose-950/40'
                },
                IN_PROGRESS: {
                  label: 'Em Andamento',
                  color: 'text-amber-300',
                  border: 'border-amber-500/40',
                  bg: 'bg-amber-950/40'
                },
                NOT_TESTED: {
                  label: 'Não Testado',
                  color: 'text-zinc-400',
                  border: 'border-white/10',
                  bg: 'bg-black/40'
                }
              };

              const badge = statusBadgeMap[status];

              const severityColorMap: Record<string, string> = {
                CRITICAL: 'text-rose-400 bg-rose-950/40 border-rose-500/40',
                HIGH: 'text-orange-400 bg-orange-950/40 border-orange-500/40',
                MEDIUM: 'text-amber-400 bg-amber-950/40 border-amber-500/40',
                LOW: 'text-sky-400 bg-sky-950/40 border-sky-500/40',
                INFO: 'text-zinc-400 bg-zinc-800 border-zinc-700'
              };

              return (
                <div
                  key={testCase.id}
                  id={`wstg-card-${testCase.id}`}
                  className={`rounded-xl border transition-all overflow-hidden ${
                    status === 'FAILED'
                      ? 'bg-[#120D0D]/90 border-rose-500/30'
                      : 'bg-[#0E0E12] border-white/10 hover:border-white/20'
                  }`}
                >
                  <div
                    onClick={() => toggleExpanded(testCase.id)}
                    className="p-4 cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 select-none"
                  >
                    <div className="flex items-start sm:items-center gap-3">
                      <div className="w-9 h-9 rounded-lg bg-emerald-950/40 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-mono font-bold text-xs shrink-0">
                        {testCase.categoryCode}
                      </div>

                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-xs font-bold text-emerald-300 bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-500/30">
                            {testCase.id}
                          </span>
                          <span className="text-xs font-mono text-zinc-400">
                            {testCase.categoryTitle}
                          </span>
                          <span
                            className={`text-[9.5px] font-mono font-bold px-1.5 py-0.5 rounded border uppercase ${
                              severityColorMap[testCase.severity] || 'text-zinc-400'
                            }`}
                          >
                            {testCase.severity}
                          </span>
                          {correlatedFindings.length > 0 && (
                            <span className="text-[10px] font-mono font-bold text-rose-400 flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3" />
                              {correlatedFindings.length} achados relacionados
                            </span>
                          )}
                        </div>
                        <h3 className="text-sm font-bold text-zinc-100 mt-1">
                          {testCase.title}
                        </h3>
                      </div>
                    </div>

                    {/* Status switcher & actions */}
                    <div className="flex items-center gap-3 self-end sm:self-center" onClick={e => e.stopPropagation()}>
                      <select
                        value={status}
                        onChange={e => handleUpdateWstgStatus(testCase.id, e.target.value as WstgTestStatus)}
                        className={`px-2.5 py-1 rounded-lg text-xs font-mono font-bold border focus:outline-none transition-all ${badge.bg} ${badge.border} ${badge.color}`}
                      >
                        <option value="PASSED">Aprovado (Pass)</option>
                        <option value="FAILED">Falha (Fail)</option>
                        <option value="IN_PROGRESS">Em Andamento</option>
                        <option value="NOT_TESTED">Não Testado</option>
                      </select>

                      <a
                        href={testCase.docUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white border border-white/10 transition-colors"
                        title="Ver guia oficial no OWASP WSTG"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>

                      <button
                        type="button"
                        onClick={() => toggleExpanded(testCase.id)}
                        className="p-1.5 rounded-lg bg-white/5 text-zinc-400 hover:text-white transition-colors"
                      >
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Expanded Content */}
                  {isExpanded && (
                    <div className="p-4 pt-0 border-t border-white/5 space-y-3">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-3">
                        <div className="p-3 rounded-lg bg-black/50 border border-white/5 space-y-1">
                          <span className="text-[10px] font-mono uppercase font-bold text-zinc-400">
                            Objetivo do Teste Defensivo
                          </span>
                          <p className="text-xs text-zinc-300 font-sans leading-relaxed">
                            {testCase.objective}
                          </p>
                        </div>

                        <div className="p-3 rounded-lg bg-black/50 border border-white/5 space-y-1">
                          <span className="text-[10px] font-mono uppercase font-bold text-emerald-400">
                            Metodologia de Teste
                          </span>
                          <p className="text-xs text-zinc-300 font-sans leading-relaxed whitespace-pre-line">
                            {testCase.methodology}
                          </p>
                        </div>
                      </div>

                      {/* Interactive CLI verification snippet */}
                      <div className="p-3 rounded-lg bg-[#050508] border border-white/10 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-mono uppercase font-bold text-zinc-400 flex items-center gap-1.5">
                            <Terminal className="w-3 h-3 text-emerald-400" />
                            Comando CLI de Auditoria & Verificação:
                          </span>
                          <button
                            type="button"
                            onClick={() => handleCopyCode(testCase.id, testCase.cliVerification)}
                            className="px-2 py-0.5 rounded text-[10px] font-mono bg-white/5 hover:bg-white/10 text-zinc-300 border border-white/10 flex items-center gap-1 transition-all"
                          >
                            {copiedCodeId === testCase.id ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                <span>Copiado!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3 text-zinc-400" />
                                <span>Copiar CLI</span>
                              </>
                            )}
                          </button>
                        </div>
                        <pre className="text-xs font-mono text-emerald-300 bg-black/80 p-2.5 rounded border border-white/5 overflow-x-auto selection:bg-emerald-500 selection:text-black">
                          {testCase.cliVerification}
                        </pre>
                      </div>

                      {/* Remediation guidance */}
                      <div className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-500/20 text-xs font-sans text-emerald-200">
                        <span className="font-bold text-emerald-300 font-mono">Orientação de Correção: </span>
                        {testCase.remediationAdvice}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 6. VIEW 4: UNIFIED PURPLE TEAM CORRELATION MATRIX                         */}
      {/* ========================================================================= */}
      {activeFramework === 'CORRELATION' && (
        <div className="space-y-4 animate-fadeIn">
          <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/30 flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-bold text-purple-200 flex items-center gap-2">
                <Layers className="w-4 h-4 text-purple-400" />
                Matriz de Correlação Cruzada (Purple Team View)
              </h2>
              <p className="text-xs text-zinc-400 mt-0.5">
                Correlaciona os achados identificados no código com as técnicas do MITRE ATT&CK, contramedidas defensivas D3FEND, subcategorias NIST CSF e guias de teste OWASP WSTG.
              </p>
            </div>
            <div className="text-xs font-mono text-purple-300 bg-purple-950/40 px-3 py-1.5 rounded-lg border border-purple-500/40 shrink-0">
              {findings.length} Achados Totais Mapeados
            </div>
          </div>

          {findings.length === 0 ? (
            <div className="p-12 rounded-xl bg-black/30 border border-white/10 text-center space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
              <h3 className="text-sm font-bold text-white">Nenhum achado ativo no momento</h3>
              <p className="text-xs text-zinc-500">
                Seu repositório está limpo. Execute uma nova varredura para cruzar credenciais e rotas detectadas com as matrizes.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-white/10">
              <table className="w-full text-left text-xs font-mono border-collapse">
                <thead>
                  <tr className="bg-[#0F0F14] border-b border-white/10 text-zinc-400">
                    <th className="p-3">Severidade & Regra</th>
                    <th className="p-3">Arquivo / Local</th>
                    <th className="p-3">MITRE ATT&CK</th>
                    <th className="p-3">D3FEND Defensivo</th>
                    <th className="p-3">NIST CSF 2.0</th>
                    <th className="p-3">OWASP WSTG</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 bg-[#09090C]">
                  {findings.map((f, idx) => {
                    // Match MITRE
                    const targetText = `${f.ruleName || ''} ${f.description || ''} ${f.matchedSecret || ''} ${f.file || ''}`.toLowerCase();
                    const matchedMitre = MITRE_ATTACK_TECHNIQUES.find(t =>
                      t.matchedKeywords.some(kw => targetText.includes(kw.toLowerCase()))
                    ) || MITRE_ATTACK_TECHNIQUES[0];

                    const d3fend = matchedMitre.d3fendCountermeasures[0];

                    return (
                      <tr
                        key={`${f.id}-${idx}`}
                        className="hover:bg-white/5 transition-colors cursor-pointer"
                        onClick={() => onSelectFinding && onSelectFinding(f)}
                      >
                        <td className="p-3">
                          <div className="flex items-center gap-1.5">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[9.5px] font-bold ${
                                f.severity === 'CRITICAL'
                                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                                  : f.severity === 'HIGH'
                                  ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                                  : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                              }`}
                            >
                              {f.severity}
                            </span>
                            <span className="font-bold text-zinc-200 truncate max-w-[150px]" title={f.ruleName}>
                              {f.ruleName}
                            </span>
                          </div>
                        </td>

                        <td className="p-3 text-zinc-400 truncate max-w-[180px]" title={`${f.file}:${f.line}`}>
                          {f.file}:{f.line}
                        </td>

                        <td className="p-3">
                          <span className="text-[#FF3E00] font-bold">
                            {matchedMitre.id}
                          </span>
                          <span className="text-zinc-500 block text-[10px] truncate max-w-[140px]">
                            {matchedMitre.name}
                          </span>
                        </td>

                        <td className="p-3">
                          <span className="text-sky-300 font-bold">
                            {d3fend?.id || 'D3-SCRA'}
                          </span>
                          <span className="text-zinc-500 block text-[10px] truncate max-w-[140px]">
                            {d3fend?.name || 'Revocation'}
                          </span>
                        </td>

                        <td className="p-3">
                          <span className="text-sky-400 font-bold">PR.AA-01</span>
                          <span className="text-zinc-500 block text-[10px]">Gestão de Acesso</span>
                        </td>

                        <td className="p-3">
                          <span className="text-emerald-400 font-bold">WSTG-ATHN-06</span>
                          <span className="text-zinc-500 block text-[10px]">Hardcoded Secrets</span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
