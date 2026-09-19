import React, { useState, useMemo } from 'react';
import {
  Activity,
  Play,
  CheckCircle2,
  AlertOctagon,
  ShieldCheck,
  Zap,
  ArrowRight,
  Database,
  Terminal,
  Globe,
  FileCode,
  Layers,
  RotateCcw,
  Sliders,
  Filter,
  Check,
  Copy,
  Info,
  Bug,
  Code2,
  Lock,
  Cpu,
  RefreshCw,
  Search,
  ExternalLink
} from 'lucide-react';
import { ScanReport, ScannedFile } from '../types';
import {
  IastExecutionReport,
  IastHookSensor,
  IastSimulationScenario,
  IastVulnerabilityFinding,
  IastTraceStep
} from '../types/iast';
import {
  INITIAL_IAST_HOOKS,
  IAST_SIMULATION_SCENARIOS,
  runIastRuntimeEmulation
} from '../lib/iastEngine';

interface IastSuiteViewProps {
  report: ScanReport;
  files: ScannedFile[];
  onNavigateToScanner?: () => void;
  onNavigateToDataFlow?: () => void;
}

export const IastSuiteView: React.FC<IastSuiteViewProps> = ({
  report,
  files,
  onNavigateToScanner,
  onNavigateToDataFlow
}) => {
  const [hooks, setHooks] = useState<IastHookSensor[]>(INITIAL_IAST_HOOKS);
  const [scenarios] = useState<IastSimulationScenario[]>(IAST_SIMULATION_SCENARIOS);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>(IAST_SIMULATION_SCENARIOS[0].id);
  const [isEmulating, setIsEmulating] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'FINDINGS' | 'HOOKS_REGISTRY' | 'SIMULATION_LAB' | 'ARCHITECTURE'>('FINDINGS');
  
  // Custom scenario form
  const [customRoute, setCustomRoute] = useState<string>('/api/v1/orders/checkout');
  const [customParam, setCustomParam] = useState<string>('voucherCode');
  const [customPayload, setCustomPayload] = useState<string>("' UNION SELECT 1, cc_number, cvv FROM credit_cards --");
  const [customSink, setCustomSink] = useState<string>('pgClient.query(`SELECT * FROM vouchers WHERE code = \'${req.body.voucherCode}\'`)');

  // Active execution report state
  const [iastReport, setIastReport] = useState<IastExecutionReport>(() => {
    return report.iastReport || runIastRuntimeEmulation(files, INITIAL_IAST_HOOKS);
  });

  const [selectedFindingId, setSelectedFindingId] = useState<string>(() => {
    return iastReport.findings[0]?.id || '';
  });

  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);

  const selectedFinding = useMemo(() => {
    return iastReport.findings.find(f => f.id === selectedFindingId) || iastReport.findings[0];
  }, [iastReport.findings, selectedFindingId]);

  const filteredFindings = useMemo(() => {
    if (severityFilter === 'ALL') return iastReport.findings;
    return iastReport.findings.filter(f => f.severity === severityFilter);
  }, [iastReport.findings, severityFilter]);

  const toggleHook = (hookId: string) => {
    setHooks(prev => {
      const updated = prev.map(h => h.id === hookId ? { ...h, active: !h.active } : h);
      const newReport = runIastRuntimeEmulation(files, updated);
      setIastReport(newReport);
      return updated;
    });
  };

  const handleRunSimulation = (scenario?: IastSimulationScenario) => {
    setIsEmulating(true);
    setTimeout(() => {
      const newReport = runIastRuntimeEmulation(files, hooks, scenario);
      setIastReport(newReport);
      if (newReport.findings.length > 0) {
        setSelectedFindingId(newReport.findings[0].id);
      }
      setIsEmulating(false);
    }, 600);
  };

  const handleRunCustomSimulation = () => {
    const custom: IastSimulationScenario = {
      id: `custom-${Date.now()}`,
      name: `Emulação Interativa Customizada (${customRoute})`,
      targetRoute: customRoute,
      httpMethod: 'POST',
      inputPayload: { [customParam]: customPayload },
      vulnerabilityTarget: customSink,
      attackVectorType: 'SQLi',
      description: 'Execução de cenário customizado com hooks ativos em tempo real.'
    };
    handleRunSimulation(custom);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCodeId(id);
    setTimeout(() => setCopiedCodeId(null), 2000);
  };

  return (
    <div className="w-full max-w-7xl mx-auto px-4 py-6 space-y-6">
      {/* Top Banner & Title */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-5 rounded-xl border border-cyan-500/20 bg-gradient-to-r from-cyan-950/40 via-black to-[#080d14]">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <span className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Activity className="w-5 h-5" />
            </span>
            <h1 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
              IAST Runtime Emulation Suite
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 font-bold">
                Dynamic Taint Hooks
              </span>
            </h1>
          </div>
          <p className="text-xs text-white/70 max-w-2xl leading-relaxed">
            Instrumentação interativa em tempo de execução para complementar a análise estática (SAST). 
            Detecta vulnerabilidades que só se manifestam dinamicamente na execução (SQLi na AST, RCE em subprocessos, SSRF e Path Traversal).
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5">
          <button
            id="btn-run-iast-emulation"
            onClick={() => handleRunSimulation()}
            disabled={isEmulating}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs font-mono transition-all shadow-lg shadow-cyan-500/20 disabled:opacity-50 cursor-pointer"
          >
            {isEmulating ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Emulando Requisições...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Emular Runtime & Hooks</span>
              </>
            )}
          </button>

          {onNavigateToDataFlow && (
            <button
              onClick={onNavigateToDataFlow}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-white/80 hover:text-white border border-white/10 text-xs font-mono transition-colors cursor-pointer"
            >
              <Layers className="w-3.5 h-3.5 text-purple-400" />
              <span>Ver Grafo D3</span>
            </button>
          )}
        </div>
      </div>

      {/* Metric Cards Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        <div className="p-3.5 rounded-xl border border-white/10 bg-black/40 space-y-1">
          <span className="text-[10px] font-mono text-white/50 uppercase tracking-wider block">Achados Confirmados</span>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-rose-400 font-mono">{iastReport.findings.length}</span>
            <span className="text-[11px] text-rose-400/80 font-mono font-medium">100% Execução</span>
          </div>
          <span className="text-[10px] text-white/40 block">Zero falsos positivos via AST</span>
        </div>

        <div className="p-3.5 rounded-xl border border-white/10 bg-black/40 space-y-1">
          <span className="text-[10px] font-mono text-white/50 uppercase tracking-wider block">Hooks Ativos</span>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-cyan-400 font-mono">{hooks.filter(h => h.active).length}</span>
            <span className="text-[11px] text-white/40 font-mono">/ {hooks.length} sensores</span>
          </div>
          <span className="text-[10px] text-white/40 block">Drivers SQL, fs, child_process</span>
        </div>

        <div className="p-3.5 rounded-xl border border-white/10 bg-black/40 space-y-1">
          <span className="text-[10px] font-mono text-white/50 uppercase tracking-wider block">Chamadas Interceptadas</span>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-emerald-400 font-mono">{iastReport.totalHooksTriggered}</span>
            <span className="text-[11px] text-emerald-400/80 font-mono">interceptações</span>
          </div>
          <span className="text-[10px] text-white/40 block">Emulação com overhead de ~1.4ms</span>
        </div>

        <div className="p-3.5 rounded-xl border border-white/10 bg-black/40 space-y-1">
          <span className="text-[10px] font-mono text-white/50 uppercase tracking-wider block">Redução Falsos Positivos</span>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-amber-400 font-mono">{iastReport.coverageMetrics.falsePositiveReductionPercent}%</span>
            <span className="text-[11px] text-amber-400/80 font-mono">vs SAST puro</span>
          </div>
          <span className="text-[10px] text-white/40 block">Validação no sink real</span>
        </div>

        <div className="p-3.5 rounded-xl border border-white/10 bg-black/40 space-y-1 col-span-2 sm:col-span-1">
          <span className="text-[10px] font-mono text-white/50 uppercase tracking-wider block">Taxa Sucesso Taint</span>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-purple-400 font-mono">{iastReport.coverageMetrics.taintPropagationSuccessRate}%</span>
            <span className="text-[11px] text-purple-400/80 font-mono">rastreabilidade</span>
          </div>
          <span className="text-[10px] text-white/40 block">Origem HTTP até o Sink</span>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex border-b border-white/10 gap-2">
        <button
          onClick={() => setActiveTab('FINDINGS')}
          className={`px-4 py-2 text-xs font-mono font-medium border-b-2 transition-colors cursor-pointer flex items-center gap-2 ${
            activeTab === 'FINDINGS'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
              : 'border-transparent text-white/60 hover:text-white'
          }`}
        >
          <Bug className="w-3.5 h-3.5" />
          <span>Vulnerabilidades em Runtime ({iastReport.findings.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('SIMULATION_LAB')}
          className={`px-4 py-2 text-xs font-mono font-medium border-b-2 transition-colors cursor-pointer flex items-center gap-2 ${
            activeTab === 'SIMULATION_LAB'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
              : 'border-transparent text-white/60 hover:text-white'
          }`}
        >
          <Zap className="w-3.5 h-3.5" />
          <span>Laboratório de Emulação Interativa</span>
        </button>

        <button
          onClick={() => setActiveTab('HOOKS_REGISTRY')}
          className={`px-4 py-2 text-xs font-mono font-medium border-b-2 transition-colors cursor-pointer flex items-center gap-2 ${
            activeTab === 'HOOKS_REGISTRY'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
              : 'border-transparent text-white/60 hover:text-white'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>Sensores & Hooks Instalados ({hooks.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('ARCHITECTURE')}
          className={`px-4 py-2 text-xs font-mono font-medium border-b-2 transition-colors cursor-pointer flex items-center gap-2 ${
            activeTab === 'ARCHITECTURE'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
              : 'border-transparent text-white/60 hover:text-white'
          }`}
        >
          <Info className="w-3.5 h-3.5" />
          <span>Arquitetura IAST vs SAST</span>
        </button>
      </div>

      {/* Tab 1: Findings and Deep Runtime Call Graph */}
      {activeTab === 'FINDINGS' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Findings List Column (5 cols) */}
          <div className="lg:col-span-5 space-y-3">
            <div className="flex items-center justify-between pb-1">
              <span className="text-xs font-mono text-white/60">Filtro de Severidade:</span>
              <div className="flex gap-1">
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(lvl => (
                  <button
                    key={lvl}
                    onClick={() => setSeverityFilter(lvl)}
                    className={`px-2 py-0.5 rounded text-[10px] font-mono cursor-pointer transition-colors ${
                      severityFilter === lvl
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                        : 'bg-white/5 text-white/50 hover:text-white'
                    }`}
                  >
                    {lvl}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-2 max-h-[640px] overflow-y-auto pr-1">
              {filteredFindings.map(finding => {
                const isSelected = finding.id === selectedFinding?.id;
                return (
                  <div
                    key={finding.id}
                    onClick={() => setSelectedFindingId(finding.id)}
                    className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-cyan-950/30 border-cyan-500/50 shadow-md shadow-cyan-500/10'
                        : 'bg-black/40 border-white/10 hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 pb-1.5">
                      <div className="flex items-center gap-1.5">
                        <span className={`w-2 h-2 rounded-full ${
                          finding.severity === 'CRITICAL' ? 'bg-rose-500' :
                          finding.severity === 'HIGH' ? 'bg-amber-500' : 'bg-yellow-500'
                        }`} />
                        <span className="text-xs font-bold text-white font-mono">{finding.id}</span>
                        <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/40 px-1.5 py-0.2 rounded border border-cyan-800/40">
                          {finding.cwe.id}
                        </span>
                      </div>

                      <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-bold uppercase ${
                        finding.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                        finding.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                        'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30'
                      }`}>
                        {finding.severity}
                      </span>
                    </div>

                    <h3 className="text-xs font-semibold text-white/90 leading-snug line-clamp-2">
                      {finding.title}
                    </h3>

                    <div className="mt-2 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] text-white/50 font-mono">
                      <span className="flex items-center gap-1 truncate max-w-[200px]">
                        <Globe className="w-3 h-3 text-cyan-400 shrink-0" />
                        <span>{finding.httpMethod} {finding.sourceEndpoint}</span>
                      </span>
                      <span className="text-emerald-400 font-semibold">{finding.confidence}% Confiança</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Finding Details & Trace Path (7 cols) */}
          <div className="lg:col-span-7 space-y-4">
            {selectedFinding ? (
              <div className="p-5 rounded-xl border border-white/10 bg-black/60 space-y-5">
                {/* Header finding */}
                <div className="space-y-2 border-b border-white/10 pb-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-rose-500/20 border border-rose-500/30 text-rose-300 font-mono text-[11px] font-bold">
                        {selectedFinding.severity}
                      </span>
                      <span className="text-xs font-mono text-cyan-400 font-bold">
                        {selectedFinding.cwe.id} - {selectedFinding.cwe.name}
                      </span>
                    </div>

                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                      Status: {selectedFinding.status} (Dynamic Interception)
                    </span>
                  </div>

                  <h2 className="text-base font-bold text-white leading-snug">
                    {selectedFinding.title}
                  </h2>
                  <p className="text-xs text-white/70 leading-relaxed">
                    {selectedFinding.vulnerabilityExplanation}
                  </p>
                </div>

                {/* Runtime Evidence Box */}
                <div className="p-3.5 rounded-lg border border-cyan-500/30 bg-cyan-950/20 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono uppercase text-cyan-300 font-bold flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                      Evidência de Execução Capturada pelo Hook
                    </span>
                    <span className="text-[10px] font-mono text-white/50">
                      Duração do Sink: {selectedFinding.runtimeEvidence.runtimeDurationMs}ms
                    </span>
                  </div>

                  <div className="p-2.5 rounded bg-black/80 font-mono text-[11px] text-white/90 border border-white/10 break-all space-y-1.5">
                    <div>
                      <span className="text-white/40 block text-[10px]">Chamada Executada no Sink em Runtime:</span>
                      <span className="text-rose-300 font-semibold">{selectedFinding.runtimeEvidence.executedQueryOrCommand}</span>
                    </div>
                    <div>
                      <span className="text-white/40 block text-[10px]">Substring Tainted Injetada:</span>
                      <span className="text-amber-300 bg-amber-950/40 px-1 py-0.5 rounded border border-amber-800/40">
                        {selectedFinding.runtimeEvidence.unfilteredTaintSubstring}
                      </span>
                    </div>
                    {selectedFinding.runtimeEvidence.sanitizerBypassed && (
                      <div className="text-[10.5px] text-white/60 italic">
                        Nota de Análise: {selectedFinding.runtimeEvidence.sanitizerBypassed}
                      </div>
                    )}
                  </div>
                </div>

                {/* Step-by-Step Taint Propagation Flow */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-mono font-bold text-white flex items-center gap-2 uppercase tracking-wider">
                      <Activity className="w-3.5 h-3.5 text-purple-400" />
                      Trilha de Propagação de Dados (Taint Flow em Runtime)
                    </h3>
                    <span className="text-[10px] font-mono text-white/40">
                      {selectedFinding.tracePath.length} Etapas Rastreadas
                    </span>
                  </div>

                  <div className="relative border-l-2 border-cyan-500/30 ml-3 space-y-4 py-1">
                    {selectedFinding.tracePath.map((step, idx) => (
                      <div key={idx} className="relative pl-6">
                        {/* Dot indicator */}
                        <div className="absolute -left-[9px] top-1 w-4 h-4 rounded-full bg-cyan-500/20 border-2 border-cyan-400 flex items-center justify-center">
                          <div className="w-1.5 h-1.5 rounded-full bg-cyan-300" />
                        </div>

                        <div className="p-3 rounded-lg bg-black/40 border border-white/10 space-y-1.5 text-xs font-mono">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-[11px] font-bold text-cyan-300">
                              Etapa #{step.stepIndex}: {step.functionName}
                            </span>
                            <span className="text-[10px] text-white/50">
                              {step.file}:{step.line}
                            </span>
                          </div>

                          <div className="text-[11px] text-white/80">
                            {step.description}
                          </div>

                          <div className="bg-black/60 p-2 rounded border border-white/5 text-[10.5px] flex items-center justify-between gap-2">
                            <div className="truncate">
                              <span className="text-white/40">Variável: </span>
                              <span className="text-purple-300">{step.variableName}</span>
                              <span className="text-white/40"> = </span>
                              <span className="text-amber-300">"{step.runtimeValue}"</span>
                            </div>
                            <span className="text-[9px] font-bold px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 shrink-0">
                              TAINTED
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Call Stack Inspection */}
                <div className="space-y-2">
                  <h4 className="text-xs font-mono font-bold text-white/80 uppercase">
                    Call Stack de Execução no Momento do Sink
                  </h4>
                  <div className="p-2.5 rounded-lg bg-black/80 border border-white/10 font-mono text-[10.5px] text-white/70 space-y-1 max-h-32 overflow-y-auto">
                    {selectedFinding.runtimeCallStack.map((frame, fIdx) => (
                      <div key={fIdx} className="text-white/60 hover:text-white transition-colors">
                        {frame}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Remediation & Code Diff */}
                <div className="space-y-3 pt-2 border-t border-white/10">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1.5 uppercase">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                      Remediação e Código Seguro Recomendado
                    </h3>
                    <button
                      onClick={() => copyToClipboard(selectedFinding.remediationCodeExample.secure, selectedFinding.id)}
                      className="flex items-center gap-1 text-[10px] font-mono text-white/60 hover:text-white px-2 py-1 rounded bg-white/5 border border-white/10 cursor-pointer"
                    >
                      {copiedCodeId === selectedFinding.id ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-300">Copiado</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copiar Fix</span>
                        </>
                      )}
                    </button>
                  </div>

                  <p className="text-xs text-white/80 leading-relaxed">
                    {selectedFinding.remediationAdvice}
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <span className="text-[10px] font-mono text-rose-400 uppercase font-bold">Padrão Vulnerável (Antes):</span>
                      <pre className="p-2.5 rounded bg-rose-950/20 border border-rose-500/30 text-[10.5px] font-mono text-rose-200 overflow-x-auto">
                        {selectedFinding.remediationCodeExample.vulnerable}
                      </pre>
                    </div>

                    <div className="space-y-1">
                      <span className="text-[10px] font-mono text-emerald-400 uppercase font-bold">Padrão Seguro (Depois):</span>
                      <pre className="p-2.5 rounded bg-emerald-950/20 border border-emerald-500/30 text-[10.5px] font-mono text-emerald-200 overflow-x-auto">
                        {selectedFinding.remediationCodeExample.secure}
                      </pre>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-12 text-center border border-white/10 rounded-xl bg-black/40 text-white/50 font-mono text-xs">
                Selecione uma vulnerabilidade para inspecionar a trilha de propagação IAST.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Simulation Lab */}
      {activeTab === 'SIMULATION_LAB' && (
        <div className="space-y-6">
          <div className="p-5 rounded-xl border border-white/10 bg-black/60 space-y-4">
            <h2 className="text-sm font-bold font-mono text-white flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              Cenários Predefinidos de Emulação Dinâmica
            </h2>
            <p className="text-xs text-white/70">
              Dispare requisições simuladas através dos controllers do workspace. Os sensores IAST monitoram a AST das queries, parâmetros de shell e chamadas de arquivo em tempo real.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
              {scenarios.map(sc => (
                <div
                  key={sc.id}
                  className={`p-4 rounded-xl border transition-all space-y-2.5 ${
                    selectedScenarioId === sc.id
                      ? 'bg-cyan-950/30 border-cyan-500/50'
                      : 'bg-black/40 border-white/10 hover:border-white/20'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold">
                      {sc.attackVectorType}
                    </span>
                    <span className="text-[10px] font-mono text-white/50">{sc.httpMethod} {sc.targetRoute}</span>
                  </div>

                  <h4 className="text-xs font-bold text-white leading-snug">{sc.name}</h4>
                  <p className="text-[11px] text-white/60 leading-relaxed line-clamp-2">{sc.description}</p>

                  <div className="p-2 rounded bg-black/60 border border-white/5 font-mono text-[10px] text-amber-300/90 truncate">
                    Payload: {JSON.stringify(sc.inputPayload)}
                  </div>

                  <button
                    onClick={() => {
                      setSelectedScenarioId(sc.id);
                      handleRunSimulation(sc);
                    }}
                    disabled={isEmulating}
                    className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 text-cyan-300 font-mono text-xs font-semibold cursor-pointer transition-colors"
                  >
                    <Play className="w-3 h-3 fill-current" />
                    <span>Executar Emulação</span>
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Custom Simulation Form */}
          <div className="p-5 rounded-xl border border-white/10 bg-black/60 space-y-4">
            <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-purple-400" />
              Injetor Customizado de Requisição em Runtime
            </h3>
            <p className="text-xs text-white/70">
              Defina uma rota arbitrária e payload de teste para avaliar se os hooks IAST interceptam a propagação no sink de destino.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs font-mono text-white/70">Rota HTTP de Origem:</label>
                <input
                  type="text"
                  value={customRoute}
                  onChange={(e) => setCustomRoute(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-black border border-white/15 text-white font-mono text-xs focus:border-cyan-400 outline-none"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-mono text-white/70">Nome do Parâmetro de Entrada:</label>
                <input
                  type="text"
                  value={customParam}
                  onChange={(e) => setCustomParam(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-black border border-white/15 text-white font-mono text-xs focus:border-cyan-400 outline-none"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-mono text-white/70">Payload Simulado (Tainted String):</label>
                <input
                  type="text"
                  value={customPayload}
                  onChange={(e) => setCustomPayload(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-black border border-white/15 text-white font-mono text-xs focus:border-cyan-400 outline-none"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-mono text-white/70">Sink Alvo Simulado:</label>
                <input
                  type="text"
                  value={customSink}
                  onChange={(e) => setCustomSink(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-black border border-white/15 text-white font-mono text-xs focus:border-cyan-400 outline-none"
                />
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={handleRunCustomSimulation}
                disabled={isEmulating}
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold text-xs font-mono transition-all shadow-md shadow-purple-600/30 cursor-pointer"
              >
                <Zap className="w-3.5 h-3.5 fill-current" />
                <span>Disparar Injeção Customizada</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Hooks Registry */}
      {activeTab === 'HOOKS_REGISTRY' && (
        <div className="p-5 rounded-xl border border-white/10 bg-black/60 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" />
                Sensores de Instrumentação em Tempo de Execução
              </h2>
              <p className="text-xs text-white/70 mt-1">
                Ganchos (hooks) instalados dinamicamente nos módulos do Node.js/JavaScript para inspecionar parâmetros antes da execução real.
              </p>
            </div>
            <span className="text-xs font-mono text-cyan-400 bg-cyan-950/40 px-2.5 py-1 rounded-lg border border-cyan-800/40">
              {hooks.filter(h => h.active).length} Ativos
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 pt-2">
            {hooks.map(hook => (
              <div
                key={hook.id}
                className={`p-4 rounded-xl border transition-all space-y-3 ${
                  hook.active
                    ? 'bg-black/50 border-white/15'
                    : 'bg-black/20 border-white/5 opacity-60'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="p-1.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                      <Code2 className="w-4 h-4" />
                    </span>
                    <div>
                      <h4 className="text-xs font-bold text-white font-mono">{hook.name}</h4>
                      <span className="text-[10px] text-white/50 font-mono">{hook.category}</span>
                    </div>
                  </div>

                  <button
                    onClick={() => toggleHook(hook.id)}
                    className={`px-3 py-1 rounded-lg font-mono text-[11px] font-bold cursor-pointer transition-colors ${
                      hook.active
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        : 'bg-white/5 text-white/40 border border-white/10 hover:text-white'
                    }`}
                  >
                    {hook.active ? 'ATIVADO' : 'DESATIVADO'}
                  </button>
                </div>

                <p className="text-xs text-white/70 leading-relaxed">{hook.description}</p>

                <div className="flex items-center justify-between text-[11px] font-mono pt-2 border-t border-white/5 text-white/60">
                  <span className="text-cyan-300 truncate max-w-[240px]">
                    Alvo: {hook.targetPackageOrGlobal}
                  </span>
                  <span className="text-emerald-400">
                    {hook.interceptedCallsCount} chamadas monitoradas
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 4: Architecture Comparison */}
      {activeTab === 'ARCHITECTURE' && (
        <div className="p-5 rounded-xl border border-white/10 bg-black/60 space-y-5">
          <h2 className="text-sm font-bold font-mono text-white flex items-center gap-2">
            <Info className="w-4 h-4 text-cyan-400" />
            Como o IAST Complementa o SAST Existente no SecScan
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl border border-blue-500/20 bg-blue-950/10 space-y-2.5">
              <span className="text-xs font-mono font-bold text-blue-400 uppercase tracking-wider block">
                SAST (Static Application Security Testing)
              </span>
              <ul className="space-y-2 text-xs text-white/80 list-disc list-inside">
                <li>Analisa o código-fonte estático sem executá-lo (Regex, AST, LinkFinder).</li>
                <li>Identifica chaves hardcoded, credenciais e chamadas inseguras sintáticas.</li>
                <li>Pode gerar falsos positivos se uma sanitização ou guard ocorrer fora do escopo léxico visível.</li>
                <li>Excelente para cobertura ampla (100% dos arquivos do repositório).</li>
              </ul>
            </div>

            <div className="p-4 rounded-xl border border-cyan-500/30 bg-cyan-950/20 space-y-2.5">
              <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider block">
                IAST (Interactive Application Security Testing)
              </span>
              <ul className="space-y-2 text-xs text-white/80 list-disc list-inside">
                <li>Opera dentro da aplicação através de agentes/hooks de instrumentação.</li>
                <li>Rastreia variáveis com tags Taint desde a entrada HTTP até o driver SQL/OS.</li>
                <li>Garante zero falsos positivos ao verificar se a árvore sintática do comando foi alterada no runtime.</li>
                <li>Identifica falhas que só ocorrem mediante encadeamento dinâmico de dados.</li>
              </ul>
            </div>
          </div>

          <div className="p-4 rounded-xl border border-white/10 bg-black/40 space-y-2">
            <h4 className="text-xs font-mono font-bold text-white uppercase">Fluxo Integrado DevSecOps</h4>
            <p className="text-xs text-white/70 leading-relaxed">
              O SecScan executa primeiro a varredura SAST para mapear a superfície de ataque (endpoints de API, segredos e sinks perigosos) e, em seguida, engaja o motor IAST para emular fluxos de dados reais através dos pontos críticos identificados, fornecendo relatórios com call stacks reais e evidências determinísticas.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
