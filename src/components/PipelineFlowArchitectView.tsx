import React, { useState, useMemo, useEffect } from 'react';
import {
  Workflow,
  GitBranch,
  Play,
  Copy,
  Check,
  Download,
  FileCode,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  GripVertical,
  Plus,
  Trash2,
  SlidersHorizontal,
  Layers,
  ArrowRight,
  Terminal,
  RefreshCw,
  Sparkles,
  Info,
  CheckCircle2,
  XCircle,
  Clock,
  Settings,
  ChevronDown,
  ChevronUp,
  FileSpreadsheet,
  Lock,
  Boxes,
  Save,
  Zap,
  RotateCcw,
  ExternalLink,
  ChevronRight,
  Filter,
  Eye,
  Activity
} from 'lucide-react';
import { ScanFinding, SeverityLevel, ScannedFile, AuditLogEvent } from '../types';
import {
  PipelineStageId,
  PipelineActionStep,
  PipelineStageConfig,
  PipelineArchitectConfig,
  DEFAULT_PIPELINE_STAGES,
  INITIAL_ACTION_STEPS,
  PIPELINE_PRESETS,
  autoCategorizeFindingToStage,
  buildInitialFindingStageMapping,
  generateGitHubActionsWorkflowYaml,
  simulatePipelineRun,
  PipelineSimulationReport,
  StageSimulationResult
} from '../lib/pipelineFlowEngine';

interface PipelineFlowArchitectViewProps {
  findings: ScanFinding[];
  files: ScannedFile[];
  onUpdateFiles?: (updatedFiles: ScannedFile[]) => void;
  onNavigateToFile?: (filePath: string, line?: number) => void;
  onLogAudit?: (event: AuditLogEvent) => void;
}

export const PipelineFlowArchitectView: React.FC<PipelineFlowArchitectViewProps> = ({
  findings = [],
  files = [],
  onUpdateFiles,
  onNavigateToFile,
  onLogAudit
}) => {
  // State for pipeline configuration
  const [workflowName, setWorkflowName] = useState('SecScan Shift-Left DevSecOps Pipeline');
  const [stages, setStages] = useState<Record<PipelineStageId, PipelineStageConfig>>(DEFAULT_PIPELINE_STAGES);
  const [steps, setSteps] = useState<PipelineActionStep[]>(INITIAL_ACTION_STEPS);
  const [findingStageMapping, setFindingStageMapping] = useState<Record<string, PipelineStageId>>(() =>
    buildInitialFindingStageMapping(findings)
  );

  // Workflow trigger settings
  const [triggerPush, setTriggerPush] = useState(true);
  const [triggerPullRequest, setTriggerPullRequest] = useState(true);
  const [triggerSchedule, setTriggerSchedule] = useState(true);
  const [triggerWorkflowDispatch, setTriggerWorkflowDispatch] = useState(true);
  const [runner, setRunner] = useState('ubuntu-latest');
  const [nodeVersion, setNodeVersion] = useState('22');
  const [uploadSarif, setUploadSarif] = useState(true);
  const [concurrencyGroup, setConcurrencyGroup] = useState(true);
  const [branches, setBranches] = useState<string[]>(['main', 'master']);
  const [newBranchInput, setNewBranchInput] = useState('');

  // UI state
  const [activeTab, setActiveTab] = useState<'visual' | 'yaml' | 'simulation'>('visual');
  const [selectedStageForFindings, setSelectedStageForFindings] = useState<PipelineStageId | 'ALL'>('ALL');
  const [findingSearch, setFindingSearch] = useState('');
  const [findingSeverityFilter, setFindingSeverityFilter] = useState<string>('ALL');
  const [copiedYaml, setCopiedYaml] = useState(false);
  const [savedToWorkspace, setSavedToWorkspace] = useState(false);
  const [showSettingsDrawer, setShowSettingsDrawer] = useState(false);
  const [showAddStepModal, setShowAddStepModal] = useState(false);
  const [targetStageForNewStep, setTargetStageForNewStep] = useState<PipelineStageId>('pre-commit');

  // Drag & drop tracking state
  const [draggedItem, setDraggedItem] = useState<{
    type: 'FINDING' | 'STEP';
    id: string;
    sourceStage?: PipelineStageId;
  } | null>(null);
  const [dragOverStage, setDragOverStage] = useState<PipelineStageId | null>(null);

  // Simulation state
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulatedStageProgress, setSimulatedStageProgress] = useState<PipelineStageId | null>(null);
  const [simulationReport, setSimulationReport] = useState<PipelineSimulationReport | null>(null);

  // Synchronize initial findings if findings change
  useEffect(() => {
    setFindingStageMapping(prev => {
      const next = { ...prev };
      findings.forEach(f => {
        if (!next[f.id]) {
          next[f.id] = autoCategorizeFindingToStage(f);
        }
      });
      return next;
    });
  }, [findings]);

  // Derived full config
  const fullConfig: PipelineArchitectConfig = useMemo(() => ({
    workflowName,
    fileName: '.github/workflows/secscan-pipeline.yml',
    triggerPush,
    triggerPullRequest,
    triggerSchedule,
    triggerWorkflowDispatch,
    branches,
    runner,
    nodeVersion,
    uploadSarif,
    concurrencyGroup,
    stages,
    steps,
    findingStageMapping
  }), [
    workflowName,
    triggerPush,
    triggerPullRequest,
    triggerSchedule,
    triggerWorkflowDispatch,
    branches,
    runner,
    nodeVersion,
    uploadSarif,
    concurrencyGroup,
    stages,
    steps,
    findingStageMapping
  ]);

  // Generated YAML code
  const generatedYaml = useMemo(() => {
    return generateGitHubActionsWorkflowYaml(fullConfig, findings);
  }, [fullConfig, findings]);

  // Grouped findings by stage
  const findingsGroupedByStage = useMemo(() => {
    const result: Record<PipelineStageId, ScanFinding[]> = {
      'pre-commit': [],
      'build': [],
      'deploy': []
    };
    findings.forEach(f => {
      const stg = findingStageMapping[f.id] || autoCategorizeFindingToStage(f);
      result[stg].push(f);
    });
    return result;
  }, [findings, findingStageMapping]);

  // Filtered findings for the mapping drawer
  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      const stg = findingStageMapping[f.id] || autoCategorizeFindingToStage(f);
      if (selectedStageForFindings !== 'ALL' && stg !== selectedStageForFindings) return false;
      if (findingSeverityFilter !== 'ALL' && f.severity !== findingSeverityFilter) return false;
      if (findingSearch.trim()) {
        const q = findingSearch.toLowerCase();
        return (
          f.ruleName.toLowerCase().includes(q) ||
          f.file.toLowerCase().includes(q) ||
          f.category.toLowerCase().includes(q) ||
          f.matchedSecret.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [findings, findingStageMapping, selectedStageForFindings, findingSeverityFilter, findingSearch]);

  // Drag & drop handlers
  const handleDragStart = (e: React.DragEvent, type: 'FINDING' | 'STEP', id: string, sourceStage?: PipelineStageId) => {
    setDraggedItem({ type, id, sourceStage });
    e.dataTransfer.setData('application/json', JSON.stringify({ type, id, sourceStage }));
    e.dataTransfer.effectAllowed = 'move';
  };

  const handleDragOverStage = (e: React.DragEvent, stageId: PipelineStageId) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    if (dragOverStage !== stageId) {
      setDragOverStage(stageId);
    }
  };

  const handleDragLeaveStage = (e: React.DragEvent, stageId: PipelineStageId) => {
    if (dragOverStage === stageId) {
      setDragOverStage(null);
    }
  };

  const handleDropOnStage = (e: React.DragEvent, targetStage: PipelineStageId) => {
    e.preventDefault();
    setDragOverStage(null);

    let data = draggedItem;
    if (!data) {
      try {
        const raw = e.dataTransfer.getData('application/json');
        if (raw) data = JSON.parse(raw);
      } catch {
        // Fallback
      }
    }

    if (!data) return;

    if (data.type === 'FINDING') {
      // Move finding to target stage
      setFindingStageMapping(prev => ({
        ...prev,
        [data!.id]: targetStage
      }));
    } else if (data.type === 'STEP') {
      // Move step to target stage
      setSteps(prev =>
        prev.map(step => (step.id === data!.id ? { ...step, stage: targetStage } : step))
      );
    }

    setDraggedItem(null);
  };

  // Reorder steps within a stage or across stages
  const handleStepReorder = (stepId: string, direction: 'UP' | 'DOWN') => {
    setSteps(prev => {
      const index = prev.findIndex(s => s.id === stepId);
      if (index === -1) return prev;
      const targetIndex = direction === 'UP' ? index - 1 : index + 1;
      if (targetIndex < 0 || targetIndex >= prev.length) return prev;
      const copy = [...prev];
      const temp = copy[index];
      copy[index] = copy[targetIndex];
      copy[targetIndex] = temp;
      return copy;
    });
  };

  const handleToggleStep = (stepId: string) => {
    setSteps(prev =>
      prev.map(s => (s.id === stepId ? { ...s, enabled: !s.enabled } : s))
    );
  };

  const handleDeleteStep = (stepId: string) => {
    setSteps(prev => prev.filter(s => s.id !== stepId));
  };

  const handleUpdateStepSeverity = (stepId: string, sev: SeverityLevel | 'NONE') => {
    setSteps(prev =>
      prev.map(s => (s.id === stepId ? { ...s, failOnSeverity: sev } : s))
    );
  };

  // Stage configuration helpers
  const handleUpdateStageThreshold = (stageId: PipelineStageId, threshold: SeverityLevel) => {
    setStages(prev => ({
      ...prev,
      [stageId]: { ...prev[stageId], failThreshold: threshold }
    }));
  };

  const handleToggleStageBlock = (stageId: PipelineStageId) => {
    setStages(prev => ({
      ...prev,
      [stageId]: { ...prev[stageId], blockPipelineOnBreach: !prev[stageId].blockPipelineOnBreach }
    }));
  };

  // Apply Preset
  const handleApplyPreset = (presetId: string) => {
    const preset = PIPELINE_PRESETS.find(p => p.id === presetId);
    if (!preset) return;

    setStages(prev => ({
      'pre-commit': { ...prev['pre-commit'], ...preset.stages['pre-commit'] },
      'build': { ...prev['build'], ...preset.stages['build'] },
      'deploy': { ...prev['deploy'], ...preset.stages['deploy'] },
    }));
    setSteps(preset.steps);

    if (onLogAudit) {
      onLogAudit({
        id: `audit-preset-${Date.now()}`,
        timestamp: new Date().toISOString(),
        type: 'RULE_APPLIED',
        message: `Pipeline Flow Architect: Aplicado preset de automação "${preset.name}".`,
        severity: 'INFO',
        details: { presetId: preset.id, stepsCount: preset.steps.length }
      });
    }
  };

  // Auto-Categorize All Findings
  const handleAutoCategorizeAll = () => {
    const fresh = buildInitialFindingStageMapping(findings);
    setFindingStageMapping(fresh);
  };

  // Copy YAML
  const handleCopyYaml = () => {
    navigator.clipboard.writeText(generatedYaml);
    setCopiedYaml(true);
    setTimeout(() => setCopiedYaml(false), 2000);
  };

  // Download YAML
  const handleDownloadYaml = () => {
    const blob = new Blob([generatedYaml], { type: 'text/yaml;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'secscan-pipeline.yml';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Save to Workspace
  const handleSaveToWorkspace = () => {
    if (!onUpdateFiles) return;
    const targetPath = '.github/workflows/secscan-pipeline.yml';
    const existingIndex = files.findIndex(f => f.path === targetPath || f.name === 'secscan-pipeline.yml');

    let updatedList: ScannedFile[];
    if (existingIndex >= 0) {
      updatedList = files.map((f, idx) =>
        idx === existingIndex ? { ...f, content: generatedYaml, size: generatedYaml.length } : f
      );
    } else {
      const newFile: ScannedFile = {
        name: 'secscan-pipeline.yml',
        path: targetPath,
        content: generatedYaml,
        size: generatedYaml.length,
        extension: 'yml'
      };
      updatedList = [newFile, ...files];
    }

    onUpdateFiles(updatedList);
    setSavedToWorkspace(true);
    setTimeout(() => setSavedToWorkspace(false), 2500);

    if (onLogAudit) {
      onLogAudit({
        id: `audit-pipeline-save-${Date.now()}`,
        timestamp: new Date().toISOString(),
        type: 'FIX_APPLIED',
        message: `Workflow GitHub Actions salvo em ${targetPath} com sucesso.`,
        severity: 'INFO',
        details: { path: targetPath, size: generatedYaml.length }
      });
    }
  };

  // Run Simulation
  const handleStartSimulation = () => {
    setIsSimulating(true);
    setSimulationReport(null);
    setActiveTab('simulation');
    setSimulatedStageProgress('pre-commit');

    setTimeout(() => {
      setSimulatedStageProgress('build');
      setTimeout(() => {
        setSimulatedStageProgress('deploy');
        setTimeout(() => {
          const report = simulatePipelineRun(fullConfig, findings);
          setSimulationReport(report);
          setIsSimulating(false);
          setSimulatedStageProgress(null);

          if (onLogAudit) {
            onLogAudit({
              id: `audit-pipeline-sim-${Date.now()}`,
              timestamp: new Date().toISOString(),
              type: 'ALERT_TRIGGERED',
              message: `Simulação de Pipeline concluída: Status ${report.overallStatus} (${report.summary}).`,
              severity: report.overallStatus === 'PASSED' ? 'INFO' : 'HIGH',
              details: {
                overallStatus: report.overallStatus,
                duration: report.totalDurationSeconds
              }
            });
          }
        }, 1200);
      }, 1400);
    }, 1200);
  };

  // Severity color helpers
  const getSeverityBadge = (sev: SeverityLevel) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'LOW':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
      default:
        return 'bg-zinc-800 text-zinc-400 border-zinc-700';
    }
  };

  const getStageHeaderColor = (stageId: PipelineStageId) => {
    switch (stageId) {
      case 'pre-commit':
        return {
          border: 'border-emerald-500/30',
          bg: 'bg-emerald-500/5',
          text: 'text-emerald-400',
          chip: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
        };
      case 'build':
        return {
          border: 'border-cyan-500/30',
          bg: 'bg-cyan-500/5',
          text: 'text-cyan-400',
          chip: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
        };
      case 'deploy':
        return {
          border: 'border-purple-500/30',
          bg: 'bg-purple-500/5',
          text: 'text-purple-400',
          chip: 'bg-purple-500/15 text-purple-300 border-purple-500/30'
        };
    }
  };

  // Add custom step
  const handleAddNewStep = (newStep: PipelineActionStep) => {
    setSteps(prev => [...prev, newStep]);
    setShowAddStepModal(false);
  };

  return (
    <div className="space-y-6 pb-16 font-sans">
      {/* Top Banner & Control Bar */}
      <div className="bg-[#0A0A0A] p-6 sm:p-8 border border-[#222]">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="text-[10px] font-black tracking-[0.25em] text-[#00FF41] uppercase">
                // DEVSECOPS SHIFT-LEFT PIPELINE FLOW ARCHITECT
              </span>
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-[#141414] text-white border border-[#333]">
                DRAG & DROP CONFIGURATOR
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                {findings.length} ACHADOS MAPEÁVEIS
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white uppercase mt-1 flex items-center gap-3">
              <Workflow className="w-7 h-7 text-[#00FF41]" />
              <span>Pipeline Flow Architect</span>
            </h1>
            <p className="text-xs font-mono text-[#888] mt-1.5 max-w-3xl leading-relaxed">
              Mapeie os achados de segurança locais diretamente para os estágios da esteira (<strong className="text-white">Pre-commit</strong>, <strong className="text-white">Build</strong> e <strong className="text-white">Deploy</strong>), configure passos de verificação e gere workflows declarativos do <strong className="text-white">GitHub Actions</strong> com suporte total a drag-and-drop.
            </p>
          </div>

          {/* Quick Actions Header */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              id="btn-simulate-pipeline"
              type="button"
              onClick={handleStartSimulation}
              disabled={isSimulating}
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-[#00FF41] hover:bg-[#00dd38] text-black font-mono font-black text-xs uppercase tracking-wider transition-all cursor-pointer shadow-lg shadow-[#00FF41]/10 active:scale-95 disabled:opacity-50"
            >
              {isSimulating ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-black" />
                  <span>Simulando Esteira...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-black text-black" />
                  <span>Simular Execução (Test Gate)</span>
                </>
              )}
            </button>

            <button
              id="btn-save-workspace-pipeline"
              type="button"
              onClick={handleSaveToWorkspace}
              className="inline-flex items-center gap-2 px-3.5 py-2.5 bg-[#141414] hover:bg-[#202020] text-white font-mono text-xs uppercase tracking-wider border border-[#333] transition-colors cursor-pointer"
              title="Salvar .github/workflows/secscan-pipeline.yml no workspace local"
            >
              {savedToWorkspace ? (
                <>
                  <Check className="w-4 h-4 text-[#00FF41]" />
                  <span className="text-[#00FF41]">Salvo no Workspace!</span>
                </>
              ) : (
                <>
                  <Save className="w-4 h-4 text-zinc-400" />
                  <span>Salvar no Workspace</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={() => setShowSettingsDrawer(true)}
              className="inline-flex items-center gap-2 px-3 py-2.5 bg-[#141414] hover:bg-[#202020] text-zinc-300 font-mono text-xs uppercase border border-[#333] transition-colors cursor-pointer"
              title="Configurações do Workflow (Runners, Branches, Triggers)"
            >
              <Settings className="w-4 h-4" />
              <span>Configurações</span>
            </button>
          </div>
        </div>

        {/* Presets & View Tabs Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mt-6 pt-5 border-t border-[#1C1C1C]">
          {/* Preset Selector */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] font-mono text-zinc-400 uppercase flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-amber-400" />
              Presets:
            </span>
            {PIPELINE_PRESETS.map(preset => (
              <button
                key={preset.id}
                type="button"
                onClick={() => handleApplyPreset(preset.id)}
                className="px-2.5 py-1 text-[11px] font-mono bg-[#141414] hover:bg-[#1E1E1E] text-zinc-200 border border-[#333] hover:border-[#555] transition-all cursor-pointer rounded-none flex items-center gap-1.5"
                title={preset.description}
              >
                <span>{preset.name}</span>
                <span className="text-[9px] px-1 py-0.2 bg-[#000] text-emerald-400 border border-emerald-500/20">
                  {preset.badge}
                </span>
              </button>
            ))}
          </div>

          {/* View Mode Toggle Tabs */}
          <div className="flex items-center bg-[#121212] p-1 border border-[#262626]">
            <button
              type="button"
              onClick={() => setActiveTab('visual')}
              className={`px-3.5 py-1.5 text-xs font-mono font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer ${
                activeTab === 'visual'
                  ? 'bg-[#00FF41] text-black font-black'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <Workflow className="w-3.5 h-3.5" />
              <span>Diagrama Visual (Drag & Drop)</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('yaml')}
              className={`px-3.5 py-1.5 text-xs font-mono font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer ${
                activeTab === 'yaml'
                  ? 'bg-[#00FF41] text-black font-black'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>GitHub Actions YAML</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('simulation')}
              className={`px-3.5 py-1.5 text-xs font-mono font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer ${
                activeTab === 'simulation'
                  ? 'bg-[#00FF41] text-black font-black'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <Play className="w-3.5 h-3.5" />
              <span>Simulação ({simulationReport ? simulationReport.overallStatus : 'Aguardando'})</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Area Based on Active Tab */}
      {activeTab === 'visual' && (
        <div className="space-y-6">
          {/* Pipeline Connector Header Visualizer */}
          <div className="bg-[#0D0D0D] border border-[#222] p-4 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-xs font-mono text-zinc-300">
              <Activity className="w-4 h-4 text-[#00FF41]" />
              <span>Fluxo Contínuo de Estágios:</span>
            </div>

            <div className="flex items-center gap-3 w-full md:w-auto justify-center flex-wrap">
              {/* Pre-commit stage chip */}
              <div className="flex items-center gap-2 px-3 py-1.5 bg-[#141414] border border-emerald-500/30 text-emerald-400 font-mono text-xs">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="font-bold">1. Pre-commit</span>
                <span className="text-[10px] px-1.5 py-0.2 bg-emerald-500/20 text-emerald-300">
                  {findingsGroupedByStage['pre-commit'].length} achados
                </span>
              </div>

              <ArrowRight className="w-4 h-4 text-zinc-600 hidden sm:block" />

              {/* Build stage chip */}
              <div className="flex items-center gap-2 px-3 py-1.5 bg-[#141414] border border-cyan-500/30 text-cyan-400 font-mono text-xs">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                <span className="font-bold">2. Build & SAST</span>
                <span className="text-[10px] px-1.5 py-0.2 bg-cyan-500/20 text-cyan-300">
                  {findingsGroupedByStage['build'].length} achados
                </span>
              </div>

              <ArrowRight className="w-4 h-4 text-zinc-600 hidden sm:block" />

              {/* Deploy stage chip */}
              <div className="flex items-center gap-2 px-3 py-1.5 bg-[#141414] border border-purple-500/30 text-purple-400 font-mono text-xs">
                <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse" />
                <span className="font-bold">3. Deploy Gate</span>
                <span className="text-[10px] px-1.5 py-0.2 bg-purple-500/20 text-purple-300">
                  {findingsGroupedByStage['deploy'].length} achados
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleAutoCategorizeAll}
                className="px-2.5 py-1 text-[11px] font-mono bg-[#181818] hover:bg-[#252525] text-zinc-300 border border-[#333] transition-colors flex items-center gap-1.5 cursor-pointer"
                title="Mapear achados automaticamente conforme padrões FIPS e OWASP"
              >
                <RotateCcw className="w-3 h-3 text-zinc-400" />
                <span>Auto-Mapear Achados</span>
              </button>
            </div>
          </div>

          {/* 3-Column Drag & Drop Pipeline Board */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {(['pre-commit', 'build', 'deploy'] as PipelineStageId[]).map((stageId) => {
              const stageConf = stages[stageId];
              const stageSteps = steps.filter(s => s.stage === stageId);
              const stageFindings = findingsGroupedByStage[stageId];
              const colors = getStageHeaderColor(stageId);
              const isOver = dragOverStage === stageId;

              return (
                <div
                  key={stageId}
                  onDragOver={(e) => handleDragOverStage(e, stageId)}
                  onDragLeave={(e) => handleDragLeaveStage(e, stageId)}
                  onDrop={(e) => handleDropOnStage(e, stageId)}
                  className={`bg-[#0A0A0A] border transition-all duration-200 flex flex-col ${
                    isOver
                      ? 'border-[#00FF41] ring-2 ring-[#00FF41]/20 bg-[#0F1810]'
                      : colors.border
                  }`}
                >
                  {/* Stage Header */}
                  <div className={`p-4 border-b ${colors.border} ${colors.bg}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-mono font-bold px-2 py-0.5 border ${colors.chip}`}>
                          STAGE: {stageId.toUpperCase()}
                        </span>
                      </div>
                      <span className="text-[11px] font-mono text-zinc-400">
                        {stageSteps.length} ações | {stageFindings.length} achados
                      </span>
                    </div>

                    <h2 className="text-base font-black text-white uppercase tracking-tight mt-2 flex items-center justify-between">
                      <span>{stageConf.title}</span>
                    </h2>
                    <p className="text-[11px] font-mono text-zinc-400 mt-0.5">
                      {stageConf.subtitle}
                    </p>

                    {/* Stage Quality Gate Policies */}
                    <div className="mt-3 pt-3 border-t border-[#222] grid grid-cols-2 gap-2 text-[10px] font-mono">
                      <div>
                        <span className="text-zinc-500 block mb-1">FAIL ON SEVERITY:</span>
                        <select
                          value={stageConf.failThreshold}
                          onChange={(e) => handleUpdateStageThreshold(stageId, e.target.value as SeverityLevel)}
                          className="w-full bg-[#121212] border border-[#333] text-white px-2 py-1 focus:border-[#00FF41] focus:outline-none"
                        >
                          <option value="CRITICAL">CRITICAL ONLY</option>
                          <option value="HIGH">HIGH & CRITICAL</option>
                          <option value="MEDIUM">MEDIUM + ACIMA</option>
                          <option value="LOW">QUALQUER ACHADO</option>
                        </select>
                      </div>

                      <div>
                        <span className="text-zinc-500 block mb-1">POLÍTICA DE BLOQUEIO:</span>
                        <label className="flex items-center gap-1.5 text-zinc-300 cursor-pointer pt-1">
                          <input
                            type="checkbox"
                            checked={stageConf.blockPipelineOnBreach}
                            onChange={() => handleToggleStageBlock(stageId)}
                            className="rounded bg-[#111] border-[#444] text-[#00FF41] focus:ring-0"
                          />
                          <span className="text-[10.5px]">Travar Pipeline</span>
                        </label>
                      </div>
                    </div>
                  </div>

                  {/* Drag Target Notice */}
                  {isOver && (
                    <div className="p-3 bg-[#00FF41]/10 border-b border-[#00FF41]/30 text-center text-xs font-mono text-[#00FF41] animate-pulse">
                      Solte o achado ou ação aqui para vincular ao {stageConf.title}
                    </div>
                  )}

                  {/* Stage Body */}
                  <div className="p-4 space-y-4 flex-1 flex flex-col">
                    {/* Section: Mapped Local Findings */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-zinc-400 uppercase font-bold flex items-center gap-1.5">
                          <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                          Achados Mapeados ({stageFindings.length})
                        </span>
                        <span className="text-[10px] text-zinc-500">
                          Arraste para mover
                        </span>
                      </div>

                      {stageFindings.length === 0 ? (
                        <div className="p-3 bg-[#050505] border border-dashed border-[#222] text-center text-[11px] font-mono text-zinc-500">
                          Nenhum achado mapeado para este estágio.
                        </div>
                      ) : (
                        <div className="max-h-48 overflow-y-auto space-y-1.5 pr-1">
                          {stageFindings.slice(0, 8).map(finding => (
                            <div
                              key={finding.id}
                              draggable
                              onDragStart={(e) => handleDragStart(e, 'FINDING', finding.id, stageId)}
                              className="p-2 bg-[#050505] border border-[#1F1F1F] hover:border-[#444] transition-all text-xs font-mono flex items-center justify-between gap-2 cursor-grab active:cursor-grabbing group"
                            >
                              <div className="flex items-center gap-2 min-w-0">
                                <GripVertical className="w-3.5 h-3.5 text-zinc-600 group-hover:text-zinc-300 shrink-0" />
                                <span className={`text-[9px] font-bold px-1.5 py-0.2 border shrink-0 ${getSeverityBadge(finding.severity)}`}>
                                  {finding.severity}
                                </span>
                                <span className="text-zinc-200 truncate font-semibold">
                                  {finding.ruleName}
                                </span>
                              </div>
                              <span className="text-[10px] text-zinc-500 shrink-0 font-mono">
                                {finding.file.split('/').pop()}:{finding.line}
                              </span>
                            </div>
                          ))}
                          {stageFindings.length > 8 && (
                            <div className="text-[10px] font-mono text-center text-zinc-500 py-1">
                              + {stageFindings.length - 8} achados mapeados adicionais
                            </div>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Section: Action Steps in This Stage */}
                    <div className="space-y-2 pt-2 border-t border-[#1C1C1C] flex-1 flex flex-col">
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-zinc-400 uppercase font-bold flex items-center gap-1.5">
                          <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" />
                          Ações do Workflow ({stageSteps.length})
                        </span>
                        <button
                          type="button"
                          onClick={() => {
                            setTargetStageForNewStep(stageId);
                            setShowAddStepModal(true);
                          }}
                          className="text-[10px] text-[#00FF41] hover:underline flex items-center gap-1 cursor-pointer"
                        >
                          <Plus className="w-3 h-3" />
                          <span>Adicionar Ação</span>
                        </button>
                      </div>

                      <div className="space-y-2 flex-1">
                        {stageSteps.map((step, sIndex) => (
                          <div
                            key={step.id}
                            draggable
                            onDragStart={(e) => handleDragStart(e, 'STEP', step.id, stageId)}
                            className={`p-2.5 bg-[#080808] border transition-all text-xs font-mono space-y-2 cursor-grab active:cursor-grabbing ${
                              step.enabled
                                ? 'border-[#222] hover:border-[#444]'
                                : 'border-[#1C1C1C] opacity-50 bg-[#040404]'
                            }`}
                          >
                            <div className="flex items-start justify-between gap-2">
                              <div className="flex items-center gap-2 min-w-0">
                                <GripVertical className="w-3.5 h-3.5 text-zinc-600 hover:text-zinc-300 shrink-0" />
                                <input
                                  type="checkbox"
                                  checked={step.enabled}
                                  onChange={() => handleToggleStep(step.id)}
                                  className="rounded bg-[#111] border-[#444] text-[#00FF41] focus:ring-0 shrink-0"
                                  title={step.enabled ? 'Desativar este passo' : 'Ativar este passo'}
                                />
                                <span className="text-white font-bold truncate text-[11.5px]">
                                  {step.name}
                                </span>
                              </div>

                              <div className="flex items-center gap-1 shrink-0">
                                <button
                                  type="button"
                                  onClick={() => handleStepReorder(step.id, 'UP')}
                                  disabled={sIndex === 0}
                                  className="p-0.5 text-zinc-500 hover:text-white disabled:opacity-20 cursor-pointer"
                                  title="Subir na ordem"
                                >
                                  <ChevronUp className="w-3.5 h-3.5" />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleStepReorder(step.id, 'DOWN')}
                                  disabled={sIndex === stageSteps.length - 1}
                                  className="p-0.5 text-zinc-500 hover:text-white disabled:opacity-20 cursor-pointer"
                                  title="Descer na ordem"
                                >
                                  <ChevronDown className="w-3.5 h-3.5" />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleDeleteStep(step.id)}
                                  className="p-0.5 text-zinc-600 hover:text-red-400 cursor-pointer ml-1"
                                  title="Remover passo"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              </div>
                            </div>

                            <p className="text-[10px] text-zinc-400 line-clamp-2 leading-relaxed">
                              {step.description}
                            </p>

                            <div className="flex items-center justify-between pt-1 border-t border-[#181818] text-[10px] text-zinc-500">
                              <span className="font-mono bg-[#000] px-1 py-0.5 border border-[#1F1F1F] text-zinc-300">
                                {step.uses ? `uses: ${step.uses.split('@')[0]}` : 'run: CLI'}
                              </span>

                              <div className="flex items-center gap-1.5">
                                <span className="text-zinc-500">Gate:</span>
                                <select
                                  value={step.failOnSeverity}
                                  onChange={(e) => handleUpdateStepSeverity(step.id, e.target.value as SeverityLevel | 'NONE')}
                                  className="bg-[#000] text-zinc-300 border border-[#222] px-1.5 py-0.5 text-[9.5px] focus:outline-none"
                                >
                                  <option value="CRITICAL">CRITICAL</option>
                                  <option value="HIGH">HIGH</option>
                                  <option value="MEDIUM">MEDIUM</option>
                                  <option value="LOW">LOW</option>
                                  <option value="NONE">NO FAIL</option>
                                </select>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Bottom Drawer: Local Findings Mapping Dock */}
          <div className="bg-[#0A0A0A] border border-[#222] p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-amber-400" />
                  <h2 className="text-xs font-black uppercase tracking-wider text-white">
                    Docas de Achados Locais: Mapeamento & Atribuição de Estágio
                  </h2>
                </div>
                <p className="text-[11px] font-mono text-zinc-400 mt-0.5">
                  Arraste os achados acima para o estágio desejado ou use os seletores rápidos abaixo para deslocar achados para a esquerda (Shift-Left).
                </p>
              </div>

              {/* Filters for findings */}
              <div className="flex items-center gap-2.5 flex-wrap">
                <div className="relative">
                  <input
                    type="text"
                    placeholder="Filtrar por regra, arquivo..."
                    value={findingSearch}
                    onChange={(e) => setFindingSearch(e.target.value)}
                    className="bg-[#050505] border border-[#333] text-white text-xs px-2.5 py-1.5 font-mono focus:border-[#00FF41] focus:outline-none w-48 sm:w-56"
                  />
                </div>

                <select
                  value={selectedStageForFindings}
                  onChange={(e) => setSelectedStageForFindings(e.target.value as PipelineStageId | 'ALL')}
                  className="bg-[#050505] border border-[#333] text-zinc-300 text-xs px-2.5 py-1.5 font-mono focus:border-[#00FF41] focus:outline-none"
                >
                  <option value="ALL">Todos os Estágios</option>
                  <option value="pre-commit">Apenas Pre-commit</option>
                  <option value="build">Apenas Build</option>
                  <option value="deploy">Apenas Deploy</option>
                </select>

                <select
                  value={findingSeverityFilter}
                  onChange={(e) => setFindingSeverityFilter(e.target.value)}
                  className="bg-[#050505] border border-[#333] text-zinc-300 text-xs px-2.5 py-1.5 font-mono focus:border-[#00FF41] focus:outline-none"
                >
                  <option value="ALL">Todas as Severidades</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>
            </div>

            {/* Findings Table / Grid */}
            <div className="max-h-72 overflow-y-auto border border-[#1C1C1C]">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#050505] text-zinc-400 uppercase text-[10px] sticky top-0 border-b border-[#222]">
                  <tr>
                    <th className="p-2.5 font-bold">Severidade</th>
                    <th className="p-2.5 font-bold">Vulnerabilidade / Regra</th>
                    <th className="p-2.5 font-bold">Arquivo e Linha</th>
                    <th className="p-2.5 font-bold">Estágio Atribuído</th>
                    <th className="p-2.5 font-bold text-right">Ação Rápida</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#181818] bg-[#0A0A0A]">
                  {filteredFindings.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="p-6 text-center text-zinc-500 font-mono text-xs">
                        Nenhum achado encontrado com os filtros aplicados.
                      </td>
                    </tr>
                  ) : (
                    filteredFindings.map(finding => {
                      const currentStage = findingStageMapping[finding.id] || autoCategorizeFindingToStage(finding);

                      return (
                        <tr
                          key={finding.id}
                          draggable
                          onDragStart={(e) => handleDragStart(e, 'FINDING', finding.id, currentStage)}
                          className="hover:bg-[#121212] transition-colors cursor-grab active:cursor-grabbing group"
                        >
                          <td className="p-2.5 whitespace-nowrap">
                            <span className={`text-[9.5px] font-bold px-1.5 py-0.5 border ${getSeverityBadge(finding.severity)}`}>
                              {finding.severity}
                            </span>
                          </td>
                          <td className="p-2.5 text-zinc-200 font-semibold max-w-xs truncate">
                            <div className="flex items-center gap-1.5">
                              <GripVertical className="w-3.5 h-3.5 text-zinc-600 group-hover:text-zinc-300 shrink-0" />
                              <span className="truncate">{finding.ruleName}</span>
                            </div>
                          </td>
                          <td className="p-2.5 text-zinc-400 font-mono max-w-xs truncate">
                            <button
                              type="button"
                              onClick={() => onNavigateToFile?.(finding.file, finding.line)}
                              className="hover:text-[#00FF41] hover:underline text-left truncate cursor-pointer"
                            >
                              {finding.file}:{finding.line}
                            </button>
                          </td>
                          <td className="p-2.5 whitespace-nowrap">
                            <select
                              value={currentStage}
                              onChange={(e) => {
                                const newStage = e.target.value as PipelineStageId;
                                setFindingStageMapping(prev => ({
                                  ...prev,
                                  [finding.id]: newStage
                                }));
                              }}
                              className="bg-[#050505] text-white border border-[#333] px-2 py-1 text-[11px] font-mono focus:border-[#00FF41] focus:outline-none"
                            >
                              <option value="pre-commit">🛡️ Pre-commit (Shift-Left)</option>
                              <option value="build">⚡ Build & SAST</option>
                              <option value="deploy">🚀 Deploy Gate</option>
                            </select>
                          </td>
                          <td className="p-2.5 text-right whitespace-nowrap">
                            <div className="flex items-center justify-end gap-1">
                              <button
                                type="button"
                                onClick={() => {
                                  setFindingStageMapping(prev => ({ ...prev, [finding.id]: 'pre-commit' }));
                                }}
                                className={`px-1.5 py-0.5 text-[9.5px] border cursor-pointer ${
                                  currentStage === 'pre-commit'
                                    ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                                    : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
                                }`}
                                title="Enviar para Pre-commit"
                              >
                                Pre-commit
                              </button>
                              <button
                                type="button"
                                onClick={() => {
                                  setFindingStageMapping(prev => ({ ...prev, [finding.id]: 'build' }));
                                }}
                                className={`px-1.5 py-0.5 text-[9.5px] border cursor-pointer ${
                                  currentStage === 'build'
                                    ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40'
                                    : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
                                }`}
                                title="Enviar para Build"
                              >
                                Build
                              </button>
                              <button
                                type="button"
                                onClick={() => {
                                  setFindingStageMapping(prev => ({ ...prev, [finding.id]: 'deploy' }));
                                }}
                                className={`px-1.5 py-0.5 text-[9.5px] border cursor-pointer ${
                                  currentStage === 'deploy'
                                    ? 'bg-purple-500/20 text-purple-400 border-purple-500/40'
                                    : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
                                }`}
                                title="Enviar para Deploy"
                              >
                                Deploy
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* GitHub Actions YAML Code Viewer Tab */}
      {activeTab === 'yaml' && (
        <div className="bg-[#0A0A0A] border border-[#222] overflow-hidden space-y-0">
          <div className="p-4 bg-[#080808] border-b border-[#222] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-[#00FF41]" />
              <span className="text-xs font-mono font-bold text-white uppercase">
                .github/workflows/secscan-pipeline.yml
              </span>
              <span className="text-[10px] font-mono px-2 py-0.2 bg-[#141414] text-zinc-400 border border-[#2A2A2A]">
                SINTAXE REATIVA GITHUB ACTIONS V2
              </span>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <button
                type="button"
                onClick={handleCopyYaml}
                className="px-3 py-1.5 bg-[#141414] hover:bg-[#202020] text-white text-xs font-mono uppercase tracking-wider border border-[#333] transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                {copiedYaml ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-[#00FF41]" />
                    <span className="text-[#00FF41]">Copiado!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-zinc-400" />
                    <span>Copiar YAML</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={handleDownloadYaml}
                className="px-3 py-1.5 bg-[#141414] hover:bg-[#202020] text-white text-xs font-mono uppercase tracking-wider border border-[#333] transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5 text-zinc-400" />
                <span>Baixar .yml</span>
              </button>

              <button
                type="button"
                onClick={handleSaveToWorkspace}
                className="px-3 py-1.5 bg-[#00FF41] hover:bg-[#00dd38] text-black font-black text-xs font-mono uppercase tracking-wider transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <Save className="w-3.5 h-3.5 text-black" />
                <span>{savedToWorkspace ? 'Salvo no Workspace!' : 'Salvar no Workspace'}</span>
              </button>
            </div>
          </div>

          <div className="p-4 bg-[#050505] text-xs font-mono text-[#00FF41] overflow-x-auto leading-relaxed max-h-[600px] select-all">
            <pre className="font-mono whitespace-pre">{generatedYaml}</pre>
          </div>

          <div className="p-3 bg-[#080808] border-t border-[#222] flex items-center justify-between text-[11px] font-mono text-zinc-400">
            <span>
              💡 Para ativar no repositório, faça commit deste arquivo na pasta <code className="text-white">.github/workflows/</code> do seu projeto.
            </span>
            <span className="text-[#00FF41]">Runner: {runner} | Node: {nodeVersion}</span>
          </div>
        </div>
      )}

      {/* Pipeline Simulation Tab */}
      {activeTab === 'simulation' && (
        <div className="space-y-6">
          {/* Simulation Status Card */}
          <div className="bg-[#0A0A0A] border border-[#222] p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <Play className="w-4 h-4 text-[#00FF41]" />
                  <h2 className="text-xs font-black uppercase tracking-wider text-white">
                    Simulador Interativo de Pipeline CI/CD (Quality Gate Test)
                  </h2>
                </div>
                <p className="text-xs font-mono text-zinc-400 mt-1">
                  Avalia se o commit atual seria autorizado ou bloqueado em cada um dos 3 estágios com base nos achados locais e nas regras de limite configuradas.
                </p>
              </div>

              <button
                type="button"
                onClick={handleStartSimulation}
                disabled={isSimulating}
                className="px-4 py-2 bg-[#00FF41] hover:bg-[#00dd38] text-black font-mono font-black text-xs uppercase tracking-wider transition-colors flex items-center gap-2 cursor-pointer disabled:opacity-50 shrink-0"
              >
                <RefreshCw className={`w-3.5 h-3.5 text-black ${isSimulating ? 'animate-spin' : ''}`} />
                <span>{isSimulating ? 'Executando Teste...' : 'Re-executar Simulação'}</span>
              </button>
            </div>

            {/* Stage Progress Visualizer */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {(['pre-commit', 'build', 'deploy'] as PipelineStageId[]).map((stageId) => {
                const stageConf = stages[stageId];
                const stageResult = simulationReport?.stageResults[stageId];
                const isRunningCurrent = isSimulating && simulatedStageProgress === stageId;

                let badge = { text: 'AGUARDANDO', color: 'bg-zinc-800 text-zinc-400 border-zinc-700' };
                if (isRunningCurrent) {
                  badge = { text: 'EXECUTANDO...', color: 'bg-amber-500/20 text-amber-300 border-amber-500/30 animate-pulse' };
                } else if (stageResult) {
                  if (stageResult.status === 'PASSED') {
                    badge = { text: 'APROVADO', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40' };
                  } else if (stageResult.status === 'FAILED') {
                    badge = { text: 'BLOQUEADO', color: 'bg-red-500/20 text-red-400 border-red-500/40' };
                  } else if (stageResult.status === 'SKIPPED') {
                    badge = { text: 'PULADO', color: 'bg-zinc-800 text-zinc-500 border-zinc-700' };
                  }
                }

                return (
                  <div
                    key={stageId}
                    className={`p-4 bg-[#050505] border transition-all ${
                      isRunningCurrent
                        ? 'border-amber-500/40 ring-1 ring-amber-500/20'
                        : stageResult?.status === 'PASSED'
                        ? 'border-emerald-500/30'
                        : stageResult?.status === 'FAILED'
                        ? 'border-red-500/40'
                        : 'border-[#1E1E1E]'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono uppercase text-zinc-400 font-bold">
                        ESTÁGIO {stageId.toUpperCase()}
                      </span>
                      <span className={`text-[9.5px] font-mono font-bold px-2 py-0.5 border ${badge.color}`}>
                        {badge.text}
                      </span>
                    </div>

                    <h3 className="text-sm font-bold text-white uppercase mt-2">
                      {stageConf.title}
                    </h3>

                    <div className="mt-3 pt-3 border-t border-[#1C1C1C] text-[11px] font-mono space-y-1 text-zinc-400">
                      <div className="flex justify-between">
                        <span>Limite:</span>
                        <span className="text-white font-bold">{stageConf.failThreshold}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Achados no estágio:</span>
                        <span className="text-white font-bold">{stageResult?.evaluatedFindingsCount ?? findingsGroupedByStage[stageId].length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Violações do Gate:</span>
                        <span className={stageResult?.breachingFindings.length ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                          {stageResult?.breachingFindings.length ?? 0}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Overall Summary Box */}
            {simulationReport && (
              <div
                className={`p-4 border font-mono text-xs flex flex-col sm:flex-row items-center justify-between gap-4 ${
                  simulationReport.overallStatus === 'PASSED'
                    ? 'bg-emerald-500/5 border-emerald-500/30 text-emerald-400'
                    : 'bg-red-500/5 border-red-500/30 text-red-400'
                }`}
              >
                <div className="flex items-center gap-3">
                  {simulationReport.overallStatus === 'PASSED' ? (
                    <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
                  ) : (
                    <XCircle className="w-6 h-6 text-red-400 shrink-0" />
                  )}
                  <div>
                    <div className="font-bold text-sm">
                      {simulationReport.overallStatus === 'PASSED'
                        ? 'STATUS FINAL: PIPELINE APROVADO PARA PRODUÇÃO'
                        : 'STATUS FINAL: PIPELINE BLOQUEADO POR VIOLAÇÃO DE POLÍTICA'}
                    </div>
                    <div className="text-[11px] opacity-90 mt-0.5">
                      {simulationReport.summary} (Tempo total simulado: {simulationReport.totalDurationSeconds}s)
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => setActiveTab('visual')}
                  className="px-3 py-1.5 bg-[#141414] hover:bg-[#202020] text-white border border-[#333] text-xs uppercase cursor-pointer"
                >
                  Ajustar Mapeamento
                </button>
              </div>
            )}

            {/* Simulated Terminal Log Stream */}
            <div className="bg-[#050505] border border-[#222] overflow-hidden">
              <div className="p-3 bg-[#080808] border-b border-[#222] flex items-center justify-between text-xs font-mono text-zinc-400">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-[#00FF41]" />
                  <span>Log de Execução Simulada (GitHub Actions Runner Console)</span>
                </div>
                <span className="text-[10px] text-zinc-500">Bash / Node 22 LTS</span>
              </div>

              <div className="p-4 font-mono text-xs max-h-72 overflow-y-auto space-y-1 bg-[#050505]">
                {simulationReport ? (
                  (['pre-commit', 'build', 'deploy'] as PipelineStageId[]).map(stageId => {
                    const stgRes = simulationReport.stageResults[stageId];
                    return (
                      <div key={stageId} className="space-y-1 mb-3">
                        <div className="text-zinc-400 font-bold border-b border-[#1A1A1A] pb-1">
                          === [STAGE {stageId.toUpperCase()}] {stgRes.stageTitle} ===
                        </div>
                        {stgRes.logs.map((lg, lIdx) => (
                          <div
                            key={lIdx}
                            className={`flex items-start gap-2 ${
                              lg.level === 'ERROR'
                                ? 'text-red-400'
                                : lg.level === 'SUCCESS'
                                ? 'text-[#00FF41]'
                                : lg.level === 'WARN'
                                ? 'text-amber-300'
                                : 'text-zinc-300'
                            }`}
                          >
                            <span className="text-zinc-600 select-none">[{lg.timestamp}]</span>
                            <span>{lg.message}</span>
                          </div>
                        ))}
                      </div>
                    );
                  })
                ) : (
                  <div className="text-zinc-500 py-4 text-center">
                    Clique em "Simular Execução (Test Gate)" para iniciar o teste da esteira.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Settings Drawer Modal */}
      {showSettingsDrawer && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0A0A0A] border border-[#333] w-full max-w-lg p-6 space-y-5 font-mono text-xs shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-[#222]">
              <div className="flex items-center gap-2">
                <Settings className="w-4 h-4 text-[#00FF41]" />
                <h3 className="text-sm font-black text-white uppercase">
                  Configurações do Workflow GitHub Actions
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowSettingsDrawer(false)}
                className="text-zinc-500 hover:text-white cursor-pointer text-base"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-zinc-400 mb-1 font-bold">NOME DO WORKFLOW:</label>
                <input
                  type="text"
                  value={workflowName}
                  onChange={(e) => setWorkflowName(e.target.value)}
                  className="w-full bg-[#050505] border border-[#333] text-white px-3 py-2 focus:border-[#00FF41] focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-zinc-400 mb-1 font-bold">RUNNER OS:</label>
                  <select
                    value={runner}
                    onChange={(e) => setRunner(e.target.value)}
                    className="w-full bg-[#050505] border border-[#333] text-white px-3 py-2 focus:border-[#00FF41] focus:outline-none"
                  >
                    <option value="ubuntu-latest">ubuntu-latest (Recomendado)</option>
                    <option value="ubuntu-24.04">ubuntu-24.04</option>
                    <option value="windows-latest">windows-latest</option>
                    <option value="macos-latest">macos-latest</option>
                  </select>
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1 font-bold">NODE.JS VERSION:</label>
                  <select
                    value={nodeVersion}
                    onChange={(e) => setNodeVersion(e.target.value)}
                    className="w-full bg-[#050505] border border-[#333] text-white px-3 py-2 focus:border-[#00FF41] focus:outline-none"
                  >
                    <option value="22">Node 22 LTS (Padrão SecScan)</option>
                    <option value="20">Node 20 LTS</option>
                    <option value="18">Node 18</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-bold">GATILHOS DE EXECUÇÃO (EVENTS):</label>
                <div className="grid grid-cols-2 gap-2 bg-[#050505] p-3 border border-[#222]">
                  <label className="flex items-center gap-2 cursor-pointer text-zinc-300">
                    <input
                      type="checkbox"
                      checked={triggerPush}
                      onChange={(e) => setTriggerPush(e.target.checked)}
                      className="rounded bg-[#111] border-[#444] text-[#00FF41] focus:ring-0"
                    />
                    <span>on: push</span>
                  </label>

                  <label className="flex items-center gap-2 cursor-pointer text-zinc-300">
                    <input
                      type="checkbox"
                      checked={triggerPullRequest}
                      onChange={(e) => setTriggerPullRequest(e.target.checked)}
                      className="rounded bg-[#111] border-[#444] text-[#00FF41] focus:ring-0"
                    />
                    <span>on: pull_request</span>
                  </label>

                  <label className="flex items-center gap-2 cursor-pointer text-zinc-300">
                    <input
                      type="checkbox"
                      checked={triggerSchedule}
                      onChange={(e) => setTriggerSchedule(e.target.checked)}
                      className="rounded bg-[#111] border-[#444] text-[#00FF41] focus:ring-0"
                    />
                    <span>on: schedule (Noturno)</span>
                  </label>

                  <label className="flex items-center gap-2 cursor-pointer text-zinc-300">
                    <input
                      type="checkbox"
                      checked={triggerWorkflowDispatch}
                      onChange={(e) => setTriggerWorkflowDispatch(e.target.checked)}
                      className="rounded bg-[#111] border-[#444] text-[#00FF41] focus:ring-0"
                    />
                    <span>workflow_dispatch (Manual)</span>
                  </label>
                </div>
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-bold">RECURSOS ADICIONAIS:</label>
                <div className="space-y-2 bg-[#050505] p-3 border border-[#222]">
                  <label className="flex items-center gap-2 cursor-pointer text-zinc-300">
                    <input
                      type="checkbox"
                      checked={uploadSarif}
                      onChange={(e) => setUploadSarif(e.target.checked)}
                      className="rounded bg-[#111] border-[#444] text-[#00FF41] focus:ring-0"
                    />
                    <span>Publicar SARIF na aba Security do GitHub (CodeQL Action)</span>
                  </label>

                  <label className="flex items-center gap-2 cursor-pointer text-zinc-300">
                    <input
                      type="checkbox"
                      checked={concurrencyGroup}
                      onChange={(e) => setConcurrencyGroup(e.target.checked)}
                      className="rounded bg-[#111] border-[#444] text-[#00FF41] focus:ring-0"
                    />
                    <span>Cancelar execuções anteriores em commits pendentes (concurrency)</span>
                  </label>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-[#222] flex justify-end">
              <button
                type="button"
                onClick={() => setShowSettingsDrawer(false)}
                className="px-4 py-2 bg-[#00FF41] hover:bg-[#00dd38] text-black font-black uppercase tracking-wider cursor-pointer"
              >
                Concluir Configurações
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Step Modal */}
      {showAddStepModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0A0A0A] border border-[#333] w-full max-w-lg p-6 space-y-4 font-mono text-xs shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-[#222]">
              <div className="flex items-center gap-2">
                <Plus className="w-4 h-4 text-[#00FF41]" />
                <h3 className="text-sm font-black text-white uppercase">
                  Adicionar Ação ao Estágio {targetStageForNewStep.toUpperCase()}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowAddStepModal(false)}
                className="text-zinc-500 hover:text-white cursor-pointer text-base"
              >
                ✕
              </button>
            </div>

            <div className="space-y-2">
              <p className="text-zinc-400 text-[11px]">
                Escolha uma verificação padrão de segurança recomendada:
              </p>

              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {[
                  {
                    name: 'Secret & Shannon Entropy Check',
                    type: 'secret' as const,
                    run: 'node bin/secscan.js . --fail-on high --entropy-threshold 3.8',
                    desc: 'Verifica chaves e tokens de alta entropia antes do commit.',
                    badge: 'Entropy'
                  },
                  {
                    name: 'OWASP Dependency-Check (SCA)',
                    type: 'sca' as const,
                    run: 'npm audit --audit-level=high',
                    desc: 'Verifica dependências vulneráveis com base na base NVD.',
                    badge: 'SCA'
                  },
                  {
                    name: 'Trivy Container Vulnerability Scan',
                    type: 'container' as const,
                    uses: 'aquasecurity/trivy-action@master',
                    desc: 'Analisa vulnerabilidades em imagens Docker e pacotes OS.',
                    badge: 'CIS Docker'
                  },
                  {
                    name: 'DAST API Security Fuzzer',
                    type: 'dast' as const,
                    run: 'node bin/secscan.js --fuzz-endpoints --target-url https://api.staging.internal',
                    desc: 'Executa testes dinâmicos de injeção em endpoints REST.',
                    badge: 'DAST'
                  },
                  {
                    name: 'Gitleaks Credential Audit',
                    type: 'secret' as const,
                    uses: 'gitleaks/gitleaks-action@v2',
                    desc: 'Varredura profunda de commits para prevenção de vazamento.',
                    badge: 'Gitleaks'
                  },
                  {
                    name: 'Security Headers & CSP Verifier',
                    type: 'dast' as const,
                    run: 'node bin/secscan.js --verify-headers --enforce-csp',
                    desc: 'Garante a presença de cabeçalhos de segurança (HSTS, CSP, X-Frame).',
                    badge: 'Headers'
                  }
                ].map((item, idx) => (
                  <div
                    key={idx}
                    onClick={() => {
                      handleAddNewStep({
                        id: `step-custom-${Date.now()}-${idx}`,
                        name: item.name,
                        stage: targetStageForNewStep,
                        type: item.type,
                        enabled: true,
                        uses: item.uses,
                        run: item.run,
                        failOnSeverity: 'HIGH',
                        description: item.desc,
                        badge: item.badge
                      });
                    }}
                    className="p-3 bg-[#050505] border border-[#222] hover:border-[#00FF41] hover:bg-[#080808] transition-all cursor-pointer flex items-center justify-between gap-3 group"
                  >
                    <div>
                      <div className="font-bold text-white group-hover:text-[#00FF41] flex items-center gap-2">
                        <span>{item.name}</span>
                        <span className="text-[9px] px-1 py-0.2 bg-[#121212] text-zinc-400 border border-[#333]">
                          {item.badge}
                        </span>
                      </div>
                      <p className="text-[10px] text-zinc-400 mt-0.5">{item.desc}</p>
                    </div>
                    <Plus className="w-4 h-4 text-zinc-500 group-hover:text-[#00FF41] shrink-0" />
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-3 border-t border-[#222] flex justify-end">
              <button
                type="button"
                onClick={() => setShowAddStepModal(false)}
                className="px-3 py-1.5 bg-[#141414] hover:bg-[#202020] text-zinc-300 border border-[#333] cursor-pointer"
              >
                Cancelar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
