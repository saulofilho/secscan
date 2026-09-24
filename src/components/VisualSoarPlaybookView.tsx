import React, { useState, useMemo } from 'react';
import {
  Workflow,
  Play,
  RotateCcw,
  Plus,
  Trash2,
  Copy,
  Check,
  Download,
  Upload,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Activity,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  FileCode2,
  Server,
  Cloud,
  Lock,
  Radio,
  SlidersHorizontal,
  Flame,
  KeyRound,
  ExternalLink,
  Zap,
  Clock
} from 'lucide-react';
import {
  SoarPlaybook,
  SoarPlaybookStep,
  SoarExecutionRun,
  DEFAULT_SOAR_PLAYBOOKS,
  executeSoarPlaybook,
  exportPlaybookToYaml,
  SoarActionType,
  SoarTriggerType
} from '../lib/soarEngine';
import { ScanReport } from '../types';

interface VisualSoarPlaybookViewProps {
  report?: ScanReport;
  onNavigateToTab?: (tab: string) => void;
  onLogAudit?: (event: any) => void;
}

const SERVICE_ICONS: Record<string, any> = {
  AWS_IAM: Cloud,
  NGFW_FIREWALL: Flame,
  JIRA: FileCode2,
  SLACK: Radio,
  EDR_AGENT: ShieldAlert,
  VAULT_KMS: KeyRound,
  GIT_PATCH: Settings,
  PAGERDUTY: Zap
};

const ACTION_DESCRIPTIONS: Record<string, string> = {
  REVOKE_CREDENTIAL: 'Revogação de credencial e tokens de acesso na nuvem (IAM)',
  BLOCK_IP_FIREWALL: 'Criação de regra dinâmica de bloqueio (DROP) no NGFW/WAF',
  CREATE_JIRA_TICKET: 'Abertura de chamado P0/P1 com anexo de evidência SAST',
  SEND_SLACK_ALERT: 'Envio de alerta instantâneo para o canal #sec-incidents',
  ISOLATE_CONTAINER: 'Isolamento de host ou pod comprometido da rede corporativa',
  ROTATE_KMS_KEY: 'Rotação emergencial de chave de encriptação no cofre Vault/KMS',
  EXECUTE_PATCH: 'Aplicação automatizada de patch com Git Unified Diff',
  NOTIFY_SOC_ON_CALL: 'Escalação emergencial para engenheiro de plantão no PagerDuty'
};

export const VisualSoarPlaybookView: React.FC<VisualSoarPlaybookViewProps> = ({
  report,
  onNavigateToTab,
  onLogAudit
}) => {
  const [playbooks, setPlaybooks] = useState<SoarPlaybook[]>(() => {
    // Extend default playbooks with 2 high-impact templates
    const extended = [...DEFAULT_SOAR_PLAYBOOKS];
    if (!extended.some(p => p.id === 'soar-pb-ransomware-containment')) {
      extended.push({
        id: 'soar-pb-ransomware-containment',
        name: 'Playbook: Contenção de Ransomware & Isolamento de Host',
        description: 'Detecta atividade suspeita de encriptação no EDR, isola o host da rede local imediatamente e abre canal de guerra no Slack.',
        category: 'Incident Response',
        enabled: true,
        trigger: {
          type: 'CRITICAL_RISK_THRESHOLD',
          threshold: 95
        },
        executionCount: 5,
        lastRunTimestamp: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
        averageExecutionTimeMs: 310,
        steps: [
          {
            id: 'step-rw-1',
            name: 'Gatilho: Alerta Crítico de Ransomware / C2 Beaconing',
            type: 'TRIGGER',
            triggerType: 'CRITICAL_RISK_THRESHOLD',
            targetService: 'EDR_AGENT',
            config: { indicator: 'RANSOMWARE_ENCRYPTION_SPIKE', confidence: 'HIGH' }
          },
          {
            id: 'step-rw-2',
            name: 'Condição: Validar se Host Contém Dados Sensíveis de Produção',
            type: 'CONDITION',
            conditionExpr: "host.tags.includes('PROD') && threat.score >= 90",
            targetService: 'AWS_IAM',
            config: { scope: 'ENTERPRISE_ASSETS' }
          },
          {
            id: 'step-rw-3',
            name: 'Ação: Isolar Host Comprometido no CrowdStrike / EDR',
            type: 'ACTION',
            actionType: 'ISOLATE_CONTAINER',
            targetService: 'EDR_AGENT',
            config: { isolationType: 'NETWORK_CONTAINMENT', allowSocRtr: true }
          },
          {
            id: 'step-rw-4',
            name: 'Ação: Bloquear Tráfego de Saída do Host no NGFW',
            type: 'ACTION',
            actionType: 'BLOCK_IP_FIREWALL',
            targetService: 'NGFW_FIREWALL',
            config: { action: 'DROP_ALL_EXTERNAL', durationHours: 24 }
          },
          {
            id: 'step-rw-5',
            name: 'Ação: Disparar War-Room de Emergência no PagerDuty',
            type: 'ACTION',
            actionType: 'NOTIFY_SOC_ON_CALL',
            targetService: 'PAGERDUTY',
            config: { urgency: 'CRITICAL_P0', bridgeUrl: 'https://meet.corp/sec-incident-war-room' }
          }
        ]
      });
    }
    return extended;
  });

  const [activePlaybookId, setActivePlaybookId] = useState<string>(playbooks[0].id);
  const activePlaybook = useMemo(() => {
    return playbooks.find(p => p.id === activePlaybookId) || playbooks[0];
  }, [playbooks, activePlaybookId]);

  const [selectedStepId, setSelectedStepId] = useState<string | null>(activePlaybook.steps[0]?.id || null);
  const selectedStep = useMemo(() => {
    return activePlaybook.steps.find(s => s.id === selectedStepId) || activePlaybook.steps[0];
  }, [activePlaybook, selectedStepId]);

  // Execution state
  const [executionRun, setExecutionRun] = useState<SoarExecutionRun | null>(null);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [activeExecutionStepIdx, setActiveExecutionStepIdx] = useState<number | null>(null);

  // New Node Modal State
  const [showAddNodeModal, setShowAddNodeModal] = useState<boolean>(false);
  const [newNodeType, setNewNodeType] = useState<'ACTION' | 'CONDITION'>('ACTION');
  const [newNodeName, setNewNodeName] = useState<string>('Ação: Bloquear IP do Atacante');
  const [newNodeService, setNewNodeService] = useState<'AWS_IAM' | 'NGFW_FIREWALL' | 'JIRA' | 'SLACK' | 'EDR_AGENT' | 'VAULT_KMS' | 'PAGERDUTY'>('NGFW_FIREWALL');
  const [newNodeActionType, setNewNodeActionType] = useState<SoarActionType>('BLOCK_IP_FIREWALL');

  // Copy state
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Run playbook simulation with step-by-step visualization
  const handleExecutePlaybook = () => {
    setIsExecuting(true);
    setActiveExecutionStepIdx(0);
    setExecutionRun(null);

    const totalSteps = activePlaybook.steps.length;
    let currentIdx = 0;

    const interval = setInterval(() => {
      currentIdx++;
      if (currentIdx < totalSteps) {
        setActiveExecutionStepIdx(currentIdx);
      } else {
        clearInterval(interval);
        const finalRun = executeSoarPlaybook(activePlaybook, { source: 'Visual SOAR Studio Simulator' });
        setExecutionRun(finalRun);
        setIsExecuting(false);
        setActiveExecutionStepIdx(null);

        // Update run stats
        setPlaybooks(prev => prev.map(p => {
          if (p.id === activePlaybook.id) {
            return {
              ...p,
              executionCount: p.executionCount + 1,
              lastRunTimestamp: new Date().toISOString()
            };
          }
          return p;
        }));

        if (onLogAudit) {
          onLogAudit({
            id: `audit-soar-sim-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString(),
            action: `SOAR Flow Studio: Playbook "${activePlaybook.name}" executado com sucesso (${finalRun.totalDurationMs}ms).`,
            user: 'SOAR-Visual-Orchestrator',
            status: 'SUCCESS'
          });
        }
      }
    }, 450);
  };

  // Add new step to active playbook
  const handleAddStep = () => {
    const newStep: SoarPlaybookStep = {
      id: `step-${Date.now()}-${Math.random().toString(36).substring(2, 5)}`,
      name: newNodeName,
      type: newNodeType,
      targetService: newNodeService,
      actionType: newNodeType === 'ACTION' ? newNodeActionType : undefined,
      conditionExpr: newNodeType === 'CONDITION' ? "finding.severity == 'CRITICAL'" : undefined,
      config: newNodeType === 'ACTION' ? { target: 'automatic_quarantine', timeoutSec: 3600 } : { check: 'threat_eval' }
    };

    setPlaybooks(prev => prev.map(p => {
      if (p.id === activePlaybook.id) {
        return {
          ...p,
          steps: [...p.steps, newStep]
        };
      }
      return p;
    }));

    setSelectedStepId(newStep.id);
    setShowAddNodeModal(false);
  };

  // Delete step
  const handleDeleteStep = (stepId: string) => {
    if (activePlaybook.steps.length <= 1) {
      alert('O playbook deve conter pelo menos 1 passo.');
      return;
    }
    setPlaybooks(prev => prev.map(p => {
      if (p.id === activePlaybook.id) {
        return {
          ...p,
          steps: p.steps.filter(s => s.id !== stepId)
        };
      }
      return p;
    }));
    setSelectedStepId(activePlaybook.steps.find(s => s.id !== stepId)?.id || null);
  };

  // Move step up or down
  const handleMoveStep = (stepId: string, direction: 'UP' | 'DOWN') => {
    const idx = activePlaybook.steps.findIndex(s => s.id === stepId);
    if (idx === -1) return;
    if (direction === 'UP' && idx === 0) return;
    if (direction === 'DOWN' && idx === activePlaybook.steps.length - 1) return;

    const newSteps = [...activePlaybook.steps];
    const targetIdx = direction === 'UP' ? idx - 1 : idx + 1;
    const temp = newSteps[idx];
    newSteps[idx] = newSteps[targetIdx];
    newSteps[targetIdx] = temp;

    setPlaybooks(prev => prev.map(p => {
      if (p.id === activePlaybook.id) {
        return {
          ...p,
          steps: newSteps
        };
      }
      return p;
    }));
  };

  // Create new blank playbook
  const handleCreatePlaybook = () => {
    const newPb: SoarPlaybook = {
      id: `soar-pb-custom-${Date.now()}`,
      name: 'Novo Playbook de Resposta Automatizada',
      description: 'Orquestração personalizada para resposta a incidentes críticos e contenção automatizada.',
      category: 'Incident Response',
      enabled: true,
      trigger: {
        type: 'FINDING_DETECTED',
        severity: ['CRITICAL']
      },
      executionCount: 0,
      averageExecutionTimeMs: 250,
      steps: [
        {
          id: `step-init-${Date.now()}`,
          name: 'Gatilho: Detecção de Vulnerabilidade Crítica SAST/DAST',
          type: 'TRIGGER',
          triggerType: 'FINDING_DETECTED',
          targetService: 'JIRA',
          config: { severity: 'CRITICAL' }
        },
        {
          id: `step-action-${Date.now()}`,
          name: 'Ação: Disparar Alerta no Slack #sec-incidents',
          type: 'ACTION',
          actionType: 'SEND_SLACK_ALERT',
          targetService: 'SLACK',
          config: { channel: '#sec-incidents', urgency: 'URGENT' }
        }
      ]
    };

    setPlaybooks(prev => [newPb, ...prev]);
    setActivePlaybookId(newPb.id);
    setSelectedStepId(newPb.steps[0].id);
  };

  return (
    <div className="space-y-6 animate-fadeIn pb-16">
      {/* Top Header Banner */}
      <div className="bg-[#0D0D0D] border-2 border-[#00FF41]/40 p-6 rounded-none relative overflow-hidden shadow-[0_0_30px_rgba(0,255,65,0.08)]">
        <div className="absolute top-0 right-0 w-96 h-96 bg-[#00FF41]/5 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-3">
              <span className="px-2.5 py-0.5 bg-[#00FF41] text-black font-mono font-black text-xs uppercase tracking-widest">
                SOAR VISUAL STUDIO
              </span>
              <span className="text-xs font-mono text-[#888] uppercase">
                SECURITY ORCHESTRATION, AUTOMATION & RESPONSE CANVAS
              </span>
            </div>
            <h1 className="text-3xl font-black text-white tracking-tight uppercase mt-2 flex items-center gap-3">
              <Workflow className="w-8 h-8 text-[#00FF41]" />
              Visual SOAR Playbook Builder
            </h1>
            <p className="text-sm text-[#AAA] font-mono mt-1 max-w-3xl">
              Projete, conecte e simule playbooks visuais de contenção de incidentes com integração para AWS IAM, Next-Gen Firewalls, CrowdStrike EDR, HashiCorp Vault, Jira, Slack e PagerDuty.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              onClick={handleCreatePlaybook}
              className="px-3.5 py-2 bg-[#1A1A1A] hover:bg-[#252525] border border-[#333] hover:border-[#00FF41] text-white text-xs font-mono font-bold uppercase flex items-center gap-2 transition-all cursor-pointer"
            >
              <Plus className="w-4 h-4 text-[#00FF41]" />
              <span>Novo Playbook</span>
            </button>
            <button
              onClick={() => copyToClipboard(exportPlaybookToYaml(activePlaybook), 'soar-yaml-export')}
              className="px-3.5 py-2 bg-[#1A1A1A] hover:bg-[#252525] border border-[#333] text-white text-xs font-mono font-bold uppercase flex items-center gap-1.5 transition-all cursor-pointer"
            >
              {copiedKey === 'soar-yaml-export' ? <Check className="w-4 h-4 text-[#00FF41]" /> : <Copy className="w-4 h-4" />}
              <span>Exportar YAML</span>
            </button>
            <button
              onClick={handleExecutePlaybook}
              disabled={isExecuting}
              className="px-5 py-2.5 bg-[#00FF41] hover:bg-[#00D636] text-black text-xs font-mono font-black uppercase flex items-center gap-2 transition-all cursor-pointer shadow-[0_0_20px_rgba(0,255,65,0.4)] disabled:opacity-50"
            >
              {isExecuting ? <RotateCcw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-black" />}
              <span>{isExecuting ? 'Simulando Fluxo...' : 'Simular Execução (Dry-Run)'}</span>
            </button>
          </div>
        </div>

        {/* Playbook Picker Ribbon */}
        <div className="mt-6 pt-4 border-t border-[#222] flex items-center gap-2 overflow-x-auto pb-2 scrollbar-thin">
          {playbooks.map(pb => {
            const isSelected = activePlaybook.id === pb.id;
            return (
              <button
                key={pb.id}
                onClick={() => {
                  setActivePlaybookId(pb.id);
                  setSelectedStepId(pb.steps[0]?.id || null);
                  setExecutionRun(null);
                }}
                className={`flex items-center gap-2.5 px-3.5 py-2 text-xs font-mono font-bold uppercase transition-all whitespace-nowrap cursor-pointer border ${
                  isSelected
                    ? 'bg-[#181818] text-white border-[#00FF41] shadow-[0_0_12px_rgba(0,255,65,0.25)]'
                    : 'bg-[#101010] text-[#777] hover:text-white border-[#222] hover:border-[#444]'
                }`}
              >
                <span className={`w-2 h-2 rounded-full ${isSelected ? 'bg-[#00FF41] animate-pulse' : 'bg-[#444]'}`} />
                <span>{pb.name}</span>
                <span className="text-[10px] text-[#555] px-1 py-0.2 bg-black border border-[#222]">
                  {pb.steps.length} nós
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Visual Canvas & Node Inspector Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Visual Pipeline Canvas */}
        <div className="lg:col-span-8 bg-[#0F0F0F] border border-[#222] p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#222]">
            <div>
              <h2 className="text-base font-bold text-white uppercase flex items-center gap-2">
                <Workflow className="w-4 h-4 text-[#00FF41]" />
                {activePlaybook.name}
              </h2>
              <p className="text-xs text-[#888] font-mono mt-0.5">{activePlaybook.description}</p>
            </div>
            <button
              onClick={() => setShowAddNodeModal(true)}
              className="px-3 py-1.5 bg-[#00FF41]/10 hover:bg-[#00FF41]/20 border border-[#00FF41]/40 text-[#00FF41] text-xs font-mono font-bold uppercase flex items-center gap-1.5 transition-all self-start sm:self-auto cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Adicionar Nó</span>
            </button>
          </div>

          {/* Interactive Node Flowchart */}
          <div className="space-y-4">
            <div className="flex items-center justify-between text-xs font-mono text-[#666] uppercase">
              <span>Sequência de Nós (Gatilho &rarr; Filtros &rarr; Ações de Resposta)</span>
              <span>{activePlaybook.steps.length} passos configurados</span>
            </div>

            <div className="space-y-3 relative">
              {activePlaybook.steps.map((step, idx) => {
                const Icon = SERVICE_ICONS[step.targetService] || Server;
                const isSelected = selectedStep?.id === step.id;
                const isExecutingThisStep = isExecuting && activeExecutionStepIdx === idx;
                const isDoneExecution = isExecuting && activeExecutionStepIdx !== null && idx < activeExecutionStepIdx;

                return (
                  <div key={step.id} className="relative">
                    {/* Connecting line to next node */}
                    {idx < activePlaybook.steps.length - 1 && (
                      <div className="absolute left-6 top-14 bottom-[-16px] w-0.5 bg-[#222] z-0" />
                    )}

                    <div
                      onClick={() => setSelectedStepId(step.id)}
                      className={`relative z-10 p-4 border transition-all cursor-pointer flex items-start justify-between gap-4 ${
                        isExecutingThisStep
                          ? 'bg-[#1C1C1C] border-[#00FF41] shadow-[0_0_20px_rgba(0,255,65,0.4)] scale-[1.01]'
                          : isSelected
                          ? 'bg-[#161616] border-[#00FF41] shadow-[0_0_12px_rgba(0,255,65,0.15)]'
                          : 'bg-[#121212] border-[#222] hover:border-[#444]'
                      }`}
                    >
                      <div className="flex items-start gap-3.5">
                        {/* Step Number & Service Icon */}
                        <div className={`w-9 h-9 flex items-center justify-center text-xs font-mono font-bold shrink-0 border ${
                          isExecutingThisStep
                            ? 'bg-[#00FF41] text-black border-[#00FF41] animate-pulse'
                            : isDoneExecution
                            ? 'bg-[#00FF41]/20 text-[#00FF41] border-[#00FF41]/40'
                            : 'bg-[#1A1A1A] text-white border-[#333]'
                        }`}>
                          <Icon className="w-4 h-4" />
                        </div>

                        {/* Step Meta */}
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className={`text-[10px] font-mono px-2 py-0.5 uppercase font-bold border ${
                              step.type === 'TRIGGER' ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' :
                              step.type === 'CONDITION' ? 'bg-amber-500/20 text-amber-400 border-amber-500/30' :
                              'bg-[#00FF41]/20 text-[#00FF41] border-[#00FF41]/30'
                            }`}>
                              Nó {idx + 1}: {step.type}
                            </span>
                            <span className="text-[10px] font-mono px-2 py-0.5 bg-[#1F1F1F] text-[#AAA] border border-[#333]">
                              {step.targetService}
                            </span>
                            {step.actionType && (
                              <span className="text-[10px] font-mono text-[#00FF41]">
                                {step.actionType}
                              </span>
                            )}
                          </div>

                          <h3 className="text-sm font-bold text-white">{step.name}</h3>

                          {step.conditionExpr && (
                            <code className="text-xs font-mono text-amber-300 block bg-black px-2 py-1 border border-[#222] mt-1">
                              if: {step.conditionExpr}
                            </code>
                          )}

                          {step.config && (
                            <div className="text-[11px] font-mono text-[#777] mt-0.5">
                              config: {JSON.stringify(step.config)}
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Step Reorder / Action Buttons */}
                      <div className="flex items-center gap-1 shrink-0">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleMoveStep(step.id, 'UP');
                          }}
                          disabled={idx === 0}
                          className="p-1 hover:bg-[#252525] text-[#777] hover:text-white transition-all disabled:opacity-30 cursor-pointer"
                          title="Mover para cima"
                        >
                          <ChevronUp className="w-4 h-4" />
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleMoveStep(step.id, 'DOWN');
                          }}
                          disabled={idx === activePlaybook.steps.length - 1}
                          className="p-1 hover:bg-[#252525] text-[#777] hover:text-white transition-all disabled:opacity-30 cursor-pointer"
                          title="Mover para baixo"
                        >
                          <ChevronDown className="w-4 h-4" />
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDeleteStep(step.id);
                          }}
                          className="p-1 hover:bg-rose-950/40 text-rose-400 hover:text-rose-300 transition-all cursor-pointer"
                          title="Remover nó"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Execution Trace Panel */}
          {executionRun && (
            <div className="pt-6 border-t border-[#222] space-y-3 animate-fadeIn">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-[#00FF41] uppercase flex items-center gap-2">
                  <Check className="w-4 h-4 text-[#00FF41]" />
                  Trilha Forense de Execução do Playbook ({executionRun.totalDurationMs}ms total)
                </span>
                <span className="text-[10px] font-mono text-[#666]">
                  Status: {executionRun.status}
                </span>
              </div>

              <div className="bg-black border border-[#222] p-4 font-mono text-xs space-y-2">
                {executionRun.stepResults.map((res, i) => (
                  <div key={i} className="flex items-start gap-3 border-b border-[#181818] pb-2 last:border-b-0">
                    <span className="text-[#00FF41] font-bold shrink-0">[OK - {res.durationMs}ms]</span>
                    <div>
                      <span className="text-white font-bold">{res.stepName}: </span>
                      <span className="text-[#AAA]">{res.message}</span>
                      {res.actionResultPayload && (
                        <div className="text-[10px] text-[#666] mt-0.5">
                          payload: {JSON.stringify(res.actionResultPayload)}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Node Inspector & Properties Panel */}
        <div className="lg:col-span-4 space-y-6">
          <div className="bg-[#0F0F0F] border border-[#222] p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#222]">
              <span className="text-xs font-mono font-bold text-white uppercase flex items-center gap-2">
                <Settings className="w-4 h-4 text-[#00FF41]" />
                Inspetor de Propriedades do Nó
              </span>
              <span className="text-[10px] font-mono text-[#666]">
                {selectedStep ? selectedStep.type : 'Nenhum nó'}
              </span>
            </div>

            {selectedStep ? (
              <div className="space-y-4">
                {/* Step Name */}
                <div className="space-y-1">
                  <label className="text-xs font-mono text-[#888] uppercase block">Nome do Passo:</label>
                  <input
                    type="text"
                    value={selectedStep.name}
                    onChange={(e) => {
                      const newName = e.target.value;
                      setPlaybooks(prev => prev.map(p => {
                        if (p.id === activePlaybook.id) {
                          return {
                            ...p,
                            steps: p.steps.map(s => s.id === selectedStep.id ? { ...s, name: newName } : s)
                          };
                        }
                        return p;
                      }));
                    }}
                    className="w-full bg-black border border-[#333] focus:border-[#00FF41] px-3 py-1.5 text-xs font-mono text-white outline-none"
                  />
                </div>

                {/* Target Service */}
                <div className="space-y-1">
                  <label className="text-xs font-mono text-[#888] uppercase block">Serviço de Destino:</label>
                  <select
                    value={selectedStep.targetService}
                    onChange={(e) => {
                      const newService = e.target.value as any;
                      setPlaybooks(prev => prev.map(p => {
                        if (p.id === activePlaybook.id) {
                          return {
                            ...p,
                            steps: p.steps.map(s => s.id === selectedStep.id ? { ...s, targetService: newService } : s)
                          };
                        }
                        return p;
                      }));
                    }}
                    className="w-full bg-black border border-[#333] focus:border-[#00FF41] px-3 py-1.5 text-xs font-mono text-white outline-none"
                  >
                    <option value="AWS_IAM">AWS IAM (Identity & Access Management)</option>
                    <option value="NGFW_FIREWALL">Next-Gen Firewall / WAF</option>
                    <option value="EDR_AGENT">CrowdStrike Falcon / EDR Agent</option>
                    <option value="VAULT_KMS">HashiCorp Vault / AWS KMS</option>
                    <option value="JIRA">Atlassian Jira SecOps</option>
                    <option value="SLACK">Slack Incident Alerting</option>
                    <option value="PAGERDUTY">PagerDuty On-Call Escalation</option>
                  </select>
                </div>

                {/* Action Type */}
                {selectedStep.type === 'ACTION' && (
                  <div className="space-y-1">
                    <label className="text-xs font-mono text-[#888] uppercase block">Tipo de Ação:</label>
                    <select
                      value={selectedStep.actionType}
                      onChange={(e) => {
                        const newAction = e.target.value as any;
                        setPlaybooks(prev => prev.map(p => {
                          if (p.id === activePlaybook.id) {
                            return {
                              ...p,
                              steps: p.steps.map(s => s.id === selectedStep.id ? { ...s, actionType: newAction } : s)
                            };
                          }
                          return p;
                        }));
                      }}
                      className="w-full bg-black border border-[#333] focus:border-[#00FF41] px-3 py-1.5 text-xs font-mono text-white outline-none"
                    >
                      <option value="REVOKE_CREDENTIAL">REVOKE_CREDENTIAL - Revogar credencial</option>
                      <option value="BLOCK_IP_FIREWALL">BLOCK_IP_FIREWALL - Bloquear tráfego no Firewall</option>
                      <option value="CREATE_JIRA_TICKET">CREATE_JIRA_TICKET - Abertura de ticket Jira</option>
                      <option value="SEND_SLACK_ALERT">SEND_SLACK_ALERT - Alerta de emergência no Slack</option>
                      <option value="ISOLATE_CONTAINER">ISOLATE_CONTAINER - Isolar host/pod da rede</option>
                      <option value="ROTATE_KMS_KEY">ROTATE_KMS_KEY - Rotacionar chave KMS</option>
                      <option value="NOTIFY_SOC_ON_CALL">NOTIFY_SOC_ON_CALL - Chamar plantonista PagerDuty</option>
                    </select>
                    {selectedStep.actionType && (
                      <p className="text-[11px] font-mono text-[#00FF41] mt-1">
                        {ACTION_DESCRIPTIONS[selectedStep.actionType]}
                      </p>
                    )}
                  </div>
                )}

                {/* Condition Expression */}
                {selectedStep.type === 'CONDITION' && (
                  <div className="space-y-1">
                    <label className="text-xs font-mono text-[#888] uppercase block">Expressão Condicional (JavaScript):</label>
                    <input
                      type="text"
                      value={selectedStep.conditionExpr || ''}
                      onChange={(e) => {
                        const expr = e.target.value;
                        setPlaybooks(prev => prev.map(p => {
                          if (p.id === activePlaybook.id) {
                            return {
                              ...p,
                              steps: p.steps.map(s => s.id === selectedStep.id ? { ...s, conditionExpr: expr } : s)
                            };
                          }
                          return p;
                        }));
                      }}
                      className="w-full bg-black border border-[#333] focus:border-[#00FF41] px-3 py-1.5 text-xs font-mono text-amber-300 outline-none"
                    />
                  </div>
                )}

                {/* Config JSON preview */}
                <div className="space-y-1">
                  <label className="text-xs font-mono text-[#888] uppercase block">Parâmetros de Configuração (JSON):</label>
                  <pre className="bg-black p-3 border border-[#222] text-xs font-mono text-[#AAA] overflow-x-auto">
                    {JSON.stringify(selectedStep.config, null, 2)}
                  </pre>
                </div>
              </div>
            ) : (
              <p className="text-xs font-mono text-[#666]">Selecione um nó no diagrama para inspecionar parâmetros.</p>
            )}
          </div>
        </div>
      </div>

      {/* Add Node Modal */}
      {showAddNodeModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#121212] border-2 border-[#00FF41] max-w-lg w-full p-6 space-y-4 shadow-[0_0_30px_rgba(0,255,65,0.2)]">
            <div className="flex items-center justify-between pb-3 border-b border-[#222]">
              <h3 className="text-sm font-bold text-white uppercase flex items-center gap-2">
                <Plus className="w-4 h-4 text-[#00FF41]" />
                Adicionar Novo Nó ao Playbook
              </h3>
              <button
                onClick={() => setShowAddNodeModal(false)}
                className="text-[#777] hover:text-white font-mono text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="space-y-1">
                <label className="text-[#AAA] uppercase block">Tipo de Nó:</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setNewNodeType('ACTION');
                      setNewNodeName('Ação: Bloquear IP Malicioso no Firewall');
                    }}
                    className={`py-2 px-3 border text-center font-bold cursor-pointer ${
                      newNodeType === 'ACTION' ? 'bg-[#00FF41] text-black border-[#00FF41]' : 'bg-[#181818] text-[#888] border-[#333]'
                    }`}
                  >
                    AÇÃO AUTOMÁTICA
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setNewNodeType('CONDITION');
                      setNewNodeName('Condição: Validar Severidade Crítica');
                    }}
                    className={`py-2 px-3 border text-center font-bold cursor-pointer ${
                      newNodeType === 'CONDITION' ? 'bg-amber-400 text-black border-amber-400' : 'bg-[#181818] text-[#888] border-[#333]'
                    }`}
                  >
                    CONDIÇÃO / FILTRO
                  </button>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-[#AAA] uppercase block">Título do Passo:</label>
                <input
                  type="text"
                  value={newNodeName}
                  onChange={(e) => setNewNodeName(e.target.value)}
                  className="w-full bg-black border border-[#333] p-2 text-white outline-none"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[#AAA] uppercase block">Serviço de Destino:</label>
                <select
                  value={newNodeService}
                  onChange={(e) => setNewNodeService(e.target.value as any)}
                  className="w-full bg-black border border-[#333] p-2 text-white outline-none"
                >
                  <option value="NGFW_FIREWALL">NGFW_FIREWALL - Firewall / WAF</option>
                  <option value="AWS_IAM">AWS_IAM - Nuvem AWS IAM</option>
                  <option value="EDR_AGENT">EDR_AGENT - Sensor de Endpoint (CrowdStrike)</option>
                  <option value="VAULT_KMS">VAULT_KMS - Cofre HashiCorp Vault</option>
                  <option value="JIRA">JIRA - Atlassian Jira SecOps</option>
                  <option value="SLACK">SLACK - Canal de Resposta a Incidentes</option>
                  <option value="PAGERDUTY">PAGERDUTY - Escalação On-Call</option>
                </select>
              </div>

              {newNodeType === 'ACTION' && (
                <div className="space-y-1">
                  <label className="text-[#AAA] uppercase block">Tipo de Ação de Resposta:</label>
                  <select
                    value={newNodeActionType}
                    onChange={(e) => setNewNodeActionType(e.target.value as any)}
                    className="w-full bg-black border border-[#333] p-2 text-white outline-none"
                  >
                    <option value="BLOCK_IP_FIREWALL">BLOCK_IP_FIREWALL - Bloquear tráfego de rede</option>
                    <option value="REVOKE_CREDENTIAL">REVOKE_CREDENTIAL - Revogar credencial vazada</option>
                    <option value="ISOLATE_CONTAINER">ISOLATE_CONTAINER - Isolar host infectado</option>
                    <option value="ROTATE_KMS_KEY">ROTATE_KMS_KEY - Rotacionar chave criptográfica</option>
                    <option value="CREATE_JIRA_TICKET">CREATE_JIRA_TICKET - Abrir ticket P0 no Jira</option>
                    <option value="SEND_SLACK_ALERT">SEND_SLACK_ALERT - Disparar notificação no Slack</option>
                    <option value="NOTIFY_SOC_ON_CALL">NOTIFY_SOC_ON_CALL - Escalar no PagerDuty</option>
                  </select>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-[#222]">
              <button
                type="button"
                onClick={() => setShowAddNodeModal(false)}
                className="px-4 py-2 bg-[#1A1A1A] hover:bg-[#252525] text-white text-xs font-mono font-bold cursor-pointer"
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={handleAddStep}
                className="px-4 py-2 bg-[#00FF41] hover:bg-[#00D636] text-black text-xs font-mono font-black uppercase cursor-pointer"
              >
                Inserir Nó no Fluxo
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
