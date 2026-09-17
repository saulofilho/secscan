import React, { useState, useMemo, useEffect } from 'react';
import {
  ShieldAlert,
  Zap,
  Activity,
  Search,
  Crosshair,
  Server,
  Globe,
  Sliders,
  Terminal,
  Lock,
  Unlock,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Download,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  Cpu,
  Layers,
  ArrowRight,
  Sparkles,
  Filter,
  Eye,
  Workflow,
  Radio,
  XCircle
} from 'lucide-react';
import { ScanReport, ScanFinding } from '../types';
import { safeGetItem, safeSetItem } from '../lib/storage';

export interface CrowdStrikeEndpoint {
  id: string;
  hostname: string;
  ip: string;
  os: string;
  agentVersion: string;
  status: 'ONLINE' | 'ISOLATED' | 'OFFLINE';
  containmentStatus: 'CONTAINED' | 'NORMAL';
  assignedRepo: string;
  lastSeen: string;
  activeThreatCount: number;
  policy: string;
}

export interface CrowdStrikeDetection {
  id: string;
  title: string;
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  processTree: {
    name: string;
    pid: number;
    cmd: string;
    action: 'BLOCKED' | 'SUSPICIOUS' | 'PARENT';
  }[];
  sourceFile?: string;
  line?: number;
  iocs: string[];
  suggestedAction: string;
  status: 'NEW' | 'INVESTIGATING' | 'RESOLVED';
  timestamp: string;
}

export interface CrowdStrikeActor {
  id: string;
  name: string;
  alias: string;
  origin: string;
  motivation: 'STATE_SPONSORED' | 'FINANCIAL' | 'HACKTIVISM';
  targetIndustries: string[];
  targetedFlaws: string[];
  activeCampaign: string;
  confidenceScore: number;
}

interface CrowdStrikeSuiteViewProps {
  report: ScanReport;
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToScanner?: () => void;
  onNavigateToDataFlow?: () => void;
}

type FalconTab = 'ENDPOINT_EDR' | 'IOA_DETECTIONS' | 'THREAT_GRAPH' | 'REAL_TIME_RESPONSE' | 'ADVERSARY_INTEL';

const FALCON_ENDPOINTS_STORAGE_KEY = 'secscan_falcon_endpoints_v1';

export const CrowdStrikeSuiteView: React.FC<CrowdStrikeSuiteViewProps> = ({
  report,
  onSelectFinding,
  onNavigateToScanner,
  onNavigateToDataFlow
}) => {
  const [activeTab, setActiveTab] = useState<FalconTab>('ENDPOINT_EDR');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // =========================================================================
  // 1. ENDPOINTS & SENSOR FLEET (Host Management & Network Containment)
  // =========================================================================
  const [endpoints, setEndpoints] = useState<CrowdStrikeEndpoint[]>(() => {
    const saved = safeGetItem(FALCON_ENDPOINTS_STORAGE_KEY);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) return parsed;
      } catch (e) {
        console.error('Failed to parse saved falcon endpoints', e);
      }
    }

    return [
      {
        id: 'AID-99201-US',
        hostname: 'prod-api-gateway-01',
        ip: '10.240.12.8',
        os: 'Ubuntu 24.04 LTS (Kernel 6.8)',
        agentVersion: 'Falcon 7.15.17804',
        status: 'ONLINE',
        containmentStatus: 'NORMAL',
        assignedRepo: 'src/config/aws.ts',
        lastSeen: 'Agora há pouco',
        activeThreatCount: report.metrics.criticalCount || 2,
        policy: 'Production Hardened Zero-Trust'
      },
      {
        id: 'AID-99202-US',
        hostname: 'worker-node-k8s-pod-7',
        ip: '10.240.14.19',
        os: 'Amazon Linux 2023',
        agentVersion: 'Falcon 7.15.17804',
        status: 'ONLINE',
        containmentStatus: 'NORMAL',
        assignedRepo: 'src/auth/jwt.js',
        lastSeen: '1 min atrás',
        activeThreatCount: report.metrics.highCount || 1,
        policy: 'Container Workload Protection'
      },
      {
        id: 'AID-99203-EU',
        hostname: 'dev-ci-runner-build-9',
        ip: '192.168.88.42',
        os: 'Debian 12 Bookworm',
        agentVersion: 'Falcon 7.14.16500',
        status: 'ONLINE',
        containmentStatus: 'NORMAL',
        assignedRepo: 'src/db/connection.ts',
        lastSeen: '3 mins atrás',
        activeThreatCount: 0,
        policy: 'CI/CD Pipeline Enclave'
      }
    ];
  });

  useEffect(() => {
    safeSetItem(FALCON_ENDPOINTS_STORAGE_KEY, JSON.stringify(endpoints));
  }, [endpoints]);

  const [selectedEndpointId, setSelectedEndpointId] = useState<string>(endpoints[0]?.id || '');
  const selectedEndpoint = useMemo(() => {
    return endpoints.find(e => e.id === selectedEndpointId) || endpoints[0];
  }, [endpoints, selectedEndpointId]);

  const toggleNetworkContainment = (id: string) => {
    setEndpoints(prev => prev.map(ep => {
      if (ep.id !== id) return ep;
      const nextStatus = ep.containmentStatus === 'CONTAINED' ? 'NORMAL' : 'CONTAINED';
      return {
        ...ep,
        containmentStatus: nextStatus,
        status: nextStatus === 'CONTAINED' ? 'ISOLATED' : 'ONLINE'
      };
    }));
  };

  // =========================================================================
  // 2. IOA / IOC DETECTIONS (Indicators of Attack derived from code findings)
  // =========================================================================
  const detections: CrowdStrikeDetection[] = useMemo(() => {
    const findings = report.findings.slice(0, 10);
    if (findings.length === 0) {
      return [
        {
          id: 'DET-1001',
          title: 'Credencial AWS IAM Detectada com Privilégios de Administração',
          tactic: 'Credential Access',
          techniqueId: 'T1552.001',
          techniqueName: 'Credentials In Files',
          severity: 'CRITICAL',
          processTree: [
            { name: 'git.exe', pid: 4820, cmd: 'git commit -m "update config"', action: 'PARENT' },
            { name: 'node.exe', pid: 5124, cmd: 'node dist/server.cjs', action: 'SUSPICIOUS' },
            { name: 'aws-sdk-client', pid: 6192, cmd: 'sts:GetCallerIdentity --key AKIA...', action: 'BLOCKED' }
          ],
          sourceFile: 'src/config/aws.ts',
          line: 14,
          iocs: ['AKIAIOSFODNN7EXAMPLE', '10.240.12.8', 'sts.amazonaws.com'],
          suggestedAction: 'Isolar endpoint da rede imediatamente e revogar credencial no AWS IAM.',
          status: 'NEW',
          timestamp: '2026-09-17 07:22:15'
        }
      ];
    }

    return findings.map((f, idx) => {
      const isCloud = f.category === 'CLOUD_CREDENTIAL';
      const isJwt = f.category === 'AUTH_TOKEN';

      return {
        id: `DET-FALCON-${1000 + idx}`,
        title: `${f.ruleName} em ${f.file.split('/').pop()}`,
        tactic: isCloud ? 'Credential Access' : isJwt ? 'Defense Evasion' : 'Execution',
        techniqueId: isCloud ? 'T1552.001' : isJwt ? 'T1552.004' : 'T1059.007',
        techniqueName: isCloud ? 'Credentials In Files' : isJwt ? 'Private Keys / Tokens' : 'JavaScript Execution',
        severity: f.severity as any,
        processTree: [
          { name: 'code-editor', pid: 2100 + idx, cmd: `open ${f.file}`, action: 'PARENT' },
          { name: 'node', pid: 3200 + idx, cmd: `node ${f.file} --eval-sink`, action: 'SUSPICIOUS' },
          { name: 'falcon-sensor', pid: 4000 + idx, cmd: `falcon-block --pid ${3200 + idx} --rule ${f.ruleId}`, action: 'BLOCKED' }
        ],
        sourceFile: f.file,
        line: f.line,
        iocs: [f.matchedSecret || f.ruleId, f.file, `SHA256:${f.id.slice(0, 16)}`],
        suggestedAction: isCloud
          ? 'Rotacionar chave na nuvem, acionar playbook de contenção e sanitizar histórico git.'
          : 'Aplicar validação estrita no sink e parametrizar entrada externa.',
        status: 'NEW',
        timestamp: new Date().toLocaleTimeString()
      };
    });
  }, [report.findings]);

  const [selectedDetectionId, setSelectedDetectionId] = useState<string>(detections[0]?.id || '');
  const selectedDetection = useMemo(() => {
    return detections.find(d => d.id === selectedDetectionId) || detections[0];
  }, [detections, selectedDetectionId]);

  // =========================================================================
  // 3. ADVERSARY INTEL (Falcon Adversary OverWatch)
  // =========================================================================
  const ADVERSARIES: CrowdStrikeActor[] = [
    {
      id: 'ADV-BEAR-01',
      name: 'FANCY BEAR',
      alias: 'APT28 / Sofacy / Sednit',
      origin: 'Federação Russa (GRU)',
      motivation: 'STATE_SPONSORED',
      targetIndustries: ['Governo', 'Defesa', 'Nuvem e Provedores de SaaS'],
      targetedFlaws: ['Exposição de Segredos Cloud', 'Tokens OAuth / JWT', 'SSRF em Proxies'],
      activeCampaign: 'Operação CloudHarvest (Extração de Tokens CI/CD)',
      confidenceScore: 94
    },
    {
      id: 'ADV-PANDA-02',
      name: 'WICKED PANDA',
      alias: 'APT41 / Winnti Group',
      origin: 'República Popular da China',
      motivation: 'STATE_SPONSORED',
      targetIndustries: ['Telecomunicações', 'Desenvolvimento de Software', 'Finanças'],
      targetedFlaws: ['Supply Chain Dependencies', 'Injeção de Código (RCE)', 'Hardcoded Credentials'],
      activeCampaign: 'Campanha GhostBuild (Envenenamento de Repositórios)',
      confidenceScore: 91
    },
    {
      id: 'ADV-SPIDER-03',
      name: 'SCATTERED SPIDER',
      alias: 'UNC3944 / Octo Tempest',
      origin: 'Global / Atores Cibercriminosos',
      motivation: 'FINANCIAL',
      targetIndustries: ['Provedores de Nuvem (AWS/Azure/GCP)', 'Identity Providers (IdP)', 'Gaming'],
      targetedFlaws: ['API Keys com Permissões IAM Elevadas', 'Falta de MFA em Tokens de API', 'Sessões Longas'],
      activeCampaign: 'Cloud Credential Spreading & Ransomware',
      confidenceScore: 98
    },
    {
      id: 'ADV-CHOLLIMA-04',
      name: 'LABYRINTH CHOLLIMA',
      alias: 'Lazarus Group / Hidden Cobra',
      origin: 'Coreia do Norte (RGB)',
      motivation: 'FINANCIAL',
      targetIndustries: ['Criptoativos', 'Bancos', 'Engenharia de Software'],
      targetedFlaws: ['Chaves Privadas ECDSA/RSA', 'Database URIs em Código', 'Taint Sinks em APIs'],
      activeCampaign: 'Operação VaultBuster (Saques via Chaves Expostas)',
      confidenceScore: 96
    }
  ];

  const [selectedActorId, setSelectedActorId] = useState<string>(ADVERSARIES[0].id);
  const selectedActor = useMemo(() => {
    return ADVERSARIES.find(a => a.id === selectedActorId) || ADVERSARIES[0];
  }, [selectedActorId]);

  // =========================================================================
  // 4. REAL TIME RESPONSE (RTR Remote Shell Console)
  // =========================================================================
  const [rtrCommand, setRtrCommand] = useState<string>('falcon-ctl --status');
  const [rtrHistory, setRtrHistory] = useState<{ cmd: string; output: string; timestamp: string }[]>([
    {
      cmd: 'falcon-ctl --status',
      output: `CrowdStrike Falcon Sensor (EDR Enclave)
Sensor Version: 7.15.17804.0
RFM Status: OFF (Full Kernel & User-Space Visibility Active)
Connected to Falcon Cloud: Yes (Region: us-east-1)
Prevent Policy: Block On Critical IOA & Quarantine In-Memory
Active Containers Monitored: 8
Quarantine Isolation: READY`,
      timestamp: '07:28:10'
    },
    {
      cmd: 'containment status',
      output: `Endpoint ID: AID-99201-US (prod-api-gateway-01)
Network Containment: NORMAL (Unrestricted)
Allowlist IPs: 10.0.0.0/8, 127.0.0.1, falcon.cloud.crowdstrike.com:443`,
      timestamp: '07:29:45'
    }
  ]);

  const handleRunRtrCommand = () => {
    if (!rtrCommand.trim()) return;
    const cmd = rtrCommand.trim();
    let out = '';

    if (cmd.startsWith('isolate') || cmd.startsWith('contain')) {
      toggleNetworkContainment(selectedEndpoint.id);
      out = `[+] SINAL ENVIADO: Endpoint ${selectedEndpoint.hostname} (${selectedEndpoint.id}) agora está ISOLADO da rede. Todo tráfego externo bloqueado exceto telemetria Falcon.`;
    } else if (cmd.startsWith('unisolate') || cmd.startsWith('release')) {
      toggleNetworkContainment(selectedEndpoint.id);
      out = `[+] SINAL ENVIADO: Endpoint ${selectedEndpoint.hostname} liberado do isolamento de rede. Conexões restauradas.`;
    } else if (cmd.startsWith('kill') || cmd.startsWith('block')) {
      out = `[+] PROCESSO TERMINADO: PID interceptado com sucesso. Assinatura do processo adicionada à lista de bloqueio de IOA.`;
    } else if (cmd.startsWith('ps') || cmd.startsWith('top')) {
      out = `PID    NAME              STATUS      IOA RISK
4820   git.exe           RUNNING     LOW
5124   node.exe          SUSPICIOUS  HIGH (Taint Sink: eval/exec)
6192   aws-sdk-client    BLOCKED     CRITICAL (Unencrypted Credential Access)`;
    } else if (cmd.startsWith('iocs') || cmd.startsWith('dump')) {
      out = `Observables Coletados em Memória:
- Chaves Identificadas: ${report.findings.filter(f => f.category === 'CLOUD_CREDENTIAL').length} chaves de cloud
- Total de Alertas P0/P1: ${report.metrics.criticalCount + report.metrics.highCount}
- Arquivo sob análise: ${selectedEndpoint.assignedRepo}`;
    } else {
      out = `Comando '${cmd}' executado com sucesso no sensor remoto.
Código de saída: 0 (OK). Telemetria transmitida para a nuvem Falcon Threat Graph.`;
    }

    setRtrHistory(prev => [
      ...prev,
      {
        cmd,
        output: out,
        timestamp: new Date().toLocaleTimeString()
      }
    ]);
    setRtrCommand('');
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* CrowdStrike Falcon Header Banner */}
      <div className="p-4 sm:p-5 rounded-xl border border-red-500/30 bg-gradient-to-r from-[#1f0505]/95 via-[#140303]/95 to-[#080202] shadow-[0_0_25px_rgba(239,68,68,0.12)] relative overflow-hidden">
        <div className="absolute -right-6 -bottom-6 opacity-10 pointer-events-none">
          <Zap className="w-56 h-56 text-red-500" />
        </div>

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5 flex-wrap">
              <div className="p-2 rounded-lg bg-red-500/20 border border-red-500/40 text-red-400 shadow-sm">
                <Zap className="w-5 h-5 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-lg sm:text-xl font-bold font-mono text-white tracking-tight">
                    CrowdStrike Falcon // EDR & Threat Graph Suite
                  </h1>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/20 text-red-300 border border-red-500/40 uppercase">
                    EDR • XDR • Threat Intel
                  </span>
                </div>
                <p className="text-xs text-zinc-300 mt-0.5">
                  Módulo defensivo inspirado no CrowdStrike Falcon: visibilidade de endpoints em tempo real, detecção por Indicadores de Ataque (IOAs), isolamento de rede sob demanda, inteligência de adversários e console de resposta remota (RTR).
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3 flex-wrap font-mono text-xs">
            <div className="px-3 py-1.5 rounded-lg bg-black/50 border border-red-500/20 text-zinc-300 flex items-center gap-2">
              <Server className="w-3.5 h-3.5 text-red-400" />
              <span>Endpoints Protegidos:</span>
              <strong className="text-white">{endpoints.length}</strong>
            </div>

            <div className="px-3 py-1.5 rounded-lg bg-black/50 border border-amber-500/20 text-zinc-300 flex items-center gap-2">
              <Activity className="w-3.5 h-3.5 text-amber-400" />
              <span>IOA Detections:</span>
              <strong className="text-amber-300">{detections.length}</strong>
            </div>
          </div>
        </div>
      </div>

      {/* Falcon Sub-tool Navigation Tabs */}
      <div className="flex items-center gap-1.5 p-1.5 rounded-xl bg-[#0d0f12] border border-white/10 overflow-x-auto text-xs font-mono">
        <button
          type="button"
          onClick={() => setActiveTab('ENDPOINT_EDR')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
            activeTab === 'ENDPOINT_EDR'
              ? 'bg-red-500/20 text-red-300 border border-red-500/40 shadow-sm'
              : 'text-zinc-400 hover:text-white hover:bg-white/5 border border-transparent'
          }`}
        >
          <Server className="w-3.5 h-3.5 text-red-400" />
          <span>Hosts & Contenção de Rede (EDR)</span>
          <span className="px-1.5 py-0.2 rounded bg-red-500/30 text-red-200 text-[10px]">
            {endpoints.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('IOA_DETECTIONS')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
            activeTab === 'IOA_DETECTIONS'
              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm'
              : 'text-zinc-400 hover:text-white hover:bg-white/5 border border-transparent'
          }`}
        >
          <Crosshair className="w-3.5 h-3.5 text-amber-400" />
          <span>Indicadores de Ataque (IOA & Process Trees)</span>
          <span className="px-1.5 py-0.2 rounded bg-amber-500/30 text-amber-200 text-[10px]">
            {detections.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('REAL_TIME_RESPONSE')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
            activeTab === 'REAL_TIME_RESPONSE'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-zinc-400 hover:text-white hover:bg-white/5 border border-transparent'
          }`}
        >
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span>Real Time Response (RTR Shell)</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('ADVERSARY_INTEL')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-semibold transition-all cursor-pointer whitespace-nowrap ${
            activeTab === 'ADVERSARY_INTEL'
              ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm'
              : 'text-zinc-400 hover:text-white hover:bg-white/5 border border-transparent'
          }`}
        >
          <Globe className="w-3.5 h-3.5 text-purple-400" />
          <span>Threat Intel & Adversários (OverWatch)</span>
          <span className="px-1.5 py-0.2 rounded bg-purple-500/30 text-purple-200 text-[10px]">
            {ADVERSARIES.length}
          </span>
        </button>
      </div>

      {/* =================================================================== */}
      {/* 1. HOSTS & NETWORK CONTAINMENT (EDR FLEET)                          */}
      {/* =================================================================== */}
      {activeTab === 'ENDPOINT_EDR' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Host List */}
            <div className="lg:col-span-6 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-red-400" />
                  <span>Frota de Sensores Falcon Monitorados ({endpoints.length})</span>
                </h2>
                <span className="text-[10px] font-mono text-zinc-400">Clique para inspecionar</span>
              </div>

              <div className="space-y-2.5">
                {endpoints.map(ep => {
                  const isSelected = ep.id === selectedEndpoint.id;
                  const isContained = ep.containmentStatus === 'CONTAINED';

                  return (
                    <div
                      key={ep.id}
                      onClick={() => setSelectedEndpointId(ep.id)}
                      className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                        isSelected
                          ? 'bg-[#180909] border-red-500/60 shadow-lg'
                          : 'bg-[#0d0d0f] border-white/10 hover:border-white/20 hover:bg-[#121215]'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-white">{ep.hostname}</span>
                            <span className="text-[10px] font-mono text-zinc-500">({ep.ip})</span>
                          </div>
                          <span className="text-[10px] font-mono text-zinc-400 block">{ep.os}</span>
                        </div>

                        <div className="flex items-center gap-1.5">
                          {isContained ? (
                            <span className="px-2 py-0.5 rounded text-[9.5px] font-mono font-bold bg-red-500/20 text-red-300 border border-red-500/40 flex items-center gap-1 animate-pulse">
                              <Lock className="w-2.5 h-2.5" />
                              ISOLADO (CONTAINED)
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[9.5px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex items-center gap-1">
                              <CheckCircle2 className="w-2.5 h-2.5" />
                              NORMAL (ONLINE)
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400 mt-2.5 pt-2 border-t border-white/5">
                        <span>Arquivo: <code className="text-zinc-300">{ep.assignedRepo}</code></span>
                        <span className="text-red-400 font-bold">{ep.activeThreatCount} ameaças ativas</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Selected Host Control Panel & Rapid Isolation Action */}
            <div className="lg:col-span-6">
              <div className="p-4 sm:p-5 rounded-xl bg-[#0d0f12] border border-white/10 space-y-4">
                <div className="flex items-start justify-between border-b border-white/10 pb-3">
                  <div>
                    <span className="text-xs font-mono text-red-400 font-bold">{selectedEndpoint.id}</span>
                    <h3 className="text-base font-bold text-white mt-0.5">{selectedEndpoint.hostname}</h3>
                    <p className="text-xs text-zinc-400">{selectedEndpoint.policy}</p>
                  </div>

                  {/* Network Containment Button */}
                  <button
                    type="button"
                    onClick={() => toggleNetworkContainment(selectedEndpoint.id)}
                    className={`px-3 py-2 rounded-lg font-mono text-xs font-bold border transition-all cursor-pointer flex items-center gap-2 ${
                      selectedEndpoint.containmentStatus === 'CONTAINED'
                        ? 'bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border-emerald-500/40 shadow-sm'
                        : 'bg-red-500/20 hover:bg-red-500/30 text-red-300 border-red-500/40 shadow-md animate-pulse'
                    }`}
                  >
                    {selectedEndpoint.containmentStatus === 'CONTAINED' ? (
                      <>
                        <Unlock className="w-4 h-4 text-emerald-400" />
                        <span>Liberar Isolamento</span>
                      </>
                    ) : (
                      <>
                        <Lock className="w-4 h-4 text-red-400" />
                        <span>Isolar Endpoint da Rede</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Host Details Grid */}
                <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                    <span className="text-[10px] text-zinc-500 block uppercase">Versão do Agente</span>
                    <strong className="text-white">{selectedEndpoint.agentVersion}</strong>
                  </div>
                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                    <span className="text-[10px] text-zinc-500 block uppercase">Último Heartbeat</span>
                    <strong className="text-emerald-400">{selectedEndpoint.lastSeen}</strong>
                  </div>
                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                    <span className="text-[10px] text-zinc-500 block uppercase">Endereço IP / Subnet</span>
                    <strong className="text-white">{selectedEndpoint.ip}</strong>
                  </div>
                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                    <span className="text-[10px] text-zinc-500 block uppercase">Ameaças Pendentes</span>
                    <strong className="text-red-400">{selectedEndpoint.activeThreatCount} ativas</strong>
                  </div>
                </div>

                {/* Containment Explanatory Banner */}
                <div className={`p-3 rounded-lg border text-xs font-mono ${
                  selectedEndpoint.containmentStatus === 'CONTAINED'
                    ? 'bg-red-950/40 border-red-500/40 text-red-200'
                    : 'bg-zinc-900 border-white/10 text-zinc-300'
                }`}>
                  <div className="flex items-start gap-2">
                    <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
                    <div>
                      <strong className="text-white block">
                        {selectedEndpoint.containmentStatus === 'CONTAINED'
                          ? 'Mecanismo de Contenção Zero-Trust Ativo'
                          : 'Isolamento Rápido em 1-Clique Disponível'}
                      </strong>
                      <p className="text-[11px] text-zinc-400 mt-1">
                        {selectedEndpoint.containmentStatus === 'CONTAINED'
                          ? 'O host teve todas as portas e tráfego de entrada e saída bloqueados a nível de kernel pelo driver Falcon, preservando unicamente o túnel TLS com a console de investigação para que atacantes não possam exfiltrar segredos adicionais nem fazer movimentação lateral.'
                          : 'Ao detectar vazamento de credenciais mestre ou execução remota de código (RCE), acione o isolamento para cortar conexões com a Internet e com a VPC mantendo a máquina ligada para coleta de memória.'}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Quick actions for host */}
                <div className="flex items-center gap-2 pt-2 border-t border-white/10">
                  <button
                    type="button"
                    onClick={() => setActiveTab('REAL_TIME_RESPONSE')}
                    className="flex-1 px-3 py-2 rounded bg-white/5 hover:bg-white/10 text-zinc-200 border border-white/15 text-xs font-mono transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Conectar via RTR Shell</span>
                  </button>

                  {onNavigateToScanner && (
                    <button
                      type="button"
                      onClick={onNavigateToScanner}
                      className="px-3 py-2 rounded bg-white/5 hover:bg-white/10 text-zinc-200 border border-white/15 text-xs font-mono transition-colors flex items-center gap-1.5 cursor-pointer"
                    >
                      <FileCode className="w-3.5 h-3.5 text-amber-400" />
                      <span>Ver Código Afetado</span>
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* 2. INDICATORS OF ATTACK (IOA DETECTIONS & PROCESS TREES)            */}
      {/* =================================================================== */}
      {activeTab === 'IOA_DETECTIONS' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* IOA Detection List */}
          <div className="lg:col-span-5 space-y-3">
            <h2 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <Crosshair className="w-3.5 h-3.5 text-amber-400" />
              <span>Detecções por Indicador de Ataque ({detections.length})</span>
            </h2>

            <div className="space-y-2 max-h-[640px] overflow-y-auto pr-1">
              {detections.map(det => {
                const isSelected = det.id === selectedDetection.id;
                const isCrit = det.severity === 'CRITICAL';

                return (
                  <div
                    key={det.id}
                    onClick={() => setSelectedDetectionId(det.id)}
                    className={`p-3 rounded-xl border transition-all cursor-pointer ${
                      isSelected
                        ? 'bg-[#181109] border-amber-500/60 shadow-lg'
                        : 'bg-[#0d0d0f] border-white/10 hover:border-white/20 hover:bg-[#121215]'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-[10px] font-mono text-zinc-500 font-bold">{det.id}</span>
                      <span
                        className={`px-1.5 py-0.2 rounded text-[8.5px] font-mono font-bold border ${
                          isCrit
                            ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                            : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                        }`}
                      >
                        {det.severity}
                      </span>
                    </div>

                    <h4 className="text-xs font-bold text-white mt-1 leading-snug">
                      {det.title}
                    </h4>

                    <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400 mt-2 pt-1.5 border-t border-white/5">
                      <span className="text-amber-400 font-semibold">{det.techniqueId}</span>
                      <span>{det.tactic}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Process Tree & IOA Analysis Workbench */}
          <div className="lg:col-span-7">
            <div className="p-4 sm:p-5 rounded-xl bg-[#0d0f12] border border-white/10 space-y-4">
              <div className="flex items-start justify-between border-b border-white/10 pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-amber-400">{selectedDetection.id}</span>
                    <span className="text-zinc-500">•</span>
                    <span className="text-xs font-mono text-zinc-300">{selectedDetection.techniqueId}: {selectedDetection.techniqueName}</span>
                  </div>
                  <h3 className="text-base font-bold text-white mt-0.5">{selectedDetection.title}</h3>
                </div>

                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                  IOA TRIGGERED
                </span>
              </div>

              {/* Falcon Process Tree Visualizer (Parent -> Child -> Blocked Process) */}
              <div className="space-y-2">
                <h4 className="text-xs font-mono font-bold text-zinc-300 uppercase tracking-wider flex items-center gap-1.5">
                  <Workflow className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Árvore de Execução de Processos (Falcon Process Lineage)</span>
                </h4>

                <div className="p-3.5 rounded-lg bg-black/60 border border-white/10 space-y-3 font-mono text-xs">
                  {selectedDetection.processTree.map((proc, index) => {
                    const isBlocked = proc.action === 'BLOCKED';
                    const isSuspicious = proc.action === 'SUSPICIOUS';

                    return (
                      <div key={index} className="flex items-start gap-3 relative">
                        {index < selectedDetection.processTree.length - 1 && (
                          <div className="absolute left-2.5 top-6 bottom-0 w-0.5 bg-white/15" />
                        )}

                        <div className={`w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-0.5 text-[10px] font-bold ${
                          isBlocked
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                            : isSuspicious
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                            : 'bg-zinc-800 text-zinc-400 border border-white/15'
                        }`}>
                          {index + 1}
                        </div>

                        <div className="flex-1 space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="text-white font-bold">{proc.name}</span>
                            <span className="text-zinc-500 text-[10px]">(PID: {proc.pid})</span>
                            <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold border ${
                              isBlocked
                                ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                                : isSuspicious
                                ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                                : 'bg-white/5 text-zinc-400 border-white/10'
                            }`}>
                              {proc.action}
                            </span>
                          </div>
                          <code className="text-[11px] text-emerald-300 block bg-black/80 px-2 py-1 rounded border border-white/5 truncate">
                            $ {proc.cmd}
                          </code>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Indicators of Compromise (IOCs) */}
              <div className="space-y-1.5">
                <span className="text-xs font-mono font-bold text-zinc-300 uppercase block">Observables & IOCs:</span>
                <div className="flex flex-wrap gap-1.5">
                  {selectedDetection.iocs.map((ioc, i) => (
                    <span
                      key={i}
                      className="px-2 py-1 rounded bg-[#161616] border border-white/10 text-zinc-300 font-mono text-[11px] flex items-center gap-1.5"
                    >
                      <span>{ioc}</span>
                      <button
                        type="button"
                        onClick={() => handleCopy(ioc, `ioc-${i}`)}
                        className="text-zinc-500 hover:text-white"
                        title="Copiar IOC"
                      >
                        {copiedKey === `ioc-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </span>
                  ))}
                </div>
              </div>

              {/* Remediation Guidance */}
              <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs font-mono text-amber-200">
                <strong className="text-white block mb-1">Ação Preventiva Recomendada pelo Falcon Sensor:</strong>
                {selectedDetection.suggestedAction}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* 3. REAL TIME RESPONSE (RTR REMOTE INVESTIGATION CONSOLE)            */}
      {/* =================================================================== */}
      {activeTab === 'REAL_TIME_RESPONSE' && (
        <div className="p-4 sm:p-5 rounded-xl bg-[#090b0e] border border-white/10 space-y-4 font-mono text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-bold text-white">Falcon Real Time Response (RTR) Enclave</h2>
              <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                Sessão Ativa: {selectedEndpoint.hostname} ({selectedEndpoint.id})
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setRtrHistory([])}
                className="px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white border border-white/10 text-[11px] transition-colors cursor-pointer"
              >
                Limpar Tela
              </button>
            </div>
          </div>

          {/* Quick RTR macros */}
          <div className="flex items-center gap-2 flex-wrap pt-1">
            <span className="text-[10px] text-zinc-500 uppercase font-semibold">Comandos Rápidos:</span>
            {[
              { cmd: 'falcon-ctl --status', label: 'Status do Sensor' },
              { cmd: 'isolate host', label: 'Isolar Host' },
              { cmd: 'unisolate host', label: 'Liberar Host' },
              { cmd: 'ps', label: 'Listar Processos' },
              { cmd: 'iocs dump', label: 'Extrair Memória' }
            ].map(m => (
              <button
                key={m.cmd}
                type="button"
                onClick={() => setRtrCommand(m.cmd)}
                className="px-2 py-0.5 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-[10.5px] transition-colors cursor-pointer"
              >
                {m.label}
              </button>
            ))}
          </div>

          {/* Shell Terminal Output Window */}
          <div className="h-80 overflow-y-auto bg-black/90 p-4 rounded-lg border border-white/10 space-y-3 font-mono text-[11.5px] text-zinc-200 select-text">
            {rtrHistory.map((item, idx) => (
              <div key={idx} className="space-y-1">
                <div className="flex items-center gap-2 text-cyan-400">
                  <span className="text-zinc-600">[{item.timestamp}]</span>
                  <span>falcon-rtr@{selectedEndpoint.hostname}:~$</span>
                  <span className="text-white font-bold">{item.cmd}</span>
                </div>
                <pre className="text-zinc-300 pl-4 whitespace-pre-wrap font-mono text-[11px] leading-relaxed">
                  {item.output}
                </pre>
              </div>
            ))}
          </div>

          {/* Shell Command Input */}
          <div className="flex items-center gap-2">
            <span className="text-cyan-400 font-bold">$</span>
            <input
              type="text"
              value={rtrCommand}
              onChange={(e) => setRtrCommand(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleRunRtrCommand();
              }}
              placeholder="Digite um comando RTR (ex: ps, isolate host, falcon-ctl --status)..."
              className="flex-1 bg-[#111] border border-white/15 focus:border-cyan-500/70 rounded-lg px-3 py-2 text-xs font-mono text-zinc-100 placeholder:text-zinc-600 focus:outline-none"
            />
            <button
              type="button"
              onClick={handleRunRtrCommand}
              className="px-4 py-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-bold transition-colors cursor-pointer"
            >
              Executar
            </button>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* 4. ADVERSARY THREAT INTELLIGENCE (CROWDSTRIKE OVERWATCH)            */}
      {/* =================================================================== */}
      {activeTab === 'ADVERSARY_INTEL' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Actor List */}
            <div className="lg:col-span-5 space-y-3">
              <h2 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-purple-400" />
                <span>Atores de Ameaça Globais Rastreados ({ADVERSARIES.length})</span>
              </h2>

              <div className="space-y-2.5">
                {ADVERSARIES.map(actor => {
                  const isSelected = actor.id === selectedActor.id;

                  return (
                    <div
                      key={actor.id}
                      onClick={() => setSelectedActorId(actor.id)}
                      className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                        isSelected
                          ? 'bg-[#180924] border-purple-500/60 shadow-lg'
                          : 'bg-[#0d0d0f] border-white/10 hover:border-white/20 hover:bg-[#121215]'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-white">{actor.name}</span>
                            <span className="text-[10px] font-mono text-zinc-500">({actor.alias})</span>
                          </div>
                          <span className="text-[10px] font-mono text-purple-400">{actor.origin}</span>
                        </div>

                        <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                          {actor.confidenceScore}% Confiança
                        </span>
                      </div>

                      <div className="text-[10px] font-mono text-zinc-400 mt-2 pt-2 border-t border-white/5 truncate">
                        Campanha: <span className="text-zinc-300">{actor.activeCampaign}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Selected Actor Deep Dossier */}
            <div className="lg:col-span-7">
              <div className="p-4 sm:p-5 rounded-xl bg-[#0d0f12] border border-white/10 space-y-4 font-mono text-xs">
                <div className="flex items-start justify-between border-b border-white/10 pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-white">{selectedActor.name}</span>
                      <span className="text-zinc-500">•</span>
                      <span className="text-xs text-purple-400 font-bold">{selectedActor.alias}</span>
                    </div>
                    <p className="text-xs text-zinc-400 mt-0.5">{selectedActor.origin} ({selectedActor.motivation})</p>
                  </div>

                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                    NÍVEL CRÍTICO
                  </span>
                </div>

                {/* Campaign Spotlight */}
                <div className="p-3 rounded-lg bg-purple-950/30 border border-purple-500/30 text-purple-200">
                  <strong className="text-white block mb-1">Campanha Ativa Mapeada:</strong>
                  {selectedActor.activeCampaign}
                </div>

                {/* Targeted Flaws (Correlated with code repo vulnerabilities) */}
                <div className="space-y-2">
                  <span className="text-zinc-300 font-bold block uppercase text-[11px]">
                    Vulnerabilidades & Vetores Alvo Deste Adversário:
                  </span>
                  <div className="space-y-1.5">
                    {selectedActor.targetedFlaws.map((flaw, idx) => (
                      <div key={idx} className="p-2 rounded bg-black/40 border border-white/5 flex items-center justify-between">
                        <span className="text-zinc-200">{flaw}</span>
                        <span className="text-[10px] text-red-400 font-bold">ALERTA NO REPO</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Target Industries */}
                <div className="space-y-1.5 pt-2 border-t border-white/10">
                  <span className="text-zinc-400 text-[10px] uppercase block font-semibold">Indústrias Alvo:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedActor.targetIndustries.map((ind, idx) => (
                      <span key={idx} className="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-zinc-300 text-[10.5px]">
                        {ind}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
