import React, { useState, useEffect, useMemo } from 'react';
import {
  Sliders,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Terminal,
  Bell,
  BellRing,
  Volume2,
  VolumeX,
  Copy,
  Check,
  RotateCcw,
  Play,
  Flame,
  Zap,
  Radio,
  ArrowRight,
  ExternalLink,
  ShieldCheck,
  AlertOctagon,
  Activity,
  Sparkles,
  History,
  Minus,
  Plus,
  Send,
  Code2,
  Layers,
  Lock,
  RefreshCw,
  Info
} from 'lucide-react';
import type { ScanReport } from '../types';

interface RiskThresholdConfigPanelProps {
  report: ScanReport;
  cumulativeRiskScore: number;
  cumulativeRiskLevel: string;
  qualityGateLimit: number;
  onUpdateQualityGateLimit: (val: number) => void;
  metrics: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    workspaceRiskBreakdown?: {
      criticalPoints: number;
      highPoints: number;
      mediumPoints: number;
      lowPoints: number;
      infoPoints: number;
      rawPoints: number;
    };
  };
  onScrollToMitigations?: () => void;
  onScrollToHistory?: () => void;
}

interface AlertTriggerEvent {
  id: string;
  timestamp: string;
  score: number;
  limit: number;
  status: 'EXCEEDED' | 'COMPLIANT';
  action: string;
  channel: string;
}

const DEFAULT_WEBHOOK_URL = 'https://hooks.slack.com/services/T00/B00/secscan-alerts';

function playAlertTone() {
  try {
    const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    if (ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }
    
    // First tone (high alert)
    const osc1 = ctx.createOscillator();
    const gain1 = ctx.createGain();
    osc1.type = 'sawtooth';
    osc1.frequency.setValueAtTime(660, ctx.currentTime);
    osc1.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.12);
    gain1.gain.setValueAtTime(0.12, ctx.currentTime);
    gain1.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.15);
    osc1.connect(gain1);
    gain1.connect(ctx.destination);
    osc1.start();
    osc1.stop(ctx.currentTime + 0.15);

    // Second tone (warning chime)
    const osc2 = ctx.createOscillator();
    const gain2 = ctx.createGain();
    osc2.type = 'triangle';
    osc2.frequency.setValueAtTime(990, ctx.currentTime + 0.15);
    osc2.frequency.exponentialRampToValueAtTime(1320, ctx.currentTime + 0.28);
    gain2.gain.setValueAtTime(0.15, ctx.currentTime + 0.15);
    gain2.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.35);
    osc2.connect(gain2);
    gain2.connect(ctx.destination);
    osc2.start(ctx.currentTime + 0.15);
    osc2.stop(ctx.currentTime + 0.35);
  } catch {
    // AudioContext blocked or unsupported
  }
}

export const RiskThresholdConfigPanel: React.FC<RiskThresholdConfigPanelProps> = ({
  report,
  cumulativeRiskScore,
  cumulativeRiskLevel,
  qualityGateLimit,
  onUpdateQualityGateLimit,
  metrics,
  onScrollToMitigations,
  onScrollToHistory
}) => {
  const isExceeded = cumulativeRiskScore > qualityGateLimit;
  const delta = cumulativeRiskScore - qualityGateLimit;

  // Configuration options persisted in localStorage
  const [soundEnabled, setSoundEnabled] = useState<boolean>(() => {
    try {
      return localStorage.getItem('secscan_alert_sound_enabled') === 'true';
    } catch {
      return false;
    }
  });

  const [webhookUrl, setWebhookUrl] = useState<string>(() => {
    try {
      return localStorage.getItem('secscan_alert_webhook_url') || DEFAULT_WEBHOOK_URL;
    } catch {
      return DEFAULT_WEBHOOK_URL;
    }
  });

  const [alertChannel, setAlertChannel] = useState<'slack' | 'discord' | 'pagerduty' | 'teams' | 'custom'>(() => {
    try {
      const saved = localStorage.getItem('secscan_alert_channel');
      if (saved && ['slack', 'discord', 'pagerduty', 'teams', 'custom'].includes(saved)) {
        return saved as 'slack' | 'discord' | 'pagerduty' | 'teams' | 'custom';
      }
    } catch {
      // ignore
    }
    return 'slack';
  });

  const [breakCiCdOnBreach, setBreakCiCdOnBreach] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem('secscan_break_cicd_on_breach');
      return saved !== 'false'; // default true
    } catch {
      return true;
    }
  });

  const [blockPrMerge, setBlockPrMerge] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem('secscan_block_pr_merge');
      return saved !== 'false'; // default true
    } catch {
      return true;
    }
  });

  // Simulator & Trigger states
  const [isSimulatingCiCd, setIsSimulatingCiCd] = useState(false);
  const [simulationLogs, setSimulationLogs] = useState<string[]>([]);
  const [simulationFinished, setSimulationFinished] = useState(false);
  const [simulationPassed, setSimulationPassed] = useState<boolean | null>(null);

  const [isDispatchingAlert, setIsDispatchingAlert] = useState(false);
  const [lastDispatchedTime, setLastDispatchedTime] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'cicd' | 'alert' | 'snippets'>('cicd');
  const [selectedSnippet, setSelectedSnippet] = useState<'github' | 'gitlab' | 'jenkins' | 'precommit'>('github');

  // Trigger events history log
  const [triggerEvents, setTriggerEvents] = useState<AlertTriggerEvent[]>(() => [
    {
      id: 'trig-1',
      timestamp: new Date(Date.now() - 3600000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      score: cumulativeRiskScore,
      limit: qualityGateLimit,
      status: isExceeded ? 'EXCEEDED' : 'COMPLIANT',
      action: isExceeded ? 'CI/CD Break (Exit 1) + Webhook Alert' : 'Quality Gate Passed (Exit 0)',
      channel: 'Slack #secops-alerts'
    }
  ]);

  // Persist settings
  useEffect(() => {
    try {
      localStorage.setItem('secscan_alert_sound_enabled', String(soundEnabled));
      localStorage.setItem('secscan_alert_webhook_url', webhookUrl);
      localStorage.setItem('secscan_alert_channel', alertChannel);
      localStorage.setItem('secscan_break_cicd_on_breach', String(breakCiCdOnBreach));
      localStorage.setItem('secscan_block_pr_merge', String(blockPrMerge));
    } catch {
      // ignore
    }
  }, [soundEnabled, webhookUrl, alertChannel, breakCiCdOnBreach, blockPrMerge]);

  // Play sound when threshold transitions to exceeded if sound is enabled
  useEffect(() => {
    if (isExceeded && soundEnabled) {
      playAlertTone();
    }
  }, [isExceeded, soundEnabled]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Predefined governance baseline presets
  const presets = [
    { val: 15, label: '15', name: 'Tolerância Zero', desc: 'Bancos / Defesa / Missão Crítica' },
    { val: 30, label: '30', name: 'Estrito DevSecOps', desc: 'Produção com Dados Sensíveis' },
    { val: 50, label: '50', name: 'Padrão SecOps', desc: 'Esteira Contínua Corporativa' },
    { val: 75, label: '75', name: 'Permissivo', desc: 'Ambientes de Dev e Staging' }
  ];

  // Dispatch Test Alert Simulation
  const handleTestAlertDispatch = () => {
    setIsDispatchingAlert(true);
    if (soundEnabled) {
      playAlertTone();
    }

    setTimeout(() => {
      setIsDispatchingAlert(false);
      const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      setLastDispatchedTime(nowStr);

      const newEvent: AlertTriggerEvent = {
        id: `trig-${Date.now()}`,
        timestamp: nowStr,
        score: cumulativeRiskScore,
        limit: qualityGateLimit,
        status: isExceeded ? 'EXCEEDED' : 'COMPLIANT',
        action: isExceeded
          ? `Disparado Alerta de Violação (+${delta} pts) → Webhook HTTP 200`
          : `Disparado Teste de Conformidade (Score ${cumulativeRiskScore} <= ${qualityGateLimit}) → Webhook HTTP 200`,
        channel: `${alertChannel.toUpperCase()} (${webhookUrl.slice(0, 32)}...)`
      };
      setTriggerEvents((prev) => [newEvent, ...prev.slice(0, 5)]);
    }, 900);
  };

  // CI/CD Pipeline Execution Simulator
  const handleRunCiCdSimulation = () => {
    setIsSimulatingCiCd(true);
    setSimulationFinished(false);
    setSimulationPassed(null);
    setSimulationLogs([
      `[CI/CD Runner] Initializing SecScan Security Gatekeeper container...`,
      `[CI/CD Runner] Working directory: /workspace/project`,
      `[SecScan] Executing: node bin/secscan.js . --max-risk ${qualityGateLimit} --format table`
    ]);

    setTimeout(() => {
      setSimulationLogs((prev) => [
        ...prev,
        `[SecScan] Scanning files for hardcoded secrets, API tokens & cloud credentials...`,
        `[SecScan] Total Findings: ${report.findings.length} (Critical: ${metrics.criticalCount}, High: ${metrics.highCount}, Medium: ${metrics.mediumCount})`,
        `[SecScan] Computed Cumulative Risk Score: ${cumulativeRiskScore} / 100`
      ]);
    }, 600);

    setTimeout(() => {
      setSimulationLogs((prev) => [
        ...prev,
        `[Quality Gate Evaluation] Configured Global Risk Threshold: ${qualityGateLimit} pts`,
        `[Quality Gate Evaluation] Current Workspace Score: ${cumulativeRiskScore} pts`
      ]);

      if (isExceeded) {
        setSimulationLogs((prev) => [
          ...prev,
          `❌ [QUALITY GATE BREACH] Risk Score (${cumulativeRiskScore}) exceeds maximum allowed threshold (${qualityGateLimit})!`,
          `🚨 Triggering Automated DevSecOps Alert to channel: ${alertChannel.toUpperCase()}...`,
          `💥 [CI/CD BREAK] Fail-on-breach is ENABLED: Exiting with status code 1.`,
          `🛑 BUILD FAILED: Pull Request cannot be merged to 'main' branch until risks are mitigated.`
        ]);
        setSimulationPassed(false);
        if (soundEnabled) {
          playAlertTone();
        }
      } else {
        setSimulationLogs((prev) => [
          ...prev,
          `✅ [QUALITY GATE PASSED] Workspace Risk Score is within acceptable parameters (${cumulativeRiskScore} <= ${qualityGateLimit}).`,
          `🎉 [CI/CD SUCCESS] Zero critical policy breaches detected: Exiting with status code 0.`,
          `🟢 BUILD PASSED: Security gate approved for deployment.`
        ]);
        setSimulationPassed(true);
      }
      setIsSimulatingCiCd(false);
      setSimulationFinished(true);
    }, 1400);
  };

  // Sample JSON webhook payload
  const webhookPayload = useMemo(() => {
    return JSON.stringify(
      {
        event: isExceeded ? 'SECURITY_RISK_THRESHOLD_EXCEEDED' : 'SECURITY_GATE_EVALUATED',
        severity: isExceeded ? 'CRITICAL_ALERT' : 'INFO',
        workspace: 'Production Workspace',
        metrics: {
          cumulativeRiskScore,
          globalRiskThresholdLimit: qualityGateLimit,
          violationDelta: delta > 0 ? `+${delta} pts` : `${delta} pts (Compliant)`,
          riskLevel: cumulativeRiskLevel,
          totalFindings: report.findings.length,
          breakdown: {
            critical: metrics.criticalCount,
            high: metrics.highCount,
            medium: metrics.mediumCount,
            low: metrics.lowCount
          }
        },
        cicdActions: {
          breakPipeline: breakCiCdOnBreach && isExceeded,
          exitCode: isExceeded && breakCiCdOnBreach ? 1 : 0,
          blockMerge: blockPrMerge && isExceeded
        },
        timestamp: new Date().toISOString()
      },
      null,
      2
    );
  }, [isExceeded, cumulativeRiskScore, qualityGateLimit, delta, cumulativeRiskLevel, report.findings.length, metrics, breakCiCdOnBreach, blockPrMerge]);

  // CI/CD Configuration Code Snippets
  const codeSnippets = {
    github: `# .github/workflows/security-gate.yml
name: SecScan Security Gatekeeper

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-audit:
    name: SecScan Risk Threshold Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Source Code
        uses: actions/checkout@v4

      - name: Setup Node.js Environment
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Install Dependencies
        run: npm ci

      - name: Evaluate Global Risk Score Quality Gate
        # Fails CI/CD build with Exit Code 1 if Risk Score > ${qualityGateLimit}
        run: node bin/secscan.js . --max-risk ${qualityGateLimit} --format table
`,
    gitlab: `# .gitlab-ci.yml
stages:
  - test
  - security

secscan-risk-gate:
  stage: security
  image: node:20-alpine
  script:
    - npm ci
    # Enforces Global Risk Score limit (${qualityGateLimit}). Breaks pipeline if exceeded.
    - node bin/secscan.js . --max-risk ${qualityGateLimit} --format table
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
`,
    jenkins: `// Jenkinsfile
pipeline {
  agent any
  stages {
    stage('Security Audit') {
      steps {
        sh 'npm ci'
        // Break build if Global Risk Score exceeds threshold
        sh 'node bin/secscan.js . --max-risk ${qualityGateLimit} --format table'
      }
    }
  }
}
`,
    precommit: `#!/bin/sh
# .git/hooks/pre-push
# Pre-push hook preventing git push if Global Risk Score exceeds ${qualityGateLimit}

echo "🛡️  Verifying SecScan Global Risk Threshold (${qualityGateLimit} pts)..."
node bin/secscan.js . --max-risk ${qualityGateLimit} --format table

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo "❌ Git push aborted! Workspace Risk Score exceeds the configured limit of ${qualityGateLimit}."
  echo "Remediate high-severity secrets before pushing to remote repository."
  exit 1
fi
`
  };

  return (
    <div
      id="risk-threshold-config"
      className={`border-2 p-6 lg:p-8 space-y-7 transition-all relative overflow-hidden ${
        isExceeded
          ? 'bg-[#0E0301] border-[#FF3E00] shadow-[0_0_35px_rgba(255,62,0,0.22)]'
          : 'bg-[#0A0A0A] border-[#2A2A2A]'
      }`}
    >
      {/* Background Subtle Ambience */}
      <div 
        className={`absolute -top-32 -right-32 w-80 h-80 rounded-full blur-[100px] pointer-events-none transition-all ${
          isExceeded ? 'bg-[#FF3E00]/15' : 'bg-[#00FF41]/5'
        }`} 
      />

      {/* Anchor duplicate for cumulative risk section compatibility */}
      <div id="cumulative-risk-validation-section" className="sr-only" />

      {/* Header Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5 pb-6 border-b border-[#222]">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono text-[#FF3E00] bg-[#FF3E00]/15 px-2.5 py-0.5 border border-[#FF3E00]/40 uppercase font-black tracking-widest flex items-center gap-1.5">
              <Sliders className="w-3.5 h-3.5 text-[#FF3E00]" />
              SECURITY GOVERNANCE // RISK THRESHOLD
            </span>
            <span
              className={`text-[10px] font-mono px-2.5 py-0.5 border font-black uppercase flex items-center gap-1.5 ${
                isExceeded
                  ? 'bg-[#FF3E00]/25 border-[#FF3E00] text-[#FF3E00] animate-pulse'
                  : 'bg-[#00FF41]/10 border-[#00FF41]/40 text-[#00FF41]'
              }`}
            >
              {isExceeded ? (
                <>
                  <AlertOctagon className="w-3 h-3 text-[#FF3E00]" />
                  <span>ALERTA DISPARADO • LIMITE EXCEDIDO (+{delta} PTS)</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-3 h-3 text-[#00FF41]" />
                  <span>CONFORME COM A POLÍTICA (LIMITE {qualityGateLimit} PTS)</span>
                </>
              )}
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 border border-[#333] bg-[#141414] text-[#AAA] font-bold uppercase">
              CI/CD: {breakCiCdOnBreach ? (isExceeded ? 'EXIT 1 (BLOQUEADO)' : 'EXIT 0 (LIBERADO)') : 'AVISO (EXIT 0)'}
            </span>
          </div>

          <h2 className="text-2xl sm:text-3xl font-black uppercase tracking-tight text-white flex items-center gap-3">
            <span>'Risk Threshold' Configuration Panel</span>
          </h2>
          <p className="text-xs font-mono text-[#999] max-w-4xl leading-relaxed">
            Defina o <strong className="text-white">Limite Global de Risk Score (0 - 100)</strong> tolerado no workspace. Quando o índice cumulativo ultrapassar este teto, a plataforma <strong className="text-[#FF3E00]">dispara alertas automatizados</strong> (notificações visuais, áudio sintetizado e webhooks) e executa o <strong className="text-white">CI/CD Break com Exit Code 1</strong>, bloqueando publicações em produção e merge de Pull Requests.
          </p>
        </div>

        {/* Quick Jump Action Pills */}
        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          {onScrollToMitigations && (
            <button
              type="button"
              onClick={onScrollToMitigations}
              className="px-3 py-2 bg-[#121212] hover:bg-[#3366FF] hover:text-white text-white border border-[#3366FF]/40 font-mono text-xs uppercase tracking-wider flex items-center gap-1.5 transition-all cursor-pointer shadow-sm"
              title="Ir para sugestões de mitigação IA Gemini"
            >
              <Sparkles className="w-3.5 h-3.5 text-[#3366FF]" />
              <span>Mitigação IA &darr;</span>
            </button>
          )}

          {onScrollToHistory && (
            <button
              type="button"
              onClick={onScrollToHistory}
              className="px-3 py-2 bg-[#121212] hover:bg-[#FF3E00] hover:text-white text-white border border-[#333] font-mono text-xs uppercase tracking-wider flex items-center gap-1.5 transition-all cursor-pointer shadow-sm"
              title="Ver gráfico de tendência histórica dos últimos 10 scans"
            >
              <History className="w-3.5 h-3.5 text-[#FF3E00]" />
              <span>Trend dos 10 Scans &darr;</span>
            </button>
          )}

          {/* Sound Toggle */}
          <button
            type="button"
            onClick={() => {
              const next = !soundEnabled;
              setSoundEnabled(next);
              if (next) playAlertTone();
            }}
            className={`px-3 py-2 border font-mono text-xs uppercase tracking-wider flex items-center gap-1.5 transition-all cursor-pointer ${
              soundEnabled
                ? 'bg-[#FF3E00]/20 border-[#FF3E00] text-[#FF3E00]'
                : 'bg-[#141414] border-[#333] text-[#777] hover:text-white'
            }`}
            title={soundEnabled ? 'Alarme sonoro ativado (Web Audio)' : 'Alarme sonoro silenciado'}
          >
            {soundEnabled ? <Volume2 className="w-3.5 h-3.5" /> : <VolumeX className="w-3.5 h-3.5" />}
            <span>Áudio: {soundEnabled ? 'ON' : 'MUTE'}</span>
          </button>
        </div>
      </div>

      {/* Main 2-Column Grid: Left (Threshold Controls & Gauge) | Right (Automated Alert & CI/CD Break Trigger) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-7 items-start">
        {/* LEFT COLUMN: Global Risk Score Limit Controls */}
        <div className="lg:col-span-6 space-y-6">
          <div className="bg-[#050505] p-6 border border-[#222] space-y-5">
            <div className="flex items-center justify-between border-b border-[#1A1A1A] pb-3">
              <span className="text-xs font-black uppercase tracking-wider text-white flex items-center gap-2">
                <Sliders className="w-4 h-4 text-[#FF3E00]" />
                <span>Definição do Limite Global (Global Risk Score Limit)</span>
              </span>
              <span className="text-[10px] font-mono text-[#777]">ESCALA 0 - 100</span>
            </div>

            {/* Current vs Limit Comparison Pods */}
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3.5 bg-[#0A0A0A] border border-[#222]">
                <div className="text-[10px] font-mono uppercase text-[#777]">Risk Score Atual</div>
                <div className="flex items-baseline gap-1.5 pt-0.5">
                  <span
                    className={`text-3xl font-black font-mono ${
                      cumulativeRiskScore >= 75
                        ? 'text-[#FF3E00]'
                        : cumulativeRiskScore >= 50
                        ? 'text-[#FF7A00]'
                        : cumulativeRiskScore >= 25
                        ? 'text-[#EAB308]'
                        : 'text-[#00FF41]'
                    }`}
                  >
                    {cumulativeRiskScore}
                  </span>
                  <span className="text-xs font-mono text-[#555]">/ 100</span>
                </div>
                <div className="text-[9px] font-mono text-[#AAA] pt-0.5 uppercase tracking-wide">
                  Nível: {cumulativeRiskLevel}
                </div>
              </div>

              <div
                className={`p-3.5 border transition-all ${
                  isExceeded
                    ? 'bg-[#180300] border-[#FF3E00]/60'
                    : 'bg-[#001405] border-[#00FF41]/40'
                }`}
              >
                <div className="text-[10px] font-mono uppercase text-[#777]">Teto Configurado</div>
                <div className="flex items-baseline gap-1.5 pt-0.5">
                  <span className={`text-3xl font-black font-mono ${isExceeded ? 'text-[#FF3E00]' : 'text-[#00FF41]'}`}>
                    {qualityGateLimit}
                  </span>
                  <span className="text-xs font-mono text-[#555]">/ 100</span>
                </div>
                <div className="text-[9px] font-mono pt-0.5 uppercase font-bold">
                  {isExceeded ? (
                    <span className="text-[#FF3E00] flex items-center gap-1">
                      <AlertTriangle className="w-2.5 h-2.5 inline" /> +{delta} pts acima do limite
                    </span>
                  ) : (
                    <span className="text-[#00FF41] flex items-center gap-1">
                      <CheckCircle2 className="w-2.5 h-2.5 inline" /> {Math.abs(delta)} pts de margem
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Interactive Steppers + Direct Input + Range Slider */}
            <div className="space-y-4 pt-1">
              <label htmlFor="input-global-risk-limit" className="text-[10px] font-mono uppercase tracking-widest text-[#AAA] font-bold block">
                Ajustar Limite Máximo Tolerado:
              </label>

              {/* Stepper controls */}
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => onUpdateQualityGateLimit(qualityGateLimit - 5)}
                  className="w-10 h-10 bg-[#121212] hover:bg-[#FF3E00] hover:text-white text-white border border-[#333] flex items-center justify-center font-bold transition-all text-xs"
                  title="Diminuir teto em 5"
                >
                  -5
                </button>
                <button
                  type="button"
                  onClick={() => onUpdateQualityGateLimit(qualityGateLimit - 1)}
                  className="w-10 h-10 bg-[#121212] hover:bg-[#FF3E00] hover:text-white text-white border border-[#333] flex items-center justify-center font-bold transition-all"
                  title="Diminuir teto em 1"
                >
                  <Minus className="w-4 h-4" />
                </button>

                {/* Direct Number Input */}
                <div className="relative flex-1">
                  <input
                    id="input-global-risk-limit"
                    type="number"
                    min="0"
                    max="100"
                    value={qualityGateLimit}
                    onChange={(e) => {
                      const val = parseInt(e.target.value, 10);
                      if (!isNaN(val)) onUpdateQualityGateLimit(val);
                    }}
                    className="w-full h-10 bg-[#080808] border border-[#333] focus:border-[#FF3E00] text-center font-mono font-black text-xl text-white outline-none px-3"
                  />
                  <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] font-mono text-[#666] pointer-events-none">
                    PTS
                  </span>
                </div>

                <button
                  type="button"
                  onClick={() => onUpdateQualityGateLimit(qualityGateLimit + 1)}
                  className="w-10 h-10 bg-[#121212] hover:bg-[#FF3E00] hover:text-white text-white border border-[#333] flex items-center justify-center font-bold transition-all"
                  title="Aumentar teto em 1"
                >
                  <Plus className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  onClick={() => onUpdateQualityGateLimit(qualityGateLimit + 5)}
                  className="w-10 h-10 bg-[#121212] hover:bg-[#FF3E00] hover:text-white text-white border border-[#333] flex items-center justify-center font-bold transition-all text-xs"
                  title="Aumentar teto em 5"
                >
                  +5
                </button>

                <button
                  type="button"
                  onClick={() => onUpdateQualityGateLimit(50)}
                  className="h-10 px-3 bg-[#111] hover:bg-[#222] border border-[#333] text-[#888] hover:text-white text-[10px] font-mono uppercase tracking-wider flex items-center gap-1 transition-all"
                  title="Restaurar padrão corporativo (50)"
                >
                  <RotateCcw className="w-3 h-3" />
                  <span className="hidden sm:inline">Reset</span>
                </button>
              </div>

              {/* Visual Range Slider with Current Score Marker */}
              <div className="space-y-2 pt-2">
                <div className="relative w-full h-4 bg-[#141414] border border-[#333] overflow-visible">
                  {/* Color Zones */}
                  <div className="absolute inset-0 flex">
                    <div className="w-1/4 h-full bg-[#00FF41]/20 border-r border-[#333]" title="Zona Mínima: 0-25" />
                    <div className="w-1/4 h-full bg-[#3366FF]/20 border-r border-[#333]" title="Zona Baixa: 25-50" />
                    <div className="w-1/4 h-full bg-[#EAB308]/20 border-r border-[#333]" title="Zona Média: 50-75" />
                    <div className="w-1/4 h-full bg-[#FF3E00]/20" title="Zona Crítica: 75-100" />
                  </div>

                  {/* Active fill up to current threshold limit */}
                  <div
                    className="absolute top-0 bottom-0 bg-[#FF3E00]/40 border-r-2 border-[#FF3E00] transition-all"
                    style={{ width: `${Math.min(100, Math.max(0, qualityGateLimit))}%` }}
                  />

                  {/* Marker for Current Score */}
                  <div
                    className="absolute -top-1.5 -bottom-1.5 w-1 bg-white shadow-[0_0_10px_#FFFFFF] z-20"
                    style={{ left: `${Math.min(99, Math.max(1, cumulativeRiskScore))}%` }}
                    title={`Score Atual: ${cumulativeRiskScore}`}
                  >
                    <div className="absolute -top-4 -translate-x-1/2 text-[8px] font-mono font-black text-white bg-black px-1 border border-white whitespace-nowrap">
                      ATUAL: {cumulativeRiskScore}
                    </div>
                  </div>

                  {/* HTML Range Slider Overlay */}
                  <input
                    type="range"
                    min="0"
                    max="100"
                    step="1"
                    value={qualityGateLimit}
                    onChange={(e) => onUpdateQualityGateLimit(Number(e.target.value))}
                    className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-30"
                  />
                </div>

                <div className="flex justify-between text-[9px] font-mono text-[#666]">
                  <span className="text-[#00FF41]">0 Tolerância Zero</span>
                  <span className="text-[#3366FF]">25 Rigoroso</span>
                  <span className="text-[#EAB308]">50 Padrão</span>
                  <span className="text-[#FF7A00]">75 Permissivo</span>
                  <span className="text-[#FF3E00]">100 Crítico</span>
                </div>
              </div>
            </div>

            {/* Quick Governance Presets */}
            <div className="space-y-2 pt-2 border-t border-[#1A1A1A]">
              <div className="text-[10px] font-mono text-[#AAA] uppercase font-bold">
                Políticas de Segurança Pré-configuradas (1-Clique):
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {presets.map((p) => {
                  const isSelected = qualityGateLimit === p.val;
                  return (
                    <button
                      key={p.val}
                      type="button"
                      onClick={() => onUpdateQualityGateLimit(p.val)}
                      className={`p-2.5 border text-left font-mono transition-all ${
                        isSelected
                          ? 'border-[#FF3E00] bg-[#FF3E00]/15 text-white shadow-[0_0_12px_rgba(255,62,0,0.2)]'
                          : 'border-[#222] bg-[#0A0A0A] text-[#888] hover:border-[#444] hover:text-white'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className={`text-xs font-black ${isSelected ? 'text-[#FF3E00]' : 'text-white'}`}>
                          {p.label} pts
                        </span>
                        {isSelected && <Check className="w-3 h-3 text-[#FF3E00]" />}
                      </div>
                      <div className="text-[9px] font-bold uppercase text-[#DDD] pt-0.5 truncate">{p.name}</div>
                      <div className="text-[8px] text-[#666] truncate">{p.desc}</div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Current Score Severity Points Breakdown */}
            <div className="p-3 bg-[#080808] border border-[#1A1A1A] space-y-2 font-mono text-xs">
              <div className="flex items-center justify-between text-[10px] text-[#777] uppercase font-bold">
                <span>Composição dos Pontos Atuais:</span>
                <span className="text-white">{metrics.workspaceRiskBreakdown?.rawPoints ?? 0} pts brutos</span>
              </div>
              <div className="grid grid-cols-5 gap-1 text-[10px] text-center">
                <div className="p-1 bg-[#140400] border border-[#FF3E00]/30 text-[#FF3E00]">
                  <div className="font-bold">{metrics.criticalCount} Críticos</div>
                  <div className="text-[8px] text-[#888]">{metrics.criticalCount * 25} pts</div>
                </div>
                <div className="p-1 bg-[#140800] border border-[#FF7A00]/30 text-[#FF7A00]">
                  <div className="font-bold">{metrics.highCount} Altos</div>
                  <div className="text-[8px] text-[#888]">{metrics.highCount * 15} pts</div>
                </div>
                <div className="p-1 bg-[#120F00] border border-[#EAB308]/30 text-[#EAB308]">
                  <div className="font-bold">{metrics.mediumCount} Médios</div>
                  <div className="text-[8px] text-[#888]">{metrics.mediumCount * 6} pts</div>
                </div>
                <div className="p-1 bg-[#000E1C] border border-[#3366FF]/30 text-[#3366FF]">
                  <div className="font-bold">{metrics.lowCount} Baixos</div>
                  <div className="text-[8px] text-[#888]">{metrics.lowCount * 2} pts</div>
                </div>
                <div className="p-1 bg-[#0A0A0A] border border-[#333] text-[#AAA]">
                  <div className="font-bold">{metrics.infoCount} Info</div>
                  <div className="text-[8px] text-[#888]">{metrics.infoCount * 0.5} pts</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: Automated Alert & CI/CD Break Trigger Tabs */}
        <div className="lg:col-span-6 space-y-5">
          {/* Tab Selection Header */}
          <div className="flex items-center gap-1 border-b border-[#222] pb-2">
            <button
              type="button"
              onClick={() => setActiveTab('cicd')}
              className={`px-3.5 py-2 font-mono text-xs font-bold uppercase tracking-wider flex items-center gap-2 border transition-all cursor-pointer ${
                activeTab === 'cicd'
                  ? 'bg-[#FF3E00] text-white border-[#FF3E00]'
                  : 'bg-[#0E0E0E] text-[#888] border-[#222] hover:text-white'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>CI/CD Break Trigger</span>
              {breakCiCdOnBreach && isExceeded && (
                <span className="w-2 h-2 rounded-full bg-white animate-ping" />
              )}
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('alert')}
              className={`px-3.5 py-2 font-mono text-xs font-bold uppercase tracking-wider flex items-center gap-2 border transition-all cursor-pointer ${
                activeTab === 'alert'
                  ? 'bg-[#FF3E00] text-white border-[#FF3E00]'
                  : 'bg-[#0E0E0E] text-[#888] border-[#222] hover:text-white'
              }`}
            >
              <Bell className="w-3.5 h-3.5" />
              <span>Automated Alert Trigger</span>
              {isExceeded && (
                <span className="w-2 h-2 rounded-full bg-yellow-400 animate-ping" />
              )}
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('snippets')}
              className={`px-3.5 py-2 font-mono text-xs font-bold uppercase tracking-wider flex items-center gap-2 border transition-all cursor-pointer ${
                activeTab === 'snippets'
                  ? 'bg-[#FF3E00] text-white border-[#FF3E00]'
                  : 'bg-[#0E0E0E] text-[#888] border-[#222] hover:text-white'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>Pipeline Snippets</span>
            </button>
          </div>

          {/* TAB 1: CI/CD BREAK TRIGGER & INTERACTIVE PIPELINE SIMULATOR */}
          {activeTab === 'cicd' && (
            <div className="bg-[#050505] p-6 border border-[#222] space-y-5">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-xs font-black uppercase tracking-wider text-white flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-[#FF3E00]" />
                    <span>Regras do CI/CD Breaker (Exit Code Automation)</span>
                  </div>
                  <div className="text-[10px] font-mono text-[#777] pt-0.5">
                    Bloqueio automatizado de commits e builds de produção quando o threshold é violado
                  </div>
                </div>
                <div
                  className={`px-2.5 py-1 text-[10px] font-mono font-black uppercase border ${
                    isExceeded
                      ? 'bg-[#FF3E00]/20 border-[#FF3E00] text-[#FF3E00] animate-pulse'
                      : 'bg-[#00FF41]/15 border-[#00FF41] text-[#00FF41]'
                  }`}
                >
                  {isExceeded ? 'PIPELINE BLOQUEADO (EXIT 1)' : 'PIPELINE APROVADO (EXIT 0)'}
                </div>
              </div>

              {/* Policy Toggles */}
              <div className="space-y-2.5">
                <label className="flex items-start gap-3 p-3 bg-[#0A0A0A] border border-[#222] cursor-pointer hover:border-[#333] transition-colors">
                  <input
                    type="checkbox"
                    checked={breakCiCdOnBreach}
                    onChange={(e) => setBreakCiCdOnBreach(e.target.checked)}
                    className="mt-0.5 w-4 h-4 accent-[#FF3E00] cursor-pointer"
                  />
                  <div className="text-xs font-mono">
                    <strong className="text-white block">Fail CI/CD Pipeline on Breach (Exit Code 1)</strong>
                    <span className="text-[11px] text-[#888]">
                      Interrompe instantaneamente jobs do GitHub Actions, GitLab CI ou Jenkins ao detectar que o score ({cumulativeRiskScore}) ultrapassou o teto ({qualityGateLimit}).
                    </span>
                  </div>
                </label>

                <label className="flex items-start gap-3 p-3 bg-[#0A0A0A] border border-[#222] cursor-pointer hover:border-[#333] transition-colors">
                  <input
                    type="checkbox"
                    checked={blockPrMerge}
                    onChange={(e) => setBlockPrMerge(e.target.checked)}
                    className="mt-0.5 w-4 h-4 accent-[#FF3E00] cursor-pointer"
                  />
                  <div className="text-xs font-mono">
                    <strong className="text-white block">Bloqueio Estrito de Pull Request / Merge Gatekeeper</strong>
                    <span className="text-[11px] text-[#888]">
                      Marca os status checks de branch protection como com falha, impedindo aprovação de merge em branches protegidas.
                    </span>
                  </div>
                </label>
              </div>

              {/* Interactive CI/CD Simulator Box */}
              <div className="space-y-3 pt-1">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-[#AAA] uppercase font-bold flex items-center gap-1.5">
                    <Play className="w-3 h-3 text-[#00FF41]" />
                    Simulador Interativo de Execução do Pipeline CI/CD:
                  </span>
                  <button
                    type="button"
                    onClick={handleRunCiCdSimulation}
                    disabled={isSimulatingCiCd}
                    className="px-3 py-1.5 bg-[#FF3E00] hover:bg-[#E03500] text-white font-mono text-[11px] font-black uppercase tracking-wider flex items-center gap-1.5 transition-all disabled:opacity-50 cursor-pointer shadow-[0_0_15px_rgba(255,62,0,0.3)]"
                  >
                    <Play className="w-3 h-3 fill-current" />
                    <span>{isSimulatingCiCd ? 'Executando Análise...' : 'Simular Pipeline CI/CD'}</span>
                  </button>
                </div>

                {/* Console Log Terminal */}
                <div className="bg-[#030303] border border-[#262626] p-4 font-mono text-xs text-[#CCC] space-y-1.5 min-h-[160px] max-h-[220px] overflow-y-auto relative">
                  <div className="flex items-center justify-between pb-2 border-b border-[#1A1A1A] text-[10px] text-[#666]">
                    <span className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-[#FF3E00]" />
                      <span className="w-2 h-2 rounded-full bg-[#EAB308]" />
                      <span className="w-2 h-2 rounded-full bg-[#00FF41]" />
                      <span className="ml-2 text-[#888]">secscan-runner-ci-cd-simulator.log</span>
                    </span>
                    <span>bash • node 20.x</span>
                  </div>

                  {simulationLogs.length === 0 ? (
                    <div className="text-[#666] py-6 text-center italic">
                      Clique em "Simular Pipeline CI/CD" acima para testar o comportamento do Quality Gate com o teto atual ({qualityGateLimit} pts).
                    </div>
                  ) : (
                    simulationLogs.map((log, idx) => (
                      <div
                        key={idx}
                        className={`text-[11px] leading-relaxed font-mono ${
                          log.includes('❌') || log.includes('FAILED') || log.includes('BREACH')
                            ? 'text-[#FF3E00] font-bold'
                            : log.includes('✅') || log.includes('PASSED') || log.includes('SUCCESS')
                            ? 'text-[#00FF41] font-bold'
                            : log.includes('🚨')
                            ? 'text-[#FF7A00]'
                            : 'text-[#BBB]'
                        }`}
                      >
                        {log}
                      </div>
                    ))
                  )}

                  {simulationFinished && (
                    <div className="pt-2 border-t border-[#222] flex items-center justify-between text-[11px]">
                      <span className="font-bold">
                        Resultado: {simulationPassed ? (
                          <span className="text-[#00FF41]">PASS (Exit Code 0)</span>
                        ) : (
                          <span className="text-[#FF3E00]">BUILD BREAK TRIGGERED (Exit Code 1)</span>
                        )}
                      </span>
                      <span className="text-[10px] text-[#666]">
                        {isExceeded
                          ? 'Comportamento de contenção verificado com sucesso.'
                          : 'Ambiente aprovado para deploy.'}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* CLI Command Quick Copy */}
              <div className="p-3 bg-[#080808] border border-[#1A1A1A] flex items-center justify-between gap-3 font-mono text-xs">
                <div className="truncate">
                  <span className="text-[10px] text-[#777] block uppercase">Comando exato para pipelines:</span>
                  <code className="text-[#00FF41] text-[11px]">node bin/secscan.js . --max-risk {qualityGateLimit}</code>
                </div>
                <button
                  type="button"
                  onClick={() => copyToClipboard(`node bin/secscan.js . --max-risk ${qualityGateLimit}`, 'cli-cmd')}
                  className="px-2.5 py-1.5 bg-[#141414] hover:bg-[#FF3E00] hover:text-white text-[#CCC] border border-[#333] transition-all flex items-center gap-1 text-[10px] shrink-0 font-bold"
                >
                  {copiedKey === 'cli-cmd' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedKey === 'cli-cmd' ? 'Copiado' : 'Copiar'}</span>
                </button>
              </div>
            </div>
          )}

          {/* TAB 2: AUTOMATED ALERT TRIGGER & WEBHOOKS */}
          {activeTab === 'alert' && (
            <div className="bg-[#050505] p-6 border border-[#222] space-y-5">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-xs font-black uppercase tracking-wider text-white flex items-center gap-2">
                    <BellRing className="w-4 h-4 text-[#FF3E00]" />
                    <span>Disparo Automatizado de Alertas (Webhooks & Notificações)</span>
                  </div>
                  <div className="text-[10px] font-mono text-[#777] pt-0.5">
                    Notifique canais DevSecOps automaticamente quando o Risk Score ultrapassar o teto
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleTestAlertDispatch}
                  disabled={isDispatchingAlert}
                  className="px-3 py-1.5 bg-[#141414] hover:bg-[#FF3E00] hover:text-white text-white border border-[#333] font-mono text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all disabled:opacity-50 cursor-pointer"
                >
                  <Send className="w-3 h-3" />
                  <span>{isDispatchingAlert ? 'Disparando...' : 'Testar Alerta'}</span>
                </button>
              </div>

              {/* Alert Channel & Webhook URL */}
              <div className="space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="text-[10px] font-mono uppercase text-[#AAA] font-bold block mb-1">
                      Canal de Notificação:
                    </label>
                    <select
                      value={alertChannel}
                      onChange={(e) => setAlertChannel(e.target.value as any)}
                      className="w-full h-9 bg-[#0C0C0C] border border-[#333] text-white font-mono text-xs px-2.5 outline-none focus:border-[#FF3E00]"
                    >
                      <option value="slack">Slack Incoming Webhook</option>
                      <option value="discord">Discord Security Webhook</option>
                      <option value="pagerduty">PagerDuty Event API v2</option>
                      <option value="teams">Microsoft Teams Connector</option>
                      <option value="custom">Generic JSON Webhook Endpoint</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[10px] font-mono uppercase text-[#AAA] font-bold block mb-1">
                      Status do Gatilho Atual:
                    </label>
                    <div
                      className={`h-9 px-3 flex items-center justify-between border font-mono text-xs font-bold ${
                        isExceeded
                          ? 'bg-[#1A0400] border-[#FF3E00]/60 text-[#FF3E00]'
                          : 'bg-[#001405] border-[#00FF41]/40 text-[#00FF41]'
                      }`}
                    >
                      <span>{isExceeded ? 'ALERTA ATIVO' : 'NOMINAL (SEM ALERTA)'}</span>
                      <span className="text-[10px] text-[#AAA]">{isExceeded ? `+${delta} pts excesso` : 'Dentro do teto'}</span>
                    </div>
                  </div>
                </div>

                <div>
                  <label className="text-[10px] font-mono uppercase text-[#AAA] font-bold block mb-1">
                    URL do Endpoint de Webhook:
                  </label>
                  <input
                    type="text"
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                    placeholder="https://hooks.slack.com/services/..."
                    className="w-full h-9 bg-[#0C0C0C] border border-[#333] text-white font-mono text-xs px-3 outline-none focus:border-[#FF3E00]"
                  />
                </div>
              </div>

              {/* Webhook JSON Payload Preview */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[10px] font-mono text-[#888]">
                  <span>PAYLOAD JSON ENVIADO AO DISPARAR:</span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(webhookPayload, 'payload-json')}
                    className="hover:text-white flex items-center gap-1"
                  >
                    {copiedKey === 'payload-json' ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === 'payload-json' ? 'Copiado' : 'Copiar Payload'}</span>
                  </button>
                </div>
                <pre className="bg-[#030303] border border-[#222] p-3 text-[10px] font-mono text-[#00FF41] max-h-36 overflow-y-auto leading-relaxed">
                  {webhookPayload}
                </pre>
              </div>

              {/* Trigger Events History */}
              <div className="space-y-2 pt-1 border-t border-[#1A1A1A]">
                <div className="text-[10px] font-mono text-[#AAA] uppercase font-bold flex items-center justify-between">
                  <span>Log de Disparos de Alerta Recentes:</span>
                  {lastDispatchedTime && (
                    <span className="text-[#00FF41]">Último disparo: {lastDispatchedTime}</span>
                  )}
                </div>
                <div className="space-y-1.5">
                  {triggerEvents.map((evt) => (
                    <div
                      key={evt.id}
                      className="p-2 bg-[#080808] border border-[#1A1A1A] flex items-center justify-between gap-2 font-mono text-[11px]"
                    >
                      <div className="flex items-center gap-2 truncate">
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            evt.status === 'EXCEEDED' ? 'bg-[#FF3E00]' : 'bg-[#00FF41]'
                          }`}
                        />
                        <span className="text-[#666]">{evt.timestamp}</span>
                        <span className="text-white truncate">{evt.action}</span>
                      </div>
                      <span className="text-[10px] text-[#888] shrink-0">{evt.channel}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: CI/CD PIPELINE WORKFLOW SNIPPETS */}
          {activeTab === 'snippets' && (
            <div className="bg-[#050505] p-6 border border-[#222] space-y-5">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-xs font-black uppercase tracking-wider text-white flex items-center gap-2">
                    <Code2 className="w-4 h-4 text-[#FF3E00]" />
                    <span>Snippets Prontos para CI/CD (GitHub, GitLab, Jenkins)</span>
                  </div>
                  <div className="text-[10px] font-mono text-[#777] pt-0.5">
                    Copie e cole nos seus arquivos de pipeline para impor o teto de {qualityGateLimit} pts
                  </div>
                </div>
              </div>

              {/* Selector Pills */}
              <div className="grid grid-cols-4 gap-2">
                {[
                  { id: 'github', label: 'GitHub Actions' },
                  { id: 'gitlab', label: 'GitLab CI' },
                  { id: 'jenkins', label: 'Jenkins' },
                  { id: 'precommit', label: 'Pre-push Hook' }
                ].map((snip) => (
                  <button
                    key={snip.id}
                    type="button"
                    onClick={() => setSelectedSnippet(snip.id as any)}
                    className={`p-2 font-mono text-center text-xs font-bold border transition-all ${
                      selectedSnippet === snip.id
                        ? 'bg-[#FF3E00] text-white border-[#FF3E00]'
                        : 'bg-[#0E0E0E] text-[#888] border-[#222] hover:text-white hover:border-[#444]'
                    }`}
                  >
                    {snip.label}
                  </button>
                ))}
              </div>

              {/* Snippet Code Viewer */}
              <div className="relative">
                <pre className="bg-[#030303] border border-[#262626] p-4 text-[11px] font-mono text-[#DDD] overflow-x-auto max-h-64 leading-relaxed">
                  {codeSnippets[selectedSnippet]}
                </pre>
                <button
                  type="button"
                  onClick={() => copyToClipboard(codeSnippets[selectedSnippet], `snippet-${selectedSnippet}`)}
                  className="absolute top-2.5 right-2.5 px-3 py-1.5 bg-[#1A1A1A] hover:bg-[#FF3E00] hover:text-white text-white border border-[#333] text-[10px] font-mono font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all shadow-md"
                >
                  {copiedKey === `snippet-${selectedSnippet}` ? (
                    <Check className="w-3.5 h-3.5 text-[#00FF41]" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                  <span>{copiedKey === `snippet-${selectedSnippet}` ? 'Copiado!' : 'Copiar Código'}</span>
                </button>
              </div>

              <div className="p-3 bg-[#0A0A0A] border border-[#1A1A1A] text-[11px] font-mono text-[#888] flex items-center gap-2">
                <Info className="w-4 h-4 text-[#FF3E00] shrink-0" />
                <span>
                  O argumento <code className="text-white bg-[#141414] px-1 py-0.5">--max-risk {qualityGateLimit}</code> faz o comando <code className="text-[#00FF41]">secscan</code> retornar automaticamente <code className="text-[#FF3E00]">exit code 1</code> caso o Risk Score do repositório supere o valor configurado.
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
