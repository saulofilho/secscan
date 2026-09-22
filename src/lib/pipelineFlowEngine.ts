import { ScanFinding, SeverityLevel, ScannedFile } from '../types';

export type PipelineStageId = 'pre-commit' | 'build' | 'deploy';

export interface PipelineActionStep {
  id: string;
  name: string;
  stage: PipelineStageId;
  type: 'secret' | 'sast' | 'sca' | 'sbom' | 'dast' | 'container' | 'iac' | 'lint' | 'custom';
  enabled: boolean;
  uses?: string;
  run?: string;
  failOnSeverity: SeverityLevel | 'NONE';
  continueOnError?: boolean;
  timeoutMinutes?: number;
  description: string;
  badge?: string;
}

export interface PipelineStageConfig {
  id: PipelineStageId;
  title: string;
  subtitle: string;
  environment: string;
  failThreshold: SeverityLevel;
  blockPipelineOnBreach: boolean;
  customShellScript?: string;
}

export interface PipelineArchitectConfig {
  workflowName: string;
  fileName: string;
  triggerPush: boolean;
  triggerPullRequest: boolean;
  triggerSchedule: boolean;
  triggerWorkflowDispatch: boolean;
  branches: string[];
  runner: string;
  nodeVersion: string;
  uploadSarif: boolean;
  concurrencyGroup: boolean;
  stages: Record<PipelineStageId, PipelineStageConfig>;
  steps: PipelineActionStep[];
  findingStageMapping: Record<string, PipelineStageId>; // finding.id -> stageId
}

export interface StageSimulationResult {
  stageId: PipelineStageId;
  stageTitle: string;
  status: 'PENDING' | 'RUNNING' | 'PASSED' | 'FAILED' | 'SKIPPED';
  durationSeconds: number;
  evaluatedFindingsCount: number;
  breachingFindings: ScanFinding[];
  logs: { timestamp: string; level: 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS'; message: string }[];
}

export interface PipelineSimulationReport {
  timestamp: string;
  overallStatus: 'PASSED' | 'FAILED';
  totalDurationSeconds: number;
  stageResults: Record<PipelineStageId, StageSimulationResult>;
  summary: string;
}

export const DEFAULT_PIPELINE_STAGES: Record<PipelineStageId, PipelineStageConfig> = {
  'pre-commit': {
    id: 'pre-commit',
    title: 'Pre-commit (Shift-Left)',
    subtitle: 'Validação local & git hook antes do push',
    environment: 'Local / Husky Git Hook / PR Fast-Gate',
    failThreshold: 'HIGH',
    blockPipelineOnBreach: true,
  },
  'build': {
    id: 'build',
    title: 'Build & CI Security Gate',
    subtitle: 'Análise SAST estática, SCA e compilação',
    environment: 'GitHub Actions Hosted Runner (ubuntu-latest)',
    failThreshold: 'HIGH',
    blockPipelineOnBreach: true,
  },
  'deploy': {
    id: 'deploy',
    title: 'Deploy & CD Verification',
    subtitle: 'DAST API Fuzzing, Container & Cloud Gate',
    environment: 'Staging / Production Deployment Gate',
    failThreshold: 'CRITICAL',
    blockPipelineOnBreach: true,
  },
};

export const INITIAL_ACTION_STEPS: PipelineActionStep[] = [
  {
    id: 'step-secret-scan',
    name: 'Secret & High-Entropy Token Scan',
    stage: 'pre-commit',
    type: 'secret',
    enabled: true,
    run: 'node bin/secscan.js . --stage pre-commit --fail-on high --entropy-threshold 3.8',
    failOnSeverity: 'HIGH',
    description: 'Bloqueia credenciais, chaves AWS/GCP e tokens privados antes de entrar no Git',
    badge: 'Shift-Left'
  },
  {
    id: 'step-git-hygiene',
    name: 'Git History & .gitignore Audit',
    stage: 'pre-commit',
    type: 'lint',
    enabled: true,
    run: 'node bin/secscan.js --audit-gitignore --verify-tracked-secrets',
    failOnSeverity: 'HIGH',
    description: 'Verifica arquivos sensíveis rastreados (.env, id_rsa, *.pem) no Git staged index',
    badge: 'Hygiene'
  },
  {
    id: 'step-sast-dataflow',
    name: 'SecScan Deep SAST & Taint Dataflow',
    stage: 'build',
    type: 'sast',
    enabled: true,
    run: 'node bin/secscan.js . --format sarif --output secscan-sast.sarif --taint-analysis',
    failOnSeverity: 'HIGH',
    description: 'Rastreia fluxo de entrada inseguro (Source ➔ Sanitizer ➔ Sink) e injeções SQL/XSS',
    badge: 'SAST'
  },
  {
    id: 'step-sca-deps',
    name: 'SCA Dependency & CVE Vulnerability Audit',
    stage: 'build',
    type: 'sca',
    enabled: true,
    run: 'npm audit --audit-level=high || node bin/secscan.js --audit-sca package.json',
    failOnSeverity: 'HIGH',
    description: 'Cruza dependências contra base NVD/OSV e analisa riscos de licenças copyleft',
    badge: 'SCA'
  },
  {
    id: 'step-cyclonedx-sbom',
    name: 'CycloneDX v1.5 SBOM Inventory Generation',
    stage: 'build',
    type: 'sbom',
    enabled: true,
    run: 'node bin/secscan.js --generate-sbom --format cyclonedx-json --output dist/sbom.json',
    failOnSeverity: 'NONE',
    continueOnError: true,
    description: 'Gera inventário de software rastreável compatível com conformidade executiva (EO 14028)',
    badge: 'SBOM'
  },
  {
    id: 'step-sarif-upload',
    name: 'Upload SARIF to GitHub Security Tab',
    stage: 'build',
    type: 'sast',
    enabled: true,
    uses: 'github/codeql-action/upload-sarif@v3',
    failOnSeverity: 'NONE',
    continueOnError: true,
    description: 'Publica alertas e rastreabilidade na aba Security do repositório GitHub',
    badge: 'GitHub SARIF'
  },
  {
    id: 'step-container-cis',
    name: 'Container Image & CIS Benchmark Scan',
    stage: 'deploy',
    type: 'container',
    enabled: true,
    run: 'node bin/secscan.js --scan-dockerfile Dockerfile --enforce-nonroot',
    failOnSeverity: 'CRITICAL',
    description: 'Valida execução sem root, ausência de pacotes vulneráveis na imagem base e portas expostas',
    badge: 'CIS Docker'
  },
  {
    id: 'step-dast-fuzz',
    name: 'DAST API Security & BOLA Endpoint Fuzzer',
    stage: 'deploy',
    type: 'dast',
    enabled: true,
    run: 'node bin/secscan.js --fuzz-endpoints --target-url https://staging.internal.net --fail-on critical',
    failOnSeverity: 'CRITICAL',
    description: 'Executa testes dinâmicos de injeção em endpoints REST mapeados e valida headers CSP/HSTS',
    badge: 'DAST'
  },
  {
    id: 'step-cloud-iam-gate',
    name: 'Cloud IAM & SSRF Least-Privilege Gate',
    stage: 'deploy',
    type: 'iac',
    enabled: true,
    run: 'node bin/secscan.js --verify-iam-policies --check-ssrf-metadata',
    failOnSeverity: 'CRITICAL',
    description: 'Garante que os recursos de nuvem não possuem permissões curinga (iam:*) ou metadados desprotegidos',
    badge: 'IAM Gate'
  }
];

export const PIPELINE_PRESETS: {
  id: string;
  name: string;
  description: string;
  badge: string;
  stages: Record<PipelineStageId, Partial<PipelineStageConfig>>;
  steps: PipelineActionStep[];
}[] = [
  {
    id: 'zero-trust',
    name: 'Zero Trust DevSecOps (Strict Gates)',
    description: 'Máxima proteção: Falhas no Pre-commit para segredos, bloqueio estrito no Build e validação DAST rigorosa antes do Deploy.',
    badge: 'FIPS / SOC2',
    stages: {
      'pre-commit': { failThreshold: 'HIGH', blockPipelineOnBreach: true },
      'build': { failThreshold: 'HIGH', blockPipelineOnBreach: true },
      'deploy': { failThreshold: 'CRITICAL', blockPipelineOnBreach: true },
    },
    steps: INITIAL_ACTION_STEPS.map(s => ({ ...s, enabled: true }))
  },
  {
    id: 'pr-velocity',
    name: 'Agile PR Guard (Fast Feedback)',
    description: 'Focado em velocidade: Pre-commit apenas para chaves críticas, SAST condensado no Build sem travar deploy.',
    badge: 'Fast PR',
    stages: {
      'pre-commit': { failThreshold: 'CRITICAL', blockPipelineOnBreach: true },
      'build': { failThreshold: 'CRITICAL', blockPipelineOnBreach: false },
      'deploy': { failThreshold: 'CRITICAL', blockPipelineOnBreach: false },
    },
    steps: INITIAL_ACTION_STEPS.map(s => ({
      ...s,
      enabled: s.id === 'step-secret-scan' || s.id === 'step-sast-dataflow' || s.id === 'step-sarif-upload'
    }))
  },
  {
    id: 'cloud-native',
    name: 'Cloud Native & Kubernetes Hardened',
    description: 'Prioriza segurança de contêineres Docker, políticas de nuvem AWS/GCP, varredura de IaC e inventário SBOM completo.',
    badge: 'K8s / CIS',
    stages: {
      'pre-commit': { failThreshold: 'HIGH', blockPipelineOnBreach: true },
      'build': { failThreshold: 'HIGH', blockPipelineOnBreach: true },
      'deploy': { failThreshold: 'HIGH', blockPipelineOnBreach: true },
    },
    steps: INITIAL_ACTION_STEPS.map(s => ({
      ...s,
      enabled: s.id !== 'step-dast-fuzz' || true
    }))
  }
];

/**
 * Automatically categorizes a local scan finding to a recommended pipeline stage
 */
export function autoCategorizeFindingToStage(finding: ScanFinding): PipelineStageId {
  const cat = (finding.category || '').toUpperCase();
  const rule = (finding.ruleName || '').toLowerCase();
  const file = (finding.file || '').toLowerCase();

  // Pre-commit: Secrets, Credentials, Tokens, High Entropy, Gitignore
  if (
    cat.includes('SECRET') ||
    cat.includes('KEY') ||
    cat.includes('TOKEN') ||
    cat.includes('CREDENTIAL') ||
    rule.includes('secret') ||
    rule.includes('token') ||
    rule.includes('password') ||
    rule.includes('api key') ||
    rule.includes('private key') ||
    file.includes('.env') ||
    finding.entropy >= 4.0
  ) {
    return 'pre-commit';
  }

  // Deploy: Endpoints, DAST, Container, Docker, K8s, Cloud, IAM, SSRF, Headers, WAF
  if (
    cat.includes('API') ||
    cat.includes('DAST') ||
    cat.includes('CONTAINER') ||
    cat.includes('DOCKER') ||
    cat.includes('KUBERNETES') ||
    cat.includes('CLOUD') ||
    cat.includes('IAM') ||
    cat.includes('SSRF') ||
    cat.includes('HEADER') ||
    rule.includes('docker') ||
    rule.includes('endpoint') ||
    rule.includes('ssrf') ||
    rule.includes('cors') ||
    rule.includes('header') ||
    file.includes('dockerfile') ||
    file.endsWith('.yaml') ||
    file.endsWith('.yml')
  ) {
    return 'deploy';
  }

  // Build: Default for SAST, Taint, SCA, Code Logic, Obsolete Crypto, XSS, SQLi
  return 'build';
}

/**
 * Builds the initial finding-to-stage mapping for a set of findings
 */
export function buildInitialFindingStageMapping(findings: ScanFinding[]): Record<string, PipelineStageId> {
  const mapping: Record<string, PipelineStageId> = {};
  findings.forEach(f => {
    mapping[f.id] = autoCategorizeFindingToStage(f);
  });
  return mapping;
}

/**
 * Generates the clean, production-ready GitHub Actions YAML workflow
 */
export function generateGitHubActionsWorkflowYaml(
  config: PipelineArchitectConfig,
  findings: ScanFinding[]
): string {
  const branchesFormatted = config.branches.map(b => `      - "${b}"`).join('\n');

  // Group steps by stage
  const preCommitSteps = config.steps.filter(s => s.stage === 'pre-commit' && s.enabled);
  const buildSteps = config.steps.filter(s => s.stage === 'build' && s.enabled);
  const deploySteps = config.steps.filter(s => s.stage === 'deploy' && s.enabled);

  // Mapped findings count per stage
  const findingsByStage: Record<PipelineStageId, ScanFinding[]> = {
    'pre-commit': [],
    'build': [],
    'deploy': []
  };

  findings.forEach(f => {
    const stage = config.findingStageMapping[f.id] || autoCategorizeFindingToStage(f);
    findingsByStage[stage].push(f);
  });

  const renderStepsYaml = (steps: PipelineActionStep[], stageId: PipelineStageId): string => {
    if (steps.length === 0) {
      return `      - name: ℹ️ Stage ${stageId} Placeholder
        run: echo "Nenhuma ação ativa configurada para o estágio ${stageId}."`;
    }

    return steps.map(step => {
      const lines: string[] = [];
      lines.push(`      - name: ${step.name}`);
      if (step.uses) {
        lines.push(`        uses: ${step.uses}`);
      }
      if (step.continueOnError) {
        lines.push(`        continue-on-error: true`);
      }
      if (step.run) {
        const runLines = step.run.split('\n');
        if (runLines.length === 1) {
          lines.push(`        run: ${step.run}`);
        } else {
          lines.push(`        run: |`);
          runLines.forEach(rl => lines.push(`          ${rl}`));
        }
      }
      return lines.join('\n');
    }).join('\n\n');
  };

  const yaml = `# ====================================================================
# SECSCAN DEVSECOPS PIPELINE FLOW ARCHITECT
# Auto-generated by SecScan Suite - Pipeline Flow Visualizer
# Date: ${new Date().toISOString()}
# Mapped Findings: Pre-commit: ${findingsByStage['pre-commit'].length} | Build: ${findingsByStage['build'].length} | Deploy: ${findingsByStage['deploy'].length}
# ====================================================================

name: "${config.workflowName}"

on:
${config.triggerPush ? `  push:
    branches:
${branchesFormatted}` : ''}
${config.triggerPullRequest ? `  pull_request:
    branches:
${branchesFormatted}` : ''}
${config.triggerSchedule ? `  schedule:
    - cron: '0 2 * * 1-5' # Execução diária de auditoria noturna` : ''}
${config.triggerWorkflowDispatch ? `  workflow_dispatch:` : ''}

${config.concurrencyGroup ? `concurrency:
  group: \${{ github.workflow }}-\${{ github.ref }}
  cancel-in-progress: true` : ''}

permissions:
  contents: read
  security-events: write
  actions: read
  pull-requests: write

jobs:
  # ------------------------------------------------------------------
  # STAGE 1: PRE-COMMIT & SHIFT-LEFT GATE
  # Enforces local secret detection and prevents dirty commits
  # Mapped Findings: ${findingsByStage['pre-commit'].length} items (Gate: Fail on ${config.stages['pre-commit'].failThreshold})
  # ------------------------------------------------------------------
  pre-commit-gate:
    name: "🛡️ Stage 1: Pre-commit & Secret Hygiene"
    runs-on: ${config.runner}
    steps:
      - name: 📥 Checkout Repository Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: ⚙️ Setup Node.js Runtime
        uses: actions/setup-node@v4
        with:
          node-version: ${config.nodeVersion}
          cache: 'npm'

      - name: 📦 Install SecScan CLI
        run: npm ci --prefer-offline || npm install

${renderStepsYaml(preCommitSteps, 'pre-commit')}

  # ------------------------------------------------------------------
  # STAGE 2: BUILD & STATIC APPLICATION SECURITY TESTING (SAST / SCA)
  # Deep dataflow analysis, dependency scanning and SBOM generation
  # Mapped Findings: ${findingsByStage['build'].length} items (Gate: Fail on ${config.stages['build'].failThreshold})
  # ------------------------------------------------------------------
  build-and-sast-gate:
    name: "⚡ Stage 2: Build & SAST Taint Analysis"
    needs: [pre-commit-gate]
    runs-on: ${config.runner}
    steps:
      - name: 📥 Checkout Repository Code
        uses: actions/checkout@v4

      - name: ⚙️ Setup Node.js Runtime
        uses: actions/setup-node@v4
        with:
          node-version: ${config.nodeVersion}
          cache: 'npm'

      - name: 📦 Install Project Dependencies
        run: npm ci

${renderStepsYaml(buildSteps, 'build')}

${config.uploadSarif ? `      - name: 🛡️ Publish SARIF to GitHub Security Alerts
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secscan-sast.sarif
          category: secscan-sast` : ''}

  # ------------------------------------------------------------------
  # STAGE 3: DEPLOY & CLOUD RUNTIME GATE
  # DAST API fuzzer, Docker CIS verification & IAM least-privilege
  # Mapped Findings: ${findingsByStage['deploy'].length} items (Gate: Fail on ${config.stages['deploy'].failThreshold})
  # ------------------------------------------------------------------
  deploy-and-runtime-gate:
    name: "🚀 Stage 3: Deploy & Dynamic Verification"
    needs: [build-and-sast-gate]
    runs-on: ${config.runner}
    steps:
      - name: 📥 Checkout Repository Code
        uses: actions/checkout@v4

      - name: ⚙️ Setup Node.js Runtime
        uses: actions/setup-node@v4
        with:
          node-version: ${config.nodeVersion}

${renderStepsYaml(deploySteps, 'deploy')}

      - name: ✅ Pipeline Gate Attestation
        run: |
          echo "================================================="
          echo "SecScan DevSecOps Pipeline Finished Successfully!"
          echo "Pre-commit, Build and Deploy Quality Gates passed."
          echo "================================================="
`;

  return yaml;
}

/**
 * Simulates pipeline execution against current mapped findings
 */
export function simulatePipelineRun(
  config: PipelineArchitectConfig,
  findings: ScanFinding[]
): PipelineSimulationReport {
  const severityRank: Record<SeverityLevel, number> = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'INFO': 0
  };

  const getBreachesForStage = (stageId: PipelineStageId): ScanFinding[] => {
    const stageConf = config.stages[stageId];
    const minThreshold = severityRank[stageConf.failThreshold] || 3;

    return findings.filter(f => {
      const assignedStage = config.findingStageMapping[f.id] || autoCategorizeFindingToStage(f);
      if (assignedStage !== stageId) return false;
      const fRank = severityRank[f.severity] || 0;
      return fRank >= minThreshold;
    });
  };

  const stageResults: Record<PipelineStageId, StageSimulationResult> = {
    'pre-commit': {
      stageId: 'pre-commit',
      stageTitle: config.stages['pre-commit'].title,
      status: 'PENDING',
      durationSeconds: 2.4,
      evaluatedFindingsCount: 0,
      breachingFindings: [],
      logs: []
    },
    'build': {
      stageId: 'build',
      stageTitle: config.stages['build'].title,
      status: 'PENDING',
      durationSeconds: 4.8,
      evaluatedFindingsCount: 0,
      breachingFindings: [],
      logs: []
    },
    'deploy': {
      stageId: 'deploy',
      stageTitle: config.stages['deploy'].title,
      status: 'PENDING',
      durationSeconds: 3.1,
      evaluatedFindingsCount: 0,
      breachingFindings: [],
      logs: []
    }
  };

  let pipelineBlocked = false;

  // 1. Stage Pre-commit
  const preCommitFindings = findings.filter(f => (config.findingStageMapping[f.id] || autoCategorizeFindingToStage(f)) === 'pre-commit');
  const preCommitBreaches = getBreachesForStage('pre-commit');
  stageResults['pre-commit'].evaluatedFindingsCount = preCommitFindings.length;
  stageResults['pre-commit'].breachingFindings = preCommitBreaches;

  const preLogs = stageResults['pre-commit'].logs;
  preLogs.push({ timestamp: '00:01s', level: 'INFO', message: 'Executando hook pre-commit: Checando regras de segredos e entropia de Shannon...' });
  preLogs.push({ timestamp: '00:02s', level: 'INFO', message: `Avaliados ${preCommitFindings.length} achados mapeados para o estágio local.` });

  if (preCommitBreaches.length > 0) {
    stageResults['pre-commit'].status = 'FAILED';
    preLogs.push({ timestamp: '00:02s', level: 'ERROR', message: `❌ Quality Gate Rompido! ${preCommitBreaches.length} achado(s) violam o limite (${config.stages['pre-commit'].failThreshold}).` });
    preCommitBreaches.slice(0, 3).forEach(b => {
      preLogs.push({ timestamp: '00:02s', level: 'ERROR', message: `  ↳ [${b.severity}] ${b.ruleName} em ${b.file}:${b.line}` });
    });
    if (config.stages['pre-commit'].blockPipelineOnBreach) {
      pipelineBlocked = true;
      preLogs.push({ timestamp: '00:02s', level: 'ERROR', message: '⛔ Pipeline interrompido no Pre-commit (Shift-Left Block).' });
    }
  } else {
    stageResults['pre-commit'].status = 'PASSED';
    preLogs.push({ timestamp: '00:02s', level: 'SUCCESS', message: '✅ Stage 1 Pre-commit APROVADO: Nenhuma credencial acima do limite detectada.' });
  }

  // 2. Stage Build
  if (pipelineBlocked) {
    stageResults['build'].status = 'SKIPPED';
    stageResults['build'].logs.push({ timestamp: '00:00s', level: 'WARN', message: '⚠️ Estágio Build pulado devido a bloqueio no estágio anterior (Pre-commit).' });
  } else {
    const buildFindings = findings.filter(f => (config.findingStageMapping[f.id] || autoCategorizeFindingToStage(f)) === 'build');
    const buildBreaches = getBreachesForStage('build');
    stageResults['build'].evaluatedFindingsCount = buildFindings.length;
    stageResults['build'].breachingFindings = buildBreaches;

    const bLogs = stageResults['build'].logs;
    bLogs.push({ timestamp: '00:01s', level: 'INFO', message: 'Executando Runner SAST Taint Dataflow e auditoria SCA...' });
    bLogs.push({ timestamp: '00:03s', level: 'INFO', message: `Avaliados ${buildFindings.length} achados estáticos de código.` });

    if (buildBreaches.length > 0) {
      stageResults['build'].status = 'FAILED';
      bLogs.push({ timestamp: '00:04s', level: 'ERROR', message: `❌ Quality Gate Build Rompido! ${buildBreaches.length} achado(s) excedem ${config.stages['build'].failThreshold}.` });
      buildBreaches.slice(0, 3).forEach(b => {
        bLogs.push({ timestamp: '00:04s', level: 'ERROR', message: `  ↳ [${b.severity}] ${b.ruleName} em ${b.file}:${b.line}` });
      });
      if (config.stages['build'].blockPipelineOnBreach) {
        pipelineBlocked = true;
        bLogs.push({ timestamp: '00:04s', level: 'ERROR', message: '⛔ Pipeline interrompido no Build (CI Quality Gate Block).' });
      }
    } else {
      stageResults['build'].status = 'PASSED';
      bLogs.push({ timestamp: '00:04s', level: 'SUCCESS', message: '✅ Stage 2 Build APROVADO: SAST, SCA e SBOM conformes.' });
    }
  }

  // 3. Stage Deploy
  if (pipelineBlocked) {
    stageResults['deploy'].status = 'SKIPPED';
    stageResults['deploy'].logs.push({ timestamp: '00:00s', level: 'WARN', message: '⚠️ Estágio Deploy pulado devido a falha nos estágios anteriores.' });
  } else {
    const deployFindings = findings.filter(f => (config.findingStageMapping[f.id] || autoCategorizeFindingToStage(f)) === 'deploy');
    const deployBreaches = getBreachesForStage('deploy');
    stageResults['deploy'].evaluatedFindingsCount = deployFindings.length;
    stageResults['deploy'].breachingFindings = deployBreaches;

    const dLogs = stageResults['deploy'].logs;
    dLogs.push({ timestamp: '00:01s', level: 'INFO', message: 'Executando DAST API Fuzzer, CIS Docker e IAM Verification...' });
    dLogs.push({ timestamp: '00:03s', level: 'INFO', message: `Avaliados ${deployFindings.length} achados de infraestrutura e runtime.` });

    if (deployBreaches.length > 0) {
      stageResults['deploy'].status = 'FAILED';
      dLogs.push({ timestamp: '00:03s', level: 'ERROR', message: `❌ Quality Gate Deploy Rompido! ${deployBreaches.length} achado(s) excedem ${config.stages['deploy'].failThreshold}.` });
      deployBreaches.slice(0, 3).forEach(b => {
        dLogs.push({ timestamp: '00:03s', level: 'ERROR', message: `  ↳ [${b.severity}] ${b.ruleName} em ${b.file}:${b.line}` });
      });
    } else {
      stageResults['deploy'].status = 'PASSED';
      dLogs.push({ timestamp: '00:03s', level: 'SUCCESS', message: '✅ Stage 3 Deploy APROVADO: Ambiente apto para deploy seguro em produção.' });
    }
  }

  const overallPassed = !pipelineBlocked && stageResults['deploy'].status === 'PASSED';
  const totalDuration = Number((stageResults['pre-commit'].durationSeconds + stageResults['build'].durationSeconds + stageResults['deploy'].durationSeconds).toFixed(1));

  return {
    timestamp: new Date().toISOString(),
    overallStatus: overallPassed ? 'PASSED' : 'FAILED',
    totalDurationSeconds: totalDuration,
    stageResults,
    summary: overallPassed
      ? `✅ Pipeline Aprovado! Todas as verificações de Pre-commit, Build e Deploy atenderam aos Quality Gates.`
      : `❌ Pipeline Reprovado: Detectadas violações de Quality Gate nos achados mapeados.`
  };
}
