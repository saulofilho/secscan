import { 
  ScanReport, 
  WorkflowRun, 
  WorkflowLogStep, 
  WorkflowLogLine, 
  CiCdPipelineHealthSummary,
  ScanFinding
} from '../types';
import { safeGetItem, safeSetItem } from './storage';

export const WORKFLOW_STORAGE_KEY = 'secscan_cicd_workflow_runs_v2';

/**
 * Builds realistic, chronological log lines for a SecScan GitHub Actions execution
 */
export function generateWorkflowRunLogs(
  runNumber: number,
  commitSha: string,
  branch: string,
  findings: ScanFinding[],
  isFailed: boolean,
  failureReason: string = 'Quality Gate Breached'
): { steps: WorkflowLogStep[]; rawLogs: string } {
  const baseTime = new Date(Date.now() - 1000 * 60 * 12);
  const getTs = (offsetSeconds: number) => {
    return new Date(baseTime.getTime() + offsetSeconds * 1000).toISOString().replace('T', ' ').slice(0, 19) + 'Z';
  };

  const steps: WorkflowLogStep[] = [];
  const rawLogLines: string[] = [];

  const addRaw = (ts: string, level: string, msg: string) => {
    rawLogLines.push(`[${ts}] [${level.padEnd(5)}] ${msg}`);
  };

  // Step 1: Set up runner
  const step1Lines: WorkflowLogLine[] = [
    { timestamp: getTs(0), level: 'INFO', message: 'Current runner version: 2.316.0' },
    { timestamp: getTs(1), level: 'INFO', message: 'Operating System: Ubuntu 24.04.1 LTS (Linux 6.8.0-1017-azure)' },
    { timestamp: getTs(2), level: 'INFO', message: 'Runner Image: ubuntu-24.04 (Version: 20260901.1.0)' },
    { timestamp: getTs(2), level: 'INFO', message: 'GITHUB_TOKEN Permissions: contents: read, security-events: write, actions: read' },
    { timestamp: getTs(3), level: 'INFO', message: 'Complete job initialization.' }
  ];
  step1Lines.forEach(l => addRaw(l.timestamp, l.level, l.message));
  steps.push({
    id: 'setup-runner',
    name: '⚙️ Set up job runner (ubuntu-latest)',
    status: 'success',
    durationSeconds: 3,
    lines: step1Lines
  });

  // Step 2: Checkout
  const step2Lines: WorkflowLogLine[] = [
    { timestamp: getTs(4), level: 'INFO', message: `Syncing repository to commit: ${commitSha} (${branch})` },
    { timestamp: getTs(5), level: 'INFO', message: 'Fetching origin references with depth 1...' },
    { timestamp: getTs(6), level: 'INFO', message: `HEAD is now at ${commitSha.slice(0, 7)} (verified commit signature GPG: OK)` }
  ];
  step2Lines.forEach(l => addRaw(l.timestamp, l.level, l.message));
  steps.push({
    id: 'checkout',
    name: '📥 actions/checkout@v4',
    status: 'success',
    durationSeconds: 3,
    lines: step2Lines
  });

  // Step 3: Setup Node.js & Dependencies
  const step3Lines: WorkflowLogLine[] = [
    { timestamp: getTs(7), level: 'INFO', message: 'actions/setup-node@v4: Resolved version Node.js 22.11.0' },
    { timestamp: getTs(8), level: 'INFO', message: 'Running: npm ci --prefer-offline --no-audit' },
    { timestamp: getTs(12), level: 'INFO', message: 'added 248 packages, audited 249 packages in 3.8s' },
    { timestamp: getTs(13), level: 'INFO', message: 'Found 0 known vulnerabilities in core dependencies' }
  ];
  step3Lines.forEach(l => addRaw(l.timestamp, l.level, l.message));
  steps.push({
    id: 'setup-node',
    name: '📦 Setup Node.js 22 & npm ci',
    status: 'success',
    durationSeconds: 6,
    lines: step3Lines
  });

  // Step 4: SecScan SAST Execution
  const step4Lines: WorkflowLogLine[] = [
    { timestamp: getTs(14), level: 'INFO', message: 'Executing SecScan SAST Secret & API Analysis Engine v2.4.0' },
    { timestamp: getTs(15), level: 'INFO', message: 'Options: --format sarif --output secscan-results.sarif --ignore "node_modules,dist,.git"' },
    { timestamp: getTs(16), level: 'INFO', message: 'Loaded 48 pattern detection rules (Shannon entropy threshold: 4.2 bits)' },
    { timestamp: getTs(17), level: 'INFO', message: 'Scanning target directory workspace...' }
  ];

  if (findings.length === 0) {
    step4Lines.push({
      timestamp: getTs(19),
      level: 'INFO',
      message: '✅ Workspace Clean: 0 hardcoded secrets, 0 plaintext API keys identified.'
    });
  } else {
    findings.slice(0, 10).forEach((finding, idx) => {
      const isCrit = finding.severity === 'CRITICAL' || finding.severity === 'HIGH';
      step4Lines.push({
        timestamp: getTs(18 + idx),
        level: isCrit ? 'ERROR' : 'WARN',
        message: `[${finding.severity}] Rule: ${finding.ruleName} in ${finding.file}:${finding.line} | Masked: ${finding.maskedSecret}`,
        findingId: finding.id,
        highlight: isCrit
      });
    });

    if (findings.length > 10) {
      step4Lines.push({
        timestamp: getTs(28),
        level: 'WARN',
        message: `... and ${findings.length - 10} additional occurrences detected across the codebase.`
      });
    }
  }

  step4Lines.push({
    timestamp: getTs(30),
    level: 'INFO',
    message: `Scan finished in 412ms. Generated SARIF report: secscan-results.sarif (${(findings.length * 0.4 + 1.2).toFixed(1)} KB)`
  });

  step4Lines.forEach(l => addRaw(l.timestamp, l.level, l.message));
  steps.push({
    id: 'secscan-sast',
    name: '🔍 Run SecScan Secret & API SAST',
    status: 'success',
    durationSeconds: 16,
    lines: step4Lines
  });

  // Step 5: Upload SARIF to GitHub CodeQL
  const step5Lines: WorkflowLogLine[] = [
    { timestamp: getTs(31), level: 'INFO', message: 'github/codeql-action/upload-sarif@v3: Validating SARIF v2.1.0 schema...' },
    { timestamp: getTs(32), level: 'INFO', message: `Uploading ${findings.length} code scanning findings to GitHub Security Tab...` },
    { timestamp: getTs(34), level: 'INFO', message: 'POST https://api.github.com/repos/org/repo/code-scanning/sarifs -> HTTP 202 Accepted' },
    { timestamp: getTs(35), level: 'INFO', message: 'SARIF upload completed successfully. Alerts will reflect on GitHub Pull Requests.' }
  ];
  step5Lines.forEach(l => addRaw(l.timestamp, l.level, l.message));
  steps.push({
    id: 'upload-sarif',
    name: '🛡️ Upload SARIF to GitHub Code Scanning',
    status: 'success',
    durationSeconds: 4,
    lines: step5Lines
  });

  // Step 6: Quality Gate Enforcement
  const step6Lines: WorkflowLogLine[] = [];
  if (isFailed) {
    step6Lines.push({
      timestamp: getTs(36),
      level: 'INFO',
      message: 'Evaluating Quality Gate Policy: --fail-on critical --max-risk 50'
    });
    step6Lines.push({
      timestamp: getTs(37),
      level: 'ERROR',
      message: `❌ QUALITY GATE VIOLATION: ${failureReason}`,
      highlight: true
    });
    step6Lines.push({
      timestamp: getTs(38),
      level: 'ERROR',
      message: `Found active blocking vulnerabilities. Commit ${commitSha.slice(0, 7)} has been rejected by SecScan Policy.`,
      highlight: true
    });
    step6Lines.push({
      timestamp: getTs(39),
      level: 'ERROR',
      message: 'Failing workflow job step: exit code 1.'
    });
    step6Lines.forEach(l => addRaw(l.timestamp, l.level, l.message));
    steps.push({
      id: 'quality-gate',
      name: '🚦 Quality Gate (CI/CD Breaker)',
      status: 'failed',
      durationSeconds: 3,
      lines: step6Lines
    });
  } else {
    step6Lines.push({
      timestamp: getTs(36),
      level: 'INFO',
      message: 'Evaluating Quality Gate Policy: --fail-on critical --max-risk 50'
    });
    step6Lines.push({
      timestamp: getTs(37),
      level: 'INFO',
      message: '✅ QUALITY GATE PASSED: Zero blocking credentials detected. All risk indicators within acceptable tolerance.'
    });
    step6Lines.push({
      timestamp: getTs(38),
      level: 'INFO',
      message: 'Security Quality Gate verified with exit code 0. Proceeding with deployment.'
    });
    step6Lines.forEach(l => addRaw(l.timestamp, l.level, l.message));
    steps.push({
      id: 'quality-gate',
      name: '🚦 Quality Gate (CI/CD Breaker)',
      status: 'success',
      durationSeconds: 2,
      lines: step6Lines
    });
  }

  return {
    steps,
    rawLogs: rawLogLines.join('\n')
  };
}

/**
 * Initializes realistic historical and active workflow runs based on the current workspace scan report
 */
export function buildInitialWorkflowRuns(
  report: ScanReport,
  qualityGateMaxRisk: number = 50
): WorkflowRun[] {
  const activeFindings = report.findings.filter(f => !f.isFalsePositive);
  const criticalCount = activeFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = activeFindings.filter(f => f.severity === 'HIGH').length;
  const medCount = activeFindings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = activeFindings.filter(f => f.severity === 'LOW').length;
  const currentRiskScore = report.metrics.riskScore ?? 0;

  // Determine if current workspace run is failing Quality Gate
  const isCurrentFailing = criticalCount > 0 || currentRiskScore > qualityGateMaxRisk;
  const failureReason = criticalCount > 0 
    ? `${criticalCount} credencial(is) de nível CRITICAL detectada(s) no workspace` 
    : currentRiskScore > qualityGateMaxRisk 
    ? `Risk Score acumulado (${currentRiskScore}) ultrapassou o teto tolerado (${qualityGateMaxRisk})` 
    : 'Quality Gate Policy Violation';

  const now = Date.now();
  const ONE_MIN = 60 * 1000;
  const ONE_HOUR = 60 * ONE_MIN;
  const ONE_DAY = 24 * ONE_HOUR;

  // Run #154 (Current / Latest Run)
  const currentLogs = generateWorkflowRunLogs(
    154,
    'a3b89f2',
    'main',
    activeFindings,
    isCurrentFailing,
    failureReason
  );

  const run154: WorkflowRun = {
    id: 'run-154',
    runNumber: 154,
    title: 'chore: automated security audit on push [main]',
    event: 'push',
    status: 'completed',
    conclusion: isCurrentFailing ? 'failure' : 'success',
    branch: 'main',
    commitSha: 'a3b89f21d98a',
    commitMessage: 'chore(infra): sync workspace and update security rules',
    actor: {
      name: 'github-actions[bot]',
      isBot: true
    },
    startedAt: new Date(now - 14 * ONE_MIN).toISOString(),
    durationSeconds: 38,
    findingsCount: {
      critical: criticalCount,
      high: highCount,
      medium: medCount,
      low: lowCount,
      total: activeFindings.length
    },
    riskScore: currentRiskScore,
    qualityGateStatus: isCurrentFailing ? 'FAILED_CRITICAL' : 'PASSED',
    sarifUploaded: true,
    workflowFile: '.github/workflows/secscan.yml',
    steps: currentLogs.steps,
    rawLogs: currentLogs.rawLogs
  };

  // Run #153 (PR #49 by developer)
  const run153Findings = activeFindings.slice(0, 1);
  const run153Logs = generateWorkflowRunLogs(
    153,
    '7c10ea4',
    'feature/payment-stripe-v2',
    run153Findings,
    false,
    ''
  );
  const run153: WorkflowRun = {
    id: 'run-153',
    runNumber: 153,
    title: 'PR #49: feat(checkout): migrate stripe webhook signatures',
    event: 'pull_request',
    status: 'completed',
    conclusion: 'success',
    branch: 'feature/payment-stripe-v2',
    commitSha: '7c10ea49e0b1',
    commitMessage: 'feat(checkout): migrate stripe webhook signatures & decouple keys',
    actor: {
      name: 'dev-lead-alex',
      isBot: false
    },
    startedAt: new Date(now - 2 * ONE_HOUR - 15 * ONE_MIN).toISOString(),
    durationSeconds: 42,
    findingsCount: {
      critical: 0,
      high: 0,
      medium: 1,
      low: 0,
      total: 1
    },
    riskScore: 12,
    qualityGateStatus: 'PASSED',
    sarifUploaded: true,
    workflowFile: '.github/workflows/secscan.yml',
    steps: run153Logs.steps,
    rawLogs: run153Logs.rawLogs
  };

  // Run #152 (Scheduled Nightly Cron)
  const run152Logs = generateWorkflowRunLogs(
    152,
    '5d8a1c9',
    'main',
    [],
    false,
    ''
  );
  const run152: WorkflowRun = {
    id: 'run-152',
    runNumber: 152,
    title: 'Nightly Scheduled Workspace Vulnerability Scan',
    event: 'schedule',
    status: 'completed',
    conclusion: 'success',
    branch: 'main',
    commitSha: '5d8a1c91ff30',
    commitMessage: 'schedule(cron): daily 02:00 UTC security sweep',
    actor: {
      name: 'github-actions[bot]',
      isBot: true
    },
    startedAt: new Date(now - 14 * ONE_HOUR).toISOString(),
    durationSeconds: 31,
    findingsCount: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 0
    },
    riskScore: 0,
    qualityGateStatus: 'PASSED',
    sarifUploaded: true,
    workflowFile: '.github/workflows/secscan.yml',
    steps: run152Logs.steps,
    rawLogs: run152Logs.rawLogs
  };

  // Run #151 (PR #48 Failed Quality Gate: hardcoded token)
  const dummyLeakFinding: ScanFinding = {
    id: 'sim-finding-151',
    ruleId: 'sec-github-pat',
    ruleName: 'GitHub Personal Access Token',
    severity: 'CRITICAL',
    category: 'AUTH_TOKEN',
    file: 'scripts/deploy.sh',
    line: 14,
    column: 1,
    matchedSecret: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
    snippet: 'export GITHUB_TOKEN="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"',
    maskedSecret: 'ghp_ABCDE********************7890',
    entropy: 4.62,
    description: 'Hardcoded GitHub PAT detected in automation shell script',
    remediation: 'Revogar token no GitHub e utilizar Secrets de repositório.',
    timestamp: new Date().toISOString(),
    riskScore: 90
  };
  const run151Logs = generateWorkflowRunLogs(
    151,
    'b841e2a',
    'fix/deploy-script',
    [dummyLeakFinding],
    true,
    '1 token de acesso pessoal (PAT) detectado em scripts/deploy.sh:14'
  );
  const run151: WorkflowRun = {
    id: 'run-151',
    runNumber: 151,
    title: 'PR #48: fix: update release automation bash script',
    event: 'pull_request',
    status: 'completed',
    conclusion: 'failure',
    branch: 'fix/deploy-script',
    commitSha: 'b841e2a44bb0',
    commitMessage: 'fix: update release automation bash script',
    actor: {
      name: 'junior-dev-lucas',
      isBot: false
    },
    startedAt: new Date(now - 1 * ONE_DAY - 3 * ONE_HOUR).toISOString(),
    durationSeconds: 35,
    findingsCount: {
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      total: 1
    },
    riskScore: 90,
    qualityGateStatus: 'FAILED_CRITICAL',
    sarifUploaded: true,
    workflowFile: '.github/workflows/secscan.yml',
    steps: run151Logs.steps,
    rawLogs: run151Logs.rawLogs
  };

  // Run #150 (Manual Dispatch on Staging branch)
  const run150Logs = generateWorkflowRunLogs(
    150,
    '1e39a7b',
    'staging',
    [],
    false,
    ''
  );
  const run150: WorkflowRun = {
    id: 'run-150',
    runNumber: 150,
    title: 'Manual Workflow Dispatch by SecOps Lead',
    event: 'workflow_dispatch',
    status: 'completed',
    conclusion: 'success',
    branch: 'staging',
    commitSha: '1e39a7b77ce2',
    commitMessage: 'release(rc2): prepare v2.4.0 candidate image',
    actor: {
      name: 'secops-sarah',
      isBot: false
    },
    startedAt: new Date(now - 2 * ONE_DAY).toISOString(),
    durationSeconds: 45,
    findingsCount: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 0
    },
    riskScore: 0,
    qualityGateStatus: 'PASSED',
    sarifUploaded: true,
    workflowFile: '.github/workflows/secscan.yml',
    steps: run150Logs.steps,
    rawLogs: run150Logs.rawLogs
  };

  // Run #149 (Push on main: Clean)
  const run149Logs = generateWorkflowRunLogs(
    149,
    '88fa290',
    'main',
    [],
    false,
    ''
  );
  const run149: WorkflowRun = {
    id: 'run-149',
    runNumber: 149,
    title: 'merge(pull #46): sanitize environment configuration',
    event: 'push',
    status: 'completed',
    conclusion: 'success',
    branch: 'main',
    commitSha: '88fa290cc145',
    commitMessage: 'Merge pull request #46 from acme/fix-env',
    actor: {
      name: 'dev-lead-alex',
      isBot: false
    },
    startedAt: new Date(now - 3 * ONE_DAY).toISOString(),
    durationSeconds: 39,
    findingsCount: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 0
    },
    riskScore: 0,
    qualityGateStatus: 'PASSED',
    sarifUploaded: true,
    workflowFile: '.github/workflows/secscan.yml',
    steps: run149Logs.steps,
    rawLogs: run149Logs.rawLogs
  };

  // Run #148 (Dependabot security bump: Success)
  const run148Logs = generateWorkflowRunLogs(
    148,
    '44db107',
    'dependabot/npm_and_yarn/express-4.21.0',
    [],
    false,
    ''
  );
  const run148: WorkflowRun = {
    id: 'run-148',
    runNumber: 148,
    title: 'build(deps): bump express from 4.19.2 to 4.21.0',
    event: 'pull_request',
    status: 'completed',
    conclusion: 'success',
    branch: 'dependabot/npm_and_yarn/express-4.21.0',
    commitSha: '44db10781a99',
    commitMessage: 'build(deps): bump express from 4.19.2 to 4.21.0 in /src',
    actor: {
      name: 'dependabot[bot]',
      isBot: true
    },
    startedAt: new Date(now - 4 * ONE_DAY).toISOString(),
    durationSeconds: 34,
    findingsCount: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 0
    },
    riskScore: 0,
    qualityGateStatus: 'PASSED',
    sarifUploaded: true,
    workflowFile: '.github/workflows/secscan.yml',
    steps: run148Logs.steps,
    rawLogs: run148Logs.rawLogs
  };

  return [run154, run153, run152, run151, run150, run149, run148];
}

/**
 * Loads stored runs or initializes them with current report
 */
export function getOrInitWorkflowRuns(report: ScanReport, qualityGateMaxRisk: number = 50): WorkflowRun[] {
  const saved = safeGetItem(WORKFLOW_STORAGE_KEY);
  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      if (Array.isArray(parsed) && parsed.length > 0) {
        // Sync the latest run with current report findings so real-time status reflects workspace
        const latest = parsed[0];
        const activeFindings = report.findings.filter(f => !f.isFalsePositive);
        const criticalCount = activeFindings.filter(f => f.severity === 'CRITICAL').length;
        const currentRiskScore = report.metrics.riskScore ?? 0;
        const isCurrentFailing = criticalCount > 0 || currentRiskScore > qualityGateMaxRisk;

        const updatedLatestLogs = generateWorkflowRunLogs(
          latest.runNumber,
          latest.commitSha,
          latest.branch,
          activeFindings,
          isCurrentFailing,
          criticalCount > 0
            ? `${criticalCount} credencial(is) de nível CRITICAL detectada(s)`
            : `Risk score (${currentRiskScore}) excedeu o teto (${qualityGateMaxRisk})`
        );

        parsed[0] = {
          ...latest,
          conclusion: isCurrentFailing ? 'failure' : 'success',
          findingsCount: {
            critical: criticalCount,
            high: activeFindings.filter(f => f.severity === 'HIGH').length,
            medium: activeFindings.filter(f => f.severity === 'MEDIUM').length,
            low: activeFindings.filter(f => f.severity === 'LOW').length,
            total: activeFindings.length
          },
          riskScore: currentRiskScore,
          qualityGateStatus: isCurrentFailing ? 'FAILED_CRITICAL' : 'PASSED',
          steps: updatedLatestLogs.steps,
          rawLogs: updatedLatestLogs.rawLogs
        };

        return parsed;
      }
    } catch {
      // fallback
    }
  }

  const initial = buildInitialWorkflowRuns(report, qualityGateMaxRisk);
  safeSetItem(WORKFLOW_STORAGE_KEY, JSON.stringify(initial));
  return initial;
}

/**
 * Calculates aggregate pipeline health metrics
 */
export function computePipelineHealth(runs: WorkflowRun[]): CiCdPipelineHealthSummary {
  if (runs.length === 0) {
    return {
      successRatePercentage: 100,
      totalRuns: 0,
      successfulRuns: 0,
      failedRuns: 0,
      inProgressRuns: 0,
      averageDurationSeconds: 0,
      lastRunStatus: 'unknown',
      lastRunTimestamp: new Date().toISOString(),
      runnerStatus: 'ONLINE',
      webhookStatus: 'ACTIVE',
      branchProtectionActive: true,
      sarifCodeScanningActive: true
    };
  }

  let successCount = 0;
  let failCount = 0;
  let inProgressCount = 0;
  let totalDuration = 0;

  runs.forEach(r => {
    totalDuration += r.durationSeconds;
    if (r.conclusion === 'success') {
      successCount++;
    } else if (r.conclusion === 'failure') {
      failCount++;
    } else if (r.status === 'in_progress' || r.status === 'queued') {
      inProgressCount++;
    }
  });

  const completed = successCount + failCount;
  const successRate = completed > 0 ? Math.round((successCount / completed) * 1000) / 10 : 100;
  const avgDuration = Math.round(totalDuration / runs.length);
  const latestRun = runs[0];

  return {
    successRatePercentage: successRate,
    totalRuns: runs.length,
    successfulRuns: successCount,
    failedRuns: failCount,
    inProgressRuns: inProgressCount,
    averageDurationSeconds: avgDuration,
    lastRunStatus: latestRun ? (latestRun.conclusion === 'success' ? 'success' : latestRun.conclusion === 'failure' ? 'failure' : 'in_progress') : 'unknown',
    lastRunTimestamp: latestRun ? latestRun.startedAt : new Date().toISOString(),
    runnerStatus: 'ONLINE',
    webhookStatus: 'ACTIVE',
    branchProtectionActive: true,
    sarifCodeScanningActive: true
  };
}

/**
 * Creates a brand new workflow run (e.g. when developer clicks 'Trigger Scan Now' / dispatch)
 */
export function dispatchNewWorkflowRun(
  report: ScanReport,
  branch: string = 'main',
  actorName: string = 'current-user',
  qualityGateMaxRisk: number = 50,
  existingRuns: WorkflowRun[]
): WorkflowRun {
  const activeFindings = report.findings.filter(f => !f.isFalsePositive);
  const criticalCount = activeFindings.filter(f => f.severity === 'CRITICAL').length;
  const currentRiskScore = report.metrics.riskScore ?? 0;
  const isFailing = criticalCount > 0 || currentRiskScore > qualityGateMaxRisk;

  const nextRunNumber = (existingRuns[0]?.runNumber || 154) + 1;
  const randomCommit = Math.random().toString(16).substring(2, 9);

  const logs = generateWorkflowRunLogs(
    nextRunNumber,
    randomCommit,
    branch,
    activeFindings,
    isFailing,
    criticalCount > 0
      ? `Quality Gate: ${criticalCount} credenciais críticas detectadas no branch ${branch}`
      : `Quality Gate: Risk Score (${currentRiskScore}) > Teto tolerado (${qualityGateMaxRisk})`
  );

  return {
    id: `run-${nextRunNumber}`,
    runNumber: nextRunNumber,
    title: `Manual workflow_dispatch on [${branch}]`,
    event: 'workflow_dispatch',
    status: 'completed',
    conclusion: isFailing ? 'failure' : 'success',
    branch,
    commitSha: randomCommit,
    commitMessage: `chore(scan): manual security run triggered via SecScan dashboard`,
    actor: {
      name: actorName,
      isBot: false
    },
    startedAt: new Date().toISOString(),
    durationSeconds: Math.floor(Math.random() * 15) + 30,
    findingsCount: {
      critical: criticalCount,
      high: activeFindings.filter(f => f.severity === 'HIGH').length,
      medium: activeFindings.filter(f => f.severity === 'MEDIUM').length,
      low: activeFindings.filter(f => f.severity === 'LOW').length,
      total: activeFindings.length
    },
    riskScore: currentRiskScore,
    qualityGateStatus: isFailing ? 'FAILED_CRITICAL' : 'PASSED',
    sarifUploaded: true,
    workflowFile: '.github/workflows/secscan.yml',
    steps: logs.steps,
    rawLogs: logs.rawLogs
  };
}
