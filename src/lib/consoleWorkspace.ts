import { FEATURE_REGISTRY } from './featureRegistry';
import { DEFAULT_RULES } from './defaultRules';
import { calculateCumulativeWorkspaceRiskScore } from './scanner';
import { extractLinkFinderEndpoints } from './linkFinderEngine';
import { analyzeWithJsMiner } from './jsMinerEngine';
import { buildDataFlowGraph } from './dataFlowGraphEngine';
import { auditApiSecurity } from './apiSecurityScanner';
import { generateRemediationPatchForFinding } from './autoRemediator';
import { findApplicableRecipes } from './securityRefactoringData';
import { runIastRuntimeEmulation, INITIAL_IAST_HOOKS } from './iastEngine';
import { getDemoNmapHosts } from './nmapEngine';
import { getDemoNiktoTargets } from './niktoEngine';
import { INITIAL_WAF_RULES, INITIAL_WAF_OVERVIEW } from './wafEngine';
import { INITIAL_POLICY_RULES, INITIAL_NGFW_METRICS } from './ngfwEngine';
import { INITIAL_IDS_RULES, INITIAL_IDS_ALERTS, INITIAL_IDS_STATUS } from './idsEngine';
import { INITIAL_DNS_QUERIES, INITIAL_DNSSEC_CHAINS, INITIAL_DNS_OVERVIEW } from './dnsEngine';
import { INITIAL_SDWAN_EDGES, INITIAL_SDWAN_TELEMETRY } from './sdwanEngine';
import { INITIAL_HOST_ENDPOINTS, INITIAL_BEHAVIORAL_RULES, INITIAL_EDR_TELEMETRY } from './edrEngine';
import { DEFAULT_SOAR_PLAYBOOKS, executeSoarPlaybook } from './soarEngine';
import { runBreachAttackSimulation } from './basEngine';
import { SAMPLE_SIGMA_RULES } from './sigmaEngine';
import { analyzeArtifact } from './malwareSandboxEngine';
import { DEFAULT_VAULT_SECRETS } from './secretsVaultEngine';
import { SAMPLE_SUPPLY_CHAIN_PACKAGES } from './supplyChainEngine';
import { DEFAULT_EASM_ASSETS } from './easmEngine';
import { SAMPLE_DARK_WEB_BREACHES, extractEmailsFromFiles } from './darkWebEngine';
import { SAMPLE_CSPM_FINDINGS } from './cspmEngine';
import { DEFAULT_TLS_CERTS } from './pkiEngine';
import { getThreatIntelSummary, lookupThreatIndicator } from './osintThreatFeedsData';
import { computeCtiHeatmapMatrix } from './ctiHeatmapEngine';
import { buildThreatModelFromWorkspace } from './threatModeler';
import { DEFAULT_OPA_POLICIES, evaluateAllOpaPolicies } from './opaPolicyEngine';
import { NIST_CSF_SUBCATEGORIES, evaluateAutoNistStatus } from './frameworksData';
import { buildAsocInventory } from './asocManager';
import { analyzePromptForInjections } from './llmSecurityEngine';
import { buildInitialFindingStageMapping, DEFAULT_PIPELINE_STAGES, INITIAL_ACTION_STEPS, simulatePipelineRun } from './pipelineFlowEngine';
import { buildInitialWorkflowRuns, computePipelineHealth } from './cicdPipelineData';
import { extractSuiteCriticalAlerts, calculateSocMetrics } from './socCommandEngine';
import type { ApiEndpointFinding, ScanFinding, ScannedFile, ScanReport } from '../types';
import type { PipelineArchitectConfig } from './pipelineFlowEngine';

export type ConsoleModuleKind = 'existing' | 'workspace' | 'text' | 'sample';

export interface ConsoleModule {
  id: string;
  kind: ConsoleModuleKind;
  command: string;
  aliases: string[];
}

const LAB = 'Laboratório. Mesmo cenário da tela. Não varre rede, host, feed nem console.';

export const CONSOLE_MODULES: ConsoleModule[] = [
  { id: 'scanner', kind: 'existing', command: 'scan', aliases: ['scan'] },
  { id: 'dataflow', kind: 'workspace', command: 'dataflow', aliases: [] },
  { id: 'endpoints', kind: 'existing', command: 'endpoints', aliases: [] },
  { id: 'entropy', kind: 'existing', command: 'entropy', aliases: [] },
  { id: 'jsminer', kind: 'workspace', command: 'jsminer', aliases: [] },
  { id: 'sca', kind: 'existing', command: 'sca', aliases: [] },
  { id: 'autoremediation', kind: 'workspace', command: 'autoremediation', aliases: [] },
  { id: 'refactoring', kind: 'workspace', command: 'refactoring', aliases: [] },
  { id: 'apisecurity', kind: 'workspace', command: 'apisecurity', aliases: [] },
  { id: 'dast', kind: 'workspace', command: 'dast', aliases: [] },
  { id: 'iast', kind: 'workspace', command: 'iast', aliases: [] },
  { id: 'headers', kind: 'existing', command: 'headers', aliases: [] },
  { id: 'jwtinspector', kind: 'existing', command: 'jwt', aliases: ['jwt'] },
  { id: 'ssrfvalidator', kind: 'existing', command: 'ssrf', aliases: ['ssrf'] },
  { id: 'waf', kind: 'sample', command: 'waf', aliases: [] },
  { id: 'nmap', kind: 'sample', command: 'nmap', aliases: [] },
  { id: 'nikto', kind: 'sample', command: 'nikto', aliases: [] },
  { id: 'iac', kind: 'existing', command: 'iac', aliases: [] },
  { id: 'containerscan', kind: 'existing', command: 'dockerfile', aliases: ['dockerfile'] },
  { id: 'cloudiam', kind: 'existing', command: 'iam', aliases: ['iam'] },
  { id: 'ngfw', kind: 'sample', command: 'ngfw', aliases: [] },
  { id: 'idsips', kind: 'sample', command: 'idsips', aliases: [] },
  { id: 'dnssec', kind: 'sample', command: 'dnssec', aliases: [] },
  { id: 'sdwan', kind: 'sample', command: 'sdwan', aliases: [] },
  { id: 'soccommand', kind: 'workspace', command: 'soccommand', aliases: [] },
  { id: 'securityonion', kind: 'workspace', command: 'securityonion', aliases: [] },
  { id: 'crowdstrike', kind: 'workspace', command: 'crowdstrike', aliases: [] },
  { id: 'edr', kind: 'sample', command: 'edr', aliases: [] },
  { id: 'dashboard', kind: 'workspace', command: 'dashboard', aliases: [] },
  { id: 'trenddashboard', kind: 'workspace', command: 'trenddashboard', aliases: [] },
  { id: 'ctihub', kind: 'text', command: 'ctihub', aliases: [] },
  { id: 'threatmodel', kind: 'workspace', command: 'threatmodel', aliases: [] },
  { id: 'policyascode', kind: 'workspace', command: 'policyascode', aliases: [] },
  { id: 'sbom', kind: 'existing', command: 'sbom', aliases: [] },
  { id: 'compliance', kind: 'existing', command: 'compliance', aliases: [] },
  { id: 'frameworks', kind: 'workspace', command: 'frameworks', aliases: [] },
  { id: 'asocsla', kind: 'workspace', command: 'asocsla', aliases: [] },
  { id: 'llmsecurity', kind: 'text', command: 'llmsecurity', aliases: [] },
  { id: 'soarbuilder', kind: 'sample', command: 'soarbuilder', aliases: [] },
  { id: 'procyber', kind: 'sample', command: 'procyber', aliases: [] },
  { id: 'rules', kind: 'sample', command: 'rules', aliases: [] },
  { id: 'cli', kind: 'sample', command: 'cli', aliases: [] },
  { id: 'pipelineflow', kind: 'workspace', command: 'pipelineflow', aliases: [] },
  { id: 'cicd', kind: 'workspace', command: 'cicd', aliases: [] },
];

export function resolveConsoleCommand(token: string): ConsoleModule | null {
  return CONSOLE_MODULES.find((module) => module.id === token || module.command === token || module.aliases.includes(token)) || null;
}

export function consoleListLines(): string[] {
  const groups = ['CODE_SAST', 'API_DAST', 'CLOUD_INFRA', 'SOC_EDR', 'GOV_AI'] as const;
  const lines = ['SecScan console. Um comando por módulo do app.', ''];
  for (const group of groups) {
    lines.push(group);
    for (const feature of FEATURE_REGISTRY.filter((item) => item.category === group)) {
      const module = CONSOLE_MODULES.find((item) => item.id === feature.id);
      const command = module?.command || feature.id;
      const note = module?.kind === 'sample' ? 'cenário da tela' : module?.kind === 'text' ? 'texto' : 'arquivos';
      lines.push(`  ${command.padEnd(18)} ${feature.name}  (${note})`);
    }
    lines.push('');
  }
  lines.push('O diretório padrão dos comandos de arquivo é o diretório atual.');
  lines.push('Comandos de cenário repetem a tela e não consultam rede, host, feed nem console.');
  lines.push('secscan --help mostra as opções do scan estático.');
  return lines;
}

export interface ConsoleRunInput {
  target: string;
  files: ScannedFile[];
  findings: ScanFinding[];
  text?: string;
  artifact?: { name: string; content: string };
}

export interface ConsoleRunResult {
  lines: string[];
  payload: unknown;
}

function countSeverity(findings: ScanFinding[]) {
  return {
    criticalCount: findings.filter((finding) => finding.severity === 'CRITICAL').length,
    highCount: findings.filter((finding) => finding.severity === 'HIGH').length,
    mediumCount: findings.filter((finding) => finding.severity === 'MEDIUM').length,
    lowCount: findings.filter((finding) => finding.severity === 'LOW').length,
    infoCount: findings.filter((finding) => finding.severity === 'INFO').length,
  };
}

function buildReport(input: ConsoleRunInput, endpoints: ApiEndpointFinding[]): ScanReport {
  const counts = countSeverity(input.findings);
  const risk = calculateCumulativeWorkspaceRiskScore(counts);
  const impactLevel = risk.riskLevel === 'MINIMAL'
    ? 'NOMINAL'
    : risk.riskLevel === 'MEDIUM'
      ? 'MODERATE'
      : risk.riskLevel;
  return {
    id: 'cli-workspace',
    timestamp: new Date().toISOString(),
    target: input.target,
    totalFiles: input.files.length,
    scannedFilesCount: input.files.length,
    ignoredFilesCount: 0,
    findings: input.findings,
    apiEndpoints: endpoints,
    metrics: {
      criticalCount: counts.criticalCount,
      highCount: counts.highCount,
      mediumCount: counts.mediumCount,
      lowCount: counts.lowCount,
      infoCount: counts.infoCount,
      securityScore: Math.max(0, 100 - risk.riskScore),
      securityImpactScore: risk.riskScore,
      impactLevel,
      totalWeightedRisk: risk.rawPoints,
      riskScore: risk.riskScore,
      riskLevel: risk.riskLevel,
      criticalityDistribution: { criticalFiles: 0, highFiles: 0, mediumFiles: 0, lowFiles: 0 },
      averageEntropy: 0,
    },
    durationMs: 0,
  };
}

function endpointsOf(files: ScannedFile[]): ApiEndpointFinding[] {
  return files.flatMap((file) => extractLinkFinderEndpoints(file.path, file.content));
}

function cap(lines: string[], limit = 40): string[] {
  if (lines.length <= limit) return lines;
  return [...lines.slice(0, limit), `... e mais ${lines.length - limit}`];
}

export function runConsoleModule(id: string, input: ConsoleRunInput): ConsoleRunResult {
  const endpoints = endpointsOf(input.files);
  const report = buildReport(input, endpoints);

  if (id === 'dataflow') {
    const sinks = input.files.flatMap((file) => analyzeWithJsMiner(file.path, file.content).dangerousSinks);
    const graph = buildDataFlowGraph(input.files, endpoints, sinks);
    return {
      lines: [
        `Data flow  arquivos=${graph.metrics.filesAnalyzed}  endpoints=${graph.metrics.totalEndpoints}  sinks=${graph.metrics.totalSinks}  fluxos=${graph.metrics.totalTaintFlows}`,
        ...cap((graph.taintFlows || []).map((flow) => `${flow.severity.padEnd(8)} ${flow.variableName} -> ${flow.sinkLabel}`)),
      ],
      payload: { metrics: graph.metrics, nodes: graph.nodes.length, links: graph.links.length },
    };
  }

  if (id === 'jsminer') {
    const mined = input.files.map((file) => analyzeWithJsMiner(file.path, file.content));
    const totals = mined.reduce((acc, item) => ({
      sourceMaps: acc.sourceMaps + item.sourceMaps.length,
      buckets: acc.buckets + item.cloudBuckets.length,
      jwt: acc.jwt + item.jwtTokens.length,
      sinks: acc.sinks + item.dangerousSinks.length,
    }), { sourceMaps: 0, buckets: 0, jwt: 0, sinks: 0 });
    const sinkLines = mined.flatMap((item) => item.dangerousSinks.map((sink) => `${sink.severity}  ${sink.sinkType}  ${sink.file}:${sink.line}`));
    return {
      lines: [
        `JS Miner  sourceMaps=${totals.sourceMaps}  buckets=${totals.buckets}  jwt=${totals.jwt}  sinks=${totals.sinks}`,
        ...cap(sinkLines),
      ],
      payload: totals,
    };
  }

  if (id === 'apisecurity') {
    const audit = auditApiSecurity(input.files);
    const safe = audit.findings.map((finding) => ({
      severity: finding.severity,
      title: finding.vulnerabilityTitle,
      file: finding.file,
      line: finding.line,
      endpoint: finding.endpoint,
    }));
    return {
      lines: [
        `API Security  endpoints=${audit.totalEndpointsAudited}  achados=${audit.vulnerableEndpointsCount}  score=${audit.apiRiskScore}`,
        ...cap(safe.map((finding) => `${finding.severity.padEnd(8)} ${finding.title}  ${finding.file}:${finding.line}`)),
      ],
      payload: { ...audit, findings: safe },
    };
  }

  if (id === 'autoremediation') {
    const patches = input.findings
      .map((finding) => generateRemediationPatchForFinding(finding, input.files))
      .filter((patch): patch is NonNullable<typeof patch> => patch !== null);
    return {
      lines: [
        `Remediação  achados=${input.findings.length}  patches=${patches.length}`,
        'Nenhum arquivo foi alterado.',
        ...cap(patches.map((patch) => `${patch.file}:${patch.line}  ${patch.title}`)),
      ],
      payload: patches.map((patch) => ({ file: patch.file, line: patch.line, title: patch.title, explanation: patch.explanation })),
    };
  }

  if (id === 'refactoring') {
    const recipes = findApplicableRecipes(input.files, input.findings);
    return {
      lines: [
        `Refactoring  receitas=${recipes.length}`,
        ...cap(recipes.map((item) => `${item.recipe.title}  ${item.matchedFile?.path || item.matchedFinding?.file || ''}`)),
      ],
      payload: recipes.map((item) => ({ title: item.recipe.title, file: item.matchedFile?.path || item.matchedFinding?.file || '' })),
    };
  }

  if (id === 'dast') {
    return {
      lines: [
        LAB,
        'DAST não envia requisição. Abaixo estão as rotas lidas no código.',
        `Rotas=${endpoints.length}`,
        ...cap(endpoints.map((endpoint) => `${endpoint.method || 'UNKNOWN'}  ${endpoint.path}  ${endpoint.file}:${endpoint.line}`)),
      ],
      payload: { mode: 'LOCAL_ROUTES', total: endpoints.length, endpoints },
    };
  }

  if (id === 'iast') {
    const emulation = runIastRuntimeEmulation(input.files, INITIAL_IAST_HOOKS, undefined, [], endpoints);
    const safe = emulation.findings.map((finding) => ({
      severity: finding.severity,
      title: finding.title,
      file: finding.sinkFile,
      line: finding.sinkLine,
      cwe: finding.cwe.id,
    }));
    return {
      lines: [
        `IAST  status=${emulation.status}  hooks=${emulation.totalHooksTriggered}  achados=${emulation.findings.length}`,
        'A emulação lê o código local e não envia tráfego.',
        ...cap(safe.map((finding) => `${finding.severity.padEnd(8)} ${finding.title}  ${finding.file}:${finding.line}`)),
      ],
      payload: { status: emulation.status, totalHooksTriggered: emulation.totalHooksTriggered, findings: safe },
    };
  }

  if (id === 'dashboard' || id === 'trenddashboard' || id === 'asocsla') {
    const asoc = buildAsocInventory(input.findings);
    const lines = [
      `Workspace  arquivos=${input.files.length}  achados=${input.findings.length}  risk=${report.metrics.riskScore}/100 ${report.metrics.riskLevel}`,
      `CRITICAL=${report.metrics.criticalCount} HIGH=${report.metrics.highCount} MEDIUM=${report.metrics.mediumCount} LOW=${report.metrics.lowCount} INFO=${report.metrics.infoCount}`,
    ];
    if (id !== 'dashboard') {
      lines.push(`SLA  conformidade=${asoc.metrics.slaCompliancePercentage}%  abertos=${asoc.metrics.openCount}  MTTR=${asoc.metrics.mttrHours}h`);
      lines.push('O gráfico de tendência da tela usa o histórico do navegador. Aqui entra só o workspace atual.');
    }
    return { lines, payload: { metrics: report.metrics, asoc: asoc.metrics } };
  }

  if (id === 'threatmodel') {
    const model = buildThreatModelFromWorkspace(input.findings, endpoints);
    return {
      lines: [
        `STRIDE  ameaças=${model.strideThreats.length}  ASVS=${model.compliancePercentage}%`,
        ...cap(model.strideThreats.map((threat) => `${threat.riskLevel.padEnd(8)} ${threat.category}  ${threat.title}`)),
      ],
      payload: model,
    };
  }

  if (id === 'policyascode') {
    const evaluation = evaluateAllOpaPolicies(DEFAULT_OPA_POLICIES, report);
    return {
      lines: [
        `OPA  veredito=${evaluation.verdict}  score=${evaluation.complianceScore}  políticas=${evaluation.totalPolicies}  violações=${evaluation.violatedCount}`,
        ...cap(evaluation.policyResults.map((policy) => `${policy.status.padEnd(10)} ${policy.policyName}`)),
      ],
      payload: { verdict: evaluation.verdict, complianceScore: evaluation.complianceScore, violatedCount: evaluation.violatedCount },
    };
  }

  if (id === 'frameworks') {
    const rows = NIST_CSF_SUBCATEGORIES.map((sub) => {
      const status = evaluateAutoNistStatus(sub, input.findings);
      return { id: sub.id, status: status.status, title: sub.title };
    });
    return {
      lines: [
        `NIST CSF  controles=${rows.length}`,
        ...cap(rows.map((row) => `${row.status.padEnd(14)} ${row.id}  ${row.title}`), 60),
      ],
      payload: rows,
    };
  }

  if (id === 'llmsecurity') {
    const analysis = analyzePromptForInjections(input.text || '');
    return {
      lines: [
        `LLM  veredito=${analysis.verdict}  score=${analysis.riskScore}`,
        ...analysis.detectedHeuristics.map((item) => `${item.category}  ${item.description}`),
      ],
      payload: { verdict: analysis.verdict, riskScore: analysis.riskScore, heuristics: analysis.detectedHeuristics },
    };
  }

  if (id === 'ctihub') {
    const summary = getThreatIntelSummary();
    const lookup = input.text ? lookupThreatIndicator(input.text) : null;
    const heatmap = computeCtiHeatmapMatrix(input.findings);
    const lines = [
      LAB,
      `Catálogo local  indicadores=${summary.totalIndicators}  campanhas=${summary.activeCampaignsCount}  modo=${summary.catalogMode}`,
      `Heatmap  achados sobrepostos=${heatmap.totalOverlayFindings}  hotspots críticos=${heatmap.criticalHotspotsCount}`,
    ];
    if (lookup) lines.push(`Consulta  ${lookup.verdict}  matches=${lookup.matchCount}`);
    return { lines, payload: { summary, lookup, heatmap: { totalOverlayFindings: heatmap.totalOverlayFindings, criticalHotspotsCount: heatmap.criticalHotspotsCount } } };
  }

  if (id === 'soccommand' || id === 'securityonion') {
    const alerts = extractSuiteCriticalAlerts(report, []);
    const metrics = calculateSocMetrics(alerts, 0);
    return {
      lines: [
        id === 'securityonion' ? 'Casos derivados dos achados locais. Não consulta um sensor Security Onion.' : 'Fila derivada dos achados locais. Não é um SOC ao vivo.',
        `Alertas=${alerts.length}  abertos=${metrics.openCasesCount}  CRITICAL=${metrics.criticalCount}  HIGH=${metrics.highCount}`,
        ...cap(alerts.map((alert) => `${alert.severity.padEnd(8)} ${alert.title}`)),
      ],
      payload: { openCasesCount: metrics.openCasesCount, alerts: alerts.map((alert) => ({ severity: alert.severity, title: alert.title, source: alert.source })) },
    };
  }

  if (id === 'crowdstrike') {
    if (input.files.length === 0) {
      return { lines: [LAB, 'Sem arquivos no workspace. A tela também fica sem host nesse caso.'], payload: { hosts: [] } };
    }
    const hosts = [
      { hostname: 'prod-api-gateway-01', threats: report.metrics.criticalCount },
      { hostname: 'worker-node-k8s-pod-7', threats: report.metrics.highCount },
      { hostname: 'dev-ci-runner-build-9', threats: 0 },
    ];
    return {
      lines: [LAB, 'Hosts de demonstração da tela. Não fala com a API da CrowdStrike.', ...hosts.map((host) => `${host.hostname}  ameaças=${host.threats}`)],
      payload: { hosts },
    };
  }

  if (id === 'pipelineflow') {
    const config: PipelineArchitectConfig = {
      workflowName: 'secscan',
      fileName: 'secscan.yml',
      triggerPush: true,
      triggerPullRequest: true,
      triggerSchedule: false,
      triggerWorkflowDispatch: true,
      branches: ['main'],
      runner: 'ubuntu-latest',
      nodeVersion: '22',
      uploadSarif: true,
      concurrencyGroup: true,
      stages: DEFAULT_PIPELINE_STAGES,
      steps: INITIAL_ACTION_STEPS,
      findingStageMapping: buildInitialFindingStageMapping(input.findings),
    };
    const simulation = simulatePipelineRun(config, input.findings);
    return {
      lines: [
        `Pipeline  ${simulation.overallStatus}`,
        ...Object.values(simulation.stageResults).map((stage) => `${stage.status.padEnd(8)} ${stage.stageTitle}  achados=${stage.breachingFindings.length}`),
      ],
      payload: { overallStatus: simulation.overallStatus, stages: Object.values(simulation.stageResults).map((stage) => ({ id: stage.stageId, status: stage.status })) },
    };
  }

  if (id === 'cicd') {
    const runs = buildInitialWorkflowRuns(report, 50);
    const health = computePipelineHealth(runs);
    return {
      lines: [
        'Histórico de exemplo calculado com os achados locais. Não lê o GitHub Actions.',
        `CI  sucesso=${health.successRatePercentage}%  runs=${health.totalRuns}  falhas=${health.failedRuns}  último=${health.lastRunStatus}`,
      ],
      payload: health,
    };
  }

  if (id === 'waf') {
    return {
      lines: [LAB, `WAF  regras=${INITIAL_WAF_RULES.length}  bloqueios de exemplo=${INITIAL_WAF_OVERVIEW.blockedAttacksToday}`, ...INITIAL_WAF_RULES.map((rule) => `${rule.action.padEnd(12)} ${rule.name}`)],
      payload: { rules: INITIAL_WAF_RULES.map((rule) => ({ name: rule.name, action: rule.action, enabled: rule.enabled })) },
    };
  }

  if (id === 'nmap') {
    const hosts = getDemoNmapHosts();
    return {
      lines: [LAB, `Hosts de exemplo=${hosts.length}`, ...hosts.map((host) => `${host.status.padEnd(6)} ${host.hostname}  ${host.ip}  portas abertas=${host.ports.filter((port) => port.state === 'OPEN').length}`)],
      payload: { hosts: hosts.map((host) => ({ hostname: host.hostname, ip: host.ip, status: host.status })) },
    };
  }

  if (id === 'nikto') {
    const targets = getDemoNiktoTargets();
    return {
      lines: [LAB, ...targets.map((target) => `${target.targetUrl}  falhas=${target.checksFailed}  achados=${target.findings.length}`)],
      payload: { targets: targets.map((target) => ({ url: target.targetUrl, failed: target.checksFailed, findings: target.findings.length })) },
    };
  }

  if (id === 'ngfw') {
    return {
      lines: [LAB, `NGFW  regras=${INITIAL_POLICY_RULES.length}  sessões de exemplo=${INITIAL_NGFW_METRICS.activeSessions}`, ...INITIAL_POLICY_RULES.map((rule) => `${rule.action.padEnd(8)} ${rule.ruleName}`)],
      payload: { rules: INITIAL_POLICY_RULES.map((rule) => ({ name: rule.ruleName, action: rule.action })) },
    };
  }

  if (id === 'idsips') {
    return {
      lines: [LAB, `IDS  regras=${INITIAL_IDS_RULES.length}  alertas=${INITIAL_IDS_ALERTS.length}  modo=${INITIAL_IDS_STATUS.mode}`, ...INITIAL_IDS_RULES.map((rule) => `${rule.action.padEnd(6)} ${rule.msg}`)],
      payload: { rules: INITIAL_IDS_RULES.length, alerts: INITIAL_IDS_ALERTS.length },
    };
  }

  if (id === 'dnssec') {
    return {
      lines: [
        LAB,
        `DNS  consultas de exemplo=${INITIAL_DNS_QUERIES.length}  bloqueadas=${INITIAL_DNS_OVERVIEW.blockedQueriesToday}`,
        ...INITIAL_DNSSEC_CHAINS.map((chain) => `${chain.rrsigStatus.padEnd(10)} ${chain.domain}`),
      ],
      payload: { chains: INITIAL_DNSSEC_CHAINS.map((chain) => ({ domain: chain.domain, status: chain.rrsigStatus })) },
    };
  }

  if (id === 'sdwan') {
    return {
      lines: [LAB, `SD-WAN  edges=${INITIAL_SDWAN_EDGES.length}  túneis=${INITIAL_SDWAN_TELEMETRY.totalDynamicTunnels}`, ...INITIAL_SDWAN_EDGES.map((edge) => `${edge.status.padEnd(8)} ${edge.name}`)],
      payload: { edges: INITIAL_SDWAN_EDGES.map((edge) => ({ name: edge.name, status: edge.status })) },
    };
  }

  if (id === 'edr') {
    return {
      lines: [
        LAB,
        `EDR  hosts=${INITIAL_HOST_ENDPOINTS.length}  bloqueios de exemplo=${INITIAL_EDR_TELEMETRY.blockedAttacksToday}`,
        ...INITIAL_HOST_ENDPOINTS.map((host) => `${host.isolationStatus.padEnd(10)} ${host.hostname}  alertas=${host.activeAlertsCount}`),
        ...INITIAL_BEHAVIORAL_RULES.map((rule) => rule.name),
      ],
      payload: { hosts: INITIAL_HOST_ENDPOINTS.map((host) => ({ hostname: host.hostname, isolation: host.isolationStatus })) },
    };
  }

  if (id === 'soarbuilder') {
    const runs = DEFAULT_SOAR_PLAYBOOKS.map((playbook) => executeSoarPlaybook(playbook));
    return {
      lines: [
        LAB,
        'A execução é local. Não abre chamado, não isola host e não chama firewall.',
        ...runs.map((run) => `${run.status.padEnd(8)} ${run.playbookName}  passos=${run.stepResults.length}`),
      ],
      payload: runs.map((run) => ({ name: run.playbookName, status: run.status, steps: run.stepResults.map((step) => step.stepName) })),
    };
  }

  if (id === 'procyber') {
    const bas = runBreachAttackSimulation();
    const emails = extractEmailsFromFiles(input.files.map((file) => ({ name: file.name, content: file.content })));
    const artifact = input.artifact ? analyzeArtifact(input.artifact.name, input.artifact.content) : null;
    return {
      lines: [
        LAB,
        `SOAR=${DEFAULT_SOAR_PLAYBOOKS.length}  Sigma=${SAMPLE_SIGMA_RULES.length}  CSPM=${SAMPLE_CSPM_FINDINGS.length}  EASM=${DEFAULT_EASM_ASSETS.length}`,
        `BAS  cobertura=${bas.defenseCoverageScore}%  bloqueados=${bas.blockedCount}  lacunas=${bas.gapCount}`,
        `Vault paths=${DEFAULT_VAULT_SECRETS.length}  certificados=${DEFAULT_TLS_CERTS.length}  supply-chain=${SAMPLE_SUPPLY_CHAIN_PACKAGES.length}`,
        `Dark web de exemplo=${SAMPLE_DARK_WEB_BREACHES.length}  e-mails no código=${emails.length}`,
        ...SAMPLE_CSPM_FINDINGS.map((finding) => `${finding.severity.padEnd(8)} ${finding.title}`),
        ...DEFAULT_EASM_ASSETS.map((asset) => asset.domain),
        ...DEFAULT_TLS_CERTS.map((cert) => `${cert.status.padEnd(14)} ${cert.domain}`),
        ...(artifact ? [`Artefato  ${artifact.fileName}  ${artifact.verdict}  score=${artifact.threatScore}`] : ['Passe --file <arquivo> para classificar um artefato local.']),
      ],
      payload: {
        bas: { coverage: bas.defenseCoverageScore, blocked: bas.blockedCount, gaps: bas.gapCount },
        sigma: SAMPLE_SIGMA_RULES.map((rule) => rule.title),
        emailsInCode: emails.length,
        artifact: artifact ? { file: artifact.fileName, verdict: artifact.verdict, score: artifact.threatScore } : null,
      },
    };
  }

  if (id === 'rules') {
    return {
      lines: [
        `Regras padrão=${DEFAULT_RULES.length}`,
        ...DEFAULT_RULES.map((rule) => `${(rule.enabled === false ? 'off' : 'on').padEnd(4)} ${rule.severity.padEnd(8)} ${rule.id}  ${rule.name}`),
      ],
      payload: DEFAULT_RULES.map((rule) => ({ id: rule.id, name: rule.name, severity: rule.severity, enabled: rule.enabled !== false })),
    };
  }

  if (id === 'cli') {
    return {
      lines: [
        'Este processo é o workspace de console.',
        'secscan list mostra cada módulo do app.',
        'secscan <módulo> [alvo] roda esse módulo sem abrir a interface.',
      ],
      payload: { modules: CONSOLE_MODULES.length },
    };
  }

  throw new Error(`Módulo sem implementação de console: ${id}`);
}
