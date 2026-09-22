export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FileCriticalityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface FileCriticalityInfo {
  level: FileCriticalityLevel;
  weight: number;
  category: string;
  reason: string;
}

export type FindingCategory = 
  | 'CLOUD_CREDENTIAL' 
  | 'API_KEY' 
  | 'AUTH_TOKEN' 
  | 'DATABASE_URI' 
  | 'PRIVATE_KEY' 
  | 'API_PATH' 
  | 'PASSWORD' 
  | 'CUSTOM_REGEX'
  | 'TAINT_SINK'
  | 'ENTROPY';

export interface RegexRule {
  id: string;
  name: string;
  pattern: string; // regex string
  flags?: string;
  category: FindingCategory;
  severity: SeverityLevel;
  description: string;
  remediation: string;
  minEntropy?: number;
  enabled: boolean;
  isCustom?: boolean;
  tags?: string[];
  exampleMatch?: string;
}

export interface RegexUnitTestCase {
  id: string;
  name: string;
  pattern: string;
  flags: string;
  testInput: string;
  expectedMatchCount: number;
  expectedMatches: string[];
  expectedGroups?: {
    groupIndex: number;
    name?: string;
    value: string;
  }[];
  category?: FindingCategory;
  severity?: SeverityLevel;
  tags?: string[];
  description?: string;
  createdAt: string;
  lastRunStatus?: 'PASSED' | 'FAILED' | 'PENDING';
  lastRunMessage?: string;
  lastRunAt?: string;
  lastActualCount?: number;
  lastActualMatches?: string[];
}

export interface RegexTestSuiteSummary {
  totalTests: number;
  passedCount: number;
  failedCount: number;
  pendingCount: number;
  lastRunTimestamp?: string;
  passRatePercentage: number;
}

export interface RuleRegressionResult {
  testCaseId: string;
  testCaseName: string;
  category?: FindingCategory;
  severity?: SeverityLevel;
  pattern: string;
  expectedMatches: string[];
  expectedCount: number;
  status: 'PASSED' | 'FAILED';
  matchedRuleId?: string;
  matchedRuleName?: string;
  actualMatches: string[];
  message: string;
  durationMs: number;
}

export interface RuleRegressionReport {
  timestamp: string;
  totalTests: number;
  passedCount: number;
  failedCount: number;
  passRate: number;
  activeRulesCount: number;
  results: RuleRegressionResult[];
}

export interface OfficialDocLink {
  provider: 'OWASP' | 'SNYK' | 'CWE' | 'NIST';
  title: string;
  url: string;
  badge: string;
  description?: string;
  cheatSheetUrl?: string;
}

export interface ScanFinding {
  id: string;
  ruleId: string;
  ruleName: string;
  category: FindingCategory;
  severity: SeverityLevel;
  file: string;
  line: number;
  column: number;
  snippet: string;
  matchedSecret: string;
  maskedSecret: string;
  entropy: number;
  description: string;
  remediation: string;
  timestamp: string;
  isFalsePositive?: boolean;
  fileCriticality?: FileCriticalityLevel;
  fileCriticalityWeight?: number;
  weightedScore?: number;
  riskScore?: number;
  documentationLinks?: OfficialDocLink[];
  riskScoreDetails?: {
    baseRuleScore: number;
    categoryAdjustment: number;
    entropyAdjustment: number;
    contextMultiplier: number;
    finalScore: number;
    assignedSeverity: SeverityLevel;
    factors: string[];
  };
  threatIntelTag?: FindingThreatIntelTag;
}

export interface ApiEndpointFinding {
  id: string;
  file: string;
  line: number;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'ALL' | 'UNKNOWN';
  path: string;
  isInternalOrAdmin: boolean;
  snippet: string;
  // LinkFinder extensions
  urlType?: 'RELATIVE_PATH' | 'FULL_URL' | 'WEBSOCKET' | 'GRAPHQL' | 'STATIC_ASSET';
  scope?: 'IN_SCOPE' | 'EXTERNAL' | 'CDN' | 'INTERNAL';
  params?: string[];
  sourceTool?: 'LINK_FINDER' | 'JS_MINER' | 'SECSCAN_AST';
  curlCommand?: string;
}

// JS Miner specific types
export interface SourceMapFinding {
  id: string;
  file: string;
  line: number;
  url: string;
  type: 'EXTERNAL_FILE' | 'INLINE_BASE64' | 'EXPOSED_DIR';
  snippet: string;
  riskDescription: string;
}

export interface CloudBucketFinding {
  id: string;
  provider: 'AWS_S3' | 'GOOGLE_CLOUD_STORAGE' | 'AZURE_BLOB' | 'DIGITAL_OCEAN' | 'FIREBASE';
  bucketName: string;
  url: string;
  file: string;
  line: number;
  snippet: string;
  riskDescription: string;
  checkCommand?: string;
}

export interface JwtTokenFinding {
  id: string;
  token: string;
  file: string;
  line: number;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  algorithm: string;
  isExpired: boolean;
  expiresAt?: string;
  issuer?: string;
  subject?: string;
  roles?: string[];
  risks: string[];
}

export interface BundledDependencyFinding {
  id: string;
  name: string;
  version: string;
  file: string;
  line: number;
  confidence: 'HIGH' | 'MEDIUM';
  status: 'VULNERABLE' | 'OUTDATED' | 'OK';
  cveAdvisory?: string;
  description: string;
}

export interface DangerousSinkFinding {
  id: string;
  sinkType: 'EVAL' | 'INNER_HTML' | 'DOCUMENT_WRITE' | 'POST_MESSAGE' | 'INSECURE_STORAGE' | 'FUNCTION_CONSTRUCTOR';
  file: string;
  line: number;
  snippet: string;
  severity: SeverityLevel;
  description: string;
  remediation: string;
}

export interface JsMinerResults {
  sourceMaps: SourceMapFinding[];
  cloudBuckets: CloudBucketFinding[];
  jwtTokens: JwtTokenFinding[];
  dependencies: BundledDependencyFinding[];
  dangerousSinks: DangerousSinkFinding[];
  totalAssetsCount: number;
}

export interface ScannedFile {
  name: string;
  path: string;
  content: string;
  size: number;
  extension: string;
  isIgnored?: boolean;
  ignoreReason?: string;
  findingsCount?: number;
  lastModified?: number | string;
}

export interface ScanReport {
  id: string;
  timestamp: string;
  target: string;
  totalFiles: number;
  scannedFilesCount: number;
  ignoredFilesCount: number;
  findings: ScanFinding[];
  apiEndpoints: ApiEndpointFinding[];
  jsMiner?: JsMinerResults;
  dataFlowGraph?: DataFlowGraphData;
  iastReport?: import('./types/iast').IastExecutionReport;
  iacReport?: import('./lib/iacScanner').IacReport;
  apiSecurityReport?: import('./types').ApiSecurityReport;
  scaReport?: import('./lib/scaScanner').ScaAnalysisReport;
  metrics: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    securityScore: number; // 0 - 100 (Compliance / Health)
    securityImpactScore: number; // 0 - 100 (Weighted Risk Impact: 0 = Nominal, 100 = Catastrophic)
    impactLevel: 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'MODERATE' | 'LOW' | 'NOMINAL';
    totalWeightedRisk: number;
    // Cumulative Workspace Risk Score (0 - 100) based on severity and count of detected vulnerabilities
    riskScore: number;
    riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'MINIMAL';
    workspaceRiskBreakdown?: {
      rawPoints: number;
      criticalCount: number;
      highCount: number;
      mediumCount: number;
      lowCount: number;
      infoCount: number;
      criticalPoints: number;
      highPoints: number;
      mediumPoints: number;
      lowPoints: number;
      infoPoints: number;
      formula: string;
      maxThreshold?: number;
      isThresholdExceeded?: boolean;
    };
    criticalityDistribution: {
      criticalFiles: number;
      highFiles: number;
      mediumFiles: number;
      lowFiles: number;
    };
    averageEntropy: number;
    averageRiskScore?: number;
    maxRiskScore?: number;
    // LinkFinder & JS Miner metrics
    linkFinderTotalEndpoints?: number;
    jsMinerTotalAssets?: number;
    jsMinerCloudBucketsCount?: number;
    jsMinerSourceMapsCount?: number;
    jsMinerDangerousSinksCount?: number;
  };
  durationMs: number;
}

export interface AuditLogEvent {
  id: string;
  timestamp: string;
  type: 'SCAN_START' | 'FILE_PARSED' | 'SECRET_DETECTED' | 'DEP_IGNORED' | 'SCAN_COMPLETE' | 'ALERT_TRIGGERED' | 'RULE_APPLIED' | 'FIX_APPLIED';
  message: string;
  severity?: SeverityLevel;
  durationMs?: number;
  details?: Record<string, unknown>;
}

export interface CliCommandHistory {
  id: string;
  command: string;
  output: string;
  timestamp: string;
  exitCode: number;
}

export type ScheduleInterval = 
  | 'HOURLY' 
  | 'DAILY_MIDNIGHT' 
  | 'WEEKLY_SUNDAY' 
  | 'WEEKDAY_MORNING' 
  | 'EVERY_6_HOURS'
  | 'CUSTOM_CRON';

export type CiCdProvider = 'github-actions' | 'gitlab-ci' | 'circleci' | 'jenkins' | 'azure-pipelines';

export interface ScanSchedule {
  id: string;
  name: string;
  repository: string;
  branch: string;
  cronExpression: string;
  intervalPreset: ScheduleInterval;
  provider: CiCdProvider;
  enabled: boolean;
  failOnSeverity: SeverityLevel;
  notifyChannels: ('webhook' | 'email' | 'pr_comment')[];
  lastRun?: {
    timestamp: string;
    status: 'SUCCESS' | 'FAILED' | 'WARNING';
    findingsCount: number;
    securityImpactScore: number;
    durationMs: number;
  };
  nextRun: string;
  createdAt: string;
}

export interface IgnorePatternItem {
  id: string;
  pattern: string;
  enabled: boolean;
  description?: string;
  isBuiltIn?: boolean;
  createdAt: string;
}

// Data Flow Graph & Taint Analysis Types
export type DataFlowNodeType = 'ENDPOINT' | 'CONSUMER' | 'SINK';

export type DataFlowLinkType = 'ENDPOINT_TO_CONSUMER' | 'CONSUMER_TO_SINK' | 'DIRECT_FLOW';

export interface TaintVariableFlow {
  id: string;
  variableName: string;
  sourceNodeId: string;
  sourceLabel: string;
  sourceParamOrField: string;
  intermediateNodeIds: string[];
  sinkNodeId: string;
  sinkLabel: string;
  sinkType: DangerousSinkFinding['sinkType'] | string;
  pathNodeIds: string[];
  pathLinkIds: string[];
  severity: SeverityLevel;
  riskCategory: string;
  cwe?: { id: string; name: string };
  description: string;
  variableTransformSummary: string;
}

export interface DataFlowNode {
  id: string;
  type: DataFlowNodeType;
  label: string;
  sublabel?: string;
  file: string;
  line: number;
  method?: string;
  urlType?: string;
  scope?: string;
  isInternalOrAdmin?: boolean;
  sinkType?: DangerousSinkFinding['sinkType'];
  severity?: SeverityLevel;
  snippet?: string;
  remediation?: string;
  description?: string;
  tainted?: boolean;
  taintedVariables?: string[];
  taintRole?: 'SOURCE' | 'PROPAGATOR' | 'SINK';
  riskCategory?: string;
  cwe?: { id: string; name: string };
  connectionsCount?: number;
  // Delta fields
  deltaStatus?: DataFlowNodeDeltaStatus;
  isNewlyTainted?: boolean;
  deltaReason?: string;
  isGhostRemoved?: boolean;
  previousTainted?: boolean;
  // D3 force layout fields
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
  vx?: number;
  vy?: number;
  index?: number;
}

export interface DataFlowLink {
  id: string;
  source: string | DataFlowNode;
  target: string | DataFlowNode;
  flowType: DataFlowLinkType;
  isTainted: boolean;
  taintedVariable?: string;
  taintedVariableList?: string[];
  label?: string;
  file: string;
  // Delta fields
  deltaStatus?: DataFlowLinkDeltaStatus;
  isNewlyTainted?: boolean;
  isGhostRemoved?: boolean;
  deltaReason?: string;
}

export type DataFlowNodeDeltaStatus = 'NEW' | 'MODIFIED' | 'REMOVED' | 'UNCHANGED';
export type DataFlowLinkDeltaStatus = 'NEW' | 'NEWLY_TAINTED' | 'REMEDIATED' | 'REMOVED' | 'UNCHANGED';

export type DataFlowVulnerabilityDeltaType = 'NEW_VULNERABILITY' | 'RESOLVED_VULNERABILITY' | 'PERSISTENT_VULNERABILITY';

export interface DataFlowVulnerabilityDelta {
  id: string;
  type: DataFlowVulnerabilityDeltaType;
  flow: TaintVariableFlow;
  severity: SeverityLevel;
  changeReason: string;
  introducedInFile: string;
  introducedAtLine?: number;
  variableName: string;
  sourceLabel: string;
  sinkLabel: string;
  riskCategory: string;
  cwe?: { id: string; name: string };
  remediationAdvice: string;
  codeSnippetPreview?: string;
}

export interface DataFlowDeltaAnalysis {
  hasPreviousAnalysis: boolean;
  baselineName?: string;
  previousTimestamp?: string;
  currentTimestamp?: string;
  nodeDeltaMap: Record<string, {
    status: DataFlowNodeDeltaStatus;
    isNewlyTainted: boolean;
    previousTainted?: boolean;
    currentTainted?: boolean;
    newlyAddedVariables?: string[];
    changeDescription?: string;
  }>;
  linkDeltaMap: Record<string, {
    status: DataFlowLinkDeltaStatus;
    isNewlyTainted: boolean;
    changeDescription?: string;
  }>;
  vulnerabilityDeltas: DataFlowVulnerabilityDelta[];
  newVulnerabilities: DataFlowVulnerabilityDelta[];
  resolvedVulnerabilities: DataFlowVulnerabilityDelta[];
  persistentVulnerabilities: DataFlowVulnerabilityDelta[];
  metrics: {
    newVulnerabilitiesCount: number;
    resolvedVulnerabilitiesCount: number;
    netVulnerabilityDelta: number; // e.g. +2
    newNodesCount: number;
    removedNodesCount: number;
    modifiedNodesCount: number;
    newlyTaintedNodesCount: number;
    newLinksCount: number;
    riskStatus: 'REGRESSION_CRITICAL' | 'REGRESSION_WARNING' | 'IMPROVED' | 'NEUTRAL';
  };
  removedNodes: DataFlowNode[];
  removedLinks: DataFlowLink[];
}

export interface DataFlowGraphData {
  nodes: DataFlowNode[];
  links: DataFlowLink[];
  taintFlows?: TaintVariableFlow[];
  metrics: {
    totalEndpoints: number;
    totalConsumers: number;
    totalSinks: number;
    totalTaintFlows: number;
    criticalSinksCount: number;
    filesAnalyzed: number;
  };
}

export type DataFlowLayoutMode = 'HIERARCHICAL' | 'FORCE' | 'PIPELINE' | 'FILE_GROUPS';

export interface DataFlowGraphSettings {
  layoutMode: DataFlowLayoutMode;
  hierarchicalOrientation: 'HORIZONTAL' | 'VERTICAL';
  rankSeparation: number;
  nodeSeparation: number;
  curveStyle: 'BEZIER' | 'STRAIGHT';
  alignSinksToEnd: boolean;
  chargeStrength: number;
  linkDistance: number;
  collisionRadius: number;
  isPhysicsPaused: boolean;
  hideIsolatedNodes: boolean;
  showLevelGuides: boolean;
  highlightTaintEdges: boolean;
  highlightTaintedVariables?: boolean;
  showVariableLabelsOnLinks?: boolean;
}

export interface WorkspaceRiskValidation {
  riskScore: number;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'MINIMAL';
  status: 'PASS' | 'WARN' | 'FAIL';
  maxAllowedRiskScore: number;
  isCompliant: boolean;
  reasons: string[];
  findingsSummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  scoreBreakdown: {
    criticalContribution: number;
    highContribution: number;
    mediumContribution: number;
    lowContribution: number;
    infoContribution: number;
    rawSum: number;
    saturatedScore: number;
  };
}

export interface GeminiRefactorStep {
  findingId: string;
  ruleName: string;
  category: string;
  severity: SeverityLevel;
  file: string;
  line: number;
  riskImpact: string;
  rootCauseAnalysis: string;
  securePattern: string;
  refactorSteps: string[];
  beforeCode: string;
  afterCode: string;
  estimatedRiskReductionPoints: number;
  mitigationPriority: 'P0 - BLOQUEANTE' | 'P1 - CRÍTICO' | 'P2 - ALTO';
}

export interface GeminiMitigationReport {
  source: 'gemini' | 'rule_engine';
  model: string;
  timestamp: string;
  executiveSummary: string;
  totalPotentialRiskReduction: number;
  projectedNewRiskScore: number;
  willPassQualityGate: boolean;
  suggestions: GeminiRefactorStep[];
  actionPlan: string[];
}

export type ScanPhase = 
  | 'INITIALIZING' 
  | 'SECRETS_SCAN' 
  | 'LINK_FINDER' 
  | 'JS_MINER' 
  | 'DATA_FLOW' 
  | 'IAST_EMULATION'
  | 'FINALIZING' 
  | 'COMPLETED';

export interface ScanProgress {
  percentage: number; // 0 to 100
  currentFileIndex: number;
  totalFiles: number;
  currentFileName: string;
  currentFilePath: string;
  phase: ScanPhase;
  phaseLabel: string;
  findingsFoundCount: number;
  scannedCount: number;
  ignoredCount: number;
  elapsedMs: number;
}

// Compliance Frameworks and Readiness Mapping Types
export type ComplianceFrameworkId = 'SOC2' | 'HIPAA' | 'OWASP_TOP_10' | 'PCI_DSS' | 'ISO_27001';

export type ComplianceControlStatus = 'COMPLIANT' | 'DEGRADED' | 'AT_RISK';

export interface ComplianceControlDefinition {
  id: string;
  framework: ComplianceFrameworkId;
  frameworkName: string;
  code: string;
  title: string;
  category: string;
  description: string;
  auditImplication: string;
  recommendedRemediation: string;
  severityThreshold: SeverityLevel;
  matchingCategories: FindingCategory[];
  matchingRuleIds?: string[];
  matchingKeywords?: string[];
  docUrl?: string;
}

export interface EvaluatedComplianceControl extends ComplianceControlDefinition {
  status: ComplianceControlStatus;
  matchingFindings: ScanFinding[];
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  riskPoints: number;
}

export interface FrameworkReadinessSummary {
  framework: ComplianceFrameworkId;
  name: string;
  badge: string;
  shortDescription: string;
  totalControls: number;
  compliantControls: number;
  atRiskControls: number;
  degradedControls: number;
  readinessPercentage: number;
  status: ComplianceControlStatus;
  violatingFindingsCount: number;
}

export interface GlobalComplianceAssessment {
  overallReadinessPercentage: number;
  overallStatus: ComplianceControlStatus;
  totalControlsEvaluated: number;
  totalControlsAtRisk: number;
  totalControlsDegraded: number;
  totalControlsCompliant: number;
  frameworksAtRiskCount: number;
  totalFrameworksCount: number;
  frameworkSummaries: Record<ComplianceFrameworkId, FrameworkReadinessSummary>;
  evaluatedControls: EvaluatedComplianceControl[];
}

// CI/CD Pipeline Health & GitHub Actions Integration Types
export type WorkflowRunStatus = 'completed' | 'in_progress' | 'queued';
export type WorkflowConclusion = 'success' | 'failure' | 'cancelled' | 'timed_out';
export type WorkflowTriggerEvent = 'push' | 'pull_request' | 'workflow_dispatch' | 'schedule';

export interface WorkflowLogLine {
  timestamp: string;
  level: 'INFO' | 'WARN' | 'ERROR' | 'DEBUG';
  message: string;
  findingId?: string;
  highlight?: boolean;
}

export interface WorkflowLogStep {
  id: string;
  name: string;
  status: 'success' | 'failed' | 'running' | 'skipped';
  durationSeconds: number;
  lines: WorkflowLogLine[];
}

export interface WorkflowRun {
  id: string;
  runNumber: number;
  title: string;
  event: WorkflowTriggerEvent;
  status: WorkflowRunStatus;
  conclusion: WorkflowConclusion | null;
  branch: string;
  commitSha: string;
  commitMessage: string;
  actor: {
    name: string;
    avatar?: string;
    isBot?: boolean;
  };
  startedAt: string;
  durationSeconds: number;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  riskScore: number;
  qualityGateStatus: 'PASSED' | 'FAILED_CRITICAL' | 'FAILED_THRESHOLD';
  sarifUploaded: boolean;
  workflowFile: string;
  steps: WorkflowLogStep[];
  rawLogs?: string;
}

export interface CiCdPipelineHealthSummary {
  successRatePercentage: number;
  totalRuns: number;
  successfulRuns: number;
  failedRuns: number;
  inProgressRuns: number;
  averageDurationSeconds: number;
  lastRunStatus: 'success' | 'failure' | 'in_progress' | 'unknown';
  lastRunTimestamp: string;
  runnerStatus: 'ONLINE' | 'BUSY' | 'OFFLINE';
  webhookStatus: 'ACTIVE' | 'PENDING' | 'ERROR';
  branchProtectionActive: boolean;
  sarifCodeScanningActive: boolean;
}

export interface SuggestedFixEnvConfig {
  variableName: string;
  exampleLine: string;
  instructions: string;
}

export interface SuggestedFixResult {
  source: 'gemini' | 'rule_engine';
  model: string;
  timestamp: string;
  findingId: string;
  ruleName: string;
  vulnerabilityType: string;
  cweOwaspReference: string;
  securePattern: string;
  replacementSnippet: string;
  beforeSnippet: string;
  explanation: string;
  envConfig?: SuggestedFixEnvConfig;
  securityChecklist: string[];
  diff?: {
    removed: string[];
    added: string[];
  };
}

export type RemediationSeverityKey = 'CRITICAL' | 'HIGH' | 'WARNING';

export interface SeverityRemediationConfig {
  remediationTime: string; // Dynamic MTTR (e.g. '1.5h – 2h')
  slaTarget?: string;
  tier?: string;
  badgeCode?: string;
  urgencyLevel?: string;
  description?: string;
  recommendedAction?: string;
}

export interface SecScanGlobalConfig {
  version: string;
  appName: string;
  remediationTime: {
    CRITICAL: string;
    HIGH: string;
    WARNING: string;
  };
  severityConfig: {
    CRITICAL: SeverityRemediationConfig;
    HIGH: SeverityRemediationConfig;
    WARNING: SeverityRemediationConfig;
    [key: string]: SeverityRemediationConfig;
  };
  dynamicMttrCalculation?: boolean;
  maxAllowedMttrHours?: number; // Configured maximum MTTR limit threshold in hours
  idealBenchmarkMttrHours?: number; // Target benchmark ideal MTTR in hours (e.g. 2.0h)
  [key: string]: unknown;
}

export type MitreTacticId =
  | 'TA0001' // Initial Access
  | 'TA0002' // Execution
  | 'TA0003' // Persistence
  | 'TA0004' // Privilege Escalation
  | 'TA0006' // Credential Access
  | 'TA0007' // Discovery
  | 'TA0008' // Lateral Movement
  | 'TA0009' // Collection
  | 'TA0010'; // Exfiltration

export interface MitreD3fendCountermeasure {
  id: string; // e.g. D3-SCRA
  name: string;
  category: 'Model' | 'Harden' | 'Detect' | 'Isolate' | 'Deceive' | 'Evict';
  description: string;
  implementationGuide: string;
  verificationMethod: string;
  docUrl: string;
}

export interface MitreAttackTechnique {
  id: string; // e.g. T1552.001
  tacticId: MitreTacticId;
  tacticName: string;
  name: string;
  description: string;
  adversaryObjective: string;
  matchedKeywords: string[]; // for correlating findings
  d3fendCountermeasures: MitreD3fendCountermeasure[];
  docUrl: string;
}

export type NistCsfFunctionId = 'GV' | 'ID' | 'PR' | 'DE' | 'RS' | 'RC';

export type NistAuditStatus = 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT' | 'UNDER_REVIEW';

export interface NistCsfSubcategory {
  id: string; // e.g. PR.AA-01
  functionId: NistCsfFunctionId;
  functionName: string;
  categoryName: string;
  title: string;
  requirement: string;
  devSecOpsAction: string;
  verificationEvidence: string;
  docUrl: string;
  autoCheckKeywords?: string[];
}

export type WstgTestStatus = 'PASSED' | 'FAILED' | 'IN_PROGRESS' | 'NOT_TESTED';

export interface OwaspWstgTestCase {
  id: string; // e.g. WSTG-CONF-04
  categoryCode: 'INFO' | 'CONF' | 'IDNT' | 'ATHN' | 'ATHZ' | 'SESS' | 'INPV' | 'CRYP' | 'BUSL';
  categoryTitle: string;
  title: string;
  objective: string;
  methodology: string;
  cliVerification: string;
  remediationAdvice: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  docUrl: string;
  correlatedRules?: string[];
}

export type ThreatIntelSource = 'ALIENVAULT_OTX' | 'ABUSE_CH_URLHAUS' | 'ABUSE_CH_THREATFOX' | 'ABUSE_CH_FEODO' | 'CISA_KEV';

export type ThreatIndicatorType = 'IP' | 'DOMAIN' | 'URL' | 'HASH_SHA256' | 'CVE' | 'API_SIGNATURE';

export interface ThreatIntelActivity {
  id: string;
  source: ThreatIntelSource;
  sourceName: string;
  indicator: string;
  indicatorType: ThreatIndicatorType;
  threatType: string;
  malwareFamily?: string;
  confidenceScore: number; // 0 - 100
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  firstSeen: string;
  lastSeen: string;
  tags: string[];
  referenceUrl: string;
  asnOrCountry?: string;
  status: 'ACTIVE' | 'INVESTIGATING' | 'MITIGATED';
  matchedFindingId?: string;
  matchedFindingTitle?: string;
  defenseAction: string;
}

export interface ThreatIntelFeedSummary {
  totalIndicators: number;
  activeCampaignsCount: number;
  lastSyncTimestamp: string;
  sourcesOnline: {
    name: string;
    source: ThreatIntelSource;
    status: 'ONLINE' | 'DEGRADED' | 'RATE_LIMITED';
    indicatorsCount: number;
    latencyMs: number;
  }[];
}

// ==========================================
// API Security & BOLA/IDOR Inspector Types
// ==========================================
export type OwaspApiCategory =
  | 'API1:2023_BOLA'
  | 'API2:2023_BROKEN_AUTH'
  | 'API3:2023_BOPLA'
  | 'API4:2023_UNRESTRICTED_RESOURCE'
  | 'API5:2023_BFLA'
  | 'API6:2023_SSRF'
  | 'API7:2023_SECURITY_MISCONFIG'
  | 'API8:2023_LACK_PROTECTION'
  | 'API9:2023_IMPROPER_INVENTORY'
  | 'API10:2023_UNSAFE_CONSUMPTION';

export interface ApiSecurityFinding {
  id: string;
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  category: OwaspApiCategory;
  categoryTitle: string;
  severity: SeverityLevel;
  vulnerabilityTitle: string;
  description: string;
  impact: string;
  cwe: string;
  remediation: string;
  sampleExploitCurl: string;
  securedCodeSnippet: string;
  vulnerableParam?: string;
  file?: string;
  line?: number;
}

export interface ApiSecurityReport {
  timestamp: string;
  totalEndpointsAudited: number;
  vulnerableEndpointsCount: number;
  apiRiskScore: number;
  findings: ApiSecurityFinding[];
  summaryByCategory: Record<string, number>;
  summaryBySeverity: Record<SeverityLevel, number>;
}

// ==========================================
// ASOC & Vulnerability SLA Manager Types
// ==========================================
export type SlaStatus = 'WITHIN_SLA' | 'NEARING_BREACH' | 'BREACHED' | 'REMEDIATED' | 'ACCEPTED_EXCEPTION';

export interface ManagedVulnerabilityItem {
  id: string;
  findingId?: string;
  title: string;
  severity: SeverityLevel;
  category: string;
  sourceFile: string;
  line: number;
  firstDiscovered: string; // ISO date
  slaDeadline: string; // ISO date
  remainingHours: number;
  slaStatus: SlaStatus;
  slaPolicyHours: number;
  assignedOwner: string;
  assignedTeam: 'AppSec' | 'Backend' | 'DevOps' | 'Frontend' | 'SecOps';
  remediationCostHours: number;
  status: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'EXCEPTION_APPROVED';
  exceptionReason?: string;
  exceptionExpiresAt?: string;
  mitreTactic?: string;
  cveOrCwe?: string;
}

export interface AsocSlaMetrics {
  totalVulnerabilities: number;
  openCount: number;
  resolvedCount: number;
  withinSlaCount: number;
  nearingBreachCount: number;
  breachedCount: number;
  exceptionsCount: number;
  mttrHours: number; // Mean Time To Remediate
  slaCompliancePercentage: number;
  securityDebtScore: number; // 0-100 debt level
  teamPerformance: {
    team: string;
    open: number;
    breached: number;
    complianceRate: number;
  }[];
}

export type SocTimeFilterRange = '1H' | '6H' | '24H' | '7D' | '30D' | 'ALL';

export interface SocTrendDataPoint {
  timestamp: string;
  label: string;
  criticalAlerts: number;
  highAlerts: number;
  auditEvents: number;
  mttrCurrentHours: number;
  resolvedIncidents: number;
}

export interface SocCriticalAlert {
  id: string;
  timestamp: string;
  title: string;
  severity: SeverityLevel;
  source: 'SAST' | 'SCA' | 'IaC' | 'API_SECURITY' | 'EDR' | 'WAF' | 'SECRETS';
  status: 'NEW' | 'TRIAGED' | 'ACKNOWLEDGED' | 'RESOLVED' | 'SUPPRESSED';
  targetResource: string;
  cweOrMitre: string;
  description: string;
  mttrTargetHours: number;
  elapsedHours: number;
  remediationAdvice: string;
  rawPayload?: Record<string, unknown>;
}

export type RefactoringCategory = 
  | 'CRYPTOGRAPHY'
  | 'AUTHENTICATION'
  | 'INJECTION'
  | 'SECRETS'
  | 'DATA_VALIDATION'
  | 'NETWORK_SSRF'
  | 'FILE_SYSTEM'
  | 'DESERIALIZATION';

export interface SecurityRefactoringRecipe {
  id: string;
  title: string;
  category: RefactoringCategory;
  severity: SeverityLevel;
  cwe: string;
  cweUrl: string;
  owasp: string;
  owaspUrl: string;
  cvssReduction: {
    before: number;
    after: number;
  };
  language: 'typescript' | 'javascript' | 'python' | 'go' | 'sql' | 'docker';
  legacyLibraryOrPattern: string;
  modernReplacement: string;
  shortSummary: string;
  vulnerabilityExplanation: string;
  modernSolutionExplanation: string;
  prerequisites: string[]; // e.g. ["npm install argon2", "node >= 18.0.0"]
  breakingChangesWarning?: string;
  beforeCode: string;
  afterCode: string;
  unifiedDiff: string;
  fileMatchPatterns?: string[]; // regex or file patterns that match this vulnerability
  defaultTargetFileName?: string;
  tags: string[];
}

// ==========================================
// CYBER THREAT INTELLIGENCE (CTI) HUB TYPES
// ==========================================

export type ThreatIntelFeedId = 
  | 'ALIENVAULT_OTX' 
  | 'CISA_KEV' 
  | 'MISP_CIRCL' 
  | 'ABUSE_IPDB' 
  | 'URLHAUS' 
  | 'MITRE_CTI';

export interface ThreatIntelFeedStatus {
  id: ThreatIntelFeedId;
  name: string;
  provider: string;
  status: 'LIVE' | 'CONNECTED' | 'SYNCING' | 'RATE_LIMITED' | 'ERROR';
  pulseCount: number;
  iocCount: number;
  lastSyncTimestamp: string;
  apiEndpoint: string;
  isRealtimeEnabled: boolean;
  reliabilityScore: number; // 0 - 100
  badge: string;
}

export interface ThreatActorProfile {
  id: string;
  name: string;
  codeName: string;
  aliases: string[];
  origin: string;
  motivation: 'FINANCIAL' | 'ESPIONAGE' | 'SABOTAGE' | 'RANSOMWARE' | 'EXTORTION';
  activeSectors: string[];
  associatedMalware: string[];
  targetedTechnologies: string[];
  ttps: {
    techniqueId: string;
    name: string;
    tactic: string;
  }[];
  threatScore: number; // 0 - 100
  activeCampaigns: string[];
  recentIocSignatures: string[];
  description: string;
  firstObserved: string;
  lastActive: string;
}

export type ThreatIocType = 
  | 'IPv4' 
  | 'domain' 
  | 'URL' 
  | 'hash_sha256' 
  | 'hash_md5' 
  | 'cve' 
  | 'api_key_pattern' 
  | 'email';

export interface ThreatIocItem {
  id: string;
  type: ThreatIocType;
  indicator: string;
  title?: string;
  confidence: number; // 0 - 100
  severity: SeverityLevel;
  firstSeen: string;
  lastSeen: string;
  sourceFeed: ThreatIntelFeedId;
  threatActor?: string;
  maliciousContext: string;
  relatedPulses?: string[];
}

export interface OtxPulse {
  id: string;
  name: string;
  author: string;
  description: string;
  created: string;
  modified: string;
  tlp: 'WHITE' | 'GREEN' | 'AMBER' | 'RED';
  tags: string[];
  adversary?: string;
  targetedCountries?: string[];
  malwareFamilies?: string[];
  subscriberCount: number;
  iocs: ThreatIocItem[];
  cves?: string[];
  referenceUrl?: string;
}

export interface FindingThreatIntelTag {
  findingId: string;
  threatActor?: ThreatActorProfile;
  matchingPulses: OtxPulse[];
  matchingIocs: ThreatIocItem[];
  campaigns: string[];
  cisaKevExploited: boolean;
  cisaKevDueDate?: string;
  cisaKevRansomwareCampaign?: boolean;
  threatActorTtp?: string;
  riskScoreAmplifier: number; // e.g. 1.5 multiplier
  threatSummary: string;
  remediationUrgency: 'IMMEDIATE_ACTION' | 'HIGH_PRIORITY' | 'MONITOR';
  detectedAt: string;
}

export interface CtiFilterOptions {
  search: string;
  feedId: ThreatIntelFeedId | 'ALL';
  threatActor: string | 'ALL';
  iocType: ThreatIocType | 'ALL';
  cisaKevOnly: boolean;
  minConfidence: number;
}








