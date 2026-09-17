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
  riskCategory?: string;
  cwe?: { id: string; name: string };
  connectionsCount?: number;
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
  label?: string;
  file: string;
}

export interface DataFlowGraphData {
  nodes: DataFlowNode[];
  links: DataFlowLink[];
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




