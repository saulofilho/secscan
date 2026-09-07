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
  | 'CUSTOM_REGEX';

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
  type: 'SCAN_START' | 'FILE_PARSED' | 'SECRET_DETECTED' | 'DEP_IGNORED' | 'SCAN_COMPLETE' | 'ALERT_TRIGGERED' | 'RULE_APPLIED';
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

