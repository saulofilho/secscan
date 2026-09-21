// ============================================================================
// SECSCAN - NEW SECURITY TOOLS TYPE DEFINITIONS
// Covers: Security Headers/CSP, Container/Dockerfile, Cloud IAM, JWT, SSRF
// ============================================================================

// ----------------------------------------------------------------------------
// 1. HTTP SECURITY HEADERS & CSP
// ----------------------------------------------------------------------------
export type HeaderGrade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

export interface SecurityHeaderRule {
  headerName: string;
  category: 'XSS_CSP' | 'TRANSPORT' | 'FRAMING' | 'ISOLATION' | 'PRIVACY' | 'SNIFFING';
  importance: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  recommendedValue: string;
  description: string;
  securityImpact: string;
  cwe: string;
  docUrl: string;
}

export interface HeaderEvaluationResult {
  headerName: string;
  configuredValue: string | null;
  isPresent: boolean;
  isCompliant: boolean;
  score: number; // 0-100
  status: 'OPTIMAL' | 'ACCEPTABLE' | 'WEAK' | 'MISSING';
  rule: SecurityHeaderRule;
  issues: string[];
  remediationSnippet: string;
}

export interface CspDirective {
  name: string;
  description: string;
  values: string[];
  isEssential: boolean;
  riskWarning?: string;
}

export interface SecurityHeadersAuditReport {
  targetUrl: string;
  grade: HeaderGrade;
  totalScore: number; // 0-100
  headersEvaluated: HeaderEvaluationResult[];
  criticalMissing: string[];
  recommendationsCount: number;
  serverConfigSnippets: {
    nginx: string;
    apache: string;
    expressHelmet: string;
    nextConfig: string;
    caddy: string;
  };
}

// ----------------------------------------------------------------------------
// 2. CONTAINER & DOCKERFILE SECURITY (Trivy / Hadolint)
// ----------------------------------------------------------------------------
export type ContainerSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface DockerfileFinding {
  id: string;
  ruleCode: string; // e.g., 'DL3002', 'DL3004', 'CIS-4.1'
  title: string;
  severity: ContainerSeverity;
  lineNumber: number;
  lineContent: string;
  description: string;
  remediation: string;
  cwe: string;
  mitreTechnique?: string;
  suggestedPatch: string;
}

export interface ContainerBaseImageAudit {
  baseImage: string;
  tag: string;
  isOutdated: boolean;
  latestSecureTag: string;
  isPinnedByHash: boolean;
  knownCveCount: number;
  criticalCves: string[];
}

export interface ContainerAuditReport {
  imageOrDockerfileName: string;
  totalScore: number; // 0 - 100
  status: 'SECURE' | 'NEEDS_REVIEW' | 'CRITICAL_RISK';
  baseImageAudit: ContainerBaseImageAudit;
  findings: DockerfileFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  hardenedDockerfileSnippet: string;
}

// ----------------------------------------------------------------------------
// 3. CLOUD IAM & CSPM LEAST-PRIVILEGE AUDITOR
// ----------------------------------------------------------------------------
export type IamRiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface IamPolicyFinding {
  id: string;
  title: string;
  severity: IamRiskLevel;
  category: 'PRIVILEGE_ESCALATION' | 'WILDCARD_ACTION' | 'WILDCARD_RESOURCE' | 'PUBLIC_EXPOSURE' | 'CREDENTIAL_EXPOSURE' | 'MISSING_MFA';
  affectedStatementIndex: number;
  affectedActionOrResource: string;
  description: string;
  attackVector: string;
  remediation: string;
  cwe: string;
  benchmark: string; // e.g. 'AWS CIS 1.16', 'NIST 800-53 AC-6'
}

export interface IamAuditReport {
  policyName: string;
  riskScore: number; // 0 (Worst) - 100 (Best)
  posture: 'NON_COMPLIANT' | 'OVERPRIVILEGED' | 'HARDENED';
  findings: IamPolicyFinding[];
  wildcardActionsDetected: string[];
  wildcardResourcesDetected: string[];
  privilegeEscalationVectors: string[];
  leastPrivilegePolicySnippet: string;
}

// ----------------------------------------------------------------------------
// 4. JWT & API TOKEN FORENSIC INSPECTOR
// ----------------------------------------------------------------------------
export type JwtAlgorithmType = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'none' | 'UNKNOWN';

export interface JwtClaimAudit {
  claim: string;
  value: any;
  status: 'VALID' | 'WARNING' | 'CRITICAL_RISK' | 'MISSING';
  detail: string;
}

export interface JwtVulnerability {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  description: string;
  cwe: string;
  exploitScenario: string;
  remediation: string;
}

export interface JwtAuditReport {
  rawToken: string;
  isValidFormat: boolean;
  header: Record<string, any>;
  payload: Record<string, any>;
  signature: string;
  algorithm: JwtAlgorithmType;
  isExpired: boolean;
  expiresAt: string | null;
  issuedAt: string | null;
  claimsAudit: JwtClaimAudit[];
  vulnerabilities: JwtVulnerability[];
  isWeakSecretDetected: boolean;
  guessedSecret?: string;
  securityScore: number; // 0-100
}

// ----------------------------------------------------------------------------
// 5. SSRF & WEBHOOK SAFETY VALIDATOR
// ----------------------------------------------------------------------------
export type SsrfRisk = 'BLOCKED_CRITICAL' | 'BLOCKED_PRIVATE' | 'RISK_DETECTED' | 'SAFE';

export interface SsrfCheckResult {
  url: string;
  resolvedIp?: string;
  hostname: string;
  scheme: string;
  port: number;
  isPrivateOrLoopback: boolean;
  isCloudMetadata: boolean;
  isDecimalOrHexBypass: boolean;
  riskLevel: SsrfRisk;
  classification: string;
  attackTechnique: string;
  remediationAdvice: string;
  safeClientExample: string;
}
