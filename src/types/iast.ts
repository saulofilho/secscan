import { SeverityLevel } from '../types';

/**
 * Types of instrumentation hooks installed by the IAST agent during runtime emulation
 */
export type IastHookCategory = 
  | 'HTTP_REQUEST_SOURCE'
  | 'SQL_DATABASE_SINK'
  | 'NOSQL_INJECTION_SINK'
  | 'COMMAND_EXEC_SINK'
  | 'FILE_SYSTEM_TRAVERSAL_SINK'
  | 'DOM_XSS_SINK'
  | 'SSRF_NETWORK_SINK'
  | 'INSECURE_DESERIALIZATION_SINK'
  | 'CRYPTO_ALGO_SINK'
  | 'AUTH_HEADER_SOURCE';

export type IastTaintStatus = 'TAINTED' | 'SANITIZED' | 'UNTAINTED';

export type IastFindingStatus = 'CONFIRMED' | 'SUSPECTED' | 'BLOCKED_BY_GUARD' | 'SAFE';

/**
 * An individual trace event captured by an IAST instrumentation hook
 */
export interface IastTraceStep {
  stepIndex: number;
  hookId: string;
  hookCategory: IastHookCategory;
  file: string;
  line: number;
  functionName: string;
  variableName: string;
  runtimeValue: string;
  isTainted: boolean;
  sanitizationApplied?: string;
  description: string;
  stackFrame?: string;
}

/**
 * An IAST vulnerability finding discovered specifically through runtime emulation hooks
 */
export interface IastVulnerabilityFinding {
  id: string;
  title: string;
  cwe: { id: string; name: string };
  owaspCategory: string;
  severity: SeverityLevel;
  confidence: number; // 0 - 100%
  status: IastFindingStatus;
  sourceEndpoint: string;
  httpMethod: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  taintedParameter: string;
  simulatedPayload: string;
  sinkFunction: string;
  sinkFile: string;
  sinkLine: number;
  tracePath: IastTraceStep[];
  runtimeCallStack: string[];
  vulnerabilityExplanation: string;
  runtimeEvidence: {
    executedQueryOrCommand: string;
    unfilteredTaintSubstring: string;
    sanitizerBypassed?: string;
    runtimeDurationMs: number;
  };
  remediationAdvice: string;
  remediationCodeExample: {
    vulnerable: string;
    secure: string;
  };
}

/**
 * Runtime Hook Sensor definition
 */
export interface IastHookSensor {
  id: string;
  name: string;
  category: IastHookCategory;
  targetPackageOrGlobal: string; // e.g., 'child_process.exec', 'mysql.query', 'fetch', 'fs.readFile'
  active: boolean;
  interceptedCallsCount: number;
  vulnerabilitiesTriggeredCount: number;
  description: string;
}

/**
 * Interactive Simulation Scenario for IAST Emulation
 */
export interface IastSimulationScenario {
  id: string;
  name: string;
  targetRoute: string;
  httpMethod: 'GET' | 'POST' | 'PUT' | 'DELETE';
  inputPayload: Record<string, any>;
  vulnerabilityTarget: string;
  description: string;
  attackVectorType: 'SQLi' | 'Command Injection' | 'Path Traversal' | 'SSRF' | 'DOM XSS' | 'Insecure Deserialization';
}

/**
 * Summary and metrics for IAST Execution
 */
export interface IastExecutionReport {
  sessionId: string;
  timestamp: string;
  status: 'IDLE' | 'EMULATING' | 'COMPLETED' | 'ERROR';
  totalEmulatedRequests: number;
  totalHooksTriggered: number;
  findings: IastVulnerabilityFinding[];
  activeHooks: IastHookSensor[];
  coverageMetrics: {
    endpointsInstrumented: number;
    sinksCovered: number;
    taintPropagationSuccessRate: number; // e.g. 98.4%
    falsePositiveReductionPercent: number; // e.g. 85%
    avgInspectionOverheadMs: number;
  };
}
