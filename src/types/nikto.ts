export type NiktoTuningCategory =
  | 'FILE_CHECK'          // 1: Interesting File / seen in logs
  | 'MISCONFIG_DEFAULT'   // 2: Misconfiguration / Default File
  | 'INFO_DISCLOSURE'     // 3: Information Disclosure
  | 'INJECTION_XSS'       // 4: Injection (XSS/Scripting)
  | 'REMOTE_FILE_RET'     // 5: Remote File Retrieval
  | 'DENIAL_OF_SERVICE'   // 6: Denial of Service
  | 'REMOTE_COMMAND'      // 7: Remote File Execution / Command Injection
  | 'SQL_INJECTION'       // 9: SQL Injection
  | 'FILE_UPLOAD'         // 0: File Upload
  | 'SOFTWARE_VERSION'    // b: Software / Component Version
  | 'SECURITY_HEADER';    // c: Security Headers & Cookies

export type NiktoFindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface NiktoCheckItem {
  id: string;
  osvdb?: number;
  uri: string;
  httpMethod: 'GET' | 'POST' | 'HEAD' | 'OPTIONS' | 'TRACE' | 'PUT' | 'DELETE';
  tuningCode: string; // e.g. "1", "2", "3", "b", "c"
  category: NiktoTuningCategory;
  severity: NiktoFindingSeverity;
  description: string;
  serverBannerSnippet?: string;
  matchPattern?: string;
  recommendation: string;
  remediationSnippet?: string;
  referenceUrl?: string;
}

export interface NiktoSecurityHeaderCheck {
  headerName: string;
  status: 'MISSING' | 'WEAK' | 'VALID';
  expectedValue: string;
  actualValue?: string;
  riskDescription: string;
  remediationSnippet: string;
}

export interface NiktoHttpMethodsAudit {
  method: string;
  allowed: boolean;
  isDangerous: boolean;
  statusResponse: number;
  riskNote?: string;
}

export interface NiktoTargetProfile {
  id: string;
  targetUrl: string;
  host: string;
  port: number;
  useSsl: boolean;
  webServerBanner: string;
  serverVersion: string;
  ip: string;
  responseTimeMs: number;
  securityHeaders: NiktoSecurityHeaderCheck[];
  httpMethods: NiktoHttpMethodsAudit[];
  checksPassed: number;
  checksFailed: number;
  findings: NiktoCheckItem[];
}

export interface NiktoScanOptions {
  targetUrl: string;
  port: number;
  useSsl: boolean;
  tuningCategories: string[]; // e.g. ['1', '2', '3', 'b', 'c']
  customUserAgent: string;
  timeoutSeconds: number;
  evasionTechnique?: 'NONE' | 'RANDOM_ENCODING' | 'FAKE_HEADER' | 'URI_WHITESPACE';
  singleHostScanOnly: boolean;
}

export interface NiktoScanSession {
  sessionId: string;
  timestamp: string;
  cliCommand: string;
  durationSeconds: number;
  target: NiktoTargetProfile;
  rawConsoleOutput: string;
}
