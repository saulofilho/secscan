import { FindingCategory, SeverityLevel } from '../types';

export type NmapScanTechnique = 
  | 'SYN_STEALTH'    // -sS
  | 'CONNECT'        // -sT
  | 'UDP'            // -sU
  | 'VERSION_DETECTION' // -sV
  | 'OS_DETECTION'   // -O
  | 'SCRIPT_NSE'     // -sC / --script
  | 'AGGRESSIVE'     // -A
  | 'PING_SWEEP';    // -sn

export type NmapPortState = 'OPEN' | 'FILTERED' | 'CLOSED' | 'OPEN|FILTERED' | 'UNFILTERED';

export type NmapScriptCategory = 
  | 'auth'
  | 'broadcast'
  | 'brute'
  | 'default'
  | 'discovery'
  | 'dos'
  | 'exploit'
  | 'external'
  | 'fuzzer'
  | 'intrusive'
  | 'malware'
  | 'safe'
  | 'version'
  | 'vuln';

export interface NmapPortService {
  port: number;
  protocol: 'tcp' | 'udp';
  state: NmapPortState;
  service: string;
  version: string;
  product?: string;
  extraInfo?: string;
  cpe?: string;
  confidence: number; // 0 to 10
  bannerSnippet?: string;
  riskSeverity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cveMatches?: string[];
  remediation?: string;
}

export interface NmapScriptResult {
  id: string;
  name: string;
  category: NmapScriptCategory;
  output: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cve?: string;
  cvss?: number;
  recommendation: string;
  scriptSource?: string;
}

export interface NmapHostTarget {
  id: string;
  hostname: string;
  ip: string;
  macAddress?: string;
  vendor?: string;
  osFingerprint: {
    name: string;
    family: string;
    accuracy: number; // 0 - 100
    cpe: string;
    deviceType: string;
  };
  latencyMs: number;
  status: 'UP' | 'DOWN';
  ports: NmapPortService[];
  scriptResults: NmapScriptResult[];
  tracerouteHops?: {
    hop: number;
    rttMs: number;
    ip: string;
    hostname?: string;
  }[];
  originFinding?: string;
}

export interface NmapScanProfile {
  id: string;
  name: string;
  cliFlags: string;
  description: string;
  timingTemplate: 'T0' | 'T1' | 'T2' | 'T3' | 'T4' | 'T5';
  technique: NmapScanTechnique;
  detectOS: boolean;
  detectServices: boolean;
  runScripts: boolean;
  scriptArg?: string;
  portsRange: string;
}

export interface NmapSuiteSession {
  sessionId: string;
  timestamp: string;
  commandExecuted: string;
  timingTemplate: string;
  durationSeconds: number;
  hostsScanned: number;
  hostsUp: number;
  totalOpenPorts: number;
  vulnerabilitiesDetected: number;
  targets: NmapHostTarget[];
  rawConsoleOutput: string;
}
