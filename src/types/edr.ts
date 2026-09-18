export type EdrProcessAction = 'ALLOW' | 'SUSPICIOUS' | 'TERMINATE' | 'QUARANTINE' | 'ISOLATE';

export interface EdrProcessNode {
  pid: number;
  ppid: number;
  name: string;
  commandLine: string;
  hashSha256: string;
  user: string;
  integrityLevel: 'SYSTEM' | 'HIGH' | 'MEDIUM' | 'LOW';
  startTime: string;
  threatScore: number; // 0 - 100
  actionTaken: EdrProcessAction;
  networkConnections: {
    protocol: 'TCP' | 'UDP';
    localPort: number;
    remoteAddress: string;
    remotePort: number;
    state: 'ESTABLISHED' | 'LISTENING' | 'SYN_SENT' | 'CLOSED';
  }[];
  fileModifications: string[];
  children?: EdrProcessNode[];
}

export interface EdrBehavioralRule {
  id: string;
  name: string;
  mitreTactic: 'Initial Access' | 'Execution' | 'Persistence' | 'Privilege Escalation' | 'Credential Access' | 'Defense Evasion' | 'Lateral Movement' | 'Exfiltration';
  mitreTechnique: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  triggerCondition: string;
  autoRemediation: 'KILL_PROCESS_TREE' | 'QUARANTINE_FILE' | 'ISOLATE_HOST' | 'ALERT_ONLY';
  active: boolean;
  hitsCount: number;
}

export interface EdrMemoryDumpAnalysis {
  id: string;
  endpointHostname: string;
  processName: string;
  pid: number;
  dumpSizeMb: number;
  extractedSecretsCount: number;
  yaraRuleMatches: string[];
  injectedDlls: string[];
  hollowedMemoryRegions: boolean;
  status: 'ANALYZED' | 'PROCESSING' | 'FLAGGED';
  timestamp: string;
}

export interface EdrThreatHuntingQuery {
  id: string;
  title: string;
  category: 'LOLBINS' | 'PERSISTENCE' | 'CREDENTIAL_DUMPING' | 'REVERSE_SHELL';
  queryText: string;
  matchesFound: number;
  description: string;
}

export interface EdrLiveTelemetry {
  agentStatus: 'HEALTHY' | 'DEGRADED' | 'ISOLATED';
  kernelDriver: 'eBPF / Windows Filter Driver (Active)';
  totalMonitoredProcesses: number;
  blockedAttacksToday: number;
  quarantinedBinaries: number;
  networkSensorsActive: number;
  tamperProtection: 'ENABLED (Protected Process Light)';
}
