export type IdsMode = 'IDS_PASSIVE' | 'IPS_INLINE';

export type IdsEngineType = 'SIGNATURE_SURICATA' | 'ANOMALY_HEURISTIC' | 'PROTOCOL_DECODER';

export type IdsAction = 'ALERT' | 'DROP' | 'REJECT' | 'PASS' | 'LOG';

export type IdsSeverity = '1_HIGH' | '2_MEDIUM' | '3_LOW' | '4_INFO';

export interface SnortSuricataRule {
  id: string;
  sid: number;
  rev: number;
  action: IdsAction;
  protocol: 'tcp' | 'udp' | 'icmp' | 'ip' | 'http' | 'tls' | 'dns';
  srcIp: string;
  srcPort: string;
  direction: '->' | '<>';
  dstIp: string;
  dstPort: string;
  msg: string;
  contentMatches: string[];
  classtype: string;
  cve?: string;
  reference?: string;
  enabled: boolean;
  hitsCount: number;
  rawRuleString: string;
}

export interface IdsLiveAlert {
  id: string;
  timestamp: string;
  sid: number;
  engine: IdsEngineType;
  severity: IdsSeverity;
  category: string;
  signatureMsg: string;
  actionTaken: IdsAction;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: string;
  packetHexPayload: string;
  packetAsciiPayload: string;
  pcapPacketNo: number;
  interfaceName: string;
}

export interface IdsAnomalyMetric {
  metricName: string;
  currentValue: number;
  baselineThreshold: number;
  status: 'NORMAL' | 'ELEVATED' | 'ANOMALOUS';
  unit: string;
  description: string;
}

export interface IdsSystemStatus {
  mode: IdsMode;
  afPacketThreads: number;
  activeRulesCount: number;
  packetsInspectedPerSec: number;
  droppedPacketsPerSec: number;
  zeroCopyInterface: string;
  memoryUsageMb: number;
  reassembledTcpStreams: number;
}
