export type WanLinkType = 'MPLS_DEDICATED' | 'INTERNET_DIA_FIBER' | '5G_LTE_BACKUP' | 'STARLINK_SATELLITE';

export type WanLinkStatus = 'OPTIMAL' | 'DEGRADED' | 'FAILOVER_ACTIVE' | 'DOWN';

export type SlaHealthStatus = 'IN_SLA' | 'VIOLATING_SLA' | 'CRITICAL';

export interface SdwanEdgeDevice {
  id: string;
  name: string; // Ex: "Edge-HQ-SaoPaulo", "Edge-Branch-NovaIorque"
  location: string;
  role: 'HUB' | 'SPOKE' | 'GATEWAY';
  firmwareVersion: string;
  ipsecTunnelCount: number;
  cpuLoadPct: number;
  memoryUsagePct: number;
  activeWanLinks: SdwanLink[];
  status: 'ONLINE' | 'STANDBY' | 'OFFLINE';
}

export interface SdwanLink {
  id: string;
  name: string;
  type: WanLinkType;
  provider: string; // Ex: "Embratel Dedicated", "Lumen DIA", "Claro 5G"
  bandwidthCapacityMbps: number;
  currentThroughputMbps: number;
  latencyMs: number;
  jitterMs: number;
  packetLossPct: number;
  status: WanLinkStatus;
  encryption: 'IPsec AES-256-GCM (IKEv2)' | 'WireGuard ChaCha20';
}

export interface SdwanTrafficPolicy {
  id: string;
  name: string;
  applicationClass: 'VOIP_TEAMS_ZOOM' | 'PAYMENT_CORE_API' | 'ERP_SAP_SALESFORCE' | 'GENERAL_INTERNET_YOUTUBE';
  priorityOrder: number; // 1 = Highest
  slaRequirement: {
    maxLatencyMs: number;
    maxJitterMs: number;
    maxPacketLossPct: number;
  };
  preferredLink: WanLinkType;
  secondaryLink: WanLinkType;
  activeSteeringRoute: string;
  forwardErrorCorrection: boolean; // FEC ativo em perda de pacotes
  packetDuplication: boolean; // Envio simultâneo em 2 links para jitter zero
}

export interface SdwanTunnelMesh {
  sourceEdge: string;
  destEdge: string;
  transportType: 'DIRECT_UNDERLAY' | 'OVERLAY_IPSEC_VPN';
  currentLatency: number;
  activeLinkUsed: string;
  encryptionState: 'SECURE_ESTABLISHED' | 'REKEYING' | 'DISCONNECTED';
}

export interface SdwanNetworkTelemetry {
  orchestratorStatus: 'SYNCHRONIZED (Zero-Touch Provisioning Active)';
  totalSitesOnline: number;
  totalDynamicTunnels: number;
  trafficOptimizedTodayGb: number;
  failoversHandledWithoutDrop: number;
  globalAvgLatencyMs: number;
  globalAvgPacketLossPct: number;
}
