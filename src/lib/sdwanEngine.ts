import {
  SdwanEdgeDevice,
  SdwanTrafficPolicy,
  SdwanTunnelMesh,
  SdwanNetworkTelemetry
} from '../types/sdwan';

export const INITIAL_SDWAN_EDGES: SdwanEdgeDevice[] = [
  {
    id: 'edge-hq-sp',
    name: 'Edge-HQ-SaoPaulo-Datacenter',
    location: '🇧🇷 São Paulo, SP (HQ Central)',
    role: 'HUB',
    firmwareVersion: 'v6.4.2-SecureOS',
    ipsecTunnelCount: 14,
    cpuLoadPct: 34,
    memoryUsagePct: 48,
    status: 'ONLINE',
    activeWanLinks: [
      {
        id: 'link-sp-mpls',
        name: 'WAN1 (MPLS Corporativo)',
        type: 'MPLS_DEDICATED',
        provider: 'Embratel MetroEthernet',
        bandwidthCapacityMbps: 1000,
        currentThroughputMbps: 480,
        latencyMs: 8.2,
        jitterMs: 1.1,
        packetLossPct: 0.0,
        status: 'OPTIMAL',
        encryption: 'IPsec AES-256-GCM (IKEv2)'
      },
      {
        id: 'link-sp-dia',
        name: 'WAN2 (Internet Fibra Direta)',
        type: 'INTERNET_DIA_FIBER',
        provider: 'Lumen Global Tier-1',
        bandwidthCapacityMbps: 1000,
        currentThroughputMbps: 620,
        latencyMs: 14.5,
        jitterMs: 2.3,
        packetLossPct: 0.05,
        status: 'OPTIMAL',
        encryption: 'IPsec AES-256-GCM (IKEv2)'
      },
      {
        id: 'link-sp-5g',
        name: 'WAN3 (5G Redundância Crítica)',
        type: '5G_LTE_BACKUP',
        provider: 'Claro 5G Standalone',
        bandwidthCapacityMbps: 300,
        currentThroughputMbps: 12,
        latencyMs: 28.0,
        jitterMs: 4.8,
        packetLossPct: 0.1,
        status: 'OPTIMAL',
        encryption: 'WireGuard ChaCha20'
      }
    ]
  },
  {
    id: 'edge-branch-rj',
    name: 'Edge-Filial-RioDeJaneiro',
    location: '🇧🇷 Rio de Janeiro, RJ',
    role: 'SPOKE',
    firmwareVersion: 'v6.4.2-SecureOS',
    ipsecTunnelCount: 4,
    cpuLoadPct: 18,
    memoryUsagePct: 29,
    status: 'ONLINE',
    activeWanLinks: [
      {
        id: 'link-rj-dia',
        name: 'WAN1 (Fibra Primária)',
        type: 'INTERNET_DIA_FIBER',
        provider: 'Vivo Fibra Dedicada',
        bandwidthCapacityMbps: 500,
        currentThroughputMbps: 210,
        latencyMs: 12.1,
        jitterMs: 1.8,
        packetLossPct: 0.0,
        status: 'OPTIMAL',
        encryption: 'IPsec AES-256-GCM (IKEv2)'
      },
      {
        id: 'link-rj-5g',
        name: 'WAN2 (Backup Celular)',
        type: '5G_LTE_BACKUP',
        provider: 'TIM 5G Ultra',
        bandwidthCapacityMbps: 200,
        currentThroughputMbps: 0,
        latencyMs: 31.4,
        jitterMs: 5.2,
        packetLossPct: 0.2,
        status: 'OPTIMAL',
        encryption: 'IPsec AES-256-GCM (IKEv2)'
      }
    ]
  },
  {
    id: 'edge-branch-ny',
    name: 'Edge-Branch-NewYork',
    location: '🇺🇸 Nova York, NY (Escritório Internacional)',
    role: 'GATEWAY',
    firmwareVersion: 'v6.4.2-SecureOS',
    ipsecTunnelCount: 6,
    cpuLoadPct: 27,
    memoryUsagePct: 41,
    status: 'ONLINE',
    activeWanLinks: [
      {
        id: 'link-ny-dia1',
        name: 'WAN1 (Verizon Fios Business)',
        type: 'INTERNET_DIA_FIBER',
        provider: 'Verizon Enterprise',
        bandwidthCapacityMbps: 1000,
        currentThroughputMbps: 450,
        latencyMs: 108.4,
        jitterMs: 3.1,
        packetLossPct: 0.08,
        status: 'OPTIMAL',
        encryption: 'IPsec AES-256-GCM (IKEv2)'
      },
      {
        id: 'link-ny-starlink',
        name: 'WAN2 (Starlink Low-Orbit Backup)',
        type: 'STARLINK_SATELLITE',
        provider: 'SpaceX Starlink Business',
        bandwidthCapacityMbps: 220,
        currentThroughputMbps: 45,
        latencyMs: 125.0,
        jitterMs: 8.5,
        packetLossPct: 0.35,
        status: 'OPTIMAL',
        encryption: 'WireGuard ChaCha20'
      }
    ]
  },
  {
    id: 'edge-plant-curitiba',
    name: 'Edge-Industria-Curitiba',
    location: '🇧🇷 Curitiba, PR (Fábrica / OT)',
    role: 'SPOKE',
    firmwareVersion: 'v6.4.2-SecureOS',
    ipsecTunnelCount: 3,
    cpuLoadPct: 22,
    memoryUsagePct: 35,
    status: 'ONLINE',
    activeWanLinks: [
      {
        id: 'link-cwb-dia',
        name: 'WAN1 (Copel Telecom)',
        type: 'INTERNET_DIA_FIBER',
        provider: 'Copel Telecom',
        bandwidthCapacityMbps: 300,
        currentThroughputMbps: 180,
        latencyMs: 19.3,
        jitterMs: 2.1,
        packetLossPct: 0.0,
        status: 'OPTIMAL',
        encryption: 'IPsec AES-256-GCM (IKEv2)'
      },
      {
        id: 'link-cwb-5g',
        name: 'WAN2 (Claro 5G Industrial)',
        type: '5G_LTE_BACKUP',
        provider: 'Claro 5G Industrial IoT',
        bandwidthCapacityMbps: 150,
        currentThroughputMbps: 0,
        latencyMs: 35.0,
        jitterMs: 6.0,
        packetLossPct: 0.0,
        status: 'OPTIMAL',
        encryption: 'IPsec AES-256-GCM (IKEv2)'
      }
    ]
  }
];

export const INITIAL_TRAFFIC_POLICIES: SdwanTrafficPolicy[] = [
  {
    id: 'pol-voip',
    name: 'QoS Crítico: Voz sobre IP, Zoom & Teams',
    applicationClass: 'VOIP_TEAMS_ZOOM',
    priorityOrder: 1,
    slaRequirement: {
      maxLatencyMs: 150,
      maxJitterMs: 15,
      maxPacketLossPct: 0.5
    },
    preferredLink: 'MPLS_DEDICATED',
    secondaryLink: 'INTERNET_DIA_FIBER',
    activeSteeringRoute: 'Roteado dinamicamente via MPLS (Jitter 1.1ms)',
    forwardErrorCorrection: true,
    packetDuplication: true
  },
  {
    id: 'pol-payment',
    name: 'Transações de Pagamento & Core Bancário (PCI-DSS)',
    applicationClass: 'PAYMENT_CORE_API',
    priorityOrder: 2,
    slaRequirement: {
      maxLatencyMs: 80,
      maxJitterMs: 10,
      maxPacketLossPct: 0.1
    },
    preferredLink: 'MPLS_DEDICATED',
    secondaryLink: 'INTERNET_DIA_FIBER',
    activeSteeringRoute: 'Túnel IPsec Overlay com Criptografia Forte AES-256-GCM',
    forwardErrorCorrection: true,
    packetDuplication: false
  },
  {
    id: 'pol-erp',
    name: 'Aplicações de Negócios: SAP S/4HANA & Salesforce',
    applicationClass: 'ERP_SAP_SALESFORCE',
    priorityOrder: 3,
    slaRequirement: {
      maxLatencyMs: 250,
      maxJitterMs: 30,
      maxPacketLossPct: 1.5
    },
    preferredLink: 'INTERNET_DIA_FIBER',
    secondaryLink: '5G_LTE_BACKUP',
    activeSteeringRoute: 'Balanceado por Sessão L7 via Internet Fibra Direta',
    forwardErrorCorrection: false,
    packetDuplication: false
  },
  {
    id: 'pol-web',
    name: 'Tráfego de Navegação Geral & Vídeos (Best-Effort)',
    applicationClass: 'GENERAL_INTERNET_YOUTUBE',
    priorityOrder: 4,
    slaRequirement: {
      maxLatencyMs: 500,
      maxJitterMs: 80,
      maxPacketLossPct: 5.0
    },
    preferredLink: 'INTERNET_DIA_FIBER',
    secondaryLink: '5G_LTE_BACKUP',
    activeSteeringRoute: 'Descarregado direto p/ Provedor de Internet Local (Direct Internet Breakout)',
    forwardErrorCorrection: false,
    packetDuplication: false
  }
];

export const INITIAL_TUNNELS_MESH: SdwanTunnelMesh[] = [
  {
    sourceEdge: 'Edge-HQ-SaoPaulo',
    destEdge: 'Edge-Filial-RioDeJaneiro',
    transportType: 'OVERLAY_IPSEC_VPN',
    currentLatency: 12.1,
    activeLinkUsed: 'WAN1 (Vivo Fibra) -> WAN1 (Embratel MPLS)',
    encryptionState: 'SECURE_ESTABLISHED'
  },
  {
    sourceEdge: 'Edge-HQ-SaoPaulo',
    destEdge: 'Edge-Branch-NewYork',
    transportType: 'OVERLAY_IPSEC_VPN',
    currentLatency: 108.4,
    activeLinkUsed: 'WAN2 (Lumen DIA) -> WAN1 (Verizon Fios)',
    encryptionState: 'SECURE_ESTABLISHED'
  },
  {
    sourceEdge: 'Edge-HQ-SaoPaulo',
    destEdge: 'Edge-Industria-Curitiba',
    transportType: 'OVERLAY_IPSEC_VPN',
    currentLatency: 19.3,
    activeLinkUsed: 'WAN1 (Embratel MPLS) -> WAN1 (Copel Telecom)',
    encryptionState: 'SECURE_ESTABLISHED'
  },
  {
    sourceEdge: 'Edge-Filial-RioDeJaneiro',
    destEdge: 'Edge-Industria-Curitiba',
    transportType: 'OVERLAY_IPSEC_VPN',
    currentLatency: 22.8,
    activeLinkUsed: 'Dynamic Mesh (Direct Branch-to-Branch)',
    encryptionState: 'SECURE_ESTABLISHED'
  }
];

export const INITIAL_SDWAN_TELEMETRY: SdwanNetworkTelemetry = {
  orchestratorStatus: 'SYNCHRONIZED (Zero-Touch Provisioning Active)',
  totalSitesOnline: 4,
  totalDynamicTunnels: 27,
  trafficOptimizedTodayGb: 3410.8,
  failoversHandledWithoutDrop: 14,
  globalAvgLatencyMs: 14.8,
  globalAvgPacketLossPct: 0.02
};
