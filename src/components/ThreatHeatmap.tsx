import React, { useState, useMemo, useRef, useEffect } from 'react';
import {
  Globe,
  Radio,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Search,
  Filter,
  ExternalLink,
  Copy,
  Check,
  Activity,
  Zap,
  Tag,
  Crosshair,
  Skull,
  Terminal,
  Layers,
  ChevronRight,
  Info,
  Clock,
  Lock,
  ArrowRight,
  Flame,
  Grid,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Maximize2,
  Minimize2,
  Server,
  Eye,
  SlidersHorizontal,
  X,
  FileCode2,
  Navigation,
  MapPin,
  Compass,
  AlertOctagon,
  Radar,
  Play,
  Pause,
  SkipBack,
  SkipForward,
  Repeat,
  Calendar,
  History
} from 'lucide-react';
import {
  ScanFinding,
  ThreatActorProfile,
  OtxPulse,
  SeverityLevel
} from '../types';
import {
  INITIAL_OTX_PULSES,
  THREAT_ACTOR_PROFILES
} from '../lib/cyberThreatIntelEngine';
import {
  OtxThreatActorGeoNode,
  ThreatTrajectoryArc,
  extractOtxGeoThreatData,
  projectGeoToSvg,
  GeoCoordinate,
  ThreatRegion,
  COUNTRY_COORDINATE_MAP,
  THREAT_ACTOR_ORIGIN_COORDINATES,
  OTX_C2_GEO_RECORDS,
  getTimelineDateInfo
} from '../lib/otxGeoEngine';
import {
  CTI_VECTORS,
  computeCtiHeatmapMatrix
} from '../lib/ctiHeatmapEngine';
import { CtiVulnerabilityHeatmap } from './CtiVulnerabilityHeatmap';
import { useLanguage } from '../lib/i18nContext';

export interface ThreatHeatmapProps {
  findings?: ScanFinding[];
  actors?: ThreatActorProfile[];
  pulses?: OtxPulse[];
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToScanner?: () => void;
  onApplyTags?: () => void;
}

type ThreatHeatmapDisplayMode = 'GEO_MAP' | 'MATRIX_2D';

// Simplified world continent landmass SVG paths calibrated for 1000x500 equirectangular canvas
const WORLD_CONTINENTS_SVG_PATHS = [
  // North America
  {
    id: 'north-america',
    name: 'North America',
    d: 'M 120,65 L 180,50 L 250,55 L 290,90 L 310,130 L 280,150 L 260,180 L 230,190 L 220,240 L 205,270 L 195,300 L 180,280 L 160,250 L 125,230 L 105,200 L 80,170 L 70,120 L 95,85 Z M 270,30 L 330,25 L 360,60 L 320,80 L 275,55 Z'
  },
  // South America
  {
    id: 'south-america',
    name: 'South America',
    d: 'M 250,290 L 290,295 L 335,325 L 360,360 L 340,410 L 310,460 L 280,480 L 260,450 L 265,390 L 245,340 Z'
  },
  // Europe
  {
    id: 'europe',
    name: 'Europe',
    d: 'M 460,105 L 510,95 L 560,90 L 590,125 L 565,165 L 530,175 L 490,195 L 460,185 L 450,150 L 440,120 Z M 440,110 L 465,100 L 455,130 L 430,140 Z'
  },
  // Africa
  {
    id: 'africa',
    name: 'Africa',
    d: 'M 470,200 L 540,195 L 585,240 L 610,290 L 580,360 L 540,430 L 500,435 L 470,370 L 445,280 L 450,230 Z'
  },
  // Asia
  {
    id: 'asia',
    name: 'Asia',
    d: 'M 590,95 L 680,80 L 770,75 L 870,85 L 890,140 L 850,180 L 820,170 L 800,220 L 750,260 L 710,270 L 670,250 L 630,230 L 600,180 L 590,130 Z M 850,160 L 870,180 L 860,220 L 835,200 Z'
  },
  // Australia & Oceania
  {
    id: 'australia',
    name: 'Australia',
    d: 'M 780,350 L 850,340 L 880,380 L 860,430 L 810,435 L 775,395 Z M 890,420 L 910,440 L 880,455 Z'
  }
];

export const ThreatHeatmap: React.FC<ThreatHeatmapProps> = ({
  findings = [],
  actors = THREAT_ACTOR_PROFILES,
  pulses = INITIAL_OTX_PULSES,
  onSelectFinding,
  onNavigateToScanner,
  onApplyTags
}) => {
  const { language } = useLanguage();
  const isEn = language === 'en';

  // Display Mode: Geo Map vs 2D Matrix
  const [displayMode, setDisplayMode] = useState<ThreatHeatmapDisplayMode>('GEO_MAP');

  // Map Navigation & Zoom
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [panOffset, setPanOffset] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState<boolean>(false);
  const panStartRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });

  // Layer Toggles
  const [showDetectedVulns, setShowDetectedVulns] = useState<boolean>(true);
  const [showActorOrigins, setShowActorOrigins] = useState<boolean>(true);
  const [showOtxTargetZones, setShowOtxTargetZones] = useState<boolean>(true);
  const [showC2Infrastructure, setShowC2Infrastructure] = useState<boolean>(true);
  const [showTrajectoryArcs, setShowTrajectoryArcs] = useState<boolean>(true);
  const [showHeatGlow, setShowHeatGlow] = useState<boolean>(true);

  // Filters
  const [selectedActorFilter, setSelectedActorFilter] = useState<string>('ALL');
  const [selectedRegionFilter, setSelectedRegionFilter] = useState<ThreatRegion>('ALL');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Timeline Replay (Last 30 Days) State
  const [timelineDay, setTimelineDay] = useState<number>(30); // 1 = 30 days ago, 30 = Present (Today)
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1); // 0.5x, 1x, 2x, 4x
  const [isLooping, setIsLooping] = useState<boolean>(true);
  const [timelineMode, setTimelineMode] = useState<'CUMULATIVE' | 'DAY_ONLY'>('CUMULATIVE');

  // Selected Geo Node for Deep Dive Inspector Drawer
  const [selectedNode, setSelectedNode] = useState<OtxThreatActorGeoNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<OtxThreatActorGeoNode | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number } | null>(null);
  const mapContainerRef = useRef<HTMLDivElement>(null);

  // Canvas Dimensions
  const mapWidth = 1000;
  const mapHeight = 500;

  // Extract OTX Geo Threat Data
  const geoData = useMemo(() => {
    return extractOtxGeoThreatData(findings, actors, pulses);
  }, [findings, actors, pulses]);

  // Animation Replay Timer Effect
  useEffect(() => {
    if (!isPlaying) return;
    const intervalMs = Math.round(850 / playbackSpeed);
    const timer = setInterval(() => {
      setTimelineDay(prev => {
        if (prev >= 30) {
          if (isLooping) {
            return 1;
          } else {
            setIsPlaying(false);
            return 30;
          }
        }
        return prev + 1;
      });
    }, intervalMs);
    return () => clearInterval(timer);
  }, [isPlaying, playbackSpeed, isLooping]);

  // Current timeline date information
  const timelineDate = useMemo(() => getTimelineDateInfo(timelineDay), [timelineDay]);

  // Filtered Nodes (Respecting Region, Actor, Severity, Search, and Timeline Day)
  const filteredActorNodes = useMemo(() => {
    if (!showActorOrigins) return [];
    return geoData.actorNodes.filter(node => {
      if (timelineMode === 'CUMULATIVE') {
        if (node.timelineDay > timelineDay) return false;
      } else {
        if (node.timelineDay !== timelineDay) return false;
      }
      if (selectedRegionFilter !== 'ALL' && node.region !== selectedRegionFilter) return false;
      if (selectedActorFilter !== 'ALL' && node.actorId !== selectedActorFilter) return false;
      if (severityFilter === 'CRITICAL' && node.severity !== 'CRITICAL') return false;
      if (severityFilter === 'HIGH' && node.severity !== 'CRITICAL' && node.severity !== 'HIGH') return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return node.name.toLowerCase().includes(q) ||
          node.country.toLowerCase().includes(q) ||
          node.locationLabel.toLowerCase().includes(q);
      }
      return true;
    });
  }, [geoData.actorNodes, showActorOrigins, selectedRegionFilter, selectedActorFilter, severityFilter, searchQuery, timelineDay, timelineMode]);

  const filteredTargetCountryNodes = useMemo(() => {
    if (!showOtxTargetZones) return [];
    return geoData.targetCountryNodes.filter(node => {
      if (timelineMode === 'CUMULATIVE') {
        if (node.timelineDay > timelineDay) return false;
      } else {
        if (node.timelineDay !== timelineDay) return false;
      }
      if (selectedRegionFilter !== 'ALL' && node.region !== selectedRegionFilter) return false;
      if (severityFilter === 'CRITICAL' && node.severity !== 'CRITICAL') return false;
      if (severityFilter === 'HIGH' && node.severity !== 'CRITICAL' && node.severity !== 'HIGH') return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return node.name.toLowerCase().includes(q) ||
          node.country.toLowerCase().includes(q) ||
          node.locationLabel.toLowerCase().includes(q);
      }
      return true;
    });
  }, [geoData.targetCountryNodes, showOtxTargetZones, selectedRegionFilter, severityFilter, searchQuery, timelineDay, timelineMode]);

  const filteredC2Nodes = useMemo(() => {
    if (!showC2Infrastructure) return [];
    return geoData.c2Nodes.filter(node => {
      if (timelineMode === 'CUMULATIVE') {
        if (node.timelineDay > timelineDay) return false;
      } else {
        if (node.timelineDay !== timelineDay) return false;
      }
      if (selectedRegionFilter !== 'ALL' && node.region !== selectedRegionFilter) return false;
      if (severityFilter === 'CRITICAL' && node.severity !== 'CRITICAL') return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return node.name.toLowerCase().includes(q) ||
          node.country.toLowerCase().includes(q) ||
          node.locationLabel.toLowerCase().includes(q);
      }
      return true;
    });
  }, [geoData.c2Nodes, showC2Infrastructure, selectedRegionFilter, severityFilter, searchQuery, timelineDay, timelineMode]);

  const filteredVulnNodes = useMemo(() => {
    if (!showDetectedVulns) return [];
    return geoData.detectedVulnerabilityNodes.filter(node => {
      if (timelineMode === 'CUMULATIVE') {
        if (node.timelineDay > timelineDay) return false;
      } else {
        if (node.timelineDay !== timelineDay) return false;
      }
      if (selectedRegionFilter !== 'ALL' && node.region !== selectedRegionFilter) return false;
      if (severityFilter === 'CRITICAL' && node.severity !== 'CRITICAL') return false;
      if (severityFilter === 'HIGH' && node.severity !== 'CRITICAL' && node.severity !== 'HIGH') return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return node.name.toLowerCase().includes(q) ||
          node.locationLabel.toLowerCase().includes(q) ||
          node.findings.some(f => f.ruleName.toLowerCase().includes(q) || f.file.toLowerCase().includes(q));
      }
      return true;
    });
  }, [geoData.detectedVulnerabilityNodes, showDetectedVulns, selectedRegionFilter, severityFilter, searchQuery, timelineDay, timelineMode]);

  const filteredTrajectories = useMemo(() => {
    if (!showTrajectoryArcs) return [];
    return geoData.trajectories.filter(traj => {
      if (timelineMode === 'CUMULATIVE') {
        if (traj.timelineDay > timelineDay) return false;
      } else {
        if (traj.timelineDay !== timelineDay) return false;
      }
      if (selectedRegionFilter !== 'ALL') {
        const sourceActor = geoData.actorNodes.find(a => a.id === traj.sourceNodeId);
        const targetNode = geoData.detectedVulnerabilityNodes.find(v => v.id === traj.targetNodeId) ||
                           geoData.targetCountryNodes.find(t => t.id === traj.targetNodeId);
        // Trajectory matches if either the threat actor source or target region matches the selected region
        const sourceMatches = sourceActor?.region === selectedRegionFilter;
        const targetMatches = targetNode?.region === selectedRegionFilter;
        if (!sourceMatches && !targetMatches) return false;
      }
      if (selectedActorFilter !== 'ALL') {
        const actor = actors.find(a => a.id === selectedActorFilter);
        if (actor && !traj.actorName.toLowerCase().includes(actor.name.toLowerCase().split(' ')[0])) {
          return false;
        }
      }
      if (severityFilter === 'CRITICAL' && traj.severity !== 'CRITICAL') return false;
      return true;
    });
  }, [geoData.trajectories, geoData.actorNodes, geoData.detectedVulnerabilityNodes, geoData.targetCountryNodes, showTrajectoryArcs, selectedRegionFilter, selectedActorFilter, severityFilter, actors, timelineDay, timelineMode]);

  // Active vulnerabilities count up to current timeline day
  const activeVulnCount = useMemo(() => {
    return filteredVulnNodes.reduce((acc, node) => {
      const activeInNode = node.findings.filter(f => !f.timelineDay || f.timelineDay <= timelineDay).length;
      return acc + (activeInNode || 1);
    }, 0);
  }, [filteredVulnNodes, timelineDay]);

  const eventsOnCurrentDay = geoData.timelineDayEventsCount[timelineDay] || 0;

  // Daily intelligence narrative dispatch for the current timeline day
  const dailyIntelEventNarrative = useMemo(() => {
    if (timelineDay === 30) {
      return isEn
        ? 'Present Day (T-0): Consolidated 30-day global CTI overlay active across all regions.'
        : 'Hoje (T-0): Panorama consolidado de 30 dias de inteligência CTI ativo em todas as regiões.';
    }
    const actorToday = geoData.actorNodes.find(a => a.timelineDay === timelineDay);
    if (actorToday) {
      return isEn
        ? `Threat Campaign Surge: ${actorToday.name} (${actorToday.locationLabel}) active campaign detected in AlienVault OTX feeds.`
        : `Surto de Ameaça: Campanha ativa de ${actorToday.name} (${actorToday.locationLabel}) detectada nos feeds OTX.`;
    }
    const vulnToday = geoData.detectedVulnerabilityNodes.find(v => v.timelineDay === timelineDay);
    if (vulnToday) {
      return isEn
        ? `Vulnerability Discovery: New attack surface exposed in ${vulnToday.locationLabel} (${vulnToday.findings.length} findings mapped).`
        : `Vulnerabilidade Identificada: Nova superfície de ataque exposta em ${vulnToday.locationLabel} (${vulnToday.findings.length} falhas mapeadas).`;
    }
    const c2Today = geoData.c2Nodes.find(c => c.timelineDay === timelineDay);
    if (c2Today) {
      return isEn
        ? `OTX C2 Infrastructure Spotted: ${c2Today.name} active scanner in ${c2Today.locationLabel}.`
        : `Infraestrutura C2 OTX Detectada: Scanner ativo ${c2Today.name} em ${c2Today.locationLabel}.`;
    }
    const targetToday = geoData.targetCountryNodes.find(t => t.timelineDay === timelineDay);
    if (targetToday) {
      return isEn
        ? `OTX Strike Zone Escalation: Surge in pulses targeting infrastructure in ${targetToday.country}.`
        : `Escalada de Zona Alvo OTX: Aumento de pulses mirando infraestruturas em ${targetToday.country}.`;
    }
    return isEn
      ? `Ongoing reconnaissance and telemetry tracking across global nodes (${eventsOnCurrentDay} threat pulses observed).`
      : `Reconhecimento contínuo e rastreamento de telemetria em nós globais (${eventsOnCurrentDay} eventos observados).`;
  }, [timelineDay, geoData, isEn, eventsOnCurrentDay]);

  // Handle Pan Mouse Events
  const handleMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    if (zoomLevel <= 1) return;
    setIsPanning(true);
    panStartRef.current = { x: e.clientX - panOffset.x, y: e.clientY - panOffset.y };
  };

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!isPanning) return;
    setPanOffset({
      x: e.clientX - panStartRef.current.x,
      y: e.clientY - panStartRef.current.y
    });
  };

  const handleMouseUp = () => {
    setIsPanning(false);
  };

  const resetView = () => {
    setZoomLevel(1);
    setPanOffset({ x: 0, y: 0 });
  };

  const updateTooltipCoordinates = (e: React.MouseEvent) => {
    if (!mapContainerRef.current) return;
    const rect = mapContainerRef.current.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const tooltipWidth = 360;
    const tooltipHeight = 290;

    let posX = mouseX + 16;
    if (posX + tooltipWidth > rect.width - 16) {
      posX = mouseX - tooltipWidth - 16;
    }
    let posY = mouseY - 24;
    if (posY + tooltipHeight > rect.height - 16) {
      posY = rect.height - tooltipHeight - 16;
    }
    posX = Math.max(16, posX);
    posY = Math.max(16, posY);

    setTooltipPos({ x: posX, y: posY });
  };

  const handleNodeMouseEnter = (node: OtxThreatActorGeoNode, e: React.MouseEvent) => {
    setHoveredNode(node);
    updateTooltipCoordinates(e);
  };

  const handleNodeMouseMove = (e: React.MouseEvent) => {
    updateTooltipCoordinates(e);
  };

  const handleNodeMouseLeave = () => {
    setHoveredNode(null);
    setTooltipPos(null);
  };

  const handleCopyDossier = (node: OtxThreatActorGeoNode) => {
    const text = `[CTI GEO DOSSIER - ALIENVAULT OTX & SAST OVERLAY]
Node: ${node.name}
Type: ${node.type}
Region: ${node.region}
Specific Threat Actor: ${node.specificThreatActor || node.actorName || 'N/A'} ${node.threatActorCodeName ? `(${node.threatActorCodeName})` : ''}
CVE ID: ${node.cveId || 'N/A'}
Last Observed Timestamp: ${node.lastObservedFormatted || node.lastObservedTimestamp || node.discoveryDate}
Timeline Discovery: Day ${node.timelineDay} of 30 (${node.discoveryDate})
Geo Coordinates: Lat ${node.lat.toFixed(4)}, Lng ${node.lng.toFixed(4)} (${node.locationLabel}, ${node.country})
Threat Score: ${node.threatScore}/100 [${node.severity}]
CISA KEV Associated: ${node.cisaKevAssociated ? 'YES - ACTIVE IN THE WILD' : 'No'}
Active Pulses: ${node.pulses.map(p => p.name).join(' | ') || 'N/A'}
IOC Indicators: ${node.iocs.map(i => `${i.type}: ${i.indicator}`).join(', ') || 'N/A'}
Detected Code Vulnerabilities: ${node.findings.length}
MITRE ATT&CK TTPs: ${node.ttps.join(', ')}
Details: ${node.details}`;

    navigator.clipboard.writeText(text);
    setCopiedId(node.id);
    setTimeout(() => setCopiedId(null), 2500);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Mode Toggle */}
      <div className="bg-[#0A0A0A] border border-[#222] p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#00FF41] animate-ping" />
              <span className="text-[10px] font-mono font-bold tracking-widest text-[#00FF41] uppercase">
                {isEn ? 'ALIENVAULT OTX & CISA KEV GEO-INTELLIGENCE' : 'GEO-INTELIGÊNCIA ALIENVAULT OTX & CISA KEV'}
              </span>
              <span className="text-zinc-600 text-xs">/</span>
              <span className="text-[10px] font-mono text-zinc-400">
                {isEn ? 'GLOBAL THREAT HEATMAP' : 'MAPA GLOBAL DE CALOR DE AMEAÇAS'}
              </span>
            </div>
            <h2 className="text-xl font-black text-white tracking-tight mt-1 flex items-center gap-2.5">
              <Globe className="w-5 h-5 text-[#00FF41]" />
              <span>{isEn ? 'Threat Heatmap (Geo-Location Overlay)' : 'Mapa de Calor de Ameaças (Geo-Localização)'}</span>
            </h2>
            <p className="text-xs text-zinc-400 font-mono mt-1 max-w-3xl">
              {isEn
                ? 'Visualizes detected code vulnerabilities against global threat actor operating bases, C2 exfiltration nodes, and active strike campaigns pulling coordinates directly from AlienVault OTX & CISA KEV feeds.'
                : 'Visualiza as vulnerabilidades detectadas no código contra as bases de operação dos atores de ameaça globais, nós C2 de exfiltração e campanhas ativas extraídas dos feeds AlienVault OTX e CISA KEV.'}
            </p>
          </div>

          {/* View Switcher: Geo Map vs 2D Matrix */}
          <div className="flex items-center gap-2 shrink-0">
            <div className="flex items-center bg-[#121212] p-1 border border-[#262626]">
              <button
                type="button"
                onClick={() => setDisplayMode('GEO_MAP')}
                className={`px-3 py-1.5 text-xs font-mono font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer ${
                  displayMode === 'GEO_MAP'
                    ? 'bg-[#00FF41] text-black font-black'
                    : 'text-zinc-400 hover:text-white'
                }`}
              >
                <Globe className="w-3.5 h-3.5" />
                <span>{isEn ? 'Geo Map' : 'Mapa Global'}</span>
              </button>
              <button
                type="button"
                onClick={() => setDisplayMode('MATRIX_2D')}
                className={`px-3 py-1.5 text-xs font-mono font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors cursor-pointer ${
                  displayMode === 'MATRIX_2D'
                    ? 'bg-[#00FF41] text-black font-black'
                    : 'text-zinc-400 hover:text-white'
                }`}
              >
                <Grid className="w-3.5 h-3.5" />
                <span>{isEn ? 'Tactical Matrix' : 'Matriz Tática'}</span>
              </button>
            </div>

            {onApplyTags && (
              <button
                type="button"
                onClick={onApplyTags}
                className="px-3.5 py-1.5 bg-[#181818] hover:bg-[#222] border border-[#333] hover:border-[#00FF41] text-white text-xs font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer"
                title={isEn ? 'Apply CTI tags to workspace' : 'Aplicar tags CTI ao workspace'}
              >
                <Tag className="w-3.5 h-3.5 text-[#00FF41]" />
                <span className="hidden sm:inline">{isEn ? 'Apply Tags' : 'Aplicar Tags'}</span>
              </button>
            )}
          </div>
        </div>

        {/* Tactical Metric Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mt-5 pt-4 border-t border-[#1C1C1C]">
          <div className="p-3 bg-[#050505] border border-[#1E1E1E]">
            <div className="text-[10px] text-zinc-500 font-mono uppercase tracking-wider flex items-center justify-between">
              <span>{isEn ? 'Vulnerabilities' : 'Vulnerabilidades'}</span>
              <Crosshair className="w-3.5 h-3.5 text-[#00FF41]" />
            </div>
            <div className="text-xl font-black font-mono text-[#00FF41] mt-1">
              {geoData.totalVulnerabilitiesMapped}
            </div>
            <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
              {geoData.detectedVulnerabilityNodes.length} {isEn ? 'cloud anchors' : 'regiões ancoradas'}
            </div>
          </div>

          <div className="p-3 bg-[#050505] border border-[#1E1E1E]">
            <div className="text-[10px] text-zinc-500 font-mono uppercase tracking-wider flex items-center justify-between">
              <span>{isEn ? 'Threat Actors' : 'Atores de Ameaça'}</span>
              <Skull className="w-3.5 h-3.5 text-[#EF4444]" />
            </div>
            <div className="text-xl font-black font-mono text-[#EF4444] mt-1">
              {geoData.activeAttackingActors}
            </div>
            <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
              {isEn ? 'pulled from OTX feed' : 'mapeados no OTX'}
            </div>
          </div>

          <div className="p-3 bg-[#050505] border border-[#1E1E1E]">
            <div className="text-[10px] text-zinc-500 font-mono uppercase tracking-wider flex items-center justify-between">
              <span>{isEn ? 'OTX Strike Zones' : 'Zonas de Ataque OTX'}</span>
              <Flame className="w-3.5 h-3.5 text-[#F59E0B]" />
            </div>
            <div className="text-xl font-black font-mono text-[#F59E0B] mt-1">
              {geoData.targetCountryNodes.length}
            </div>
            <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
              {isEn ? 'countries targeted' : 'países sob ataque'}
            </div>
          </div>

          <div className="p-3 bg-[#050505] border border-[#1E1E1E]">
            <div className="text-[10px] text-zinc-500 font-mono uppercase tracking-wider flex items-center justify-between">
              <span>{isEn ? 'Attack Trajectories' : 'Trajetórias Ativas'}</span>
              <Activity className="w-3.5 h-3.5 text-[#38BDF8]" />
            </div>
            <div className="text-xl font-black font-mono text-[#38BDF8] mt-1">
              {geoData.trajectories.length}
            </div>
            <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
              {isEn ? 'direct vector links' : 'vínculos diretos'}
            </div>
          </div>

          <div className="p-3 bg-[#050505] border border-[#1E1E1E]">
            <div className="text-[10px] text-zinc-500 font-mono uppercase tracking-wider flex items-center justify-between">
              <span>{isEn ? 'CISA KEV Outbreaks' : 'Alertas CISA KEV'}</span>
              <AlertOctagon className="w-3.5 h-3.5 text-[#EC4899]" />
            </div>
            <div className="text-xl font-black font-mono text-[#EC4899] mt-1">
              {geoData.criticalCisaKevOverlays}
            </div>
            <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
              {isEn ? 'in-the-wild zero-days' : 'exploração ativa'}
            </div>
          </div>
        </div>
      </div>

      {/* Conditionally Render: GEO MAP or MATRIX 2D */}
      {displayMode === 'MATRIX_2D' ? (
        <CtiVulnerabilityHeatmap
          findings={findings}
          actors={actors}
          pulses={pulses}
          onSelectFinding={onSelectFinding}
          onNavigateToScanner={onNavigateToScanner}
          onApplyTags={onApplyTags}
        />
      ) : (
        <div className="space-y-4">
          {/* Controls & Layer Filters Toolbar */}
          <div className="bg-[#0A0A0A] border border-[#222] p-4 flex flex-col lg:flex-row items-center justify-between gap-4">
            {/* Search */}
            <div className="relative w-full lg:w-72">
              <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder={isEn ? 'Search actor, country, CVE, IP...' : 'Buscar ator, país, CVE, IP...'}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-[#050505] border border-[#333] text-white text-xs pl-9 pr-3 py-2 font-mono focus:border-[#00FF41] focus:outline-none"
              />
            </div>

            {/* Filter Dropdowns */}
            <div className="flex flex-wrap items-center gap-2.5 w-full lg:w-auto">
              {/* Region Filter Dropdown */}
              <div className="flex items-center gap-1.5 bg-[#050505] border border-[#333] px-2 py-1 text-zinc-300">
                <Globe className="w-3.5 h-3.5 text-[#38BDF8]" />
                <select
                  value={selectedRegionFilter}
                  onChange={(e) => setSelectedRegionFilter(e.target.value as ThreatRegion)}
                  className="bg-transparent text-zinc-300 text-xs py-1 font-mono focus:border-[#00FF41] focus:outline-none cursor-pointer"
                  title={isEn ? 'Filter by Threat Actor Region' : 'Filtrar por Região do Ator de Ameaça'}
                  aria-label={isEn ? 'Threat Actor Region Filter' : 'Filtro de Região do Ator de Ameaça'}
                >
                  <option value="ALL" className="bg-[#121212] text-white">
                    {isEn ? '🌐 All Regions (Global)' : '🌐 Todas as Regiões (Global)'}
                  </option>
                  <option value="APAC" className="bg-[#121212] text-white">
                    {isEn ? '🌏 APAC (Asia-Pacific)' : '🌏 APAC (Ásia-Pacífico)'}
                  </option>
                  <option value="EMEA" className="bg-[#121212] text-white">
                    {isEn ? '🌍 EMEA (Europe, Middle East, Africa)' : '🌍 EMEA (Europa, Oriente Médio, África)'}
                  </option>
                  <option value="Americas" className="bg-[#121212] text-white">
                    {isEn ? '🌎 Americas (North & South America)' : '🌎 Américas (Norte e Sul)'}
                  </option>
                </select>
              </div>

              {/* Threat Actor Filter Dropdown */}
              <select
                value={selectedActorFilter}
                onChange={(e) => setSelectedActorFilter(e.target.value)}
                className="bg-[#050505] border border-[#333] text-zinc-300 text-xs px-2.5 py-2 font-mono focus:border-[#00FF41] focus:outline-none"
              >
                <option value="ALL">{isEn ? 'All Threat Actors' : 'Todos os Atores'}</option>
                {actors.map(actor => (
                  <option key={actor.id} value={actor.id}>
                    {actor.name} ({actor.codeName})
                  </option>
                ))}
              </select>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as any)}
                className="bg-[#050505] border border-[#333] text-zinc-300 text-xs px-2.5 py-2 font-mono focus:border-[#00FF41] focus:outline-none"
              >
                <option value="ALL">{isEn ? 'All Severities' : 'Todas as Severidades'}</option>
                <option value="CRITICAL">{isEn ? 'Critical Only' : 'Apenas Críticos'}</option>
                <option value="HIGH">{isEn ? 'High and Critical' : 'Altos e Críticos'}</option>
              </select>

              {/* Zoom Controls */}
              <div className="flex items-center bg-[#121212] border border-[#333]">
                <button
                  type="button"
                  onClick={() => setZoomLevel(prev => Math.min(3, prev + 0.3))}
                  className="p-2 text-zinc-400 hover:text-white hover:bg-[#1A1A1A] cursor-pointer"
                  title={isEn ? 'Zoom In' : 'Aproximar'}
                >
                  <ZoomIn className="w-3.5 h-3.5" />
                </button>
                <span className="text-[10px] font-mono px-1.5 text-zinc-400">
                  {zoomLevel.toFixed(1)}x
                </span>
                <button
                  type="button"
                  onClick={() => setZoomLevel(prev => Math.max(0.8, prev - 0.3))}
                  className="p-2 text-zinc-400 hover:text-white hover:bg-[#1A1A1A] cursor-pointer"
                  title={isEn ? 'Zoom Out' : 'Afastar'}
                >
                  <ZoomOut className="w-3.5 h-3.5" />
                </button>
                <button
                  type="button"
                  onClick={resetView}
                  className="p-2 text-zinc-400 hover:text-[#00FF41] hover:bg-[#1A1A1A] border-l border-[#333] cursor-pointer"
                  title={isEn ? 'Reset View' : 'Redefinir Visão'}
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>

          {/* Layer Toggle Chips */}
          <div className="flex flex-wrap items-center gap-2 bg-[#050505] border border-[#1C1C1C] px-3.5 py-2.5 text-xs font-mono">
            <span className="text-[10px] text-zinc-500 uppercase tracking-widest font-bold flex items-center gap-1.5 mr-2">
              <Layers className="w-3.5 h-3.5 text-zinc-400" />
              <span>{isEn ? 'Layers:' : 'Camadas:'}</span>
            </span>

            <button
              type="button"
              onClick={() => setShowDetectedVulns(!showDetectedVulns)}
              className={`px-2.5 py-1 text-[11px] font-bold flex items-center gap-1.5 border transition-all cursor-pointer ${
                showDetectedVulns
                  ? 'bg-emerald-500/10 border-[#00FF41] text-[#00FF41]'
                  : 'bg-transparent border-[#262626] text-zinc-500'
              }`}
            >
              <Crosshair className="w-3 h-3" />
              <span>{isEn ? 'Detected Vulns' : 'Vulnerabilidades'} ({filteredVulnNodes.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setShowActorOrigins(!showActorOrigins)}
              className={`px-2.5 py-1 text-[11px] font-bold flex items-center gap-1.5 border transition-all cursor-pointer ${
                showActorOrigins
                  ? 'bg-red-500/10 border-[#EF4444] text-[#EF4444]'
                  : 'bg-transparent border-[#262626] text-zinc-500'
              }`}
            >
              <Skull className="w-3 h-3" />
              <span>{isEn ? 'Threat Actors' : 'Atores Hostis'} ({filteredActorNodes.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setShowOtxTargetZones(!showOtxTargetZones)}
              className={`px-2.5 py-1 text-[11px] font-bold flex items-center gap-1.5 border transition-all cursor-pointer ${
                showOtxTargetZones
                  ? 'bg-amber-500/10 border-[#F59E0B] text-[#F59E0B]'
                  : 'bg-transparent border-[#262626] text-zinc-500'
              }`}
            >
              <Flame className="w-3 h-3" />
              <span>{isEn ? 'OTX Strike Zones' : 'Zonas Alvo OTX'} ({filteredTargetCountryNodes.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setShowC2Infrastructure(!showC2Infrastructure)}
              className={`px-2.5 py-1 text-[11px] font-bold flex items-center gap-1.5 border transition-all cursor-pointer ${
                showC2Infrastructure
                  ? 'bg-purple-500/10 border-[#A855F7] text-[#A855F7]'
                  : 'bg-transparent border-[#262626] text-zinc-500'
              }`}
            >
              <Server className="w-3 h-3" />
              <span>{isEn ? 'OTX C2 Nodes' : 'Nós C2 OTX'} ({filteredC2Nodes.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setShowTrajectoryArcs(!showTrajectoryArcs)}
              className={`px-2.5 py-1 text-[11px] font-bold flex items-center gap-1.5 border transition-all cursor-pointer ${
                showTrajectoryArcs
                  ? 'bg-sky-500/10 border-[#38BDF8] text-[#38BDF8]'
                  : 'bg-transparent border-[#262626] text-zinc-500'
              }`}
            >
              <Activity className="w-3 h-3" />
              <span>{isEn ? 'Trajectories' : 'Trajetórias'} ({filteredTrajectories.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setShowHeatGlow(!showHeatGlow)}
              className={`px-2.5 py-1 text-[11px] font-bold flex items-center gap-1.5 border transition-all cursor-pointer ${
                showHeatGlow
                  ? 'bg-orange-500/10 border-[#FB923C] text-[#FB923C]'
                  : 'bg-transparent border-[#262626] text-zinc-500'
              }`}
            >
              <Zap className="w-3 h-3" />
              <span>{isEn ? 'Thermal Glow' : 'Glow Térmico'}</span>
            </button>
          </div>

          {/* ⏱️ TIMELINE REPLAY CONTROL CENTER (LAST 30 DAYS) */}
          <div className="bg-[#08090C] border border-[#222] p-4 relative overflow-hidden">
            {/* Ambient subtle glow background */}
            <div className="absolute top-0 right-0 w-96 h-full bg-gradient-to-l from-emerald-950/20 to-transparent pointer-events-none" />

            {/* Header: Title, Live Date badge, Stats summary */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-[#181818]">
              <div className="flex items-center gap-3">
                <div className={`p-2 border flex items-center justify-center ${isPlaying ? 'bg-emerald-500/10 border-[#00FF41] text-[#00FF41]' : 'bg-[#121212] border-[#2E2E2E] text-zinc-300'}`}>
                  <History className={`w-4 h-4 ${isPlaying ? 'animate-spin' : ''}`} style={{ animationDuration: '3s' }} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-black font-mono tracking-wider text-white uppercase flex items-center gap-1.5">
                      <span>{isEn ? 'Timeline Replay' : 'Replay da Linha do Tempo'}</span>
                      <span className="text-[10px] px-1.5 py-0.2 bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30 font-bold">
                        30 {isEn ? 'DAYS' : 'DIAS'}
                      </span>
                    </span>
                    {isPlaying && (
                      <span className="flex items-center gap-1 text-[10px] font-mono text-[#00FF41] font-bold">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#00FF41] animate-ping" />
                        <span>{isEn ? 'ANIMATING' : 'ANIMANDO'}</span>
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] font-mono text-zinc-400 mt-0.5">
                    {isEn
                      ? 'Animate the progression of vulnerability discovery & threat actor activity over the past 30 days.'
                      : 'Animar a progressão de descoberta de vulnerabilidades e atividades de ameaça nos últimos 30 dias.'}
                  </p>
                </div>
              </div>

              {/* Date Badge & Stats Counters */}
              <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                {/* Date badge */}
                <div className="px-3 py-1.5 bg-[#0F141C] border border-[#233142] flex items-center gap-2">
                  <Calendar className="w-3.5 h-3.5 text-[#38BDF8]" />
                  <span className="text-white font-bold">{timelineDate.dateStr}</span>
                  <span className="text-zinc-500">|</span>
                  <span className={timelineDate.daysAgo === 0 ? 'text-[#00FF41] font-bold' : 'text-zinc-400'}>
                    {timelineDate.daysAgo === 0 ? (isEn ? 'Present (Today)' : 'Hoje (Atual)') : (isEn ? `Day ${timelineDay} (T - ${timelineDate.daysAgo}d)` : `Dia ${timelineDay} (T - ${timelineDate.daysAgo}d)`)}
                  </span>
                </div>

                {/* Quick stats pills */}
                <div className="hidden lg:flex items-center gap-2 text-[11px]">
                  <span className="px-2 py-1 bg-black/60 border border-[#222] text-zinc-400">
                    <span className="text-[#00FF41] font-bold">{activeVulnCount}</span>/{geoData.totalVulnerabilitiesMapped} {isEn ? 'Vulns' : 'Falhas'}
                  </span>
                  <span className="px-2 py-1 bg-black/60 border border-[#222] text-zinc-400">
                    <span className="text-[#EF4444] font-bold">{filteredActorNodes.length}</span>/{geoData.activeAttackingActors} {isEn ? 'Actors' : 'Atores'}
                  </span>
                  <span className="px-2 py-1 bg-black/60 border border-[#222] text-zinc-400">
                    <span className="text-[#38BDF8] font-bold">{filteredTrajectories.length}</span> {isEn ? 'Arcs' : 'Arcos'}
                  </span>
                  {eventsOnCurrentDay > 0 && (
                    <span className="px-2 py-1 bg-emerald-500/10 border border-[#00FF41]/40 text-[#00FF41] font-bold flex items-center gap-1">
                      <Zap className="w-3 h-3 text-[#00FF41]" />
                      <span>+{eventsOnCurrentDay} {isEn ? 'today' : 'hoje'}</span>
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Activity Frequency Histogram (30 Bars above the slider) */}
            <div className="pt-3 pb-1">
              <div className="flex items-end justify-between h-9 px-1 gap-1">
                {Array.from({ length: 30 }, (_, i) => i + 1).map(day => {
                  const count = geoData.timelineDayEventsCount[day] || 0;
                  const maxCount = Math.max(...Object.values(geoData.timelineDayEventsCount), 1);
                  const heightPct = Math.max(15, Math.min(100, (count / maxCount) * 100));
                  const isCurrent = day === timelineDay;
                  const isPast = day < timelineDay;
                  const dayDate = getTimelineDateInfo(day);

                  return (
                    <button
                      key={`hist-bar-${day}`}
                      type="button"
                      onClick={() => setTimelineDay(day)}
                      className="flex-1 flex flex-col items-center justify-end h-full group cursor-pointer focus:outline-none"
                      title={`${dayDate.dateStr} (Day ${day}): ${count} threat & vuln events`}
                    >
                      <div
                        style={{ height: `${heightPct}%` }}
                        className={`w-full transition-all rounded-xs ${
                          isCurrent
                            ? 'bg-[#00FF41] shadow-[0_0_8px_#00FF41]'
                            : isPast
                            ? 'bg-emerald-700/60 hover:bg-emerald-500'
                            : 'bg-zinc-800 hover:bg-zinc-600'
                        }`}
                      />
                    </button>
                  );
                })}
              </div>

              {/* Slider Range Input */}
              <div className="relative mt-1 px-1">
                <input
                  type="range"
                  min={1}
                  max={30}
                  step={1}
                  value={timelineDay}
                  onChange={(e) => setTimelineDay(Number(e.target.value))}
                  className="w-full accent-[#00FF41] bg-[#1A1A1A] h-2 rounded-lg cursor-pointer focus:outline-none"
                  aria-label={isEn ? 'Timeline Replay Day Slider' : 'Controle Deslizante da Linha do Tempo'}
                />

                {/* Day Ticks / Labels */}
                <div className="flex justify-between text-[10px] font-mono text-zinc-500 mt-1 select-none">
                  <span className={timelineDay === 1 ? 'text-[#00FF41] font-bold' : ''}>Day 1 (T-29d)</span>
                  <span className={timelineDay === 8 ? 'text-[#00FF41] font-bold' : ''}>Day 8 (T-22d)</span>
                  <span className={timelineDay === 15 ? 'text-[#00FF41] font-bold' : ''}>Day 15 (T-15d)</span>
                  <span className={timelineDay === 22 ? 'text-[#00FF41] font-bold' : ''}>Day 22 (T-8d)</span>
                  <span className={timelineDay === 30 ? 'text-[#00FF41] font-bold' : ''}>Day 30 (Today)</span>
                </div>
              </div>
            </div>

            {/* Controls Toolbar: Play/Pause, Step Back/Forward, Speed, Mode, Reset */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-3 mt-2 border-t border-[#181818]">
              {/* Left: Transport Buttons */}
              <div className="flex items-center gap-1.5">
                {/* Skip to Day 1 */}
                <button
                  type="button"
                  onClick={() => setTimelineDay(1)}
                  className="p-2 bg-[#121212] hover:bg-[#1E1E1E] border border-[#2E2E2E] text-zinc-400 hover:text-white transition-colors cursor-pointer"
                  title={isEn ? 'Jump to Day 1 (Start)' : 'Pular para Dia 1 (Início)'}
                >
                  <SkipBack className="w-3.5 h-3.5" />
                </button>

                {/* Step -1 Day */}
                <button
                  type="button"
                  onClick={() => setTimelineDay(prev => Math.max(1, prev - 1))}
                  className="px-2.5 py-1.5 bg-[#121212] hover:bg-[#1E1E1E] border border-[#2E2E2E] text-zinc-400 hover:text-white text-xs font-mono font-bold transition-colors cursor-pointer"
                  title={isEn ? 'Step Back 1 Day' : 'Voltar 1 Dia'}
                >
                  -1d
                </button>

                {/* Main Play / Pause Button */}
                <button
                  type="button"
                  onClick={() => {
                    if (!isPlaying && timelineDay >= 30) {
                      setTimelineDay(1);
                    }
                    setIsPlaying(!isPlaying);
                  }}
                  className={`px-4 py-1.5 text-xs font-mono font-bold uppercase tracking-wider flex items-center gap-2 border transition-all cursor-pointer ${
                    isPlaying
                      ? 'bg-[#EF4444] border-red-500 text-white shadow-[0_0_12px_rgba(239,68,68,0.4)]'
                      : 'bg-[#00FF41] border-[#00FF41] text-black font-black shadow-[0_0_12px_rgba(0,255,65,0.3)] hover:brightness-110'
                  }`}
                >
                  {isPlaying ? (
                    <>
                      <Pause className="w-3.5 h-3.5 fill-current" />
                      <span>{isEn ? 'Pause' : 'Pausar'}</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>{timelineDay >= 30 ? (isEn ? 'Replay (Start)' : 'Iniciar Replay') : (isEn ? 'Play Animation' : 'Reproduzir')}</span>
                    </>
                  )}
                </button>

                {/* Step +1 Day */}
                <button
                  type="button"
                  onClick={() => setTimelineDay(prev => Math.min(30, prev + 1))}
                  className="px-2.5 py-1.5 bg-[#121212] hover:bg-[#1E1E1E] border border-[#2E2E2E] text-zinc-400 hover:text-white text-xs font-mono font-bold transition-colors cursor-pointer"
                  title={isEn ? 'Step Forward 1 Day' : 'Avançar 1 Dia'}
                >
                  +1d
                </button>

                {/* Jump to Present (Day 30) */}
                <button
                  type="button"
                  onClick={() => {
                    setTimelineDay(30);
                    setIsPlaying(false);
                  }}
                  className="p-2 bg-[#121212] hover:bg-[#1E1E1E] border border-[#2E2E2E] text-zinc-400 hover:text-white transition-colors cursor-pointer"
                  title={isEn ? 'Jump to Present (Day 30)' : 'Pular para o Presente (Dia 30)'}
                >
                  <SkipForward className="w-3.5 h-3.5" />
                </button>
              </div>

              {/* Center: Playback Speed Toggle & Loop */}
              <div className="flex items-center gap-2 font-mono text-xs">
                {/* Speed Selector */}
                <div className="flex items-center bg-[#121212] border border-[#2A2A2A] p-0.5">
                  {[0.5, 1, 2, 4].map(speed => (
                    <button
                      key={`speed-${speed}`}
                      type="button"
                      onClick={() => setPlaybackSpeed(speed)}
                      className={`px-2 py-0.5 text-[11px] font-bold cursor-pointer transition-colors ${
                        playbackSpeed === speed
                          ? 'bg-[#00FF41] text-black font-black'
                          : 'text-zinc-400 hover:text-white'
                      }`}
                    >
                      {speed}x
                    </button>
                  ))}
                </div>

                {/* Loop toggle */}
                <button
                  type="button"
                  onClick={() => setIsLooping(!isLooping)}
                  className={`px-2.5 py-1 border text-[11px] font-bold flex items-center gap-1.5 transition-colors cursor-pointer ${
                    isLooping
                      ? 'bg-emerald-500/10 border-[#00FF41]/40 text-[#00FF41]'
                      : 'bg-[#121212] border-[#2A2A2A] text-zinc-500 hover:text-zinc-300'
                  }`}
                  title={isEn ? 'Loop animation' : 'Repetir em loop'}
                >
                  <Repeat className="w-3 h-3" />
                  <span className="hidden sm:inline">{isEn ? 'Loop' : 'Loop'}</span>
                </button>

                {/* Cumulative vs Single Day Mode */}
                <div className="flex items-center bg-[#121212] border border-[#2A2A2A] p-0.5">
                  <button
                    type="button"
                    onClick={() => setTimelineMode('CUMULATIVE')}
                    className={`px-2 py-0.5 text-[10px] font-bold uppercase transition-colors cursor-pointer ${
                      timelineMode === 'CUMULATIVE'
                        ? 'bg-[#38BDF8] text-black font-black'
                        : 'text-zinc-400 hover:text-white'
                    }`}
                    title={isEn ? 'Show all discoveries accumulated up to selected day' : 'Mostrar descobertas acumuladas até o dia selecionado'}
                  >
                    {isEn ? 'Cumulative' : 'Acumulado'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setTimelineMode('DAY_ONLY')}
                    className={`px-2 py-0.5 text-[10px] font-bold uppercase transition-colors cursor-pointer ${
                      timelineMode === 'DAY_ONLY'
                        ? 'bg-[#38BDF8] text-black font-black'
                        : 'text-zinc-400 hover:text-white'
                    }`}
                    title={isEn ? 'Show only items discovered on selected day' : 'Mostrar apenas itens descobertos no dia selecionado'}
                  >
                    {isEn ? 'Single Day' : 'Apenas Dia'}
                  </button>
                </div>
              </div>

              {/* Right: Quick Reset to Live */}
              <button
                type="button"
                onClick={() => {
                  setTimelineDay(30);
                  setIsPlaying(false);
                  setTimelineMode('CUMULATIVE');
                }}
                className={`px-3 py-1 text-xs font-mono font-bold border transition-colors cursor-pointer flex items-center gap-1.5 ${
                  timelineDay === 30 && !isPlaying
                    ? 'bg-emerald-500/10 border-[#00FF41]/50 text-[#00FF41]'
                    : 'bg-[#121212] border-[#333] text-zinc-400 hover:text-white'
                }`}
              >
                <Clock className="w-3 h-3" />
                <span>{isEn ? 'Live Full View (Day 30)' : 'Visão Total (Dia 30)'}</span>
              </button>
            </div>

            {/* Daily Event Narrative Banner / Ticker */}
            <div className="mt-3 pt-2 border-t border-[#141414] flex items-center gap-2 text-[11px] font-mono">
              <span className="px-1.5 py-0.5 bg-[#121212] border border-[#2E2E2E] text-zinc-400 shrink-0 font-bold">
                DISPATCH:
              </span>
              <span className="text-[#00FF41] truncate">
                {dailyIntelEventNarrative}
              </span>
            </div>
          </div>

          {/* Interactive World Map Canvas Container */}
          <div
            ref={mapContainerRef}
            className="relative bg-[#050608] border border-[#222] overflow-hidden select-none"
          >
            {/* Tactical Grid Background & Scanlines */}
            <div className="absolute inset-0 pointer-events-none opacity-20 bg-[radial-gradient(#15202B_1px,transparent_1px)] [background-size:20px_20px]" />

            {/* Corner Tactical HUD Metadata */}
            <div className="absolute top-3 left-3 z-10 pointer-events-none flex flex-wrap items-center gap-2 font-mono text-[10px] text-zinc-500">
              <span className="px-1.5 py-0.5 bg-black/80 border border-[#222] text-[#00FF41]">
                LAT [-80°, +80°] / LNG [-180°, +180°]
              </span>
              <span className="px-1.5 py-0.5 bg-black/80 border border-[#222] text-zinc-400">
                PROJ: EQUIRECTANGULAR
              </span>
              {selectedRegionFilter !== 'ALL' && (
                <span className="px-1.5 py-0.5 bg-sky-950/80 border border-sky-600/50 text-[#38BDF8] font-bold flex items-center gap-1">
                  <span>REGION: {selectedRegionFilter}</span>
                </span>
              )}
              <span className={`px-1.5 py-0.5 bg-black/80 border text-[10px] flex items-center gap-1.5 ${
                timelineDay < 30 ? 'border-[#00FF41]/70 text-[#00FF41]' : 'border-[#222] text-zinc-400'
              }`}>
                <Clock className="w-3 h-3 text-[#00FF41]" />
                <span>REPLAY: DAY {timelineDay}/30 ({timelineDate.daysAgo === 0 ? 'TODAY' : `-${timelineDate.daysAgo}D`})</span>
                {isPlaying && <span className="w-1.5 h-1.5 rounded-full bg-[#00FF41] animate-ping" />}
              </span>
            </div>

            <div className="absolute top-3 right-3 z-10 pointer-events-none flex items-center gap-2 font-mono text-[10px] text-zinc-500">
              <span className="px-1.5 py-0.5 bg-black/80 border border-[#222] text-red-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping" />
                LIVE OTX FEED
              </span>
            </div>

            {/* SVG Global Map */}
            <svg
              viewBox={`0 0 ${mapWidth} ${mapHeight}`}
              className="w-full h-auto cursor-grab active:cursor-grabbing block"
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseUp}
              style={{ minHeight: '380px', maxHeight: '620px' }}
            >
              <defs>
                {/* Thermal Gradient Glows */}
                <radialGradient id="actorGlow" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#EF4444" stopOpacity="0.8" />
                  <stop offset="50%" stopColor="#EF4444" stopOpacity="0.3" />
                  <stop offset="100%" stopColor="#EF4444" stopOpacity="0" />
                </radialGradient>
                <radialGradient id="vulnGlow" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#00FF41" stopOpacity="0.8" />
                  <stop offset="50%" stopColor="#00FF41" stopOpacity="0.3" />
                  <stop offset="100%" stopColor="#00FF41" stopOpacity="0" />
                </radialGradient>
                <radialGradient id="targetGlow" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#F59E0B" stopOpacity="0.8" />
                  <stop offset="50%" stopColor="#F59E0B" stopOpacity="0.3" />
                  <stop offset="100%" stopColor="#F59E0B" stopOpacity="0" />
                </radialGradient>

                {/* Animated Trajectory Dash Marker */}
                <linearGradient id="arcGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#EF4444" />
                  <stop offset="50%" stopColor="#F59E0B" />
                  <stop offset="100%" stopColor="#00FF41" />
                </linearGradient>
              </defs>

              <g
                transform={`translate(${panOffset.x}, ${panOffset.y}) scale(${zoomLevel})`}
                transform-origin="500 250"
              >
                {/* Map Grid Latitude & Longitude Lines */}
                <g stroke="#141B22" strokeWidth="0.8" strokeDasharray="3 3">
                  {/* Latitude lines */}
                  <line x1="0" y1="125" x2={mapWidth} y2="125" />
                  <line x1="0" y1="250" x2={mapWidth} y2="250" stroke="#1E293B" strokeWidth="1.2" /> {/* Equator */}
                  <line x1="0" y1="375" x2={mapWidth} y2="375" />

                  {/* Longitude lines */}
                  <line x1="250" y1="0" x2="250" y2={mapHeight} />
                  <line x1="500" y1="0" x2="500" y2={mapHeight} stroke="#1E293B" strokeWidth="1.2" /> {/* Prime Meridian */}
                  <line x1="750" y1="0" x2="750" y2={mapHeight} />
                </g>

                {/* Continents Landmass Polygons */}
                <g>
                  {WORLD_CONTINENTS_SVG_PATHS.map(continent => (
                    <path
                      key={continent.id}
                      d={continent.d}
                      fill="#0D1117"
                      stroke="#1F2937"
                      strokeWidth="1.2"
                      className="transition-colors hover:fill-[#131B26]"
                    />
                  ))}
                </g>

                {/* Heat Glow Underlay for Hotspot Concentrations */}
                {showHeatGlow && (
                  <g pointerEvents="none">
                    {filteredActorNodes.map(actor => {
                      const pt = projectGeoToSvg(actor.lat, actor.lng, mapWidth, mapHeight);
                      return (
                        <circle
                          key={`glow-actor-${actor.id}`}
                          cx={pt.x}
                          cy={pt.y}
                          r="45"
                          fill="url(#actorGlow)"
                          opacity="0.6"
                        />
                      );
                    })}
                    {filteredVulnNodes.map(vuln => {
                      const pt = projectGeoToSvg(vuln.lat, vuln.lng, mapWidth, mapHeight);
                      return (
                        <circle
                          key={`glow-vuln-${vuln.id}`}
                          cx={pt.x}
                          cy={pt.y}
                          r="50"
                          fill="url(#vulnGlow)"
                          opacity="0.6"
                        />
                      );
                    })}
                  </g>
                )}

                {/* Attack Trajectory Arcs (Bezier curves from Threat Actors to Detected Vulnerabilities) */}
                {filteredTrajectories.map(traj => {
                  const p1 = projectGeoToSvg(traj.sourceCoords[0], traj.sourceCoords[1], mapWidth, mapHeight);
                  const p2 = projectGeoToSvg(traj.targetCoords[0], traj.targetCoords[1], mapWidth, mapHeight);

                  // Calculate control point for arch curve
                  const midX = (p1.x + p2.x) / 2;
                  const midY = Math.min(p1.y, p2.y) - Math.abs(p1.x - p2.x) * 0.2 - 20;

                  return (
                    <g key={traj.id} className="transition-opacity">
                      {/* Ambient arc glow */}
                      <path
                        d={`M ${p1.x} ${p1.y} Q ${midX} ${midY} ${p2.x} ${p2.y}`}
                        fill="none"
                        stroke="#EF4444"
                        strokeWidth="3"
                        strokeOpacity="0.2"
                      />
                      {/* Animated dashed trajectory */}
                      <path
                        d={`M ${p1.x} ${p1.y} Q ${midX} ${midY} ${p2.x} ${p2.y}`}
                        fill="none"
                        stroke="url(#arcGradient)"
                        strokeWidth="1.6"
                        strokeDasharray="6 4"
                        className="animate-pulse"
                      />
                    </g>
                  );
                })}

                {/* Layer: AlienVault OTX Target Country Hotspots */}
                {filteredTargetCountryNodes.map(target => {
                  const pt = projectGeoToSvg(target.lat, target.lng, mapWidth, mapHeight);
                  const isSelected = selectedNode?.id === target.id;
                  const isNewToday = target.timelineDay === timelineDay;

                  return (
                    <g
                      key={target.id}
                      transform={`translate(${pt.x}, ${pt.y})`}
                      className="cursor-pointer"
                      onClick={() => setSelectedNode(target)}
                      onMouseEnter={(e) => handleNodeMouseEnter(target, e)}
                      onMouseMove={handleNodeMouseMove}
                      onMouseLeave={handleNodeMouseLeave}
                    >
                      {/* Active Day Pulse Ping */}
                      {isNewToday && (
                        <circle
                          r="26"
                          fill="none"
                          stroke="#F59E0B"
                          strokeWidth="2"
                          strokeOpacity="0.8"
                          className="animate-ping"
                        />
                      )}
                      <circle
                        r="18"
                        fill="none"
                        stroke="#F59E0B"
                        strokeWidth="1"
                        strokeOpacity="0.3"
                        strokeDasharray="2 2"
                      />
                      <circle
                        r="6"
                        fill="#F59E0B"
                        stroke="#000"
                        strokeWidth="1.5"
                        className="transition-transform hover:scale-125"
                      />
                      {isSelected && (
                        <circle
                          r="12"
                          fill="none"
                          stroke="#F59E0B"
                          strokeWidth="2"
                        />
                      )}
                    </g>
                  );
                })}

                {/* Layer: OTX C2 Infrastructure Nodes */}
                {filteredC2Nodes.map(c2 => {
                  const pt = projectGeoToSvg(c2.lat, c2.lng, mapWidth, mapHeight);
                  const isSelected = selectedNode?.id === c2.id;
                  const isNewToday = c2.timelineDay === timelineDay;

                  return (
                    <g
                      key={c2.id}
                      transform={`translate(${pt.x}, ${pt.y})`}
                      className="cursor-pointer"
                      onClick={() => setSelectedNode(c2)}
                      onMouseEnter={(e) => handleNodeMouseEnter(c2, e)}
                      onMouseMove={handleNodeMouseMove}
                      onMouseLeave={handleNodeMouseLeave}
                    >
                      {/* Active Day Pulse Ping */}
                      {isNewToday && (
                        <circle
                          r="22"
                          fill="none"
                          stroke="#A855F7"
                          strokeWidth="2"
                          strokeOpacity="0.8"
                          className="animate-ping"
                        />
                      )}
                      {/* Diamond shape for C2 */}
                      <polygon
                        points="0,-8 8,0 0,8 -8,0"
                        fill="#A855F7"
                        stroke="#000"
                        strokeWidth="1.5"
                        className="transition-transform hover:scale-125"
                      />
                      {isSelected && (
                        <polygon
                          points="0,-14 14,0 0,14 -14,0"
                          fill="none"
                          stroke="#A855F7"
                          strokeWidth="2"
                        />
                      )}
                    </g>
                  );
                })}

                {/* Layer: Threat Actor Operating Origins */}
                {filteredActorNodes.map(actor => {
                  const pt = projectGeoToSvg(actor.lat, actor.lng, mapWidth, mapHeight);
                  const isSelected = selectedNode?.id === actor.id;
                  const isNewToday = actor.timelineDay === timelineDay;

                  return (
                    <g
                      key={actor.id}
                      transform={`translate(${pt.x}, ${pt.y})`}
                      className="cursor-pointer"
                      onClick={() => setSelectedNode(actor)}
                      onMouseEnter={(e) => handleNodeMouseEnter(actor, e)}
                      onMouseMove={handleNodeMouseMove}
                      onMouseLeave={handleNodeMouseLeave}
                    >
                      {/* Extra beacon ping for newly active actors on replay day */}
                      {isNewToday && (
                        <circle
                          r="28"
                          fill="none"
                          stroke="#EF4444"
                          strokeWidth="2.5"
                          strokeOpacity="0.9"
                          className="animate-ping"
                        />
                      )}
                      {/* Standard Pulse Ring */}
                      <circle
                        r="14"
                        fill="none"
                        stroke="#EF4444"
                        strokeWidth="1.5"
                        strokeOpacity="0.6"
                        className="animate-ping"
                      />
                      <circle
                        r="8"
                        fill="#EF4444"
                        stroke="#000"
                        strokeWidth="2"
                      />
                      {isSelected && (
                        <circle
                          r="18"
                          fill="none"
                          stroke="#EF4444"
                          strokeWidth="2.5"
                        />
                      )}
                      <text
                        x="12"
                        y="4"
                        fill="#F87171"
                        fontSize="9"
                        fontFamily="monospace"
                        fontWeight="bold"
                        className="pointer-events-none drop-shadow"
                      >
                        {actor.actorName?.split(' ')[0] || actor.name}
                      </text>
                    </g>
                  );
                })}

                {/* Layer: Detected Vulnerability Anchors */}
                {filteredVulnNodes.map(vuln => {
                  const pt = projectGeoToSvg(vuln.lat, vuln.lng, mapWidth, mapHeight);
                  const isSelected = selectedNode?.id === vuln.id;
                  const isCritical = vuln.severity === 'CRITICAL';
                  const isNewToday = vuln.timelineDay === timelineDay;
                  // Dynamic findings count discovered up to current timeline day
                  const currentDiscoveredFindings = vuln.findings.filter(f => !f.timelineDay || f.timelineDay <= timelineDay);
                  const displayCount = currentDiscoveredFindings.length || vuln.findings.length;

                  return (
                    <g
                      key={vuln.id}
                      transform={`translate(${pt.x}, ${pt.y})`}
                      className="cursor-pointer"
                      onClick={() => setSelectedNode(vuln)}
                      onMouseEnter={(e) => handleNodeMouseEnter(vuln, e)}
                      onMouseMove={handleNodeMouseMove}
                      onMouseLeave={handleNodeMouseLeave}
                    >
                      {/* Glowing Radar Beacon Ping for New Discoveries on Replay Day */}
                      {isNewToday && (
                        <g>
                          <circle
                            r="28"
                            fill="none"
                            stroke="#00FF41"
                            strokeWidth="2.5"
                            strokeOpacity="0.9"
                            className="animate-ping"
                          />
                          <rect
                            x="-14"
                            y="14"
                            width="28"
                            height="10"
                            fill="#00FF41"
                            rx="2"
                          />
                          <text
                            x="0"
                            y="22"
                            textAnchor="middle"
                            fill="#000"
                            fontSize="7"
                            fontWeight="black"
                            fontFamily="monospace"
                          >
                            NEW
                          </text>
                        </g>
                      )}

                      {/* Radar Target Reticle */}
                      <circle
                        r="16"
                        fill="none"
                        stroke={isCritical ? '#EF4444' : '#00FF41'}
                        strokeWidth="1.5"
                        strokeDasharray="4 2"
                      />
                      <circle
                        r="8"
                        fill={isCritical ? '#EF4444' : '#00FF41'}
                        stroke="#000"
                        strokeWidth="2"
                      />
                      {isSelected && (
                        <circle
                          r="22"
                          fill="none"
                          stroke="#00FF41"
                          strokeWidth="2.5"
                        />
                      )}
                      {/* Dynamic Finding Count Badge */}
                      <rect
                        x="-10"
                        y="-22"
                        width="20"
                        height="12"
                        fill="#000"
                        stroke={isCritical ? '#EF4444' : '#00FF41'}
                        strokeWidth="1"
                      />
                      <text
                        x="0"
                        y="-13"
                        textAnchor="middle"
                        fill="#FFF"
                        fontSize="8"
                        fontFamily="monospace"
                        fontWeight="black"
                      >
                        {displayCount}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>

            {/* Interactive Floating Tooltip for Vulnerability Marker (and other Geo nodes) */}
            {hoveredNode && (
              <div
                style={
                  tooltipPos
                    ? { left: `${tooltipPos.x}px`, top: `${tooltipPos.y}px` }
                    : { bottom: '16px', left: '16px' }
                }
                className={`absolute z-30 pointer-events-none bg-[#090D14]/95 border p-3.5 text-xs font-mono max-w-sm rounded backdrop-blur-md transition-all duration-75 shadow-2xl ${
                  hoveredNode.type === 'DETECTED_VULNERABILITY'
                    ? 'border-[#00FF41]/60 shadow-[0_0_25px_rgba(0,255,65,0.2)]'
                    : hoveredNode.type === 'THREAT_ACTOR_ORIGIN'
                    ? 'border-red-500/60 shadow-[0_0_25px_rgba(239,68,68,0.2)]'
                    : 'border-[#38BDF8]/50 shadow-[0_0_25px_rgba(56,189,248,0.2)]'
                }`}
              >
                {/* Header: Node Type & Severity Risk Badge */}
                <div className="flex items-center justify-between gap-2 border-b border-[#1E293B] pb-2 mb-2">
                  <div className="flex items-center gap-1.5">
                    {hoveredNode.type === 'DETECTED_VULNERABILITY' ? (
                      <Crosshair className="w-3.5 h-3.5 text-[#00FF41] animate-pulse" />
                    ) : hoveredNode.type === 'THREAT_ACTOR_ORIGIN' ? (
                      <Skull className="w-3.5 h-3.5 text-red-500 animate-pulse" />
                    ) : hoveredNode.type === 'C2_INFRASTRUCTURE' ? (
                      <Radio className="w-3.5 h-3.5 text-purple-400 animate-pulse" />
                    ) : (
                      <Globe className="w-3.5 h-3.5 text-amber-400 animate-pulse" />
                    )}
                    <span className="text-[10px] font-black tracking-wider uppercase text-zinc-300">
                      {hoveredNode.type === 'DETECTED_VULNERABILITY'
                        ? (isEn ? 'Detected Vulnerability Marker' : 'Marcador de Vulnerabilidade')
                        : hoveredNode.type.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`text-[9px] px-1.5 py-0.5 font-bold uppercase rounded-xs border ${
                        hoveredNode.severity === 'CRITICAL'
                          ? 'bg-red-500/20 text-red-400 border-red-500/40'
                          : hoveredNode.severity === 'HIGH'
                          ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                          : 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40'
                      }`}
                    >
                      {hoveredNode.severity}
                    </span>
                    <span className="text-[10px] text-zinc-400 font-bold bg-[#141B26] px-1 py-0.5 border border-[#223044]">
                      {hoveredNode.threatScore}/100
                    </span>
                  </div>
                </div>

                {/* Specific Threat Actor Highlight Box (Prominently displayed) */}
                <div className="bg-red-950/25 border border-red-500/35 p-2 mb-2 rounded-xs">
                  <div className="text-[10px] text-red-400 uppercase tracking-wider font-bold flex items-center justify-between">
                    <span className="flex items-center gap-1">
                      <Skull className="w-3 h-3 text-red-400" />
                      <span>{isEn ? 'Specific Threat Actor:' : 'Ator Hostil Específico:'}</span>
                    </span>
                    <span className="text-[9px] text-zinc-400 font-mono">
                      {hoveredNode.threatActorMotivation || (isEn ? 'ACTIVE CAMPAIGN' : 'CAMPANHA ATIVA')}
                    </span>
                  </div>
                  <div className="text-white font-black text-sm mt-0.5 flex items-center gap-1.5 truncate">
                    <span className="text-red-200">
                      {hoveredNode.specificThreatActor || hoveredNode.actorName || hoveredNode.name}
                    </span>
                    {hoveredNode.threatActorCodeName && (
                      <span className="text-[10px] text-zinc-400 font-normal">
                        ({hoveredNode.threatActorCodeName})
                      </span>
                    )}
                  </div>
                </div>

                {/* CVE ID Badge with CISA KEV Exploited Status */}
                <div className="bg-[#0D1520] border border-[#1E2E44] p-2 mb-2 rounded-xs flex items-center justify-between">
                  <div>
                    <div className="text-[10px] text-zinc-400 uppercase font-bold flex items-center gap-1">
                      <ShieldAlert className="w-3 h-3 text-[#38BDF8]" />
                      <span>{isEn ? 'CVE ID:' : 'Identificador CVE:'}</span>
                    </div>
                    <div className="text-[#38BDF8] font-bold text-sm font-mono mt-0.5 tracking-wide">
                      {hoveredNode.cveId || (hoveredNode.pulses[0]?.cves?.[0] || 'CVE-2024-21626')}
                    </div>
                  </div>
                  <div className="text-right">
                    {hoveredNode.cisaKevAssociated ? (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-red-900/40 border border-red-500/50 text-red-300 text-[9px] font-bold uppercase rounded-xs">
                        <AlertTriangle className="w-2.5 h-2.5 text-red-400" />
                        <span>CISA KEV</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-sky-950/40 border border-sky-500/40 text-sky-300 text-[9px] font-bold uppercase rounded-xs">
                        <span>OTX VERIFIED</span>
                      </span>
                    )}
                  </div>
                </div>

                {/* Last Observed Timestamp Box */}
                <div className="bg-black/70 border border-[#222] p-2 mb-2 rounded-xs">
                  <div className="text-[10px] text-zinc-400 uppercase font-bold flex items-center gap-1">
                    <Clock className="w-3 h-3 text-[#00FF41]" />
                    <span>{isEn ? 'Last Observed Timestamp:' : 'Última Observação Registrada:'}</span>
                  </div>
                  <div className="text-[#00FF41] font-mono text-xs font-bold mt-0.5">
                    {hoveredNode.lastObservedFormatted || hoveredNode.lastObservedTimestamp || hoveredNode.discoveryDate}
                  </div>
                </div>

                {/* Geographic & Findings Context */}
                <div className="text-[11px] text-zinc-300 flex items-center justify-between border-t border-[#1C2636] pt-1.5 mt-1">
                  <span className="text-zinc-400 truncate max-w-[210px]">
                    📍 {hoveredNode.locationLabel} [{hoveredNode.region}]
                  </span>
                  {hoveredNode.findings.length > 0 && (
                    <span className="text-[#00FF41] font-bold shrink-0">
                      {hoveredNode.findings.length} {hoveredNode.findings.length === 1 ? 'vulnerability' : 'vulnerabilities'}
                    </span>
                  )}
                </div>

                {/* Interactive Click Prompt */}
                <div className="text-[9px] text-sky-400/80 mt-1.5 flex items-center justify-between pt-1 border-t border-[#141B26]">
                  <span className="font-bold flex items-center gap-1">
                    <ExternalLink className="w-2.5 h-2.5" />
                    {isEn ? 'Click marker to inspect full dossier' : 'Clique no marcador para dossiê'}
                  </span>
                  <span className="text-zinc-500">Day {hoveredNode.timelineDay}/30</span>
                </div>
              </div>
            )}
          </div>

          {/* Map Legend Bar */}
          <div className="bg-[#0A0A0A] border border-[#222] p-3 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
            <div className="flex flex-wrap items-center gap-4">
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">
                {isEn ? 'Legend:' : 'Legenda:'}
              </span>
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full bg-[#00FF41] border border-black inline-block" />
                <span className="text-zinc-300 text-[11px]">
                  {isEn ? 'Detected Vuln Target' : 'Alvo de Vulnerabilidade'}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full bg-[#EF4444] border border-black inline-block" />
                <span className="text-zinc-300 text-[11px]">
                  {isEn ? 'Threat Actor Hub' : 'Base do Ator Hostil'}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full bg-[#F59E0B] border border-black inline-block" />
                <span className="text-zinc-300 text-[11px]">
                  {isEn ? 'OTX Strike Country' : 'País Alvo no OTX'}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rotate-45 bg-[#A855F7] border border-black inline-block" />
                <span className="text-zinc-300 text-[11px]">
                  {isEn ? 'OTX C2 IP Node' : 'Nó C2 / Exfil OTX'}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-5 h-0.5 bg-gradient-to-r from-red-500 to-emerald-500 inline-block" />
                <span className="text-zinc-300 text-[11px]">
                  {isEn ? 'Active Attack Arc' : 'Arco de Ataque Ativo'}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#00FF41] animate-ping inline-block" />
                <span className="text-zinc-300 text-[11px]">
                  {isEn ? 'Timeline Discovery Ping' : 'Novo Alvo na Linha do Tempo'}
                </span>
              </div>
            </div>

            <div className="text-[10px] text-zinc-500">
              {isEn ? 'Feed sync: AlienVault OTX live feed' : 'Sincronizado: Feed AlienVault OTX ativo'}
            </div>
          </div>

          {/* Deep-Dive Geo Node Inspector Drawer (Selected Node) */}
          {selectedNode && (
            <div className="bg-[#0A0A0A] border border-[#00FF41] p-5 font-mono animate-in fade-in duration-200">
              <div className="flex items-start justify-between gap-4 border-b border-[#222] pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] uppercase font-bold text-zinc-400">
                      {selectedNode.type.replace(/_/g, ' ')}
                    </span>
                    <span className="text-zinc-600">/</span>
                    <span className="text-[10px] text-[#00FF41] font-bold">
                      {selectedNode.sourceFeed}
                    </span>
                    {selectedNode.cisaKevAssociated && (
                      <span className="text-[9px] px-1.5 py-0.2 bg-red-500/20 text-red-400 border border-red-500/40 font-bold">
                        CISA KEV ALERT
                      </span>
                    )}
                  </div>
                  <h3 className="text-lg font-black text-white mt-1 flex items-center gap-2">
                    <span>{selectedNode.name}</span>
                  </h3>
                  <div className="text-xs text-zinc-400 mt-0.5 flex flex-wrap items-center gap-2">
                    <span>📍 {selectedNode.locationLabel}, {selectedNode.country}</span>
                    <span className="text-zinc-600">•</span>
                    <span className="px-1.5 py-0.5 bg-[#151515] border border-[#333] text-[#38BDF8] text-[10px] font-bold">
                      {selectedNode.region}
                    </span>
                    <span className="text-zinc-600">•</span>
                    <span className="px-1.5 py-0.5 bg-emerald-950/60 border border-emerald-600/40 text-[#00FF41] text-[10px] font-bold flex items-center gap-1">
                      <Clock className="w-2.5 h-2.5" />
                      <span>{selectedNode.discoveryDate} (Day {selectedNode.timelineDay}/30)</span>
                    </span>
                    <span className="text-zinc-600">•</span>
                    <span>COORDS: {selectedNode.lat.toFixed(4)}° N, {selectedNode.lng.toFixed(4)}° E</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => handleCopyDossier(selectedNode)}
                    className="px-3 py-1.5 bg-[#181818] hover:bg-[#222] border border-[#333] text-white text-xs font-bold flex items-center gap-1.5 cursor-pointer"
                  >
                    {copiedId === selectedNode.id ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-[#00FF41]" />
                        <span className="text-[#00FF41]">{isEn ? 'Copied' : 'Copiado'}</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>{isEn ? 'Copy Dossier' : 'Copiar Dossiê'}</span>
                      </>
                    )}
                  </button>

                  <button
                    type="button"
                    onClick={() => setSelectedNode(null)}
                    className="p-1.5 bg-[#181818] hover:bg-[#222] border border-[#333] text-zinc-400 hover:text-white cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Node Details Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                <div className="md:col-span-2 space-y-4">
                  {/* Dedicated Threat Intelligence Correlation Card for Detected Vulnerability */}
                  {selectedNode.type === 'DETECTED_VULNERABILITY' && (
                    <div className="p-3.5 bg-gradient-to-r from-red-950/30 via-zinc-950 to-sky-950/30 border border-emerald-500/40 rounded-xs">
                      <div className="text-[10px] text-emerald-400 font-bold uppercase tracking-wider flex items-center justify-between border-b border-[#222] pb-2 mb-2.5">
                        <span className="flex items-center gap-1.5">
                          <ShieldAlert className="w-3.5 h-3.5 text-emerald-400" />
                          <span>{isEn ? 'Vulnerability Threat Intel Correlation' : 'Correlação de Inteligência de Ameaça'}</span>
                        </span>
                        <span className="text-zinc-500 text-[9px] font-mono">
                          {selectedNode.cisaKevAssociated ? 'CISA KEV EXPLOITED' : 'OTX FEED CORRELATED'}
                        </span>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        {/* Threat Actor */}
                        <div className="bg-black/60 border border-red-500/30 p-2.5">
                          <div className="text-[9px] text-zinc-400 uppercase font-bold flex items-center gap-1">
                            <Skull className="w-3 h-3 text-red-400" />
                            <span>{isEn ? 'Specific Threat Actor' : 'Ator Hostil Específico'}</span>
                          </div>
                          <div className="text-white font-black text-sm mt-1 text-red-200">
                            {selectedNode.specificThreatActor || selectedNode.actorName || 'Scattered Spider'}
                          </div>
                          {selectedNode.threatActorCodeName && (
                            <div className="text-[10px] text-zinc-400 mt-0.5">
                              {selectedNode.threatActorCodeName}
                            </div>
                          )}
                        </div>

                        {/* CVE ID */}
                        <div className="bg-black/60 border border-sky-500/30 p-2.5">
                          <div className="text-[9px] text-zinc-400 uppercase font-bold flex items-center gap-1">
                            <ShieldAlert className="w-3 h-3 text-sky-400" />
                            <span>{isEn ? 'Correlated CVE ID' : 'Identificador CVE'}</span>
                          </div>
                          <div className="text-[#38BDF8] font-black text-sm font-mono mt-1">
                            {selectedNode.cveId || 'CVE-2024-21626'}
                          </div>
                          {selectedNode.cveIds && selectedNode.cveIds.length > 1 && (
                            <div className="text-[9px] text-zinc-400 mt-0.5 truncate">
                              +{selectedNode.cveIds.slice(1).join(', ')}
                            </div>
                          )}
                        </div>

                        {/* Last Observed Timestamp */}
                        <div className="bg-black/60 border border-emerald-500/30 p-2.5">
                          <div className="text-[9px] text-zinc-400 uppercase font-bold flex items-center gap-1">
                            <Clock className="w-3 h-3 text-emerald-400" />
                            <span>{isEn ? 'Last Observed Timestamp' : 'Última Observação'}</span>
                          </div>
                          <div className="text-[#00FF41] font-bold text-xs font-mono mt-1">
                            {selectedNode.lastObservedFormatted || selectedNode.lastObservedTimestamp || selectedNode.discoveryDate}
                          </div>
                          <div className="text-[9px] text-zinc-500 mt-0.5">
                            Day {selectedNode.timelineDay} of 30 Observation Window
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="p-3 bg-[#050505] border border-[#1C1C1C]">
                    <div className="text-[10px] text-zinc-500 uppercase font-bold tracking-wider">
                      {isEn ? 'Threat Intelligence Assessment' : 'Avaliação de Inteligência de Ameaça'}
                    </div>
                    <div className="text-xs text-zinc-300 mt-1 leading-relaxed">
                      {selectedNode.details}
                    </div>
                  </div>

                  {/* If it's a detected vulnerability node: List Findings */}
                  {selectedNode.findings.length > 0 && (
                    <div className="p-3 bg-[#050505] border border-[#1C1C1C]">
                      <div className="text-[10px] text-[#00FF41] uppercase font-bold tracking-wider flex items-center justify-between">
                        <span>{isEn ? 'Detected Code Vulnerabilities In This Cloud Anchor' : 'Vulnerabilidades de Código Detectadas Nesta Região'}</span>
                        <span>{selectedNode.findings.length} {isEn ? 'findings' : 'achados'}</span>
                      </div>
                      <div className="mt-2 divide-y divide-[#1C1C1C] max-h-52 overflow-y-auto pr-1">
                        {selectedNode.findings.map(finding => (
                          <div key={finding.id} className="py-2 flex items-center justify-between gap-3 text-xs">
                            <div className="min-w-0">
                              <div className="flex items-center gap-1.5">
                                <span
                                  className={`text-[9px] px-1 font-bold ${
                                    finding.severity === 'CRITICAL'
                                      ? 'text-red-400 bg-red-500/10'
                                      : 'text-amber-400 bg-amber-500/10'
                                  }`}
                                >
                                  {finding.severity}
                                </span>
                                <span className="font-bold text-white truncate">{finding.ruleName}</span>
                              </div>
                              <div className="text-[10px] text-zinc-500 truncate font-mono mt-0.5">
                                📄 {finding.file}:{finding.line}
                              </div>
                            </div>
                            {onSelectFinding && (
                              <button
                                type="button"
                                onClick={() => onSelectFinding(finding)}
                                className="px-2 py-1 bg-[#1A1A1A] hover:bg-[#262626] border border-[#333] text-zinc-300 hover:text-white text-[10px] font-bold shrink-0 cursor-pointer"
                              >
                                {isEn ? 'Inspect' : 'Inspecionar'}
                              </button>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Active Campaigns & OTX Pulses */}
                  {selectedNode.pulses.length > 0 && (
                    <div className="p-3 bg-[#050505] border border-[#1C1C1C]">
                      <div className="text-[10px] text-zinc-500 uppercase font-bold tracking-wider">
                        {isEn ? 'Associated AlienVault OTX Pulses' : 'Pulses AlienVault OTX Associados'}
                      </div>
                      <div className="mt-2 space-y-1.5">
                        {selectedNode.pulses.map(pulse => (
                          <div key={pulse.id} className="flex items-center justify-between text-xs bg-[#111] p-2 border border-[#222]">
                            <span className="font-bold text-zinc-200 truncate">{pulse.name}</span>
                            <span className="text-[10px] text-[#00FF41] shrink-0 font-bold">
                              TLP:{pulse.tlp}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Right Column: TTPs, Score & Action Buttons */}
                <div className="space-y-4">
                  <div className="p-3 bg-[#050505] border border-[#1C1C1C]">
                    <div className="text-[10px] text-zinc-500 uppercase font-bold tracking-wider">
                      {isEn ? 'Calculated Threat Score' : 'Score de Ameaça Calculado'}
                    </div>
                    <div className="text-3xl font-black text-white mt-1">
                      {selectedNode.threatScore}
                      <span className="text-xs text-zinc-500 font-normal"> / 100</span>
                    </div>
                    <div className="text-[10px] text-zinc-400 mt-1">
                      Severidade: <span className="font-bold text-[#00FF41]">{selectedNode.severity}</span>
                    </div>
                  </div>

                  <div className="p-3 bg-[#050505] border border-[#1C1C1C]">
                    <div className="text-[10px] text-zinc-500 uppercase font-bold tracking-wider">
                      {isEn ? 'MITRE ATT&CK TTPs' : 'Táticas & Técnicas MITRE'}
                    </div>
                    <div className="mt-2 space-y-1">
                      {selectedNode.ttps.map((ttp, idx) => (
                        <div key={idx} className="text-[11px] text-zinc-300 bg-[#111] px-2 py-1 border border-[#1E1E1E]">
                          • {ttp}
                        </div>
                      ))}
                    </div>
                  </div>

                  {onNavigateToScanner && (
                    <button
                      type="button"
                      onClick={onNavigateToScanner}
                      className="w-full py-2.5 bg-[#00FF41] hover:bg-[#00DD38] text-black font-black text-xs uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer shadow-lg"
                    >
                      <Terminal className="w-4 h-4" />
                      <span>{isEn ? 'Open SAST Scanner' : 'Abrir Scanner SAST'}</span>
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
